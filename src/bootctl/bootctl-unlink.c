/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <fnmatch.h>

#include "sd-id128.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "boot-entry.h"
#include "bootctl.h"
#include "bootctl-unlink.h"
#include "bootspec.h"
#include "bootspec-util.h"
#include "chase.h"
#include "efi-loader.h"
#include "errno-util.h"
#include "find-esp.h"
#include "fd-util.h"
#include "hashmap.h"
#include "id128-util.h"
#include "json-util.h"
#include "log.h"
#include "path-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"

typedef struct UnlinkContext {
        char *root;
        int root_fd;

        sd_id128_t machine_id;
        BootEntryTokenType entry_token_type;
        char *entry_token;

        char *esp_path;
        dev_t esp_devid;
        int esp_fd;

        char *xbootldr_path;
        dev_t xbootldr_devid;
        int xbootldr_fd;
} UnlinkContext;

#define UNLINK_CONTEXT_NULL                                             \
        (UnlinkContext) {                                               \
                .root_fd = -EBADF,                                      \
                .entry_token_type = _BOOT_ENTRY_TOKEN_TYPE_INVALID,     \
                .esp_fd = -EBADF,                                       \
                .xbootldr_fd = -EBADF,                                  \
        }

static void unlink_context_done(UnlinkContext *c) {
        assert(c);

        c->root = mfree(c->root);
        c->root_fd = safe_close(c->root_fd);

        c->entry_token = mfree(c->entry_token);

        c->esp_path = mfree(c->esp_path);
        c->esp_fd = safe_close(c->esp_fd);
        c->xbootldr_path = mfree(c->xbootldr_path);
        c->xbootldr_fd = safe_close(c->xbootldr_fd);
}

static int ref_file(Hashmap **known_files, const char *fn, int increment) {
        int n, r;

        assert(known_files);

        /* just gracefully ignore this. This way the caller doesn't have to verify whether the bootloader
         * entry is relevant. */
        if (!fn)
                return 0;

        char *k = NULL;
        n = PTR_TO_INT(hashmap_get2(*known_files, fn, (void**)&k));
        if (!INC_SAFE(&n, increment))
                return -EOVERFLOW;

        assert(n >= 0);

        if (n == 0) {
                (void) hashmap_remove(*known_files, k);
                free(k);
        } else if (!k) {
                _cleanup_free_ char *t = NULL;

                t = strdup(fn);
                if (!t)
                        return -ENOMEM;

                r = hashmap_ensure_put(known_files, &path_hash_ops_free, t, INT_TO_PTR(n));
                if (r < 0)
                        return r;

                TAKE_PTR(t);
        } else {
                r = hashmap_update(*known_files, k, INT_TO_PTR(n));
                if (r < 0)
                        return r;
        }

        return n;
}

static int boot_entry_ref_files(
                const BootEntry *e,
                Hashmap **known_files,
                int increment) {

        int r;

        assert(e);
        assert(known_files);
        assert(increment != 0);

        r = ref_file(known_files, e->kernel, increment);
        if (r < 0)
                return r;

        r = ref_file(known_files, e->efi, increment);
        if (r < 0)
                return r;

        r = ref_file(known_files, e->uki, increment);
        if (r < 0)
                return r;

        STRV_FOREACH(s, e->initrd) {
                r = ref_file(known_files, *s, increment);
                if (r < 0)
                        return r;
        }

        r = ref_file(known_files, e->device_tree, increment);
        if (r < 0)
                return r;

        STRV_FOREACH(s, e->device_tree_overlay) {
                r = ref_file(known_files, *s, increment);
                if (r < 0)
                        return r;
        }

        return 0;
}

int boot_config_count_known_files(
                const BootConfig *config,
                BootEntrySource source,
                Hashmap **ret_known_files) {

        int r;

        assert(config);
        assert(ret_known_files);

        _cleanup_hashmap_free_ Hashmap *known_files = NULL;
        FOREACH_ARRAY(e, config->entries, config->n_entries) {

                if (e->source != source)
                        continue;

                r = boot_entry_ref_files(e, &known_files, +1);
                if (r < 0)
                        return r;
        }

        *ret_known_files = TAKE_PTR(known_files);
        return 0;
}

static int unref_unlink_file(
                Hashmap **known_files,
                const char *root,
                int root_fd,
                const char *path,
                bool dry_run) {

        int r;

        assert(known_files);

        /* just gracefully ignore this. This way the caller doesn't
           have to verify whether the bootloader entry is relevant */
        if (root_fd < 0 || !root || !path)
                return 0;

        r = ref_file(known_files, path, -1);
        if (r < 0)
                return log_error_errno(r, "Failed to unref '%s': %m", path);
        if (r > 0)
                return 0;

        if (dry_run) {
                _cleanup_free_ char *resolved = NULL;
                r = chase_and_accessat(root_fd, path, CHASE_AT_RESOLVE_IN_ROOT|CHASE_PROHIBIT_SYMLINKS|CHASE_TRIGGER_AUTOFS|CHASE_MUST_BE_REGULAR, F_OK, &resolved);
                if (r < 0) {
                        log_warning_errno(r, "Unable to determine whether '%s' exists, ignoring: %m", path);
                        return 0;
                }

                log_info("Would remove '%s'", resolved);
                return 1;
        }

        _cleanup_free_ char *resolved = NULL;
        r = chase_and_unlinkat(root_fd, path, CHASE_AT_RESOLVE_IN_ROOT|CHASE_PROHIBIT_SYMLINKS|CHASE_TRIGGER_AUTOFS, /* unlink_flags= */ 0, &resolved);
        if (r == -ENOENT)
                log_debug("Resource '%s' is already removed, skipping.", path);
        else if (r < 0) {
                log_warning_errno(r, "Failed to remove '%s', ignoring: %m", path);
                return 0;
        } else
                log_info("Removed '%s'", resolved);

        _cleanup_free_ char *parent = NULL;
        r = path_extract_directory(path, &parent);
        if (r < 0)
                log_debug_errno(r, "Failed to extract parent directory of '%s', ignoring.", path);
        else {
                _cleanup_free_ char *resolved_parent = NULL;
                r = chase_and_unlinkat(root_fd, parent, CHASE_AT_RESOLVE_IN_ROOT|CHASE_PROHIBIT_SYMLINKS|CHASE_TRIGGER_AUTOFS, AT_REMOVEDIR, &resolved_parent);
                if (IN_SET(r, -ENOTEMPTY, -ENOENT))
                        log_debug_errno(r, "Failed to remove directory '%s', ignoring: %m", parent);
                else if (r < 0)
                        log_warning_errno(r, "Failed to remove directory '%s', ignoring: %m", parent);
                else
                        log_info("Removed '%s'.", resolved_parent);
        }

        return 1;
}

static ssize_t boot_config_find_in(
                const BootConfig *config,
                BootEntrySource source,
                const char *id) {

        assert(config);
        assert(source >= 0);
        assert(source < _BOOT_ENTRY_SOURCE_MAX);

        if (!id)
                return -ENOENT;

        for (size_t i = 0; i < config->n_entries; i++)
                if (config->entries[i].source == source &&
                    fnmatch(id, config->entries[i].id, FNM_CASEFOLD) == 0)
                        return (ssize_t) i;

        return -ENOENT;
}

int boot_entry_unlink(
                const BootEntry *e,
                const char *root,
                int root_fd,
                Hashmap *known_files,
                bool dry_run) {

        int r;

        assert(e);
        assert(root_fd >= 0);

        (void) unref_unlink_file(&known_files, root, root_fd, e->kernel, dry_run);
        (void) unref_unlink_file(&known_files, root, root_fd, e->efi, dry_run);
        (void) unref_unlink_file(&known_files, root, root_fd, e->uki, dry_run);
        STRV_FOREACH(s, e->initrd)
                (void) unref_unlink_file(&known_files, root, root_fd, *s, dry_run);
        (void) unref_unlink_file(&known_files, root, root_fd, e->device_tree, dry_run);
        STRV_FOREACH(s, e->device_tree_overlay)
                (void) unref_unlink_file(&known_files, root, root_fd, *s, dry_run);

        if (arg_dry_run)
                log_info("Would remove \"%s\"", e->path);
        else {
                const char *p = path_startswith(e->path, root);
                if (!p)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "File '%s' is not inside root '%s', refusing.", e->path, root);

                _cleanup_free_ char *resolved = NULL;
                r = chase_and_unlinkat(root_fd, p, CHASE_AT_RESOLVE_IN_ROOT|CHASE_PROHIBIT_SYMLINKS|CHASE_TRIGGER_AUTOFS, /* unlink_flags= */ 0, &resolved);
                if (r == -ENOENT)
                        return 0; /* Already removed? */
                if (r < 0)
                        return log_error_errno(r, "Failed to remove \"%s\": %m", e->path);

                log_info("Removed '%s'.", resolved);
        }

        return 0;
}

static int unlink_entry(
                const BootConfig *config,
                const char *root,
                int root_fd,
                BootEntrySource source,
                char **ids,
                bool dry_run) {

        size_t n_removed = 0;
        int r;

        assert(config);

        _cleanup_hashmap_free_ Hashmap *known_files = NULL;
        r = boot_config_count_known_files(config, source, &known_files);
        if (r < 0)
                return log_error_errno(r, "Failed to count files in %s: %m", root);

        int ret = 0;
        STRV_FOREACH(id, ids) {
                log_debug("Unlinking '%s'", *id);
                ssize_t idx = boot_config_find_in(config, source, *id);
                if (idx < 0)
                        continue; /* There is nothing to remove. */

                log_debug("Index %zi", idx);

                if (idx == config->default_entry)
                        log_warning("%s is the default boot entry", *id);
                if (idx == config->selected_entry)
                        log_warning("%s is the selected boot entry", *id);

                r = boot_entry_unlink(config->entries + idx, root, root_fd, known_files, dry_run);
                if (r < 0)
                        RET_GATHER(ret, r);
                else
                        n_removed++;
        }

        if (n_removed == 0)
                log_info("No matching entries found or removed.");

        return ret;
}

static int unlink_context_from_cmdline(UnlinkContext *ret) {
        int r;

        assert(ret);

        _cleanup_(unlink_context_done) UnlinkContext b = UNLINK_CONTEXT_NULL;
        b.entry_token_type = arg_entry_token_type;

        if (strdup_to(&b.entry_token, arg_entry_token) < 0)
                return log_oom();

        if (arg_root) {
                b.root_fd = open(arg_root, O_CLOEXEC|O_DIRECTORY|O_PATH);
                if (b.root_fd < 0)
                        return log_error_errno(errno, "Failed to open root directory '%s': %m", arg_root);

                if (strdup_to(&b.root, arg_root) < 0)
                        return log_oom();
        } else
                b.root_fd = XAT_FDROOT;

        r = acquire_esp(/* unprivileged_mode= */ false,
                        /* graceful= */ false,
                        &b.esp_fd,
                        /* ret_part= */ NULL,
                        /* ret_pstart= */ NULL,
                        /* ret_psize= */ NULL,
                        /* ret_uuid= */ NULL,
                        &b.esp_devid);
        if (r < 0 && r != -ENOKEY)
                return r; /* About all other errors acquire_esp() logs on its own */
        if (r > 0) {
                if (arg_root) {
                        const char *e = path_startswith(arg_esp_path, arg_root);
                        if (!e)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "ESP path '%s' not below specified root '%s', refusing.", arg_esp_path, arg_root);

                        r = strdup_to(&b.esp_path, e);
                } else
                        r = strdup_to(&b.esp_path, arg_esp_path);
                if (r < 0)
                        return log_oom();
        }

        r = acquire_xbootldr(
                        /* unprivileged_mode= */ false,
                        &b.xbootldr_fd,
                        /* ret_uuid= */ NULL,
                        &b.xbootldr_devid);
        if (r < 0 && r != -ENOKEY)
                return r;
        if (r > 0) {
                if (arg_root) {
                        const char *e = path_startswith(arg_xbootldr_path, arg_root);
                        if (!e)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "XBOOTLDR path '%s' not below specified root '%s', refusing.", arg_xbootldr_path, arg_root);

                        r = strdup_to(&b.xbootldr_path, e);
                } else
                        r = strdup_to(&b.xbootldr_path, arg_xbootldr_path);
                if (r < 0)
                        return log_oom();
        }

        /* Only if we found neither ESP nor XBOOTLDR let's fail. */
        if (!b.xbootldr_path && !b.esp_path)
                return log_error_errno(SYNTHETIC_ERRNO(ENOKEY), "Neither ESP nor XBOOTLDR found, refusing.");

        *ret = TAKE_GENERIC(b, UnlinkContext, UNLINK_CONTEXT_NULL);
        return 0;
}

static int run_unlink(
                UnlinkContext *c,
                char **_ids,
                bool dry_run) {

        int r;
        assert(c);

        _cleanup_free_ char *x = NULL, *y = NULL;
        if (c->root && c->esp_path) {
                x = path_join(c->root, c->esp_path);
                if (!x)
                        return log_oom();
        }

        if (c->root && c->xbootldr_path) {
                y = path_join(c->root, c->xbootldr_path);
                if (!y)
                        return log_oom();
        }

        _cleanup_(boot_config_free) BootConfig config = BOOT_CONFIG_NULL;
        r = boot_config_load_and_select(
                        &config,
                        c->root,
                        x ?: c->esp_path,
                        c->esp_devid,
                        y ?: c->xbootldr_path,
                        c->xbootldr_devid);
        if (r < 0)
                return r;

        _cleanup_(strv_freep) char **ids = NULL;
        if (strv_isempty(_ids)) {
                r = id128_get_machine_at(c->root_fd, &c->machine_id);
                if (r < 0 && !ERRNO_IS_NEG_MACHINE_ID_UNSET(r))
                        return log_error_errno(r, "Failed to get machine-id: %m");

                const char *e = secure_getenv("KERNEL_INSTALL_CONF_ROOT");
                r = boot_entry_token_ensure_at(
                                e ? XAT_FDROOT : c->root_fd,
                                e,
                                c->machine_id,
                                /* machine_id_is_random= */ false,
                                &c->entry_token_type,
                                &c->entry_token);
                if (r < 0)
                        return r;

                r = boot_config_find_oldest_commit(
                                &config,
                                c->entry_token,
                                &ids);
                if (r == -ENXIO)
                        return log_error_errno(r, "No suitable boot menu entry to delete found.");
                if (r == -EBUSY)
                        return log_error_errno(r, "Refusing to remove currently booted boot menu entry.");
                if (r < 0)
                        return log_error_errno(r, "Failed to find suitable oldest boot menu entry: %m");

                STRV_FOREACH(id, ids)
                        log_info("Will unlink '%s'.", *id);
        } else {
                ids = strv_copy(_ids);
                if (!ids)
                        return log_oom();
        }

        strv_sort_uniq(ids);

        r = 0;
        if (c->esp_path)
                RET_GATHER(r, unlink_entry(&config, x ?: c->esp_path, c->esp_fd, BOOT_ENTRY_ESP, ids, dry_run));

        if (c->xbootldr_path && c->xbootldr_devid != c->esp_devid)
                RET_GATHER(r, unlink_entry(&config, y ?: c->xbootldr_path, c->xbootldr_fd, BOOT_ENTRY_XBOOTLDR, ids, dry_run));

        return r;

}

int verb_unlink(int argc, char *argv[], uintptr_t _data, void *userdata) {
        int r;

        assert(argc < 3);

        if (arg_oldest != isempty(argv[1]))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Either an entry ID or --oldest= must be specified, not both.");

        const char *id = NULL;
        if (!isempty(argv[1])) {
                if (!efi_loader_entry_name_valid(argv[1]))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Boot entry ID is not valid: %s", argv[1]);

                id = argv[1];
        }

        _cleanup_(unlink_context_done) UnlinkContext c = UNLINK_CONTEXT_NULL;
        r = unlink_context_from_cmdline(&c);
        if (r < 0)
                return r;

        return run_unlink(&c, STRV_MAKE(id), arg_dry_run);
}

static JSON_DISPATCH_ENUM_DEFINE(json_dispatch_boot_entry_token_type, BootEntryTokenType, boot_entry_token_type_from_string);

typedef struct UnlinkParameters {
        UnlinkContext context;
        unsigned root_fd_index;
        sd_varlink *link;
        const char *id;
        bool oldest;
} UnlinkParameters;

static void unlink_parameters_done(UnlinkParameters *p) {
        assert(p);

        unlink_context_done(&p->context);
}

int vl_method_unlink(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        int r;

        assert(link);

        _cleanup_(unlink_parameters_done) UnlinkParameters p = {
                .context = UNLINK_CONTEXT_NULL,
                .root_fd_index = UINT_MAX,
                .link = link,
        };

        static const sd_json_dispatch_field dispatch_table[] = {
                { "rootFileDescriptor",   _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,               voffsetof(p, root_fd_index),            0 },
                { "rootDirectory",        SD_JSON_VARIANT_STRING,        json_dispatch_path,                  voffsetof(p, context.root),             0 },
                { "bootEntryTokenType",   SD_JSON_VARIANT_STRING,        json_dispatch_boot_entry_token_type, voffsetof(p, context.entry_token_type), 0 },
                { "id",                   SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string,       voffsetof(p, id),                       0 },
                { "oldest",               SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool,            voffsetof(p, oldest),                   0 },
                {},
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        /* Only allow oldest *or* id to be set */
        if (p.oldest == !!p.id)
                return sd_varlink_error_invalid_parameter_name(link, "id");
        if (p.id && !efi_loader_entry_name_valid(p.id))
                return sd_varlink_error_invalid_parameter_name(link, "id");

        if (p.root_fd_index != UINT_MAX) {
                p.context.root_fd = sd_varlink_peek_dup_fd(link, p.root_fd_index);
                if (p.context.root_fd < 0)
                        return log_debug_errno(p.context.root_fd, "Failed to acquire root fd from Varlink: %m");

                r = fd_verify_safe_flags_full(p.context.root_fd, O_DIRECTORY);
                if (r < 0)
                        return sd_varlink_error_invalid_parameter_name(link, "rootFileDescriptor");

                r = fd_verify_directory(p.context.root_fd);
                if (r < 0)
                        return log_debug_errno(r, "Specified file descriptor does not refer to a directory: %m");

                if (!p.context.root) {
                        r = fd_get_path(p.context.root_fd, &p.context.root);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to get path of file descriptor: %m");

                        if (empty_or_root(p.context.root))
                                p.context.root = mfree(p.context.root);
                }
        } else if (p.context.root) {
                p.context.root_fd = open(p.context.root, O_RDONLY|O_CLOEXEC|O_DIRECTORY);
                if (p.context.root_fd < 0)
                        return log_debug_errno(errno, "Failed to open '%s': %m", p.context.root);
        } else
                p.context.root_fd = XAT_FDROOT;

        if (p.context.entry_token_type < 0)
                p.context.entry_token_type = BOOT_ENTRY_TOKEN_AUTO;

        r = find_esp_and_warn_at_full(
                        p.context.root_fd,
                        /* path= */ NULL,
                        /* unprivileged_mode= */ false,
                        &p.context.esp_path,
                        &p.context.esp_fd,
                        /* ret_part= */ NULL,
                        /* ret_pstart= */ NULL,
                        /* ret_psize= */ NULL,
                        /* ret_uuid= */ NULL,
                        &p.context.esp_devid);
        if (r < 0 && r != -ENOKEY)
                return r;
        r = find_xbootldr_and_warn_at_full(
                        p.context.root_fd,
                        /* path= */ NULL,
                        /* unprivileged_mode= */ false,
                        &p.context.xbootldr_path,
                        &p.context.xbootldr_fd,
                        /* ret_uuid= */ NULL,
                        &p.context.xbootldr_devid);
        if (r < 0 && r != -ENOKEY)
                return r;

        /* Only if we found neither ESP nor XBOOTLDR let's fail. */
        if (!p.context.xbootldr_path && !p.context.esp_path)
                return sd_varlink_error(link, "io.systemd.BootControl.NoDollarBootFound", NULL);

        r = run_unlink(&p.context, STRV_MAKE(p.id), /* dry_run= */ false);
        if (r == -EUNATCH) /* no boot entry token is set */
                return sd_varlink_error(link, "io.systemd.BootControl.BootEntryTokenUnavailable", NULL);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, NULL);
}
