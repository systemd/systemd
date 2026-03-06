/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <fnmatch.h>

#include "alloc-util.h"
#include "bootctl.h"
#include "bootctl-unlink.h"
#include "bootspec.h"
#include "bootspec-util.h"
#include "chase.h"
#include "errno-util.h"
#include "hashmap.h"
#include "log.h"
#include "path-util.h"
#include "strv.h"

static int ref_file(Hashmap **known_files, const char *fn, int increment) {
        char *k = NULL;
        int n, r;

        assert(known_files);

        /* just gracefully ignore this. This way the caller doesn't have to verify whether the bootloader
         * entry is relevant. */
        if (!fn)
                return 0;

        n = PTR_TO_INT(hashmap_get2(*known_files, fn, (void**)&k));
        n += increment;

        assert(n >= 0);

        if (n == 0) {
                (void) hashmap_remove(*known_files, fn);
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
                r = hashmap_update(*known_files, fn, INT_TO_PTR(n));
                if (r < 0)
                        return r;
        }

        return n;
}

int boot_config_count_known_files(
                const BootConfig *config,
                const char* root,
                Hashmap **ret_known_files) {

        _cleanup_hashmap_free_ Hashmap *known_files = NULL;
        int r;

        assert(config);
        assert(ret_known_files);

        for (size_t i = 0; i < config->n_entries; i++) {
                const BootEntry *e = config->entries + i;

                if (!path_equal(e->root, root))
                        continue;

                r = ref_file(&known_files, e->kernel, +1);
                if (r < 0)
                        return r;
                r = ref_file(&known_files, e->efi, +1);
                if (r < 0)
                        return r;
                r = ref_file(&known_files, e->uki, +1);
                if (r < 0)
                        return r;
                STRV_FOREACH(s, e->initrd) {
                        r = ref_file(&known_files, *s, +1);
                        if (r < 0)
                                return r;
                }
                r = ref_file(&known_files, e->device_tree, +1);
                if (r < 0)
                        return r;
                STRV_FOREACH(s, e->device_tree_overlay) {
                        r = ref_file(&known_files, *s, +1);
                        if (r < 0)
                                return r;
                }
        }

        *ret_known_files = TAKE_PTR(known_files);

        return 0;
}

static void deref_unlink_file(Hashmap **known_files, const char *fn, const char *root) {
        _cleanup_free_ char *path = NULL;
        int r;

        assert(known_files);

        /* just gracefully ignore this. This way the caller doesn't
           have to verify whether the bootloader entry is relevant */
        if (!fn || !root)
                return;

        r = ref_file(known_files, fn, -1);
        if (r < 0)
                return (void) log_warning_errno(r, "Failed to deref \"%s\", ignoring: %m", fn);
        if (r > 0)
                return;

        if (arg_dry_run) {
                r = chase_and_access(fn, root, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS|CHASE_TRIGGER_AUTOFS, F_OK, &path);
                if (r < 0)
                        log_info_errno(r, "Unable to determine whether \"%s\" exists, ignoring: %m", fn);
                else
                        log_info("Would remove \"%s\"", path);
                return;
        }

        r = chase_and_unlink(fn, root, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS|CHASE_TRIGGER_AUTOFS, 0, &path);
        if (r >= 0)
                log_info("Removed \"%s\"", path);
        else if (r != -ENOENT)
                return (void) log_warning_errno(r, "Failed to remove \"%s\", ignoring: %m", fn);

        _cleanup_free_ char *d = NULL;
        if (path_extract_directory(fn, &d) >= 0 && !path_equal(d, "/")) {
                r = chase_and_unlink(d, root, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS|CHASE_TRIGGER_AUTOFS, AT_REMOVEDIR, NULL);
                if (r < 0 && !IN_SET(r, -ENOTEMPTY, -ENOENT))
                        log_warning_errno(r, "Failed to remove directory \"%s\", ignoring: %m", d);
        }
}

static int boot_config_find_in(const BootConfig *config, const char *root, const char *id) {
        assert(config);

        if (!root || !id)
                return -ENOENT;

        for (size_t i = 0; i < config->n_entries; i++)
                if (path_equal(config->entries[i].root, root) &&
                    fnmatch(id, config->entries[i].id, FNM_CASEFOLD) == 0)
                        return i;

        return -ENOENT;
}

static int unlink_entry(const BootConfig *config, const char *root, const char *id) {
        _cleanup_hashmap_free_ Hashmap *known_files = NULL;
        const BootEntry *e = NULL;
        int r;

        assert(config);

        r = boot_config_count_known_files(config, root, &known_files);
        if (r < 0)
                return log_error_errno(r, "Failed to count files in %s: %m", root);

        r = boot_config_find_in(config, root, id);
        if (r < 0)
                return 0; /* There is nothing to remove. */

        if (r == config->default_entry)
                log_warning("%s is the default boot entry", id);
        if (r == config->selected_entry)
                log_warning("%s is the selected boot entry", id);

        e = &config->entries[r];

        deref_unlink_file(&known_files, e->kernel, e->root);
        deref_unlink_file(&known_files, e->efi, e->root);
        deref_unlink_file(&known_files, e->uki, e->root);
        STRV_FOREACH(s, e->initrd)
                deref_unlink_file(&known_files, *s, e->root);
        deref_unlink_file(&known_files, e->device_tree, e->root);
        STRV_FOREACH(s, e->device_tree_overlay)
                deref_unlink_file(&known_files, *s, e->root);

        if (arg_dry_run)
                log_info("Would remove \"%s\"", e->path);
        else {
                r = chase_and_unlink(e->path, root, CHASE_PROHIBIT_SYMLINKS|CHASE_TRIGGER_AUTOFS, 0, NULL);
                if (r == -ENOENT)
                        return 0; /* Already removed? */
                if (r < 0)
                        return log_error_errno(r, "Failed to remove \"%s\": %m", e->path);

                log_info("Removed %s", e->path);
        }

        return 0;
}

int verb_unlink(int argc, char *argv[], void *userdata) {
        dev_t esp_devid = 0, xbootldr_devid = 0;
        int r;

        r = acquire_esp(/* unprivileged_mode= */ false,
                        /* graceful= */ false,
                        /* ret_part= */ NULL,
                        /* ret_pstart= */ NULL,
                        /* ret_psize= */ NULL,
                        /* ret_uuid= */ NULL,
                        &esp_devid);
        if (r == -EACCES) /* We really need the ESP path for this call, hence also log about access errors */
                return log_error_errno(r, "Failed to determine ESP location: %m");
        if (r < 0)
                return r;

        r = acquire_xbootldr(
                        /* unprivileged_mode= */ false,
                        /* ret_uuid= */ NULL,
                        &xbootldr_devid);
        if (r == -EACCES)
                return log_error_errno(r, "Failed to determine XBOOTLDR partition: %m");
        if (r < 0)
                return r;

        _cleanup_(boot_config_free) BootConfig config = BOOT_CONFIG_NULL;
        r = boot_config_load_and_select(
                        &config,
                        arg_esp_path,
                        esp_devid,
                        arg_xbootldr_path,
                        xbootldr_devid);
        if (r < 0)
                return r;

        r = 0;
        RET_GATHER(r, unlink_entry(&config, arg_esp_path, argv[1]));

        if (arg_xbootldr_path && xbootldr_devid != esp_devid)
                RET_GATHER(r, unlink_entry(&config, arg_xbootldr_path, argv[1]));

        return r;
}
