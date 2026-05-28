/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <unistd.h>

#include "sd-json.h"
#include "sd-varlink.h"

#include "boot-entry.h"
#include "bootctl.h"
#include "bootctl-link.h"
#include "bootctl-unlink.h"
#include "bootspec.h"
#include "bootspec-util.h"
#include "chase.h"
#include "copy.h"
#include "dirent-util.h"
#include "efi-loader.h"
#include "env-file.h"
#include "errno-util.h"
#include "fd-util.h"
#include "find-esp.h"
#include "format-util.h"
#include "fs-util.h"
#include "hashmap.h"
#include "id128-util.h"
#include "io-util.h"
#include "iovec-util.h"
#include "json-util.h"
#include "kernel-image.h"
#include "log.h"
#include "parse-argument.h"
#include "path-util.h"
#include "recurse-dir.h"
#include "set.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "uki.h"
#include "utf8.h"
#include "varlink-util.h"
#include "vpick.h"

/* Keeps track of an "extra" file to associate with the type 1 entries to generate */
typedef struct ExtraFile {
        /* The source and the temporary file we copy it into */
        int source_fd, temp_fd;
        char *filename, *temp_filename;
        struct iovec data; /* Alternative to 'source_fd': literal data */
} ExtraFile;

#define EXTRA_FILE_NULL                     \
        (const ExtraFile) {                 \
                .source_fd = -EBADF,        \
                .temp_fd = -EBADF,          \
        }

/* Keeps track of a specific UKI profile we need to generate a type entry for */
typedef struct Profile {
        /* The final and the temporary file for the .conf entry file, while we write it */
        char *entry_filename, *entry_temp_filename;
        int entry_temp_fd;
} Profile;

typedef struct LinkContext {
        char *root;
        int root_fd;

        sd_id128_t machine_id;
        BootEntryTokenType entry_token_type;
        char *entry_token;

        char *entry_title;
        char *entry_version;
        uint64_t entry_commit;

        BootEntrySource dollar_boot_source;
        char *dollar_boot_path;
        int dollar_boot_fd;
        int entry_token_dir_fd;
        int loader_entries_dir_fd;

        /* The UKI source and temporary target while we write it. Note that for now we exclusively support
         * UKIs, but let's keep things somewhat generic to keep options open for the future. */
        char *kernel_filename, *kernel_temp_filename;
        int kernel_fd, kernel_temp_fd;

        ExtraFile *extra;
        size_t n_extra;

        Profile *profiles;
        size_t n_profiles;

        unsigned tries_left;

        uint64_t keep_free;

        char **linked_ids;
} LinkContext;

#define LINK_CONTEXT_NULL                                               \
        (LinkContext) {                                                 \
                .root_fd = -EBADF,                                      \
                .entry_token_type = _BOOT_ENTRY_TOKEN_TYPE_INVALID,     \
                .dollar_boot_fd = -EBADF,                               \
                .loader_entries_dir_fd = -EBADF,                        \
                .entry_token_dir_fd = -EBADF,                           \
                .kernel_fd = -EBADF,                                    \
                .kernel_temp_fd = -EBADF,                               \
                .tries_left = UINT_MAX,                                 \
                .keep_free = UINT64_MAX,                                \
        }

static void extra_file_done(ExtraFile *x) {
        assert(x);

        x->source_fd = safe_close(x->source_fd);
        x->temp_fd = safe_close(x->temp_fd);
        x->filename = mfree(x->filename);
        x->temp_filename = mfree(x->temp_filename);
        iovec_done(&x->data);
}

static void profile_done(Profile *p) {
        assert(p);

        p->entry_filename = mfree(p->entry_filename);
        p->entry_temp_filename = mfree(p->entry_temp_filename);
        p->entry_temp_fd = safe_close(p->entry_temp_fd);
}

static void link_context_unlink_temporary(LinkContext *c) {
        assert(c);

        if (c->kernel_temp_filename) {
                if (c->entry_token_dir_fd >= 0)
                        (void) unlinkat(c->entry_token_dir_fd, c->kernel_temp_filename, /* flags= */ 0);

                c->kernel_temp_fd = safe_close(c->kernel_temp_fd);
                c->kernel_temp_filename = mfree(c->kernel_temp_filename);
        }

        FOREACH_ARRAY(x, c->extra, c->n_extra) {
                if (!x->temp_filename)
                        continue;

                if (c->entry_token_dir_fd >= 0)
                        (void) unlinkat(c->entry_token_dir_fd, x->temp_filename, /* flags= */ 0);

                x->temp_fd = safe_close(x->temp_fd);
                x->temp_filename = mfree(x->temp_filename);
        }

        FOREACH_ARRAY(p, c->profiles, c->n_profiles) {
                if (!p->entry_temp_filename)
                        continue;

                if (c->loader_entries_dir_fd >= 0)
                        (void) unlinkat(c->loader_entries_dir_fd, p->entry_temp_filename, /* flags= */ 0);

                p->entry_temp_fd = safe_close(p->entry_temp_fd);
                p->entry_temp_filename = mfree(p->entry_temp_filename);
        }
}

static void link_context_clear_profiles(LinkContext *c) {
        assert(c);

        FOREACH_ARRAY(p, c->profiles, c->n_profiles)
                profile_done(p);

        c->profiles = mfree(c->profiles);
        c->n_profiles = 0;
}

static void link_context_done(LinkContext *c) {
        assert(c);

        link_context_unlink_temporary(c);

        FOREACH_ARRAY(x, c->extra, c->n_extra)
                extra_file_done(x);

        c->extra = mfree(c->extra);
        c->n_extra = 0;

        link_context_clear_profiles(c);

        c->kernel_filename = mfree(c->kernel_filename);
        c->kernel_fd = safe_close(c->kernel_fd);
        c->kernel_temp_filename = mfree(c->kernel_temp_filename);
        c->kernel_temp_fd = safe_close(c->kernel_temp_fd);

        c->root = mfree(c->root);
        c->root_fd = safe_close(c->root_fd);

        c->entry_token = mfree(c->entry_token);
        c->entry_title = mfree(c->entry_title);
        c->entry_version = mfree(c->entry_version);

        c->dollar_boot_path = mfree(c->dollar_boot_path);
        c->dollar_boot_fd = safe_close(c->dollar_boot_fd);
        c->entry_token_dir_fd = safe_close(c->entry_token_dir_fd);
        c->loader_entries_dir_fd = safe_close(c->loader_entries_dir_fd);

        c->linked_ids = strv_free(c->linked_ids);
}

static int link_context_acquire_dollar_boot(LinkContext *b) {
        int r;

        assert(b);

        r = acquire_xbootldr(
                        /* unprivileged_mode= */ false,
                        &b->dollar_boot_fd,
                        /* ret_uuid= */ NULL,
                        /* ret_devid= */ NULL);
        if (r < 0)
                return r;
        if (r > 0) { /* XBOOTLDR has been found */
                assert(arg_xbootldr_path);

                if (arg_root) {
                        const char *e = path_startswith(arg_xbootldr_path, arg_root);
                        if (!e)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "XBOOTLDR path '%s' not below specified root '%s', refusing.", arg_xbootldr_path, arg_root);

                        r = strdup_to(&b->dollar_boot_path, e);
                } else
                        r = strdup_to(&b->dollar_boot_path, arg_xbootldr_path);
                if (r < 0)
                        return log_oom();

                b->dollar_boot_source = BOOT_ENTRY_XBOOTLDR;
        } else {
                /* No XBOOTLDR has been found, look for ESP */

                r = acquire_esp(/* unprivileged_mode= */ false,
                                /* graceful= */ false,
                                &b->dollar_boot_fd,
                                /* ret_part= */ NULL,
                                /* ret_pstart= */ NULL,
                                /* ret_psize= */ NULL,
                                /* ret_uuid= */ NULL,
                                /* ret_devid= */ NULL);
                if (r < 0)
                        return r;

                assert(arg_esp_path);

                if (arg_root) {
                        const char *e = path_startswith(arg_esp_path, arg_root);
                        if (!e)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "ESP path '%s' not below specified root '%s', refusing.", arg_esp_path, arg_root);

                        r = strdup_to(&b->dollar_boot_path, e);
                } else
                        r = strdup_to(&b->dollar_boot_path, arg_esp_path);
                if (r < 0)
                        return log_oom();

                b->dollar_boot_source = BOOT_ENTRY_ESP;
        }

        return 0;
}

/* Fills the bits of a LinkContext that both "bootctl link" and "bootctl link-auto" derive from the global
 * command line options (everything except the kernel image and extra files themselves). */
static int link_context_from_cmdline_common(LinkContext *b) {
        assert(b);

        b->entry_token_type = arg_entry_token_type;
        b->tries_left = arg_tries_left;
        b->entry_commit = arg_entry_commit;
        b->keep_free = arg_keep_free;

        if (strdup_to(&b->entry_token, arg_entry_token) < 0 ||
            strdup_to(&b->entry_title, arg_entry_title) < 0 ||
            strdup_to(&b->entry_version, arg_entry_version) < 0)
                return log_oom();

        if (arg_root) {
                b->root_fd = open(arg_root, O_CLOEXEC|O_DIRECTORY|O_PATH);
                if (b->root_fd < 0)
                        return log_error_errno(errno, "Failed to open root directory '%s': %m", arg_root);

                if (strdup_to(&b->root, arg_root) < 0)
                        return log_oom();
        } else
                b->root_fd = XAT_FDROOT;

        return 0;
}

/* Appends the files passed via --extra= on the command line as extra resources to the link context. */
static int link_context_add_cmdline_extras(LinkContext *b) {
        int r;

        assert(b);

        STRV_FOREACH(x, arg_extras) {
                _cleanup_free_ char *fn = NULL;
                r = path_extract_filename(*x, &fn);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract filename from path '%s': %m", *x);
                if (r == O_DIRECTORY)
                        return log_error_errno(SYNTHETIC_ERRNO(EISDIR), "Extra file path '%s' does not refer to regular file.", *x);

                _cleanup_close_ int fd = xopenat_full(AT_FDCWD, *x, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY, XO_REGULAR, /* mode= */ MODE_INVALID);
                if (fd < 0)
                        return log_error_errno(fd, "Failed to open '%s': %m", *x);

                if (!GREEDY_REALLOC(b->extra, b->n_extra+1))
                        return log_oom();

                b->extra[b->n_extra++] = (ExtraFile) {
                        .source_fd = TAKE_FD(fd),
                        .filename = TAKE_PTR(fn),
                        .temp_fd = -EBADF,
                };
        }

        return 0;
}

static int link_context_from_cmdline(LinkContext *ret, const char *kernel) {
        int r;

        assert(ret);
        assert(kernel);

        _cleanup_(link_context_done) LinkContext b = LINK_CONTEXT_NULL;
        r = link_context_from_cmdline_common(&b);
        if (r < 0)
                return r;

        r = path_extract_filename(kernel, &b.kernel_filename);
        if (r < 0)
                return log_error_errno(r, "Failed to extract filename from kernel path '%s': %m", kernel);
        if (!efi_loader_entry_resource_filename_valid(b.kernel_filename))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Kernel '%s' is not suitable for reference in a boot menu entry.", kernel);
        b.kernel_fd = xopenat_full(AT_FDCWD, kernel, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY, XO_REGULAR, /* mode= */ MODE_INVALID);
        if (b.kernel_fd < 0)
                return log_error_errno(b.kernel_fd, "Failed to open kernel path '%s': %m", kernel);

        KernelImageType kit = _KERNEL_IMAGE_TYPE_INVALID;
        r = inspect_kernel(b.kernel_fd, /* filename= */ NULL, &kit);
        if (r == -EBADMSG)
                return log_error_errno(r, "Kernel image '%s' is not valid.", kernel);
        if (r < 0)
                return log_error_errno(r, "Failed to determine kernel image type of '%s': %m", kernel);
        if (kit != KERNEL_IMAGE_TYPE_UKI)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Kernel image '%s' is not a UKI.", kernel);

        r = link_context_add_cmdline_extras(&b);
        if (r < 0)
                return r;

        r = link_context_acquire_dollar_boot(&b);
        if (r < 0)
                return r;

        *ret = TAKE_GENERIC(b, LinkContext, LINK_CONTEXT_NULL);
        return 0;
}

static int link_context_load_etc_machine_id(LinkContext *c) {
        int r;

        assert(c);

        r = id128_get_machine_at(c->root_fd, &c->machine_id);
        if (ERRNO_IS_NEG_MACHINE_ID_UNSET(r)) /* Not set or empty */
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to get machine-id: %m");

        log_debug("Loaded machine ID %s from '%s/etc/machine-id'.", SD_ID128_TO_STRING(c->machine_id), strempty(c->root));
        return 0;
}

static int link_context_pick_entry_token(LinkContext *c) {
        int r;

        assert(c);

        r = link_context_load_etc_machine_id(c);
        if (r < 0)
                return r;

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

        log_debug("Using entry token: %s", c->entry_token);
        return 0;
}

static int begin_copy_file(
                int source_fd,               /* Either the source fd is specified, or the 'data' below, not both */
                const struct iovec *data,
                const char *filename,
                int target_dir_fd,
                int *ret_tmpfile_fd,
                char **ret_tmpfile_filename) {

        int r;

        assert(filename);
        assert(target_dir_fd >= 0);
        assert(ret_tmpfile_fd);
        assert(ret_tmpfile_filename);

        if (faccessat(target_dir_fd, filename, F_OK, AT_SYMLINK_NOFOLLOW) < 0) {
                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to check if '%s' exists already: %m", filename);
        } else {
                log_info("'%s' already in place, not copying.", filename);

                *ret_tmpfile_fd = -EBADF;
                *ret_tmpfile_filename = NULL;
                return 0;
        }

        _cleanup_free_ char *t = NULL;
        _cleanup_close_ int write_fd = open_tmpfile_linkable_at(target_dir_fd, filename, O_WRONLY|O_CLOEXEC, &t);
        if (write_fd < 0)
                return log_error_errno(write_fd, "Failed to create '%s': %m", filename);

        CLEANUP_TMPFILE_AT(target_dir_fd, t);

        if (source_fd >= 0) {
                r = copy_bytes(source_fd, write_fd, UINT64_MAX, COPY_REFLINK|COPY_SEEK0_SOURCE);
                if (r < 0)
                        return log_error_errno(r, "Failed to copy data into '%s': %m", filename);

                (void) copy_times(source_fd, write_fd, /* flags= */ 0);
        } else if (iovec_is_set(data)) {
                r = loop_write(write_fd, data->iov_base, data->iov_len);
                if (r < 0)
                        return log_error_errno(r, "Failed to write data into '%s': %m", filename);
        }

        (void) fchmod(write_fd, 0644);

        *ret_tmpfile_fd = TAKE_FD(write_fd);
        *ret_tmpfile_filename = TAKE_PTR(t);

        return 1;
}

static int begin_write_entry_file(
                LinkContext *c,
                unsigned profile_nr,
                const char *osrelease_text,
                const char *profile_text,
                Profile *ret) {

        int r;

        assert(c);
        assert(osrelease_text);
        assert(ret);

        assert(c->entry_token);
        assert(c->kernel_filename);
        assert(c->loader_entries_dir_fd >= 0);

        _cleanup_free_ char *good_name = NULL, *good_sort_key = NULL, *os_version_id = NULL, *image_version = NULL;
        r = bootspec_extract_osrelease(
                        osrelease_text,
                        /* These three fields are used by systemd-stub for showing entries + sorting them */
                        &good_name,     /* human readable */
                        /* ret_good_version= */ NULL,
                        &good_sort_key,
                        /* These four fields are the raw fields provided in os-release */
                        /* ret_os_id= */ NULL,
                        &os_version_id,
                        /* ret_image_id= */ NULL,
                        &image_version);
        if (r < 0)
                return log_error_errno(r, "Failed to extract name/version/sort-key from os-release data from unified kernel image, refusing.");

        assert(good_name); /* This one is the only field guaranteed to be defined once the above succeeds */

        _cleanup_free_ char *profile_id = NULL, *profile_title = NULL;
        if (profile_text) {
                r = parse_env_data(
                                profile_text, /* size= */ SIZE_MAX,
                                ".profile",
                                "ID", &profile_id,
                                "TITLE", &profile_title);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse profile data from unified kernel image: %m");
        }

        const char *version = c->entry_version ?: image_version ?: os_version_id;

        _cleanup_free_ char *filename = NULL;
        r = boot_entry_make_commit_filename(
                        c->entry_token,
                        c->entry_commit,
                        version,
                        profile_nr,
                        c->tries_left,
                        &filename);
        if (r < 0)
                return log_error_errno(r, "Failed to generate filename for entry file: %m");

        if (faccessat(c->loader_entries_dir_fd, filename, F_OK, AT_SYMLINK_NOFOLLOW) < 0) {
                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to check if '%s' exists: %m", filename);
        } else
                return log_error_errno(SYNTHETIC_ERRNO(EEXIST), "Boot menu entry '%s' exists already, refusing.", filename);

        log_info("Writing new boot menu entry '%s/loader/entries/%s' for profile %u.", c->dollar_boot_path, filename, profile_nr);

        _cleanup_free_ char *t = NULL;
        _cleanup_close_ int write_fd = open_tmpfile_linkable_at(c->loader_entries_dir_fd, filename, O_WRONLY|O_CLOEXEC, &t);
        if (write_fd < 0)
                return log_error_errno(write_fd, "Failed to create '%s': %m", filename);

        CLEANUP_TMPFILE_AT(c->loader_entries_dir_fd, t);

        _cleanup_free_ char *_title = NULL;
        const char *title;
        if (profile_title || profile_id) {
                _title = strjoin(c->entry_title ?: good_name, " (", profile_title ?: profile_id, ")");
                if (!_title)
                        return log_oom();

                title = _title;
        } else if (profile_nr > 0) {
                _title = asprintf_safe("%s (Profile #%u)", c->entry_title ?: good_name, profile_nr);
                if (!_title)
                        return log_oom();

                title = _title;
        } else
                title = c->entry_title ?: good_name;

        /* Do some validation that this will result in a valid type #1 entry before we write this out */
        if (string_has_cc(title, /* ok= */ NULL) || !utf8_is_valid(title))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to generate valid title for new commit: %s", title);
        if (string_has_cc(c->kernel_filename, /* ok= */ NULL) || !utf8_is_valid(c->kernel_filename))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "UKI filename is not suitable for inclusion in new commit: %s", c->kernel_filename);

        _cleanup_free_ char *text = NULL;
        if (asprintf(&text,
                     "title %s\n"
                     "uki /%s/%s\n"
                     "version %" PRIu64 "%s%s\n",
                     title,
                     c->entry_token, c->kernel_filename,
                     c->entry_commit, isempty(version) ? "" : ".", strempty(version)) < 0)
                return log_oom();

        if (good_sort_key && strextendf(&text, "sort-key %s\n", good_sort_key) < 0)
                return log_oom();

        if (profile_nr > 0 && strextendf(&text, "profile %u\n", profile_nr) < 0)
                return log_oom();

        if (!sd_id128_is_null(c->machine_id) && strextendf(&text, "machine-id " SD_ID128_FORMAT_STR "\n", SD_ID128_FORMAT_VAL(c->machine_id)) < 0)
                return log_oom();

        FOREACH_ARRAY(x, c->extra, c->n_extra) {
                if (string_has_cc(x->filename, /* ok= */ NULL) || !utf8_is_valid(x->filename))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Extra filename is not suitable for inclusion in new commit: %s", x->filename);

                if (strextendf(&text,
                               "extra /%s/%s\n",
                               c->entry_token,
                               x->filename) < 0)
                        return log_oom();
        }

        r = loop_write(write_fd, text, /* nbytes= */ SIZE_MAX);
        if (r < 0)
                return log_error_errno(r, "Failed to write entry file: %m");

        *ret = (Profile) {
                .entry_filename = TAKE_PTR(filename),
                .entry_temp_filename = TAKE_PTR(t),
                .entry_temp_fd = TAKE_FD(write_fd),
        };

        return 0;
}

static int finalize_file(
                const char *filename,
                int target_dir_fd,
                int tmpfile_fd,
                const char *tmpfile_filename) {

        int r;

        assert(filename);
        assert(target_dir_fd >= 0);

        if (tmpfile_fd < 0) /* If the file already existed, we don't move anything into place. */
                return 0;

        r = link_tmpfile_at(tmpfile_fd, target_dir_fd, tmpfile_filename, filename, LINK_TMPFILE_REPLACE|LINK_TMPFILE_SYNC);
        if (r < 0)
                return log_error_errno(r, "Failed to move from '%s' into place: %m", filename);

        log_info("Installed '%s' into place.", filename);
        return 1;
}

static int link_context_pick_entry_commit(LinkContext *c) {
        int r;

        assert(c);
        assert(c->loader_entries_dir_fd >= 0);
        assert(c->entry_token);

        /* Already have a commit nr? */
        if (c->entry_commit != 0)
                return 0;

        _cleanup_close_ int opened_fd = fd_reopen(c->loader_entries_dir_fd, O_DIRECTORY|O_CLOEXEC);
        if (opened_fd < 0)
                return log_error_errno(opened_fd, "Failed to reopen loader entries dir: %m");

        _cleanup_free_ DirectoryEntries *dentries = NULL;
        r = readdir_all(opened_fd, RECURSE_DIR_IGNORE_DOT, &dentries);
        if (r < 0)
                return log_error_errno(r, "Failed to read loader entries directory: %m");

        uint64_t m = 0; /* largest commit number seen */
        FOREACH_ARRAY(i, dentries->entries, dentries->n_entries) {
                const struct dirent *de = *i;

                /* We look for files named <token>-commit_<commit>[.<version>][.p<profile>].conf */

                if (!dirent_is_file(de))
                        continue;

                if (!efi_loader_entry_name_valid(de->d_name))
                        continue;

                _cleanup_free_ char *et = NULL;
                uint64_t ec;
                r = boot_entry_parse_commit_filename(de->d_name, &et, &ec);
                if (r < 0) {
                        log_debug_errno(r, "Cannot extract entry token/commit number from '%s', ignoring.", de->d_name);
                        continue;
                }

                if (!streq(c->entry_token, et))
                        continue;

                log_debug("Found existing commit %" PRIu64 ".", ec);
                if (ec > m)
                        m = ec;
        }

        assert(m < UINT64_MAX);
        uint64_t next = m + 1;

        if (!entry_commit_valid(next))
                return log_error_errno(SYNTHETIC_ERRNO(E2BIG), "Too many commits already in place, refusing.");

        log_debug("Picking commit %" PRIu64 " for new commit.", next);
        c->entry_commit = next;
        return 0;
}

static int clean_temporary_files(int fd) {
        int r;

        assert(fd >= 0);

        /* Before we create any new files let's clear any possible left-overs from a previous run. We look
         * specifically for all temporary files whose name starts with .# because that's what we create, via
         * open_tmpfile_linkable_at().
         *
         * Ideally, this would not be necessary because O_TMPFILE would ensure that files are not
         * materialized before they are fully written. However, vfat currently does not support O_TMPFILE,
         * hence we need to clean things up manually. */

        _cleanup_close_ int dfd = fd_reopen(fd, O_CLOEXEC|O_DIRECTORY);
        if (dfd < 0)
                return log_error_errno(dfd, "Failed to open directory: %m");

        _cleanup_free_ DirectoryEntries *de = NULL;
        r = readdir_all(dfd, RECURSE_DIR_ENSURE_TYPE, &de);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate contents of directory: %m");

        FOREACH_ARRAY(i, de->entries, de->n_entries) {
                struct dirent *e = *i;

                if (e->d_type != DT_REG)
                        continue;

                if (!startswith_no_case(e->d_name, ".#"))
                        continue;

                if (unlinkat(dfd, e->d_name, /* flags= */ 0) < 0 && errno != ENOENT)
                        log_warning_errno(errno, "Failed to remove temporary file '%s', ignoring: %m", e->d_name);
        }

        return 0;
}

static int link_context_unlink_oldest(LinkContext *c) {
        int r;

        assert(c);

        /* We only load the entries from the partition we want to make space on (!) */
        _cleanup_(boot_config_free) BootConfig config = BOOT_CONFIG_NULL;
        r = boot_config_load_and_select(
                        &config,
                        c->root,
                        c->dollar_boot_source == BOOT_ENTRY_ESP ? c->dollar_boot_path : NULL,
                        /* esp_devid= */ 0,
                        c->dollar_boot_source == BOOT_ENTRY_XBOOTLDR ? c->dollar_boot_path : NULL,
                        /* xbootldr_devid= */ 0);
        if (r < 0)
                return r;

        _cleanup_(strv_freep) char **ids = NULL;
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

        _cleanup_(hashmap_freep) Hashmap *known_files = NULL;
        r = boot_config_count_known_files(&config, c->dollar_boot_source, &known_files);
        if (r < 0)
                return r;

        int ret = 0;
        STRV_FOREACH(id, ids) {
                const BootEntry *entry = boot_config_find_entry(&config, *id);
                if (!entry)
                        continue;

                RET_GATHER(ret, boot_entry_unlink(entry, c->dollar_boot_path, c->dollar_boot_fd, known_files, /* dry_run= */ false));
        }

        if (ret < 0)
                return ret;

        return 1;
}

static int verify_keep_free(LinkContext *c) {
        int r;

        assert(c);

        if (c->keep_free == 0)
                return 0;

        uint64_t f;
        r = vfs_free_bytes(ASSERT_FD(c->dollar_boot_fd), &f);
        if (r < 0)
                return log_error_errno(r, "Failed to statvfs() the $BOOT partition: %m");

        if (f < c->keep_free)
                return log_error_errno(
                                SYNTHETIC_ERRNO(EDQUOT),
                                "Not installing boot menu entry, free space after installation of %s would be below configured keep free size %s.",
                                FORMAT_BYTES(f), FORMAT_BYTES(c->keep_free));

        return 0;
}

static int run_link_now(LinkContext *c) {
        int r;

        assert(c);
        assert(c->dollar_boot_fd >= 0);

        _cleanup_free_ char *j = path_join(empty_to_root(c->root), c->dollar_boot_path);
        if (!j)
                return log_oom();

        if (c->loader_entries_dir_fd < 0) {
                r = chaseat(/* root_fd= */ c->dollar_boot_fd,
                            /* dir_fd= */ c->dollar_boot_fd,
                            "loader/entries",
                            CHASE_PROHIBIT_SYMLINKS|CHASE_MKDIR_0755|CHASE_MUST_BE_DIRECTORY,
                            /* ret_path= */ NULL,
                            &c->loader_entries_dir_fd);
                if (r < 0)
                        return log_error_errno(r, "Failed to pin '/loader/entries' directory below '%s': %m", j);
        }

        /* Remove any left-overs from an earlier run before we write new stuff */
        (void) clean_temporary_files(c->loader_entries_dir_fd);

        r = link_context_pick_entry_commit(c);
        if (r < 0)
                return r;

        log_info("Will create commit %" PRIu64 ".", c->entry_commit);

        if (c->entry_token_dir_fd < 0) {
                r = chaseat(/* root_fd= */ c->dollar_boot_fd,
                            /* dir_fd= */ c->dollar_boot_fd,
                            c->entry_token,
                            CHASE_PROHIBIT_SYMLINKS|CHASE_MKDIR_0755|CHASE_MUST_BE_DIRECTORY,
                            /* ret_path= */ NULL,
                            &c->entry_token_dir_fd);
                if (r < 0)
                        return log_error_errno(r, "Failed to pin '/%s' directory below '%s': %m", c->entry_token, j);
        }

        /* As above */
        (void) clean_temporary_files(c->entry_token_dir_fd);

        /* Synchronize everything to disk before we verify the disk space, to ensure the counters are
         * accurate (some file systems delay accurate counters) */
        (void) syncfs(c->dollar_boot_fd);

        /* Before we start copying things, let's see if there's even a remote chance to get this copied
         * in. Note that we do not try to be overly smart here, i.e. we do not try to calculate how much
         * extra space we'll need here. Doing that is not trivial since after all the same resources can be
         * referenced by multiple entries, which makes copying them multiple times unnecessary. */
        r = verify_keep_free(c);
        if (r < 0)
                return r;

        for (unsigned p = 0; p < UNIFIED_PROFILES_MAX; p++) {
                _cleanup_free_ char *osrelease = NULL, *profile = NULL;
                r = pe_find_uki_sections(c->kernel_fd, j, p, &osrelease, &profile, /* ret_cmdline= */ NULL);
                if (r < 0)
                        return r;
                if (r == 0) /* this profile does not exist, we are done */
                        break;

                if (!GREEDY_REALLOC(c->profiles, c->n_profiles+1))
                        return log_oom();

                r = begin_write_entry_file(
                                c,
                                p,
                                osrelease,
                                profile,
                                c->profiles + c->n_profiles);
                if (r < 0)
                        return r;

                c->n_profiles++;
        }

        if (c->n_profiles == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "UKI with no valid profile, refusing.");

        r = begin_copy_file(
                        c->kernel_fd,
                        /* data= */ NULL,
                        c->kernel_filename,
                        c->entry_token_dir_fd,
                        &c->kernel_temp_fd,
                        &c->kernel_temp_filename);
        if (r < 0)
                return r;

        FOREACH_ARRAY(x, c->extra, c->n_extra) {
                r = begin_copy_file(
                                x->source_fd,
                                &x->data,
                                x->filename,
                                c->entry_token_dir_fd,
                                &x->temp_fd,
                                &x->temp_filename);
                if (r < 0)
                        return r;
        }

        /* We copied all files into place, but they are not materialized yet. Let's ensure the data hits the
         * disk before we proceed */
        (void) syncfs(c->dollar_boot_fd);

        /* Before we materialize things, let's ensure the space to keep free is not taken */
        r = verify_keep_free(c);
        if (r < 0)
                return r;

        /* We successfully managed to put all resources we need into the $BOOT partition. Now, let's
         * "materialize" them by linking them into the file system. Before this point we'd get rid of every
         * file we created on error again. But from now on we switch modes: what we manage to move into place
         * we leave in place even on error. These are not lost resources after all, the GC logic implemented
         * by "bootctl cleanup" will take care of removing things again if necessary. */

        r = finalize_file(
                        c->kernel_filename,
                        c->entry_token_dir_fd,
                        c->kernel_temp_fd,
                        c->kernel_temp_filename);
        if (r < 0)
                return r;

        c->kernel_temp_fd = safe_close(c->kernel_temp_fd);
        c->kernel_temp_filename = mfree(c->kernel_temp_filename);

        FOREACH_ARRAY(x, c->extra, c->n_extra) {
                r = finalize_file(
                                x->filename,
                                c->entry_token_dir_fd,
                                x->temp_fd,
                                x->temp_filename);
                if (r < 0)
                        return r;

                x->temp_fd = safe_close(x->temp_fd);
                x->temp_filename = mfree(x->temp_filename);
        }

        /* Finally, after all our resources are in place, also materialize the menu entry files themselves */
        FOREACH_ARRAY(profile, c->profiles, c->n_profiles) {
                r = finalize_file(
                                profile->entry_filename,
                                c->loader_entries_dir_fd,
                                profile->entry_temp_fd,
                                profile->entry_temp_filename);
                if (r < 0)
                        return r;

                profile->entry_temp_fd = safe_close(profile->entry_temp_fd);
                profile->entry_temp_filename = mfree(profile->entry_temp_filename);

                _cleanup_free_ char *stripped = NULL;
                r = boot_filename_extract_tries(
                                profile->entry_filename,
                                &stripped,
                                /* ret_tries_left= */ NULL,
                                /* ret_tries_done= */ NULL);
                if (r < 0)
                        return log_warning_errno(r, "Failed to extract tries counters from id '%s'", profile->entry_filename);

                if (strv_consume(&c->linked_ids, TAKE_PTR(stripped)) < 0)
                        return log_oom();
        }

        (void) syncfs(c->dollar_boot_fd);
        return 0;
}

static int run_link(LinkContext *c) {
        int r;

        assert(c);
        assert(c->dollar_boot_path);
        assert(c->dollar_boot_fd >= 0);

        if (c->keep_free == UINT64_MAX)
                c->keep_free = KEEP_FREE_BYTES_DEFAULT;

        r = link_context_pick_entry_token(c);
        if (r < 0)
                return r;

        unsigned n_removals = 0;
        for (;;) {
                r = run_link_now(c);
                if (r < 0) {
                        if (!ERRNO_IS_NEG_DISK_SPACE(r))
                                return r;
                } else
                        break;

                log_notice("Attempt to link entry failed due to exhausted disk space, trying to remove oldest boot menu entry.");

                link_context_unlink_temporary(c);
                link_context_clear_profiles(c);

                if (link_context_unlink_oldest(c) <= 0) {
                        log_warning("Attempted to make space on $BOOT, but this failed, attempt to link entry failed.");
                        return r; /* propagate original error */
                }

                /* Close entry token dir here, quite possible the unlinking above might have removed it too, in case it was empty */
                c->entry_token_dir_fd = safe_close(c->entry_token_dir_fd);

                log_info("Removing oldest boot menu entry succeeded, will retry to create boot loader menu entry.");
                n_removals++;
        }

        _cleanup_free_ char *j = strv_join(c->linked_ids, "', '");
        if (!j)
                return log_oom();

        if (n_removals > 0)
                log_info("Successfully installed boot loader entries '%s', after removing %u old entries.", j, n_removals);
        else
                log_info("Successfully installed boot loader entries '%s'.", j);

        return 0;
}

int verb_link(int argc, char *argv[], uintptr_t data, void *userdata) {
        int r;

        assert(argc == 2);

        _cleanup_free_ char *x = NULL;
        r = parse_path_argument(argv[1], /* suppress_root= */ false, &x);
        if (r < 0)
                return r;

        _cleanup_(link_context_done) LinkContext c = LINK_CONTEXT_NULL;
        r = link_context_from_cmdline(&c, x);
        if (r < 0)
                return r;

        return run_link(&c);
}

/* Directories (relative to the operative root) below which "bootctl link-auto" looks for a staged UKI and
 * extra resources, in decreasing priority order. /var/lib/systemd/uki/ is where systemd-sysupdate stages
 * downloaded resources; the others follow the usual configuration search path precedence, with
 * /var/lib/ slotted in just below the volatile locations and above the vendor trees. */
static const char* const uki_auto_dirs[] = {
        "etc/systemd/uki",
        "run/systemd/uki",
        "var/lib/systemd/uki",
        "usr/local/lib/systemd/uki",
        "usr/lib/systemd/uki",
};

static const PickFilter pick_filter_uki = {
        .type_mask = UINT32_C(1) << DT_REG,
        .architecture = _ARCHITECTURE_INVALID,
        .suffix = ".efi",
};

/* The recognized suffixes of extra resources we pick up alongside the UKI. Each may appear as a plain file
 * (e.g. foo.sysext.raw) or as a versioned directory (e.g. foo.sysext.raw.v/) resolved via the vpick
 * mechanism. */
static const char* const auto_link_extra_suffixes[] = {
        ".sysext.raw",
        ".confext.raw",
        ".cred",
};

static int link_context_add_extra(LinkContext *c, int dir_fd, const char *path, const char *filename) {
        assert(c);
        assert(dir_fd >= 0);
        assert(path);
        assert(filename);

        if (!efi_loader_entry_resource_filename_valid(filename))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Extra file '%s' is not suitable for reference in a boot menu entry, refusing.", filename);

        _cleanup_close_ int fd = xopenat_full(dir_fd, path, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY, XO_REGULAR, /* mode= */ MODE_INVALID);
        if (fd < 0)
                return log_error_errno(fd, "Failed to open extra file '%s': %m", path);

        _cleanup_free_ char *fn = strdup(filename);
        if (!fn)
                return log_oom();

        if (!GREEDY_REALLOC(c->extra, c->n_extra + 1))
                return log_oom();

        c->extra[c->n_extra++] = (ExtraFile) {
                .source_fd = TAKE_FD(fd),
                .filename = TAKE_PTR(fn),
                .temp_fd = -EBADF,
        };

        return 0;
}

/* Adds the extra resources found in <uki_dir_fd>/extras.d/ to the link context. The 'seen' set tracks the
 * logical resource names already added by a higher-priority directory, so the same resource appearing in
 * multiple directories is taken from the highest-priority one only. */
static int link_context_add_extras(LinkContext *c, int uki_dir_fd, Set **seen) {
        int r;

        assert(c);
        assert(uki_dir_fd >= 0);
        assert(seen);

        _cleanup_close_ int extras_dir_fd = openat(uki_dir_fd, "extras.d", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        if (extras_dir_fd < 0) {
                if (errno == ENOENT)
                        return 0;
                return log_error_errno(errno, "Failed to open extras.d/ directory: %m");
        }

        _cleanup_free_ DirectoryEntries *des = NULL;
        r = readdir_all(extras_dir_fd, RECURSE_DIR_IGNORE_DOT|RECURSE_DIR_ENSURE_TYPE|RECURSE_DIR_SORT, &des);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate extras.d/ directory: %m");

        FOREACH_ARRAY(i, des->entries, des->n_entries) {
                struct dirent *de = *i;

                if (!IN_SET(de->d_type, DT_DIR, DT_REG))
                        continue;

                FOREACH_ELEMENT(suffix, auto_link_extra_suffixes) {
                        _cleanup_free_ char *dot_v = strjoin(*suffix, ".v");
                        if (!dot_v)
                                return log_oom();

                        bool versioned;
                        _cleanup_free_ char *key = NULL;
                        if (endswith(de->d_name, *suffix)) {
                                if (de->d_type != DT_REG)
                                        continue;

                                versioned = false;
                                key = strdup(de->d_name);
                        } else if (endswith(de->d_name, dot_v)) {

                                if (de->d_type != DT_DIR)
                                        continue;

                                /* The dedup key is the directory entry name with any trailing ".v" stripped, so that
                                 * a plain file and a versioned directory of the same resource collapse, and a
                                 * higher-priority directory wins. */
                                versioned = true;
                                key = strndup(de->d_name, strlen(de->d_name) - strlen(".v"));
                        } else
                                continue;
                        if (!key)
                                return log_oom();

                        if (set_contains(*seen, key))
                                break;

                        if (versioned) {
                                /* A versioned directory: resolve the best version via vpick, relative to the
                                 * extras directory fd. We deliberately do not honour boot-counting suffixes
                                 * here. */
                                _cleanup_(pick_result_done) PickResult pick = PICK_RESULT_NULL;
                                const PickFilter filter = {
                                        .type_mask = UINT32_C(1) << DT_REG,
                                        .architecture = _ARCHITECTURE_INVALID,
                                        .suffix = *suffix,
                                };

                                r = path_pick(/* root_path= */ NULL,
                                              /* root_fd= */ c->root_fd,
                                              /* dir_fd= */ extras_dir_fd,
                                              de->d_name,
                                              &filter,
                                              /* n_filters= */ 1,
                                              /* flags= */ 0,
                                              &pick);
                                if (r == -ENOENT || r == 0) {
                                        log_debug("No matching entry in versioned directory '%s', skipping.", de->d_name);
                                        break;
                                }
                                if (r < 0)
                                        return log_error_errno(r, "Failed to pick version in '%s': %m", de->d_name);

                                _cleanup_free_ char *fn = NULL;
                                r = path_extract_filename(pick.path, &fn);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to extract filename from '%s': %m", pick.path);

                                r = link_context_add_extra(c, extras_dir_fd, pick.path, fn);
                        } else
                                /* A plain file. */
                                r = link_context_add_extra(c, extras_dir_fd, de->d_name, de->d_name);
                        if (r < 0)
                                return r;

                        r = set_ensure_consume(seen, &string_hash_ops_free, TAKE_PTR(key));
                        if (r < 0)
                                return log_oom();

                        break;
                }
        }

        return 0;
}

/* Looks for a UKI (kernel.efi, or the best version in kernel.efi.v/) in the directory referenced by
 * uki_dir_fd and, if found, fills c->kernel_fd and c->kernel_filename. Returns 1 if found, 0 if not, and a
 * negative errno on error. We deliberately do not honour boot-counting suffixes here. */
static int link_context_find_kernel(LinkContext *c, int uki_dir_fd) {
        int r;

        assert(c);
        assert(uki_dir_fd >= 0);

        _cleanup_free_ char *filename = NULL;
        _cleanup_close_ int kernel_fd = xopenat_full(uki_dir_fd, "kernel.efi", O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY, XO_REGULAR, /* mode= */ MODE_INVALID);
        if (kernel_fd == -ENOENT) {
                _cleanup_(pick_result_done) PickResult pick = PICK_RESULT_NULL;
                r = path_pick(/* root_path= */ NULL,
                              /* root_fd= */ c->root_fd,
                              /* dir_fd= */ uki_dir_fd,
                              "kernel.efi.v",
                              &pick_filter_uki,
                              /* n_filters= */ 1,
                              /* flags= */ 0,
                              &pick);
                if (r == -ENOENT || r == 0)
                        return 0;
                if (r < 0)
                        return log_error_errno(r, "Failed to pick UKI version in 'kernel.efi.v': %m");

                r = path_extract_filename(pick.path, &filename);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract filename from '%s': %m", pick.path);

                kernel_fd = xopenat_full(uki_dir_fd, pick.path, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY, XO_REGULAR, /* mode= */ MODE_INVALID);
                if (kernel_fd < 0)
                        return log_error_errno(kernel_fd, "Failed to open UKI '%s': %m", pick.path);
        } else if (kernel_fd < 0)
                return log_error_errno(kernel_fd, "Failed to open 'kernel.efi': %m");
        else {
                filename = strdup("kernel.efi");
                if (!filename)
                        return log_oom();
        }

        if (!efi_loader_entry_resource_filename_valid(filename))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "UKI '%s' is not suitable for reference in a boot menu entry.", filename);

        KernelImageType kit = _KERNEL_IMAGE_TYPE_INVALID;
        r = inspect_kernel(kernel_fd, /* filename= */ NULL, &kit);
        if (r == -EBADMSG)
                return log_error_errno(r, "UKI '%s' is not valid.", filename);
        if (r < 0)
                return log_error_errno(r, "Failed to determine kernel image type of '%s': %m", filename);
        if (kit != KERNEL_IMAGE_TYPE_UKI)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Image '%s' is not a UKI.", filename);

        c->kernel_fd = TAKE_FD(kernel_fd);
        c->kernel_filename = TAKE_PTR(filename);
        return 1;
}

/* Discovers the staged UKI and extra resources below the uki_auto_dirs[] (relative to the already-pinned
 * c->root_fd) and fills c->kernel_fd, c->kernel_filename and c->extra[] accordingly. The directories are
 * searched in priority order: the UKI is taken from the first directory that has one, and extra resources
 * are combined across all directories with higher-priority directories winning on conflicts. Returns 1 if a
 * UKI was found, 0 if there is nothing to link, and a negative errno on error. */
static int link_context_discover_resources(LinkContext *c) {
        _cleanup_set_free_ Set *seen = NULL;
        int r;

        assert(c);

        FOREACH_ELEMENT(dir, uki_auto_dirs) {
                _cleanup_close_ int uki_dir_fd = chase_and_openat(
                                /* root_fd= */ c->root_fd,
                                /* dir_fd= */ c->root_fd,
                                *dir,
                                CHASE_MUST_BE_DIRECTORY,
                                O_RDONLY|O_DIRECTORY|O_CLOEXEC,
                                /* ret_path= */ NULL);
                if (uki_dir_fd == -ENOENT)
                        continue;
                if (uki_dir_fd < 0)
                        return log_error_errno(uki_dir_fd, "Failed to open '%s': %m", *dir);

                /* Take the UKI from the first (highest-priority) directory that has one. */
                if (c->kernel_fd < 0) {
                        r = link_context_find_kernel(c, uki_dir_fd);
                        if (r < 0)
                                return r;
                }

                r = link_context_add_extras(c, uki_dir_fd, &seen);
                if (r < 0)
                        return r;
        }

        if (c->kernel_fd < 0) {
                log_debug("No UKI found in any of the search directories, nothing to link.");
                return 0;
        }

        return 1;
}

int verb_link_auto(int argc, char *argv[], uintptr_t data, void *userdata) {
        int r;

        assert(argc == 1);

        _cleanup_(link_context_done) LinkContext c = LINK_CONTEXT_NULL;
        r = link_context_from_cmdline_common(&c);
        if (r < 0)
                return r;

        r = link_context_discover_resources(&c);
        if (r < 0)
                return r;
        if (r == 0) {
                log_info("No UKI staged for linking, nothing to do.");
                return 0;
        }

        /* In addition to the auto-discovered resources, also honour any files passed via --extra=. */
        r = link_context_add_cmdline_extras(&c);
        if (r < 0)
                return r;

        r = link_context_acquire_dollar_boot(&c);
        if (r < 0)
                return r;

        return run_link(&c);
}

static JSON_DISPATCH_ENUM_DEFINE(json_dispatch_boot_entry_token_type, BootEntryTokenType, boot_entry_token_type_from_string);

typedef struct LinkParameters {
        LinkContext context;
        unsigned root_fd_index;
        unsigned kernel_fd_index;
        sd_varlink *link;
} LinkParameters;

static void link_parameters_done(LinkParameters *p) {
        assert(p);

        link_context_done(&p->context);
}

typedef struct ExtraParameters {
        ExtraFile extra_file;
        unsigned fd_index;
} ExtraParameters;

static void extra_parameters_done(ExtraParameters *p) {
        assert(p);

        extra_file_done(&p->extra_file);
}

static int json_dispatch_loader_entry_resource_filename(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        char **n = ASSERT_PTR(userdata);
        const char *filename;
        int r;

        assert(variant);

        r = json_dispatch_const_filename(name, variant, flags, &filename);
        if (r < 0)
                return r;

        if (filename && !efi_loader_entry_resource_filename_valid(filename))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a valid boot entry resource filename.", strna(name));

        if (free_and_strdup(n, filename) < 0)
                return json_log_oom(variant, flags);

        return 0;
}

static int dispatch_extras(const char *name, sd_json_variant *v, sd_json_dispatch_flags_t flags, void *userdata) {
        LinkParameters *c = ASSERT_PTR(userdata);
        int r;

        if (!sd_json_variant_is_array(v))
                return json_log(v, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an array.", strna(name));

        sd_json_variant *i;
        JSON_VARIANT_ARRAY_FOREACH(i, v) {
                _cleanup_(extra_parameters_done) ExtraParameters xp = {
                        .extra_file = EXTRA_FILE_NULL,
                        .fd_index = UINT_MAX,
                };

                static const sd_json_dispatch_field dispatch_table[] = {
                        { "filename",       SD_JSON_VARIANT_STRING,        json_dispatch_loader_entry_resource_filename, offsetof(ExtraParameters, extra_file.filename),  SD_JSON_MANDATORY },
                        { "fileDescriptor", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,                        offsetof(ExtraParameters, fd_index),             0                 },
                        { "data",           SD_JSON_VARIANT_STRING,        json_dispatch_unbase64_iovec,                 offsetof(ExtraParameters, extra_file.data),      0                 },
                        {},
                };

                r = sd_json_dispatch(i, dispatch_table, /* flags= */ 0, &xp);
                if (r < 0)
                        return r;

                if (iovec_is_set(&xp.extra_file.data) == (xp.fd_index != UINT_MAX))
                        return sd_varlink_error_invalid_parameter_name(c->link, name);
                if (xp.fd_index != UINT_MAX) {
                        xp.extra_file.source_fd = sd_varlink_peek_dup_fd(c->link, xp.fd_index);
                        if (xp.extra_file.source_fd < 0)
                                return log_debug_errno(xp.extra_file.source_fd, "Failed to acquire extra fd from Varlink: %m");

                        r = fd_verify_safe_flags(xp.extra_file.source_fd);
                        if (r < 0)
                                return sd_varlink_error_invalid_parameter_name(c->link, name);

                        r = fd_verify_regular(xp.extra_file.source_fd);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to validate that the extra file is a regular file descriptor: %m");
                }

                if (!GREEDY_REALLOC(c->context.extra, c->context.n_extra+1))
                        return log_oom();

                c->context.extra[c->context.n_extra++] = TAKE_GENERIC(xp.extra_file, ExtraFile, EXTRA_FILE_NULL);
        }

        return 0;
}

/* Resolves the root_fd of the LinkContext from the dispatched Link/LinkAuto parameters, fills in the
 * boot entry token type default, and validates the entry title/version/commit fields. Returns 0 on success,
 * non-zero (Varlink error or negative errno) otherwise. */
static int vl_link_prepare(sd_varlink *link, LinkParameters *p) {
        int r;

        assert(link);
        assert(p);

        if (p->root_fd_index != UINT_MAX) {
                p->context.root_fd = sd_varlink_peek_dup_fd(link, p->root_fd_index);
                if (p->context.root_fd < 0)
                        return log_debug_errno(p->context.root_fd, "Failed to acquire root fd from Varlink: %m");

                r = fd_verify_safe_flags_full(p->context.root_fd, O_DIRECTORY);
                if (r < 0)
                        return sd_varlink_error_invalid_parameter_name(link, "rootFileDescriptor");

                r = fd_verify_directory(p->context.root_fd);
                if (r < 0)
                        return log_debug_errno(r, "Specified file descriptor does not refer to a directory: %m");

                if (!p->context.root) {
                        r = fd_get_path(p->context.root_fd, &p->context.root);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to get path of file descriptor: %m");

                        if (empty_or_root(p->context.root))
                                p->context.root = mfree(p->context.root);
                }
        } else if (p->context.root) {
                p->context.root_fd = open(p->context.root, O_RDONLY|O_CLOEXEC|O_DIRECTORY);
                if (p->context.root_fd < 0)
                        return log_debug_errno(errno, "Failed to open '%s': %m", p->context.root);
        } else
                p->context.root_fd = XAT_FDROOT;

        if (p->context.entry_token_type < 0)
                p->context.entry_token_type = BOOT_ENTRY_TOKEN_AUTO;

        if (p->context.entry_title && !efi_loader_entry_title_valid(p->context.entry_title))
                return sd_varlink_error_invalid_parameter_name(link, "entryTitle");

        if (p->context.entry_version && !version_is_valid_versionspec(p->context.entry_version))
                return sd_varlink_error_invalid_parameter_name(link, "entryVersion");

        if (p->context.entry_commit != 0 && !entry_commit_valid(p->context.entry_commit))
                return sd_varlink_error_invalid_parameter_name(link, "entryCommit");

        return 0;
}

/* Resolves $BOOT, runs the link operation and sends the reply. Expects the kernel and extra files to already
 * be set up in the context. If with_ids is true the reply carries the list of created entry IDs (as expected
 * by Link()/LinkAuto()), otherwise an empty reply is sent (as expected by
 * io.systemd.SysUpdate.Notify.OnCompletedUpdate(), which declares no output fields). */
static int vl_link_finish(sd_varlink *link, LinkParameters *p, bool with_ids) {
        int r;

        assert(link);
        assert(p);

        r = find_xbootldr_and_warn_at(
                        p->context.root_fd,
                        /* path= */ NULL,
                        /* unprivileged_mode= */ false,
                        &p->context.dollar_boot_path,
                        &p->context.dollar_boot_fd);
        if (r < 0) {
                if (r != -ENOKEY)
                        return r;

                /* No XBOOTLDR found, let's look for ESP then. */

                r = find_esp_and_warn_at(
                                p->context.root_fd,
                                /* path= */ NULL,
                                /* unprivileged_mode= */ false,
                                &p->context.dollar_boot_path,
                                &p->context.dollar_boot_fd);
                if (r == -ENOKEY)
                        return sd_varlink_error(link, "io.systemd.BootControl.NoDollarBootFound", NULL);
                if (r < 0)
                        return r;

                p->context.dollar_boot_source = BOOT_ENTRY_ESP;
        } else
                p->context.dollar_boot_source = BOOT_ENTRY_XBOOTLDR;

        r = run_link(&p->context);
        if (r == -EUNATCH) /* no boot entry token is set */
                return sd_varlink_error(link, "io.systemd.BootControl.BootEntryTokenUnavailable", NULL);
        if (r < 0)
                return r;

        if (with_ids)
                return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_STRV("ids", p->context.linked_ids));

        return sd_varlink_reply(link, NULL);
}

int vl_method_link(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        int r;

        assert(link);

        _cleanup_(link_parameters_done) LinkParameters p = {
                .context = LINK_CONTEXT_NULL,
                .root_fd_index = UINT_MAX,
                .kernel_fd_index = UINT_MAX,
                .link = link,
        };

        static const sd_json_dispatch_field dispatch_table[] = {
                { "rootFileDescriptor",   _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,                        voffsetof(p, root_fd_index),            0                 },
                { "rootDirectory",        SD_JSON_VARIANT_STRING,        json_dispatch_path,                           voffsetof(p, context.root),             0                 },
                { "bootEntryTokenType",   SD_JSON_VARIANT_STRING,        json_dispatch_boot_entry_token_type,          voffsetof(p, context.entry_token_type), 0                 },
                { "entryTitle",           SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,                      voffsetof(p, context.entry_title),      0                 },
                { "entryVersion",         SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,                      voffsetof(p, context.entry_version),    0                 },
                { "entryCommit",          SD_JSON_VARIANT_INTEGER,       sd_json_dispatch_uint64,                      voffsetof(p, context.entry_commit),     0                 },
                { "kernelFilename",       SD_JSON_VARIANT_STRING,        json_dispatch_loader_entry_resource_filename, voffsetof(p, context.kernel_filename),  SD_JSON_MANDATORY },
                { "kernelFileDescriptor", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,                        voffsetof(p, kernel_fd_index),          SD_JSON_MANDATORY },
                { "extraFiles",           SD_JSON_VARIANT_ARRAY,         dispatch_extras,                              0,                                      0                 },
                { "triesLeft",            _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,                        voffsetof(p, context.tries_left),       0                 },
                { "keepFree",             _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,                      voffsetof(p, context.keep_free),        0                 },
                {},
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        r = vl_link_prepare(link, &p);
        if (r != 0)
                return r;

        p.context.kernel_fd = sd_varlink_peek_dup_fd(link, p.kernel_fd_index);
        if (p.context.kernel_fd < 0)
                return log_debug_errno(p.context.kernel_fd, "Failed to acquire kernel fd from Varlink: %m");

        r = fd_verify_safe_flags(p.context.kernel_fd);
        if (r < 0)
                return sd_varlink_error_invalid_parameter_name(link, "kernelFileDescriptor");
        r = fd_verify_regular(p.context.kernel_fd);
        if (r < 0)
                return log_debug_errno(r, "Failed to validate that kernel image file is a regular file descriptor: %m");

        /* Refuse non-UKIs for now. */
        KernelImageType kit = _KERNEL_IMAGE_TYPE_INVALID;
        r = inspect_kernel(p.context.kernel_fd, /* filename= */ NULL, &kit);
        if (r == -EBADMSG)
                return sd_varlink_error(link, "io.systemd.BootControl.InvalidKernelImage", NULL);
        if (r < 0)
                return r;
        if (kit != KERNEL_IMAGE_TYPE_UKI)
                return sd_varlink_error(link, "io.systemd.BootControl.InvalidKernelImage", NULL);

        return vl_link_finish(link, &p, /* with_ids= */ true);
}

int vl_method_link_auto(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        int r;

        assert(link);

        _cleanup_(link_parameters_done) LinkParameters p = {
                .context = LINK_CONTEXT_NULL,
                .root_fd_index = UINT_MAX,
                .kernel_fd_index = UINT_MAX,
                .link = link,
        };

        static const sd_json_dispatch_field dispatch_table[] = {
                { "rootFileDescriptor", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,               voffsetof(p, root_fd_index),            0 },
                { "rootDirectory",      SD_JSON_VARIANT_STRING,        json_dispatch_path,                  voffsetof(p, context.root),             0 },
                { "bootEntryTokenType", SD_JSON_VARIANT_STRING,        json_dispatch_boot_entry_token_type, voffsetof(p, context.entry_token_type), 0 },
                { "entryTitle",         SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,             voffsetof(p, context.entry_title),      0 },
                { "entryVersion",       SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,             voffsetof(p, context.entry_version),    0 },
                { "entryCommit",        SD_JSON_VARIANT_INTEGER,       sd_json_dispatch_uint64,             voffsetof(p, context.entry_commit),     0 },
                { "triesLeft",          _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,               voffsetof(p, context.tries_left),       0 },
                { "keepFree",           _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,             voffsetof(p, context.keep_free),        0 },
                {},
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        r = vl_link_prepare(link, &p);
        if (r != 0)
                return r;

        r = link_context_discover_resources(&p.context);
        if (r < 0)
                return r;
        if (r == 0) /* Nothing staged for linking. */
                return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_STRV("ids", STRV_EMPTY));

        return vl_link_finish(link, &p, /* with_ids= */ true);
}

int vl_method_on_completed_update(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        int r;

        assert(link);

        /* Only honour update notifications if they come from root */
        r = varlink_check_privileged_peer(link);
        if (r < 0)
                return r;

        /* Triggered by systemd-sysupdate after an update completed. We deliberately ignore all parameters
         * (we don't even dispatch them) and behave like LinkAuto() with default parameters: discover the
         * staged UKI and extra resources and link them in. Contrary to LinkAuto() we reply without any
         * parameters, matching the io.systemd.SysUpdate.Notify.OnCompletedUpdate() signature. */

        _cleanup_(link_parameters_done) LinkParameters p = {
                .context = LINK_CONTEXT_NULL,
                .root_fd_index = UINT_MAX,
                .kernel_fd_index = UINT_MAX,
                .link = link,
        };

        r = vl_link_prepare(link, &p);
        if (r != 0)
                return r;

        r = link_context_discover_resources(&p.context);
        if (r < 0)
                return r;
        if (r == 0) /* Nothing staged for linking. */
                return sd_varlink_reply(link, NULL);

        return vl_link_finish(link, &p, /* with_ids= */ false);
}
