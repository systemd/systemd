/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "sd-json.h"
#include "sd-varlink.h"

#include "boot-entry.h"
#include "bootctl.h"
#include "bootctl-link.h"
#include "bootctl-util.h"
#include "bootspec.h"
#include "chase.h"
#include "copy.h"
#include "dirent-util.h"
#include "efi-loader.h"
#include "env-file.h"
#include "find-esp.h"
#include "fs-util.h"
#include "id128-util.h"
#include "io-util.h"
#include "json-util.h"
#include "kernel-config.h"
#include "kernel-image.h"
#include "log.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "recurse-dir.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "uki.h"
#include "utf8.h"

/* Keeps track of an "extra" file to assiciate with the type 1 entries to generate */
typedef struct ExtraFile {
        /* The source and the temporary file we copy it into */
        int source_fd, temp_fd;
        char *filename, *temp_filename;
} ExtraFile;

#define EXTRA_FILE_NULL                     \
        (const ExtraFile) {                 \
                .source_fd = -EBADF,        \
                .temp_fd = -EBADF,          \
        }

/* Keeps track a specific UKI profile we need to generate a type entry for */
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
        }

static void extra_file_done(ExtraFile *x, int entry_token_dir_fd) {
        assert(x);

        /* If the temporary filename is still initialized, we auto-delete the file on free */
        if (x->temp_filename && entry_token_dir_fd >= 0)
                (void) unlinkat(entry_token_dir_fd, x->temp_filename, /* flags= */ 0);

        x->source_fd = safe_close(x->source_fd);
        x->temp_fd = safe_close(x->temp_fd);
        x->filename = mfree(x->filename);
        x->temp_filename = mfree(x->temp_filename);
}

static void profile_done(Profile *p, int loader_entries_dir_fd) {
        assert(p);

        /* If the temporary filename is still initialized, we auto-delete the file on free */
        if (p->entry_temp_filename && loader_entries_dir_fd >= 0)
                (void) unlinkat(loader_entries_dir_fd, p->entry_temp_filename, /* flags= */ 0);

        p->entry_filename = mfree(p->entry_filename);
        p->entry_temp_filename = mfree(p->entry_temp_filename);
        p->entry_temp_fd = safe_close(p->entry_temp_fd);
}

static void link_context_done(LinkContext *c) {
        assert(c);

        FOREACH_ARRAY(x, c->extra, c->n_extra)
                extra_file_done(x, c->entry_token_dir_fd);

        c->extra = mfree(c->extra);
        c->n_extra = 0;

        FOREACH_ARRAY(p, c->profiles, c->n_profiles)
                profile_done(p, c->loader_entries_dir_fd);

        c->profiles = mfree(c->profiles);
        c->n_profiles = 0;

        if (c->kernel_temp_filename && c->entry_token_dir_fd >= 0)
                (void) unlinkat(c->entry_token_dir_fd, c->kernel_temp_filename, /* flags= */ 0);

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
}

static int link_context_from_cmdline(LinkContext *ret, const char *kernel) {
        int r;

        assert(ret);
        assert(kernel);

        _cleanup_(link_context_done) LinkContext b = LINK_CONTEXT_NULL;
        b.entry_token_type = arg_entry_token_type;
        b.tries_left = arg_tries_left;
        b.entry_commit = arg_entry_commit;

        if (strdup_to(&b.entry_token, arg_entry_token) < 0 ||
            strdup_to(&b.entry_title, arg_entry_title) < 0 ||
            strdup_to(&b.entry_version, arg_entry_version) < 0)
                return log_oom();

        if (arg_root) {
                b.root_fd = open(arg_root, O_CLOEXEC|O_DIRECTORY|O_PATH);
                if (b.root_fd < 0)
                        return log_error_errno(errno, "Failed to open root directory '%s': %m", arg_root);

                if (strdup_to(&b.root, arg_root) < 0)
                        return log_oom();
        } else
                b.root_fd = XAT_FDROOT;

        r = path_extract_filename(kernel, &b.kernel_filename);
        if (r < 0)
                return log_error_errno(r, "Failed to extract filename from kernel path '%s': %m", kernel);
        if (!efi_loader_entry_resource_filename_valid(b.kernel_filename))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Kernel '%s' is not suitable for reference in a boot menu entry.", kernel);
        b.kernel_fd = xopenat_full(AT_FDCWD, kernel, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY, XO_REGULAR, /* mode= */ MODE_INVALID);
        if (b.kernel_fd < 0)
                return log_error_errno(b.kernel_fd, "Faled to open kernel path '%s': %m", kernel);

        KernelImageType kit = _KERNEL_IMAGE_TYPE_INVALID;
        r = inspect_kernel(b.kernel_fd, /* path= */ NULL, &kit);
        if (r == -EBADMSG)
                return log_error_errno(r, "Kernel image '%s' is not valid.", kernel);
        if (r < 0)
                return log_error_errno(r, "Failed to determine kernel image type of '%s': %m", kernel);
        if (kit != KERNEL_IMAGE_TYPE_UKI)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Kernel image '%s' is not a UKI.", kernel);

        STRV_FOREACH(x, arg_extras) {
                _cleanup_free_ char *fn = NULL;
                r = path_extract_filename(*x, &fn);
                if (r < 0)
                        return log_error_errno(r, "Failed to extra filename from path '%s': %m", *x);
                if (r == O_DIRECTORY)
                        return log_error_errno(SYNTHETIC_ERRNO(EISDIR), "Extra file path '%s' does not refer to regular file.", *x);

                _cleanup_close_ int fd = -EBADF;
                fd = xopenat_full(AT_FDCWD, *x, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY, XO_REGULAR, /* mode= */ MODE_INVALID);
                if (fd < 0)
                        return log_error_errno(fd, "Failed to open '%s': %m", *x);

                if (!GREEDY_REALLOC(b.extra, b.n_extra+1))
                        return log_oom();

                b.extra[b.n_extra++] = (ExtraFile) {
                        .source_fd = TAKE_FD(fd),
                        .filename = TAKE_PTR(fn),
                        .temp_fd = -EBADF,
                };
        }

        r = acquire_xbootldr(
                        /* unprivileged_mode= */ false,
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

                        r = strdup_to(&b.dollar_boot_path, e);
                } else
                        r = strdup_to(&b.dollar_boot_path, arg_xbootldr_path);
                if (r < 0)
                        return log_oom();
        } else {
                /* No XBOOTLDR has been found, look for ESP */

                r = acquire_esp(/* unprivileged_mode= */ false,
                                /* graceful= */ false,
                                /* ret_part= */ NULL,
                                /* ret_pstart= */ NULL,
                                /* ret_psize= */ NULL,
                                /* ret_uuid= */ NULL,
                                /* ret_devid= */ NULL);
                /* If --graceful is specified and we can't find an ESP, handle this cleanly */
                if (r == -ENOKEY)
                        return log_error_errno(r, "Failed to find either XBOOTLDR nor ESP, cannot install kernel.");
                if (r < 0)
                        return r; /* About all other errors acquire_esp() logs on its own */

                assert(arg_esp_path);

                if (arg_root) {
                        const char *e = path_startswith(arg_esp_path, arg_root);
                        if (!e)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "ESP path '%s' not below specified root '%s', refusing.", arg_esp_path, arg_root);

                        r = strdup_to(&b.dollar_boot_path, e);
                } else
                        r = strdup_to(&b.dollar_boot_path, arg_esp_path);
                if (r < 0)
                        return log_oom();
        }

        *ret = TAKE_GENERIC(b, LinkContext, LINK_CONTEXT_NULL);
        return 0;
}

static int acquire_dollar_boot_fd(LinkContext *c) {
        int r;

        assert(c);

        if (c->dollar_boot_fd >= 0)
                return c->dollar_boot_fd;

        assert(c->dollar_boot_path);

        _cleanup_free_ char *j = path_join(c->root, c->dollar_boot_path);
        if (!j)
                return log_oom();

        r = chaseat(c->root_fd,
                    c->dollar_boot_path,
                    CHASE_AT_RESOLVE_IN_ROOT|CHASE_TRIGGER_AUTOFS|CHASE_MUST_BE_DIRECTORY,
                    /* ret_path= */ NULL,
                    &c->dollar_boot_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to open $BOOT '%s': %m", j);

        return c->dollar_boot_fd;
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
                int source_fd,
                const char *filename,
                int target_dir_fd,
                int *ret_tmpfile_fd,
                char **ret_tmpfile_filename) {

        int r;

        assert(source_fd >= 0);
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

        r = copy_bytes(source_fd, write_fd, UINT64_MAX, COPY_REFLINK|COPY_SEEK0_SOURCE);
        if (r < 0)
                return log_error_errno(r, "Failed to copy data into '%s': %m", filename);

        (void) copy_times(source_fd, write_fd, /* flags= */ 0);
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

        _cleanup_free_ char *good_name = NULL, *good_version = NULL, *good_sort_key = NULL, *os_version_id = NULL, *image_version = NULL;
        r = bootspec_extract_osrelease(
                        osrelease_text,
                        /* These three fields are used by systemd-stub for showing entries + sorting them */
                        &good_name,     /* human readable */
                        &good_version,  /* human readable */
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

        const char *version = image_version ?: os_version_id;

        /* Generate a new filename from the entry token, the commit number, and (optionally) the image/OS
         * version and (if non-zero) the profile number. */
        _cleanup_free_ char *filename = asprintf_safe("%s-commit_%" PRIu64, c->entry_token, c->entry_commit);
        if (!filename)
                return log_oom();
        if (version &&!strextend(&filename, ".", version))
                return log_oom();
        if (profile_nr > 0 && strextendf(&filename, ".p%u", profile_nr) < 0)
                return log_oom();
        if (!strextend(&filename, ".conf"))
                return log_oom();

        if (!filename_is_valid(filename) || string_has_cc(filename, /* ok= */ NULL) || !utf8_is_valid(filename))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to generate valid filename for the new commit: %s", filename);

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
                title = good_name;

        /* Do some validation that this will result in a valid type #1 entry before we write this out */
        if (string_has_cc(title, /* ok= */ NULL) || !utf8_is_valid(title))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to generate valid title for new commit: %s", title);
        if (string_has_cc(c->kernel_filename, /* ok= */ NULL) || !utf8_is_valid(c->kernel_filename))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "UKI filename is not suitable for inclusion in new commit: %s", c->kernel_filename);

        _cleanup_free_ char *text = NULL;
        if (asprintf(&text,
                     "title %s\n"
                     "uki /%s/%s\n"
                     "sort-key %s\n"
                     "version %" PRIu64 "%s%s\n",
                     title,
                     c->entry_token, c->kernel_filename,
                     good_sort_key,
                     c->entry_commit, isempty(version) ? "" : ".", strempty(version)) < 0)
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

        /* Already have an commit nr? */
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
                _cleanup_fclose_ FILE *f = NULL;

                /* We look for files named <token>-commit_<commit>[.<version>][.p<profile>].conf */

                if (!dirent_is_file(de))
                        continue;

                if (!efi_loader_entry_name_valid(de->d_name))
                        continue;

                const char *e = endswith_no_case(de->d_name, ".conf");
                if (!e)
                        continue;

                _cleanup_free_ char *b = strndup(de->d_name, e - de->d_name);
                if (!b)
                        return log_oom();

                char *a = startswith_no_case(b, c->entry_token);
                if (!a)
                        continue;
                a = startswith_no_case(a, "-commit_");
                if (!a)
                        continue;

                char *dot = strchr(a, '.');
                if (dot)
                        *dot = 0;

                uint64_t n;
                if (safe_atou64(a, &n) < 0)
                        continue;
                if (!entry_commit_valid(n))
                        continue;

                log_debug("Found existing commit %" PRIu64 ".", n);
                if (n > m)
                        m = n;
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

static int run_link(LinkContext *c) {
        int r;

        assert(c);

        r = link_context_pick_entry_token(c);
        if (r < 0)
                return r;

        assert(c->dollar_boot_fd < 0);
        c->dollar_boot_fd = acquire_dollar_boot_fd(c);
        if (c->dollar_boot_fd < 0)
                return c->dollar_boot_fd;

        _cleanup_free_ char *j = path_join(empty_to_root(c->root), c->dollar_boot_path);
        if (!j)
                return log_oom();

        assert(c->loader_entries_dir_fd < 0);
        r = chaseat(c->dollar_boot_fd,
                    "loader/entries",
                    CHASE_AT_RESOLVE_IN_ROOT|CHASE_PROHIBIT_SYMLINKS|CHASE_MKDIR_0755|CHASE_MUST_BE_DIRECTORY,
                    /* ret_path= */ NULL,
                    &c->loader_entries_dir_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to pin '/loader/entries' directory below '%s': %m", j);

        /* Remove any left-overs from an earlier run before we write new stuff */
        (void) clean_temporary_files(c->loader_entries_dir_fd);

        r = link_context_pick_entry_commit(c);
        if (r < 0)
                return r;

        assert(c->entry_token_dir_fd < 0);
        r = chaseat(c->dollar_boot_fd,
                    c->entry_token,
                    CHASE_AT_RESOLVE_IN_ROOT|CHASE_PROHIBIT_SYMLINKS|CHASE_MKDIR_0755|CHASE_MUST_BE_DIRECTORY,
                    /* ret_path= */ NULL,
                    &c->entry_token_dir_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to pin '/%s' directory below '%s': %m", c->entry_token, j);

        /* As above */
        (void) clean_temporary_files(c->entry_token_dir_fd);

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
                        c->kernel_filename,
                        c->entry_token_dir_fd,
                        &c->kernel_temp_fd,
                        &c->kernel_temp_filename);
        if (r < 0)
                return r;

        FOREACH_ARRAY(x, c->extra, c->n_extra) {
                r = begin_copy_file(
                                x->source_fd,
                                x->filename,
                                c->entry_token_dir_fd,
                                &x->temp_fd,
                                &x->temp_filename);
                if (r < 0)
                        return r;
        }

        /* We copied all files into place, but they are not materialized yet. Let's ensure the data hits the
         * disk before we proceed */
        (void) sync_everything();

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

        /* Finally, after all our resources are in place, also materialze the menu entry files themselves */
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
        }

        (void) sync_everything();
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

        extra_file_done(&p->extra_file, /* entry_token_dir_fd= */ -EBADF);
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
                        { "filename",             SD_JSON_VARIANT_STRING,        json_dispatch_filename, offsetof(ExtraParameters, extra_file.filename),  SD_JSON_MANDATORY },
                        { "kernelFileDescriptor", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,  offsetof(ExtraParameters, fd_index),             SD_JSON_MANDATORY },
                        {},
                };

                r = sd_json_dispatch(i, dispatch_table, /* flags= */ 0, &xp);
                if (r < 0)
                        return r;

                xp.extra_file.source_fd = sd_varlink_peek_dup_fd(c->link, xp.fd_index);
                if (xp.extra_file.source_fd < 0)
                        return log_debug_errno(xp.extra_file.source_fd, "Failed to acquire extra fd from Varlink: %m");

                r = fd_verify_safe_flags(xp.extra_file.source_fd);
                if (r < 0)
                        return sd_varlink_error_invalid_parameter_name(c->link, "extra");

                r = fd_verify_regular(xp.extra_file.source_fd);
                if (r < 0)
                        return log_debug_errno(r, "Failed to validate that the extra file file is a regular file descriptor: %m");

                if (!GREEDY_REALLOC(c->context.extra, c->context.n_extra+1))
                        return log_oom();

                c->context.extra[c->context.n_extra++] = TAKE_GENERIC(xp.extra_file, ExtraFile, EXTRA_FILE_NULL);
        }

        return 0;
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
                { "rootFileDescriptor",   _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,               voffsetof(p, root_fd_index),            0                 },
                { "rootDirectory",        SD_JSON_VARIANT_STRING,        json_dispatch_path,                  voffsetof(p, context.root),             0                 },
                { "bootEntryTokenType",   SD_JSON_VARIANT_STRING,        json_dispatch_boot_entry_token_type, voffsetof(p, context.entry_token_type), 0                 },
                { "entryTitle",           SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,             voffsetof(p, context.entry_title),      0                 },
                { "entryVersion",         SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,             voffsetof(p, context.entry_version),    0                 },
                { "entryCommit",          SD_JSON_VARIANT_INTEGER,       sd_json_dispatch_uint64,             voffsetof(p, context.entry_commit),     0                 },
                { "kernelFilename",       SD_JSON_VARIANT_STRING,        json_dispatch_filename,              voffsetof(p, context.kernel_filename),  SD_JSON_MANDATORY },
                { "kernelFileDescriptor", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,               voffsetof(p, context.kernel_fd),        SD_JSON_MANDATORY },
                { "extras",               SD_JSON_VARIANT_ARRAY,         dispatch_extras,                     0,                                      0                 },
                { "triesLeft",            _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,               voffsetof(p, context.tries_left),       0                 },
                {},
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

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

        if (p.context.entry_title && !efi_loader_entry_title_valid(p.context.entry_title))
                return sd_varlink_error_invalid_parameter_name(link, "entryTitle");

        if (p.context.entry_version && !version_is_valid_versionspec(p.context.entry_version))
                return sd_varlink_error_invalid_parameter_name(link, "entryVersion");

        if (p.context.entry_commit == UINT64_MAX)
                return sd_varlink_error_invalid_parameter_name(link, "entryCommit");

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
        r = inspect_kernel(p.context.kernel_fd, /* path= */ NULL, &kit);
        if (r == -EBADMSG)
                return sd_varlink_error(link, "io.systemd.BootControl.InvalidKernelImage", NULL);
        if (r < 0)
                return r;
        if (kit != KERNEL_IMAGE_TYPE_UKI)
                return sd_varlink_error(link, "io.systemd.BootControl.InvalidKernelImage", NULL);

        r = find_xbootldr_and_warn_at(
                        p.context.root_fd,
                        /* path= */ NULL,
                        /* unprivileged_mode= */ false,
                        &p.context.dollar_boot_path);
        if (r < 0) {
                if (r != -ENOKEY)
                        return r;

                /* No XBOOTLDR found, let's look for ESP then. */

                r = find_esp_and_warn_at(
                                p.context.root_fd,
                                /* path= */ NULL,
                                /* unprivileged_mode= */ false,
                                &p.context.dollar_boot_path);
                if (r == -ENOKEY)
                        return sd_varlink_error(link, "io.systemd.BootControl.NoDollarBootFound", NULL);
                if (r < 0)
                        return r;
        }

        r = run_link(&p.context);
        if (r == -EUNATCH) /* no boot entry token is set */
                return sd_varlink_error(link, "io.systemd.BootControl.BootEntryTokenUnavailable", NULL);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, NULL);
}
