/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <unistd.h>

#include "alloc-util.h"
#include "boot-entry.h"
#include "bootctl.h"
#include "bootctl-install.h"
#include "bootctl-random-seed.h"
#include "bootctl-util.h"
#include "chase.h"
#include "copy.h"
#include "dirent-util.h"
#include "efi-api.h"
#include "efi-fundamental.h"
#include "efivars.h"
#include "env-file.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "glyph-util.h"
#include "id128-util.h"
#include "io-util.h"
#include "kernel-config.h"
#include "log.h"
#include "openssl-util.h"
#include "parse-argument.h"
#include "path-util.h"
#include "pe-binary.h"
#include "rm-rf.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "sync-util.h"
#include "time-util.h"
#include "tmpfile-util.h"
#include "umask-util.h"
#include "utf8.h"

typedef enum InstallOperation {
        INSTALL_NEW,
        INSTALL_UPDATE,
        INSTALL_REMOVE,
        INSTALL_TEST,
        _INSTALL_OPERATION_MAX,
        _INSTALL_OPERATION_INVALID = -1,
} InstallOperation;

typedef struct InstallContext {
        InstallOperation operation;
        bool graceful;
        char *root;
        int root_fd;
        sd_id128_t machine_id;
        char *install_layout;
        BootEntryTokenType entry_token_type;
        char *entry_token;
        int make_entry_directory; /* tri-state */
        InstallSource install_source;
        char *esp_path;
        int esp_fd;
        uint32_t esp_part;
        uint64_t esp_pstart;
        uint64_t esp_psize;
        sd_id128_t esp_uuid;
        char *xbootldr_path;
        int xbootldr_fd;
        X509 *secure_boot_certificate;
        EVP_PKEY *secure_boot_private_key;
        int touch_variables;
} InstallContext;

#define INSTALL_CONTEXT_NULL                                            \
        (InstallContext) {                                              \
                .operation = _INSTALL_OPERATION_INVALID,                \
                .root_fd = -EBADF,                                      \
                .entry_token_type = _BOOT_ENTRY_TOKEN_TYPE_INVALID,     \
                .make_entry_directory = -1,                             \
                .install_source = _INSTALL_SOURCE_INVALID,              \
                .esp_part = UINT32_MAX,                                 \
                .esp_pstart = UINT64_MAX,                               \
                .esp_psize = UINT64_MAX,                                \
                .esp_fd = -EBADF,                                       \
                .xbootldr_fd = -EBADF,                                  \
                .touch_variables = -1,                                  \
        }

static void install_context_done(InstallContext *c) {
        assert(c);

        c->root_fd = safe_close(c->root_fd);
        c->install_layout = mfree(c->install_layout);
        c->entry_token = mfree(c->entry_token);
        c->esp_path = mfree(c->esp_path);
        c->esp_fd = safe_close(c->esp_fd);
        c->xbootldr_path = mfree(c->xbootldr_path);
        c->xbootldr_fd = safe_close(c->xbootldr_fd);
        if (c->secure_boot_private_key) {
                EVP_PKEY_free(c->secure_boot_private_key);
                c->secure_boot_private_key = NULL;
        }
        if (c->secure_boot_certificate) {
                X509_free(c->secure_boot_certificate);
                c->secure_boot_certificate = NULL;
        }
}

static int install_context_from_cmdline(
                InstallContext *c,
                InstallOperation operation) {

        int r;

        assert(c);
        assert(operation >= 0);
        assert(operation < _INSTALL_OPERATION_MAX);

        _cleanup_(install_context_done) InstallContext b = {
                .operation = operation,
                .graceful = arg_graceful() == ARG_GRACEFUL_FORCE ||
                            (operation == INSTALL_UPDATE && arg_graceful() != ARG_GRACEFUL_NO),
                .root_fd = -EBADF,
                .machine_id = arg_machine_id,
                .entry_token_type = arg_entry_token_type,
                .make_entry_directory = arg_make_entry_directory,
                .install_source = arg_install_source,
                .esp_part = UINT32_MAX,
                .esp_pstart = UINT64_MAX,
                .esp_psize = UINT64_MAX,
                .esp_fd = -EBADF,
                .xbootldr_fd = -EBADF,
                .touch_variables = -1,
        };

        if (strdup_to(&b.entry_token, arg_entry_token) < 0 ||
            strdup_to(&b.root, arg_root) < 0 ||
            strdup_to(&b.install_layout, arg_install_layout) < 0 ||
            strdup_to(&b.esp_path, arg_esp_path) < 0 ||
            strdup_to(&b.xbootldr_path, arg_xbootldr_path) < 0)
                return log_oom();

        if (!b.esp_path) {
                r = acquire_esp(/* unprivileged_mode= */ false,
                                b.graceful,
                                &b.esp_part,
                                &b.esp_pstart,
                                &b.esp_psize,
                                &b.esp_uuid,
                                /* ret_devid= */ NULL);
                /* If --graceful is specified and we can't find an ESP, handle this cleanly */
                if (r < 0 && !(b.graceful && r == -ENOKEY))
                        return r;
                if (strdup_to(&b.esp_path, arg_esp_path) < 0)
                        return log_oom();
        }

        if (!b.xbootldr_path) {
                r = acquire_xbootldr(
                                /* unprivileged_mode= */ false,
                                /* ret_uuid= */ NULL,
                                /* ret_devid= */ NULL);
                if (r < 0)
                        return r;
                if (strdup_to(&b.xbootldr_path, arg_xbootldr_path) < 0)
                        return log_oom();
        }

        *c = b;
        b = INSTALL_CONTEXT_NULL;

        return 0;
}

static int acquire_esp_fd(InstallContext *c) {
        int r;

        assert(c);

        if (c->esp_fd >= 0)
                return c->esp_fd;

        r = chaseat(c->root_fd,
                    c->esp_path,
                    CHASE_AT_RESOLVE_IN_ROOT|CHASE_TRIGGER_AUTOFS|CHASE_MUST_BE_DIRECTORY,
                    /* ret_path= */ NULL,
                    &c->esp_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to open ESP: %m");

        return c->esp_fd;
}

static int acquire_dollar_boot_fd(InstallContext *c) {
        int r;

        assert(c);

        if (c->xbootldr_fd >= 0)
                return c->xbootldr_fd;

        if (!c->xbootldr_path)
                return acquire_esp_fd(c);

        r = chaseat(c->root_fd,
                    c->xbootldr_path,
                    CHASE_AT_RESOLVE_IN_ROOT|CHASE_TRIGGER_AUTOFS|CHASE_MUST_BE_DIRECTORY,
                    /* ret_path= */ NULL,
                    &c->xbootldr_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to open XBOOTLDR: %m");

        return c->xbootldr_fd;
}

static const char *dollar_boot_path(InstallContext *c) {
        assert(c);

        return c->xbootldr_path ?: c->esp_path;
}

static bool touch_install_variables(InstallContext *c) {
        assert(c);

        if (c->touch_variables >= 0)
                return c->touch_variables;

        if (!is_efi_boot())  /* NB: this internally checks if we run in a container */
                return false;

        return empty_or_root(c->root);
}

static int load_etc_machine_id(InstallContext *c) {
        int r;

        assert(c);

        r = id128_get_machine_at(c->root_fd, &c->machine_id);
        if (ERRNO_IS_NEG_MACHINE_ID_UNSET(r)) /* Not set or empty */
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to get machine-id: %m");

        log_debug("Loaded machine ID %s from /etc/machine-id.", SD_ID128_TO_STRING(c->machine_id));
        return 0;
}

static int load_etc_machine_info(InstallContext *c) {
        /* systemd v250 added support to store the kernel-install layout setting and the machine ID to use
         * for setting up the ESP in /etc/machine-info. The newer /etc/kernel/entry-token file, as well as
         * the $layout field in /etc/kernel/install.conf are better replacements for this though, hence this
         * has been deprecated and is only returned for compatibility. */
        _cleanup_free_ char *p = NULL, *s = NULL, *layout = NULL;
        int r;

        assert(c);

        _cleanup_close_ int fd =
                chase_and_openat(c->root_fd, "etc/machine-info", CHASE_AT_RESOLVE_IN_ROOT|CHASE_MUST_BE_REGULAR, O_RDONLY|O_CLOEXEC, /* ret_path= */ NULL);
        if (fd == -ENOENT)
                return 0;
        if (fd < 0)
                return log_error_errno(fd, "Failed to open /etc/machine-info: %m");

        r = parse_env_file_fd(
                        fd, "/etc/machine-info",
                        "KERNEL_INSTALL_LAYOUT", &layout,
                        "KERNEL_INSTALL_MACHINE_ID", &s);
        if (r < 0)
                return log_error_errno(r, "Failed to parse /etc/machine-info: %m");

        if (!isempty(s)) {
                if (!arg_quiet)
                        log_notice("Read $KERNEL_INSTALL_MACHINE_ID from /etc/machine-info. "
                                   "Please move it to /etc/kernel/entry-token.");

                r = sd_id128_from_string(s, &c->machine_id);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse KERNEL_INSTALL_MACHINE_ID=%s in /etc/machine-info: %m", s);

                log_debug("Loaded KERNEL_INSTALL_MACHINE_ID=%s from /etc/machine-info.",
                          SD_ID128_TO_STRING(c->machine_id));
        }

        if (!isempty(layout)) {
                if (!arg_quiet)
                        log_notice("Read $KERNEL_INSTALL_LAYOUT from /etc/machine-info. "
                                   "Please move it to the layout= setting of /etc/kernel/install.conf.");

                log_debug("KERNEL_INSTALL_LAYOUT=%s is specified in /etc/machine-info.", layout);
                free_and_replace(c->install_layout, layout);
        }

        return 0;
}

static int load_kernel_install_layout(InstallContext *c) {
        _cleanup_free_ char *layout = NULL;
        int r;

        assert(c);

        const char *e = secure_getenv("KERNEL_INSTALL_CONF_ROOT");
        if (e)
                r = load_kernel_install_conf_at(
                                /* root= */ NULL,
                                /* root_fd= */ -EBADF,
                                e,
                                /* ret_machine_id= */ NULL,
                                /* ret_boot_root= */ NULL,
                                &layout,
                                /* ret_initrd_generator= */ NULL,
                                /* ret_uki_generator= */ NULL);
        else
                r = load_kernel_install_conf_at(
                                c->root,
                                c->root_fd,
                                /* conf_root= */ NULL,
                                /* ret_machine_id= */ NULL,
                                /* ret_boot_root= */ NULL,
                                &layout,
                                /* ret_initrd_generator= */ NULL,
                                /* ret_uki_generator= */ NULL);
        if (r <= 0)
                return r;

        if (!isempty(layout)) {
                log_debug("layout=%s is specified in config.", layout);
                free_and_replace(c->install_layout, layout);
        }

        return 0;
}

static bool use_boot_loader_spec_type1(InstallContext *c) {
        assert(c);
        /* If the layout is not specified, or if it is set explicitly to "bls" we assume Boot Loader
         * Specification Type #1 is the chosen format for our boot loader entries */
        return !c->install_layout || streq(c->install_layout, "bls");
}

static int settle_make_entry_directory(InstallContext *c) {
        int r;

        assert(c);

        r = load_etc_machine_id(c);
        if (r < 0)
                return r;

        r = load_etc_machine_info(c);
        if (r < 0)
                return r;

        r = load_kernel_install_layout(c);
        if (r < 0)
                return r;

        const char *e = secure_getenv("KERNEL_INSTALL_CONF_ROOT");
        r = boot_entry_token_ensure_at(
                        e ? -EBADF : c->root_fd,
                        e,
                        c->machine_id,
                        /* machine_id_is_random = */ false,
                        &c->entry_token_type,
                        &c->entry_token);
        if (r < 0)
                return r;

        log_debug("Using entry token: %s", c->entry_token);

        bool layout_type1 = use_boot_loader_spec_type1(c);
        if (c->make_entry_directory < 0) { /* Automatic mode */
                if (layout_type1) {
                        if (c->entry_token_type == BOOT_ENTRY_TOKEN_MACHINE_ID) {
                                _cleanup_close_ int fd = -EBADF;

                                r = chaseat(c->root_fd, "etc/machine-id", CHASE_AT_RESOLVE_IN_ROOT|CHASE_MUST_BE_REGULAR, /* ret_path= */ NULL, &fd);
                                if (r < 0)
                                        return log_debug_errno(r, "Unable to open /etc/machine-id: %m");

                                r = fd_is_temporary_fs(fd);
                                if (r < 0)
                                        return log_debug_errno(r, "Couldn't determine whether /etc/machine-id is on a temporary file system: %m");

                                c->make_entry_directory = r == 0;
                        } else
                                c->make_entry_directory = true;
                } else
                        c->make_entry_directory = false;
        }

        if (c->make_entry_directory > 0 && !layout_type1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "KERNEL_INSTALL_LAYOUT=%s is configured, but Boot Loader Specification Type #1 entry directory creation was requested.",
                                       c->install_layout);

        return 0;
}

static int compare_product(const char *a, const char *b) {
        size_t x, y;

        assert(a);
        assert(b);

        x = strcspn(a, " ");
        y = strcspn(b, " ");
        if (x != y)
                return x < y ? -1 : x > y ? 1 : 0;

        return strncmp(a, b, x);
}

static int compare_version(const char *a, const char *b) {
        assert(a);
        assert(b);

        a += strcspn(a, " ");
        a += strspn(a, " ");
        b += strcspn(b, " ");
        b += strspn(b, " ");

        return strverscmp_improved(a, b);
}

static int version_check(int fd_from, const char *from, int fd_to, const char *to) {
        _cleanup_free_ char *a = NULL, *b = NULL;
        int r;

        assert(fd_from >= 0);
        assert(from);
        assert(fd_to >= 0);
        assert(to);

        r = get_file_version(fd_from, &a);
        if (r == -ESRCH)
                return log_notice_errno(r, "Source file \"%s\" does not carry version information!", from);
        if (r < 0)
                return r;

        r = get_file_version(fd_to, &b);
        if (r == -ESRCH)
                return log_info_errno(r, "Skipping \"%s\", it's owned by another boot loader (no version info found).",
                                        to);
        if (r < 0)
                return r;
        if (compare_product(a, b) != 0)
                return log_info_errno(SYNTHETIC_ERRNO(ESRCH),
                                        "Skipping \"%s\", it's owned by another boot loader.", to);

        r = compare_version(a, b);
        log_debug("Comparing versions: \"%s\" %s \"%s\"", a, comparison_operator(r), b);
        if (r < 0)
                return log_warning_errno(SYNTHETIC_ERRNO(ESTALE),
                                         "Skipping \"%s\", newer boot loader version in place already.", to);
        if (r == 0)
                return log_info_errno(SYNTHETIC_ERRNO(ESTALE),
                                      "Skipping \"%s\", same boot loader version in place already.", to);

        return 0;
}

static int copy_file_with_version_check(
                const char *source_path,
                int source_fd,
                const char *dest_path,
                int dest_parent_fd,
                const char *dest_filename,
                int dest_fd,
                bool force) {

        _cleanup_close_ int fd_from = -EBADF, fd_to = -EBADF;
        int r;

        assert(source_path);
        assert(source_fd >= 0);
        assert(dest_path);
        assert(dest_parent_fd >= 0);
        assert(dest_filename);

        if (!force && dest_fd >= 0) {
                r = version_check(source_fd, source_path, dest_fd, dest_path);
                if (r < 0)
                        return r;

                if (lseek(source_fd, 0, SEEK_SET) < 0)
                        return log_error_errno(errno, "Failed to seek in \"%s\": %m", source_path);
        }

        _cleanup_free_ char *t = NULL;
        _cleanup_close_ int write_fd = -EBADF;
        write_fd = open_tmpfile_linkable_at(dest_parent_fd, dest_filename, O_WRONLY|O_CLOEXEC, &t);
        if (write_fd < 0)
                return log_error_errno(write_fd, "Failed to open \"%s\" for writing: %m", dest_path);

        CLEANUP_TMPFILE_AT(dest_parent_fd, t);

        r = copy_bytes(source_fd, write_fd, UINT64_MAX, COPY_REFLINK);
        if (r < 0)
                return log_error_errno(r, "Failed to copy data from \"%s\" to \"%s\": %m", source_path, dest_path);

        (void) copy_times(source_fd, write_fd, /* flags= */ 0);
        (void) fchmod(write_fd, 0666);

        r = link_tmpfile_at(write_fd, dest_parent_fd, t, dest_filename, LINK_TMPFILE_REPLACE|LINK_TMPFILE_SYNC);
        if (r < 0)
                return log_error_errno(r, "Failed to move data from \"%s\" to \"%s\": %m", source_path, dest_path);

        t = mfree(t); /* disarm CLEANUP_TMPFILE_AT() */

        log_info("Copied \"%s\" to \"%s\".", source_path, dest_path);
        return 0;
}

static int mkdir_one(const char *root, int root_fd, const char *path) {
        int r;

        assert(root);
        assert(root_fd >= 0);
        assert(path);

        _cleanup_free_ char *p = path_join(empty_to_root(root), path);
        if (!p)
                return log_oom();

        r = chaseat(root_fd, path, CHASE_AT_RESOLVE_IN_ROOT|CHASE_PROHIBIT_SYMLINKS|CHASE_MKDIR_0755|CHASE_MUST_BE_DIRECTORY, /* ret_path= */ NULL, /* ret_fd= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to create \"%s\": %m", p);

        log_info("Created \"%s\".", p);
        return 0;
}

static const char *const esp_subdirs[] = {
        /* The directories to place in the ESP */
        "EFI",
        "EFI/systemd",
        "EFI/BOOT",
        "loader",
        "loader/keys",
        NULL
};

static const char *const dollar_boot_subdirs[] = {
        /* The directories to place in the XBOOTLDR partition or the ESP, depending what exists */
        "loader",
        "loader/entries",  /* Type #1 entries */
        "EFI",
        "EFI/Linux",       /* Type #2 entries */
        NULL
};

static int create_subdirs(const char *root, int root_fd, const char * const *subdirs) {
        int r;

        assert(root);
        assert(root_fd >= 0);

        STRV_FOREACH(i, subdirs) {
                r = mkdir_one(root, root_fd, *i);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int update_efi_boot_binaries(
                const char *esp_path,
                int esp_fd,
                const char *source_path,
                int source_fd,
                const char *ignore_filename) {

        int r, ret = 0;

        assert(esp_path);
        assert(esp_fd >= 0);
        assert(source_path);

        _cleanup_free_ char *p = NULL;
        _cleanup_closedir_ DIR *d = NULL;
        r = chase_and_opendirat(esp_fd, "EFI/BOOT", CHASE_AT_RESOLVE_IN_ROOT|CHASE_PROHIBIT_SYMLINKS|CHASE_MUST_BE_DIRECTORY, &p, &d);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to open directory \"%s/EFI/BOOT\": %m", esp_path);

        FOREACH_DIRENT(de, d, break) {
                _cleanup_close_ int fd = -EBADF;

                if (!endswith_no_case(de->d_name, ".efi"))
                        continue;

                if (strcaseeq_ptr(ignore_filename, de->d_name))
                        continue;

                fd = xopenat_full(dirfd(d), de->d_name, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY|O_NOFOLLOW, XO_REGULAR, /* mode= */ MODE_INVALID);
                if (fd < 0)
                        return log_error_errno(fd, "Failed to open \"%s/%s\" for reading: %m", p, de->d_name);

                r = pe_is_native_fd(fd);
                if (r < 0) {
                        log_warning_errno(r, "Failed to detect if \"%s/%s\" is for native architecture, ignoring: %m", p, de->d_name);
                        continue;
                }
                if (r == 0)
                        continue;

                _cleanup_free_ char *dest_path = path_join("EFI/BOOT", de->d_name);
                if (!dest_path)
                        return log_oom();

                if (lseek(source_fd, 0, SEEK_SET) < 0)
                        return log_error_errno(errno, "Failed to seek in \"%s\": %m", source_path);

                r = copy_file_with_version_check(source_path, source_fd, dest_path, dirfd(d), de->d_name, fd, /* force = */ false);
                if (IN_SET(r, -ESTALE, -ESRCH))
                        continue;
                RET_GATHER(ret, r);
        }

        return ret;
}

static int copy_one_file(
                InstallContext *c,
                const char *name,
                bool force) {

        int r, ret = 0;

        assert(c);

        _cleanup_free_ char *dest_name = strdup(name);
        if (!dest_name)
                return log_oom();
        char *s = endswith_no_case(dest_name, ".signed");
        if (s)
                *s = 0;

        _cleanup_free_ char *sp = path_join(BOOTLIBDIR, name);
        if (!sp)
                return log_oom();

        _cleanup_free_ char *source_path = NULL;
        _cleanup_close_ int source_fd = -EBADF;
        if (IN_SET(c->install_source, INSTALL_SOURCE_AUTO, INSTALL_SOURCE_IMAGE)) {
                source_fd = chase_and_openat(c->root_fd, sp, CHASE_AT_RESOLVE_IN_ROOT|CHASE_TRIGGER_AUTOFS|CHASE_MUST_BE_REGULAR, O_RDONLY|O_CLOEXEC, &source_path);
                if (source_fd < 0 && (source_fd != -ENOENT || c->install_source != INSTALL_SOURCE_AUTO))
                        return log_error_errno(source_fd, "Failed to resolve path '%s' under directory '%s': %m", sp, c->root);

                /* If we had a root directory to try, we didn't find it and we are in auto mode, retry on the host */
        }
        if (source_fd < 0) {
                source_fd = chase_and_open(sp, /* root= */ NULL, CHASE_TRIGGER_AUTOFS|CHASE_MUST_BE_REGULAR, O_RDONLY|O_CLOEXEC, &source_path);
                if (source_fd < 0)
                        return log_error_errno(source_fd, "Failed to resolve path %s: %m", sp);
        }

        int esp_fd = acquire_esp_fd(c);
        if (esp_fd < 0)
                return esp_fd;

        _cleanup_free_ char *dest_path = NULL;
        _cleanup_close_ int dest_parent_fd = -EBADF;
        r = chaseat(esp_fd, "EFI/systemd", CHASE_PROHIBIT_SYMLINKS|CHASE_TRIGGER_AUTOFS|CHASE_MKDIR_0755|CHASE_MUST_BE_DIRECTORY, &dest_path, &dest_parent_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to resolve path '/EFI/systemd' under directory '%s': %m", c->esp_path);

        if (!path_extend(&dest_path, dest_name))
                return log_oom();

        _cleanup_close_ int dest_fd = xopenat_full(dest_parent_fd, dest_name, O_RDONLY|O_CLOEXEC, XO_REGULAR, MODE_INVALID);
        if (dest_fd < 0 && dest_fd != -ENOENT)
                return log_error_errno(dest_fd, "Failed to open '%s' under '/EFI/systemd' directory: %m", dest_name);

        /* Note that if this fails we do the second copy anyway, but return this error code,
         * so we stash it away in a separate variable. */
        ret = copy_file_with_version_check(source_path, source_fd, dest_path, dest_parent_fd, dest_name, dest_fd, force);

        const char *e = startswith(dest_name, "systemd-boot");
        if (e) {

                /* Create the EFI default boot loader name (specified for removable devices) */
                _cleanup_free_ char *boot_dot_efi = strjoin("BOOT", e);
                if (!boot_dot_efi)
                        return log_oom();

                ascii_strupper(boot_dot_efi);

                _cleanup_free_ char *default_dest_path = NULL;
                _cleanup_close_ int default_dest_parent_fd = -EBADF;
                r = chaseat(esp_fd, "/EFI/BOOT", CHASE_PROHIBIT_SYMLINKS|CHASE_TRIGGER_AUTOFS|CHASE_MKDIR_0755|CHASE_MUST_BE_DIRECTORY, &default_dest_path, &default_dest_parent_fd);
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve path '/EFI/BOOT/' under directory '%s': %m", c->esp_path);

                if (!path_extend(&default_dest_path, boot_dot_efi))
                        return log_oom();

                _cleanup_close_ int default_dest_fd = xopenat_full(default_dest_parent_fd, boot_dot_efi, O_RDONLY|O_CLOEXEC, XO_REGULAR, MODE_INVALID);
                if (default_dest_fd < 0 && dest_fd != -ENOENT)
                        return log_error_errno(dest_fd, "Failed to open '%s' under '/EFI/BOOT' directory: %m", boot_dot_efi);

                if (lseek(source_fd, 0, SEEK_SET) < 0)
                        return log_error_errno(errno, "Failed to seek in \"%s\": %m", source_path);

                RET_GATHER(ret, copy_file_with_version_check(source_path, source_fd, default_dest_path, default_dest_parent_fd, boot_dot_efi, default_dest_fd, force));

                /* If we were installed under any other name in /EFI/BOOT/, make sure we update those
                 * binaries as well. */
                if (!force) {
                        if (lseek(source_fd, 0, SEEK_SET) < 0)
                                return log_error_errno(errno, "Failed to seek in \"%s\": %m", source_path);

                        RET_GATHER(ret, update_efi_boot_binaries(c->esp_path, esp_fd, source_path, source_fd, boot_dot_efi));
                }
        }

        return ret;
}

static int install_binaries(
                InstallContext *c,
                const char *arch) {

        int r;

        assert(c);

        _cleanup_free_ char *source_path = NULL;
        _cleanup_closedir_ DIR *d = NULL;
        if (IN_SET(c->install_source, INSTALL_SOURCE_AUTO, INSTALL_SOURCE_IMAGE)) {
                r = chase_and_opendirat(c->root_fd, BOOTLIBDIR, CHASE_TRIGGER_AUTOFS|CHASE_MUST_BE_DIRECTORY, &source_path, &d);
                if (r < 0 && (r != -ENOENT || c->install_source != INSTALL_SOURCE_AUTO))
                        return log_error_errno(r, "Failed to resolve path '%s' under directory '%s': %m", BOOTLIBDIR, c->root);

                /* If we had a root directory to try, we didn't find it and we are in auto mode, retry on the host */
        }
        if (!d) {
                r = chase_and_opendir(BOOTLIBDIR, /* root= */ NULL, CHASE_TRIGGER_AUTOFS|CHASE_MUST_BE_DIRECTORY, &source_path, &d);
                if (r == -ENOENT && c->graceful) {
                        log_debug("Source directory '%s' does not exist, ignoring.", BOOTLIBDIR);
                        return 0;
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve path '%s': %m", BOOTLIBDIR);
        }

        const char *suffix = strjoina(arch, ".efi");
        const char *suffix_signed = strjoina(arch, ".efi.signed");

        FOREACH_DIRENT(de, d, return log_error_errno(errno, "Failed to read \"%s\": %m", source_path)) {
                int k;

                if (endswith_no_case(de->d_name, suffix)) {
                        /* skip the .efi file, if there's a .signed version of it */
                        _cleanup_free_ const char *s = strjoin(de->d_name, ".signed");
                        if (!s)
                                return log_oom();
                        if (faccessat(dirfd(d), s, F_OK, 0) >= 0)
                                continue;
                } else if (!endswith_no_case(de->d_name, suffix_signed))
                        continue;

                k = copy_one_file(c, de->d_name, c->operation == INSTALL_NEW);
                /* Don't propagate an error code if no update necessary, installed version already equal or
                 * newer version, or other boot loader in place. */
                if (c->graceful && IN_SET(k, -ESTALE, -ESRCH))
                        continue;
                RET_GATHER(r, k);
        }

        return r;
}

static int install_loader_config(InstallContext *c) {
        int r;

        assert(c);
        assert(c->make_entry_directory >= 0);

        int esp_fd = acquire_esp_fd(c);
        if (esp_fd < 0)
                return esp_fd;

        _cleanup_close_ int loader_dir_fd = -EBADF;
        r = chaseat(esp_fd, "loader", CHASE_PROHIBIT_SYMLINKS|CHASE_TRIGGER_AUTOFS|CHASE_MKDIR_0755|CHASE_MUST_BE_DIRECTORY, /* ret_path= */ NULL, &loader_dir_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to open '/loader/' directory below '%s': %m", c->esp_path);

        if (faccessat(loader_dir_fd, "loader.conf", F_OK, AT_SYMLINK_NOFOLLOW) < 0) {
                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to check if '/loader/loader.conf' exists below '%s': %m", c->esp_path);
        } else /* Silently skip creation if the file already exists (early check) */
                return 0;

        _cleanup_free_ char *t = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        r = fopen_tmpfile_linkable_at(loader_dir_fd, "loader.conf", O_WRONLY|O_CLOEXEC, &t, &f);
        if (r < 0)
                return log_error_errno(r, "Failed to open '/loader/loader.conf' for writing: %m");

        CLEANUP_TMPFILE_AT(loader_dir_fd, t);

        fprintf(f, "#timeout 3\n"
                   "#console-mode keep\n");

        if (c->make_entry_directory) {
                assert(c->entry_token);
                fprintf(f, "default %s-*\n", c->entry_token);
        }

        r = flink_tmpfile_at(f, loader_dir_fd, t, "loader.conf", LINK_TMPFILE_SYNC);
        if (r == -EEXIST)
                return 0; /* Silently skip creation if the file exists now (recheck) */
        if (r < 0)
                return log_error_errno(r, "Failed to move 'loader.conf' into place: %m");

        t = mfree(t); /* disarm CLEANUP_TMPFILE_AT() */
        return 1;
}

static int install_loader_specification(InstallContext *c) {
        int r;

        assert(c);

        int dollar_boot_fd = acquire_dollar_boot_fd(c);
        if (dollar_boot_fd < 0)
                return dollar_boot_fd;

        _cleanup_close_ int loader_dir_fd = -EBADF;
        r = chaseat(dollar_boot_fd, "loader", CHASE_PROHIBIT_SYMLINKS|CHASE_TRIGGER_AUTOFS|CHASE_MKDIR_0755|CHASE_MUST_BE_DIRECTORY, /* ret_path= */ NULL, &loader_dir_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to pin '/loader' directory below '%s': %m", dollar_boot_path(c));

        if (faccessat(loader_dir_fd, "entries.srel", F_OK, AT_SYMLINK_NOFOLLOW) < 0) {
                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to check if '/loader/entries.srel' exists below '%s': %m", c->esp_path);
        } else /* Silently skip creation if the file already exists (early check) */
                return 0;

        _cleanup_free_ char *t = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        r = fopen_tmpfile_linkable_at(loader_dir_fd, "entries.srel", O_WRONLY|O_CLOEXEC, &t, &f);
        if (r < 0)
                return log_error_errno(r, "Failed to open '/loader/entries.srel' for writing: %m");

        CLEANUP_TMPFILE_AT(loader_dir_fd, t);

        fprintf(f, "type1\n");

        r = flink_tmpfile_at(f, loader_dir_fd, t, "entries.srel", LINK_TMPFILE_SYNC);
        if (r == -EEXIST)
                return 0; /* Silently skip creation if the file exists now (recheck) */
        if (r < 0)
                return log_error_errno(r, "Failed to move '/loader/entries.srel' into place: %m");

        t = mfree(t); /* disarm CLEANUP_TMPFILE_AT() */
        return 1;
}

static int install_entry_directory(InstallContext *c) {
        assert(c);
        assert(c->make_entry_directory >= 0);

        if (!c->make_entry_directory)
                return 0;

        assert(c->entry_token);

        int dollar_boot_fd = acquire_dollar_boot_fd(c);
        if (dollar_boot_fd < 0)
                return dollar_boot_fd;

        return mkdir_one(dollar_boot_path(c), dollar_boot_fd, c->entry_token);
}

static int install_entry_token(InstallContext *c) {
        _cleanup_free_ char* p = NULL;
        int r;

        assert(c);
        assert(c->make_entry_directory >= 0);
        assert(c->entry_token);

        /* Let's save the used entry token in /etc/kernel/entry-token if we used it to create the entry
         * directory, or if anything else but the machine ID */

        if (!c->make_entry_directory && c->entry_token_type == BOOT_ENTRY_TOKEN_MACHINE_ID)
                return 0;

        const char *confdir = secure_getenv("KERNEL_INSTALL_CONF_ROOT") ?: "/etc/kernel/";
        _cleanup_close_ int dfd = -EBADF;
        r = chaseat(c->root_fd, confdir, CHASE_AT_RESOLVE_IN_ROOT|CHASE_MUST_BE_DIRECTORY|CHASE_MKDIR_0755, /* ret_path= */ NULL, &dfd);
        if (r < 0)
                return log_error_errno(r, "Failed to open '%s': %m", confdir);

        r = write_string_file_at(dfd, "entry-token", c->entry_token, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC|WRITE_STRING_FILE_MKDIR_0755);
        if (r < 0)
                return log_error_errno(r, "Failed to write entry token '%s' to '%s/entry-token': %m", c->entry_token, confdir);

        return 0;
}

#if HAVE_OPENSSL
static int efi_timestamp(EFI_TIME *ret) {
        uint64_t epoch = UINT64_MAX;
        struct tm tm = {};
        int r;

        assert(ret);

        r = secure_getenv_uint64("SOURCE_DATE_EPOCH", &epoch);
        if (r != -ENXIO)
                log_debug_errno(r, "Failed to parse $SOURCE_DATE_EPOCH, ignoring: %m");

        r = localtime_or_gmtime_usec(epoch != UINT64_MAX ? epoch : now(CLOCK_REALTIME), /*utc=*/ true, &tm);
        if (r < 0)
                return log_error_errno(r, "Failed to convert timestamp to calendar time: %m");

        *ret = (EFI_TIME) {
                .Year = 1900 + tm.tm_year,
                /* tm_mon starts at 0, EFI_TIME months start at 1. */
                .Month = tm.tm_mon + 1,
                .Day = tm.tm_mday,
                .Hour = tm.tm_hour,
                .Minute = tm.tm_min,
                .Second = tm.tm_sec,
        };

        return 0;
}
#endif

static int install_secure_boot_auto_enroll(InstallContext *c) {
#if HAVE_OPENSSL
        int r;

        if (!c->secure_boot_certificate || !c->secure_boot_private_key)
                return 0;

        _cleanup_free_ uint8_t *dercert = NULL;
        int dercertsz;
        dercertsz = i2d_X509(c->secure_boot_certificate, &dercert);
        if (dercertsz < 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to convert X.509 certificate to DER: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        int esp_fd = acquire_esp_fd(c);
        if (esp_fd < 0)
                return esp_fd;

        _cleanup_close_ int keys_fd = -EBADF;
        r = chaseat(esp_fd,
                    "loader/keys/auto",
                    CHASE_AT_RESOLVE_IN_ROOT|CHASE_PROHIBIT_SYMLINKS|CHASE_MUST_BE_DIRECTORY|CHASE_MKDIR_0755,
                    /* ret_path= */ NULL,
                    &keys_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to chase /loader/keys/auto/ in the ESP: %m");

        uint32_t siglistsz = offsetof(EFI_SIGNATURE_LIST, Signatures) + offsetof(EFI_SIGNATURE_DATA, SignatureData) + dercertsz;
        /* We use malloc0() to zero-initialize the SignatureOwner field of Signatures[0]. */
        _cleanup_free_ EFI_SIGNATURE_LIST *siglist = malloc0(siglistsz);
        if (!siglist)
                return log_oom();

        *siglist = (EFI_SIGNATURE_LIST) {
                .SignatureType = EFI_CERT_X509_GUID,
                .SignatureListSize = siglistsz,
                .SignatureSize = offsetof(EFI_SIGNATURE_DATA, SignatureData) + dercertsz,
        };

        memcpy(siglist->Signatures[0].SignatureData, dercert, dercertsz);

        EFI_TIME timestamp;
        r = efi_timestamp(&timestamp);
        if (r < 0)
                return r;

        uint32_t attrs =
                EFI_VARIABLE_NON_VOLATILE|
                EFI_VARIABLE_BOOTSERVICE_ACCESS|
                EFI_VARIABLE_RUNTIME_ACCESS|
                EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;

        FOREACH_STRING(db, "PK", "KEK", "db") {
                _cleanup_(BIO_freep) BIO *bio = NULL;

                bio = BIO_new(BIO_s_mem());
                if (!bio)
                        return log_oom();

                _cleanup_free_ char16_t *db16 = utf8_to_utf16(db, SIZE_MAX);
                if (!db16)
                        return log_oom();

                /* Don't count the trailing NUL terminator. */
                if (BIO_write(bio, db16, char16_strsize(db16) - sizeof(char16_t)) < 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to write variable name to bio");

                EFI_GUID *guid = STR_IN_SET(db, "PK", "KEK") ? &(EFI_GUID) EFI_GLOBAL_VARIABLE : &(EFI_GUID) EFI_IMAGE_SECURITY_DATABASE_GUID;

                if (BIO_write(bio, guid, sizeof(*guid)) < 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to write variable GUID to bio");

                if (BIO_write(bio, &attrs, sizeof(attrs)) < 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to write variable attributes to bio");

                if (BIO_write(bio, &timestamp, sizeof(timestamp)) < 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to write timestamp to bio");

                if (BIO_write(bio, siglist, siglistsz) < 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to write signature list to bio");

                _cleanup_(PKCS7_freep) PKCS7 *p7 = NULL;
                p7 = PKCS7_sign(c->secure_boot_certificate, c->secure_boot_private_key, /*certs=*/ NULL, bio, PKCS7_DETACHED|PKCS7_NOATTR|PKCS7_BINARY|PKCS7_NOSMIMECAP);
                if (!p7)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to calculate PKCS7 signature: %s",
                                               ERR_error_string(ERR_get_error(), NULL));

                _cleanup_free_ uint8_t *sig = NULL;
                int sigsz = i2d_PKCS7(p7, &sig);
                if (sigsz < 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to convert PKCS7 signature to DER: %s",
                                               ERR_error_string(ERR_get_error(), NULL));

                size_t authsz = offsetof(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo.CertData) + sigsz;
                _cleanup_free_ EFI_VARIABLE_AUTHENTICATION_2 *auth = malloc(authsz);
                if (!auth)
                        return log_oom();

                *auth = (EFI_VARIABLE_AUTHENTICATION_2) {
                        .TimeStamp = timestamp,
                        .AuthInfo = {
                                .Hdr = {
                                        .dwLength = offsetof(WIN_CERTIFICATE_UEFI_GUID, CertData) + sigsz,
                                        .wRevision = 0x0200,
                                        .wCertificateType = 0x0EF1, /* WIN_CERT_TYPE_EFI_GUID */
                                },
                                .CertType = EFI_CERT_TYPE_PKCS7_GUID,
                        }
                };

                memcpy(auth->AuthInfo.CertData, sig, sigsz);

                _cleanup_free_ char *filename = strjoin(db, ".auth");
                if (!filename)
                        return log_oom();

                _cleanup_free_ char *t = NULL;
                _cleanup_close_ int fd = open_tmpfile_linkable_at(keys_fd, filename, O_WRONLY|O_CLOEXEC, &t);
                if (fd < 0)
                        return log_error_errno(fd, "Failed to open secure boot auto-enrollment file for writing: %m");

                CLEANUP_TMPFILE_AT(keys_fd, t);

                r = loop_write(fd, auth, authsz);
                if (r < 0)
                        return log_error_errno(r, "Failed to write authentication descriptor to secure boot auto-enrollment file: %m");

                r = loop_write(fd, siglist, siglistsz);
                if (r < 0)
                        return log_error_errno(r, "Failed to write signature list to secure boot auto-enrollment file: %m");

                r = link_tmpfile_at(fd, keys_fd, t, filename, LINK_TMPFILE_SYNC);
                if (r < 0)
                        return log_error_errno(errno, "Failed to link secure boot auto-enrollment file: %m");

                t = mfree(t); /* Disarm CLEANUP_TMPFILE_AT() */

                log_info("Secure boot auto-enrollment file %s/loader/keys/auto/%s successfully written.", c->esp_path, filename);
        }

        return 0;
#else
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "OpenSSL is not supported, cannot set up secure boot auto-enrollment.");
#endif
}

static bool same_entry(uint16_t id, sd_id128_t uuid, const char *path) {
        _cleanup_free_ char *opath = NULL;
        sd_id128_t ouuid;
        int r;

        r = efi_get_boot_option(id, NULL, &ouuid, &opath, NULL);
        if (r < 0)
                return false;
        if (!sd_id128_equal(uuid, ouuid))
                return false;

        /* Some motherboards convert the path to uppercase under certain circumstances
         * (e.g. after booting into the Boot Menu in the ASUS ROG STRIX B350-F GAMING),
         * so use case-insensitive checking */
        if (!strcaseeq_ptr(path, opath))
                return false;

        return true;
}

static int find_slot(sd_id128_t uuid, const char *path, uint16_t *id) {
        _cleanup_free_ uint16_t *options = NULL;

        int n = efi_get_boot_options(&options);
        if (n < 0)
                return n;

        /* find already existing systemd-boot entry */
        for (int i = 0; i < n; i++)
                if (same_entry(options[i], uuid, path)) {
                        *id = options[i];
                        return 1;
                }

        /* find free slot in the sorted BootXXXX variable list */
        for (int i = 0; i < n; i++)
                if (i != options[i]) {
                        *id = i;
                        return 0;
                }

        /* use the next one */
        if (n == 0xffff)
                return -ENOSPC;
        *id = n;
        return 0;
}

static int insert_into_order(InstallContext *c, uint16_t slot) {
        _cleanup_free_ uint16_t *order = NULL;
        uint16_t *t;
        int n;

        assert(c);

        n = efi_get_boot_order(&order);
        if (n <= 0)
                /* no entry, add us */
                return efi_set_boot_order(&slot, 1);

        /* are we the first and only one? */
        if (n == 1 && order[0] == slot)
                return 0;

        /* are we already in the boot order? */
        for (int i = 0; i < n; i++) {
                if (order[i] != slot)
                        continue;

                /* we do not require to be the first one, all is fine */
                if (c->operation != INSTALL_NEW)
                        return 0;

                /* move us to the first slot */
                memmove(order + 1, order, i * sizeof(uint16_t));
                order[0] = slot;
                return efi_set_boot_order(order, n);
        }

        /* extend array */
        t = reallocarray(order, n + 1, sizeof(uint16_t));
        if (!t)
                return -ENOMEM;
        order = t;

        /* add us to the top or end of the list */
        if (c->operation != INSTALL_NEW) {
                memmove(order + 1, order, n * sizeof(uint16_t));
                order[0] = slot;
        } else
                order[n] = slot;

        return efi_set_boot_order(order, n + 1);
}

static int remove_from_order(uint16_t slot) {
        _cleanup_free_ uint16_t *order = NULL;
        int n;

        n = efi_get_boot_order(&order);
        if (n <= 0)
                return n;

        for (int i = 0; i < n; i++) {
                if (order[i] != slot)
                        continue;

                if (i + 1 < n)
                        memmove(order + i, order + i+1, (n - i) * sizeof(uint16_t));
                return efi_set_boot_order(order, n - 1);
        }

        return 0;
}

static const char *pick_efi_boot_option_description(void) {
        return arg_efi_boot_option_description ?: "Linux Boot Manager";
}

static int install_variables(
                InstallContext *c,
                uint32_t part,
                uint64_t pstart,
                uint64_t psize,
                sd_id128_t uuid,
                const char *path) {

        uint16_t slot;
        int r;

        assert(c);

        int esp_fd = acquire_esp_fd(c);
        if (esp_fd < 0)
                return esp_fd;

        r = chase_and_accessat(esp_fd, path, CHASE_AT_RESOLVE_IN_ROOT|CHASE_PROHIBIT_SYMLINKS|CHASE_MUST_BE_REGULAR, F_OK, /* ret_path= */ NULL);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Cannot access \"%s/%s\": %m", c->esp_path, skip_leading_slash(path));

        r = find_slot(uuid, path, &slot);
        if (r < 0) {
                int level = c->graceful ? arg_quiet ? LOG_DEBUG : LOG_INFO : LOG_ERR;
                const char *skip = c->graceful ? ", skipping" : "";

                log_full_errno(level, r,
                               r == -ENOENT ?
                               "Failed to access EFI variables%s. Is the \"efivarfs\" filesystem mounted?" :
                               "Failed to determine current boot order%s: %m", skip);

                return c->graceful ? 0 : r;
        }

        bool existing = r > 0;

        if (c->operation == INSTALL_NEW || !existing) {
                r = efi_add_boot_option(
                                slot,
                                pick_efi_boot_option_description(),
                                part,
                                pstart,
                                psize,
                                uuid,
                                path);
                if (r < 0) {
                        int level = c->graceful ? arg_quiet ? LOG_DEBUG : LOG_INFO : LOG_ERR;
                        const char *skip = c->graceful ? ", skipping" : "";

                        log_full_errno(level, r, "Failed to create EFI Boot variable entry%s: %m", skip);

                        return c->graceful ? 0 : r;
                }

                log_info("%s EFI boot entry \"%s\".",
                         existing ? "Updated" : "Created",
                         pick_efi_boot_option_description());
        }

        return insert_into_order(c, slot);
}

static int are_we_installed(InstallContext *c) {
        int r;

        assert(c);

        /* Tests whether systemd-boot is installed. It's not obvious what to use as check here: we could
         * check EFI variables, we could check what binary /EFI/BOOT/BOOT*.EFI points to, or whether the
         * loader entries directory exists. Here we opted to check whether /EFI/systemd/ is non-empty, which
         * should be a suitable and very minimal check for a number of reasons:
         *
         *  → The check is architecture independent (i.e. we check if any systemd-boot loader is installed,
         *    not a specific one.)
         *
         *  → It doesn't assume we are the only boot loader (i.e doesn't check if we own the main
         *    /EFI/BOOT/BOOT*.EFI fallback binary.
         *
         *  → It specifically checks for systemd-boot, not for other boot loaders (which a check for
         *    /boot/loader/entries would do). */

        _cleanup_free_ char *p = path_join(c->esp_path, "/EFI/systemd");
        if (!p)
                return log_oom();

        int esp_fd = acquire_esp_fd(c);
        if (esp_fd < 0)
                return esp_fd;

        _cleanup_close_ int fd = chase_and_openat(esp_fd, "/EFI/systemd", CHASE_AT_RESOLVE_IN_ROOT|CHASE_PROHIBIT_SYMLINKS|CHASE_MUST_BE_DIRECTORY, O_RDONLY|O_CLOEXEC|O_DIRECTORY, /* ret_path= */ NULL);
        if (fd < 0)
                return log_error_errno(fd, "Failed to open '%s': %m", p);

        log_debug("Checking whether %s contains any files%s", p, glyph(GLYPH_ELLIPSIS));
        r = dir_is_empty_at(fd, /* path= */ NULL, /* ignore_hidden_or_backup= */ false);
        if (r < 0 && r != -ENOENT)
                return log_error_errno(r, "Failed to check whether '%s' contains any files: %m", p);

        return r == 0;
}

static int run_install(InstallContext *c) {

        int r;

        assert(c);
        assert(c->operation >= 0);

        if (c->operation == INSTALL_UPDATE) {
                /* If we are updating, don't do anything if sd-boot wasn't actually installed. */
                r = are_we_installed(c);
                if (r < 0)
                        return r;
                if (r == 0) {
                        log_debug("Skipping update because sd-boot is not installed in the ESP.");
                        return 0;
                }
        }

        r = settle_make_entry_directory(c);
        if (r < 0)
                return r;

        const char *arch = arg_arch_all ? "" : get_efi_arch();

        int esp_fd = acquire_esp_fd(c);
        if (esp_fd < 0)
                return esp_fd;

        int dollar_boot_fd = acquire_dollar_boot_fd(c);
        if (dollar_boot_fd < 0)
                return dollar_boot_fd;

        WITH_UMASK(0002) {
                if (c->operation == INSTALL_NEW) {
                        /* Don't create any of these directories when we are just updating. When we update
                         * we'll drop-in our files (unless there are newer ones already), but we won't create
                         * the directories for them in the first place. */
                        r = create_subdirs(c->esp_path, esp_fd, esp_subdirs);
                        if (r < 0)
                                return r;

                        r = create_subdirs(dollar_boot_path(c), dollar_boot_fd, dollar_boot_subdirs);
                        if (r < 0)
                                return r;
                }

                r = install_binaries(c, arch);
                if (r < 0)
                        return r;

                if (c->operation == INSTALL_NEW) {
                        r = install_loader_config(c);
                        if (r < 0)
                                return r;

                        r = install_entry_directory(c);
                        if (r < 0)
                                return r;

                        r = install_entry_token(c);
                        if (r < 0)
                                return r;

                        if (arg_install_random_seed && !c->root) {
                                r = install_random_seed(c->esp_path);
                                if (r < 0)
                                        return r;
                        }

                        r = install_secure_boot_auto_enroll(c);
                        if (r < 0)
                                return r;
                }

                r = install_loader_specification(c);
                if (r < 0)
                        return r;
        }

        (void) sync_everything();

        if (!touch_install_variables(c))
                return 0;

        if (arg_arch_all) {
                log_info("Not changing EFI variables with --all-architectures.");
                return 0;
        }

        char *path = strjoina("/EFI/systemd/systemd-boot", arch, ".efi");
        return install_variables(c, c->esp_part, c->esp_pstart, c->esp_psize, c->esp_uuid, path);
}

static int load_secure_boot_auto_enroll(
                X509 **ret_certificate,
                EVP_PKEY **ret_private_key) {

        int r;

        assert(ret_certificate);
        assert(ret_private_key);

        if (!arg_secure_boot_auto_enroll) {
               *ret_certificate = NULL;
               *ret_private_key = NULL;
               return 0;
        }

        if (arg_certificate_source_type == OPENSSL_CERTIFICATE_SOURCE_FILE) {
                r = parse_path_argument(arg_certificate, /*suppress_root=*/ false, &arg_certificate);
                if (r < 0)
                        return r;
        }

        _cleanup_(X509_freep) X509 *certificate = NULL;
        r = openssl_load_x509_certificate(
                        arg_certificate_source_type,
                        arg_certificate_source,
                        arg_certificate,
                        &certificate);
        if (r < 0)
                return log_error_errno(r, "Failed to load X.509 certificate from %s: %m", arg_certificate);

        if (arg_private_key_source_type == OPENSSL_KEY_SOURCE_FILE) {
                r = parse_path_argument(arg_private_key, /* suppress_root= */ false, &arg_private_key);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse private key path %s: %m", arg_private_key);
        }

        _cleanup_(EVP_PKEY_freep) EVP_PKEY *private_key = NULL;
        r = openssl_load_private_key(
                        arg_private_key_source_type,
                        arg_private_key_source,
                        arg_private_key,
                        &(AskPasswordRequest) {
                                .tty_fd = -EBADF,
                                .id = "bootctl-private-key-pin",
                                .keyring = arg_private_key,
                                .credential = "bootctl.private-key-pin",
                                .until = USEC_INFINITY,
                                .hup_fd = -EBADF,
                        },
                        &private_key,
                        /* ret_ui= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to load private key from %s: %m", arg_private_key);

        *ret_certificate = TAKE_PTR(certificate);
        *ret_private_key = TAKE_PTR(private_key);

        return 0;
}

int verb_install(int argc, char *argv[], void *userdata) {
        int r;

        /* Invoked for both "update" and "install" */

        _cleanup_(install_context_done) InstallContext c = INSTALL_CONTEXT_NULL;
        r = install_context_from_cmdline(&c, streq(argv[0], "install") ? INSTALL_NEW : INSTALL_UPDATE);
        if (r < 0)
                return r;

        r = load_secure_boot_auto_enroll(&c.secure_boot_certificate, &c.secure_boot_private_key);
        if (r < 0)
                return r;

        return run_install(&c);
}

static int remove_boot_efi(InstallContext *c) {
        int r, n = 0;

        assert(c);

        int esp_fd = acquire_esp_fd(c);
        if (esp_fd < 0)
                return esp_fd;

        _cleanup_closedir_ DIR *d = NULL;
        _cleanup_free_ char *p = NULL;
        r = chase_and_opendirat(esp_fd, "/EFI/BOOT", CHASE_AT_RESOLVE_IN_ROOT|CHASE_PROHIBIT_SYMLINKS|CHASE_MUST_BE_DIRECTORY, &p, &d);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to open directory \"%s/EFI/BOOT\": %m", c->esp_path);

        FOREACH_DIRENT(de, d, break) {
                _cleanup_close_ int fd = -EBADF;
                _cleanup_free_ char *v = NULL;

                if (!endswith_no_case(de->d_name, ".efi"))
                        continue;

                fd = xopenat_full(dirfd(d), de->d_name, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY|O_NOFOLLOW, XO_REGULAR, /* mode= */ MODE_INVALID);
                if (fd < 0)
                        return log_error_errno(fd, "Failed to open \"%s/%s\" for reading: %m", p, de->d_name);

                r = pe_is_native_fd(fd);
                if (r < 0) {
                        log_warning_errno(r, "Failed to detect if \"%s/%s\" is native architecture, ignoring: %m", p, de->d_name);
                        continue;
                }
                if (r == 0)
                        continue;

                r = get_file_version(fd, &v);
                if (r == -ESRCH)
                        continue;  /* No version information */
                if (r < 0)
                        return r;
                if (!startswith(v, "systemd-boot "))
                        continue;

                if (unlinkat(dirfd(d), de->d_name, 0) < 0)
                        return log_error_errno(errno, "Failed to remove \"%s/%s\": %m", p, de->d_name);

                log_info("Removed \"%s/%s\".", p, de->d_name);

                n++;
        }

        return n;
}

static int unlink_inode(const char *root, int root_fd, const char *path, mode_t type) {
        int r;

        assert(root);
        assert(root_fd >= 0);
        assert(path);
        assert(IN_SET(type, S_IFREG, S_IFDIR));

        _cleanup_free_ char *fn = NULL;
        r = path_extract_filename(path, &fn);
        if (r < 0)
                return log_error_errno(r, "Failed to extract filename from path '%s': %m", path);

        _cleanup_free_ char *p = path_join(empty_to_root(root), path);
        if (!p)
                return log_oom();

        _cleanup_close_ int parent_fd = -EBADF;
        r = chase_and_unlinkat(root_fd, path, CHASE_AT_RESOLVE_IN_ROOT|CHASE_PROHIBIT_SYMLINKS, S_ISDIR(type) ? AT_REMOVEDIR : 0, /* ret_path= */ NULL);
        if (r < 0) {
                bool ignore = IN_SET(r, -ENOENT, -ENOTEMPTY);
                log_full_errno(ignore ? LOG_DEBUG : LOG_ERR, r, "Failed to remove '%s': %m", p);
                return ignore ? 0 : r;
        }

        log_info("Removed \"%s\".", p);
        return 0;
}

static int remove_subdirs(const char *root, int root_fd, const char *const *subdirs) {
        int r = 0;

        assert(root);
        assert(root_fd);

        STRV_FOREACH(i, subdirs)
                RET_GATHER(r, unlink_inode(root, root_fd, *i, S_IFDIR));

        return r;
}

static int remove_entry_directory(InstallContext *c, const char *path, int fd) {
        assert(c);
        assert(c->make_entry_directory >= 0);
        assert(path);
        assert(fd >= 0);

        if (!c->make_entry_directory || !c->entry_token)
                return 0;

        return unlink_inode(path, fd, c->entry_token, S_IFDIR);
}

static int remove_binaries(InstallContext *c) {
        int r;

        _cleanup_free_ char *p = path_join(c->root, "/EFI/systemd");
        if (!p)
                return log_oom();

        _cleanup_close_ int efi_fd = -EBADF;
        r = chaseat(c->root_fd, "EFI", CHASE_AT_RESOLVE_IN_ROOT|CHASE_PROHIBIT_SYMLINKS|CHASE_MUST_BE_DIRECTORY, /* ret_path= */ NULL, &efi_fd);
        if (r < 0 && r != -ENOENT)
                return log_error_errno(r, "Failed to remove '%s': %m", p);

        r = rm_rf_at(efi_fd, "systemd", REMOVE_ROOT|REMOVE_PHYSICAL|REMOVE_MISSING_OK);
        RET_GATHER(r, remove_boot_efi(c));
        return r;
}

static int remove_variables(sd_id128_t uuid, const char *path, bool in_order) {
        uint16_t slot;
        int r;

        r = find_slot(uuid, path, &slot);
        if (r != 1)
                return 0;

        r = efi_remove_boot_option(slot);
        if (r < 0)
                return r;

        if (in_order)
                return remove_from_order(slot);

        return 0;
}

static int remove_loader_variables(void) {
        int r = 0;

        /* Remove all persistent loader variables we define */

        FOREACH_STRING(var,
                       EFI_LOADER_VARIABLE_STR("LoaderConfigConsoleMode"),
                       EFI_LOADER_VARIABLE_STR("LoaderConfigTimeout"),
                       EFI_LOADER_VARIABLE_STR("LoaderConfigTimeoutOneShot"),
                       EFI_LOADER_VARIABLE_STR("LoaderEntryDefault"),
                       EFI_LOADER_VARIABLE_STR("LoaderEntrySysFail"),
                       EFI_LOADER_VARIABLE_STR("LoaderEntryLastBooted"),
                       EFI_LOADER_VARIABLE_STR("LoaderEntryOneShot"),
                       EFI_LOADER_VARIABLE_STR("LoaderSystemToken")) {

                int q;

                q = efi_set_variable(var, NULL, 0);
                if (q == -ENOENT)
                        continue;
                if (q < 0)
                        RET_GATHER(r, log_warning_errno(q, "Failed to remove EFI variable %s: %m", var));
                else
                        log_info("Removed EFI variable %s.", var);
        }

        return r;
}

int verb_remove(int argc, char *argv[], void *userdata) {
        sd_id128_t uuid = SD_ID128_NULL;
        int r;

        _cleanup_(install_context_done) InstallContext c = INSTALL_CONTEXT_NULL;
        r = install_context_from_cmdline(&c, INSTALL_REMOVE);
        if (r < 0)
                return r;

        r = settle_make_entry_directory(&c);
        if (r < 0)
                return r;

        int esp_fd = acquire_esp_fd(&c);
        if (esp_fd < 0)
                return esp_fd;

        int dollar_boot_fd = acquire_dollar_boot_fd(&c); /* this will initialize .xbootldr_fd */
        if (dollar_boot_fd < 0)
                return dollar_boot_fd;

        r = remove_binaries(&c);
        RET_GATHER(r, unlink_inode(c.esp_path, esp_fd, "/loader/loader.conf", S_IFREG));
        RET_GATHER(r, unlink_inode(c.esp_path, esp_fd, "/loader/random-seed", S_IFREG));
        RET_GATHER(r, unlink_inode(c.esp_path, esp_fd, "/loader/entries.srel", S_IFREG));

        FOREACH_STRING(db, "PK.auth", "KEK.auth", "db.auth") {
                _cleanup_free_ char *p = path_join("/loader/keys/auto", db);
                if (!p)
                        return log_oom();

                RET_GATHER(r, unlink_inode(c.esp_path, esp_fd, p, S_IFREG));
        }

        RET_GATHER(r, remove_subdirs(c.esp_path, esp_fd, esp_subdirs));
        RET_GATHER(r, remove_subdirs(c.esp_path, esp_fd, dollar_boot_subdirs));
        RET_GATHER(r, unlink_inode(c.esp_path, esp_fd, "/loader/keys/auto", S_IFDIR));
        RET_GATHER(r, remove_entry_directory(&c, c.esp_path, esp_fd));

        if (c.xbootldr_fd >= 0) {
                /* Remove a subset of these also from the XBOOTLDR partition if it exists */
                RET_GATHER(r, unlink_inode(c.xbootldr_path, c.xbootldr_fd, "/loader/entries.srel", S_IFREG));
                RET_GATHER(r, remove_subdirs(c.xbootldr_path, c.xbootldr_fd, dollar_boot_subdirs));
                RET_GATHER(r, remove_entry_directory(&c, c.xbootldr_path, c.xbootldr_fd));
        }

        (void) sync_everything();

        if (!touch_install_variables(&c))
                return r;

        if (arg_arch_all) {
                log_info("Not changing EFI variables with --all-architectures.");
                return r;
        }

        char *path = strjoina("/EFI/systemd/systemd-boot", get_efi_arch(), ".efi");
        RET_GATHER(r, remove_variables(uuid, path, /* in_order= */ true));
        RET_GATHER(r, remove_loader_variables());
        return r;
}

int verb_is_installed(int argc, char *argv[], void *userdata) {
        int r;

        _cleanup_(install_context_done) InstallContext c = INSTALL_CONTEXT_NULL;
        r = install_context_from_cmdline(&c, INSTALL_TEST);
        if (r < 0)
                return r;

        r = are_we_installed(&c);
        if (r < 0)
                return r;

        if (r > 0) {
                if (!arg_quiet)
                        puts("yes");
                return EXIT_SUCCESS;
        } else {
                if (!arg_quiet)
                        puts("no");
                return EXIT_FAILURE;
        }
}
