/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <unistd.h>

#include "sd-device.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "ask-password-api.h"
#include "blockdev-util.h"
#include "boot-entry.h"
#include "bootctl.h"
#include "bootctl-install.h"
#include "bootctl-random-seed.h"
#include "bootctl-util.h"
#include "chase.h"
#include "copy.h"
#include "crypto-util.h"
#include "dirent-util.h"
#include "efi-api.h"
#include "efi.h"
#include "efivars.h"
#include "env-file.h"
#include "fd-util.h"
#include "fileio.h"
#include "find-esp.h"
#include "fs-util.h"
#include "glyph-util.h"
#include "hexdecoct.h"
#include "id128-util.h"
#include "install-file.h"
#include "io-util.h"
#include "json-util.h"
#include "kernel-config.h"
#include "log.h"
#include "manifest-util.h"
#include "parse-argument.h"
#include "path-util.h"
#include "pe-binary.h"
#include "rm-rf.h"
#include "sha256.h"
#include "sort-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "tmpfile-util.h"
#include "umask-util.h"
#include "utf8.h"
#include "varlink-util.h"

typedef enum InstallOperation {
        INSTALL_NEW,
        INSTALL_UPDATE,
        INSTALL_REMOVE,
        INSTALL_TEST,
        _INSTALL_OPERATION_MAX,
        _INSTALL_OPERATION_INVALID = -1,
} InstallOperation;

/* bootctl copies the contents of this directory into the ESP in addition to systemd-boot. */
#define EXTRA_FILES_DIR_NAME "extra"
#define EXTRA_FILES_DIR BOOTLIBDIR "/" EXTRA_FILES_DIR_NAME

/* bootctl lists the extra files that it installed in this file in the ESP, in the format of sha256sum(1). */
#define EXTRA_FILES_MANIFEST_DIR "EFI/systemd"
#define EXTRA_FILES_MANIFEST_NAME "extra-files.sha256"

#define EXTRA_FILES_MAX 128U
#define EXTRA_FILES_DEPTH_MAX 8U

typedef enum ExtraAction {
        EXTRA_ACTION_SKIP,   /* bootctl does not manage the file in the ESP and leaves it alone. */
        EXTRA_ACTION_KEEP,   /* bootctl manages the file in the ESP and does not replace it. */
        EXTRA_ACTION_COPY,
        EXTRA_ACTION_FAILED,
} ExtraAction;

typedef struct ExtraFile {
        char *path;        /* The path is relative to the root of the ESP. */
        char *source_path; /* The source path is NULL for an entry that was read from the manifest. */
        int source_fd;
        uint8_t hash[SHA256_DIGEST_SIZE];
        ExtraAction action;
        bool dest_managed;                     /* The file exists in the ESP and bootctl manages it. */
        uint8_t dest_hash[SHA256_DIGEST_SIZE]; /* dest_hash is only valid if dest_managed is set. */
} ExtraFile;

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
#if HAVE_OPENSSL
        X509 *secure_boot_certificate;
        EVP_PKEY *secure_boot_private_key;
#endif
        int touch_variables; /* tri-state */
        DIR *source_dir;            /* source_dir is the BOOTLIBDIR that open_source_directory() selected.
                                     * It is NULL if there is nothing to install. */
        char *source_path;
        bool source_from_image;     /* source_dir is located below c->root_fd and not on the host. */
        bool changed;               /* An extra file or a boot entry was installed or removed. */
        bool extra_manifest_damaged;
        ExtraFile *extra_files;     /* extra_files lists the files below EXTRA_FILES_DIR. */
        size_t n_extra_files;
        ExtraFile *extra_manifest;  /* extra_manifest lists the files that an earlier invocation installed.
                                     * A path is listed once per hash if an earlier invocation was
                                     * interrupted. */
        size_t n_extra_manifest;
        ExtraFile *extra_installed; /* extra_installed lists the files that bootctl manages after
                                     * install_extra_files() ran. */
        size_t n_extra_installed;
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

static const char* install_operation_table[_INSTALL_OPERATION_MAX] = {
        [INSTALL_NEW]    = "new",
        [INSTALL_UPDATE] = "update",
        [INSTALL_REMOVE] = "remove",
        [INSTALL_TEST]   = "test",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(install_operation, InstallOperation);

static void extra_file_array_free(ExtraFile *files, size_t n) {
        FOREACH_ARRAY(f, files, n) {
                free(f->path);
                free(f->source_path);
                safe_close(f->source_fd);
        }

        free(files);
}

static void install_context_done(InstallContext *c) {
        assert(c);

        extra_file_array_free(c->extra_files, c->n_extra_files);
        c->extra_files = NULL;
        c->n_extra_files = 0;
        extra_file_array_free(c->extra_manifest, c->n_extra_manifest);
        c->extra_manifest = NULL;
        c->n_extra_manifest = 0;
        extra_file_array_free(c->extra_installed, c->n_extra_installed);
        c->extra_installed = NULL;
        c->n_extra_installed = 0;

        c->source_dir = safe_closedir(c->source_dir);
        c->source_path = mfree(c->source_path);

        c->root = mfree(c->root);
        c->root_fd = safe_close(c->root_fd);
        c->install_layout = mfree(c->install_layout);
        c->entry_token = mfree(c->entry_token);
        c->esp_path = mfree(c->esp_path);
        c->esp_fd = safe_close(c->esp_fd);
        c->xbootldr_path = mfree(c->xbootldr_path);
        c->xbootldr_fd = safe_close(c->xbootldr_fd);
#if HAVE_OPENSSL
        if (c->secure_boot_private_key) {
                sym_EVP_PKEY_free(c->secure_boot_private_key);
                c->secure_boot_private_key = NULL;
        }
        if (c->secure_boot_certificate) {
                sym_X509_free(c->secure_boot_certificate);
                c->secure_boot_certificate = NULL;
        }
#endif
}

static int install_context_from_cmdline(
                InstallContext *ret,
                InstallOperation operation) {

        int r;

        assert(ret);
        assert(operation >= 0);
        assert(operation < _INSTALL_OPERATION_MAX);

        _cleanup_(install_context_done) InstallContext b = INSTALL_CONTEXT_NULL;
        b.operation = operation;
        b.graceful = arg_graceful() == ARG_GRACEFUL_FORCE ||
                (operation == INSTALL_UPDATE && arg_graceful() != ARG_GRACEFUL_NO);
        b.machine_id = arg_machine_id;
        b.entry_token_type = arg_entry_token_type;
        b.make_entry_directory = arg_make_entry_directory;
        b.install_source = arg_install_source;

        if (strdup_to(&b.entry_token, arg_entry_token) < 0 ||
            strdup_to(&b.install_layout, arg_install_layout) < 0)
                return log_oom();

        if (arg_root) {
                b.root_fd = xopenat(AT_FDCWD, arg_root, O_DIRECTORY|O_PATH);
                if (b.root_fd < 0)
                        return log_error_errno(b.root_fd, "Failed to open root directory '%s': %m", arg_root);

                r = strdup_to(&b.root, arg_root);
                if (r < 0)
                        return log_oom();
        } else
                b.root_fd = XAT_FDROOT;

        r = acquire_esp(/* unprivileged_mode= */ false,
                        b.graceful,
                        &b.esp_fd,
                        &b.esp_part,
                        &b.esp_pstart,
                        &b.esp_psize,
                        &b.esp_uuid,
                        /* ret_devid= */ NULL);
        /* If --graceful is specified and we can't find an ESP, handle this cleanly */
        if (r < 0 && (!b.graceful || r != -ENOKEY))
                return r;

        if (r >= 0) { /* An ESP has been found */
                assert(arg_esp_path);

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
                        /* ret_devid= */ NULL);
        if (r < 0)
                return r;
        if (r > 0) { /* XBOOTLDR has been found */
                assert(arg_xbootldr_path);

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

        b.touch_variables = arg_touch_variables;

        *ret = TAKE_GENERIC(b, InstallContext, INSTALL_CONTEXT_NULL);

        return !!ret->esp_path; /* return positive if we found an ESP */
}

static int acquire_dollar_boot_fd(InstallContext *c) {
        assert(c);

        if (c->xbootldr_fd >= 0)
                return c->xbootldr_fd;

        if (c->esp_fd >= 0)
                return c->esp_fd;

        return log_error_errno(SYNTHETIC_ERRNO(EBADF), "Cannot access $BOOT, as neither ESP nor XBOOTLDR have been found.");
}

static const char* dollar_boot_path(InstallContext *c) {
        assert(c);

        return c->xbootldr_path ?: c->esp_path;
}

static bool should_touch_install_variables(InstallContext *c) {
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

        log_debug("Loaded machine ID %s from '%s/etc/machine-id'.", strempty(c->root), SD_ID128_TO_STRING(c->machine_id));
        return 0;
}

static int load_etc_machine_info(InstallContext *c) {
        /* systemd v250 added support to store the kernel-install layout setting and the machine ID to use
         * for setting up the ESP in /etc/machine-info. The newer /etc/kernel/entry-token file, as well as
         * the $layout field in /etc/kernel/install.conf are better replacements for this though, hence this
         * has been deprecated and is only returned for compatibility. */
        _cleanup_free_ char *s = NULL, *layout = NULL;
        int r;

        assert(c);

        _cleanup_free_ char *j = path_join(c->root, "/etc/machine-info");
        if (!j)
                return log_oom();

        _cleanup_close_ int fd =
                chase_and_openat(
                                c->root_fd,
                                c->root_fd,
                                "/etc/machine-info",
                                CHASE_MUST_BE_REGULAR,
                                O_RDONLY,
                                /* ret_path= */ NULL);
        if (fd == -ENOENT)
                return 0;
        if (fd < 0)
                return log_error_errno(fd, "Failed to open '%s': %m", j);

        r = parse_env_file_fd(
                        fd, "/etc/machine-info",
                        "KERNEL_INSTALL_LAYOUT", &layout,
                        "KERNEL_INSTALL_MACHINE_ID", &s);
        if (r < 0)
                return log_error_errno(r, "Failed to parse '%s': %m", j);

        if (!isempty(s)) {
                if (!arg_quiet)
                        log_notice("Read $KERNEL_INSTALL_MACHINE_ID from '%s'. "
                                   "Please move it to '%s/etc/kernel/entry-token'.", j, strempty(c->root));

                r = sd_id128_from_string(s, &c->machine_id);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse KERNEL_INSTALL_MACHINE_ID=\"%s\" in '%s': %m", s, j);

                log_debug("Loaded KERNEL_INSTALL_MACHINE_ID=\"%s\" from '%s'.",
                          SD_ID128_TO_STRING(c->machine_id), j);
        }

        if (!isempty(layout)) {
                if (!arg_quiet)
                        log_notice("Read $KERNEL_INSTALL_LAYOUT from '%s'. "
                                   "Please move it to the layout= setting of '%s/etc/kernel/install.conf'.", j, strempty(c->root));

                log_debug("KERNEL_INSTALL_LAYOUT=\"%s\" is specified in '%s'.", layout, j);
                free_and_replace(c->install_layout, layout);
        }

        return 0;
}

static int load_kernel_install_layout(InstallContext *c) {
        _cleanup_free_ char *layout = NULL;
        int r;

        assert(c);

        const char *e = secure_getenv("KERNEL_INSTALL_CONF_ROOT");
        r = load_kernel_install_conf_at(
                        e ? NULL : c->root,
                        e ? XAT_FDROOT : c->root_fd,
                        e,
                        /* ret_machine_id= */ NULL,
                        /* ret_boot_root= */ NULL,
                        &layout,
                        /* ret_initrd_generator= */ NULL,
                        /* ret_uki_generator= */ NULL,
                        /* ret_entry_name_format= */ NULL);
        if (r <= 0)
                return r;

        if (!isempty(layout)) {
                log_debug("layout=\"%s\" is specified in config.", layout);
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
                        e ? XAT_FDROOT : c->root_fd,
                        e,
                        c->machine_id,
                        /* machine_id_is_random= */ false,
                        &c->entry_token_type,
                        &c->entry_token);
        if (r < 0)
                return r;

        log_debug("Using entry token: %s", c->entry_token);

        bool layout_type1 = use_boot_loader_spec_type1(c);
        if (c->make_entry_directory < 0) { /* Automatic mode */
                if (layout_type1) {
                        if (c->entry_token_type == BOOT_ENTRY_TOKEN_MACHINE_ID) {
                                _cleanup_free_ char *j = path_join(c->root, "/etc/machine-id");
                                if (!j)
                                        return log_oom();

                                _cleanup_close_ int fd = -EBADF;
                                r = chaseat(c->root_fd,
                                            c->root_fd,
                                            "/etc/machine-id",
                                            CHASE_MUST_BE_REGULAR,
                                            /* ret_path= */ NULL,
                                            &fd);
                                if (r < 0)
                                        return log_debug_errno(r, "Unable to open '%s': %m", j);

                                r = fd_is_temporary_fs(fd);
                                if (r < 0)
                                        return log_debug_errno(r, "Couldn't determine whether '%s' is on a temporary file system: %m", j);

                                c->make_entry_directory = r == 0;
                        } else
                                c->make_entry_directory = true;
                } else
                        c->make_entry_directory = false;
        }

        if (c->make_entry_directory > 0 && !layout_type1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "KERNEL_INSTALL_LAYOUT=\"%s\" is configured, but Boot Loader Specification Type #1 entry directory creation was requested.",
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

        /* Does not reposition file offset */

        r = get_file_version(fd_from, &a);
        if (r == -ESRCH)
                return log_notice_errno(r, "Source file \"%s\" does not carry version information!", from);
        if (r < 0)
                return log_error_errno(r, "Failed to get file version of '%s': %m", from);

        r = get_file_version(fd_to, &b);
        if (r == -ESRCH)
                return log_info_errno(r, "Skipping \"%s\", it's owned by another boot loader (no version info found).", to);
        if (r < 0)
                return log_error_errno(r, "Failed to get file version of '%s': %m", to);
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
        }

        _cleanup_free_ char *t = NULL;
        _cleanup_close_ int write_fd = -EBADF;
        write_fd = open_tmpfile_linkable_at(dest_parent_fd, dest_filename, O_WRONLY, &t);
        if (write_fd < 0)
                return log_error_errno(write_fd, "Failed to open \"%s\" for writing: %m", dest_path);

        CLEANUP_TMPFILE_AT(dest_parent_fd, t);

        r = copy_bytes_offset(
                        source_fd,
                        /* foffset= */ &(uint64_t) { 0 },
                        write_fd,
                        /* toffset= */ NULL,
                        /* max_bytes= */ UINT64_MAX,
                        /* copy_flags= */ 0);
        if (r < 0)
                return log_error_errno(r, "Failed to copy data from \"%s\" to \"%s\": %m", source_path, dest_path);

        (void) copy_times(source_fd, write_fd, /* flags= */ 0);
        (void) fchmod(write_fd, 0644);

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

        r = chaseat(root_fd,
                    root_fd,
                    path,
                    CHASE_PROHIBIT_SYMLINKS|CHASE_MKDIR_0755|CHASE_MUST_BE_DIRECTORY,
                    /* ret_path= */ NULL,
                    /* ret_fd= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to create \"%s\": %m", p);

        log_info("Created directory \"%s\".", p);
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

static bool extra_path_equal(const char *a, const char *b) {
        assert(a);
        assert(b);

        /* VFAT is case insensitive, hence two paths that only differ in case name the same file.
         * strcasecmp() cannot be used for the comparison, because it follows the locale: in a Turkish
         * locale it does not treat "I" and "i" as the same letter. */
        return ascii_strcasecmp_nn(a, strlen(a), b, strlen(b)) == 0;
}

static const char* extra_path_startswith(const char *path, const char *prefix) {
        assert(path);
        assert(prefix);

        size_t n = strlen(prefix);
        if (strlen(path) < n || ascii_strcasecmp_n(path, prefix, n) != 0)
                return NULL;

        return path + n;
}

static bool extra_path_endswith(const char *path, const char *suffix) {
        assert(path);
        assert(suffix);

        size_t n = strlen(path), m = strlen(suffix);
        return n >= m && ascii_strcasecmp_n(path + n - m, suffix, m) == 0;
}

static bool extra_filename_is_valid(const char *name) {
        assert(name);

        /* The manifest only stores UTF-8 file names. */
        if (!filename_is_valid(name) || !utf8_is_valid(name))
                return false;

        /* VFAT refuses control characters and the characters listed below, and it strips trailing dots and
         * spaces from file names. */
        for (const char *p = name; *p; p++)
                if ((unsigned char) *p < 0x20 || *p == 0x7f || strchr("\"*:<>?\\|", *p))
                        return false;

        return !endswith(name, ".") && !endswith(name, " ");
}

static bool extra_path_is_valid(const char *path) {
        assert(path);

        if (path_is_absolute(path) || !path_is_normalized(path))
                return false;

        for (const char *p = path;;) {
                const char *e;
                int r;

                r = path_find_first_component(&p, /* accept_dot_dot= */ false, &e);
                if (r < 0)
                        return false;
                if (r == 0)
                        return true;

                _cleanup_free_ char *component = strndup(e, r);
                if (!component || !extra_filename_is_valid(component))
                        return false;
        }
}

static int extra_file_compare(const ExtraFile *a, const ExtraFile *b) {
        return ascii_strcasecmp_nn(a->path, strlen(a->path), b->path, strlen(b->path));
}

static ExtraFile* extra_file_find(ExtraFile *files, size_t n, const char *path) {
        assert(path);

        path = skip_leading_slash(path);

        FOREACH_ARRAY(f, files, n)
                if (extra_path_equal(f->path, path))
                        return f;

        return NULL;
}

static bool extra_manifest_lists(InstallContext *c, const char *path, const uint8_t hash[static SHA256_DIGEST_SIZE]) {
        assert(c);
        assert(path);

        path = skip_leading_slash(path);

        FOREACH_ARRAY(m, c->extra_manifest, c->n_extra_manifest)
                if (extra_path_equal(m->path, path) && memcmp(m->hash, hash, SHA256_DIGEST_SIZE) == 0)
                        return true;

        return false;
}

static void extra_manifest_forget(InstallContext *c, const char *path) {
        assert(c);
        assert(path);

        path = skip_leading_slash(path);

        for (size_t i = 0; i < c->n_extra_manifest;) {
                ExtraFile *m = c->extra_manifest + i;

                if (!extra_path_equal(m->path, path)) {
                        i++;
                        continue;
                }

                free(m->path);
                memmove(m, m + 1, (c->n_extra_manifest - i - 1) * sizeof(ExtraFile));
                c->n_extra_manifest--;
        }
}

static bool extra_path_is_entry_point(const char *path) {
        const char *e;

        assert(path);

        /* The firmware starts EFI/BOOT/BOOT<ARCH>.EFI and the binary that is registered in the boot loader
         * list directly. install_extra_files() installs them after the files that they load. */
        e = extra_path_startswith(path, "EFI/BOOT/BOOT") ?: extra_path_startswith(path, "EFI/systemd/boot");
        return e && !strchr(e, '/') && extra_path_endswith(e, ".efi");
}

static int extra_files_add(
                InstallContext *c,
                const char *path,
                const char *source_path,
                int source_fd) {

        int r;

        assert(c);
        assert(path);
        assert(source_path);
        assert(source_fd >= 0);

        if (c->n_extra_files >= EXTRA_FILES_MAX)
                return log_error_errno(SYNTHETIC_ERRNO(E2BIG),
                                       "More than %u files below '%s', refusing.", EXTRA_FILES_MAX, EXTRA_FILES_DIR);

        /* bootctl installs the systemd-boot binaries as EFI/systemd/systemd-boot*, and it writes the
         * manifest. An extra file must not replace them. */
        if (extra_path_startswith(path, "EFI/systemd/systemd-boot") ||
            extra_path_equal(path, EXTRA_FILES_MANIFEST_DIR "/" EXTRA_FILES_MANIFEST_NAME))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "'%s' uses a file name that is reserved for systemd-boot, refusing.", source_path);

        _cleanup_free_ char *p = strdup(path), *sp = strdup(source_path);
        if (!p || !sp)
                return log_oom();

        _cleanup_close_ int fd = fd_reopen(source_fd, O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0)
                return log_error_errno(fd, "Failed to open '%s': %m", source_path);

        uint8_t hash[SHA256_DIGEST_SIZE];
        r = sha256_fd(fd, UINT64_MAX, hash);
        if (r < 0)
                return log_error_errno(r, "Failed to hash '%s': %m", source_path);

        if (!GREEDY_REALLOC(c->extra_files, c->n_extra_files + 1))
                return log_oom();

        ExtraFile *f = c->extra_files + c->n_extra_files++;
        *f = (ExtraFile) {
                .path = TAKE_PTR(p),
                .source_path = TAKE_PTR(sp),
                .source_fd = TAKE_FD(fd),
        };
        memcpy(f->hash, hash, sizeof(hash));

        return 0;
}

static int load_extra_directory(
                InstallContext *c,
                int root_fd,
                const char *source,
                const char *prefix,
                unsigned depth) {

        int r;

        assert(c);
        assert(source);

        /* Symlinks are followed, so that a package can link the files of another package into
         * EXTRA_FILES_DIR. A symlink to a parent directory hence makes the hierarchy infinitely deep. */
        if (depth > EXTRA_FILES_DEPTH_MAX)
                return log_error_errno(SYNTHETIC_ERRNO(ELOOP),
                                       "Directory '%s' is nested more than %u levels deep, refusing.", source, EXTRA_FILES_DEPTH_MAX);

        _cleanup_closedir_ DIR *d = NULL;
        r = chase_and_opendirat(root_fd, root_fd, source, CHASE_MUST_BE_DIRECTORY, /* ret_path= */ NULL, &d);
        if (r < 0)
                return log_error_errno(r, "Failed to open directory '%s': %m", source);

        FOREACH_DIRENT_ALL(de, d, return log_error_errno(errno, "Failed to read directory '%s': %m", source)) {
                if (dot_or_dot_dot(de->d_name))
                        continue;

                _cleanup_free_ char *child = path_join(source, de->d_name);
                if (!child)
                        return log_oom();

                if (!extra_filename_is_valid(de->d_name))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "'%s' is not a valid file name for the ESP, refusing.", child);

                _cleanup_free_ char *path = path_join(prefix, de->d_name);
                if (!path)
                        return log_oom();

                struct stat st;
                if (fstatat(dirfd(d), de->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0)
                        return log_error_errno(errno, "Failed to stat '%s': %m", child);

                /* If the target of a symlink does not exist, chaseat() returns the path of the target and
                 * no file descriptor. */
                _cleanup_free_ char *resolved = NULL;
                _cleanup_close_ int fd = -EBADF;
                r = chaseat(root_fd, root_fd, child, CHASE_NONEXISTENT, &resolved, &fd);
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve '%s': %m", child);

                /* install_binaries() prefers systemd-boot<arch>.efi.signed over systemd-boot<arch>.efi. A
                 * symlink cannot name whichever of the two files exists, hence apply the same rule to the
                 * target of a symlink: if the target is called "<name>.efi" and "<name>.efi.signed" exists
                 * next to it, the signed file is installed under the name of the symlink. */
                if (S_ISLNK(st.st_mode) && extra_path_endswith(resolved, ".efi")) {
                        _cleanup_free_ char *signed_path = strjoin(resolved, ".signed");
                        if (!signed_path)
                                return log_oom();

                        _cleanup_close_ int signed_fd = chase_and_openat(
                                        root_fd,
                                        root_fd,
                                        signed_path,
                                        CHASE_MUST_BE_REGULAR,
                                        O_RDONLY|O_CLOEXEC|O_NOCTTY,
                                        /* ret_path= */ NULL);
                        if (signed_fd >= 0) {
                                log_debug("'%s' points to '%s', installing '%s' instead.", child, resolved, signed_path);

                                r = extra_files_add(c, path, signed_path, signed_fd);
                                if (r < 0)
                                        return r;

                                continue;
                        }
                        if (signed_fd != -ENOENT)
                                return log_error_errno(signed_fd, "Failed to open '%s': %m", signed_path);
                }

                if (fd < 0)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                               "'%s' points to '%s', which does not exist, refusing.", child, resolved);

                if (fstat(fd, &st) < 0)
                        return log_error_errno(errno, "Failed to stat '%s': %m", child);

                if (S_ISDIR(st.st_mode))
                        r = load_extra_directory(c, root_fd, child, path, depth + 1);
                else if (S_ISREG(st.st_mode))
                        r = extra_files_add(c, path, child, fd);
                else
                        r = log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                            "'%s' is neither a regular file nor a directory, refusing.", child);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int load_extra_files(InstallContext *c) {
        int r;

        assert(c);
        assert(c->n_extra_files == 0);

        /* The extra files are taken from the root directory that contains the systemd-boot binaries. If
         * open_source_directory() found no systemd-boot to install, for example because the package that
         * contains BOOTLIBDIR was removed, the extra files in the ESP are left alone. A
         * missing BOOTLIBDIR must not be mistaken for an EXTRA_FILES_DIR without files. */
        if (!c->source_dir) {
                log_debug("No systemd-boot binaries to install, leaving the extra files in the ESP alone.");
                return 0;
        }

        int root_fd = c->source_from_image ? c->root_fd : XAT_FDROOT;

        r = chase_and_accessat(root_fd, root_fd, EXTRA_FILES_DIR, CHASE_MUST_BE_DIRECTORY, F_OK, /* ret_path= */ NULL);
        if (r == -ENOENT) {
                /* A symlink whose target does not exist must not be mistaken for a missing directory,
                 * because the extra files in the ESP would be removed. */
                struct stat st;
                if (fstatat(dirfd(c->source_dir), EXTRA_FILES_DIR_NAME, &st, AT_SYMLINK_NOFOLLOW) >= 0)
                        return log_error_errno(r, "'%s' points to a directory that does not exist, refusing.", EXTRA_FILES_DIR);
                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to stat '%s': %m", EXTRA_FILES_DIR);

                log_debug("Directory '%s' does not exist, not installing any extra files.", EXTRA_FILES_DIR);
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to check for '%s': %m", EXTRA_FILES_DIR);

        r = load_extra_directory(c, root_fd, EXTRA_FILES_DIR, /* prefix= */ NULL, /* depth= */ 0);
        if (r < 0)
                return r;

        typesafe_qsort(c->extra_files, c->n_extra_files, extra_file_compare);

        /* Refuse collisions before the ESP is modified. */
        FOREACH_ARRAY(a, c->extra_files, c->n_extra_files)
                FOREACH_ARRAY(b, c->extra_files, c->n_extra_files) {
                        if (a >= b)
                                continue;

                        if (extra_path_equal(a->path, b->path))
                                return log_error_errno(SYNTHETIC_ERRNO(EEXIST),
                                                       "'%s' and '%s' only differ in case and are the same file in the ESP, refusing.",
                                                       a->source_path, b->source_path);

                        const char *e = extra_path_startswith(b->path, a->path) ?: extra_path_startswith(a->path, b->path);
                        if (e && e[0] == '/')
                                return log_error_errno(SYNTHETIC_ERRNO(EEXIST),
                                                       "'%s' and '%s' need a file and a directory of the same name in the ESP, refusing.",
                                                       a->source_path, b->source_path);
                }

        return 0;
}

static int extra_file_array_add(
                ExtraFile **files,
                size_t *n,
                const char *path,
                const uint8_t hash[static SHA256_DIGEST_SIZE]) {

        assert(files);
        assert(n);
        assert(path);

        _cleanup_free_ char *p = strdup(path);
        if (!p)
                return log_oom();

        if (!GREEDY_REALLOC(*files, *n + 1))
                return log_oom();

        ExtraFile *f = *files + (*n)++;
        *f = (ExtraFile) {
                .path = TAKE_PTR(p),
                .source_fd = -EBADF,
        };
        memcpy(f->hash, hash, SHA256_DIGEST_SIZE);

        return 0;
}

static int load_extra_manifest(InstallContext *c) {
        int r;

        assert(c);
        assert(c->n_extra_manifest == 0);

        if (c->esp_fd < 0)
                return c->esp_fd;

        _cleanup_fclose_ FILE *f = NULL;
        r = chase_and_fopenat_unlocked(
                        c->esp_fd,
                        c->esp_fd,
                        EXTRA_FILES_MANIFEST_DIR "/" EXTRA_FILES_MANIFEST_NAME,
                        CHASE_PROHIBIT_SYMLINKS|CHASE_MUST_BE_REGULAR,
                        "re",
                        /* ret_path= */ NULL,
                        &f);
        if (r == -ENOENT)
                return 0;
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                /* A manifest that cannot be read is handled like a manifest that cannot be parsed. It must
                 * block neither the installation of systemd-boot nor "bootctl remove". */
                log_warning_errno(r, "Failed to open '%s' in the ESP, ignoring: %m", EXTRA_FILES_MANIFEST_DIR "/" EXTRA_FILES_MANIFEST_NAME);
                c->extra_manifest_damaged = true;
                return 0;
        }

        for (size_t line_nr = 0;;) {
                _cleanup_(iovec_done) struct iovec digest = {};
                _cleanup_free_ char *path = NULL;

                r = manifest_parse_sums(f, &line_nr, &path, &digest);
                if (r == -ENOMEM)
                        return r;
                if (r < 0) {
                        /* manifest_parse_sums() logged the reason. run_install() does not rewrite a damaged
                         * manifest during an update, because the files that the rest of the manifest lists
                         * would not be managed by bootctl anymore. */
                        log_warning("Ignoring the rest of '%s' in the ESP.", EXTRA_FILES_MANIFEST_DIR "/" EXTRA_FILES_MANIFEST_NAME);
                        c->extra_manifest_damaged = true;
                        break;
                }
                if (r == 0)
                        break;

                /* The paths are used to delete files in the ESP, hence only accept what bootctl writes.
                 * An interrupted invocation leaves two hashes per path in the manifest. */
                if (digest.iov_len != SHA256_DIGEST_SIZE || !extra_path_is_valid(path) || c->n_extra_manifest >= 2 * EXTRA_FILES_MAX) {
                        log_warning("Ignoring invalid line %zu in '%s' in the ESP.", line_nr, EXTRA_FILES_MANIFEST_DIR "/" EXTRA_FILES_MANIFEST_NAME);
                        c->extra_manifest_damaged = true;
                        continue;
                }

                if (extra_manifest_lists(c, path, digest.iov_base))
                        continue;

                r = extra_file_array_add(&c->extra_manifest, &c->n_extra_manifest, path, digest.iov_base);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int write_extra_manifest(InstallContext *c, const ExtraFile *files, size_t n) {
        int r;

        assert(c);
        assert(files || n == 0);

        _cleanup_close_ int dir_fd = -EBADF;
        r = chaseat(c->esp_fd,
                    c->esp_fd,
                    EXTRA_FILES_MANIFEST_DIR,
                    CHASE_PROHIBIT_SYMLINKS|CHASE_MUST_BE_DIRECTORY|(n > 0 ? CHASE_MKDIR_0755 : 0),
                    /* ret_path= */ NULL,
                    &dir_fd);
        if (r == -ENOENT && n == 0)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to open '%s' in the ESP: %m", EXTRA_FILES_MANIFEST_DIR);

        if (n == 0) {
                /* unlinkat() fails with EROFS for a file that does not exist if the ESP is read-only. */
                if (faccessat(dir_fd, EXTRA_FILES_MANIFEST_NAME, F_OK, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT)
                        return 0;

                if (unlinkat(dir_fd, EXTRA_FILES_MANIFEST_NAME, 0) < 0 && errno != ENOENT)
                        return log_error_errno(errno, "Failed to remove '%s' in the ESP: %m", EXTRA_FILES_MANIFEST_DIR "/" EXTRA_FILES_MANIFEST_NAME);

                return 0;
        }

        _cleanup_free_ char *text = NULL;
        FOREACH_ARRAY(f, files, n) {
                _cleanup_free_ char *h = hexmem(f->hash, sizeof(f->hash));
                if (!h)
                        return log_oom();

                if (!strextend(&text, h, "  ", f->path, "\n"))
                        return log_oom();
        }

        /* "bootctl update" runs on every boot. Do not write to the ESP if the manifest is unchanged. */
        _cleanup_free_ char *old_text = NULL;
        if (read_full_file_at(dir_fd, EXTRA_FILES_MANIFEST_NAME, &old_text, /* ret_size= */ NULL) >= 0 && streq(old_text, text))
                return 0;

        r = write_string_file_at(
                        dir_fd,
                        EXTRA_FILES_MANIFEST_NAME,
                        text,
                        WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC|WRITE_STRING_FILE_SYNC|WRITE_STRING_FILE_AVOID_NEWLINE);
        if (r < 0)
                return log_error_errno(r, "Failed to write '%s' in the ESP: %m", EXTRA_FILES_MANIFEST_DIR "/" EXTRA_FILES_MANIFEST_NAME);

        return 0;
}

static int find_name_no_case(int dir_fd, const char *name, char **ret) {
        assert(dir_fd >= 0);
        assert(name);
        assert(ret);

        /* VFAT matches file names case insensitively, but the file systems that the ESP is assembled on
         * when an image is built do not. Look for an existing entry that only differs in case, so that
         * "EFI/Boot" and "EFI/BOOT" are the same directory on any file system. */

        if (faccessat(dir_fd, name, F_OK, AT_SYMLINK_NOFOLLOW) >= 0)
                return strdup_to_full(ret, name);
        if (errno != ENOENT)
                return -errno;

        _cleanup_close_ int fd = fd_reopen(dir_fd, O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        if (fd < 0)
                return fd;

        _cleanup_closedir_ DIR *d = take_fdopendir(&fd);
        if (!d)
                return -errno;

        FOREACH_DIRENT_ALL(de, d, return -errno)
                if (extra_path_equal(de->d_name, name))
                        return strdup_to_full(ret, de->d_name);

        *ret = NULL;
        return 0;
}

static int extra_open_parent(
                InstallContext *c,
                const char *path,
                bool create,
                int *ret_dir_fd,
                char **ret_filename,
                char **ret_path) {

        int r;

        assert(c);
        assert(path);
        assert(ret_dir_fd);
        assert(ret_filename);
        assert(ret_path);

        /* extra_open_parent() opens the directory in the ESP that contains the specified file. It returns the
         * path in ret_path, spelled like the existing directories and files in the ESP. */

        if (c->esp_fd < 0)
                return c->esp_fd;

        _cleanup_close_ int dir_fd = fd_reopen(c->esp_fd, O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        if (dir_fd < 0)
                return dir_fd;

        _cleanup_free_ char *actual_path = NULL;
        for (const char *p = path;;) {
                const char *e;

                r = path_find_first_component(&p, /* accept_dot_dot= */ false, &e);
                if (r <= 0)
                        return r < 0 ? r : -EINVAL;

                _cleanup_free_ char *component = strndup(e, r);
                if (!component)
                        return -ENOMEM;

                _cleanup_free_ char *actual = NULL;
                r = find_name_no_case(dir_fd, component, &actual);
                if (r < 0)
                        return r;

                bool last = isempty(p);
                if (r == 0) {
                        if (!last) {
                                if (!create)
                                        return -ENOENT;

                                if (mkdirat(dir_fd, component, 0755) < 0 && errno != EEXIST)
                                        return -errno;
                        }

                        actual = TAKE_PTR(component);
                }

                if (!path_extend(&actual_path, actual))
                        return -ENOMEM;

                if (last) {
                        *ret_dir_fd = TAKE_FD(dir_fd);
                        *ret_filename = TAKE_PTR(actual);
                        *ret_path = TAKE_PTR(actual_path);
                        return 0;
                }

                int fd = openat(dir_fd, actual, O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
                if (fd < 0)
                        return -errno;

                close_and_replace(dir_fd, fd);
        }
}

static int remove_extra_file(InstallContext *c, const ExtraFile *f, bool remove_directories) {
        int r;

        assert(c);
        assert(f);

        _cleanup_free_ char *j = path_join(c->root, c->esp_path);
        if (!j)
                return log_oom();

        _cleanup_free_ char *filename = NULL, *path = NULL;
        _cleanup_close_ int dir_fd = -EBADF;
        r = extra_open_parent(c, f->path, /* create= */ false, &dir_fd, &filename, &path);
        if (r == -ENOENT)
                return 0;
        if (IN_SET(r, -ENOTDIR, -ELOOP)) {
                log_notice("Not removing '%s/%s', a directory in its path was replaced since it was installed.", j, f->path);
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to open the directory of '%s/%s': %m", j, f->path);

        _cleanup_close_ int fd = xopenat_full(dir_fd, filename, O_RDONLY|O_NOCTTY|O_NOFOLLOW, XO_REGULAR, MODE_INVALID);
        if (fd == -ENOENT)
                return 0;
        if (IN_SET(fd, -EISDIR, -ELOOP, -EBADFD)) {
                log_notice("Not removing '%s/%s', it was replaced by something that is not a regular file.", j, path);
                return 0;
        }
        if (fd < 0)
                return log_error_errno(fd, "Failed to open '%s/%s': %m", j, path);

        uint8_t hash[SHA256_DIGEST_SIZE];
        r = sha256_fd(fd, UINT64_MAX, hash);
        if (r < 0)
                return log_error_errno(r, "Failed to hash '%s/%s': %m", j, path);

        /* Another boot loader or the user replaced the file if its contents changed since it was installed. */
        if (!extra_manifest_lists(c, f->path, hash)) {
                log_notice("Not removing '%s/%s', it was modified since it was installed.", j, path);
                return 0;
        }

        if (unlinkat(dir_fd, filename, 0) < 0)
                return log_error_errno(errno, "Failed to remove '%s/%s': %m", j, path);

        log_info("Removed \"%s/%s\".", j, path);
        c->changed = true;

        if (!remove_directories)
                return 0;

        for (;;) {
                _cleanup_free_ char *parent = NULL;

                r = path_extract_directory(path, &parent);
                if (r < 0) /* The file was located in the root directory of the ESP. */
                        return 0;

                if (unlinkat(c->esp_fd, parent, AT_REMOVEDIR) < 0) {
                        if (!IN_SET(errno, ENOTEMPTY, EEXIST, ENOENT))
                                log_debug_errno(errno, "Failed to remove directory '%s/%s', ignoring: %m", j, parent);
                        return 0;
                }

                log_info("Removed directory \"%s/%s\".", j, parent);
                free_and_replace(path, parent);
        }
}

static int plan_extra_file(InstallContext *c, ExtraFile *f) {
        int r;

        assert(c);
        assert(f);

        /* plan_extra_file() sets f->action without modifying the ESP. "bootctl install" replaces every file.
         * "bootctl update" only replaces a file that bootctl manages. */

        f->action = EXTRA_ACTION_COPY;
        f->dest_managed = false;

        _cleanup_free_ char *j = path_join(c->root, c->esp_path);
        if (!j)
                return log_oom();

        _cleanup_free_ char *filename = NULL, *path = NULL;
        _cleanup_close_ int dir_fd = -EBADF;
        r = extra_open_parent(c, f->path, /* create= */ false, &dir_fd, &filename, &path);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to open the directory of '%s/%s': %m", j, f->path);

        /* extra_open_parent() returns the path as it is spelled in the ESP. */
        free_and_replace(f->path, path);

        _cleanup_free_ char *dest_path = path_join(j, f->path);
        if (!dest_path)
                return log_oom();

        _cleanup_close_ int dest_fd = xopenat_full(dir_fd, filename, O_RDONLY|O_NOCTTY|O_NOFOLLOW, XO_REGULAR, MODE_INVALID);
        if (dest_fd == -ENOENT)
                return 0;
        if (dest_fd < 0)
                return log_error_errno(dest_fd, "Failed to open '%s': %m", dest_path);

        r = sha256_fd(dest_fd, UINT64_MAX, f->dest_hash);
        if (r < 0)
                return log_error_errno(r, "Failed to hash '%s': %m", dest_path);

        _cleanup_free_ char *source_version = NULL, *dest_version = NULL;
        bool listed = extra_manifest_lists(c, f->path, f->dest_hash),
                same = memcmp(f->dest_hash, f->hash, SHA256_DIGEST_SIZE) == 0,
                source_is_sd_boot = get_file_version(f->source_fd, &source_version) >= 0 && startswith(source_version, "systemd-boot "),
                dest_is_sd_boot = get_file_version(dest_fd, &dest_version) >= 0 && startswith(dest_version, "systemd-boot ");

        /* "bootctl install" replaces the file in any case. If the copy fails, install_extra_files() keeps
         * a file that the manifest lists in the manifest. */
        if (c->operation == INSTALL_NEW) {
                f->dest_managed = listed;
                return 0;
        }

        if (dest_is_sd_boot && (source_is_sd_boot || !listed)) {
                /* systemd-boot in the ESP is only replaced by a newer systemd-boot, like the copies that
                 * copy_one_file() updates. A systemd-boot binary that the manifest does not list is not
                 * replaced by another binary, because another installation that shares the ESP might have
                 * installed it. */
                f->dest_managed = listed || source_is_sd_boot;

                if (!same && source_is_sd_boot && compare_version(source_version, dest_version) > 0)
                        return 0;

                if (same)
                        log_debug("\"%s\" is up-to-date.", dest_path);
                else if (source_is_sd_boot)
                        log_info("Skipping \"%s\", same or newer boot loader version in place already.", dest_path);
                else
                        log_notice("Skipping \"%s\", it is a copy of systemd-boot that bootctl did not install from '%s'. Use \"bootctl install\" to replace it.", dest_path, EXTRA_FILES_DIR);

                f->action = f->dest_managed ? EXTRA_ACTION_KEEP : EXTRA_ACTION_SKIP;
                return 0;
        }

        if (!listed) {
                if (same)
                        log_debug("\"%s\" is up-to-date, but was not installed by bootctl, leaving it alone.", dest_path);
                else
                        log_notice("Skipping \"%s\", it was not installed by bootctl or was modified since.", dest_path);

                f->action = EXTRA_ACTION_SKIP;
                return 0;
        }

        /* Every other file is replaced whenever its contents differ. This includes binaries based on
         * systemd-stub: their version is the version of the stub, which does not change when the kernel
         * or the initrd inside of a UKI changes. */
        f->dest_managed = true;
        if (same) {
                log_debug("\"%s\" is up-to-date.", dest_path);
                f->action = EXTRA_ACTION_KEEP;
        }

        return 0;
}

static int install_extra_file(InstallContext *c, ExtraFile *f) {
        int r;

        assert(c);
        assert(f);

        _cleanup_free_ char *j = path_join(c->root, c->esp_path);
        if (!j)
                return log_oom();

        _cleanup_free_ char *filename = NULL, *path = NULL;
        _cleanup_close_ int dir_fd = -EBADF;
        r = extra_open_parent(c, f->path, /* create= */ true, &dir_fd, &filename, &path);
        if (r < 0)
                return log_error_errno(r, "Failed to open the directory of '%s/%s': %m", j, f->path);

        /* extra_open_parent() returns the path as it is spelled in the ESP. */
        free_and_replace(f->path, path);

        _cleanup_free_ char *dest_path = path_join(j, f->path);
        if (!dest_path)
                return log_oom();

        r = copy_file_with_version_check(f->source_path, f->source_fd, dest_path, dir_fd, filename, /* dest_fd= */ -EBADF, /* force= */ true);
        if (r < 0)
                return r;

        c->changed = true;
        return 0;
}

static int remove_extra_conflicts(InstallContext *c) {
        int r;

        assert(c);

        /* A path can be a file in one version of EXTRA_FILES_DIR and a directory in the next version. The
         * file or the directory in the ESP then has to be removed before the new files are copied, although
         * install_extra_files() removes every other file that is not provided anymore afterwards. */

        for (size_t i = 0; i < c->n_extra_manifest;) {
                ExtraFile *m = c->extra_manifest + i;
                bool conflict = false;

                FOREACH_ARRAY(f, c->extra_files, c->n_extra_files) {
                        const char *e = extra_path_startswith(f->path, m->path) ?: extra_path_startswith(m->path, f->path);
                        if (e && e[0] == '/') {
                                conflict = true;
                                break;
                        }
                }
                if (!conflict) {
                        i++;
                        continue;
                }

                r = remove_extra_file(c, m, /* remove_directories= */ true);
                if (r < 0)
                        return r;

                /* extra_manifest_forget() removes every entry of the path, including the entry at i. */
                _cleanup_free_ char *path = strdup(m->path);
                if (!path)
                        return log_oom();

                extra_manifest_forget(c, path);
        }

        /* An earlier invocation might have left an empty directory behind where a file is provided now. */
        FOREACH_ARRAY(f, c->extra_files, c->n_extra_files) {
                _cleanup_free_ char *filename = NULL, *path = NULL;
                _cleanup_close_ int dir_fd = -EBADF;

                if (extra_open_parent(c, f->path, /* create= */ false, &dir_fd, &filename, &path) < 0)
                        continue;

                (void) unlinkat(dir_fd, filename, AT_REMOVEDIR);
        }

        return 0;
}

static int find_slot(sd_id128_t uuid, const char *path, uint16_t *id);

static bool extra_entry_point_is_registered(InstallContext *c, const char *path) {
        assert(c);
        assert(path);

        const char *entry_point = strjoina("EFI/systemd/boot", get_efi_arch(), ".efi");
        if (!extra_path_equal(path, entry_point))
                return false;

        uint16_t slot;
        return find_slot(c->esp_uuid, strjoina("/", entry_point), &slot) > 0;
}

static int install_extra_files(InstallContext *c, bool update_variables) {
        int r, ret = 0;

        assert(c);
        assert(c->n_extra_installed == 0);

        r = remove_extra_conflicts(c);
        if (r < 0)
                return r;

        bool failed = false, copy = false;
        FOREACH_ARRAY(f, c->extra_files, c->n_extra_files) {
                r = plan_extra_file(c, f);
                if (r < 0) {
                        f->action = EXTRA_ACTION_FAILED;
                        failed = true;
                        RET_GATHER(ret, r);
                }

                if (f->action != EXTRA_ACTION_COPY || extra_manifest_lists(c, f->path, f->hash))
                        continue;

                r = extra_file_array_add(&c->extra_manifest, &c->n_extra_manifest, f->path, f->hash);
                if (r < 0)
                        return r;

                copy = true;
        }

        /* The manifest is written with the hashes of the files that are about to be copied before the
         * first file is copied. If bootctl is interrupted, the next invocation hence still recognizes the
         * files that were copied as files that bootctl installed. */
        if (copy) {
                r = write_extra_manifest(c, c->extra_manifest, c->n_extra_manifest);
                if (r < 0)
                        return r;
        }

        /* A boot loader that the firmware starts may load other extra files. The entry points are installed
         * last, and only if every other file was installed. An interrupted or failed update hence does not
         * combine a new entry point with the old version of a file that it loads. */
        for (int entry_points = 0; entry_points <= 1; entry_points++)
                FOREACH_ARRAY(f, c->extra_files, c->n_extra_files) {
                        if (extra_path_is_entry_point(f->path) != !!entry_points)
                                continue;

                        const uint8_t *hash = NULL;
                        switch (f->action) {

                        case EXTRA_ACTION_SKIP:
                                break;

                        case EXTRA_ACTION_KEEP:
                                hash = f->dest_hash;
                                break;

                        case EXTRA_ACTION_COPY:
                                if (entry_points && failed) {
                                        log_warning("Not installing '%s', because another extra file could not be installed.", f->source_path);
                                        r = -ECANCELED;
                                } else
                                        r = install_extra_file(c, f);
                                if (r >= 0) {
                                        hash = f->hash;
                                        break;
                                }

                                failed = true;
                                RET_GATHER(ret, r);

                                /* The copy can fail after the new file replaced the old file. Keep the
                                 * hash of the new file and the hash of the file that an earlier invocation
                                 * installed in the manifest, so that a later invocation can replace or
                                 * remove either file. */
                                if (r != -ECANCELED) {
                                        r = extra_file_array_add(&c->extra_installed, &c->n_extra_installed, f->path, f->hash);
                                        if (r < 0)
                                                return r;
                                }
                                if (f->dest_managed)
                                        hash = f->dest_hash;
                                break;

                        case EXTRA_ACTION_FAILED:
                                /* The state of the file in the ESP is unknown, hence keep every hash that
                                 * the manifest lists for it. */
                                FOREACH_ARRAY(m, c->extra_manifest, c->n_extra_manifest)
                                        if (extra_path_equal(m->path, f->path)) {
                                                r = extra_file_array_add(&c->extra_installed, &c->n_extra_installed, m->path, m->hash);
                                                if (r < 0)
                                                        return r;
                                        }
                                break;

                        default:
                                assert_not_reached();
                        }

                        if (hash) {
                                r = extra_file_array_add(&c->extra_installed, &c->n_extra_installed, f->path, hash);
                                if (r < 0)
                                        return r;
                        }
                }

        /* The files that EXTRA_FILES_DIR does not contain anymore are removed after the new files are in
         * place. If a file could not be installed, the old entry points are still in the ESP. An old entry
         * point might load a file that is not provided anymore, hence no file is removed then. */
        FOREACH_ARRAY(m, c->extra_manifest, c->n_extra_manifest) {
                if (extra_file_find(c->extra_files, c->n_extra_files, m->path))
                        continue;

                if (failed)
                        log_debug("Not removing '%s' from the ESP, because an extra file could not be installed.", m->path);
                else if (!update_variables && extra_entry_point_is_registered(c, m->path))
                        /* The firmware would skip a boot entry whose file does not exist. The file is
                         * removed by the next invocation that also updates the boot entry. */
                        log_notice("Not removing '%s' from the ESP, because the firmware's boot loader list refers to it and is not updated now.", m->path);
                else {
                        r = remove_extra_file(c, m, /* remove_directories= */ false);
                        if (r >= 0)
                                continue;

                        RET_GATHER(ret, r);
                }

                r = extra_file_array_add(&c->extra_installed, &c->n_extra_installed, m->path, m->hash);
                if (r < 0)
                        return r;
        }

        return RET_GATHER(ret, write_extra_manifest(c, c->extra_installed, c->n_extra_installed));
}

static int remove_extra_files(InstallContext *c) {
        int r;

        assert(c);

        r = load_extra_manifest(c);
        if (r < 0)
                return r;

        FOREACH_ARRAY(m, c->extra_manifest, c->n_extra_manifest) {
                /* remove_binaries() deletes EFI/systemd/ with everything in it. */
                if (extra_path_startswith(m->path, EXTRA_FILES_MANIFEST_DIR "/"))
                        continue;

                RET_GATHER(r, remove_extra_file(c, m, /* remove_directories= */ true));
        }

        return r;
}

static int update_efi_boot_binaries(
                InstallContext *c,
                const char *source_path,
                int source_fd,
                const char *ignore_filename) {

        int r, ret = 0;

        assert(c);
        assert(source_path);

        if (c->esp_fd < 0)
                return c->esp_fd;

        _cleanup_free_ char *j = path_join(c->root, c->esp_path);
        if (!j)
                return log_oom();

        _cleanup_closedir_ DIR *d = NULL;
        r = chase_and_opendirat(
                        c->esp_fd,
                        c->esp_fd,
                        "/EFI/BOOT",
                        CHASE_PROHIBIT_SYMLINKS|CHASE_MUST_BE_DIRECTORY,
                        /* ret_path= */ NULL,
                        &d);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to open directory \"%s/EFI/BOOT\": %m", j);

        FOREACH_DIRENT(de, d, break) {
                _cleanup_close_ int fd = -EBADF;

                if (!endswith_no_case(de->d_name, ".efi"))
                        continue;

                if (strcaseeq_ptr(ignore_filename, de->d_name))
                        continue;

                /* install_extra_files() replaces or removes the files that the manifest lists. */
                _cleanup_free_ char *extra_path = path_join("EFI/BOOT", de->d_name);
                if (!extra_path)
                        return log_oom();
                if (!c->extra_manifest_damaged && extra_file_find(c->extra_manifest, c->n_extra_manifest, extra_path))
                        continue;

                fd = xopenat_full(dirfd(d), de->d_name, O_RDONLY|O_NONBLOCK|O_NOCTTY|O_NOFOLLOW, XO_REGULAR, MODE_INVALID);
                if (fd < 0)
                        return log_error_errno(fd, "Failed to open \"%s/%s\" for reading: %m", j, de->d_name);

                r = pe_is_native_fd(fd);
                if (r < 0) {
                        log_warning_errno(r, "Failed to detect if \"%s/%s\" is for native architecture, ignoring: %m", j, de->d_name);
                        continue;
                }
                if (r == 0)
                        continue;

                _cleanup_free_ char *dest_path = path_join(j, "/EFI/BOOT", de->d_name);
                if (!dest_path)
                        return log_oom();

                r = copy_file_with_version_check(source_path, source_fd, dest_path, dirfd(d), de->d_name, fd, /* force= */ false);
                if (IN_SET(r, -ESTALE, -ESRCH))
                        continue;
                RET_GATHER(ret, r);
        }

        return ret;
}

static int copy_one_file(
                InstallContext *c,
                const char *name,
                bool from_image,
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

        /* Prefer the directory we enumerated. In auto mode, retain the per-file host fallback for
         * image entries that disappeared or are dangling symlinks. */
        _cleanup_free_ char *source_path = NULL;
        _cleanup_close_ int source_fd = -EBADF;
        if (from_image) {
                source_fd = chase_and_openat(
                                c->root_fd,
                                c->root_fd,
                                sp,
                                CHASE_MUST_BE_REGULAR,
                                O_RDONLY,
                                &source_path);
                if (source_fd < 0 && (source_fd != -ENOENT || c->install_source != INSTALL_SOURCE_AUTO))
                        return log_error_errno(source_fd, "Failed to resolve path '%s' under directory '%s': %m", sp, c->root);
                if (source_fd < 0)
                        log_debug("'%s' not found under '%s', trying the host.",
                                  sp, empty_to_root(c->root));
        }
        if (source_fd < 0) {
                source_fd = chase_and_open(
                                sp,
                                /* root= */ NULL,
                                CHASE_MUST_BE_REGULAR,
                                O_RDONLY,
                                &source_path);
                if (source_fd < 0)
                        return log_error_errno(source_fd, "Failed to resolve path '%s': %m", sp);
        }

        if (c->esp_fd < 0)
                return c->esp_fd;

        _cleanup_free_ char *j = path_join(c->root, c->esp_path);
        if (!j)
                return log_oom();

        _cleanup_close_ int dest_parent_fd = -EBADF;
        r = chaseat(c->esp_fd,
                    c->esp_fd,
                    "/EFI/systemd",
                    CHASE_PROHIBIT_SYMLINKS|CHASE_MKDIR_0755|CHASE_MUST_BE_DIRECTORY,
                    /* ret_path= */ NULL,
                    &dest_parent_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to resolve path '/EFI/systemd' under directory '%s': %m", j);

        _cleanup_free_ char *dest_path = path_join(j, "/EFI/systemd", dest_name);
        if (!dest_path)
                return log_oom();

        _cleanup_close_ int dest_fd = xopenat_full(dest_parent_fd, dest_name, O_RDONLY, XO_REGULAR, MODE_INVALID);
        if (dest_fd < 0 && dest_fd != -ENOENT)
                return log_error_errno(dest_fd, "Failed to open '%s' under '%s/EFI/systemd' directory: %m", dest_name, j);

        const char *e = startswith(dest_name, "systemd-boot");

        /* If a primary sd-boot binary already exists and the source is a newer version, copy
         * the existing primary to systemd-boot-fallback{arch}.efi before installing the new
         * one, so firmware has a fallback to the previous binary. The fallback is left alone
         * when its product and version match the currently booted bootloader (from LoaderInfo),
         * so a known good binary stays as the fallback. In all other cases, like no fallback yet,
         * LoaderInfo is unavailable, or product/version differs from what booted, it is
         * overwritten with the current primary. */
        if (e && dest_fd >= 0 && !force) {
                r = version_check(source_fd, source_path, dest_fd, dest_path);
                if (r < 0)
                        /* Stash the error and fall through; the BOOT{arch}.EFI updates below still run. */
                        ret = r;
                else {
                        _cleanup_free_ char *fallback_name = strjoin("systemd-boot-fallback", e);
                        if (!fallback_name)
                                return log_oom();

                        _cleanup_free_ char *fallback_path = path_join(j, "/EFI/systemd", fallback_name);
                        if (!fallback_path)
                                return log_oom();

                        /* Leave the fallback alone if it already holds the currently booted product
                         * and version, so a known good binary stays as the fallback. If there is no
                         * fallback yet, LoaderInfo is unavailable, or there is a mismatch, then
                         * overwrite it with the current primary. */
                        bool should_rotate = true;
                        _cleanup_close_ int fallback_fd = xopenat_full(dest_parent_fd, fallback_name, O_RDONLY, XO_REGULAR, MODE_INVALID);
                        if (fallback_fd >= 0) {
                                _cleanup_free_ char *loader_info = NULL, *fallback_version = NULL;

                                if (efi_get_variable_string(EFI_LOADER_VARIABLE_STR("LoaderInfo"), &loader_info) >= 0 &&
                                    get_file_version(fallback_fd, &fallback_version) >= 0)
                                        should_rotate = compare_product(loader_info, fallback_version) != 0 ||
                                                        compare_version(loader_info, fallback_version) != 0;
                        }

                        if (should_rotate) {
                                r = copy_file_with_version_check(dest_path, dest_fd, fallback_path, dest_parent_fd, fallback_name, /* dest_fd= */ -EBADF, /* force= */ true);
                                if (r < 0)
                                        log_warning_errno(r, "Failed to back up sd-boot binary to fallback path, continuing: %m");
                        }

                        ret = copy_file_with_version_check(source_path, source_fd, dest_path, dest_parent_fd, dest_name, dest_fd, /* force= */ true);
                }
        } else
                /* Note that if this fails we do the second copy anyway, but return this error code,
                 * so we stash it away in a separate variable. */
                ret = copy_file_with_version_check(source_path, source_fd, dest_path, dest_parent_fd, dest_name, dest_fd, force);

        if (e) {

                /* Create the EFI default boot loader name (specified for removable devices) */
                _cleanup_free_ char *boot_dot_efi = strjoin("BOOT", e);
                if (!boot_dot_efi)
                        return log_oom();

                ascii_strupper(boot_dot_efi);

                _cleanup_close_ int default_dest_parent_fd = -EBADF;
                r = chaseat(c->esp_fd,
                            c->esp_fd,
                            "/EFI/BOOT",
                            CHASE_PROHIBIT_SYMLINKS|CHASE_MKDIR_0755|CHASE_MUST_BE_DIRECTORY,
                            /* ret_path= */ NULL,
                            &default_dest_parent_fd);
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve path '/EFI/BOOT/' under directory '%s': %m", j);

                _cleanup_free_ char *default_dest_path = path_join(j, "/EFI/BOOT", boot_dot_efi);
                if (!default_dest_path)
                        return log_oom();

                /* If EXTRA_FILES_DIR provides the default boot loader, it is the intended entry point. It
                 * is expected to load systemd-boot, hence don't replace it. */
                _cleanup_free_ char *default_extra_path = path_join("EFI/BOOT", boot_dot_efi);
                if (!default_extra_path)
                        return log_oom();

                /* If the manifest does not list the default boot loader, install_extra_files() leaves it
                 * alone during an update. It might be a copy of systemd-boot that an earlier invocation
                 * installed, hence update_efi_boot_binaries() below must not ignore it. */
                bool provided = extra_file_find(c->extra_files, c->n_extra_files, default_extra_path),
                        listed = extra_file_find(c->extra_manifest, c->n_extra_manifest, default_extra_path);

                if (provided)
                        log_debug("\"%s\" is provided by '%s', not installing systemd-boot under this name.", default_dest_path, EXTRA_FILES_DIR);
                else {
                        _cleanup_close_ int default_dest_fd = xopenat_full(default_dest_parent_fd, boot_dot_efi, O_RDONLY, XO_REGULAR, MODE_INVALID);
                        if (default_dest_fd < 0 && default_dest_fd != -ENOENT)
                                return log_error_errno(default_dest_fd, "Failed to open '%s' under '%s/EFI/BOOT' directory: %m", boot_dot_efi, j);

                        /* If an earlier invocation installed the default boot loader from EXTRA_FILES_DIR
                         * and EXTRA_FILES_DIR does not provide it anymore, systemd-boot replaces it
                         * directly. Removing the file first would leave the ESP without a default boot
                         * loader if the copy fails. */
                        bool obsolete = false;
                        if (default_dest_fd >= 0 && !force && !c->extra_manifest_damaged && listed) {
                                uint8_t hash[SHA256_DIGEST_SIZE];

                                r = sha256_fd(default_dest_fd, UINT64_MAX, hash);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to hash '%s': %m", default_dest_path);

                                obsolete = extra_manifest_lists(c, default_extra_path, hash);
                        }

                        r = copy_file_with_version_check(source_path, source_fd, default_dest_path, default_dest_parent_fd, boot_dot_efi, default_dest_fd, force || obsolete);
                        if (r >= 0)
                                /* systemd-boot replaced the extra file. install_extra_files() must not
                                 * handle the path as an extra file that is not provided anymore. */
                                extra_manifest_forget(c, default_extra_path);
                        else if (obsolete)
                                /* The -ESTALE or -ESRCH of the primary binary must not hide this error.
                                 * run_install() would continue, and install_extra_files() would remove
                                 * the default boot loader. */
                                ret = r;
                        RET_GATHER(ret, r);
                }

                /* If we were installed under any other name in /EFI/BOOT/, make sure we update those
                 * binaries as well. */
                if (!force)
                        RET_GATHER(ret, update_efi_boot_binaries(c, source_path, source_fd, provided && !listed ? NULL : boot_dot_efi));
        }

        return ret;
}

static int dir_has_boot_loader(DIR *d, const char *path, const char *arch) {
        /* Checks whether the directory has the systemd-boot binary that install_binaries() is supposed to
         * install. Only systemd-boot itself counts, not any other EFI binary that happens to match. Unless
         * installing for all architectures, it also has to be the one for the requested architecture, i.e.
         * the one that copy_one_file() also installs as BOOT<ARCH>.EFI, and not e.g.
         * "systemd-boot-extrax64.efi". */

        assert(d);
        assert(path);

        const char *suffix = strjoina(strempty(arch), ".efi");
        const char *suffix_signed = strjoina(strempty(arch), ".efi.signed");

        FOREACH_DIRENT(de, d, return log_error_errno(errno, "Failed to read \"%s\": %m", path)) {
                if (!endswith_no_case(de->d_name, suffix) && !endswith_no_case(de->d_name, suffix_signed))
                        continue;

                const char *e = startswith(de->d_name, "systemd-boot");
                if (e && (isempty(arch) || STRCASE_IN_SET(e, suffix, suffix_signed)))
                        return true;
        }

        return false;
}

static int open_source_directory(InstallContext *c, const char *arch) {
        int r;

        assert(c);
        assert(!c->source_dir);

        /* open_source_directory() selects the BOOTLIBDIR that the systemd-boot binaries and the extra files
         * are taken from, and stores it in c->source_dir. c->source_dir stays NULL if there is nothing to
         * install and that is not an error. */

        const char *fn = strjoina("systemd-boot", isempty(arch) ? "*" : arch, ".efi");

        _cleanup_free_ char *source_path = NULL;
        _cleanup_closedir_ DIR *d = NULL;
        bool from_image = false, found_loader = false;
        if (IN_SET(c->install_source, INSTALL_SOURCE_AUTO, INSTALL_SOURCE_IMAGE)) {
                r = chase_and_opendirat(
                                c->root_fd,
                                c->root_fd,
                                BOOTLIBDIR,
                                CHASE_MUST_BE_DIRECTORY,
                                &source_path,
                                &d);
                if (r < 0 && (r != -ENOENT || c->install_source != INSTALL_SOURCE_AUTO))
                        return log_error_errno(r, "Failed to resolve path '%s' under directory '%s': %m", BOOTLIBDIR, c->root);
                if (r >= 0) {
                        r = dir_has_boot_loader(d, source_path, arch);
                        if (r < 0)
                                return r;

                        found_loader = r > 0;

                        /* In auto mode, also try the host if the image has no boot loader for us. Without a
                         * root directory, the image is the host, there is nothing else to try then. */
                        from_image = found_loader || c->install_source == INSTALL_SOURCE_IMAGE || !c->root;
                        if (!from_image)
                                log_debug("No '%s' boot loader binary found in '%s' under '%s', trying the host.",
                                          fn, source_path, c->root);
                }

                /* If we had a root directory to try, we didn't find it and we are in auto mode, retry on the host */
        }
        if (!from_image) {
                d = safe_closedir(d);
                _cleanup_free_ char *image_source_path = TAKE_PTR(source_path);

                r = chase_and_opendir(
                                BOOTLIBDIR,
                                /* root= */ NULL,
                                CHASE_MUST_BE_DIRECTORY,
                                &source_path,
                                &d);
                if (r == -ENOENT && image_source_path) {
                        /* The image's source directory lacks a suitable boot loader and the host has no
                         * source directory at all: report the boot loader missing from the image. */
                        if (c->graceful) {
                                log_full(arg_quiet ? LOG_DEBUG : LOG_INFO,
                                         "No '%s' boot loader binary found in '%s' under '%s', skipping.",
                                         fn, image_source_path, c->root);
                                return 0;
                        }

                        return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                               "No '%s' boot loader binary found in '%s' under '%s'.",
                                               fn, image_source_path, c->root);
                }
                if (r == -ENOENT && c->graceful) {
                        log_debug("Source directory '%s' does not exist, ignoring.", BOOTLIBDIR);
                        return 0;
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve path '%s': %m", BOOTLIBDIR);

                r = dir_has_boot_loader(d, source_path, arch);
                if (r < 0)
                        return r;

                found_loader = r > 0;
        }

        /* An existing source directory without a suitable boot loader is no better than a missing one:
         * don't claim success if there is nothing to install (#41312). Check this before copying anything,
         * so that a failed installation doesn't leave other binaries behind in /EFI/systemd/, which would
         * make systemd-boot look installed. */
        if (!found_loader) {
                if (c->graceful) {
                        log_full(arg_quiet ? LOG_DEBUG : LOG_INFO,
                                 "No '%s' boot loader binary found in '%s', skipping.", fn, source_path);
                        return 0;
                }

                return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                       "No '%s' boot loader binary found in '%s'.", fn, source_path);
        }

        c->source_dir = TAKE_PTR(d);
        c->source_path = TAKE_PTR(source_path);
        c->source_from_image = from_image;
        return 0;
}

static int install_binaries(
                InstallContext *c,
                const char *arch) {

        int r, ret = 0;

        assert(c);

        DIR *d = c->source_dir;
        if (!d)
                return 0;

        rewinddir(d);

        const char *suffix = strjoina(strempty(arch), ".efi");
        const char *suffix_signed = strjoina(strempty(arch), ".efi.signed");

        FOREACH_DIRENT(de, d, return log_error_errno(errno, "Failed to read \"%s\": %m", c->source_path)) {
                if (endswith_no_case(de->d_name, suffix)) {
                        /* skip the .efi file, if there's a .signed version of it */
                        _cleanup_free_ const char *s = strjoin(de->d_name, ".signed");
                        if (!s)
                                return log_oom();
                        if (faccessat(dirfd(d), s, F_OK, 0) >= 0)
                                continue;
                } else if (!endswith_no_case(de->d_name, suffix_signed))
                        continue;

                r = copy_one_file(c, de->d_name, c->source_from_image, c->operation == INSTALL_NEW);
                /* Don't propagate an error code if no update necessary, installed version already equal or
                 * newer version, or other boot loader in place. */
                if (IN_SET(r, -ESTALE, -ESRCH)) {
                        if (!c->graceful)
                                RET_GATHER(ret, r);
                        continue;
                }

                /* run_install() continues after -ESTALE and -ESRCH, hence any other error replaces them. */
                if (r < 0 && IN_SET(ret, -ESTALE, -ESRCH))
                        ret = r;
                RET_GATHER(ret, r);
        }

        return ret;
}

static int install_loader_config(InstallContext *c) {
        int r;

        assert(c);
        assert(c->make_entry_directory >= 0);

        if (c->esp_fd < 0)
                return c->esp_fd;

        _cleanup_free_ char *j = path_join(c->root, c->esp_path);
        if (!j)
                return log_oom();

        _cleanup_close_ int loader_dir_fd = -EBADF;
        r = chaseat(c->esp_fd,
                    c->esp_fd,
                    "loader",
                    CHASE_PROHIBIT_SYMLINKS|CHASE_MKDIR_0755|CHASE_MUST_BE_DIRECTORY,
                    /* ret_path= */ NULL,
                    &loader_dir_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to open '/loader/' directory below '%s': %m", j);

        if (faccessat(loader_dir_fd, "loader.conf", F_OK, AT_SYMLINK_NOFOLLOW) < 0) {
                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to check if '/loader/loader.conf' exists below '%s': %m", j);
        } else /* Silently skip creation if the file already exists (early check) */
                return 0;

        _cleanup_free_ char *t = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        r = fopen_tmpfile_linkable_at(loader_dir_fd, "loader.conf", O_WRONLY, &t, &f);
        if (r < 0)
                return log_error_errno(r, "Failed to open '%s/loader/loader.conf' for writing: %m", j);

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
                return log_error_errno(r, "Failed to move '%s/loader/loader.conf' into place: %m", j);

        t = mfree(t); /* disarm CLEANUP_TMPFILE_AT() */
        return 1;
}

static int install_loader_specification(InstallContext *c) {
        int r;

        assert(c);

        int dollar_boot_fd = acquire_dollar_boot_fd(c);
        if (dollar_boot_fd < 0)
                return dollar_boot_fd;

        _cleanup_free_ char *j = path_join(c->root, dollar_boot_path(c));
        if (!j)
                return log_oom();

        _cleanup_close_ int loader_dir_fd = -EBADF;
        r = chaseat(dollar_boot_fd,
                    dollar_boot_fd,
                    "loader",
                    CHASE_PROHIBIT_SYMLINKS|CHASE_MKDIR_0755|CHASE_MUST_BE_DIRECTORY,
                    /* ret_path= */ NULL,
                    &loader_dir_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to pin '/loader' directory below '%s': %m", j);

        if (faccessat(loader_dir_fd, "entries.srel", F_OK, AT_SYMLINK_NOFOLLOW) < 0) {
                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to check if '/loader/entries.srel' exists below '%s': %m", j);
        } else /* Silently skip creation if the file already exists (early check) */
                return 0;

        _cleanup_free_ char *t = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        r = fopen_tmpfile_linkable_at(loader_dir_fd, "entries.srel", O_WRONLY, &t, &f);
        if (r < 0)
                return log_error_errno(r, "Failed to open '%s/loader/entries.srel' for writing: %m", j);

        CLEANUP_TMPFILE_AT(loader_dir_fd, t);

        fprintf(f, "type1\n");

        r = flink_tmpfile_at(f, loader_dir_fd, t, "entries.srel", LINK_TMPFILE_SYNC);
        if (r == -EEXIST)
                return 0; /* Silently skip creation if the file exists now (recheck) */
        if (r < 0)
                return log_error_errno(r, "Failed to move '%s/loader/entries.srel' into place: %m", j);

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

        _cleanup_free_ char *j = path_join(c->root, dollar_boot_path(c));
        if (!j)
                return log_oom();

        return mkdir_one(j, dollar_boot_fd, c->entry_token);
}

static int install_entry_token(InstallContext *c) {
        int r;

        assert(c);
        assert(c->make_entry_directory >= 0);
        assert(c->entry_token);

        /* Let's save the used entry token in /etc/kernel/entry-token if we used it to create the entry
         * directory, or if anything else but the machine ID */

        if (!c->make_entry_directory && c->entry_token_type == BOOT_ENTRY_TOKEN_MACHINE_ID)
                return 0;

        const char *confdir = secure_getenv("KERNEL_INSTALL_CONF_ROOT") ?: "/etc/kernel/";

        _cleanup_free_ char *j = path_join(c->root, confdir);
        if (!j)
                return log_oom();

        _cleanup_close_ int dfd = -EBADF;
        r = chaseat(c->root_fd,
                    c->root_fd,
                    confdir,
                    CHASE_MKDIR_0755|CHASE_MUST_BE_DIRECTORY,
                    /* ret_path= */ NULL,
                    &dfd);
        if (r < 0)
                return log_error_errno(r, "Failed to open '%s': %m", j);

        r = write_string_file_at(dfd, "entry-token", c->entry_token,
                WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC|WRITE_STRING_FILE_MKDIR_0755|WRITE_STRING_FILE_VERIFY_ON_FAILURE);
        if (r < 0)
                return log_error_errno(r, "Failed to write entry token '%s' to '%s/entry-token': %m", c->entry_token, j);

        return 0;
}

#if HAVE_OPENSSL
static int efi_timestamp(EFI_TIME *ret) {
        struct tm tm = {};
        int r;

        assert(ret);

        r = localtime_or_gmtime_usec(source_date_epoch_or_now(), /* utc= */ true, &tm);
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
#endif

        if (!arg_secure_boot_auto_enroll)
                return 0;

#if HAVE_OPENSSL
        if (!c->secure_boot_certificate || !c->secure_boot_private_key)
                return 0;

        r = dlopen_libcrypto(LOG_DEBUG);
        if (r < 0)
                return r;

        _cleanup_free_ uint8_t *dercert = NULL;
        int dercertsz;
        dercertsz = sym_i2d_X509(c->secure_boot_certificate, &dercert);
        if (dercertsz < 0)
                return log_openssl_errors(LOG_ERR, "Failed to convert X.509 certificate to DER");

        if (c->esp_fd < 0)
                return c->esp_fd;

        _cleanup_free_ char *j = path_join(c->root, c->esp_path);
        if (!j)
                return log_oom();

        _cleanup_close_ int keys_fd = -EBADF;
        r = chaseat(c->esp_fd,
                    c->esp_fd,
                    "loader/keys/auto",
                    CHASE_PROHIBIT_SYMLINKS|CHASE_MKDIR_0755|CHASE_MUST_BE_DIRECTORY,
                    /* ret_path= */ NULL,
                    &keys_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to chase /loader/keys/auto/ below '%s': %m", j);

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

                bio = sym_BIO_new(sym_BIO_s_mem());
                if (!bio)
                        return log_oom();

                _cleanup_free_ char16_t *db16 = utf8_to_utf16(db, SIZE_MAX);
                if (!db16)
                        return log_oom();

                /* Don't count the trailing NUL terminator. */
                if (sym_BIO_write(bio, db16, char16_strsize(db16) - sizeof(char16_t)) < 0)
                        return log_openssl_errors(LOG_ERR, "Failed to write variable name to bio");

                EFI_GUID *guid = STR_IN_SET(db, "PK", "KEK") ? &(EFI_GUID) EFI_GLOBAL_VARIABLE : &(EFI_GUID) EFI_IMAGE_SECURITY_DATABASE_GUID;

                if (sym_BIO_write(bio, guid, sizeof(*guid)) < 0)
                        return log_openssl_errors(LOG_ERR, "Failed to write variable GUID to bio");

                if (sym_BIO_write(bio, &attrs, sizeof(attrs)) < 0)
                        return log_openssl_errors(LOG_ERR, "Failed to write variable attributes to bio");

                if (sym_BIO_write(bio, &timestamp, sizeof(timestamp)) < 0)
                        return log_openssl_errors(LOG_ERR, "Failed to write timestamp to bio");

                if (sym_BIO_write(bio, siglist, siglistsz) < 0)
                        return log_openssl_errors(LOG_ERR, "Failed to write signature list to bio");

                _cleanup_(PKCS7_freep) PKCS7 *p7 = NULL;
                p7 = sym_PKCS7_sign(c->secure_boot_certificate, c->secure_boot_private_key, /* certs= */ NULL, bio, PKCS7_DETACHED|PKCS7_NOATTR|PKCS7_BINARY|PKCS7_NOSMIMECAP);
                if (!p7)
                        return log_openssl_errors(LOG_ERR, "Failed to calculate PKCS7 signature");

                _cleanup_free_ uint8_t *sig = NULL;
                int sigsz = sym_i2d_PKCS7(p7, &sig);
                if (sigsz < 0)
                        return log_openssl_errors(LOG_ERR, "Failed to convert PKCS7 signature to DER");

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
                _cleanup_close_ int fd = open_tmpfile_linkable_at(keys_fd, filename, O_WRONLY, &t);
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
                        return log_error_errno(r, "Failed to link secure boot auto-enrollment file: %m");

                t = mfree(t); /* Disarm CLEANUP_TMPFILE_AT() */

                log_info("Secure boot auto-enrollment file '%s/loader/keys/auto/%s' successfully written.", j, filename);
        }

        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Built without OpenSSL support, cannot set up auto-enrollment.");
#endif
}

static bool same_entry(uint16_t id, sd_id128_t uuid, const char *path) {
        _cleanup_free_ char *opath = NULL;
        sd_id128_t ouuid;
        int r;

        r = efi_get_boot_option(id, /* ret_title= */ NULL, &ouuid, &opath, /* ret_active= */ NULL);
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

        assert(id);

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

static int insert_into_order(InstallContext *c, uint16_t slot, uint16_t after_slot) {
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
                /* if after_slot is set, leave existing position alone to preserve user reordering. */
                if (i == 0 || c->operation != INSTALL_NEW || after_slot != UINT16_MAX)
                        return 0;

                /* move us to the first slot */
                memmove(order + 1, order, i * sizeof(uint16_t));
                order[0] = slot;
                return efi_set_boot_order(order, n);
        }

        /* slot is not yet in the order, so insert after a specific slot if requested */
        if (after_slot != UINT16_MAX) {
                t = reallocarray(order, n + 1, sizeof(uint16_t));
                if (!t)
                        return -ENOMEM;
                order = t;

                for (int i = 0; i < n; i++) {
                        if (order[i] != after_slot)
                                continue;

                        memmove(order + i + 2, order + i + 1, (n - i - 1) * sizeof(uint16_t));
                        order[i + 1] = slot;
                        return efi_set_boot_order(order, n + 1);
                }

                log_warning("Boot entry %04" PRIx16 " not found in BootOrder, appending new entry at the end.", after_slot);
                order[n] = slot;
                return efi_set_boot_order(order, n + 1);
        }

        /* extend array */
        t = reallocarray(order, n + 1, sizeof(uint16_t));
        if (!t)
                return -ENOMEM;
        order = t;

        /* add us to the top or end of the list */
        if (c->operation == INSTALL_NEW) {
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

static int pick_efi_boot_option_description(int esp_fd, char **ret) {
        int r;

        assert(esp_fd >= 0);
        assert(ret);

        /* early declarations, so that they are definitely initialized even if we follow any of the gotos */
        _cleanup_(sd_device_unrefp) sd_device *d = NULL;
        _cleanup_free_ char *j = NULL;

        const char *b = arg_efi_boot_option_description ?: "Linux Boot Manager";
        if (!arg_efi_boot_option_description_with_device)
                goto fallback;

        r = block_device_new_from_fd(
                        esp_fd,
                        BLOCK_DEVICE_LOOKUP_WHOLE_DISK|BLOCK_DEVICE_LOOKUP_BACKING,
                        &d);
        if (r < 0) {
                log_debug_errno(r, "Failed to find backing device of ESP: %m");
                goto fallback;
        }

        const char *serial;
        r = sd_device_get_property_value(d, "ID_SERIAL", &serial);
        if (r < 0) {
                log_debug_errno(r, "Unable to read ID_SERIAL field of backing device of ESP: %m");
                goto fallback;
        }

        j = strjoin(b, " (", serial, ")");
        if (!j)
                return log_oom();

        if (strlen(j) > EFI_BOOT_OPTION_DESCRIPTION_MAX) {
                log_debug("Boot option string suffixed with device serial would be too long, skipping: %s", j);
                j = mfree(j);
                goto fallback;
        }

        *ret = TAKE_PTR(j);
        return 0;

fallback:
        j = strdup(b);
        if (!j)
                return log_oom();

        *ret = TAKE_PTR(j);
        return 0;
}

static int install_boot_option(
                InstallContext *c,
                const char *path,
                const char *description,
                bool require_existing,
                uint16_t after_slot,
                uint16_t *ret_slot) {

        uint16_t slot;
        int r;

        assert(c);
        assert(path);
        assert(description);

        if (c->esp_fd < 0)
                return c->esp_fd;

        _cleanup_free_ char *j = path_join(c->root, c->esp_path);
        if (!j)
                return log_oom();

        r = chase_and_accessat(
                        c->esp_fd,
                        c->esp_fd,
                        path,
                        CHASE_PROHIBIT_SYMLINKS|CHASE_MUST_BE_REGULAR,
                        F_OK,
                        /* ret_path= */ NULL);
        if (r == -ENOENT && require_existing)
                return 0;
        if (r < 0 && r != -ENOENT)
                return log_error_errno(r, "Cannot access \"%s/%s\": %m", j, skip_leading_slash(path));

        r = find_slot(c->esp_uuid, path, &slot);
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
                                description,
                                c->esp_part,
                                c->esp_pstart,
                                c->esp_psize,
                                c->esp_uuid,
                                path);
                if (r < 0) {
                        int level = c->graceful ? arg_quiet ? LOG_DEBUG : LOG_INFO : LOG_ERR;
                        const char *skip = c->graceful ? ", skipping" : "";

                        log_full_errno(level, r, "Failed to create EFI Boot variable entry%s: %m", skip);

                        return c->graceful ? 0 : r;
                }

                log_info("%s EFI boot entry \"%s\".",
                         existing ? "Updated" : "Created",
                         description);
                c->changed = true;
        }

        r = insert_into_order(c, slot, after_slot);
        if (r < 0)
                return r;

        if (ret_slot)
                *ret_slot = slot;

        return 0;
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

        if (c->esp_fd < 0)
                return c->esp_fd;

        _cleanup_close_ int fd = chase_and_openat(
                        c->esp_fd,
                        c->esp_fd,
                        "/EFI/systemd",
                        CHASE_PROHIBIT_SYMLINKS|CHASE_MUST_BE_DIRECTORY,
                        O_RDONLY|O_DIRECTORY,
                        /* ret_path= */ NULL);
        if (fd == -ENOENT)
                return 0;
        if (fd < 0)
                return log_error_errno(fd, "Failed to open '%s': %m", p);

        log_debug("Checking whether '%s' contains any files%s", p, glyph(GLYPH_ELLIPSIS));
        r = dir_is_empty_at(fd, /* path= */ NULL, /* ignore_hidden_or_backup= */ false);
        if (r < 0 && r != -ENOENT)
                return log_error_errno(r, "Failed to check whether '%s' contains any files: %m", p);

        return r == 0;
}

#if HAVE_OPENSSL
static int load_secure_boot_auto_enroll(
                X509 **ret_certificate,
                EVP_PKEY **ret_private_key,
                OpenSSLAskPasswordUI **ret_ui) {

        int r;

        assert(ret_certificate);
        assert(ret_private_key);
        assert(ret_ui);

        if (!arg_secure_boot_auto_enroll) {
                *ret_certificate = NULL;
                *ret_private_key = NULL;
                return 0;
        }

        if (arg_certificate_source_type == OPENSSL_CERTIFICATE_SOURCE_FILE) {
                r = parse_path_argument(arg_certificate, /* suppress_root= */ false, &arg_certificate);
                if (r < 0)
                        return r;
        }

        if (arg_private_key_source_type == OPENSSL_KEY_SOURCE_FILE) {
                r = parse_path_argument(arg_private_key, /* suppress_root= */ false, &arg_private_key);
                if (r < 0)
                        return r;
        }

        r = openssl_load_key_pair(
                        arg_private_key_source_type,
                        arg_private_key_source,
                        arg_private_key,
                        arg_certificate_source_type,
                        arg_certificate_source,
                        arg_certificate,
                        /* public_key= */ NULL,
                        ASK_PASSWORD_PRIVATE_KEY_PIN("bootctl", arg_private_key),
                        ret_private_key,
                        ret_certificate,
                        /* ret_public_key= */ NULL,
                        ret_ui);
        if (r < 0)
                return r;

        return 0;
}
#endif

static int remove_boot_option(sd_id128_t uuid, const char *path, bool in_order) {
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

static int install_variables(InstallContext *c, const char *arch) {
        int r;

        assert(c);

        const char *path = strjoina("/EFI/systemd/systemd-boot", arch, ".efi");
        const char *fallback_path = strjoina("/EFI/systemd/systemd-boot-fallback", arch, ".efi");
        const char *extra_path = strjoina("/EFI/systemd/boot", arch, ".efi");

        _cleanup_free_ char *description = NULL;
        r = pick_efi_boot_option_description(c->esp_fd, &description);
        if (r < 0)
                return r;

        /* If EXTRA_FILES_DIR provides EFI/systemd/boot<arch>.efi, the firmware is supposed to start that
         * binary, and the binary is expected to load systemd-boot. A first stage boot loader such as shim
         * is installed this way. The firmware might refuse to start systemd-boot directly then, hence don't
         * register systemd-boot or its fallback. If BOOTLIBDIR is missing, the registration of the earlier
         * invocation is kept. */
        const ExtraFile
                *provided = extra_file_find(c->extra_files, c->n_extra_files, extra_path),
                *listed = extra_file_find(c->extra_manifest, c->n_extra_manifest, extra_path),
                *extra = c->source_dir ? provided : listed;

        /* install_extra_files() leaves a file alone that bootctl did not install or that was modified
         * since. It is unknown what that file is, hence it is not registered, and the existing boot
         * entries are kept. */
        if (provided && !extra_file_find(c->extra_installed, c->n_extra_installed, extra_path)) {
                log_notice("'%s' in the ESP is not managed by bootctl, not changing the firmware's boot loader list.", extra_path);
                return 0;
        }

        const char *new_path = extra ? strjoina("/", extra->path) : path;

        /* The boot entry of the other entry point is removed. A boot entry for EFI/systemd/boot<arch>.efi
         * is only removed if an earlier invocation of bootctl installed that file, or if the file does not
         * exist. The file does not exist if an invocation that did not touch the EFI variables removed
         * it. Something else created the boot entry otherwise. */
        const char *old_path = NULL;
        if (extra)
                old_path = path;
        else if (c->source_dir) {
                if (listed)
                        old_path = extra_path;
                else {
                        r = chase_and_accessat(c->esp_fd, c->esp_fd, extra_path, CHASE_PROHIBIT_SYMLINKS, F_OK, /* ret_path= */ NULL);
                        if (r == -ENOENT)
                                old_path = extra_path;
                }
        }

        /* If the entry point changed since the last invocation, an update inserts the new boot entry
         * directly after the old boot entry. The old boot entry is removed afterwards, so that the new
         * boot entry has the position of the old boot entry in the boot order. */
        uint16_t old_slot = UINT16_MAX;
        bool old_exists = old_path && find_slot(c->esp_uuid, old_path, &old_slot) > 0;

        uint16_t primary_slot = UINT16_MAX;
        r = install_boot_option(
                        c,
                        new_path,
                        description,
                        /* require_existing= */ true,
                        old_exists && c->operation != INSTALL_NEW ? old_slot : UINT16_MAX,
                        &primary_slot);
        if (r < 0)
                return r;
        if (primary_slot != UINT16_MAX && old_exists) {
                r = efi_remove_boot_option(old_slot);
                if (r < 0)
                        log_warning_errno(r, "Failed to remove the EFI boot entry of '%s', ignoring: %m", old_path);
                else {
                        (void) remove_from_order(old_slot);
                        c->changed = true;
                }
        }
        if (extra) {
                if (primary_slot != UINT16_MAX)
                        (void) remove_boot_option(c->esp_uuid, fallback_path, /* in_order= */ true);
                return 0;
        }

        /* If primary registration was skipped (e.g. binary not on ESP), skip the fallback too
         * or else it would land at position 0 in BootOrder with no primary ahead of it. */
        if (primary_slot == UINT16_MAX)
                return 0;

        _cleanup_free_ char *fallback_description = strjoin("Fallback ", description);
        if (!fallback_description)
                return log_oom();

        strshorten(fallback_description, EFI_BOOT_OPTION_DESCRIPTION_MAX);

        return install_boot_option(c, fallback_path, fallback_description, /* require_existing= */ false, /* after_slot= */ primary_slot, /* ret_slot= */ NULL);
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

        if (c->esp_fd < 0)
                return c->esp_fd;

        _cleanup_free_ char *j = path_join(c->root, c->esp_path);
        if (!j)
                return log_oom();

        int dollar_boot_fd = acquire_dollar_boot_fd(c);
        if (dollar_boot_fd < 0)
                return dollar_boot_fd;

        _cleanup_free_ char *w = path_join(c->root, dollar_boot_path(c));
        if (!w)
                return log_oom();

        int k;
        bool damaged, update_variables = should_touch_install_variables(c) && !arg_arch_all;
        WITH_UMASK(0002) {
                if (c->operation == INSTALL_NEW) {
                        /* Don't create any of these directories when we are just updating. When we update
                         * we'll drop-in our files (unless there are newer ones already), but we won't create
                         * the directories for them in the first place. */

                        r = create_subdirs(j, c->esp_fd, esp_subdirs);
                        if (r < 0)
                                return r;

                        r = create_subdirs(w, dollar_boot_fd, dollar_boot_subdirs);
                        if (r < 0)
                                return r;
                }

                r = open_source_directory(c, arch);
                if (r < 0)
                        return r;

                r = load_extra_manifest(c);
                if (r < 0)
                        return r;

                r = load_extra_files(c);
                if (r < 0)
                        return r;

                /* If the systemd-boot binaries in the ESP are up-to-date already or belong to another boot
                 * loader, install_binaries() fails with -ESTALE or -ESRCH. The extra files and the boot
                 * entry can still differ from what is installed, hence install_extra_files() and
                 * install_variables() run before the error is returned. The error is not returned if
                 * they changed something. */
                k = install_binaries(c, arch);
                if (k < 0 && !IN_SET(k, -ESTALE, -ESRCH))
                        return k;

                /* Without the manifest it is unknown which files and which boot entry an earlier invocation
                 * installed, hence an update changes neither the extra files nor the EFI variables. */
                damaged = c->extra_manifest_damaged && c->operation != INSTALL_NEW;
                if (damaged)
                        log_warning("'%s' in the ESP is damaged, not updating the extra files and the EFI variables. Use \"bootctl install\" to install them again.",
                                    EXTRA_FILES_MANIFEST_DIR "/" EXTRA_FILES_MANIFEST_NAME);
                else if (c->source_dir) {
                        r = install_extra_files(c, update_variables);
                        if (r < 0)
                                return r;
                }

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
                                r = install_random_seed(c->esp_path, c->esp_fd);
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

        if (should_touch_install_variables(c) && !damaged) {
                if (arg_arch_all)
                        log_info("Not changing EFI variables with --all-architectures.");
                else {
                        r = install_variables(c, arch);
                        if (r < 0)
                                return r;
                }
        }

        if (k < 0 && c->changed)
                return 0;

        return k;
}

int verb_install(int argc, char *argv[], uintptr_t _data, void *userdata) {
        int r;

        /* Invoked for both "update" and "install" */

        _cleanup_(install_context_done) InstallContext c = INSTALL_CONTEXT_NULL;
        r = install_context_from_cmdline(&c, streq(argv[0], "install") ? INSTALL_NEW : INSTALL_UPDATE);
        if (r < 0)
                return r;
        if (r == 0) {
                log_debug("No ESP found and operating in graceful mode, skipping.");
                return 0;
        }

#if HAVE_OPENSSL
        _cleanup_(openssl_ask_password_ui_freep) OpenSSLAskPasswordUI *ui = NULL;
        r = load_secure_boot_auto_enroll(&c.secure_boot_certificate, &c.secure_boot_private_key, &ui);
        if (r < 0)
                return r;
#endif

        return run_install(&c);
}

static int remove_boot_efi(InstallContext *c) {
        int r, n = 0;

        assert(c);

        if (c->esp_fd < 0)
                return c->esp_fd;

        _cleanup_free_ char *w = path_join(c->root, c->esp_path);
        if (!w)
                return log_oom();

        _cleanup_closedir_ DIR *d = NULL;
        _cleanup_free_ char *p = NULL;
        r = chase_and_opendirat(
                        c->esp_fd,
                        c->esp_fd,
                        "/EFI/BOOT",
                        CHASE_PROHIBIT_SYMLINKS|CHASE_MUST_BE_DIRECTORY,
                        &p,
                        &d);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to open directory \"%s/EFI/BOOT\": %m", w);

        _cleanup_free_ char *j = path_join(w, p);
        if (!j)
                return log_oom();

        FOREACH_DIRENT(de, d, break) {
                _cleanup_close_ int fd = -EBADF;

                if (!endswith_no_case(de->d_name, ".efi"))
                        continue;

                _cleanup_free_ char *z = path_join(j, de->d_name);
                if (!z)
                        return log_oom();

                fd = xopenat_full(dirfd(d), de->d_name, O_RDONLY|O_NONBLOCK|O_NOCTTY|O_NOFOLLOW, XO_REGULAR, MODE_INVALID);
                if (fd == -ENOENT)
                        continue;
                if (fd < 0)
                        return log_error_errno(fd, "Failed to open '%s' for reading: %m", z);

                r = pe_is_native_fd(fd);
                if (r < 0) {
                        log_warning_errno(r, "Failed to detect if '%s' is native architecture, ignoring: %m", z);
                        continue;
                }
                if (r == 0)
                        continue;

                _cleanup_free_ char *v = NULL;
                r = get_file_version(fd, &v);
                if (r == -ESRCH)
                        continue;  /* No version information */
                if (r < 0) {
                        log_warning_errno(r, "Failed to get file version of '%s', skipping: %m", de->d_name);
                        continue;
                }
                if (!startswith(v, "systemd-boot "))
                        continue;

                if (unlinkat(dirfd(d), de->d_name, 0) < 0)
                        return log_error_errno(errno, "Failed to remove '%s': %m", z);

                log_info("Removed '%s'.", z);

                n++;
        }

        log_debug("Removed %i EFI binaries from '%s'.", n, j);
        return n;
}

static int unlink_inode(const char *root, int root_fd, const char *path, mode_t type) {
        int r;

        assert(root);
        assert(root_fd >= 0);
        assert(path);
        assert(IN_SET(type, S_IFREG, S_IFDIR));

        _cleanup_free_ char *p = path_join(empty_to_root(root), path);
        if (!p)
                return log_oom();

        r = chase_and_unlinkat(
                        root_fd,
                        root_fd,
                        path,
                        CHASE_PROHIBIT_SYMLINKS,
                        S_ISDIR(type) ? AT_REMOVEDIR : 0,
                        /* ret_path= */ NULL);
        if (r < 0) {
                bool ignore = IN_SET(r, -ENOENT, -ENOTEMPTY);
                log_full_errno(ignore ? LOG_DEBUG : LOG_ERR, r, "Failed to remove '%s': %m", p);
                return ignore ? 0 : r;
        }

        log_info("Removed %s\"%s\".", S_ISDIR(type) ? "directory " : "", p);
        return 0;
}

static int remove_subdirs(const char *root, int root_fd, const char *const *subdirs) {
        int r = 0;

        assert(root);
        assert(root_fd);

        STRV_FOREACH_BACKWARDS(i, (char**) subdirs)
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
        r = chaseat(c->esp_fd,
                    c->esp_fd,
                    "EFI",
                    CHASE_PROHIBIT_SYMLINKS|CHASE_MUST_BE_DIRECTORY,
                    /* ret_path= */ NULL,
                    &efi_fd);
        if (r < 0) {
                if (r != -ENOENT)
                        return log_error_errno(r, "Failed to remove '%s': %m", p);

                r = 0;
        } else
                r = rm_rf_at(efi_fd, "systemd", REMOVE_ROOT|REMOVE_PHYSICAL|REMOVE_MISSING_OK);

        return RET_GATHER(r, remove_boot_efi(c));
}

static int remove_loader_variables(void) {
        int r = 0;

        /* Remove all persistent loader variables we define */

        FOREACH_STRING(var,
                       EFI_LOADER_VARIABLE_STR("LoaderConfigConsoleMode"),
                       EFI_LOADER_VARIABLE_STR("LoaderConfigTimeout"),
                       EFI_LOADER_VARIABLE_STR("LoaderConfigTimeoutOneShot"),
                       EFI_LOADER_VARIABLE_STR("LoaderEntryPreferred"),
                       EFI_LOADER_VARIABLE_STR("LoaderEntryDefault"),
                       EFI_LOADER_VARIABLE_STR("LoaderEntrySysFail"),
                       EFI_LOADER_VARIABLE_STR("LoaderEntryLastBooted"),
                       EFI_LOADER_VARIABLE_STR("LoaderEntryOneShot"),
                       EFI_LOADER_VARIABLE_STR("LoaderFactoryResetVariables"),
                       EFI_LOADER_VARIABLE_STR("LoaderSystemToken")) {

                int q;

                q = efi_set_variable(var, /* value= */ NULL, /* size= */ 0);
                if (q == -ENOENT)
                        continue;
                if (q < 0)
                        RET_GATHER(r, log_warning_errno(q, "Failed to remove EFI variable %s: %m", var));
                else
                        log_info("Removed EFI variable %s.", var);
        }

        return r;
}

static int remove_variables(sd_id128_t uuid) {
        int r = 0;

        const char *path = strjoina("/EFI/systemd/systemd-boot", get_efi_arch(), ".efi");
        RET_GATHER(r, remove_boot_option(uuid, path, /* in_order= */ true));

        const char *fallback_path = strjoina("/EFI/systemd/systemd-boot-fallback", get_efi_arch(), ".efi");
        RET_GATHER(r, remove_boot_option(uuid, fallback_path, /* in_order= */ true));

        /* remove_binaries() deleted EFI/systemd/ with all files in it, hence a boot entry for
         * EFI/systemd/boot<arch>.efi points to a file that does not exist anymore. */
        const char *extra_path = strjoina("/EFI/systemd/boot", get_efi_arch(), ".efi");
        RET_GATHER(r, remove_boot_option(uuid, extra_path, /* in_order= */ true));

        return RET_GATHER(r, remove_loader_variables());
}

int verb_remove(int argc, char *argv[], uintptr_t _data, void *userdata) {
        int r;

        _cleanup_(install_context_done) InstallContext c = INSTALL_CONTEXT_NULL;
        r = install_context_from_cmdline(&c, INSTALL_REMOVE);
        if (r < 0)
                return r;
        if (r == 0) {
                log_debug("No ESP found and operating in graceful mode, skipping.");
                return 0;
        }

        r = settle_make_entry_directory(&c);
        if (r < 0)
                return r;

        if (c.esp_fd < 0)
                return c.esp_fd;

        _cleanup_free_ char *j = path_join(c.root, c.esp_path);
        if (!j)
                return log_oom();

        int dollar_boot_fd = acquire_dollar_boot_fd(&c);
        if (dollar_boot_fd < 0)
                return dollar_boot_fd;

        _cleanup_free_ char *w = path_join(c.root, dollar_boot_path(&c));
        if (!w)
                return log_oom();

        /* The manifest of the extra files is located in /EFI/systemd/, which remove_binaries() deletes. */
        r = remove_extra_files(&c);
        RET_GATHER(r, remove_binaries(&c));
        RET_GATHER(r, unlink_inode(j, c.esp_fd, "/loader/loader.conf", S_IFREG));
        RET_GATHER(r, unlink_inode(j, c.esp_fd, "/loader/random-seed", S_IFREG));
        RET_GATHER(r, unlink_inode(j, c.esp_fd, "/loader/entries.srel", S_IFREG));

        FOREACH_STRING(db, "PK.auth", "KEK.auth", "db.auth") {
                _cleanup_free_ char *p = path_join("/loader/keys/auto", db);
                if (!p)
                        return log_oom();

                RET_GATHER(r, unlink_inode(j, c.esp_fd, p, S_IFREG));
        }
        RET_GATHER(r, unlink_inode(j, c.esp_fd, "/loader/keys/auto", S_IFDIR));
        RET_GATHER(r, unlink_inode(j, c.esp_fd, "/loader/entries.srel", S_IFREG));

        RET_GATHER(r, remove_subdirs(j, c.esp_fd, esp_subdirs));
        RET_GATHER(r, remove_subdirs(j, c.esp_fd, dollar_boot_subdirs));
        RET_GATHER(r, remove_entry_directory(&c, j, c.esp_fd));

        if (c.xbootldr_fd >= 0) {
                /* Remove a subset of these also from the XBOOTLDR partition if it exists */
                RET_GATHER(r, unlink_inode(w, c.xbootldr_fd, "/loader/entries.srel", S_IFREG));
                RET_GATHER(r, remove_subdirs(w, c.xbootldr_fd, dollar_boot_subdirs));
                RET_GATHER(r, remove_entry_directory(&c, w, c.xbootldr_fd));
        }

        (void) sync_everything();

        if (!should_touch_install_variables(&c))
                return r;

        if (arg_arch_all) {
                log_info("Not changing EFI variables with --all-architectures.");
                return r;
        }

        return RET_GATHER(r, remove_variables(c.esp_uuid));
}

int verb_is_installed(int argc, char *argv[], uintptr_t _data, void *userdata) {
        int r;

        _cleanup_(install_context_done) InstallContext c = INSTALL_CONTEXT_NULL;
        r = install_context_from_cmdline(&c, INSTALL_TEST);
        if (r < 0)
                return r;
        if (r == 0) {
                log_debug("No ESP found and operating in graceful mode, claiming not installed.");
                if (!arg_quiet)
                        puts("no");
                return EXIT_FAILURE;
        }

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

static JSON_DISPATCH_ENUM_DEFINE(json_dispatch_install_operation, InstallOperation, install_operation_from_string);
static JSON_DISPATCH_ENUM_DEFINE(json_dispatch_boot_entry_token_type, BootEntryTokenType, boot_entry_token_type_from_string);

typedef struct InstallParameters {
        InstallContext context;
        unsigned root_fd_index;
        char *esp_path;
        char *xbootldr_path;
} InstallParameters;

static void install_parameters_done(InstallParameters *p) {
        assert(p);

        install_context_done(&p->context);
        free(p->esp_path);
        free(p->xbootldr_path);
}

int vl_method_install(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        int r;

        assert(link);

        _cleanup_(install_parameters_done) InstallParameters p = {
                .context = INSTALL_CONTEXT_NULL,
                .root_fd_index = UINT_MAX,
        };

        static const sd_json_dispatch_field dispatch_table[] = {
                { "operation",          SD_JSON_VARIANT_STRING,        json_dispatch_install_operation,     voffsetof(p, context.operation),            SD_JSON_MANDATORY },
                { "graceful",           SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool,            voffsetof(p, context.graceful),             0                 },
                { "rootFileDescriptor", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,               voffsetof(p, root_fd_index),                0                 },
                { "rootDirectory",      SD_JSON_VARIANT_STRING,        json_dispatch_path,                  voffsetof(p, context.root),                 0                 },
                { "espPath",            SD_JSON_VARIANT_STRING,        json_dispatch_path,                  voffsetof(p, esp_path),                     0                 },
                { "xbootldrPath",       SD_JSON_VARIANT_STRING,        json_dispatch_path,                  voffsetof(p, xbootldr_path),                0                 },
                { "bootEntryTokenType", SD_JSON_VARIANT_STRING,        json_dispatch_boot_entry_token_type, voffsetof(p, context.entry_token_type),     0                 },
                { "makeEntryDirectory", SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate,           voffsetof(p, context.make_entry_directory), 0                 },
                { "touchVariables",     SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate,           voffsetof(p, context.touch_variables),      0                 },
                {},
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        r = varlink_check_privileged_peer(link);
        if (r < 0)
                return r;

        if (!IN_SET(p.context.operation, INSTALL_NEW, INSTALL_UPDATE))
                return sd_varlink_error_invalid_parameter_name(link, "operation");

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
                p.context.root_fd = xopenat(AT_FDCWD, p.context.root, O_RDONLY|O_DIRECTORY);
                if (p.context.root_fd < 0)
                        return log_debug_errno(p.context.root_fd, "Failed to open '%s': %m", p.context.root);
        } else
                p.context.root_fd = XAT_FDROOT;

        if (p.context.entry_token_type < 0)
                p.context.entry_token_type = BOOT_ENTRY_TOKEN_AUTO;

        r = find_esp_and_warn_at_full(
                        p.context.root_fd,
                        p.esp_path,
                        /* unprivileged_mode= */ false,
                        &p.context.esp_path,
                        &p.context.esp_fd,
                        &p.context.esp_part,
                        &p.context.esp_pstart,
                        &p.context.esp_psize,
                        &p.context.esp_uuid,
                        /* ret_devid= */ NULL);
        if (r == -ENOKEY)
                return sd_varlink_error(link, "io.systemd.BootControl.NoESPFound", /* parameters= */ NULL);
        if (r < 0)
                return r;

        r = find_xbootldr_and_warn_at(
                        p.context.root_fd,
                        p.xbootldr_path,
                        /* unprivileged_mode= */ false,
                        &p.context.xbootldr_path,
                        &p.context.xbootldr_fd);
        if (r == -ENOKEY)
                log_debug_errno(r, "Didn't find an XBOOTLDR partition, using ESP as $BOOT.");
        else if (r < 0)
                return r;

        r = run_install(&p.context);
        if (r == -EUNATCH) /* no boot entry token is set */
                return sd_varlink_error(link, "io.systemd.BootControl.BootEntryTokenUnavailable", /* parameters= */ NULL);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, /* parameters= */ NULL);
}
