/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bootctl.h"
#include "bootctl-install.h"
#include "bootctl-random-seed.h"
#include "bootctl-util.h"
#include "chase.h"
#include "copy.h"
#include "dirent-util.h"
#include "efi-api.h"
#include "env-file.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "glyph-util.h"
#include "id128-util.h"
#include "os-util.h"
#include "path-util.h"
#include "rm-rf.h"
#include "stat-util.h"
#include "sync-util.h"
#include "tmpfile-util.h"
#include "umask-util.h"
#include "utf8.h"

static int load_etc_machine_id(void) {
        int r;

        r = sd_id128_get_machine(&arg_machine_id);
        if (ERRNO_IS_NEG_MACHINE_ID_UNSET(r)) /* Not set or empty */
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to get machine-id: %m");

        log_debug("Loaded machine ID %s from /etc/machine-id.", SD_ID128_TO_STRING(arg_machine_id));
        return 0;
}

static int load_etc_machine_info(void) {
        /* systemd v250 added support to store the kernel-install layout setting and the machine ID to use
         * for setting up the ESP in /etc/machine-info. The newer /etc/kernel/entry-token file, as well as
         * the $layout field in /etc/kernel/install.conf are better replacements for this though, hence this
         * has been deprecated and is only returned for compatibility. */
        _cleanup_free_ char *p = NULL, *s = NULL, *layout = NULL;
        int r;

        p = path_join(arg_root, "etc/machine-info");
        if (!p)
                return log_oom();

        r = parse_env_file(NULL, p,
                           "KERNEL_INSTALL_LAYOUT", &layout,
                           "KERNEL_INSTALL_MACHINE_ID", &s);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to parse /etc/machine-info: %m");

        if (!isempty(s)) {
                if (!arg_quiet)
                        log_notice("Read $KERNEL_INSTALL_MACHINE_ID from /etc/machine-info. "
                                   "Please move it to /etc/kernel/entry-token.");

                r = sd_id128_from_string(s, &arg_machine_id);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse KERNEL_INSTALL_MACHINE_ID=%s in /etc/machine-info: %m", s);

                log_debug("Loaded KERNEL_INSTALL_MACHINE_ID=%s from /etc/machine-info.",
                          SD_ID128_TO_STRING(arg_machine_id));
        }

        if (!isempty(layout)) {
                if (!arg_quiet)
                        log_notice("Read $KERNEL_INSTALL_LAYOUT from /etc/machine-info. "
                                   "Please move it to the layout= setting of /etc/kernel/install.conf.");

                log_debug("KERNEL_INSTALL_LAYOUT=%s is specified in /etc/machine-info.", layout);
                free_and_replace(arg_install_layout, layout);
        }

        return 0;
}

static int load_etc_kernel_install_conf(void) {
        _cleanup_free_ char *layout = NULL, *p = NULL;
        int r;

        p = path_join(arg_root, etc_kernel(), "install.conf");
        if (!p)
                return log_oom();

        r = parse_env_file(NULL, p, "layout", &layout);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to parse %s: %m", p);

        if (!isempty(layout)) {
                log_debug("layout=%s is specified in %s.", layout, p);
                free_and_replace(arg_install_layout, layout);
        }

        return 0;
}

static bool use_boot_loader_spec_type1(void) {
        /* If the layout is not specified, or if it is set explicitly to "bls" we assume Boot Loader
         * Specification Type #1 is the chosen format for our boot loader entries */
        return !arg_install_layout || streq(arg_install_layout, "bls");
}

static int settle_make_entry_directory(void) {
        int r;

        r = load_etc_machine_id();
        if (r < 0)
                return r;

        r = load_etc_machine_info();
        if (r < 0)
                return r;

        r = load_etc_kernel_install_conf();
        if (r < 0)
                return r;

        r = settle_entry_token();
        if (r < 0)
                return r;

        bool layout_type1 = use_boot_loader_spec_type1();
        if (arg_make_entry_directory < 0) { /* Automatic mode */
                if (layout_type1) {
                        if (arg_entry_token_type == BOOT_ENTRY_TOKEN_MACHINE_ID) {
                                r = path_is_temporary_fs("/etc/machine-id");
                                if (r < 0)
                                        return log_debug_errno(r, "Couldn't determine whether /etc/machine-id is on a temporary file system: %m");

                                arg_make_entry_directory = r == 0;
                        } else
                                arg_make_entry_directory = true;
                } else
                        arg_make_entry_directory = false;
        }

        if (arg_make_entry_directory > 0 && !layout_type1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "KERNEL_INSTALL_LAYOUT=%s is configured, but Boot Loader Specification Type #1 entry directory creation was requested.",
                                       arg_install_layout);

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
                return log_notice_errno(r, "Skipping \"%s\", it's owned by another boot loader (no version info found).",
                                        to);
        if (r < 0)
                return r;
        if (compare_product(a, b) != 0)
                return log_notice_errno(SYNTHETIC_ERRNO(ESRCH),
                                        "Skipping \"%s\", it's owned by another boot loader.", to);

        r = compare_version(a, b);
        log_debug("Comparing versions: \"%s\" %s \"%s", a, comparison_operator(r), b);
        if (r < 0)
                return log_warning_errno(SYNTHETIC_ERRNO(ESTALE),
                                         "Skipping \"%s\", newer boot loader version in place already.", to);
        if (r == 0)
                return log_info_errno(SYNTHETIC_ERRNO(ESTALE),
                                      "Skipping \"%s\", same boot loader version in place already.", to);

        return 0;
}

static int copy_file_with_version_check(const char *from, const char *to, bool force) {
        _cleanup_close_ int fd_from = -EBADF, fd_to = -EBADF;
        _cleanup_free_ char *t = NULL;
        int r;

        fd_from = open(from, O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd_from < 0)
                return log_error_errno(errno, "Failed to open \"%s\" for reading: %m", from);

        if (!force) {
                fd_to = open(to, O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (fd_to < 0) {
                        if (errno != ENOENT)
                                return log_error_errno(errno, "Failed to open \"%s\" for reading: %m", to);
                } else {
                        r = version_check(fd_from, from, fd_to, to);
                        if (r < 0)
                                return r;

                        if (lseek(fd_from, 0, SEEK_SET) < 0)
                                return log_error_errno(errno, "Failed to seek in \"%s\": %m", from);

                        fd_to = safe_close(fd_to);
                }
        }

        r = tempfn_random(to, NULL, &t);
        if (r < 0)
                return log_oom();

        WITH_UMASK(0000) {
                fd_to = open(t, O_WRONLY|O_CREAT|O_CLOEXEC|O_EXCL|O_NOFOLLOW, 0644);
                if (fd_to < 0)
                        return log_error_errno(errno, "Failed to open \"%s\" for writing: %m", t);
        }

        r = copy_bytes(fd_from, fd_to, UINT64_MAX, COPY_REFLINK);
        if (r < 0) {
                (void) unlink(t);
                return log_error_errno(r, "Failed to copy data from \"%s\" to \"%s\": %m", from, t);
        }

        (void) copy_times(fd_from, fd_to, 0);

        r = fsync_full(fd_to);
        if (r < 0) {
                (void) unlink(t);
                return log_error_errno(r, "Failed to copy data from \"%s\" to \"%s\": %m", from, t);
        }

        r = RET_NERRNO(renameat(AT_FDCWD, t, AT_FDCWD, to));
        if (r < 0) {
                (void) unlink(t);
                return log_error_errno(r, "Failed to rename \"%s\" to \"%s\": %m", t, to);
        }

        log_info("Copied \"%s\" to \"%s\".", from, to);

        return 0;
}

static int mkdir_one(const char *prefix, const char *suffix) {
        _cleanup_free_ char *p = NULL;

        p = path_join(prefix, suffix);
        if (mkdir(p, 0700) < 0) {
                if (errno != EEXIST)
                        return log_error_errno(errno, "Failed to create \"%s\": %m", p);
        } else
                log_info("Created \"%s\".", p);

        return 0;
}

static const char *const esp_subdirs[] = {
        /* The directories to place in the ESP */
        "EFI",
        "EFI/systemd",
        "EFI/BOOT",
        "loader",
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

static int create_subdirs(const char *root, const char * const *subdirs) {
        int r;

        STRV_FOREACH(i, subdirs) {
                r = mkdir_one(root, *i);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int update_efi_boot_binaries(const char *esp_path, const char *source_path) {
        _cleanup_closedir_ DIR *d = NULL;
        _cleanup_free_ char *p = NULL;
        int r, ret = 0;

        r = chase_and_opendir("/EFI/BOOT", esp_path, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS, &p, &d);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to open directory \"%s/EFI/BOOT\": %m", esp_path);

        FOREACH_DIRENT(de, d, break) {
                _cleanup_close_ int fd = -EBADF;
                _cleanup_free_ char *v = NULL;

                if (!endswith_no_case(de->d_name, ".efi"))
                        continue;

                fd = openat(dirfd(d), de->d_name, O_RDONLY|O_CLOEXEC);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open \"%s/%s\" for reading: %m", p, de->d_name);

                r = get_file_version(fd, &v);
                if (r == -ESRCH)
                        continue;  /* No version information */
                if (r < 0)
                        return r;
                if (startswith(v, "systemd-boot ")) {
                        _cleanup_free_ char *dest_path = NULL;

                        dest_path = path_join(p, de->d_name);
                        if (!dest_path)
                                return log_oom();

                        RET_GATHER(ret, copy_file_with_version_check(source_path, dest_path, /* force = */ false));
                }
        }

        return ret;
}

static int copy_one_file(const char *esp_path, const char *name, bool force) {
        char *root = IN_SET(arg_install_source, ARG_INSTALL_SOURCE_AUTO, ARG_INSTALL_SOURCE_IMAGE) ? arg_root : NULL;
        _cleanup_free_ char *source_path = NULL, *dest_path = NULL, *p = NULL, *q = NULL;
        const char *e;
        char *dest_name, *s;
        int r, ret;

        dest_name = strdupa_safe(name);
        s = endswith_no_case(dest_name, ".signed");
        if (s)
                *s = 0;

        p = path_join(BOOTLIBDIR, name);
        if (!p)
                return log_oom();

        r = chase(p, root, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS, &source_path, NULL);
        /* If we had a root directory to try, we didn't find it and we are in auto mode, retry on the host */
        if (r == -ENOENT && root && arg_install_source == ARG_INSTALL_SOURCE_AUTO)
                r = chase(p, NULL, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS, &source_path, NULL);
        if (r < 0)
                return log_error_errno(r,
                                       "Failed to resolve path %s%s%s: %m",
                                       p,
                                       root ? " under directory " : "",
                                       strempty(root));

        q = path_join("/EFI/systemd/", dest_name);
        if (!q)
                return log_oom();

        r = chase(q, esp_path, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS|CHASE_NONEXISTENT, &dest_path, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to resolve path %s under directory %s: %m", q, esp_path);

        /* Note that if this fails we do the second copy anyway, but return this error code,
         * so we stash it away in a separate variable. */
        ret = copy_file_with_version_check(source_path, dest_path, force);

        e = startswith(dest_name, "systemd-boot");
        if (e) {
                _cleanup_free_ char *default_dest_path = NULL;
                char *v;

                /* Create the EFI default boot loader name (specified for removable devices) */
                v = strjoina("/EFI/BOOT/BOOT", e);
                ascii_strupper(strrchr(v, '/') + 1);

                r = chase(v, esp_path, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS|CHASE_NONEXISTENT, &default_dest_path, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve path %s under directory %s: %m", v, esp_path);

                RET_GATHER(ret, copy_file_with_version_check(source_path, default_dest_path, force));

                /* If we were installed under any other name in /EFI/BOOT, make sure we update those binaries
                 * as well. */
                if (!force)
                        RET_GATHER(ret, update_efi_boot_binaries(esp_path, source_path));
        }

        return ret;
}

static int install_binaries(const char *esp_path, const char *arch, bool force) {
        char *root = IN_SET(arg_install_source, ARG_INSTALL_SOURCE_AUTO, ARG_INSTALL_SOURCE_IMAGE) ? arg_root : NULL;
        _cleanup_closedir_ DIR *d = NULL;
        _cleanup_free_ char *path = NULL;
        int r;

        r = chase_and_opendir(BOOTLIBDIR, root, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS, &path, &d);
        /* If we had a root directory to try, we didn't find it and we are in auto mode, retry on the host */
        if (r == -ENOENT && root && arg_install_source == ARG_INSTALL_SOURCE_AUTO)
                r = chase_and_opendir(BOOTLIBDIR, NULL, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS, &path, &d);
        if (r == -ENOENT && arg_graceful) {
                log_debug("Source directory does not exist, ignoring.");
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to open boot loader directory %s%s: %m", strempty(root), BOOTLIBDIR);

        const char *suffix = strjoina(arch, ".efi");
        const char *suffix_signed = strjoina(arch, ".efi.signed");

        FOREACH_DIRENT(de, d, return log_error_errno(errno, "Failed to read \"%s\": %m", path)) {
                int k;

                if (!endswith_no_case(de->d_name, suffix) && !endswith_no_case(de->d_name, suffix_signed))
                        continue;

                /* skip the .efi file, if there's a .signed version of it */
                if (endswith_no_case(de->d_name, ".efi")) {
                        _cleanup_free_ const char *s = strjoin(de->d_name, ".signed");
                        if (!s)
                                return log_oom();
                        if (faccessat(dirfd(d), s, F_OK, 0) >= 0)
                                continue;
                }

                k = copy_one_file(esp_path, de->d_name, force);
                /* Don't propagate an error code if no update necessary, installed version already equal or
                 * newer version, or other boot loader in place. */
                if (arg_graceful && IN_SET(k, -ESTALE, -ESRCH))
                        continue;
                RET_GATHER(r, k);
        }

        return r;
}

static int install_loader_config(const char *esp_path) {
        _cleanup_(unlink_and_freep) char *t = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *p = NULL;
        int r;

        assert(arg_make_entry_directory >= 0);

        p = path_join(esp_path, "/loader/loader.conf");
        if (!p)
                return log_oom();
        if (access(p, F_OK) >= 0) /* Silently skip creation if the file already exists (early check) */
                return 0;

        r = fopen_tmpfile_linkable(p, O_WRONLY|O_CLOEXEC, &t, &f);
        if (r < 0)
                return log_error_errno(r, "Failed to open \"%s\" for writing: %m", p);

        fprintf(f, "#timeout 3\n"
                   "#console-mode keep\n");

        if (arg_make_entry_directory) {
                assert(arg_entry_token);
                fprintf(f, "default %s-*\n", arg_entry_token);
        }

        r = flink_tmpfile(f, t, p, LINK_TMPFILE_SYNC);
        if (r == -EEXIST)
                return 0; /* Silently skip creation if the file exists now (recheck) */
        if (r < 0)
                return log_error_errno(r, "Failed to move \"%s\" into place: %m", p);

        t = mfree(t);
        return 1;
}

static int install_loader_specification(const char *root) {
        _cleanup_(unlink_and_freep) char *t = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *p = NULL;
        int r;

        p = path_join(root, "/loader/entries.srel");
        if (!p)
                return log_oom();

        if (access(p, F_OK) >= 0) /* Silently skip creation if the file already exists (early check) */
                return 0;

        r = fopen_tmpfile_linkable(p, O_WRONLY|O_CLOEXEC, &t, &f);
        if (r < 0)
                return log_error_errno(r, "Failed to open \"%s\" for writing: %m", p);

        fprintf(f, "type1\n");

        r = flink_tmpfile(f, t, p, LINK_TMPFILE_SYNC);
        if (r == -EEXIST)
                return 0; /* Silently skip creation if the file exists now (recheck) */
        if (r < 0)
                return log_error_errno(r, "Failed to move \"%s\" into place: %m", p);

        t = mfree(t);
        return 1;
}

static int install_entry_directory(const char *root) {
        assert(root);
        assert(arg_make_entry_directory >= 0);

        if (!arg_make_entry_directory)
                return 0;

        assert(arg_entry_token);
        return mkdir_one(root, arg_entry_token);
}

static int install_entry_token(void) {
        _cleanup_free_ char* p = NULL;
        int r;

        assert(arg_make_entry_directory >= 0);
        assert(arg_entry_token);

        /* Let's save the used entry token in /etc/kernel/entry-token if we used it to create the entry
         * directory, or if anything else but the machine ID */

        if (!arg_make_entry_directory && arg_entry_token_type == BOOT_ENTRY_TOKEN_MACHINE_ID)
                return 0;

        p = path_join(arg_root, etc_kernel(), "entry-token");
        if (!p)
                return log_oom();

        r = write_string_file(p, arg_entry_token, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC|WRITE_STRING_FILE_MKDIR_0755);
        if (r < 0)
                return log_error_errno(r, "Failed to write entry token '%s' to %s: %m", arg_entry_token, p);

        return 0;
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

static int insert_into_order(uint16_t slot, bool first) {
        _cleanup_free_ uint16_t *order = NULL;
        uint16_t *t;
        int n;

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
                if (!first)
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
        if (first) {
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
                const char *esp_path,
                uint32_t part,
                uint64_t pstart,
                uint64_t psize,
                sd_id128_t uuid,
                const char *path,
                bool first,
                bool graceful) {

        uint16_t slot;
        int r;

        if (arg_root) {
                log_info("Acting on %s, skipping EFI variable setup.",
                         arg_image ? "image" : "root directory");
                return 0;
        }

        if (!is_efi_boot()) {
                log_warning("Not booted with EFI, skipping EFI variable setup.");
                return 0;
        }

        r = chase_and_access(path, esp_path, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS, F_OK, NULL);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Cannot access \"%s/%s\": %m", esp_path, path);

        r = find_slot(uuid, path, &slot);
        if (r < 0) {
                int level = graceful ? arg_quiet ? LOG_DEBUG : LOG_INFO : LOG_ERR;
                const char *skip = graceful ? ", skipping" : "";

                log_full_errno(level, r,
                               r == -ENOENT ?
                               "Failed to access EFI variables%s. Is the \"efivarfs\" filesystem mounted?" :
                               "Failed to determine current boot order%s: %m", skip);

                return graceful ? 0 : r;
        }

        if (first || r == 0) {
                r = efi_add_boot_option(slot, pick_efi_boot_option_description(),
                                        part, pstart, psize,
                                        uuid, path);
                if (r < 0) {
                        int level = graceful ? arg_quiet ? LOG_DEBUG : LOG_INFO : LOG_ERR;
                        const char *skip = graceful ? ", skipping" : "";

                        log_full_errno(level, r, "Failed to create EFI Boot variable entry%s: %m", skip);

                        return graceful ? 0 : r;
                }

                log_info("Created EFI boot entry \"%s\".", pick_efi_boot_option_description());
        }

        return insert_into_order(slot, first);
}

static int are_we_installed(const char *esp_path) {
        int r;

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

        _cleanup_free_ char *p = path_join(esp_path, "/EFI/systemd/");
        if (!p)
                return log_oom();

        log_debug("Checking whether %s contains any files%s", p, special_glyph(SPECIAL_GLYPH_ELLIPSIS));
        r = dir_is_empty(p, /* ignore_hidden_or_backup= */ false);
        if (r < 0 && r != -ENOENT)
                return log_error_errno(r, "Failed to check whether %s contains any files: %m", p);

        return r == 0;
}

int verb_install(int argc, char *argv[], void *userdata) {
        sd_id128_t uuid = SD_ID128_NULL;
        uint64_t pstart = 0, psize = 0;
        uint32_t part = 0;
        bool install, graceful;
        int r;

        /* Invoked for both "update" and "install" */

        install = streq(argv[0], "install");
        graceful = !install && arg_graceful; /* support graceful mode for updates */

        r = acquire_esp(/* unprivileged_mode= */ false, graceful, &part, &pstart, &psize, &uuid, NULL);
        if (graceful && r == -ENOKEY)
                return 0; /* If --graceful is specified and we can't find an ESP, handle this cleanly */
        if (r < 0)
                return r;

        if (!install) {
                /* If we are updating, don't do anything if sd-boot wasn't actually installed. */
                r = are_we_installed(arg_esp_path);
                if (r < 0)
                        return r;
                if (r == 0) {
                        log_debug("Skipping update because sd-boot is not installed in the ESP.");
                        return 0;
                }
        }

        r = acquire_xbootldr(/* unprivileged_mode= */ false, NULL, NULL);
        if (r < 0)
                return r;

        r = settle_make_entry_directory();
        if (r < 0)
                return r;

        const char *arch = arg_arch_all ? "" : get_efi_arch();

        WITH_UMASK(0002) {
                if (install) {
                        /* Don't create any of these directories when we are just updating. When we update
                         * we'll drop-in our files (unless there are newer ones already), but we won't create
                         * the directories for them in the first place. */
                        r = create_subdirs(arg_esp_path, esp_subdirs);
                        if (r < 0)
                                return r;

                        r = create_subdirs(arg_dollar_boot_path(), dollar_boot_subdirs);
                        if (r < 0)
                                return r;
                }

                r = install_binaries(arg_esp_path, arch, install);
                if (r < 0)
                        return r;

                if (install) {
                        r = install_loader_config(arg_esp_path);
                        if (r < 0)
                                return r;

                        r = install_entry_directory(arg_dollar_boot_path());
                        if (r < 0)
                                return r;

                        r = install_entry_token();
                        if (r < 0)
                                return r;

                        r = install_random_seed(arg_esp_path);
                        if (r < 0)
                                return r;
                }

                r = install_loader_specification(arg_dollar_boot_path());
                if (r < 0)
                        return r;
        }

        (void) sync_everything();

        if (!arg_touch_variables)
                return 0;

        if (arg_arch_all) {
                log_info("Not changing EFI variables with --all-architectures.");
                return 0;
        }

        char *path = strjoina("/EFI/systemd/systemd-boot", arch, ".efi");
        return install_variables(arg_esp_path, part, pstart, psize, uuid, path, install, graceful);
}

static int remove_boot_efi(const char *esp_path) {
        _cleanup_closedir_ DIR *d = NULL;
        _cleanup_free_ char *p = NULL;
        int r, c = 0;

        r = chase_and_opendir("/EFI/BOOT", esp_path, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS, &p, &d);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to open directory \"%s/EFI/BOOT\": %m", esp_path);

        FOREACH_DIRENT(de, d, break) {
                _cleanup_close_ int fd = -EBADF;
                _cleanup_free_ char *v = NULL;

                if (!endswith_no_case(de->d_name, ".efi"))
                        continue;

                fd = openat(dirfd(d), de->d_name, O_RDONLY|O_CLOEXEC);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open \"%s/%s\" for reading: %m", p, de->d_name);

                r = get_file_version(fd, &v);
                if (r == -ESRCH)
                        continue;  /* No version information */
                if (r < 0)
                        return r;
                if (startswith(v, "systemd-boot ")) {
                        r = unlinkat(dirfd(d), de->d_name, 0);
                        if (r < 0)
                                return log_error_errno(errno, "Failed to remove \"%s/%s\": %m", p, de->d_name);

                        log_info("Removed \"%s/%s\".", p, de->d_name);
                }

                c++;
        }

        return c;
}

static int rmdir_one(const char *prefix, const char *suffix) {
        const char *p;

        p = prefix_roota(prefix, suffix);
        if (rmdir(p) < 0) {
                bool ignore = IN_SET(errno, ENOENT, ENOTEMPTY);

                log_full_errno(ignore ? LOG_DEBUG : LOG_ERR, errno,
                               "Failed to remove directory \"%s\": %m", p);
                if (!ignore)
                        return -errno;
        } else
                log_info("Removed \"%s\".", p);

        return 0;
}

static int remove_subdirs(const char *root, const char *const *subdirs) {
        int r, q;

        /* We use recursion here to destroy the directories in reverse order. Which should be safe given how
         * short the array is. */

        if (!subdirs[0]) /* A the end of the list */
                return 0;

        r = remove_subdirs(root, subdirs + 1);
        q = rmdir_one(root, subdirs[0]);

        return r < 0 ? r : q;
}

static int remove_entry_directory(const char *root) {
        assert(root);
        assert(arg_make_entry_directory >= 0);

        if (!arg_make_entry_directory || !arg_entry_token)
                return 0;

        return rmdir_one(root, arg_entry_token);
}

static int remove_binaries(const char *esp_path) {
        const char *p;
        int r, q;

        p = prefix_roota(esp_path, "/EFI/systemd");
        r = rm_rf(p, REMOVE_ROOT|REMOVE_PHYSICAL);

        q = remove_boot_efi(esp_path);
        if (q < 0 && r == 0)
                r = q;

        return r;
}

static int remove_file(const char *root, const char *file) {
        const char *p;

        assert(root);
        assert(file);

        p = prefix_roota(root, file);
        if (unlink(p) < 0) {
                log_full_errno(errno == ENOENT ? LOG_DEBUG : LOG_ERR, errno,
                               "Failed to unlink file \"%s\": %m", p);

                return errno == ENOENT ? 0 : -errno;
        }

        log_info("Removed \"%s\".", p);
        return 1;
}

static int remove_variables(sd_id128_t uuid, const char *path, bool in_order) {
        uint16_t slot;
        int r;

        if (arg_root || !is_efi_boot())
                return 0;

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
                       EFI_LOADER_VARIABLE(LoaderConfigConsoleMode),
                       EFI_LOADER_VARIABLE(LoaderConfigTimeout),
                       EFI_LOADER_VARIABLE(LoaderConfigTimeoutOneShot),
                       EFI_LOADER_VARIABLE(LoaderEntryDefault),
                       EFI_LOADER_VARIABLE(LoaderEntryLastBooted),
                       EFI_LOADER_VARIABLE(LoaderEntryOneShot),
                       EFI_LOADER_VARIABLE(LoaderSystemToken)){

                int q;

                q = efi_set_variable(var, NULL, 0);
                if (q == -ENOENT)
                        continue;
                if (q < 0) {
                        log_warning_errno(q, "Failed to remove EFI variable %s: %m", var);
                        if (r >= 0)
                                r = q;
                } else
                        log_info("Removed EFI variable %s.", var);
        }

        return r;
}

int verb_remove(int argc, char *argv[], void *userdata) {
        sd_id128_t uuid = SD_ID128_NULL;
        int r, q;

        r = acquire_esp(/* unprivileged_mode= */ false, /* graceful= */ false, NULL, NULL, NULL, &uuid, NULL);
        if (r < 0)
                return r;

        r = acquire_xbootldr(/* unprivileged_mode= */ false, NULL, NULL);
        if (r < 0)
                return r;

        r = settle_make_entry_directory();
        if (r < 0)
                return r;

        r = remove_binaries(arg_esp_path);

        q = remove_file(arg_esp_path, "/loader/loader.conf");
        if (q < 0 && r >= 0)
                r = q;

        q = remove_file(arg_esp_path, "/loader/random-seed");
        if (q < 0 && r >= 0)
                r = q;

        q = remove_file(arg_esp_path, "/loader/entries.srel");
        if (q < 0 && r >= 0)
                r = q;

        q = remove_subdirs(arg_esp_path, esp_subdirs);
        if (q < 0 && r >= 0)
                r = q;

        q = remove_subdirs(arg_esp_path, dollar_boot_subdirs);
        if (q < 0 && r >= 0)
                r = q;

        q = remove_entry_directory(arg_esp_path);
        if (q < 0 && r >= 0)
                r = q;

        if (arg_xbootldr_path) {
                /* Remove a subset of these also from the XBOOTLDR partition if it exists */

                q = remove_file(arg_xbootldr_path, "/loader/entries.srel");
                if (q < 0 && r >= 0)
                        r = q;

                q = remove_subdirs(arg_xbootldr_path, dollar_boot_subdirs);
                if (q < 0 && r >= 0)
                        r = q;

                q = remove_entry_directory(arg_xbootldr_path);
                if (q < 0 && r >= 0)
                        r = q;
        }

        (void) sync_everything();

        if (!arg_touch_variables)
                return r;

        if (arg_arch_all) {
                log_info("Not changing EFI variables with --all-architectures.");
                return r;
        }

        char *path = strjoina("/EFI/systemd/systemd-boot", get_efi_arch(), ".efi");
        q = remove_variables(uuid, path, true);
        if (q < 0 && r >= 0)
                r = q;

        q = remove_loader_variables();
        if (q < 0 && r >= 0)
                r = q;

        return r;
}

int verb_is_installed(int argc, char *argv[], void *userdata) {
        int r;

        r = acquire_esp(/* unprivileged_mode= */ false,
                        /* graceful= */ arg_graceful,
                        NULL, NULL, NULL, NULL, NULL);
        if (r < 0)
                return r;

        r = are_we_installed(arg_esp_path);
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
