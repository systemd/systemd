/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <linux/magic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "blkid-util.h"
#include "bootctl.h"
#include "bootctl-random-seed.h"
#include "bootctl-reboot-to-firmware.h"
#include "bootctl-set-efivar.h"
#include "bootctl-status.h"
#include "bootctl-systemd-efi-options.h"
#include "bootctl-util.h"
#include "bootspec.h"
#include "build.h"
#include "chase-symlinks.h"
#include "copy.h"
#include "devnum-util.h"
#include "dirent-util.h"
#include "dissect-image.h"
#include "efi-api.h"
#include "efi-loader.h"
#include "efivars.h"
#include "env-file.h"
#include "env-util.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "find-esp.h"
#include "fs-util.h"
#include "glyph-util.h"
#include "main-func.h"
#include "mkdir.h"
#include "mount-util.h"
#include "os-util.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "random-util.h"
#include "rm-rf.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "sync-util.h"
#include "terminal-util.h"
#include "tmpfile-util.h"
#include "tmpfile-util-label.h"
#include "tpm2-util.h"
#include "umask-util.h"
#include "utf8.h"
#include "verbs.h"
#include "virt.h"

/* EFI_BOOT_OPTION_DESCRIPTION_MAX sets the maximum length for the boot option description
 * stored in NVRAM. The UEFI spec does not specify a minimum or maximum length for this
 * string, but we limit the length to something reasonable to prevent from the firmware
 * having to deal with a potentially too long string. */
#define EFI_BOOT_OPTION_DESCRIPTION_MAX ((size_t) 255)

char *arg_esp_path = NULL;
char *arg_xbootldr_path = NULL;
bool arg_print_esp_path = false;
bool arg_print_dollar_boot_path = false;
bool arg_touch_variables = true;
PagerFlags arg_pager_flags = 0;
bool arg_graceful = false;
bool arg_quiet = false;
int arg_make_entry_directory = false; /* tri-state: < 0 for automatic logic */
sd_id128_t arg_machine_id = SD_ID128_NULL;
char *arg_install_layout = NULL;
static enum {
        ARG_ENTRY_TOKEN_MACHINE_ID,
        ARG_ENTRY_TOKEN_OS_IMAGE_ID,
        ARG_ENTRY_TOKEN_OS_ID,
        ARG_ENTRY_TOKEN_LITERAL,
        ARG_ENTRY_TOKEN_AUTO,
} arg_entry_token_type = ARG_ENTRY_TOKEN_AUTO;
char *arg_entry_token = NULL;
JsonFormatFlags arg_json_format_flags = JSON_FORMAT_OFF;
bool arg_arch_all = false;
char *arg_root = NULL;
char *arg_image = NULL;
static enum {
        ARG_INSTALL_SOURCE_IMAGE,
        ARG_INSTALL_SOURCE_HOST,
        ARG_INSTALL_SOURCE_AUTO,
} arg_install_source = ARG_INSTALL_SOURCE_AUTO;
char *arg_efi_boot_option_description = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_esp_path, freep);
STATIC_DESTRUCTOR_REGISTER(arg_xbootldr_path, freep);
STATIC_DESTRUCTOR_REGISTER(arg_install_layout, freep);
STATIC_DESTRUCTOR_REGISTER(arg_entry_token, freep);
STATIC_DESTRUCTOR_REGISTER(arg_root, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image, freep);
STATIC_DESTRUCTOR_REGISTER(arg_efi_boot_option_description, freep);

static const char *pick_efi_boot_option_description(void) {
        return arg_efi_boot_option_description ?: "Linux Boot Manager";
}

int acquire_esp(
                bool unprivileged_mode,
                bool graceful,
                uint32_t *ret_part,
                uint64_t *ret_pstart,
                uint64_t *ret_psize,
                sd_id128_t *ret_uuid,
                dev_t *ret_devid) {

        char *np;
        int r;

        /* Find the ESP, and log about errors. Note that find_esp_and_warn() will log in all error cases on
         * its own, except for ENOKEY (which is good, we want to show our own message in that case,
         * suggesting use of --esp-path=) and EACCESS (only when we request unprivileged mode; in this case
         * we simply eat up the error here, so that --list and --status work too, without noise about
         * this). */

        r = find_esp_and_warn(arg_root, arg_esp_path, unprivileged_mode, &np, ret_part, ret_pstart, ret_psize, ret_uuid, ret_devid);
        if (r == -ENOKEY) {
                if (graceful)
                        return log_full_errno(arg_quiet ? LOG_DEBUG : LOG_INFO, r,
                                              "Couldn't find EFI system partition, skipping.");

                return log_error_errno(r,
                                       "Couldn't find EFI system partition. It is recommended to mount it to /boot or /efi.\n"
                                       "Alternatively, use --esp-path= to specify path to mount point.");
        }
        if (r < 0)
                return r;

        free_and_replace(arg_esp_path, np);
        log_debug("Using EFI System Partition at %s.", arg_esp_path);

        return 0;
}

int acquire_xbootldr(
                bool unprivileged_mode,
                sd_id128_t *ret_uuid,
                dev_t *ret_devid) {

        char *np;
        int r;

        r = find_xbootldr_and_warn(arg_root, arg_xbootldr_path, unprivileged_mode, &np, ret_uuid, ret_devid);
        if (r == -ENOKEY) {
                log_debug_errno(r, "Didn't find an XBOOTLDR partition, using the ESP as $BOOT.");
                arg_xbootldr_path = mfree(arg_xbootldr_path);

                if (ret_uuid)
                        *ret_uuid = SD_ID128_NULL;
                if (ret_devid)
                        *ret_devid = 0;
                return 0;
        }
        if (r < 0)
                return r;

        free_and_replace(arg_xbootldr_path, np);
        log_debug("Using XBOOTLDR partition at %s as $BOOT.", arg_xbootldr_path);

        return 1;
}

static int load_etc_machine_id(void) {
        int r;

        r = sd_id128_get_machine(&arg_machine_id);
        if (IN_SET(r, -ENOENT, -ENOMEDIUM, -ENOPKG)) /* Not set or empty */
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
        _cleanup_free_ char *s = NULL, *layout = NULL;
        int r;

        r = parse_env_file(NULL, "/etc/machine-info",
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

                log_debug("Loaded KERNEL_INSTALL_MACHINE_ID=%s from KERNEL_INSTALL_MACHINE_ID in /etc/machine-info.",
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
        _cleanup_free_ char *layout = NULL;
        int r;

        r = parse_env_file(NULL, "/etc/kernel/install.conf",
                           "layout", &layout);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to parse /etc/kernel/install.conf: %m");

        if (!isempty(layout)) {
                log_debug("layout=%s is specified in /etc/machine-info.", layout);
                free_and_replace(arg_install_layout, layout);
        }

        return 0;
}

static int settle_entry_token(void) {
        int r;

        switch (arg_entry_token_type) {

        case ARG_ENTRY_TOKEN_AUTO: {
                _cleanup_free_ char *buf = NULL;
                r = read_one_line_file("/etc/kernel/entry-token", &buf);
                if (r < 0 && r != -ENOENT)
                        return log_error_errno(r, "Failed to read /etc/kernel/entry-token: %m");

                if (!isempty(buf)) {
                        free_and_replace(arg_entry_token, buf);
                        arg_entry_token_type = ARG_ENTRY_TOKEN_LITERAL;
                } else if (sd_id128_is_null(arg_machine_id)) {
                        _cleanup_free_ char *id = NULL, *image_id = NULL;

                        r = parse_os_release(NULL,
                                             "IMAGE_ID", &image_id,
                                             "ID", &id);
                        if (r < 0)
                                return log_error_errno(r, "Failed to load /etc/os-release: %m");

                        if (!isempty(image_id)) {
                                free_and_replace(arg_entry_token, image_id);
                                arg_entry_token_type = ARG_ENTRY_TOKEN_OS_IMAGE_ID;
                        } else if (!isempty(id)) {
                                free_and_replace(arg_entry_token, id);
                                arg_entry_token_type = ARG_ENTRY_TOKEN_OS_ID;
                        } else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No machine ID set, and /etc/os-release carries no ID=/IMAGE_ID= fields.");
                } else {
                        r = free_and_strdup_warn(&arg_entry_token, SD_ID128_TO_STRING(arg_machine_id));
                        if (r < 0)
                                return r;

                        arg_entry_token_type = ARG_ENTRY_TOKEN_MACHINE_ID;
                }

                break;
        }

        case ARG_ENTRY_TOKEN_MACHINE_ID:
                if (sd_id128_is_null(arg_machine_id))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No machine ID set.");

                r = free_and_strdup_warn(&arg_entry_token, SD_ID128_TO_STRING(arg_machine_id));
                if (r < 0)
                        return r;

                break;

        case ARG_ENTRY_TOKEN_OS_IMAGE_ID: {
                _cleanup_free_ char *buf = NULL;

                r = parse_os_release(NULL, "IMAGE_ID", &buf);
                if (r < 0)
                        return log_error_errno(r, "Failed to load /etc/os-release: %m");

                if (isempty(buf))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "IMAGE_ID= field not set in /etc/os-release.");

                free_and_replace(arg_entry_token, buf);
                break;
        }

        case ARG_ENTRY_TOKEN_OS_ID: {
                _cleanup_free_ char *buf = NULL;

                r = parse_os_release(NULL, "ID", &buf);
                if (r < 0)
                        return log_error_errno(r, "Failed to load /etc/os-release: %m");

                if (isempty(buf))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "ID= field not set in /etc/os-release.");

                free_and_replace(arg_entry_token, buf);
                break;
        }

        case ARG_ENTRY_TOKEN_LITERAL:
                assert(!isempty(arg_entry_token)); /* already filled in by command line parser */
                break;
        }

        if (isempty(arg_entry_token) || !(utf8_is_valid(arg_entry_token) && string_is_safe(arg_entry_token)))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Selected entry token not valid: %s", arg_entry_token);

        log_debug("Using entry token: %s", arg_entry_token);
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
                        if (arg_entry_token == ARG_ENTRY_TOKEN_MACHINE_ID) {
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
        if (r < 0)
                return r;
        if (r == 0)
                return log_notice_errno(SYNTHETIC_ERRNO(EREMOTE),
                                       "Source file \"%s\" does not carry version information!",
                                       from);

        r = get_file_version(fd_to, &b);
        if (r < 0)
                return r;
        if (r == 0 || compare_product(a, b) != 0)
                return log_notice_errno(SYNTHETIC_ERRNO(EREMOTE),
                                        "Skipping \"%s\", since it's owned by another boot loader.",
                                        to);

        r = compare_version(a, b);
        log_debug("Comparing versions: \"%s\" %s \"%s", a, comparison_operator(r), b);
        if (r < 0)
                return log_warning_errno(SYNTHETIC_ERRNO(ESTALE),
                                         "Skipping \"%s\", since newer boot loader version in place already.", to);
        if (r == 0)
                return log_info_errno(SYNTHETIC_ERRNO(ESTALE),
                                      "Skipping \"%s\", since same boot loader version in place already.", to);

        return 0;
}

static int copy_file_with_version_check(const char *from, const char *to, bool force) {
        _cleanup_close_ int fd_from = -1, fd_to = -1;
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

                        if (lseek(fd_from, 0, SEEK_SET) == (off_t) -1)
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
                (void) unlink_noerrno(t);
                return log_error_errno(r, "Failed to copy data from \"%s\" to \"%s\": %m", from, t);
        }

        if (renameat(AT_FDCWD, t, AT_FDCWD, to) < 0) {
                (void) unlink_noerrno(t);
                return log_error_errno(errno, "Failed to rename \"%s\" to \"%s\": %m", t, to);
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

        r = chase_symlinks(p, root, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS, &source_path, NULL);
        /* If we had a root directory to try, we didn't find it and we are in auto mode, retry on the host */
        if (r == -ENOENT && root && arg_install_source == ARG_INSTALL_SOURCE_AUTO)
                r = chase_symlinks(p, NULL, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS, &source_path, NULL);
        if (r < 0)
                return log_error_errno(r,
                                       "Failed to resolve path %s%s%s: %m",
                                       p,
                                       root ? " under directory " : "",
                                       strempty(root));

        q = path_join("/EFI/systemd/", dest_name);
        if (!q)
                return log_oom();

        r = chase_symlinks(q, esp_path, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS|CHASE_NONEXISTENT, &dest_path, NULL);
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

                r = chase_symlinks(v, esp_path, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS|CHASE_NONEXISTENT, &default_dest_path, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve path %s under directory %s: %m", v, esp_path);

                r = copy_file_with_version_check(source_path, default_dest_path, force);
                if (r < 0 && ret == 0)
                        ret = r;
        }

        return ret;
}

static int install_binaries(const char *esp_path, const char *arch, bool force) {
        char *root = IN_SET(arg_install_source, ARG_INSTALL_SOURCE_AUTO, ARG_INSTALL_SOURCE_IMAGE) ? arg_root : NULL;
        _cleanup_closedir_ DIR *d = NULL;
        _cleanup_free_ char *path = NULL;
        int r;

        r = chase_symlinks_and_opendir(BOOTLIBDIR, root, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS, &path, &d);
        /* If we had a root directory to try, we didn't find it and we are in auto mode, retry on the host */
        if (r == -ENOENT && root && arg_install_source == ARG_INSTALL_SOURCE_AUTO)
                r = chase_symlinks_and_opendir(BOOTLIBDIR, NULL, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS, &path, &d);
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
                if (arg_graceful && IN_SET(k, -ESTALE, -EREMOTE))
                        continue;
                if (k < 0 && r == 0)
                        r = k;
        }

        return r;
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

static int install_variables(
                const char *esp_path,
                uint32_t part,
                uint64_t pstart,
                uint64_t psize,
                sd_id128_t uuid,
                const char *path,
                bool first) {

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

        r = chase_symlinks_and_access(path, esp_path, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS, F_OK, NULL, NULL);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Cannot access \"%s/%s\": %m", esp_path, path);

        r = find_slot(uuid, path, &slot);
        if (r < 0)
                return log_error_errno(r,
                                       r == -ENOENT ?
                                       "Failed to access EFI variables. Is the \"efivarfs\" filesystem mounted?" :
                                       "Failed to determine current boot order: %m");

        if (first || r == 0) {
                r = efi_add_boot_option(slot, pick_efi_boot_option_description(),
                                        part, pstart, psize,
                                        uuid, path);
                if (r < 0)
                        return log_error_errno(r, "Failed to create EFI Boot variable entry: %m");

                log_info("Created EFI boot entry \"%s\".", pick_efi_boot_option_description());
        }

        return insert_into_order(slot, first);
}

static int remove_boot_efi(const char *esp_path) {
        _cleanup_closedir_ DIR *d = NULL;
        _cleanup_free_ char *p = NULL;
        int r, c = 0;

        r = chase_symlinks_and_opendir("/EFI/BOOT", esp_path, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS, &p, &d);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to open directory \"%s/EFI/BOOT\": %m", esp_path);

        FOREACH_DIRENT(de, d, break) {
                _cleanup_close_ int fd = -1;
                _cleanup_free_ char *v = NULL;

                if (!endswith_no_case(de->d_name, ".efi"))
                        continue;

                if (!startswith_no_case(de->d_name, "boot"))
                        continue;

                fd = openat(dirfd(d), de->d_name, O_RDONLY|O_CLOEXEC);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open \"%s/%s\" for reading: %m", p, de->d_name);

                r = get_file_version(fd, &v);
                if (r < 0)
                        return r;
                if (r > 0 && startswith(v, "systemd-boot ")) {
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
                       EFI_LOADER_VARIABLE(LoaderConfigTimeout),
                       EFI_LOADER_VARIABLE(LoaderConfigTimeoutOneShot),
                       EFI_LOADER_VARIABLE(LoaderEntryDefault),
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

static int install_loader_config(const char *esp_path) {
        _cleanup_(unlink_and_freep) char *t = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        const char *p;
        int r;

        assert(arg_make_entry_directory >= 0);

        p = prefix_roota(esp_path, "/loader/loader.conf");
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

        r = flink_tmpfile(f, t, p);
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

        r = flink_tmpfile(f, t, p);
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
        int r;

        assert(arg_make_entry_directory >= 0);
        assert(arg_entry_token);

        /* Let's save the used entry token in /etc/kernel/entry-token if we used it to create the entry
         * directory, or if anything else but the machine ID */

        if (!arg_make_entry_directory && arg_entry_token_type == ARG_ENTRY_TOKEN_MACHINE_ID)
                return 0;

        r = write_string_file("/etc/kernel/entry-token", arg_entry_token, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC|WRITE_STRING_FILE_MKDIR_0755);
        if (r < 0)
                return log_error_errno(r, "Failed to write entry token '%s' to /etc/kernel/entry-token", arg_entry_token);

        return 0;
}

static int help(int argc, char *argv[], void *userdata) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("bootctl", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s  [OPTIONS...] COMMAND ...\n"
               "\n%5$sControl EFI firmware boot settings and manage boot loader.%6$s\n"
               "\n%3$sGeneric EFI Firmware/Boot Loader Commands:%4$s\n"
               "  status              Show status of installed boot loader and EFI variables\n"
               "  reboot-to-firmware [BOOL]\n"
               "                      Query or set reboot-to-firmware EFI flag\n"
               "  systemd-efi-options [STRING]\n"
               "                      Query or set system options string in EFI variable\n"
               "\n%3$sBoot Loader Specification Commands:%4$s\n"
               "  list                List boot loader entries\n"
               "  set-default ID      Set default boot loader entry\n"
               "  set-oneshot ID      Set default boot loader entry, for next boot only\n"
               "  set-timeout SECONDS Set the menu timeout\n"
               "  set-timeout-oneshot SECONDS\n"
               "                      Set the menu timeout for the next boot only\n"
               "\n%3$ssystemd-boot Commands:%4$s\n"
               "  install             Install systemd-boot to the ESP and EFI variables\n"
               "  update              Update systemd-boot in the ESP and EFI variables\n"
               "  remove              Remove systemd-boot from the ESP and EFI variables\n"
               "  is-installed        Test whether systemd-boot is installed in the ESP\n"
               "  random-seed         Initialize random seed in ESP and EFI variables\n"
               "\n%3$sOptions:%4$s\n"
               "  -h --help            Show this help\n"
               "     --version         Print version\n"
               "     --esp-path=PATH   Path to the EFI System Partition (ESP)\n"
               "     --boot-path=PATH  Path to the $BOOT partition\n"
               "     --root=PATH       Operate on an alternate filesystem root\n"
               "     --image=PATH      Operate on disk image as filesystem root\n"
               "     --install-source=auto|image|host\n"
               "                       Where to pick files when using --root=/--image=\n"
               "  -p --print-esp-path  Print path to the EFI System Partition\n"
               "  -x --print-boot-path Print path to the $BOOT partition\n"
               "     --no-variables    Don't touch EFI variables\n"
               "     --no-pager        Do not pipe output into a pager\n"
               "     --graceful        Don't fail when the ESP cannot be found or EFI\n"
               "                       variables cannot be written\n"
               "  -q --quiet           Suppress output\n"
               "     --make-entry-directory=yes|no|auto\n"
               "                       Create $BOOT/ENTRY-TOKEN/ directory\n"
               "     --entry-token=machine-id|os-id|os-image-id|auto|literal:…\n"
               "                       Entry token to use for this installation\n"
               "     --json=pretty|short|off\n"
               "                       Generate JSON output\n"
               "     --all-architectures\n"
               "                       Install all supported EFI architectures\n"
               "     --efi-boot-option-description=DESCRIPTION\n"
               "                       Description of the entry in the boot option list\n"
               "\nSee the %2$s for details.\n",
               program_invocation_short_name,
               link,
               ansi_underline(),
               ansi_normal(),
               ansi_highlight(),
               ansi_normal());

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_ESP_PATH = 0x100,
                ARG_BOOT_PATH,
                ARG_ROOT,
                ARG_IMAGE,
                ARG_INSTALL_SOURCE,
                ARG_VERSION,
                ARG_NO_VARIABLES,
                ARG_NO_PAGER,
                ARG_GRACEFUL,
                ARG_MAKE_ENTRY_DIRECTORY,
                ARG_ENTRY_TOKEN,
                ARG_JSON,
                ARG_ARCH_ALL,
                ARG_EFI_BOOT_OPTION_DESCRIPTION,
        };

        static const struct option options[] = {
                { "help",                        no_argument,       NULL, 'h'                             },
                { "version",                     no_argument,       NULL, ARG_VERSION                     },
                { "esp-path",                    required_argument, NULL, ARG_ESP_PATH                    },
                { "path",                        required_argument, NULL, ARG_ESP_PATH                    }, /* Compatibility alias */
                { "boot-path",                   required_argument, NULL, ARG_BOOT_PATH                   },
                { "root",                        required_argument, NULL, ARG_ROOT                        },
                { "image",                       required_argument, NULL, ARG_IMAGE                       },
                { "install-source",              required_argument, NULL, ARG_INSTALL_SOURCE              },
                { "print-esp-path",              no_argument,       NULL, 'p'                             },
                { "print-path",                  no_argument,       NULL, 'p'                             }, /* Compatibility alias */
                { "print-boot-path",             no_argument,       NULL, 'x'                             },
                { "no-variables",                no_argument,       NULL, ARG_NO_VARIABLES                },
                { "no-pager",                    no_argument,       NULL, ARG_NO_PAGER                    },
                { "graceful",                    no_argument,       NULL, ARG_GRACEFUL                    },
                { "quiet",                       no_argument,       NULL, 'q'                             },
                { "make-entry-directory",        required_argument, NULL, ARG_MAKE_ENTRY_DIRECTORY        },
                { "make-machine-id-directory",   required_argument, NULL, ARG_MAKE_ENTRY_DIRECTORY        }, /* Compatibility alias */
                { "entry-token",                 required_argument, NULL, ARG_ENTRY_TOKEN                 },
                { "json",                        required_argument, NULL, ARG_JSON                        },
                { "all-architectures",           no_argument,       NULL, ARG_ARCH_ALL                    },
                { "efi-boot-option-description", required_argument, NULL, ARG_EFI_BOOT_OPTION_DESCRIPTION },
                {}
        };

        int c, r;
        bool b;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hpx", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        help(0, NULL, NULL);
                        return 0;

                case ARG_VERSION:
                        return version();

                case ARG_ESP_PATH:
                        r = free_and_strdup(&arg_esp_path, optarg);
                        if (r < 0)
                                return log_oom();
                        break;

                case ARG_BOOT_PATH:
                        r = free_and_strdup(&arg_xbootldr_path, optarg);
                        if (r < 0)
                                return log_oom();
                        break;

                case ARG_ROOT:
                        r = parse_path_argument(optarg, /* suppress_root= */ true, &arg_root);
                        if (r < 0)
                                return r;
                        break;

                case ARG_IMAGE:
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_image);
                        if (r < 0)
                                return r;
                        break;

                case ARG_INSTALL_SOURCE:
                        if (streq(optarg, "auto"))
                                arg_install_source = ARG_INSTALL_SOURCE_AUTO;
                        else if (streq(optarg, "image"))
                                arg_install_source = ARG_INSTALL_SOURCE_IMAGE;
                        else if (streq(optarg, "host"))
                                arg_install_source = ARG_INSTALL_SOURCE_HOST;
                        else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unexpected parameter for --install-source=: %s", optarg);

                        break;

                case 'p':
                        if (arg_print_dollar_boot_path)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "--print-boot-path/-x cannot be combined with --print-esp-path/-p");
                        arg_print_esp_path = true;
                        break;

                case 'x':
                        if (arg_print_esp_path)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "--print-boot-path/-x cannot be combined with --print-esp-path/-p");
                        arg_print_dollar_boot_path = true;
                        break;

                case ARG_NO_VARIABLES:
                        arg_touch_variables = false;
                        break;

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_GRACEFUL:
                        arg_graceful = true;
                        break;

                case 'q':
                        arg_quiet = true;
                        break;

                case ARG_ENTRY_TOKEN: {
                        const char *e;

                        if (streq(optarg, "machine-id")) {
                                arg_entry_token_type = ARG_ENTRY_TOKEN_MACHINE_ID;
                                arg_entry_token = mfree(arg_entry_token);
                        } else if (streq(optarg, "os-image-id")) {
                                arg_entry_token_type = ARG_ENTRY_TOKEN_OS_IMAGE_ID;
                                arg_entry_token = mfree(arg_entry_token);
                        } else if (streq(optarg, "os-id")) {
                                arg_entry_token_type = ARG_ENTRY_TOKEN_OS_ID;
                                arg_entry_token = mfree(arg_entry_token);
                        } else if ((e = startswith(optarg, "literal:"))) {
                                arg_entry_token_type = ARG_ENTRY_TOKEN_LITERAL;

                                r = free_and_strdup_warn(&arg_entry_token, e);
                                if (r < 0)
                                        return r;
                        } else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unexpected parameter for --entry-token=: %s", optarg);

                        break;
                }

                case ARG_MAKE_ENTRY_DIRECTORY:
                        if (streq(optarg, "auto"))  /* retained for backwards compatibility */
                                arg_make_entry_directory = -1; /* yes if machine-id is permanent */
                        else {
                                r = parse_boolean_argument("--make-entry-directory=", optarg, &b);
                                if (r < 0)
                                        return r;

                                arg_make_entry_directory = b;
                        }
                        break;

                case ARG_JSON:
                        r = parse_json_argument(optarg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;
                        break;

                case ARG_ARCH_ALL:
                        arg_arch_all = true;
                        break;

                case ARG_EFI_BOOT_OPTION_DESCRIPTION:
                        if (isempty(optarg) || !(string_is_safe(optarg) && utf8_is_valid(optarg))) {
                                _cleanup_free_ char *escaped = NULL;

                                escaped = cescape(optarg);
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Invalid --efi-boot-option-description=: %s", strna(escaped));
                        }
                        if (strlen(optarg) > EFI_BOOT_OPTION_DESCRIPTION_MAX)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "--efi-boot-option-description= too long: %zu > %zu", strlen(optarg), EFI_BOOT_OPTION_DESCRIPTION_MAX);
                        r = free_and_strdup_warn(&arg_efi_boot_option_description, optarg);
                        if (r < 0)
                                return r;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if ((arg_root || arg_image) && argv[optind] && !STR_IN_SET(argv[optind], "status", "list",
                        "install", "update", "remove", "is-installed", "random-seed"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Options --root= and --image= are not supported with verb %s.",
                                       argv[optind]);

        if (arg_root && arg_image)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Please specify either --root= or --image=, the combination of both is not supported.");

        if (arg_install_source != ARG_INSTALL_SOURCE_AUTO && !arg_root && !arg_image)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--install-from-host is only supported with --root= or --image=.");

        return 1;
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

static int verb_install(int argc, char *argv[], void *userdata) {
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
        return install_variables(arg_esp_path, part, pstart, psize, uuid, path, install);
}

static int verb_remove(int argc, char *argv[], void *userdata) {
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

static int verb_is_installed(int argc, char *argv[], void *userdata) {
        int r;

        r = acquire_esp(/* privileged_mode= */ false,
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

static int bootctl_main(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "help",                VERB_ANY, VERB_ANY, 0,            help                     },
                { "status",              VERB_ANY, 1,        VERB_DEFAULT, verb_status              },
                { "install",             VERB_ANY, 1,        0,            verb_install             },
                { "update",              VERB_ANY, 1,        0,            verb_install             },
                { "remove",              VERB_ANY, 1,        0,            verb_remove              },
                { "is-installed",        VERB_ANY, 1,        0,            verb_is_installed        },
                { "list",                VERB_ANY, 1,        0,            verb_list                },
                { "set-default",         2,        2,        0,            verb_set_efivar          },
                { "set-oneshot",         2,        2,        0,            verb_set_efivar          },
                { "set-timeout",         2,        2,        0,            verb_set_efivar          },
                { "set-timeout-oneshot", 2,        2,        0,            verb_set_efivar          },
                { "random-seed",         VERB_ANY, 1,        0,            verb_random_seed         },
                { "systemd-efi-options", VERB_ANY, 2,        0,            verb_systemd_efi_options },
                { "reboot-to-firmware",  VERB_ANY, 2,        0,            verb_reboot_to_firmware  },
                {}
        };

        return dispatch_verb(argc, argv, verbs, NULL);
}

static int run(int argc, char *argv[]) {
        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(umount_and_rmdir_and_freep) char *unlink_dir = NULL;
        int r;

        log_parse_environment();
        log_open();

        /* If we run in a container, automatically turn off EFI file system access */
        if (detect_container() > 0)
                arg_touch_variables = false;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        /* Open up and mount the image */
        if (arg_image) {
                assert(!arg_root);

                r = mount_image_privately_interactively(
                                arg_image,
                                DISSECT_IMAGE_GENERIC_ROOT |
                                DISSECT_IMAGE_RELAX_VAR_CHECK,
                                &unlink_dir,
                                &loop_device);
                if (r < 0)
                        return r;

                arg_root = strdup(unlink_dir);
                if (!arg_root)
                        return log_oom();
        }

        return bootctl_main(argc, argv);
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
