/* SPDX-License-Identifier: LGPL-2.1+ */

#include <blkid.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <ftw.h>
#include <getopt.h>
#include <limits.h>
#include <linux/magic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <unistd.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "blkid-util.h"
#include "bootspec.h"
#include "copy.h"
#include "dirent-util.h"
#include "efivars.h"
#include "env-util.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "locale-util.h"
#include "main-func.h"
#include "pager.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "random-util.h"
#include "rm-rf.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "tmpfile-util.h"
#include "umask-util.h"
#include "utf8.h"
#include "util.h"
#include "verbs.h"
#include "virt.h"

static char *arg_esp_path = NULL;
static char *arg_xbootldr_path = NULL;
static bool arg_print_esp_path = false;
static bool arg_print_dollar_boot_path = false;
static bool arg_touch_variables = true;
static PagerFlags arg_pager_flags = 0;

STATIC_DESTRUCTOR_REGISTER(arg_esp_path, freep);
STATIC_DESTRUCTOR_REGISTER(arg_xbootldr_path, freep);

static const char *arg_dollar_boot_path(void) {
        /* $BOOT shall be the XBOOTLDR partition if it exists, and otherwise the ESP */
        return arg_xbootldr_path ?: arg_esp_path;
}

static int acquire_esp(
                bool unprivileged_mode,
                uint32_t *ret_part,
                uint64_t *ret_pstart,
                uint64_t *ret_psize,
                sd_id128_t *ret_uuid) {

        char *np;
        int r;

        /* Find the ESP, and log about errors. Note that find_esp_and_warn() will log in all error cases on
         * its own, except for ENOKEY (which is good, we want to show our own message in that case,
         * suggesting use of --esp-path=) and EACCESS (only when we request unprivileged mode; in this case
         * we simply eat up the error here, so that --list and --status work too, without noise about
         * this). */

        r = find_esp_and_warn(arg_esp_path, unprivileged_mode, &np, ret_part, ret_pstart, ret_psize, ret_uuid);
        if (r == -ENOKEY)
                return log_error_errno(r,
                                       "Couldn't find EFI system partition. It is recommended to mount it to /boot or /efi.\n"
                                       "Alternatively, use --esp-path= to specify path to mount point.");
        if (r < 0)
                return r;

        free_and_replace(arg_esp_path, np);
        log_debug("Using EFI System Partition at %s.", arg_esp_path);

        return 1;
}

static int acquire_xbootldr(bool unprivileged_mode, sd_id128_t *ret_uuid) {
        char *np;
        int r;

        r = find_xbootldr_and_warn(arg_xbootldr_path, unprivileged_mode, &np, ret_uuid);
        if (r == -ENOKEY) {
                log_debug_errno(r, "Didn't find an XBOOTLDR partition, using the ESP as $BOOT.");
                if (ret_uuid)
                        *ret_uuid = SD_ID128_NULL;
                arg_xbootldr_path = mfree(arg_xbootldr_path);
                return 0;
        }
        if (r < 0)
                return r;

        free_and_replace(arg_xbootldr_path, np);
        log_debug("Using XBOOTLDR partition at %s as $BOOT.", arg_xbootldr_path);

        return 1;
}

/* search for "#### LoaderInfo: systemd-boot 218 ####" string inside the binary */
static int get_file_version(int fd, char **v) {
        struct stat st;
        char *buf;
        const char *s, *e;
        char *x = NULL;
        int r = 0;

        assert(fd >= 0);
        assert(v);

        if (fstat(fd, &st) < 0)
                return log_error_errno(errno, "Failed to stat EFI binary: %m");

        r = stat_verify_regular(&st);
        if (r < 0)
                return log_error_errno(r, "EFI binary is not a regular file: %m");

        if (st.st_size < 27) {
                *v = NULL;
                return 0;
        }

        buf = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (buf == MAP_FAILED)
                return log_error_errno(errno, "Failed to memory map EFI binary: %m");

        s = memmem(buf, st.st_size - 8, "#### LoaderInfo: ", 17);
        if (!s)
                goto finish;
        s += 17;

        e = memmem(s, st.st_size - (s - buf), " ####", 5);
        if (!e || e - s < 3) {
                r = log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Malformed version string.");
                goto finish;
        }

        x = strndup(s, e - s);
        if (!x) {
                r = log_oom();
                goto finish;
        }
        r = 1;

finish:
        (void) munmap(buf, st.st_size);
        *v = x;
        return r;
}

static int enumerate_binaries(const char *esp_path, const char *path, const char *prefix) {
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;
        const char *p;
        int c = 0, r;

        assert(esp_path);
        assert(path);

        p = prefix_roota(esp_path, path);
        d = opendir(p);
        if (!d) {
                if (errno == ENOENT)
                        return 0;

                return log_error_errno(errno, "Failed to read \"%s\": %m", p);
        }

        FOREACH_DIRENT(de, d, break) {
                _cleanup_free_ char *v = NULL;
                _cleanup_close_ int fd = -1;

                if (!endswith_no_case(de->d_name, ".efi"))
                        continue;

                if (prefix && !startswith_no_case(de->d_name, prefix))
                        continue;

                fd = openat(dirfd(d), de->d_name, O_RDONLY|O_CLOEXEC);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open \"%s/%s\" for reading: %m", p, de->d_name);

                r = get_file_version(fd, &v);
                if (r < 0)
                        return r;
                if (r > 0)
                        printf("         File: %s/%s/%s (%s%s%s)\n", special_glyph(SPECIAL_GLYPH_TREE_RIGHT), path, de->d_name, ansi_highlight(), v, ansi_normal());
                else
                        printf("         File: %s/%s/%s\n", special_glyph(SPECIAL_GLYPH_TREE_RIGHT), path, de->d_name);

                c++;
        }

        return c;
}

static int status_binaries(const char *esp_path, sd_id128_t partition) {
        int r;

        printf("Available Boot Loaders on ESP:\n");

        if (!esp_path) {
                printf("          ESP: Cannot find or access mount point of ESP.\n\n");
                return -ENOENT;
        }

        printf("          ESP: %s", esp_path);
        if (!sd_id128_is_null(partition))
                printf(" (/dev/disk/by-partuuid/" SD_ID128_UUID_FORMAT_STR ")", SD_ID128_FORMAT_VAL(partition));
        printf("\n");

        r = enumerate_binaries(esp_path, "EFI/systemd", NULL);
        if (r < 0)
                goto finish;
        if (r == 0)
                log_info("systemd-boot not installed in ESP.");

        r = enumerate_binaries(esp_path, "EFI/BOOT", "boot");
        if (r < 0)
                goto finish;
        if (r == 0)
                log_info("No default/fallback boot loader installed in ESP.");

        r = 0;

finish:
        printf("\n");
        return r;
}

static int print_efi_option(uint16_t id, bool in_order) {
        _cleanup_free_ char *title = NULL;
        _cleanup_free_ char *path = NULL;
        sd_id128_t partition;
        bool active;
        int r = 0;

        r = efi_get_boot_option(id, &title, &partition, &path, &active);
        if (r < 0)
                return r;

        /* print only configured entries with partition information */
        if (!path || sd_id128_is_null(partition))
                return 0;

        efi_tilt_backslashes(path);

        printf("        Title: %s%s%s\n", ansi_highlight(), strna(title), ansi_normal());
        printf("           ID: 0x%04X\n", id);
        printf("       Status: %sactive%s\n", active ? "" : "in", in_order ? ", boot-order" : "");
        printf("    Partition: /dev/disk/by-partuuid/" SD_ID128_UUID_FORMAT_STR "\n",
               SD_ID128_FORMAT_VAL(partition));
        printf("         File: %s%s\n", special_glyph(SPECIAL_GLYPH_TREE_RIGHT), path);
        printf("\n");

        return 0;
}

static int status_variables(void) {
        _cleanup_free_ uint16_t *options = NULL, *order = NULL;
        int n_options, n_order, i;

        n_options = efi_get_boot_options(&options);
        if (n_options == -ENOENT)
                return log_error_errno(n_options,
                                       "Failed to access EFI variables, efivarfs"
                                       " needs to be available at /sys/firmware/efi/efivars/.");
        if (n_options < 0)
                return log_error_errno(n_options, "Failed to read EFI boot entries: %m");

        n_order = efi_get_boot_order(&order);
        if (n_order == -ENOENT)
                n_order = 0;
        else if (n_order < 0)
                return log_error_errno(n_order, "Failed to read EFI boot order: %m");

        /* print entries in BootOrder first */
        printf("Boot Loaders Listed in EFI Variables:\n");
        for (i = 0; i < n_order; i++)
                print_efi_option(order[i], true);

        /* print remaining entries */
        for (i = 0; i < n_options; i++) {
                int j;

                for (j = 0; j < n_order; j++)
                        if (options[i] == order[j])
                                goto next_option;

                print_efi_option(options[i], false);

        next_option:
                continue;
        }

        return 0;
}

static int boot_entry_file_check(const char *root, const char *p) {
        _cleanup_free_ char *path;

        path = path_join(root, p);
        if (!path)
                return log_oom();

        if (access(path, F_OK) < 0)
                return -errno;

        return 0;
}

static void boot_entry_file_list(const char *field, const char *root, const char *p, int *ret_status) {
        int status = boot_entry_file_check(root, p);

        printf("%13s%s ", strempty(field), field ? ":" : " ");
        if (status < 0) {
                errno = -status;
                printf("%s%s%s (%m)\n", ansi_highlight_red(), p, ansi_normal());
        } else
                printf("%s\n", p);

        if (*ret_status == 0 && status < 0)
                *ret_status = status;
}

static int boot_entry_show(const BootEntry *e, bool show_as_default) {
        int status = 0;

        /* Returns 0 on success, negative on processing error, and positive if something is wrong with the
           boot entry itself. */

        assert(e);

        printf("        title: %s%s%s" "%s%s%s\n",
               ansi_highlight(), boot_entry_title(e), ansi_normal(),
               ansi_highlight_green(), show_as_default ? " (default)" : "", ansi_normal());

        if (e->id)
                printf("           id: %s\n", e->id);
        if (e->path) {
                _cleanup_free_ char *link = NULL;

                /* Let's urlify the link to make it easy to view in an editor, but only if it is a text
                 * file. Unified images are binary ELFs, and EFI variables are not pure text either. */
                if (e->type == BOOT_ENTRY_CONF)
                        (void) terminal_urlify_path(e->path, NULL, &link);

                printf("       source: %s\n", link ?: e->path);
        }
        if (e->version)
                printf("      version: %s\n", e->version);
        if (e->machine_id)
                printf("   machine-id: %s\n", e->machine_id);
        if (e->architecture)
                printf(" architecture: %s\n", e->architecture);
        if (e->kernel)
                boot_entry_file_list("linux", e->root, e->kernel, &status);

        char **s;
        STRV_FOREACH(s, e->initrd)
                boot_entry_file_list(s == e->initrd ? "initrd" : NULL,
                                     e->root,
                                     *s,
                                     &status);
        if (!strv_isempty(e->options)) {
                _cleanup_free_ char *t = NULL, *t2 = NULL;
                _cleanup_strv_free_ char **ts = NULL;

                t = strv_join(e->options, " ");
                if (!t)
                        return log_oom();

                ts = strv_split_newlines(t);
                if (!ts)
                        return log_oom();

                t2 = strv_join(ts, "\n              ");
                if (!t2)
                        return log_oom();

                printf("      options: %s\n", t2);
        }
        if (e->device_tree)
                boot_entry_file_list("devicetree", e->root, e->device_tree, &status);

        return -status;
}

static int status_entries(
                const char *esp_path,
                sd_id128_t esp_partition_uuid,
                const char *xbootldr_path,
                sd_id128_t xbootldr_partition_uuid) {

        _cleanup_(boot_config_free) BootConfig config = {};
        sd_id128_t dollar_boot_partition_uuid;
        const char *dollar_boot_path;
        int r;

        assert(esp_path || xbootldr_path);

        if (xbootldr_path) {
                dollar_boot_path = xbootldr_path;
                dollar_boot_partition_uuid = xbootldr_partition_uuid;
        } else {
                dollar_boot_path = esp_path;
                dollar_boot_partition_uuid = esp_partition_uuid;
        }

        printf("Boot Loader Entries:\n"
               "        $BOOT: %s", dollar_boot_path);
        if (!sd_id128_is_null(dollar_boot_partition_uuid))
                printf(" (/dev/disk/by-partuuid/" SD_ID128_UUID_FORMAT_STR ")",
                       SD_ID128_FORMAT_VAL(dollar_boot_partition_uuid));
        printf("\n\n");

        r = boot_entries_load_config(esp_path, xbootldr_path, &config);
        if (r < 0)
                return r;

        if (config.default_entry < 0)
                printf("%zu entries, no entry could be determined as default.\n", config.n_entries);
        else {
                printf("Default Boot Loader Entry:\n");

                r = boot_entry_show(config.entries + config.default_entry, false);
                if (r > 0)
                        /* < 0 is already logged by the function itself, let's just emit an extra warning if
                           the default entry is broken */
                        printf("\nWARNING: default boot entry is broken\n");
        }

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

        return strverscmp(a, b);
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
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Source file \"%s\" does not carry version information!",
                                       from);

        r = get_file_version(fd_to, &b);
        if (r < 0)
                return r;
        if (r == 0 || compare_product(a, b) != 0)
                return log_notice_errno(SYNTHETIC_ERRNO(EEXIST),
                                        "Skipping \"%s\", since it's owned by another boot loader.",
                                        to);

        if (compare_version(a, b) < 0)
                return log_warning_errno(SYNTHETIC_ERRNO(ESTALE), "Skipping \"%s\", since a newer boot loader version exists already.", to);

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
                        if (errno != -ENOENT)
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

        RUN_WITH_UMASK(0000) {
                fd_to = open(t, O_WRONLY|O_CREAT|O_CLOEXEC|O_EXCL|O_NOFOLLOW, 0644);
                if (fd_to < 0)
                        return log_error_errno(errno, "Failed to open \"%s\" for writing: %m", t);
        }

        r = copy_bytes(fd_from, fd_to, (uint64_t) -1, COPY_REFLINK);
        if (r < 0) {
                (void) unlink(t);
                return log_error_errno(r, "Failed to copy data from \"%s\" to \"%s\": %m", from, t);
        }

        (void) copy_times(fd_from, fd_to, 0);

        if (fsync(fd_to) < 0) {
                (void) unlink_noerrno(t);
                return log_error_errno(errno, "Failed to copy data from \"%s\" to \"%s\": %m", from, t);
        }

        (void) fsync_directory_of_file(fd_to);

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
        const char *const *i;
        int r;

        STRV_FOREACH(i, subdirs) {
                r = mkdir_one(root, *i);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int copy_one_file(const char *esp_path, const char *name, bool force) {
        const char *e;
        char *p, *q;
        int r;

        p = strjoina(BOOTLIBDIR "/", name);
        q = strjoina(esp_path, "/EFI/systemd/", name);
        r = copy_file_with_version_check(p, q, force);

        e = startswith(name, "systemd-boot");
        if (e) {
                int k;
                char *v;

                /* Create the EFI default boot loader name (specified for removable devices) */
                v = strjoina(esp_path, "/EFI/BOOT/BOOT", e);
                ascii_strupper(strrchr(v, '/') + 1);

                k = copy_file_with_version_check(p, v, force);
                if (k < 0 && r == 0)
                        r = k;
        }

        return r;
}

static int install_binaries(const char *esp_path, bool force) {
        struct dirent *de;
        _cleanup_closedir_ DIR *d = NULL;
        int r = 0;

        d = opendir(BOOTLIBDIR);
        if (!d)
                return log_error_errno(errno, "Failed to open \""BOOTLIBDIR"\": %m");

        FOREACH_DIRENT(de, d, return log_error_errno(errno, "Failed to read \""BOOTLIBDIR"\": %m")) {
                int k;

                if (!endswith_no_case(de->d_name, ".efi"))
                        continue;

                k = copy_one_file(esp_path, de->d_name, force);
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
        if (!streq_ptr(path, opath))
                return false;

        return true;
}

static int find_slot(sd_id128_t uuid, const char *path, uint16_t *id) {
        _cleanup_free_ uint16_t *options = NULL;
        int n, i;

        n = efi_get_boot_options(&options);
        if (n < 0)
                return n;

        /* find already existing systemd-boot entry */
        for (i = 0; i < n; i++)
                if (same_entry(options[i], uuid, path)) {
                        *id = options[i];
                        return 1;
                }

        /* find free slot in the sorted BootXXXX variable list */
        for (i = 0; i < n; i++)
                if (i != options[i]) {
                        *id = i;
                        return 1;
                }

        /* use the next one */
        if (i == 0xffff)
                return -ENOSPC;
        *id = i;
        return 0;
}

static int insert_into_order(uint16_t slot, bool first) {
        _cleanup_free_ uint16_t *order = NULL;
        uint16_t *t;
        int n, i;

        n = efi_get_boot_order(&order);
        if (n <= 0)
                /* no entry, add us */
                return efi_set_boot_order(&slot, 1);

        /* are we the first and only one? */
        if (n == 1 && order[0] == slot)
                return 0;

        /* are we already in the boot order? */
        for (i = 0; i < n; i++) {
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
        int n, i;

        n = efi_get_boot_order(&order);
        if (n <= 0)
                return n;

        for (i = 0; i < n; i++) {
                if (order[i] != slot)
                        continue;

                if (i + 1 < n)
                        memmove(order + i, order + i+1, (n - i) * sizeof(uint16_t));
                return efi_set_boot_order(order, n - 1);
        }

        return 0;
}

static int install_variables(const char *esp_path,
                             uint32_t part, uint64_t pstart, uint64_t psize,
                             sd_id128_t uuid, const char *path,
                             bool first) {
        const char *p;
        uint16_t slot;
        int r;

        if (!is_efi_boot()) {
                log_warning("Not booted with EFI, skipping EFI variable setup.");
                return 0;
        }

        p = prefix_roota(esp_path, path);
        if (access(p, F_OK) < 0) {
                if (errno == ENOENT)
                        return 0;

                return log_error_errno(errno, "Cannot access \"%s\": %m", p);
        }

        r = find_slot(uuid, path, &slot);
        if (r < 0)
                return log_error_errno(r,
                                       r == -ENOENT ?
                                       "Failed to access EFI variables. Is the \"efivarfs\" filesystem mounted?" :
                                       "Failed to determine current boot order: %m");

        if (first || r == 0) {
                r = efi_add_boot_option(slot, "Linux Boot Manager",
                                        part, pstart, psize,
                                        uuid, path);
                if (r < 0)
                        return log_error_errno(r, "Failed to create EFI Boot variable entry: %m");

                log_info("Created EFI boot entry \"Linux Boot Manager\".");
        }

        return insert_into_order(slot, first);
}

static int remove_boot_efi(const char *esp_path) {
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;
        const char *p;
        int r, c = 0;

        p = prefix_roota(esp_path, "/EFI/BOOT");
        d = opendir(p);
        if (!d) {
                if (errno == ENOENT)
                        return 0;

                return log_error_errno(errno, "Failed to open directory \"%s\": %m", p);
        }

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

static int remove_machine_id_directory(const char *root, sd_id128_t machine_id) {
        char buf[SD_ID128_STRING_MAX];

        assert(root);

        return rmdir_one(root, sd_id128_to_string(machine_id, buf));
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

        if (!is_efi_boot())
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
        const char *p;
        int r = 0;

        /* Remove all persistent loader variables we define */

        FOREACH_STRING(p,
                       "LoaderConfigTimeout",
                       "LoaderConfigTimeoutOneShot",
                       "LoaderEntryDefault",
                       "LoaderEntryOneShot",
                       "LoaderSystemToken") {

                int q;

                q = efi_set_variable(EFI_VENDOR_LOADER, p, NULL, 0);
                if (q == -ENOENT)
                        continue;
                if (q < 0) {
                        log_warning_errno(q, "Failed to remove %s variable: %m", p);
                        if (r >= 0)
                                r = q;
                } else
                        log_info("Removed EFI variable %s.", p);
        }

        return r;
}

static int install_loader_config(const char *esp_path, sd_id128_t machine_id) {
        char machine_string[SD_ID128_STRING_MAX];
        _cleanup_(unlink_and_freep) char *t = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        const char *p;
        int r, fd;

        p = prefix_roota(esp_path, "/loader/loader.conf");
        if (access(p, F_OK) >= 0) /* Silently skip creation if the file already exists (early check) */
                return 0;

        fd = open_tmpfile_linkable(p, O_WRONLY|O_CLOEXEC, &t);
        if (fd < 0)
                return log_error_errno(fd, "Failed to open \"%s\" for writing: %m", p);

        f = fdopen(fd, "w");
        if (!f) {
                safe_close(fd);
                return log_oom();
        }

        fprintf(f, "#timeout 3\n"
                   "#console-mode keep\n"
                   "default %s-*\n", sd_id128_to_string(machine_id, machine_string));

        r = fflush_sync_and_check(f);
        if (r < 0)
                return log_error_errno(r, "Failed to write \"%s\": %m", p);

        r = link_tmpfile(fd, t, p);
        if (r == -EEXIST)
                return 0; /* Silently skip creation if the file exists now (recheck) */
        if (r < 0)
                return log_error_errno(r, "Failed to move \"%s\" into place: %m", p);

        t = mfree(t);
        return 1;
}

static int install_machine_id_directory(const char *root, sd_id128_t machine_id) {
        char buf[SD_ID128_STRING_MAX];

        assert(root);

        return mkdir_one(root, sd_id128_to_string(machine_id, buf));
}

static int help(int argc, char *argv[], void *userdata) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("bootctl", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [COMMAND] [OPTIONS...]\n\n"
               "Install, update or remove the systemd-boot EFI boot manager.\n\n"
               "  -h --help            Show this help\n"
               "     --version         Print version\n"
               "     --esp-path=PATH   Path to the EFI System Partition (ESP)\n"
               "     --boot-path=PATH  Path to the $BOOT partition\n"
               "  -p --print-esp-path  Print path to the EFI System Partition\n"
               "  -x --print-boot-path Print path to the $BOOT partition\n"
               "     --no-variables    Don't touch EFI variables\n"
               "     --no-pager        Do not pipe output into a pager\n"
               "\nBoot Loader Commands:\n"
               "     status            Show status of installed systemd-boot and EFI variables\n"
               "     install           Install systemd-boot to the ESP and EFI variables\n"
               "     update            Update systemd-boot in the ESP and EFI variables\n"
               "     remove            Remove systemd-boot from the ESP and EFI variables\n"
               "     random-seed       Initialize random seed in ESP and EFI variables\n"
               "     is-installed      Test whether systemd-boot is installed in the ESP\n"
               "\nBoot Loader Entries Commands:\n"
               "     list              List boot loader entries\n"
               "     set-default ID    Set default boot loader entry\n"
               "     set-oneshot ID    Set default boot loader entry, for next boot only\n"
               "\nSee the %s for details.\n"
               , program_invocation_short_name
               , link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_ESP_PATH = 0x100,
                ARG_BOOT_PATH,
                ARG_VERSION,
                ARG_NO_VARIABLES,
                ARG_NO_PAGER,
        };

        static const struct option options[] = {
                { "help",            no_argument,       NULL, 'h'                 },
                { "version",         no_argument,       NULL, ARG_VERSION         },
                { "esp-path",        required_argument, NULL, ARG_ESP_PATH        },
                { "path",            required_argument, NULL, ARG_ESP_PATH        }, /* Compatibility alias */
                { "boot-path",       required_argument, NULL, ARG_BOOT_PATH       },
                { "print-esp-path",  no_argument,       NULL, 'p'                 },
                { "print-path",      no_argument,       NULL, 'p'                 }, /* Compatibility alias */
                { "print-boot-path", no_argument,       NULL, 'x'                 },
                { "no-variables",    no_argument,       NULL, ARG_NO_VARIABLES    },
                { "no-pager",        no_argument,       NULL, ARG_NO_PAGER        },
                {}
        };

        int c, r;

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

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unknown option");
                }

        return 1;
}

static void read_loader_efi_var(const char *name, char **var) {
        int r;

        r = efi_get_variable_string(EFI_VENDOR_LOADER, name, var);
        if (r < 0 && r != -ENOENT)
                log_warning_errno(r, "Failed to read EFI variable %s: %m", name);
}

static int verb_status(int argc, char *argv[], void *userdata) {
        sd_id128_t esp_uuid = SD_ID128_NULL, xbootldr_uuid = SD_ID128_NULL;
        int r, k;

        r = acquire_esp(geteuid() != 0, NULL, NULL, NULL, &esp_uuid);
        if (arg_print_esp_path) {
                if (r == -EACCES) /* If we couldn't acquire the ESP path, log about access errors (which is the only
                                   * error the find_esp_and_warn() won't log on its own) */
                        return log_error_errno(r, "Failed to determine ESP location: %m");
                if (r < 0)
                        return r;

                puts(arg_esp_path);
        }

        r = acquire_xbootldr(geteuid() != 0, &xbootldr_uuid);
        if (arg_print_dollar_boot_path) {
                if (r == -EACCES)
                        return log_error_errno(r, "Failed to determine XBOOTLDR location: %m");
                if (r < 0)
                        return r;

                const char *path = arg_dollar_boot_path();
                if (!path)
                        return log_error_errno(SYNTHETIC_ERRNO(EACCES), "Failed to determine XBOOTLDR location: %m");

                puts(path);
        }

        if (arg_print_esp_path || arg_print_dollar_boot_path)
                return 0;

        r = 0; /* If we couldn't determine the path, then don't consider that a problem from here on, just show what we
                * can show */

        (void) pager_open(arg_pager_flags);

        if (is_efi_boot()) {
                static const struct {
                        uint64_t flag;
                        const char *name;
                } flags[] = {
                        { EFI_LOADER_FEATURE_BOOT_COUNTING,           "Boot counting"                         },
                        { EFI_LOADER_FEATURE_CONFIG_TIMEOUT,          "Menu timeout control"                  },
                        { EFI_LOADER_FEATURE_CONFIG_TIMEOUT_ONE_SHOT, "One-shot menu timeout control"         },
                        { EFI_LOADER_FEATURE_ENTRY_DEFAULT,           "Default entry control"                 },
                        { EFI_LOADER_FEATURE_ENTRY_ONESHOT,           "One-shot entry control"                },
                        { EFI_LOADER_FEATURE_XBOOTLDR,                "Support for XBOOTLDR partition"        },
                        { EFI_LOADER_FEATURE_RANDOM_SEED,             "Support for passing random seed to OS" },
                };

                _cleanup_free_ char *fw_type = NULL, *fw_info = NULL, *loader = NULL, *loader_path = NULL, *stub = NULL;
                sd_id128_t loader_part_uuid = SD_ID128_NULL;
                uint64_t loader_features = 0;
                size_t i;

                read_loader_efi_var("LoaderFirmwareType", &fw_type);
                read_loader_efi_var("LoaderFirmwareInfo", &fw_info);
                read_loader_efi_var("LoaderInfo", &loader);
                read_loader_efi_var("StubInfo", &stub);
                read_loader_efi_var("LoaderImageIdentifier", &loader_path);
                (void) efi_loader_get_features(&loader_features);

                if (loader_path)
                        efi_tilt_backslashes(loader_path);

                k = efi_loader_get_device_part_uuid(&loader_part_uuid);
                if (k < 0 && k != -ENOENT)
                        r = log_warning_errno(k, "Failed to read EFI variable LoaderDevicePartUUID: %m");

                printf("System:\n");
                printf("     Firmware: %s%s (%s)%s\n", ansi_highlight(), strna(fw_type), strna(fw_info), ansi_normal());
                printf("  Secure Boot: %sd\n", enable_disable(is_efi_secure_boot()));
                printf("   Setup Mode: %s\n", is_efi_secure_boot_setup_mode() ? "setup" : "user");
                printf("\n");

                printf("Current Boot Loader:\n");
                printf("      Product: %s%s%s\n", ansi_highlight(), strna(loader), ansi_normal());

                for (i = 0; i < ELEMENTSOF(flags); i++) {

                        if (i == 0)
                                printf("     Features: ");
                        else
                                printf("               ");

                        if (FLAGS_SET(loader_features, flags[i].flag))
                                printf("%s%s%s %s\n", ansi_highlight_green(), special_glyph(SPECIAL_GLYPH_CHECK_MARK), ansi_normal(), flags[i].name);
                        else
                                printf("%s%s%s %s\n", ansi_highlight_red(), special_glyph(SPECIAL_GLYPH_CROSS_MARK), ansi_normal(), flags[i].name);
                }

                if (stub)
                        printf("         Stub: %s\n", stub);
                if (!sd_id128_is_null(loader_part_uuid))
                        printf("          ESP: /dev/disk/by-partuuid/" SD_ID128_UUID_FORMAT_STR "\n",
                               SD_ID128_FORMAT_VAL(loader_part_uuid));
                else
                        printf("          ESP: n/a\n");
                printf("         File: %s%s\n", special_glyph(SPECIAL_GLYPH_TREE_RIGHT), strna(loader_path));
                printf("\n");

                printf("Random Seed:\n");
                printf(" Passed to OS: %s\n", yes_no(access("/sys/firmware/efi/efivars/LoaderRandomSeed-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f", F_OK) >= 0));
                printf(" System Token: %s\n", access("/sys/firmware/efi/efivars/LoaderSystemToken-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f", F_OK) >= 0 ? "set" : "not set");

                if (arg_esp_path) {
                        _cleanup_free_ char *p = NULL;

                        p = path_join(arg_esp_path, "/loader/random-seed");
                        if (!p)
                                return log_oom();

                        printf("       Exists: %s\n", yes_no(access(p, F_OK) >= 0));
                }

                printf("\n");
        } else
                printf("System:\n    Not booted with EFI\n\n");

        if (arg_esp_path) {
                k = status_binaries(arg_esp_path, esp_uuid);
                if (k < 0)
                        r = k;
        }

        if (is_efi_boot()) {
                k = status_variables();
                if (k < 0)
                        r = k;
        }

        if (arg_esp_path || arg_xbootldr_path) {
                k = status_entries(arg_esp_path, esp_uuid, arg_xbootldr_path, xbootldr_uuid);
                if (k < 0)
                        r = k;
        }

        return r;
}

static int verb_list(int argc, char *argv[], void *userdata) {
        _cleanup_(boot_config_free) BootConfig config = {};
        int r;

        /* If we lack privileges we invoke find_esp_and_warn() in "unprivileged mode" here, which does two things: turn
         * off logging about access errors and turn off potentially privileged device probing. Here we're interested in
         * the latter but not the former, hence request the mode, and log about EACCES. */

        r = acquire_esp(geteuid() != 0, NULL, NULL, NULL, NULL);
        if (r == -EACCES) /* We really need the ESP path for this call, hence also log about access errors */
                return log_error_errno(r, "Failed to determine ESP: %m");
        if (r < 0)
                return r;

        r = acquire_xbootldr(geteuid() != 0, NULL);
        if (r == -EACCES)
                return log_error_errno(r, "Failed to determine XBOOTLDR partition: %m");
        if (r < 0)
                return r;

        r = boot_entries_load_config(arg_esp_path, arg_xbootldr_path, &config);
        if (r < 0)
                return r;

        (void) boot_entries_augment_from_loader(&config, false);

        if (config.n_entries == 0)
                log_info("No boot loader entries found.");
        else {
                size_t n;

                (void) pager_open(arg_pager_flags);

                printf("Boot Loader Entries:\n");

                for (n = 0; n < config.n_entries; n++) {
                        r = boot_entry_show(config.entries + n, n == (size_t) config.default_entry);
                        if (r < 0)
                                return r;

                        if (n+1 < config.n_entries)
                                putchar('\n');
                }
        }

        return 0;
}

static int install_random_seed(const char *esp) {
        _cleanup_(unlink_and_freep) char *tmp = NULL;
        _cleanup_free_ void *buffer = NULL;
        _cleanup_free_ char *path = NULL;
        _cleanup_close_ int fd = -1;
        size_t sz, token_size;
        ssize_t n;
        int r;

        assert(esp);

        path = path_join(esp, "/loader/random-seed");
        if (!path)
                return log_oom();

        sz = random_pool_size();

        buffer = malloc(sz);
        if (!buffer)
                return log_oom();

        r = genuine_random_bytes(buffer, sz, RANDOM_BLOCK);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire random seed: %m");

        r = tempfn_random(path, "bootctl", &tmp);
        if (r < 0)
                return log_oom();

        fd = open(tmp, O_CREAT|O_EXCL|O_NOFOLLOW|O_NOCTTY|O_WRONLY|O_CLOEXEC, 0600);
        if (fd < 0) {
                tmp = mfree(tmp);
                return log_error_errno(fd, "Failed to open random seed file for writing: %m");
        }

        n = write(fd, buffer, sz);
        if (n < 0)
                return log_error_errno(errno, "Failed to write random seed file: %m");
        if ((size_t) n != sz)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Short write while writing random seed file.");

        if (rename(tmp, path) < 0)
                return log_error_errno(r, "Failed to move random seed file into place: %m");

        tmp = mfree(tmp);

        log_info("Random seed file %s successfully written (%zu bytes).", path, sz);

        if (!arg_touch_variables)
                return 0;

        if (!is_efi_boot()) {
                log_notice("Not booted with EFI, skipping EFI variable setup.");
                return 0;
        }

        r = getenv_bool("SYSTEMD_WRITE_SYSTEM_TOKEN");
        if (r < 0) {
                if (r != -ENXIO)
                         log_warning_errno(r, "Failed to parse $SYSTEMD_WRITE_SYSTEM_TOKEN, ignoring.");

                if (detect_vm() > 0) {
                        /* Let's not write a system token if we detect we are running in a VM
                         * environment. Why? Our default security model for the random seed uses the system
                         * token as a mechanism to ensure we are not vulnerable to golden master sloppiness
                         * issues, i.e. that people initialize the random seed file, then copy the image to
                         * many systems and end up with the same random seed in each that is assumed to be
                         * valid but in reality is the same for all machines. By storing a system token in
                         * the EFI variable space we can make sure that even though the random seeds on disk
                         * are all the same they will be different on each system under the assumption that
                         * the EFI variable space is maintained separate from the random seed storage. That
                         * is generally the case on physical systems, as the ESP is stored on persistant
                         * storage, and the EFI variables in NVRAM. However in virtualized environments this
                         * is generally not true: the EFI variable set is typically stored along with the
                         * disk image itself. For example, using the OVMF EFI firmware the EFI variables are
                         * stored in a file in the ESP itself. */

                        log_notice("Not installing system token, since we are running in a virtualized environment.");
                        return 0;
                }
        } else if (r == 0) {
                log_notice("Not writing system token, because $SYSTEMD_WRITE_SYSTEM_TOKEN is set to false.");
                return 0;
        }

        r = efi_get_variable(EFI_VENDOR_LOADER, "LoaderSystemToken", NULL, NULL, &token_size);
        if (r < 0) {
                if (r != -ENOENT)
                        return log_error_errno(r, "Failed to test system token validity: %m");
        } else {
                if (token_size >= sz) {
                        /* Let's avoid writes if we can, and initialize this only once. */
                        log_debug("System token already written, not updating.");
                        return 0;
                }

                log_debug("Existing system token size (%zu) does not match our expectations (%zu), replacing.", token_size, sz);
        }

        r = genuine_random_bytes(buffer, sz, RANDOM_BLOCK);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire random seed: %m");

        /* Let's write this variable with an umask in effect, so that unprivileged users can't see the token
         * and possibly get identification information or too much insight into the kernel's entropy pool
         * state. */
        RUN_WITH_UMASK(0077) {
                r = efi_set_variable(EFI_VENDOR_LOADER, "LoaderSystemToken", buffer, sz);
                if (r < 0)
                        return log_error_errno(r, "Failed to set LoaderSystemToken EFI variable: %m");
        }

        log_info("Successfully initialized system token in EFI variable with %zu bytes.", sz);
        return 0;
}

static int sync_everything(void) {
        int ret = 0, k;

        if (arg_esp_path) {
                k = syncfs_path(AT_FDCWD, arg_esp_path);
                if (k < 0)
                        ret = log_error_errno(k, "Failed to synchronize the ESP '%s': %m", arg_esp_path);
        }

        if (arg_xbootldr_path) {
                k = syncfs_path(AT_FDCWD, arg_xbootldr_path);
                if (k < 0)
                        ret = log_error_errno(k, "Failed to synchronize $BOOT '%s': %m", arg_xbootldr_path);
        }

        return ret;
}

static int verb_install(int argc, char *argv[], void *userdata) {
        sd_id128_t uuid = SD_ID128_NULL;
        uint64_t pstart = 0, psize = 0;
        uint32_t part = 0;
        sd_id128_t machine_id;
        bool install;
        int r;

        r = acquire_esp(false, &part, &pstart, &psize, &uuid);
        if (r < 0)
                return r;

        r = acquire_xbootldr(false, NULL);
        if (r < 0)
                return r;

        r = sd_id128_get_machine(&machine_id);
        if (r < 0)
                return log_error_errno(r, "Failed to get machine id: %m");

        install = streq(argv[0], "install");

        RUN_WITH_UMASK(0002) {
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

                r = install_binaries(arg_esp_path, install);
                if (r < 0)
                        return r;

                if (install) {
                        r = install_loader_config(arg_esp_path, machine_id);
                        if (r < 0)
                                return r;

                        r = install_machine_id_directory(arg_dollar_boot_path(), machine_id);
                        if (r < 0)
                                return r;

                        r = install_random_seed(arg_esp_path);
                        if (r < 0)
                                return r;
                }
        }

        (void) sync_everything();

        if (arg_touch_variables)
                r = install_variables(arg_esp_path,
                                      part, pstart, psize, uuid,
                                      "/EFI/systemd/systemd-boot" EFI_MACHINE_TYPE_NAME ".efi",
                                      install);

        return r;
}

static int verb_remove(int argc, char *argv[], void *userdata) {
        sd_id128_t uuid = SD_ID128_NULL, machine_id;
        int r, q;

        r = acquire_esp(false, NULL, NULL, NULL, &uuid);
        if (r < 0)
                return r;

        r = acquire_xbootldr(false, NULL);
        if (r < 0)
                return r;

        r = sd_id128_get_machine(&machine_id);
        if (r < 0)
                return log_error_errno(r, "Failed to get machine id: %m");

        r = remove_binaries(arg_esp_path);

        q = remove_file(arg_esp_path, "/loader/loader.conf");
        if (q < 0 && r >= 0)
                r = q;

        q = remove_file(arg_esp_path, "/loader/random-seed");
        if (q < 0 && r >= 0)
                r = q;

        q = remove_subdirs(arg_esp_path, esp_subdirs);
        if (q < 0 && r >= 0)
                r = q;

        q = remove_subdirs(arg_esp_path, dollar_boot_subdirs);
        if (q < 0 && r >= 0)
                r = q;

        q = remove_machine_id_directory(arg_esp_path, machine_id);
        if (q < 0 && r >= 0)
                r = 1;

        if (arg_xbootldr_path) {
                /* Remove the latter two also in the XBOOTLDR partition if it exists */
                q = remove_subdirs(arg_xbootldr_path, dollar_boot_subdirs);
                if (q < 0 && r >= 0)
                        r = q;

                q = remove_machine_id_directory(arg_xbootldr_path, machine_id);
                if (q < 0 && r >= 0)
                        r = q;
        }

        (void) sync_everything();

        if (!arg_touch_variables)
                return r;

        q = remove_variables(uuid, "/EFI/systemd/systemd-boot" EFI_MACHINE_TYPE_NAME ".efi", true);
        if (q < 0 && r >= 0)
                r = q;

        q = remove_loader_variables();
        if (q < 0 && r >= 0)
                r = q;

        return r;
}

static int verb_is_installed(int argc, char *argv[], void *userdata) {
        _cleanup_free_ char *p = NULL;
        int r;

        r = acquire_esp(false, NULL, NULL, NULL, NULL);
        if (r < 0)
                return r;

        /* Tests whether systemd-boot is installed. It's not obvious what to use as check here: we could
         * check EFI variables, we could check what binary /EFI/BOOT/BOOT*.EFI points to, or whether the
         * loader entries directory exists. Here we opted to check whether /EFI/systemd/ is non-empty, which
         * should be a suitable and very minimal check for a number of reasons:
         *
         *  → The check is architecture independent (i.e. we check if any systemd-boot loader is installed, not a
         *    specific one.)
         *
         *  → It doesn't assume we are the only boot loader (i.e doesn't check if we own the main
         *    /EFI/BOOT/BOOT*.EFI fallback binary.
         *
         *  → It specifically checks for systemd-boot, not for other boot loaders (which a check for
         *    /boot/loader/entries would do). */

        p = path_join(arg_esp_path, "/EFI/systemd/");
        if (!p)
                return log_oom();

        r = dir_is_empty(p);
        if (r > 0 || r == -ENOENT) {
                puts("no");
                return EXIT_FAILURE;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to detect whether systemd-boot is installed: %m");

        puts("yes");
        return EXIT_SUCCESS;
}

static int verb_set_default(int argc, char *argv[], void *userdata) {
        const char *name;
        int r;

        if (!is_efi_boot())
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Not booted with UEFI.");

        if (access("/sys/firmware/efi/efivars/LoaderInfo-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f", F_OK) < 0) {
                if (errno == ENOENT) {
                        log_error_errno(errno, "Not booted with a supported boot loader.");
                        return -EOPNOTSUPP;
                }

                return log_error_errno(errno, "Failed to detect whether boot loader supports '%s' operation: %m", argv[0]);
        }

        if (detect_container() > 0)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "'%s' operation not supported in a container.",
                                       argv[0]);

        if (!arg_touch_variables)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "'%s' operation cannot be combined with --touch-variables=no.",
                                       argv[0]);

        name = streq(argv[0], "set-default") ? "LoaderEntryDefault" : "LoaderEntryOneShot";

        if (isempty(argv[1])) {
                r = efi_set_variable(EFI_VENDOR_LOADER, name, NULL, 0);
                if (r < 0 && r != -ENOENT)
                        return log_error_errno(r, "Failed to remove EFI variale: %m");
        } else {
                _cleanup_free_ char16_t *encoded = NULL;

                encoded = utf8_to_utf16(argv[1], strlen(argv[1]));
                if (!encoded)
                        return log_oom();

                r = efi_set_variable(EFI_VENDOR_LOADER, name, encoded, char16_strlen(encoded) * 2 + 2);
                if (r < 0)
                        return log_error_errno(r, "Failed to update EFI variable: %m");
        }

        return 0;
}

static int verb_random_seed(int argc, char *argv[], void *userdata) {
        int r;

        r = acquire_esp(false, NULL, NULL, NULL, NULL);
        if (r < 0)
                return r;

        r = install_random_seed(arg_esp_path);
        if (r < 0)
                return r;

        (void) sync_everything();
        return 0;
}

static int bootctl_main(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "help",         VERB_ANY, VERB_ANY, 0,            help              },
                { "status",       VERB_ANY, 1,        VERB_DEFAULT, verb_status       },
                { "install",      VERB_ANY, 1,        0,            verb_install      },
                { "update",       VERB_ANY, 1,        0,            verb_install      },
                { "remove",       VERB_ANY, 1,        0,            verb_remove       },
                { "random-seed",  VERB_ANY, 1,        0,            verb_random_seed  },
                { "is-installed", VERB_ANY, 1,        0,            verb_is_installed },
                { "list",         VERB_ANY, 1,        0,            verb_list         },
                { "set-default",  2,        2,        0,            verb_set_default  },
                { "set-oneshot",  2,        2,        0,            verb_set_default  },
                {}
        };

        return dispatch_verb(argc, argv, verbs, NULL);
}

static int run(int argc, char *argv[]) {
        int r;

        log_parse_environment();
        log_open();

        /* If we run in a container, automatically turn off EFI file system access */
        if (detect_container() > 0)
                arg_touch_variables = false;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        return bootctl_main(argc, argv);
}

DEFINE_MAIN_FUNCTION(run);
