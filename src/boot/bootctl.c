/***
  This file is part of systemd.

  Copyright 2013-2015 Kay Sievers
  Copyright 2013 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <assert.h>
#include <blkid/blkid.h>
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

#include "alloc-util.h"
#include "blkid-util.h"
#include "dirent-util.h"
#include "efivars.h"
#include "fd-util.h"
#include "fileio.h"
#include "locale-util.h"
#include "parse-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "strv.h"
#include "umask-util.h"
#include "util.h"
#include "verbs.h"
#include "virt.h"
#include "stat-util.h"

static char *arg_path = NULL;
static bool arg_touch_variables = true;

static int verify_esp(
                bool searching,
                const char *p,
                uint32_t *ret_part,
                uint64_t *ret_pstart,
                uint64_t *ret_psize,
                sd_id128_t *ret_uuid) {

        _cleanup_blkid_free_probe_ blkid_probe b = NULL;
        _cleanup_free_ char *t = NULL;
        uint64_t pstart = 0, psize = 0;
        struct stat st, st2;
        const char *v, *t2;
        struct statfs sfs;
        sd_id128_t uuid = SD_ID128_NULL;
        uint32_t part = 0;
        int r;

        assert(p);

        if (statfs(p, &sfs) < 0) {

                /* If we are searching for the mount point, don't generate a log message if we can't find the path */
                if (errno == ENOENT && searching)
                        return -ENOENT;

                return log_error_errno(errno, "Failed to check file system type of \"%s\": %m", p);
        }

        if (!F_TYPE_EQUAL(sfs.f_type, MSDOS_SUPER_MAGIC)) {

                if (searching)
                        return -EADDRNOTAVAIL;

                log_error("File system \"%s\" is not a FAT EFI System Partition (ESP) file system.", p);
                return -ENODEV;
        }

        if (stat(p, &st) < 0)
                return log_error_errno(errno, "Failed to determine block device node of \"%s\": %m", p);

        if (major(st.st_dev) == 0) {
                log_error("Block device node of %p is invalid.", p);
                return -ENODEV;
        }

        t2 = strjoina(p, "/..");
        r = stat(t2, &st2);
        if (r < 0)
                return log_error_errno(errno, "Failed to determine block device node of parent of \"%s\": %m", p);

        if (st.st_dev == st2.st_dev) {
                log_error("Directory \"%s\" is not the root of the EFI System Partition (ESP) file system.", p);
                return -ENODEV;
        }

        /* In a container we don't have access to block devices, skip this part of the verification, we trust the
         * container manager set everything up correctly on its own. */
        if (detect_container() > 0)
                goto finish;

        r = asprintf(&t, "/dev/block/%u:%u", major(st.st_dev), minor(st.st_dev));
        if (r < 0)
                return log_oom();

        errno = 0;
        b = blkid_new_probe_from_filename(t);
        if (!b) {
                if (errno == 0)
                        return log_oom();

                return log_error_errno(errno, "Failed to open file system \"%s\": %m", p);
        }

        blkid_probe_enable_superblocks(b, 1);
        blkid_probe_set_superblocks_flags(b, BLKID_SUBLKS_TYPE);
        blkid_probe_enable_partitions(b, 1);
        blkid_probe_set_partitions_flags(b, BLKID_PARTS_ENTRY_DETAILS);

        errno = 0;
        r = blkid_do_safeprobe(b);
        if (r == -2) {
                log_error("File system \"%s\" is ambiguous.", p);
                return -ENODEV;
        } else if (r == 1) {
                log_error("File system \"%s\" does not contain a label.", p);
                return -ENODEV;
        } else if (r != 0) {
                r = errno ? -errno : -EIO;
                return log_error_errno(r, "Failed to probe file system \"%s\": %m", p);
        }

        errno = 0;
        r = blkid_probe_lookup_value(b, "TYPE", &v, NULL);
        if (r != 0) {
                r = errno ? -errno : -EIO;
                return log_error_errno(r, "Failed to probe file system type \"%s\": %m", p);
        }
        if (!streq(v, "vfat")) {
                log_error("File system \"%s\" is not FAT.", p);
                return -ENODEV;
        }

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_SCHEME", &v, NULL);
        if (r != 0) {
                r = errno ? -errno : -EIO;
                return log_error_errno(r, "Failed to probe partition scheme \"%s\": %m", p);
        }
        if (!streq(v, "gpt")) {
                log_error("File system \"%s\" is not on a GPT partition table.", p);
                return -ENODEV;
        }

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_TYPE", &v, NULL);
        if (r != 0) {
                r = errno ? -errno : -EIO;
                return log_error_errno(r, "Failed to probe partition type UUID \"%s\": %m", p);
        }
        if (!streq(v, "c12a7328-f81f-11d2-ba4b-00a0c93ec93b")) {
                log_error("File system \"%s\" has wrong type for an EFI System Partition (ESP).", p);
                return -ENODEV;
        }

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_UUID", &v, NULL);
        if (r != 0) {
                r = errno ? -errno : -EIO;
                return log_error_errno(r, "Failed to probe partition entry UUID \"%s\": %m", p);
        }
        r = sd_id128_from_string(v, &uuid);
        if (r < 0) {
                log_error("Partition \"%s\" has invalid UUID \"%s\".", p, v);
                return -EIO;
        }

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_NUMBER", &v, NULL);
        if (r != 0) {
                r = errno ? -errno : -EIO;
                return log_error_errno(r, "Failed to probe partition number \"%s\": m", p);
        }
        r = safe_atou32(v, &part);
        if (r < 0)
                return log_error_errno(r, "Failed to parse PART_ENTRY_NUMBER field.");

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_OFFSET", &v, NULL);
        if (r != 0) {
                r = errno ? -errno : -EIO;
                return log_error_errno(r, "Failed to probe partition offset \"%s\": %m", p);
        }
        r = safe_atou64(v, &pstart);
        if (r < 0)
                return log_error_errno(r, "Failed to parse PART_ENTRY_OFFSET field.");

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_SIZE", &v, NULL);
        if (r != 0) {
                r = errno ? -errno : -EIO;
                return log_error_errno(r, "Failed to probe partition size \"%s\": %m", p);
        }
        r = safe_atou64(v, &psize);
        if (r < 0)
                return log_error_errno(r, "Failed to parse PART_ENTRY_SIZE field.");

finish:
        if (ret_part)
                *ret_part = part;
        if (ret_pstart)
                *ret_pstart = pstart;
        if (ret_psize)
                *ret_psize = psize;
        if (ret_uuid)
                *ret_uuid = uuid;

        return 0;
}

static int find_esp(uint32_t *part, uint64_t *pstart, uint64_t *psize, sd_id128_t *uuid) {
        const char *path;
        int r;

        if (arg_path)
                return verify_esp(false, arg_path, part, pstart, psize, uuid);

        FOREACH_STRING(path, "/efi", "/boot", "/boot/efi") {

                r = verify_esp(true, path, part, pstart, psize, uuid);
                if (IN_SET(r, -ENOENT, -EADDRNOTAVAIL)) /* This one is not it */
                        continue;
                if (r < 0)
                        return r;

                arg_path = strdup(path);
                if (!arg_path)
                        return log_oom();

                log_info("Using EFI System Parition at %s.", path);
                return 0;
        }

        log_error("Couldn't find EFI system partition. It is recommended to mount it to /boot. Alternatively, use --path= to specify path to mount point.");
        return -ENOENT;
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
                log_error("Malformed version string.");
                r = -EINVAL;
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
        char *p;
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;
        int r = 0, c = 0;

        p = strjoina(esp_path, "/", path);
        d = opendir(p);
        if (!d) {
                if (errno == ENOENT)
                        return 0;

                return log_error_errno(errno, "Failed to read \"%s\": %m", p);
        }

        FOREACH_DIRENT(de, d, break) {
                _cleanup_close_ int fd = -1;
                _cleanup_free_ char *v = NULL;

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
                        printf("         File: %s/%s/%s (%s)\n", special_glyph(TREE_RIGHT), path, de->d_name, v);
                else
                        printf("         File: %s/%s/%s\n", special_glyph(TREE_RIGHT), path, de->d_name);
                c++;
        }

        return c;
}

static int status_binaries(const char *esp_path, sd_id128_t partition) {
        int r;

        printf("Boot Loader Binaries:\n");

        printf("          ESP: /dev/disk/by-partuuid/%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n", SD_ID128_FORMAT_VAL(partition));

        r = enumerate_binaries(esp_path, "EFI/systemd", NULL);
        if (r == 0)
                log_error("systemd-boot not installed in ESP.");
        else if (r < 0)
                return r;

        r = enumerate_binaries(esp_path, "EFI/BOOT", "boot");
        if (r == 0)
                log_error("No default/fallback boot loader installed in ESP.");
        else if (r < 0)
                return r;

        printf("\n");

        return 0;
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
        if (!path || sd_id128_equal(partition, SD_ID128_NULL))
                return 0;

        efi_tilt_backslashes(path);

        printf("        Title: %s\n", strna(title));
        printf("           ID: 0x%04X\n", id);
        printf("       Status: %sactive%s\n", active ? "" : "in", in_order ? ", boot-order" : "");
        printf("    Partition: /dev/disk/by-partuuid/%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n", SD_ID128_FORMAT_VAL(partition));
        printf("         File: %s%s\n", special_glyph(TREE_RIGHT), path);
        printf("\n");

        return 0;
}

static int status_variables(void) {
        int n_options, n_order;
        _cleanup_free_ uint16_t *options = NULL, *order = NULL;
        int i;

        if (!is_efi_boot()) {
                log_notice("Not booted with EFI, not showing EFI variables.");
                return 0;
        }

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
                return log_error_errno(n_order, "Failed to read EFI boot order.");

        /* print entries in BootOrder first */
        printf("Boot Loader Entries in EFI Variables:\n");
        for (i = 0; i < n_order; i++)
                print_efi_option(order[i], true);

        /* print remaining entries */
        for (i = 0; i < n_options; i++) {
                int j;

                for (j = 0; j < n_order; j++)
                        if (options[i] == order[j])
                                continue;

                print_efi_option(options[i], false);
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

static int version_check(int fd, const char *from, const char *to) {
        _cleanup_free_ char *a = NULL, *b = NULL;
        _cleanup_close_ int fd2 = -1;
        int r;

        assert(fd >= 0);
        assert(from);
        assert(to);

        r = get_file_version(fd, &a);
        if (r < 0)
                return r;
        if (r == 0) {
                log_error("Source file \"%s\" does not carry version information!", from);
                return -EINVAL;
        }

        fd2 = open(to, O_RDONLY|O_CLOEXEC);
        if (fd2 < 0) {
                if (errno == ENOENT)
                        return 0;

                return log_error_errno(errno, "Failed to open \"%s\" for reading: %m", to);
        }

        r = get_file_version(fd2, &b);
        if (r < 0)
                return r;
        if (r == 0 || compare_product(a, b) != 0) {
                log_notice("Skipping \"%s\", since it's owned by another boot loader.", to);
                return -EEXIST;
        }

        if (compare_version(a, b) < 0) {
                log_warning("Skipping \"%s\", since a newer boot loader version exists already.", to);
                return -ESTALE;
        }

        return 0;
}

static int copy_file(const char *from, const char *to, bool force) {
        _cleanup_fclose_ FILE *f = NULL, *g = NULL;
        char *p;
        int r;
        struct timespec t[2];
        struct stat st;

        assert(from);
        assert(to);

        f = fopen(from, "re");
        if (!f)
                return log_error_errno(errno, "Failed to open \"%s\" for reading: %m", from);

        if (!force) {
                /* If this is an update, then let's compare versions first */
                r = version_check(fileno(f), from, to);
                if (r < 0)
                        return r;
        }

        p = strjoina(to, "~");
        g = fopen(p, "wxe");
        if (!g) {
                /* Directory doesn't exist yet? Then let's skip this... */
                if (!force && errno == ENOENT)
                        return 0;

                return log_error_errno(errno, "Failed to open \"%s\" for writing: %m", to);
        }

        rewind(f);
        do {
                size_t k;
                uint8_t buf[32*1024];

                k = fread(buf, 1, sizeof(buf), f);
                if (ferror(f)) {
                        r = log_error_errno(EIO, "Failed to read \"%s\": %m", from);
                        goto error;
                }

                if (k == 0)
                        break;

                fwrite(buf, 1, k, g);
                if (ferror(g)) {
                        r = log_error_errno(EIO, "Failed to write \"%s\": %m", to);
                        goto error;
                }
        } while (!feof(f));

        r = fflush_and_check(g);
        if (r < 0) {
                log_error_errno(r, "Failed to write \"%s\": %m", to);
                goto error;
        }

        r = fstat(fileno(f), &st);
        if (r < 0) {
                r = log_error_errno(errno, "Failed to get file timestamps of \"%s\": %m", from);
                goto error;
        }

        t[0] = st.st_atim;
        t[1] = st.st_mtim;

        r = futimens(fileno(g), t);
        if (r < 0) {
                r = log_error_errno(errno, "Failed to set file timestamps on \"%s\": %m", p);
                goto error;
        }

        if (rename(p, to) < 0) {
                r = log_error_errno(errno, "Failed to rename \"%s\" to \"%s\": %m", p, to);
                goto error;
        }

        log_info("Copied \"%s\" to \"%s\".", from, to);
        return 0;

error:
        (void) unlink(p);
        return r;
}

static int mkdir_one(const char *prefix, const char *suffix) {
        char *p;

        p = strjoina(prefix, "/", suffix);
        if (mkdir(p, 0700) < 0) {
                if (errno != EEXIST)
                        return log_error_errno(errno, "Failed to create \"%s\": %m", p);
        } else
                log_info("Created \"%s\".", p);

        return 0;
}

static const char *efi_subdirs[] = {
        "EFI",
        "EFI/systemd",
        "EFI/BOOT",
        "loader",
        "loader/entries"
};

static int create_dirs(const char *esp_path) {
        const char **i;
        int r;

        STRV_FOREACH(i, efi_subdirs) {
                r = mkdir_one(esp_path, *i);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int copy_one_file(const char *esp_path, const char *name, bool force) {
        char *p, *q;
        int r;

        p = strjoina(BOOTLIBDIR "/", name);
        q = strjoina(esp_path, "/EFI/systemd/", name);
        r = copy_file(p, q, force);

        if (startswith(name, "systemd-boot")) {
                int k;
                char *v;

                /* Create the EFI default boot loader name (specified for removable devices) */
                v = strjoina(esp_path, "/EFI/BOOT/BOOT", name + strlen("systemd-boot"));
                ascii_strupper(strrchr(v, '/') + 1);

                k = copy_file(p, v, force);
                if (k < 0 && r == 0)
                        r = k;
        }

        return r;
}

static int install_binaries(const char *esp_path, bool force) {
        struct dirent *de;
        _cleanup_closedir_ DIR *d = NULL;
        int r = 0;

        if (force) {
                /* Don't create any of these directories when we are
                 * just updating. When we update we'll drop-in our
                 * files (unless there are newer ones already), but we
                 * won't create the directories for them in the first
                 * place. */
                r = create_dirs(esp_path);
                if (r < 0)
                        return r;
        }

        d = opendir(BOOTLIBDIR);
        if (!d)
                return log_error_errno(errno, "Failed to open \""BOOTLIBDIR"\": %m");

        FOREACH_DIRENT(de, d, break) {
                int k;

                if (!endswith_no_case(de->d_name, ".efi"))
                        continue;

                k = copy_one_file(esp_path, de->d_name, force);
                if (k < 0 && r == 0)
                        r = k;
        }

        return r;
}

static bool same_entry(uint16_t id, const sd_id128_t uuid, const char *path) {
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
        t = realloc(order, (n + 1) * sizeof(uint16_t));
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
        char *p;
        uint16_t slot;
        int r;

        if (!is_efi_boot()) {
                log_warning("Not booted with EFI, skipping EFI variable setup.");
                return 0;
        }

        p = strjoina(esp_path, path);
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
        char *p;
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;
        int r, c = 0;

        p = strjoina(esp_path, "/EFI/BOOT");
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
        char *p;

        p = strjoina(prefix, "/", suffix);
        if (rmdir(p) < 0) {
                if (!IN_SET(errno, ENOENT, ENOTEMPTY))
                        return log_error_errno(errno, "Failed to remove \"%s\": %m", p);
        } else
                log_info("Removed \"%s\".", p);

        return 0;
}

static int remove_binaries(const char *esp_path) {
        char *p;
        int r, q;
        unsigned i;

        p = strjoina(esp_path, "/EFI/systemd");
        r = rm_rf(p, REMOVE_ROOT|REMOVE_PHYSICAL);

        q = remove_boot_efi(esp_path);
        if (q < 0 && r == 0)
                r = q;

        for (i = ELEMENTSOF(efi_subdirs); i > 0; i--) {
                q = rmdir_one(esp_path, efi_subdirs[i-1]);
                if (q < 0 && r == 0)
                        r = q;
        }

        return r;
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

static int install_loader_config(const char *esp_path) {

        _cleanup_fclose_ FILE *f = NULL;
        char machine_string[SD_ID128_STRING_MAX];
        sd_id128_t machine_id;
        const char *p;
        int r;

        r = sd_id128_get_machine(&machine_id);
        if (r < 0)
                return log_error_errno(r, "Failed to get machine did: %m");

        p = strjoina(esp_path, "/loader/loader.conf");
        f = fopen(p, "wxe");
        if (!f)
                return log_error_errno(errno, "Failed to open loader.conf for writing: %m");

        fprintf(f, "#timeout 3\n");
        fprintf(f, "default %s-*\n", sd_id128_to_string(machine_id, machine_string));

        r = fflush_and_check(f);
        if (r < 0)
                return log_error_errno(r, "Failed to write \"%s\": %m", p);

        return 0;
}

static int help(int argc, char *argv[], void *userdata) {

        printf("%s [COMMAND] [OPTIONS...]\n"
               "\n"
               "Install, update or remove the systemd-boot EFI boot manager.\n\n"
               "  -h --help          Show this help\n"
               "     --version       Print version\n"
               "     --path=PATH     Path to the EFI System Partition (ESP)\n"
               "     --no-variables  Don't touch EFI variables\n"
               "\n"
               "Commands:\n"
               "     status          Show status of installed systemd-boot and EFI variables\n"
               "     install         Install systemd-boot to the ESP and EFI variables\n"
               "     update          Update systemd-boot in the ESP and EFI variables\n"
               "     remove          Remove systemd-boot from the ESP and EFI variables\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_PATH = 0x100,
                ARG_VERSION,
                ARG_NO_VARIABLES,
        };

        static const struct option options[] = {
                { "help",         no_argument,       NULL, 'h'              },
                { "version",      no_argument,       NULL, ARG_VERSION      },
                { "path",         required_argument, NULL, ARG_PATH         },
                { "no-variables", no_argument,       NULL, ARG_NO_VARIABLES },
                { NULL,           0,                 NULL, 0                }
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        help(0, NULL, NULL);
                        return 0;

                case ARG_VERSION:
                        return version();

                case ARG_PATH:
                        r = free_and_strdup(&arg_path, optarg);
                        if (r < 0)
                                return log_oom();
                        break;

                case ARG_NO_VARIABLES:
                        arg_touch_variables = false;
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

static int must_be_root(void) {

        if (geteuid() == 0)
                return 0;

        log_error("Need to be root.");
        return -EPERM;
}

static int verb_status(int argc, char *argv[], void *userdata) {

        sd_id128_t uuid = SD_ID128_NULL;
        int r;

        r = must_be_root();
        if (r < 0)
                return r;

        r = find_esp(NULL, NULL, NULL, &uuid);
        if (r < 0)
                return r;

        if (is_efi_boot()) {
                _cleanup_free_ char *fw_type = NULL, *fw_info = NULL, *loader = NULL, *loader_path = NULL;
                sd_id128_t loader_part_uuid = SD_ID128_NULL;

                read_loader_efi_var("LoaderFirmwareType", &fw_type);
                read_loader_efi_var("LoaderFirmwareInfo", &fw_info);
                read_loader_efi_var("LoaderInfo", &loader);
                read_loader_efi_var("LoaderImageIdentifier", &loader_path);

                if (loader_path)
                        efi_tilt_backslashes(loader_path);

                r = efi_loader_get_device_part_uuid(&loader_part_uuid);
                if (r < 0 && r != -ENOENT)
                        log_warning_errno(r, "Failed to read EFI variable LoaderDevicePartUUID: %m");

                printf("System:\n");
                printf("     Firmware: %s (%s)\n", strna(fw_type), strna(fw_info));

                r = is_efi_secure_boot();
                if (r < 0)
                        log_warning_errno(r, "Failed to query secure boot status: %m");
                else
                        printf("  Secure Boot: %s\n", r ? "enabled" : "disabled");

                r = is_efi_secure_boot_setup_mode();
                if (r < 0)
                        log_warning_errno(r, "Failed to query secure boot mode: %m");
                else
                        printf("   Setup Mode: %s\n", r ? "setup" : "user");
                printf("\n");

                printf("Loader:\n");
                printf("      Product: %s\n", strna(loader));
                if (!sd_id128_equal(loader_part_uuid, SD_ID128_NULL))
                        printf("    Partition: /dev/disk/by-partuuid/%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n",
                               SD_ID128_FORMAT_VAL(loader_part_uuid));
                else
                        printf("    Partition: n/a\n");
                printf("         File: %s%s\n", special_glyph(TREE_RIGHT), strna(loader_path));
                printf("\n");
        } else
                printf("System:\n    Not booted with EFI\n");

        r = status_binaries(arg_path, uuid);
        if (r < 0)
                return r;

        if (arg_touch_variables)
                r = status_variables();

        return r;
}

static int verb_install(int argc, char *argv[], void *userdata) {

        sd_id128_t uuid = SD_ID128_NULL;
        uint64_t pstart = 0, psize = 0;
        uint32_t part = 0;
        bool install;
        int r;

        r = must_be_root();
        if (r < 0)
                return r;

        r = find_esp(&part, &pstart, &psize, &uuid);
        if (r < 0)
                return r;

        install = streq(argv[0], "install");

        RUN_WITH_UMASK(0002) {
                r = install_binaries(arg_path, install);
                if (r < 0)
                        return r;

                if (install) {
                        r = install_loader_config(arg_path);
                        if (r < 0)
                                return r;
                }
        }

        if (arg_touch_variables)
                r = install_variables(arg_path,
                                      part, pstart, psize, uuid,
                                      "/EFI/systemd/systemd-boot" EFI_MACHINE_TYPE_NAME ".efi",
                                      install);

        return r;
}

static int verb_remove(int argc, char *argv[], void *userdata) {
        sd_id128_t uuid = SD_ID128_NULL;
        int r;

        r = must_be_root();
        if (r < 0)
                return r;

        r = find_esp(NULL, NULL, NULL, &uuid);
        if (r < 0)
                return r;

        r = remove_binaries(arg_path);

        if (arg_touch_variables) {
                int q;

                q = remove_variables(uuid, "/EFI/systemd/systemd-boot" EFI_MACHINE_TYPE_NAME ".efi", true);
                if (q < 0 && r == 0)
                        r = q;
        }

        return r;
}

static int bootctl_main(int argc, char *argv[]) {

        static const Verb verbs[] = {
                { "help",            VERB_ANY, VERB_ANY, 0,            help         },
                { "status",          VERB_ANY, 1,        VERB_DEFAULT, verb_status  },
                { "install",         VERB_ANY, 1,        0,            verb_install },
                { "update",          VERB_ANY, 1,        0,            verb_install },
                { "remove",          VERB_ANY, 1,        0,            verb_remove  },
                {}
        };

        return dispatch_verb(argc, argv, verbs, NULL);
}

int main(int argc, char *argv[]) {
        int r;

        log_parse_environment();
        log_open();

        /* If we run in a container, automatically turn of EFI file system access */
        if (detect_container() > 0)
                arg_touch_variables = false;

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        r = bootctl_main(argc, argv);

 finish:
        free(arg_path);
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
