/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/statfs.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <dirent.h>
#include <ctype.h>
#include <limits.h>
#include <ftw.h>
#include <stdbool.h>
#include <blkid/blkid.h>

#include "efivars.h"
#include "build.h"
#include "util.h"
#include "rm-rf.h"
#include "blkid-util.h"

static int verify_esp(const char *p, uint32_t *part, uint64_t *pstart, uint64_t *psize, sd_id128_t *uuid) {
        struct statfs sfs;
        struct stat st, st2;
        _cleanup_free_ char *t = NULL;
        _cleanup_blkid_free_probe_ blkid_probe b = NULL;
        int r;
        const char *v, *t2;

        if (statfs(p, &sfs) < 0)
                return log_error_errno(errno, "Failed to check file system type of \"%s\": %m", p);

        if (sfs.f_type != 0x4d44) {
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
                log_error("File system \"%s\" is ambigious.", p);
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

        r = sd_id128_from_string(v, uuid);
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
        *part = strtoul(v, NULL, 10);

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_OFFSET", &v, NULL);
        if (r != 0) {
                r = errno ? -errno : -EIO;
                return log_error_errno(r, "Failed to probe partition offset \"%s\": %m", p);
        }
        *pstart = strtoul(v, NULL, 10);

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_SIZE", &v, NULL);
        if (r != 0) {
                r = errno ? -errno : -EIO;
                return log_error_errno(r, "Failed to probe partition size \"%s\": %m", p);
        }
        *psize = strtoul(v, NULL, 10);

        return 0;
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
                return -errno;

        if (st.st_size < 27)
                return 0;

        buf = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (buf == MAP_FAILED)
                return -errno;

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
        munmap(buf, st.st_size);
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

        while ((de = readdir(d))) {
                _cleanup_close_ int fd = -1;
                _cleanup_free_ char *v = NULL;

                if (de->d_name[0] == '.')
                        continue;

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
                        printf("         File: └─/%s/%s (%s)\n", path, de->d_name, v);
                else
                        printf("         File: └─/%s/%s\n", path, de->d_name);
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

        r = enumerate_binaries(esp_path, "EFI/Boot", "boot");
        if (r == 0)
                log_error("No default/fallback boot loader installed in ESP.");
        else if (r < 0)
                return r;

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
        printf("         File: └─%s\n", path);
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
                return log_error_errno(ENOENT, "Failed to access EFI variables, efivarfs"
                                       " needs to be available at /sys/firmware/efi/efivars/.");
        else if (n_options < 0)
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
                                goto next;

                print_efi_option(options[i], false);
        next:
                continue;
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

        fflush(g);
        if (ferror(g)) {
                r = log_error_errno(EIO, "Failed to write \"%s\": %m", to);
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
        unlink(p);
        return r;
}

static char* strupper(char *s) {
        char *p;

        for (p = s; *p; p++)
                *p = toupper(*p);

        return s;
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
        "EFI/Boot",
        "loader",
        "loader/entries"
};

static int create_dirs(const char *esp_path) {
        int r;
        unsigned i;

        for (i = 0; i < ELEMENTSOF(efi_subdirs); i++) {
                r = mkdir_one(esp_path, efi_subdirs[i]);
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
                v = strjoina(esp_path, "/EFI/Boot/BOOT", name + strlen("systemd-boot"));
                strupper(strrchr(v, '/') + 1);

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

        while ((de = readdir(d))) {
                int k;

                if (de->d_name[0] == '.')
                        continue;

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
                else
                        return log_error_errno(errno, "Cannot access \"%s\": %m", p);
        }

        r = find_slot(uuid, path, &slot);
        if (r < 0)
                return log_error_errno(r,
                                       r == -ENOENT ?
                                       "Failed to access EFI variables. Is the \"efivarfs\" filesystem mounted?" :
                                       "Failed to determine current boot order: %m");

        if (first || r == false) {
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

        p = strjoina(esp_path, "/EFI/Boot");
        d = opendir(p);
        if (!d) {
                if (errno == ENOENT)
                        return 0;

                return log_error_errno(errno, "Failed to open directory \"%s\": %m", p);
        }

        while ((de = readdir(d))) {
                _cleanup_close_ int fd = -1;
                _cleanup_free_ char *v = NULL;

                if (de->d_name[0] == '.')
                        continue;

                if (!endswith_no_case(de->d_name, ".efi"))
                        continue;

                if (!startswith_no_case(de->d_name, "Boot"))
                        continue;

                fd = openat(dirfd(d), de->d_name, O_RDONLY|O_CLOEXEC);
                if (r < 0)
                        return log_error_errno(errno, "Failed to open \"%s/%s\" for reading: %m", p, de->d_name);

                r = get_file_version(fd, &v);
                if (r < 0)
                        return r;
                if (r > 0 && startswith(v, "systemd-boot ")) {
                        r = unlinkat(dirfd(d), de->d_name, 0);
                        if (r < 0)
                                return log_error_errno(errno, "Failed to remove \"%s/%s\": %m", p, de->d_name);

                        log_info("Removed \"%s/\%s\".", p, de->d_name);
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
        else
                return 0;
}

static int install_loader_config(const char *esp_path) {
        char *p;
        char line[64];
        char *machine = NULL;
        FILE *f;

        f = fopen("/etc/machine-id", "re");
        if (!f)
                return -errno;

        if (fgets(line, sizeof(line), f) != NULL) {
                char *s;

                s = strchr(line, '\n');
                if (s)
                        s[0] = '\0';
                if (strlen(line) == 32)
                        machine = line;
        }
        fclose(f);

        if (!machine)
                return -ESRCH;

        p = strjoina(esp_path, "/loader/loader.conf");
        f = fopen(p, "wxe");
        if (f) {
                fprintf(f, "#timeout 3\n");
                fprintf(f, "default %s-*\n", machine);
                fclose(f);
                if (ferror(f))
                        return log_error_errno(EIO, "Failed to write \"%s\": %m", p);
        }

        return 0;
}

static int help(void) {
        printf("%s [COMMAND] [OPTIONS...]\n"
               "\n"
               "Install, update or remove the sdboot EFI boot manager.\n\n"
               "  -h --help          Show this help\n"
               "     --version       Print version\n"
               "     --path=PATH     Path to the EFI System Partition (ESP)\n"
               "     --no-variables  Don't touch EFI variables\n"
               "\n"
               "Comands:\n"
               "     status          Show status of installed systemd-boot and EFI variables\n"
               "     install         Install systemd-boot to the ESP and EFI variables\n"
               "     update          Update systemd-boot in the ESP and EFI variables\n"
               "     remove          Remove systemd-boot from the ESP and EFI variables\n",
               program_invocation_short_name);

        return 0;
}

static const char *arg_path = "/boot";
static bool arg_touch_variables = true;

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

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        printf(VERSION "\n");
                        return 0;

                case ARG_PATH:
                        arg_path = optarg;
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

static int bootctl_main(int argc, char*argv[]) {
        enum action {
                ACTION_STATUS,
                ACTION_INSTALL,
                ACTION_UPDATE,
                ACTION_REMOVE
        } arg_action = ACTION_STATUS;
        static const struct {
                const char* verb;
                enum action action;
        } verbs[] = {
                { "status",  ACTION_STATUS },
                { "install", ACTION_INSTALL },
                { "update",  ACTION_UPDATE },
                { "remove",  ACTION_REMOVE },
        };

        sd_id128_t uuid = {};
        uint32_t part = 0;
        uint64_t pstart = 0, psize = 0;
        int r, q;

        if (argv[optind]) {
                unsigned i;

                for (i = 0; i < ELEMENTSOF(verbs); i++) {
                        if (!streq(argv[optind], verbs[i].verb))
                                continue;
                        arg_action = verbs[i].action;
                        break;
                }
                if (i >= ELEMENTSOF(verbs)) {
                        log_error("Unknown operation \"%s\"", argv[optind]);
                        return -EINVAL;
                }
        }

        if (geteuid() != 0)
                return log_error_errno(EPERM, "Need to be root.");

        r = verify_esp(arg_path, &part, &pstart, &psize, &uuid);
        if (r == -ENODEV && !arg_path)
                log_notice("You might want to use --path= to indicate the path to your ESP, in case it is not mounted on /boot.");
        if (r < 0)
                return r;

        switch (arg_action) {
        case ACTION_STATUS: {
                _cleanup_free_ char *fw_type = NULL;
                _cleanup_free_ char *fw_info = NULL;
                _cleanup_free_ char *loader = NULL;
                _cleanup_free_ char *loader_path = NULL;
                sd_id128_t loader_part_uuid = {};

                if (is_efi_boot()) {
                        read_loader_efi_var("LoaderFirmwareType", &fw_type);
                        read_loader_efi_var("LoaderFirmwareInfo", &fw_info);
                        read_loader_efi_var("LoaderInfo", &loader);
                        read_loader_efi_var("LoaderImageIdentifier", &loader_path);
                        if (loader_path)
                                efi_tilt_backslashes(loader_path);
                        r = efi_loader_get_device_part_uuid(&loader_part_uuid);
                        if (r < 0 && r == -ENOENT)
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
                        printf("         File: %s%s\n", draw_special_char(DRAW_TREE_RIGHT), strna(loader_path));
                        printf("\n");
                } else
                        printf("System:\n    Not booted with EFI\n");

                r = status_binaries(arg_path, uuid);
                if (r < 0)
                        return r;

                if (arg_touch_variables)
                        r = status_variables();
                break;
        }

        case ACTION_INSTALL:
        case ACTION_UPDATE:
                umask(0002);

                r = install_binaries(arg_path, arg_action == ACTION_INSTALL);
                if (r < 0)
                        return r;

                if (arg_action == ACTION_INSTALL) {
                        r = install_loader_config(arg_path);
                        if (r < 0)
                                return r;
                }

                if (arg_touch_variables)
                        r = install_variables(arg_path,
                                              part, pstart, psize, uuid,
                                              "/EFI/systemd/systemd-boot" EFI_MACHINE_TYPE_NAME ".efi",
                                              arg_action == ACTION_INSTALL);
                break;

        case ACTION_REMOVE:
                r = remove_binaries(arg_path);

                if (arg_touch_variables) {
                        q = remove_variables(uuid, "/EFI/systemd/systemd-boot" EFI_MACHINE_TYPE_NAME ".efi", true);
                        if (q < 0 && r == 0)
                                r = q;
                }
                break;
        }

        return r;
}

int main(int argc, char *argv[]) {
        int r;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        r = bootctl_main(argc, argv);

 finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
