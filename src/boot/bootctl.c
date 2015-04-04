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
#include <errno.h>
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

static int verify_esp(const char *p, uint32_t *part, uint64_t *pstart, uint64_t *psize, sd_id128_t *uuid) {
        struct statfs sfs;
        struct stat st, st2;
        char *t;
        blkid_probe b = NULL;
        int r;
        const char *v;

        if (statfs(p, &sfs) < 0) {
                fprintf(stderr, "Failed to check file system type of %s: %m\n", p);
                return -errno;
        }

        if (sfs.f_type != 0x4d44) {
                fprintf(stderr, "File system %s is not a FAT EFI System Partition (ESP) file system.\n", p);
                return -ENODEV;
        }

        if (stat(p, &st) < 0) {
                fprintf(stderr, "Failed to determine block device node of %s: %m\n", p);
                return -errno;
        }

        if (major(st.st_dev) == 0) {
                fprintf(stderr, "Block device node of %p is invalid.\n", p);
                return -ENODEV;
        }

        r = asprintf(&t, "%s/..", p);
        if (r < 0) {
                fprintf(stderr, "Out of memory.\n");
                return -ENOMEM;
        }

        r = stat(t, &st2);
        free(t);
        if (r < 0) {
                fprintf(stderr, "Failed to determine block device node of parent of %s: %m\n", p);
                return -errno;
        }

        if (st.st_dev == st2.st_dev) {
                fprintf(stderr, "Directory %s is not the root of the EFI System Partition (ESP) file system.\n", p);
                return -ENODEV;
        }

        r = asprintf(&t, "/dev/block/%u:%u", major(st.st_dev), minor(st.st_dev));
        if (r < 0) {
                fprintf(stderr, "Out of memory.\n");
                return -ENOMEM;
        }

        errno = 0;
        b = blkid_new_probe_from_filename(t);
        free(t);
        if (!b) {
                if (errno != 0) {
                        fprintf(stderr, "Failed to open file system %s: %m\n", p);
                        return -errno;
                }

                fprintf(stderr, "Out of memory.\n");
                return -ENOMEM;
        }

        blkid_probe_enable_superblocks(b, 1);
        blkid_probe_set_superblocks_flags(b, BLKID_SUBLKS_TYPE);
        blkid_probe_enable_partitions(b, 1);
        blkid_probe_set_partitions_flags(b, BLKID_PARTS_ENTRY_DETAILS);

        errno = 0;
        r = blkid_do_safeprobe(b);
        if (r == -2) {
                fprintf(stderr, "File system %s is ambigious.\n", p);
                r = -ENODEV;
                goto fail;
        } else if (r == 1) {
                fprintf(stderr, "File system %s does not contain a label.\n", p);
                r = -ENODEV;
                goto fail;
        } else if (r != 0) {
                r = errno ? -errno : -EIO;
                fprintf(stderr, "Failed to probe file system %s: %s\n", p, strerror(-r));
                goto fail;
        }

        errno = 0;
        r = blkid_probe_lookup_value(b, "TYPE", &v, NULL);
        if (r != 0) {
                r = errno ? -errno : -EIO;
                fprintf(stderr, "Failed to probe file system type %s: %s\n", p, strerror(-r));
                goto fail;
        }

        if (strcmp(v, "vfat") != 0) {
                fprintf(stderr, "File system %s is not a FAT EFI System Partition (ESP) file system after all.\n", p);
                r = -ENODEV;
                goto fail;
        }

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_SCHEME", &v, NULL);
        if (r != 0) {
                r = errno ? -errno : -EIO;
                fprintf(stderr, "Failed to probe partition scheme %s: %s\n", p, strerror(-r));
                goto fail;
        }

        if (strcmp(v, "gpt") != 0) {
                fprintf(stderr, "File system %s is not on a GPT partition table.\n", p);
                r = -ENODEV;
                goto fail;
        }

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_TYPE", &v, NULL);
        if (r != 0) {
                r = errno ? -errno : -EIO;
                fprintf(stderr, "Failed to probe partition type UUID %s: %s\n", p, strerror(-r));
                goto fail;
        }

        if (strcmp(v, "c12a7328-f81f-11d2-ba4b-00a0c93ec93b") != 0) {
                r = -ENODEV;
                fprintf(stderr, "File system %s is not an EFI System Partition (ESP).\n", p);
                goto fail;
        }

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_UUID", &v, NULL);
        if (r != 0) {
                r = errno ? -errno : -EIO;
                fprintf(stderr, "Failed to probe partition entry UUID %s: %s\n", p, strerror(-r));
                goto fail;
        }

        r = sd_id128_from_string(v, uuid);
        if (r < 0) {
                fprintf(stderr, "Partition %s has invalid UUID: %s\n", p, v);
                r = -EIO;
                goto fail;
        }

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_NUMBER", &v, NULL);
        if (r != 0) {
                r = errno ? -errno : -EIO;
                fprintf(stderr, "Failed to probe partition number %s: %s\n", p, strerror(-r));
                goto fail;
        }
        *part = strtoul(v, NULL, 10);

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_OFFSET", &v, NULL);
        if (r != 0) {
                r = errno ? -errno : -EIO;
                fprintf(stderr, "Failed to probe partition offset %s: %s\n", p, strerror(-r));
                goto fail;
        }
        *pstart = strtoul(v, NULL, 10);

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_SIZE", &v, NULL);
        if (r != 0) {
                r = errno ? -errno : -EIO;
                fprintf(stderr, "Failed to probe partition size %s: %s\n", p, strerror(-r));
                goto fail;
        }
        *psize = strtoul(v, NULL, 10);

        blkid_free_probe(b);
        return 0;
fail:
        if (b)
                blkid_free_probe(b);
        return r;
}

/* search for "#### LoaderInfo: systemd-boot 218 ####" string inside the binary */
static int get_file_version(FILE *f, char **v) {
        struct stat st;
        char *buf;
        const char *s, *e;
        char *x = NULL;
        int r = 0;

        assert(f);
        assert(v);

        if (fstat(fileno(f), &st) < 0)
                return -errno;

        if (st.st_size < 27)
                return 0;

        buf = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fileno(f), 0);
        if (buf == MAP_FAILED)
                return -errno;

        s = memmem(buf, st.st_size - 8, "#### LoaderInfo: ", 17);
        if (!s)
                goto finish;
        s += 17;

        e = memmem(s, st.st_size - (s - buf), " ####", 5);
        if (!e || e - s < 3) {
                fprintf(stderr, "Malformed version string.\n");
                r = -EINVAL;
                goto finish;
        }

        x = strndup(s, e - s);
        if (!x) {
                fprintf(stderr, "Out of memory.\n");
                r = -ENOMEM;
                goto finish;
        }
        r = 1;

finish:
        munmap(buf, st.st_size);
        *v = x;
        return r;
}

static int enumerate_binaries(const char *esp_path, const char *path, const char *prefix) {
        struct dirent *de;
        char *p = NULL, *q = NULL;
        DIR *d = NULL;
        int r = 0, c = 0;

        if (asprintf(&p, "%s/%s", esp_path, path) < 0) {
                fprintf(stderr, "Out of memory.\n");
                r = -ENOMEM;
                goto finish;
        }

        d = opendir(p);
        if (!d) {
                if (errno == ENOENT) {
                        r = 0;
                        goto finish;
                }

                fprintf(stderr, "Failed to read %s: %m\n", p);
                r = -errno;
                goto finish;
        }

        while ((de = readdir(d))) {
                char *v;
                size_t n;
                FILE *f;

                if (de->d_name[0] == '.')
                        continue;

                n = strlen(de->d_name);
                if (n < 4 || strcasecmp(de->d_name + n - 4, ".efi") != 0)
                        continue;

                if (prefix && strncasecmp(de->d_name, prefix, strlen(prefix)) != 0)
                        continue;

                free(q);
                q = NULL;
                if (asprintf(&q, "%s/%s/%s", esp_path, path, de->d_name) < 0) {
                        fprintf(stderr, "Out of memory.\n");
                        r = -ENOMEM;
                        goto finish;
                }

                f = fopen(q, "re");
                if (!f) {
                        fprintf(stderr, "Failed to open %s for reading: %m\n", q);
                        r = -errno;
                        goto finish;
                }

                r = get_file_version(f, &v);
                fclose(f);

                if (r < 0)
                        goto finish;

                if (r > 0)
                        printf("         File: └─/%s/%s (%s)\n", path, de->d_name, v);
                else
                        printf("         File: └─/%s/%s\n", path, de->d_name);

                c++;
                free(v);
        }

        r = c;

finish:
        if (d)
                closedir(d);

        free(p);
        free(q);
        return r;
}

static int status_binaries(const char *esp_path, sd_id128_t partition) {
        int r;

        printf("Boot Loader Binaries:\n");

        printf("          ESP: /dev/disk/by-partuuid/%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n", SD_ID128_FORMAT_VAL(partition));

        r = enumerate_binaries(esp_path, "EFI/systemd", NULL);
        if (r == 0)
                fprintf(stderr, "systemd-boot not installed in ESP.\n");
        else if (r < 0)
                return r;

        r = enumerate_binaries(esp_path, "EFI/Boot", "boot");
        if (r == 0)
                fprintf(stderr, "No default/fallback boot loader installed in ESP.\n");
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
        printf("         File: └─%s\n", path);
        printf("\n");

        return 0;
}

static int status_variables(void) {
        int n_options, n_order;
        uint16_t *options = NULL, *order = NULL;
        int r, i;

        if (!is_efi_boot()) {
                fprintf(stderr, "Not booted with EFI, not showing EFI variables.\n");
                return 0;
        }

        n_options = efi_get_boot_options(&options);
        if (n_options < 0) {
                if (n_options == -ENOENT)
                        fprintf(stderr, "Failed to access EFI variables, "
                                "efivarfs needs to be available at /sys/firmware/efi/efivars/.\n");
                else
                        fprintf(stderr, "Failed to read EFI boot entries: %s\n", strerror(-n_options));
                r = n_options;
                goto finish;
        }

        printf("Boot Loader Entries in EFI Variables:\n");
        n_order = efi_get_boot_order(&order);
        if (n_order == -ENOENT) {
                n_order = 0;
        } else if (n_order < 0) {
                fprintf(stderr, "Failed to read EFI boot order.\n");
                r = n_order;
                goto finish;
        }

        /* print entries in BootOrder first */
        for (i = 0; i < n_order; i++)
                print_efi_option(order[i], true);

        /* print remaining entries */
        for (i = 0; i < n_options; i++) {
                int j;
                bool found = false;

                for (j = 0; j < n_order; j++)
                        if (options[i] == order[j]) {
                                found = true;
                                break;
                        }

                if (found)
                        continue;

                print_efi_option(options[i], false);
        }

        r = 0;
finish:
        free(options);
        free(order);

        return r;
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

static int version_check(FILE *f, const char *from, const char *to) {
        FILE *g = NULL;
        char *a = NULL, *b = NULL;
        int r;

        assert(f);
        assert(from);
        assert(to);

        r = get_file_version(f, &a);
        if (r < 0)
                goto finish;
        if (r == 0) {
                r = -EINVAL;
                fprintf(stderr, "Source file %s does not carry version information!\n", from);
                goto finish;
        }

        g = fopen(to, "re");
        if (!g) {
                if (errno == ENOENT) {
                        r = 0;
                        goto finish;
                }

                r = -errno;
                fprintf(stderr, "Failed to open %s for reading: %m\n", to);
                goto finish;
        }

        r = get_file_version(g, &b);
        if (r < 0)
                goto finish;
        if (r == 0 || compare_product(a, b) != 0) {
                r = -EEXIST;
                fprintf(stderr, "Skipping %s, since it's owned by another boot loader.\n", to);
                goto finish;
        }

        if (compare_version(a, b) < 0) {
                r = -EEXIST;
                fprintf(stderr, "Skipping %s, since it's a newer boot loader version already.\n", to);
                goto finish;
        }

        r = 0;

finish:
        free(a);
        free(b);
        if (g)
                fclose(g);
        return r;
}

static int copy_file(const char *from, const char *to, bool force) {
        FILE *f = NULL, *g = NULL;
        char *p = NULL;
        int r;
        struct timespec t[2];
        struct stat st;

        assert(from);
        assert(to);

        f = fopen(from, "re");
        if (!f) {
                fprintf(stderr, "Failed to open %s for reading: %m\n", from);
                return -errno;
        }

        if (!force) {
                /* If this is an update, then let's compare versions first */
                r = version_check(f, from, to);
                if (r < 0)
                        goto finish;
        }

        if (asprintf(&p, "%s~", to) < 0) {
                fprintf(stderr, "Out of memory.\n");
                r = -ENOMEM;
                goto finish;
        }

        g = fopen(p, "wxe");
        if (!g) {
                /* Directory doesn't exist yet? Then let's skip this... */
                if (!force && errno == ENOENT) {
                        r = 0;
                        goto finish;
                }

                fprintf(stderr, "Failed to open %s for writing: %m\n", to);
                r = -errno;
                goto finish;
        }

        rewind(f);
        do {
                size_t k;
                uint8_t buf[32*1024];

                k = fread(buf, 1, sizeof(buf), f);
                if (ferror(f)) {
                        fprintf(stderr, "Failed to read %s: %m\n", from);
                        r = -errno;
                        goto finish;
                }
                if (k == 0)
                        break;

                fwrite(buf, 1, k, g);
                if (ferror(g)) {
                        fprintf(stderr, "Failed to write %s: %m\n", to);
                        r = -errno;
                        goto finish;
                }
        } while (!feof(f));

        fflush(g);
        if (ferror(g)) {
                fprintf(stderr, "Failed to write %s: %m\n", to);
                r = -errno;
                goto finish;
        }

        r = fstat(fileno(f), &st);
        if (r < 0) {
                fprintf(stderr, "Failed to get file timestamps of %s: %m", from);
                r = -errno;
                goto finish;
        }

        t[0] = st.st_atim;
        t[1] = st.st_mtim;

        r = futimens(fileno(g), t);
        if (r < 0) {
                fprintf(stderr, "Failed to change file timestamps for %s: %m", p);
                r = -errno;
                goto finish;
        }

        if (rename(p, to) < 0) {
                fprintf(stderr, "Failed to rename %s to %s: %m\n", p, to);
                r = -errno;
                goto finish;
        }

        fprintf(stderr, "Copied %s to %s.\n", from, to);

        free(p);
        p = NULL;
        r = 0;

finish:
        if (f)
                fclose(f);
        if (g)
                fclose(g);
        if (p) {
                unlink(p);
                free(p);
        }
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

        if (asprintf(&p, "%s/%s", prefix, suffix) < 0) {
                fprintf(stderr, "Out of memory.\n");
                return -ENOMEM;
        }

        if (mkdir(p, 0700) < 0) {
                if (errno != EEXIST) {
                        fprintf(stderr, "Failed to create %s: %m\n", p);
                        free(p);
                        return -errno;
                }
        } else
                fprintf(stderr, "Created %s.\n", p);

        free(p);
        return 0;
}

static int create_dirs(const char *esp_path) {
        int r;

        r = mkdir_one(esp_path, "EFI");
        if (r < 0)
                return r;

        r = mkdir_one(esp_path, "EFI/systemd");
        if (r < 0)
                return r;

        r = mkdir_one(esp_path, "EFI/Boot");
        if (r < 0)
                return r;

        r = mkdir_one(esp_path, "loader");
        if (r < 0)
                return r;

        r = mkdir_one(esp_path, "loader/entries");
        if (r < 0)
                return r;

        return 0;
}

static int copy_one_file(const char *esp_path, const char *name, bool force) {
        _cleanup_free_ char *p = NULL;
        _cleanup_free_ char *q = NULL;
        _cleanup_free_ char *v = NULL;
        int r;

        if (asprintf(&p, BOOTLIBDIR "/%s", name) < 0) {
                fprintf(stderr, "Out of memory.\n");
                return -ENOMEM;
        }

        if (asprintf(&q, "%s/EFI/systemd/%s", esp_path, name) < 0) {
                fprintf(stderr, "Out of memory.\n");
                return -ENOMEM;
        }

        r = copy_file(p, q, force);

        if (startswith(name, "systemd-boot")) {
                int k;

                /* Create the EFI default boot loader name (specified for removable devices) */
                if (asprintf(&v, "%s/EFI/Boot/BOOT%s", esp_path, name + strlen("systemd-boot")) < 0) {
                        fprintf(stderr, "Out of memory.\n");
                        return -ENOMEM;
                }
                strupper(strrchr(v, '/') + 1);

                k = copy_file(p, v, force);
                if (k < 0 && r == 0)
                        return k;
        }

        return r;
}

static int install_binaries(const char *esp_path, bool force) {
        struct dirent *de;
        DIR *d;
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
        if (!d) {
                fprintf(stderr, "Failed to open "BOOTLIBDIR": %m\n");
                return -errno;
        }

        while ((de = readdir(d))) {
                size_t n;
                int k;

                if (de->d_name[0] == '.')
                        continue;

                n = strlen(de->d_name);
                if (n < 4 || strcmp(de->d_name + n - 4, ".efi") != 0)
                        continue;

                k = copy_one_file(esp_path, de->d_name, force);
                if (k < 0 && r == 0)
                        r = k;
        }

        closedir(d);
        return r;
}

static bool same_entry(uint16_t id, const sd_id128_t uuid, const char *path) {
        char *opath = NULL;
        sd_id128_t ouuid;
        int err;
        bool same = false;

        err = efi_get_boot_option(id, NULL, &ouuid, &opath, NULL);
        if (err < 0)
                return false;
        if (!sd_id128_equal(uuid, ouuid))
                goto finish;

        if (!streq_ptr(path, opath))
                goto finish;

        same = true;

finish:
        return same;
}

static int find_slot(sd_id128_t uuid, const char *path, uint16_t *id) {
        uint16_t *options = NULL;
        int n_options;
        int i;
        uint16_t new_id = 0;
        bool existing = false;

        n_options = efi_get_boot_options(&options);
        if (n_options < 0)
                return n_options;

        /* find already existing systemd-boot entry */
        for (i = 0; i < n_options; i++)
                if (same_entry(options[i], uuid, path)) {
                        new_id = options[i];
                        existing = true;
                        goto finish;
                }

        /* find free slot in the sorted BootXXXX variable list */
        for (i = 0; i < n_options; i++)
                if (i != options[i]) {
                        new_id = i;
                        goto finish;
                }

        /* use the next one */
        if (i == 0xffff)
                return -ENOSPC;
        new_id = i;

finish:
        *id = new_id;
        free(options);
        return existing;
}

static int insert_into_order(uint16_t slot, bool first) {
        uint16_t *order = NULL;
        uint16_t *new_order;
        int n_order;
        int i;
        int err = 0;

        n_order = efi_get_boot_order(&order);
        if (n_order <= 0) {
                /* no entry, add us */
                err = efi_set_boot_order(&slot, 1);
                goto finish;
        }

        /* are we the first and only one? */
        if (n_order == 1 && order[0] == slot)
                goto finish;

        /* are we already in the boot order? */
        for (i = 0; i < n_order; i++) {
                if (order[i] != slot)
                        continue;

                /* we do not require to be the first one, all is fine */
                if (!first)
                        goto finish;

                /* move us to the first slot */
                memmove(&order[1], order, i * sizeof(uint16_t));
                order[0] = slot;
                efi_set_boot_order(order, n_order);
                goto finish;
        }

        /* extend array */
        new_order = realloc(order, (n_order+1) * sizeof(uint16_t));
        if (!new_order) {
                err = -ENOMEM;
                goto finish;
        }
        order = new_order;

        /* add us to the top or end of the list */
        if (first) {
                memmove(&order[1], order, n_order * sizeof(uint16_t));
                order[0] = slot;
        } else
                order[n_order] = slot;

        efi_set_boot_order(order, n_order+1);

finish:
        free(order);
        return err;
}

static int remove_from_order(uint16_t slot) {
        _cleanup_free_ uint16_t *order = NULL;
        int n_order;
        int i;
        int err = 0;

        n_order = efi_get_boot_order(&order);
        if (n_order < 0)
                return n_order;
        if (n_order == 0)
                return 0;

        for (i = 0; i < n_order; i++) {
                if (order[i] != slot)
                        continue;

                if (i+1 < n_order)
                        memmove(&order[i], &order[i+1], (n_order - i) * sizeof(uint16_t));
                efi_set_boot_order(order, n_order-1);
                break;
        }

        return err;
}

static int install_variables(const char *esp_path,
                             uint32_t part, uint64_t pstart, uint64_t psize,
                             sd_id128_t uuid, const char *path,
                             bool first) {
        char *p = NULL;
        uint16_t *options = NULL;
        uint16_t slot;
        int r;

        if (!is_efi_boot()) {
                fprintf(stderr, "Not booted with EFI, skipping EFI variable setup.\n");
                return 0;
        }

        if (asprintf(&p, "%s%s", esp_path, path) < 0) {
                fprintf(stderr, "Out of memory.\n");
                return -ENOMEM;
        }

        if (access(p, F_OK) < 0) {
                if (errno == ENOENT)
                        r = 0;
                else
                        r = -errno;
                goto finish;
        }

        r = find_slot(uuid, path, &slot);
        if (r < 0) {
                if (r == -ENOENT)
                        fprintf(stderr, "Failed to access EFI variables. Is the \"efivarfs\" filesystem mounted?\n");
                else
                        fprintf(stderr, "Failed to determine current boot order: %s\n", strerror(-r));
                goto finish;
        }

        if (first || r == false) {
                r = efi_add_boot_option(slot, "Linux Boot Manager",
                                        part, pstart, psize,
                                        uuid, path);
                if (r < 0) {
                        fprintf(stderr, "Failed to create EFI Boot variable entry: %s\n", strerror(-r));
                        goto finish;
                }
                fprintf(stderr, "Created EFI boot entry \"Linux Boot Manager\".\n");
        }

        insert_into_order(slot, first);

finish:
        free(p);
        free(options);
        return r;
}

static int remove_boot_efi(const char *esp_path) {
        struct dirent *de;
        char *p = NULL, *q = NULL;
        DIR *d = NULL;
        int r = 0, c = 0;

        if (asprintf(&p, "%s/EFI/Boot", esp_path) < 0) {
                fprintf(stderr, "Out of memory.\n");
                return -ENOMEM;
        }

        d = opendir(p);
        if (!d) {
                if (errno == ENOENT) {
                        r = 0;
                        goto finish;
                }

                fprintf(stderr, "Failed to read %s: %m\n", p);
                r = -errno;
                goto finish;
        }

        while ((de = readdir(d))) {
                char *v;
                size_t n;
                FILE *f;

                if (de->d_name[0] == '.')
                        continue;

                n = strlen(de->d_name);
                if (n < 4 || strcasecmp(de->d_name + n - 4, ".EFI") != 0)
                        continue;

                if (strncasecmp(de->d_name, "Boot", 4) != 0)
                        continue;

                free(q);
                q = NULL;
                if (asprintf(&q, "%s/%s", p, de->d_name) < 0) {
                        fprintf(stderr, "Out of memory.\n");
                        r = -ENOMEM;
                        goto finish;
                }

                f = fopen(q, "re");
                if (!f) {
                        fprintf(stderr, "Failed to open %s for reading: %m\n", q);
                        r = -errno;
                        goto finish;
                }

                r = get_file_version(f, &v);
                fclose(f);

                if (r < 0)
                        goto finish;

                if (r > 0 && strncmp(v, "systemd-boot ", 10) == 0) {

                        r = unlink(q);
                        if (r < 0) {
                                fprintf(stderr, "Failed to remove %s: %m\n", q);
                                r = -errno;
                                free(v);
                                goto finish;
                        } else
                                fprintf(stderr, "Removed %s.\n", q);
                }

                c++;
                free(v);
        }

        r = c;

finish:
        if (d)
                closedir(d);
        free(p);
        free(q);

        return r;
}

static int rmdir_one(const char *prefix, const char *suffix) {
        char *p;

        if (asprintf(&p, "%s/%s", prefix, suffix) < 0) {
                fprintf(stderr, "Out of memory.\n");
                return -ENOMEM;
        }

        if (rmdir(p) < 0) {
                if (errno != ENOENT && errno != ENOTEMPTY) {
                        fprintf(stderr, "Failed to remove %s: %m\n", p);
                        free(p);
                        return -errno;
                }
        } else
                fprintf(stderr, "Removed %s.\n", p);

        free(p);
        return 0;
}


static int remove_binaries(const char *esp_path) {
        char *p;
        int r, q;

        if (asprintf(&p, "%s/EFI/systemd-boot", esp_path) < 0) {
                fprintf(stderr, "Out of memory.\n");
                return -ENOMEM;
        }

        r = rm_rf(p, REMOVE_ROOT|REMOVE_PHYSICAL);
        free(p);

        q = remove_boot_efi(esp_path);
        if (q < 0 && r == 0)
                r = q;

        q = rmdir_one(esp_path, "loader/entries");
        if (q < 0 && r == 0)
                r = q;

        q = rmdir_one(esp_path, "loader");
        if (q < 0 && r == 0)
                r = q;

        q = rmdir_one(esp_path, "EFI/Boot");
        if (q < 0 && r == 0)
                r = q;

        q = rmdir_one(esp_path, "EFI/systemd-boot");
        if (q < 0 && r == 0)
                r = q;

        q = rmdir_one(esp_path, "EFI");
        if (q < 0 && r == 0)
                r = q;

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
                remove_from_order(slot);

        return 0;
}

static int install_loader_config(const char *esp_path) {
        char *p = NULL;
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

        if (asprintf(&p, "%s/%s", esp_path, "loader/loader.conf") < 0) {
                fprintf(stderr, "Out of memory.\n");
                return -ENOMEM;
        }

        f = fopen(p, "wxe");
        if (f) {
                fprintf(f, "#timeout 3\n");
                fprintf(f, "default %s-*\n", machine);
                fclose(f);
        }

        free(p);
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

static const char *arg_path = NULL;
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

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0) {
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
                        fprintf(stderr, "Unknown option code '%c'.\n", c);
                        return -EINVAL;
                }
        }

        return 1;
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
        uint64_t pstart = 0;
        uint64_t psize = 0;
        unsigned int i;
        int q;
        int r;

        if (argv[optind]) {
                for (i = 0; i < ELEMENTSOF(verbs); i++) {
                        if (!streq(argv[optind], verbs[i].verb))
                                continue;
                        arg_action = verbs[i].action;
                        break;
                }
                if (i >= ELEMENTSOF(verbs)) {
                        fprintf(stderr, "Unknown operation %s\n", argv[optind]);
                        r = -EINVAL;
                        goto finish;
                }
        }

        if (!arg_path)
                arg_path = "/boot";

        if (geteuid() != 0) {
                fprintf(stderr, "Need to be root.\n");
                r = -EPERM;
                goto finish;
        }

        r = verify_esp(arg_path, &part, &pstart, &psize, &uuid);
        if (r == -ENODEV && !arg_path)
                fprintf(stderr, "You might want to use --path= to indicate the path to your ESP, in case it is not mounted to /boot.\n");
        if (r < 0)
                goto finish;

        switch (arg_action) {
        case ACTION_STATUS: {
                _cleanup_free_ char *fw_type = NULL;
                _cleanup_free_ char *fw_info = NULL;
                _cleanup_free_ char *loader = NULL;
                _cleanup_free_ char *loader_path = NULL;
                sd_id128_t loader_part_uuid = {};

                efi_get_variable_string(EFI_VENDOR_LOADER, "LoaderFirmwareType", &fw_type);
                efi_get_variable_string(EFI_VENDOR_LOADER, "LoaderFirmwareInfo", &fw_info);
                efi_get_variable_string(EFI_VENDOR_LOADER, "LoaderInfo", &loader);
                if (efi_get_variable_string(EFI_VENDOR_LOADER, "LoaderImageIdentifier", &loader_path) > 0)
                        efi_tilt_backslashes(loader_path);
                efi_loader_get_device_part_uuid(&loader_part_uuid);

                printf("System:\n");
                printf("     Firmware: %s (%s)\n", fw_type, strna(fw_info));
                printf("  Secure Boot: %s\n", is_efi_secure_boot() ? "enabled" : "disabled");
                printf("   Setup Mode: %s\n", is_efi_secure_boot_setup_mode() ? "setup" : "user");
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

                r = status_binaries(arg_path, uuid);
                if (r < 0)
                        goto finish;

                if (arg_touch_variables)
                        r = status_variables();
                break;
        }

        case ACTION_INSTALL:
        case ACTION_UPDATE:
                umask(0002);

                r = install_binaries(arg_path, arg_action == ACTION_INSTALL);
                if (r < 0)
                        goto finish;

                if (arg_action == ACTION_INSTALL)
                        install_loader_config(arg_path);

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

finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
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
