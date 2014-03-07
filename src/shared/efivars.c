/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

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

#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>

#include "acpi-fpdt.h"
#include "util.h"
#include "utf8.h"
#include "efivars.h"

#ifdef ENABLE_EFI

bool is_efi_boot(void) {
        return access("/sys/firmware/efi", F_OK) >= 0;
}

static int read_flag(const char *varname) {
        int r;
        _cleanup_free_ void *v = NULL;
        size_t s;
        uint8_t b;

        r = efi_get_variable(EFI_VENDOR_GLOBAL, varname, NULL, &v, &s);
        if (r < 0)
                return r;

        if (s != 1)
                return -EINVAL;

        b = *(uint8_t *)v;
        r = b > 0;
        return r;
}

int is_efi_secure_boot(void) {
        return read_flag("SecureBoot");
}

int is_efi_secure_boot_setup_mode(void) {
        return read_flag("SetupMode");
}

int efi_get_variable(
                sd_id128_t vendor,
                const char *name,
                uint32_t *attribute,
                void **value,
                size_t *size) {

        _cleanup_close_ int fd = -1;
        _cleanup_free_ char *p = NULL;
        uint32_t a;
        ssize_t n;
        struct stat st;
        void *r;

        assert(name);
        assert(value);
        assert(size);

        if (asprintf(&p,
                     "/sys/firmware/efi/efivars/%s-%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                     name, SD_ID128_FORMAT_VAL(vendor)) < 0)
                return -ENOMEM;

        fd = open(p, O_RDONLY|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        if (fstat(fd, &st) < 0)
                return -errno;
        if (st.st_size < 4)
                return -EIO;
        if (st.st_size > 4*1024*1024 + 4)
                return -E2BIG;

        n = read(fd, &a, sizeof(a));
        if (n < 0)
                return -errno;
        if (n != sizeof(a))
                return -EIO;

        r = malloc(st.st_size - 4 + 2);
        if (!r)
                return -ENOMEM;

        n = read(fd, r, (size_t) st.st_size - 4);
        if (n < 0) {
                free(r);
                return -errno;
        }
        if (n != (ssize_t) st.st_size - 4) {
                free(r);
                return -EIO;
        }

        /* Always NUL terminate (2 bytes, to protect UTF-16) */
        ((char*) r)[st.st_size - 4] = 0;
        ((char*) r)[st.st_size - 4 + 1] = 0;

        *value = r;
        *size = (size_t) st.st_size - 4;

        if (attribute)
                *attribute = a;

        return 0;
}

int efi_get_variable_string(sd_id128_t vendor, const char *name, char **p) {
        _cleanup_free_ void *s = NULL;
        size_t ss = 0;
        int r;
        char *x;

        r = efi_get_variable(vendor, name, NULL, &s, &ss);
        if (r < 0)
                return r;

        x = utf16_to_utf8(s, ss);
        if (!x)
                return -ENOMEM;

        *p = x;
        return 0;
}

static size_t utf16_size(const uint16_t *s) {
        size_t l = 0;

        while (s[l] > 0)
                l++;

        return (l+1) * sizeof(uint16_t);
}

static void efi_guid_to_id128(const void *guid, sd_id128_t *id128) {
        struct uuid {
                uint32_t u1;
                uint16_t u2;
                uint16_t u3;
                uint8_t u4[8];
        } _packed_;
        const struct uuid *uuid = guid;

        id128->bytes[0] = (uuid->u1 >> 24) & 0xff;
        id128->bytes[1] = (uuid->u1 >> 16) & 0xff;
        id128->bytes[2] = (uuid->u1 >> 8) & 0xff;
        id128->bytes[3] = (uuid->u1) & 0xff;
        id128->bytes[4] = (uuid->u2 >> 8) & 0xff;
        id128->bytes[5] = (uuid->u2) & 0xff;
        id128->bytes[6] = (uuid->u3 >> 8) & 0xff;
        id128->bytes[7] = (uuid->u3) & 0xff;
        memcpy(&id128->bytes[8], uuid->u4, sizeof(uuid->u4));
}

int efi_get_boot_option(
                uint16_t id,
                char **title,
                sd_id128_t *part_uuid,
                char **path) {

        struct boot_option {
                uint32_t attr;
                uint16_t path_len;
                uint16_t title[];
        } _packed_;

        struct drive_path {
                uint32_t part_nr;
                uint64_t part_start;
                uint64_t part_size;
                char signature[16];
                uint8_t mbr_type;
                uint8_t signature_type;
        } _packed_;

        struct device_path {
                uint8_t type;
                uint8_t sub_type;
                uint16_t length;
                union {
                        uint16_t path[0];
                        struct drive_path drive;
                };
        } _packed_;

        char boot_id[9];
        _cleanup_free_ uint8_t *buf = NULL;
        size_t l;
        struct boot_option *header;
        size_t title_size;
        char *s = NULL;
        char *p = NULL;
        sd_id128_t p_uuid = SD_ID128_NULL;
        int err;

        snprintf(boot_id, sizeof(boot_id), "Boot%04X", id);
        err = efi_get_variable(EFI_VENDOR_GLOBAL, boot_id, NULL, (void **)&buf, &l);
        if (err < 0)
                return err;
        if (l < sizeof(struct boot_option))
                return -ENOENT;

        header = (struct boot_option *)buf;
        title_size = utf16_size(header->title);
        if (title_size > l - offsetof(struct boot_option, title))
                return -EINVAL;

        if (title) {
                s = utf16_to_utf8(header->title, title_size);
                if (!s) {
                        err = -ENOMEM;
                        goto err;
                }
        }

        if (header->path_len > 0) {
                uint8_t *dbuf;
                size_t dnext;

                dbuf = buf + offsetof(struct boot_option, title) + title_size;
                dnext = 0;
                while (dnext < header->path_len) {
                        struct device_path *dpath;

                        dpath = (struct device_path *)(dbuf + dnext);
                        if (dpath->length < 4)
                                break;

                        /* Type 0x7F – End of Hardware Device Path, Sub-Type 0xFF – End Entire Device Path */
                        if (dpath->type == 0x7f && dpath->sub_type == 0xff)
                                break;

                        dnext += dpath->length;

                        /* Type 0x04 – Media Device Path */
                        if (dpath->type != 0x04)
                                continue;

                        /* Sub-Type 1 – Hard Drive */
                        if (dpath->sub_type == 0x01) {
                                /* 0x02 – GUID Partition Table */
                                if (dpath->drive.mbr_type != 0x02)
                                        continue;

                                /* 0x02 – GUID signature */
                                if (dpath->drive.signature_type != 0x02)
                                        continue;

                                if (part_uuid)
                                        efi_guid_to_id128(dpath->drive.signature, &p_uuid);
                                continue;
                        }

                        /* Sub-Type 4 – File Path */
                        if (dpath->sub_type == 0x04 && !p && path) {
                                p = utf16_to_utf8(dpath->path, dpath->length-4);
                                continue;
                        }
                }
        }

        if (title)
                *title = s;
        if (part_uuid)
                *part_uuid = p_uuid;
        if (path)
                *path = p;

        return 0;
err:
        free(s);
        free(p);
        return err;
}

int efi_get_boot_order(uint16_t **order) {
        void *buf;
        size_t l;
        int r;

        r = efi_get_variable(EFI_VENDOR_GLOBAL, "BootOrder", NULL, &buf, &l);
        if (r < 0)
                return r;

        if (l <= 0) {
                free(buf);
                return -ENOENT;
        }

        if ((l % sizeof(uint16_t) > 0) ||
            (l / sizeof(uint16_t) > INT_MAX)) {
                free(buf);
                return -EINVAL;
        }

        *order = buf;
        return (int) (l / sizeof(uint16_t));
}

static int boot_id_hex(const char s[4]) {
        int i;
        int id = 0;

        for (i = 0; i < 4; i++)
                if (s[i] >= '0' && s[i] <= '9')
                        id |= (s[i] - '0') << (3 - i) * 4;
                else if (s[i] >= 'A' && s[i] <= 'F')
                        id |= (s[i] - 'A' + 10) << (3 - i) * 4;
                else
                        return -1;

        return id;
}

static int cmp_uint16(const void *_a, const void *_b) {
        const uint16_t *a = _a, *b = _b;

        return (int)*a - (int)*b;
}

int efi_get_boot_options(uint16_t **options) {
        _cleanup_closedir_ DIR *dir = NULL;
        struct dirent *de;
        uint16_t *list = NULL;
        int count = 0, r;

        assert(options);

        dir = opendir("/sys/firmware/efi/efivars/");
        if (!dir)
                return -errno;

        FOREACH_DIRENT(de, dir, r = -errno; goto fail) {
                int id;
                uint16_t *t;

                if (strncmp(de->d_name, "Boot", 4) != 0)
                        continue;

                if (strlen(de->d_name) != 45)
                        continue;

                if (strcmp(de->d_name + 8, "-8be4df61-93ca-11d2-aa0d-00e098032b8c") != 0)
                        continue;

                id = boot_id_hex(de->d_name + 4);
                if (id < 0)
                        continue;

                t = realloc(list, (count + 1) * sizeof(uint16_t));
                if (!t) {
                        r = -ENOMEM;
                        goto fail;
                }

                list = t;
                list[count ++] = id;
        }

        qsort_safe(list, count, sizeof(uint16_t), cmp_uint16);

        *options = list;
        return count;

fail:
        free(list);
        return r;
}

static int read_usec(sd_id128_t vendor, const char *name, usec_t *u) {
        _cleanup_free_ char *j = NULL;
        int r;
        uint64_t x = 0;

        assert(name);
        assert(u);

        r = efi_get_variable_string(EFI_VENDOR_LOADER, name, &j);
        if (r < 0)
                return r;

        r = safe_atou64(j, &x);
        if (r < 0)
                return r;

        *u = x;
        return 0;
}

int efi_loader_get_boot_usec(usec_t *firmware, usec_t *loader) {
        uint64_t x, y;
        int r;

        assert(firmware);
        assert(loader);

        r = read_usec(EFI_VENDOR_LOADER, "LoaderTimeInitUSec", &x);
        if (r < 0)
                return r;

        r = read_usec(EFI_VENDOR_LOADER, "LoaderTimeExecUSec", &y);
        if (r < 0)
                return r;

        if (y == 0 || y < x)
                return -EIO;

        if (y > USEC_PER_HOUR)
                return -EIO;

        *firmware = x;
        *loader = y;

        return 0;
}

int efi_loader_get_device_part_uuid(sd_id128_t *u) {
        _cleanup_free_ char *p = NULL;
        int r, parsed[16];

        r = efi_get_variable_string(EFI_VENDOR_LOADER, "LoaderDevicePartUUID", &p);
        if (r < 0)
                return r;

        if (sscanf(p, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                   &parsed[0], &parsed[1], &parsed[2], &parsed[3],
                   &parsed[4], &parsed[5], &parsed[6], &parsed[7],
                   &parsed[8], &parsed[9], &parsed[10], &parsed[11],
                   &parsed[12], &parsed[13], &parsed[14], &parsed[15]) != 16)
                return -EIO;

        if (u) {
                unsigned i;

                for (i = 0; i < ELEMENTSOF(parsed); i++)
                        u->bytes[i] = parsed[i];
        }

        return 0;
}

#endif
