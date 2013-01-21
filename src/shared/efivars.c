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
#include <fcntl.h>

#include "util.h"
#include "utf8.h"
#include "efivars.h"

#define EFI_VENDOR_LOADER SD_ID128_MAKE(4a,67,b0,82,0a,4c,41,cf,b6,c7,44,0b,29,bb,8c,4f)

bool is_efiboot(void) {
        return access("/sys/firmware/efi", F_OK) >= 0;
}

int efi_get_variable(sd_id128_t vendor, const char *name, uint32_t *attribute, void **value, size_t *size) {
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
                return (int) n;
        if (n != sizeof(a))
                return -EIO;

        r = malloc(st.st_size - 4 + 2);
        if (!r)
                return -ENOMEM;

        n = read(fd, r, (size_t) st.st_size - 4);
        if (n < 0) {
                free(r);
                return (int) -n;
        }
        if (n != (ssize_t) st.st_size - 4) {
                free(r);
                return -EIO;
        }

        /* Always NUL terminate (2 bytes, to protect UTF-16) */
        ((char*) r)[st.st_size - 4] = 0;
        ((char*) r)[st.st_size - 4 + 1] = 0;

        *value = r;
        *size = (size_t) st.st_size;

        if (attribute)
                *attribute = a;

        return 0;
}

static int read_bogomips(unsigned long *u) {
        _cleanup_fclose_ FILE *f = NULL;

        f = fopen("/proc/cpuinfo", "re");
        if (!f)
                return -errno;

        while (!feof(f)) {
                char line[LINE_MAX];
                char *x;
                unsigned long a, b;

                if (!fgets(line, sizeof(line), f))
                        return -EIO;

                char_array_0(line);
                truncate_nl(line);

                if (!startswith(line, "bogomips"))
                        continue;

                x = line + 8;
                x += strspn(x, WHITESPACE);
                if (*x != ':')
                        continue;
                x++;
                x += strspn(x, WHITESPACE);

                if (sscanf(x, "%lu.%lu", &a, &b) != 2)
                        continue;

                *u = a * 1000000L + b * 10000L;
                return 0;
        }

        return -EIO;
}

static int read_ticks(sd_id128_t vendor, const char *name, unsigned long speed, usec_t *u) {
        _cleanup_free_ void *i = NULL;
        _cleanup_free_ char *j = NULL;
        size_t is;
        int r;
        uint64_t x;

        assert(name);
        assert(u);

        r = efi_get_variable(EFI_VENDOR_LOADER, name, NULL, &i, &is);
        if (r < 0)
                return r;

        j = utf16_to_utf8(i, is);
        if (!j)
                return -ENOMEM;

        r = safe_atou64(j, &x);
        if (r < 0)
                return r;

        *u = USEC_PER_SEC * x / speed;
        return 0;
}

static int get_boot_usec(usec_t *firmware, usec_t *loader) {
        uint64_t x, y;
        int r;
        unsigned long bogomips;

        assert(firmware);
        assert(loader);

        /* Returns the usec after the CPU was turned on. The two
         * timestamps are: the firmware finished, and the boot loader
         * finished. */

        /* We assume that the kernel's bogomips value is calibrated to
         * twice the CPU frequency, and use this to convert the TSC
         * ticks into usec. Of course, bogomips are only vaguely
         * defined. If this breaks one day we can come up with
         * something better. However, for now this saves us from doing
         * a local calibration loop. */

        r = read_bogomips(&bogomips);
        if (r < 0)
                return r;

        r = read_ticks(EFI_VENDOR_LOADER, "LoaderTicksInit", bogomips / 2, &x);
        if (r < 0)
                return r;

        r = read_ticks(EFI_VENDOR_LOADER, "LoaderTicksExec", bogomips / 2, &y);
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

int efi_get_boot_timestamps(const dual_timestamp *n, dual_timestamp *firmware, dual_timestamp *loader) {
        usec_t x, y, a;
        int r;
        dual_timestamp _n;

        assert(firmware);
        assert(loader);

        if (!n) {
                dual_timestamp_get(&_n);
                n = &_n;
        }

        r = get_boot_usec(&x, &y);
        if (r < 0)
                return r;

        /* Let's convert this to timestamps where the firmware
         * began/loader began working. To make this more confusing:
         * since usec_t is unsigned and the kernel's monotonic clock
         * begins at kernel initialization we'll actually initialize
         * the monotonic timestamps here as negative of the actual
         * value. */

        firmware->monotonic = y;
        loader->monotonic = y - x;

        a = n->monotonic + firmware->monotonic;
        firmware->realtime = n->realtime > a ? n->realtime - a : 0;

        a = n->monotonic + loader->monotonic;
        loader->realtime = n->realtime > a ? n->realtime - a : 0;

        return 0;
}

int efi_get_loader_device_part_uuid(sd_id128_t *u) {
        _cleanup_free_ void *s = NULL;
        _cleanup_free_ char *p = NULL;
        size_t ss;
        int r, parsed[16];
        unsigned i;

        assert(u);

        r = efi_get_variable(EFI_VENDOR_LOADER, "LoaderDevicePartUUID", NULL, &s, &ss);
        if (r < 0)
                return r;

        p = utf16_to_utf8(s, ss);
        if (!p)
                return -ENOMEM;

        if (sscanf(p, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                   &parsed[0], &parsed[1], &parsed[2], &parsed[3],
                   &parsed[4], &parsed[5], &parsed[6], &parsed[7],
                   &parsed[8], &parsed[9], &parsed[10], &parsed[11],
                   &parsed[12], &parsed[13], &parsed[14], &parsed[15]) != 16)
                return -EIO;

        for (i = 0; i < ELEMENTSOF(parsed); i++)
                u->bytes[i] = parsed[i];

        return 0;
}
