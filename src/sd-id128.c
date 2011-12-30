/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "sd-id128.h"
#include "util.h"
#include "macro.h"

char *sd_id128_to_string(sd_id128_t id, char s[33]) {
        unsigned n;

        assert(s);

        for (n = 0; n < 16; n++) {
                s[n*2] = hexchar(id.bytes[n] >> 4);
                s[n*2+1] = hexchar(id.bytes[n] & 0xF);
        }

        s[32] = 0;

        return s;
}

int sd_id128_from_string(const char s[33], sd_id128_t *ret) {
        unsigned n;
        sd_id128_t t;

        assert(s);
        assert(ret);

        for (n = 0; n < 16; n++) {
                int a, b;

                a = unhexchar(s[n*2]);
                if (a < 0)
                        return -EINVAL;

                b = unhexchar(s[n*2+1]);
                if (b < 0)
                        return -EINVAL;

                t.bytes[n] = (a << 4) | b;
        }

        if (s[32] != 0)
                return -EINVAL;

        *ret = t;
        return 0;
}

sd_id128_t sd_id128_make_v4_uuid(sd_id128_t id) {
        /* Stolen from generate_random_uuid() of drivers/char/random.c
         * in the kernel sources */

        /* Set UUID version to 4 --- truly random generation */
        id.bytes[6] = (id.bytes[6] & 0x0F) | 0x40;

        /* Set the UUID variant to DCE */
        id.bytes[8] = (id.bytes[8] & 0x3F) | 0x80;

        return id;
}

int sd_id128_get_machine(sd_id128_t *ret) {
        static __thread sd_id128_t saved_machine_id;
        static __thread bool saved_machine_id_valid = false;
        int fd;
        char buf[32];
        ssize_t k;
        unsigned j;
        sd_id128_t t;

        if (saved_machine_id_valid) {
                *ret = saved_machine_id;
                return 0;
        }

        fd = open("/etc/machine-id", O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0)
                return -errno;

        k = loop_read(fd, buf, 32, false);
        close_nointr_nofail(fd);

        if (k < 0)
                return (int) k;

        if (k < 32)
                return -EIO;

        for (j = 0; j < 16; j++) {
                int a, b;

                a = unhexchar(buf[j*2]);
                b = unhexchar(buf[j*2+1]);

                if (a < 0 || b < 0)
                        return -EIO;

                t.bytes[j] = a << 4 | b;
        }

        saved_machine_id = t;
        saved_machine_id_valid = true;

        *ret = t;
        return 0;
}

int sd_id128_get_boot(sd_id128_t *ret) {
        static __thread sd_id128_t saved_boot_id;
        static __thread bool saved_boot_id_valid = false;
        int fd;
        char buf[36];
        ssize_t k;
        unsigned j;
        sd_id128_t t;
        char *p;

        if (saved_boot_id_valid) {
                *ret = saved_boot_id;
                return 0;
        }

        fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0)
                return -errno;

        k = loop_read(fd, buf, 36, false);
        close_nointr_nofail(fd);

        if (k < 0)
                return (int) k;

        if (k < 36)
                return -EIO;

        for (j = 0, p = buf; j < 16; j++) {
                int a, b;

                if (*p == '-')
                        p++;

                a = unhexchar(p[0]);
                b = unhexchar(p[1]);

                if (a < 0 || b < 0)
                        return -EIO;

                t.bytes[j] = a << 4 | b;

                p += 2;
        }

        saved_boot_id = t;
        saved_boot_id_valid = true;

        *ret = t;
        return 0;
}

int sd_id128_randomize(sd_id128_t *ret) {
        int fd;
        ssize_t k;
        sd_id128_t t;

        assert(ret);

        fd = open("/dev/urandom", O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0)
                return -errno;

        k = loop_read(fd, &t, 16, false);
        close_nointr_nofail(fd);

        if (k < 0)
                return (int) k;

        if (k < 16)
                return -EIO;

        /* Turn this into a valid v4 UUID, to be nice. Note that we
         * only guarantee this for newly generated UUIDs, not for
         * pre-existing ones.*/

        *ret = sd_id128_make_v4_uuid(t);
        return 0;
}
