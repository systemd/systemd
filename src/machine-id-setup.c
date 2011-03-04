/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mount.h>

#include "machine-id-setup.h"
#include "macro.h"
#include "util.h"
#include "log.h"

static int generate(char id[34]) {
        int fd;
        char buf[16];
        char *p, *q;
        ssize_t k;

        assert(id);

        /* First, try reading the D-Bus machine id, unless it is a symlink */
        if ((fd = open("/var/lib/dbus/machine-id", O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW)) >= 0) {

                k = loop_read(fd, id, 33, false);
                close_nointr_nofail(fd);

                if (k >= 32) {
                        id[32] = '\n';
                        id[33] = 0;

                        log_info("Initializing machine ID from D-Bus machine ID.");
                        return 0;
                }
        }

        /* If that didn't work, generate a random machine id */
        if ((fd = open("/dev/urandom", O_RDONLY|O_CLOEXEC|O_NOCTTY)) < 0) {
                log_error("Failed to open /dev/urandom: %m");
                return -errno;
        }

        k = loop_read(fd, buf, sizeof(buf), false);
        close_nointr_nofail(fd);

        if (k != sizeof(buf)) {
                log_error("Failed to read /dev/urandom: %s", strerror(k < 0 ? -k : EIO));
                return k < 0 ? (int) k : -EIO;
        }

        for (p = buf, q = id; p < buf + sizeof(buf); p++, q += 2) {
                q[0] = hexchar(*p >> 4);
                q[1] = hexchar(*p & 15);
        }

        id[32] = '\n';
        id[33] = 0;

        log_info("Initializing machine ID from random generator.");

        return 0;
}

int machine_id_setup(void) {
        int fd, r;
        bool writable;
        struct stat st;
        char id[34]; /* 32 + \n + \0 */
        mode_t m;

        m = umask(0000);

        if ((fd = open("/etc/machine-id", O_RDWR|O_CREAT|O_CLOEXEC|O_NOCTTY, 0644)) >= 0)
                writable = true;
        else {
                if ((fd = open("/etc/machine-id", O_RDONLY|O_CLOEXEC|O_NOCTTY)) < 0) {
                        umask(m);
                        log_error("Cannot open /etc/machine-id: %m");
                        return -errno;
                }

                writable = false;
        }

        umask(m);

        if (fstat(fd, &st) < 0) {
                log_error("fstat() failed: %m");
                r = -errno;
                goto finish;
        }

        if (S_ISREG(st.st_mode)) {
                if (loop_read(fd, id, 32, false) >= 32) {
                        r = 0;
                        goto finish;
                }
        }

        /* Hmm, so, the id currently stored is not useful, then let's
         * generate one */

        if ((r = generate(id)) < 0)
                goto finish;

        if (S_ISREG(st.st_mode) && writable) {
                lseek(fd, 0, SEEK_SET);

                if (loop_write(fd, id, 33, false) == 33) {
                        r = 0;
                        goto finish;
                }
        }

        close_nointr_nofail(fd);
        fd = -1;

        /* Hmm, we couldn't write it? So let's write it to
         * /dev/.systemd/machine-id as a replacement */

        mkdir_p("/dev/.systemd", 0755);

        if ((r = write_one_line_file("/dev/.systemd/machine-id", id)) < 0) {
                log_error("Cannot write /dev/.systemd/machine-id: %s", strerror(-r));

                unlink("/dev/.systemd/machine-id");
                goto finish;
        }

        /* And now, let's mount it over */
        r = mount("/dev/.systemd/machine-id", "/etc/machine-id", "bind", MS_BIND|MS_RDONLY, NULL) < 0 ? -errno : 0;
        unlink("/dev/.systemd/machine-id");

        if (r < 0)
                log_error("Failed to mount /etc/machine-id: %s", strerror(-r));
        else
                log_info("Installed non-transient /etc/machine-id file.");

finish:

        if (fd >= 0)
                close_nointr_nofail(fd);

        return r;
}
