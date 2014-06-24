/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mount.h>

#include <systemd/sd-id128.h>

#include "machine-id-setup.h"
#include "macro.h"
#include "util.h"
#include "mkdir.h"
#include "log.h"
#include "virt.h"
#include "fileio.h"
#include "path-util.h"

static int shorten_uuid(char destination[34], const char source[36]) {
        unsigned i, j;

        for (i = 0, j = 0; i < 36 && j < 32; i++) {
                int t;

                t = unhexchar(source[i]);
                if (t < 0)
                        continue;

                destination[j++] = hexchar(t);
        }

        if (i == 36 && j == 32) {
                destination[32] = '\n';
                destination[33] = 0;
                return 0;
        }

        return -EINVAL;
}

static int generate(char id[34], const char *root) {
        int fd, r;
        unsigned char *p;
        sd_id128_t buf;
        char *q;
        ssize_t k;
        const char *vm_id;
        _cleanup_free_ char *dbus_machine_id = NULL;

        assert(id);

        if (asprintf(&dbus_machine_id, "%s/var/lib/dbus/machine-id", root) < 0)
                return log_oom();

        /* First, try reading the D-Bus machine id, unless it is a symlink */
        fd = open(dbus_machine_id, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
        if (fd >= 0) {
                k = loop_read(fd, id, 33, false);
                safe_close(fd);

                if (k == 33 && id[32] == '\n') {

                        id[32] = 0;
                        if (id128_is_valid(id)) {
                                id[32] = '\n';
                                id[33] = 0;

                                log_info("Initializing machine ID from D-Bus machine ID.");
                                return 0;
                        }
                }
        }

        /* If that didn't work, see if we are running in a container,
         * and a machine ID was passed in via $container_uuid the way
         * libvirt/LXC does it */
        r = detect_container(NULL);
        if (r > 0) {
                _cleanup_free_ char *e = NULL;

                r = getenv_for_pid(1, "container_uuid", &e);
                if (r > 0) {
                        if (strlen(e) >= 36) {
                                r = shorten_uuid(id, e);
                                if (r >= 0) {
                                        log_info("Initializing machine ID from container UUID.");
                                        return 0;
                                }
                        }
                }

        } else {
                /* If we are not running in a container, see if we are
                 * running in qemu/kvm and a machine ID was passed in
                 * via -uuid on the qemu/kvm command line */

                r = detect_vm(&vm_id);
                if (r > 0 && streq(vm_id, "kvm")) {
                        char uuid[37];

                        fd = open("/sys/class/dmi/id/product_uuid", O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
                        if (fd >= 0) {
                                k = loop_read(fd, uuid, 36, false);
                                safe_close(fd);

                                if (k >= 36) {
                                        r = shorten_uuid(id, uuid);
                                        if (r >= 0) {
                                                log_info("Initializing machine ID from KVM UUID.");
                                                return 0;
                                        }
                                }
                        }
                }
        }

        /* If that didn't work, generate a random machine id */
        r = sd_id128_randomize(&buf);
        if (r < 0) {
                log_error("Failed to open /dev/urandom: %s", strerror(-r));
                return r;
        }

        for (p = buf.bytes, q = id; p < buf.bytes + sizeof(buf); p++, q += 2) {
                q[0] = hexchar(*p >> 4);
                q[1] = hexchar(*p & 15);
        }

        id[32] = '\n';
        id[33] = 0;

        log_info("Initializing machine ID from random generator.");

        return 0;
}

int machine_id_setup(const char *root) {
        const char *etc_machine_id, *run_machine_id;
        _cleanup_close_ int fd = -1;
        bool writable = false;
        struct stat st;
        char id[34]; /* 32 + \n + \0 */
        int r;

        if (isempty(root))  {
                etc_machine_id = "/etc/machine-id";
                run_machine_id = "/run/machine-id";
        } else {
                etc_machine_id = strappenda(root, "/etc/machine-id");
                path_kill_slashes((char*) etc_machine_id);

                run_machine_id = strappenda(root, "/run/machine-id");
                path_kill_slashes((char*) run_machine_id);
        }

        RUN_WITH_UMASK(0000) {
                /* We create this 0444, to indicate that this isn't really
                 * something you should ever modify. Of course, since the file
                 * will be owned by root it doesn't matter much, but maybe
                 * people look. */

                mkdir_parents(etc_machine_id, 0755);
                fd = open(etc_machine_id, O_RDWR|O_CREAT|O_CLOEXEC|O_NOCTTY, 0444);
                if (fd >= 0)
                        writable = true;
                else {
                        fd = open(etc_machine_id, O_RDONLY|O_CLOEXEC|O_NOCTTY);
                        if (fd < 0) {
                                log_error("Cannot open %s: %m", etc_machine_id);
                                return -errno;
                        }

                        writable = false;
                }
        }

        if (fstat(fd, &st) < 0) {
                log_error("fstat() failed: %m");
                return -errno;
        }

        if (S_ISREG(st.st_mode))
                if (loop_read(fd, id, 33, false) == 33 && id[32] == '\n') {
                        id[32] = 0;

                        if (id128_is_valid(id))
                                return 0;
                }

        /* Hmm, so, the id currently stored is not useful, then let's
         * generate one */

        r = generate(id, root);
        if (r < 0)
                return r;

        if (S_ISREG(st.st_mode) && writable) {
                lseek(fd, 0, SEEK_SET);

                if (loop_write(fd, id, 33, false) == 33)
                        return 0;
        }

        fd = safe_close(fd);

        /* Hmm, we couldn't write it? So let's write it to
         * /run/machine-id as a replacement */

        RUN_WITH_UMASK(0022) {
                r = write_string_file(run_machine_id, id);
        }
        if (r < 0) {
                log_error("Cannot write %s: %s", run_machine_id, strerror(-r));
                unlink(run_machine_id);
                return r;
        }

        /* And now, let's mount it over */
        r = mount(run_machine_id, etc_machine_id, NULL, MS_BIND, NULL);
        if (r < 0) {
                log_error("Failed to mount %s: %m", etc_machine_id);
                unlink_noerrno(run_machine_id);
                return -errno;
        }

        log_info("Installed transient %s file.", etc_machine_id);

        /* Mark the mount read-only */
        if (mount(NULL, etc_machine_id, NULL, MS_BIND|MS_RDONLY|MS_REMOUNT, NULL) < 0)
                log_warning("Failed to make transient %s read-only: %m", etc_machine_id);

        return 0;
}
