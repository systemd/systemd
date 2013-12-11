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
#include "fileio.h"
#include "bus-internal.h"
#include "bus-socket.h"
#include "bus-container.h"

int bus_container_connect(sd_bus *b) {
        _cleanup_free_ char *s = NULL, *ns = NULL, *root = NULL, *class = NULL;
        _cleanup_close_ int nsfd = -1, rootfd = -1;
        char *p;
        siginfo_t si;
        pid_t leader, child;
        int r;

        assert(b);
        assert(b->input_fd < 0);
        assert(b->output_fd < 0);

        p = strappenda("/run/systemd/machines/", b->machine);
        r = parse_env_file(p, NEWLINE, "LEADER", &s, "CLASS", &class, NULL);
        if (r == -ENOENT)
                return -EHOSTDOWN;
        if (r < 0)
                return r;
        if (!s)
                return -EIO;

        if (!streq_ptr(class, "container"))
                return -EIO;

        r = parse_pid(s, &leader);
        if (r < 0)
                return r;
        if (leader <= 1)
                return -EIO;

        r = asprintf(&ns, "/proc/%lu/ns/mnt", (unsigned long) leader);
        if (r < 0)
                return -ENOMEM;

        nsfd = open(ns, O_RDONLY|O_NOCTTY|O_CLOEXEC);
        if (nsfd < 0)
                return -errno;

        r = asprintf(&root, "/proc/%lu/root", (unsigned long) leader);
        if (r < 0)
                return -ENOMEM;

        rootfd = open(root, O_RDONLY|O_NOCTTY|O_CLOEXEC|O_DIRECTORY);
        if (rootfd < 0)
                return -errno;

        b->input_fd = socket(b->sockaddr.sa.sa_family, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (b->input_fd < 0)
                return -errno;

        b->output_fd = b->input_fd;

        r = bus_socket_setup(b);
        if (r < 0)
                return r;

        child = fork();
        if (child < 0)
                return -errno;

        if (child == 0) {
                r = setns(nsfd, CLONE_NEWNS);
                if (r < 0)
                        _exit(255);

                if (fchdir(rootfd) < 0)
                        _exit(255);

                if (chroot(".") < 0)
                        _exit(255);

                r = connect(b->input_fd, &b->sockaddr.sa, b->sockaddr_size);
                if (r < 0) {
                        if (errno == EINPROGRESS)
                                _exit(1);

                        _exit(255);
                }

                _exit(0);
        }

        r = wait_for_terminate(child, &si);
        if (r < 0)
                return r;

        if (si.si_code != CLD_EXITED)
                return -EIO;

        if (si.si_status == 1)
                return 1;

        if (si.si_status != 0)
                return -EIO;

        return bus_socket_start_auth(b);
}
