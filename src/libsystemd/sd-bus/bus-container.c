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
#include "process-util.h"
#include "bus-internal.h"
#include "bus-socket.h"
#include "bus-container.h"

int bus_container_connect_socket(sd_bus *b) {
        _cleanup_close_ int pidnsfd = -1, mntnsfd = -1, rootfd = -1;
        pid_t child;
        siginfo_t si;
        int r;

        assert(b);
        assert(b->input_fd < 0);
        assert(b->output_fd < 0);
        assert(b->nspid > 0 || b->machine);

        if (b->nspid <= 0) {
                r = container_get_leader(b->machine, &b->nspid);
                if (r < 0)
                        return r;
        }

        r = namespace_open(b->nspid, &pidnsfd, &mntnsfd, NULL, &rootfd);
        if (r < 0)
                return r;

        b->input_fd = socket(b->sockaddr.sa.sa_family, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (b->input_fd < 0)
                return -errno;

        b->output_fd = b->input_fd;

        bus_socket_setup(b);

        child = fork();
        if (child < 0)
                return -errno;

        if (child == 0) {
                pid_t grandchild;

                r = namespace_enter(pidnsfd, mntnsfd, -1, rootfd);
                if (r < 0)
                        _exit(255);

                /* We just changed PID namespace, however it will only
                 * take effect on the children we now fork. Hence,
                 * let's fork another time, and connect from this
                 * grandchild, so that SO_PEERCRED of our connection
                 * comes from a process from within the container, and
                 * not outside of it */

                grandchild = fork();
                if (grandchild < 0)
                        _exit(255);

                if (grandchild == 0) {

                        r = connect(b->input_fd, &b->sockaddr.sa, b->sockaddr_size);
                        if (r < 0) {
                                if (errno == EINPROGRESS)
                                        _exit(1);

                                _exit(255);
                        }

                        _exit(EXIT_SUCCESS);
                }

                r = wait_for_terminate(grandchild, &si);
                if (r < 0)
                        _exit(255);

                if (si.si_code != CLD_EXITED)
                        _exit(255);

                _exit(si.si_status);
        }

        r = wait_for_terminate(child, &si);
        if (r < 0)
                return r;

        if (si.si_code != CLD_EXITED)
                return -EIO;

        if (si.si_status == 1)
                return 1;

        if (si.si_status != EXIT_SUCCESS)
                return -EIO;

        return bus_socket_start_auth(b);
}

int bus_container_connect_kernel(sd_bus *b) {
        _cleanup_close_pair_ int pair[2] = { -1, -1 };
        _cleanup_close_ int pidnsfd = -1, mntnsfd = -1, rootfd = -1;
        union {
                struct cmsghdr cmsghdr;
                uint8_t buf[CMSG_SPACE(sizeof(int))];
        } control = {};
        struct msghdr mh = {
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        struct cmsghdr *cmsg;
        pid_t child;
        siginfo_t si;
        int r;
        _cleanup_close_ int fd = -1;

        assert(b);
        assert(b->input_fd < 0);
        assert(b->output_fd < 0);
        assert(b->nspid > 0 || b->machine);

        if (b->nspid <= 0) {
                r = container_get_leader(b->machine, &b->nspid);
                if (r < 0)
                        return r;
        }

        r = namespace_open(b->nspid, &pidnsfd, &mntnsfd, NULL, &rootfd);
        if (r < 0)
                return r;

        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) < 0)
                return -errno;

        child = fork();
        if (child < 0)
                return -errno;

        if (child == 0) {
                pid_t grandchild;

                pair[0] = safe_close(pair[0]);

                r = namespace_enter(pidnsfd, mntnsfd, -1, rootfd);
                if (r < 0)
                        _exit(EXIT_FAILURE);

                /* We just changed PID namespace, however it will only
                 * take effect on the children we now fork. Hence,
                 * let's fork another time, and connect from this
                 * grandchild, so that kdbus only sees the credentials
                 * of this process which comes from within the
                 * container, and not outside of it */

                grandchild = fork();
                if (grandchild < 0)
                        _exit(EXIT_FAILURE);

                if (grandchild == 0) {

                        fd = open(b->kernel, O_RDWR|O_NOCTTY|O_CLOEXEC);
                        if (fd < 0)
                                _exit(EXIT_FAILURE);

                        cmsg = CMSG_FIRSTHDR(&mh);
                        cmsg->cmsg_level = SOL_SOCKET;
                        cmsg->cmsg_type = SCM_RIGHTS;
                        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
                        memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

                        mh.msg_controllen = cmsg->cmsg_len;

                        if (sendmsg(pair[1], &mh, MSG_NOSIGNAL) < 0)
                                _exit(EXIT_FAILURE);

                        _exit(EXIT_SUCCESS);
                }

                r = wait_for_terminate(grandchild, &si);
                if (r < 0)
                        _exit(EXIT_FAILURE);

                if (si.si_code != CLD_EXITED)
                        _exit(EXIT_FAILURE);

                _exit(si.si_status);
        }

        pair[1] = safe_close(pair[1]);

        r = wait_for_terminate(child, &si);
        if (r < 0)
                return r;

        if (si.si_code != CLD_EXITED)
                return -EIO;

        if (si.si_status != EXIT_SUCCESS)
                return -EIO;

        if (recvmsg(pair[0], &mh, MSG_NOSIGNAL|MSG_CMSG_CLOEXEC) < 0)
                return -errno;

        for (cmsg = CMSG_FIRSTHDR(&mh); cmsg; cmsg = CMSG_NXTHDR(&mh, cmsg))
                if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
                        int *fds;
                        unsigned n_fds;

                        fds = (int*) CMSG_DATA(cmsg);
                        n_fds = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);

                        if (n_fds != 1) {
                                close_many(fds, n_fds);
                                return -EIO;
                        }

                        fd = fds[0];
                }

        b->input_fd = b->output_fd = fd;
        fd = -1;

        return bus_kernel_take_fd(b);
}
