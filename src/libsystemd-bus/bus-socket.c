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

#include <endian.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/poll.h>
#include <byteswap.h>

#include "util.h"
#include "macro.h"
#include "missing.h"
#include "strv.h"

#include "sd-bus.h"
#include "bus-socket.h"
#include "bus-internal.h"
#include "bus-message.h"

static void iovec_advance(struct iovec *iov, unsigned *idx, size_t size) {

        while (size > 0) {
                struct iovec *i = iov + *idx;

                if (i->iov_len > size) {
                        i->iov_base = (uint8_t*) i->iov_base + size;
                        i->iov_len -= size;
                        return;
                }

                size -= i->iov_len;

                i->iov_base = NULL;
                i->iov_len = 0;

                (*idx) ++;
        }
}

static int bus_socket_write_auth(sd_bus *b) {
        struct msghdr mh;
        ssize_t k;

        assert(b);
        assert(b->state == BUS_AUTHENTICATING);

        if (b->auth_index >= ELEMENTSOF(b->auth_iovec))
                return 0;

        if (b->auth_timeout == 0)
                b->auth_timeout = now(CLOCK_MONOTONIC) + BUS_DEFAULT_TIMEOUT;

        zero(mh);
        mh.msg_iov = b->auth_iovec + b->auth_index;
        mh.msg_iovlen = ELEMENTSOF(b->auth_iovec) - b->auth_index;

        k = sendmsg(b->fd, &mh, MSG_DONTWAIT|MSG_NOSIGNAL);
        if (k < 0)
                return errno == EAGAIN ? 0 : -errno;

        iovec_advance(b->auth_iovec, &b->auth_index, (size_t) k);

        return 1;
}

static int bus_socket_auth_verify(sd_bus *b) {
        char *e, *f, *start;
        sd_id128_t peer;
        unsigned i;
        int r;

        /* We expect two response lines: "OK" and possibly
         * "AGREE_UNIX_FD" */

        e = memmem(b->rbuffer, b->rbuffer_size, "\r\n", 2);
        if (!e)
                return 0;

        if (b->negotiate_fds) {
                f = memmem(e + 2, b->rbuffer_size - (e - (char*) b->rbuffer) - 2, "\r\n", 2);
                if (!f)
                        return 0;

                start = f + 2;
        } else {
                f = NULL;
                start = e + 2;
        }

        /* Nice! We got all the lines we need. First check the OK
         * line */

        if (e - (char*) b->rbuffer != 3 + 32)
                return -EPERM;

        if (memcmp(b->rbuffer, "OK ", 3))
                return -EPERM;

        for (i = 0; i < 32; i += 2) {
                int x, y;

                x = unhexchar(((char*) b->rbuffer)[3 + i]);
                y = unhexchar(((char*) b->rbuffer)[3 + i + 1]);

                if (x < 0 || y < 0)
                        return -EINVAL;

                peer.bytes[i/2] = ((uint8_t) x << 4 | (uint8_t) y);
        }

        if (!sd_id128_equal(b->peer, SD_ID128_NULL) &&
            !sd_id128_equal(b->peer, peer))
                return -EPERM;

        b->peer = peer;

        /* And possibly check the second line, too */

        if (f)
                b->can_fds =
                        (f - e == sizeof("\r\nAGREE_UNIX_FD") - 1) &&
                        memcmp(e + 2, "AGREE_UNIX_FD", sizeof("AGREE_UNIX_FD") - 1) == 0;

        b->rbuffer_size -= (start - (char*) b->rbuffer);
        memmove(b->rbuffer, start, b->rbuffer_size);

        r = bus_start_running(b);
        if (r < 0)
                return r;

        return 1;
}

static int bus_socket_read_auth(sd_bus *b) {
        struct msghdr mh;
        struct iovec iov;
        size_t n;
        ssize_t k;
        int r;
        void *p;

        assert(b);

        r = bus_socket_auth_verify(b);
        if (r != 0)
                return r;

        n = MAX(3 + 32 + 2 + sizeof("AGREE_UNIX_FD") - 1 + 2, b->rbuffer_size * 2);

        if (n > BUS_AUTH_SIZE_MAX)
                n = BUS_AUTH_SIZE_MAX;

        if (b->rbuffer_size >= n)
                return -ENOBUFS;

        p = realloc(b->rbuffer, n);
        if (!p)
                return -ENOMEM;

        b->rbuffer = p;

        zero(iov);
        iov.iov_base = (uint8_t*) b->rbuffer + b->rbuffer_size;
        iov.iov_len = n - b->rbuffer_size;

        zero(mh);
        mh.msg_iov = &iov;
        mh.msg_iovlen = 1;

        k = recvmsg(b->fd, &mh, MSG_DONTWAIT|MSG_NOSIGNAL);
        if (k < 0)
                return errno == EAGAIN ? 0 : -errno;
        if (k == 0)
                return -ECONNRESET;

        b->rbuffer_size += k;

        r = bus_socket_auth_verify(b);
        if (r != 0)
                return r;

        return 1;
}

static int bus_socket_setup(sd_bus *b) {
        int one;

        assert(b);

        /* Enable SO_PASSCRED + SO_PASSEC. We try this on any socket,
         * just in case. This is actually irrelavant for */
        one = 1;
        setsockopt(b->fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one));
        setsockopt(b->fd, SOL_SOCKET, SO_PASSSEC, &one, sizeof(one));

        /* Increase the buffers to a MB */
        fd_inc_rcvbuf(b->fd, 1024*1024);
        fd_inc_sndbuf(b->fd, 1024*1024);

        return 0;
}

static int bus_socket_start_auth(sd_bus *b) {
        static const char auth_prefix[] = "\0AUTH EXTERNAL ";
        static const char auth_suffix_with_unix_fd[] = "\r\nNEGOTIATE_UNIX_FD\r\nBEGIN\r\n";
        static const char auth_suffix_without_unix_fd[] = "\r\nBEGIN\r\n";

        char text[20 + 1]; /* enough space for a 64bit integer plus NUL */
        size_t l;
        const char *auth_suffix;
        int domain = 0, r;
        socklen_t sl;

        assert(b);

        b->state = BUS_AUTHENTICATING;

        sl = sizeof(domain);
        r = getsockopt(b->fd, SOL_SOCKET, SO_DOMAIN, &domain, &sl);
        if (r < 0)
                return -errno;

        if (domain != AF_UNIX)
                b->negotiate_fds = false;

        snprintf(text, sizeof(text), "%llu", (unsigned long long) geteuid());
        char_array_0(text);

        l = strlen(text);
        b->auth_uid = hexmem(text, l);
        if (!b->auth_uid)
                return -ENOMEM;

        auth_suffix = b->negotiate_fds ? auth_suffix_with_unix_fd : auth_suffix_without_unix_fd;

        b->auth_iovec[0].iov_base = (void*) auth_prefix;
        b->auth_iovec[0].iov_len = sizeof(auth_prefix) -1;
        b->auth_iovec[1].iov_base = (void*) b->auth_uid;
        b->auth_iovec[1].iov_len = l * 2;
        b->auth_iovec[2].iov_base = (void*) auth_suffix;
        b->auth_iovec[2].iov_len = strlen(auth_suffix);
        b->auth_size = sizeof(auth_prefix) - 1 + l * 2 + sizeof(auth_suffix) - 1;

        return bus_socket_write_auth(b);
}

int bus_socket_connect(sd_bus *b) {
        int r;

        assert(b);
        assert(b->fd < 0);
        assert(b->sockaddr.sa.sa_family != AF_UNSPEC);

        b->fd = socket(b->sockaddr.sa.sa_family, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (b->fd < 0)
                return -errno;

        r = bus_socket_setup(b);
        if (r < 0)
                return r;

        r = connect(b->fd, &b->sockaddr.sa, b->sockaddr_size);
        if (r < 0) {
                if (errno == EINPROGRESS)
                        return 1;

                return -errno;
        }

        return bus_socket_start_auth(b);
}

int bus_socket_exec(sd_bus *b) {
        int s[2];
        pid_t pid;

        assert(b);
        assert(b->fd < 0);
        assert(b->exec_path);

        b->fd = socketpair(AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0, s);
        if (b->fd < 0)
                return -errno;

        pid = fork();
        if (pid < 0) {
                close_pipe(s);
                return -errno;
        }
        if (pid == 0) {
                /* Child */

                close_all_fds(s, 2);
                close_nointr_nofail(s[0]);

                assert_se(dup3(s[1], STDIN_FILENO, 0) == STDIN_FILENO);
                assert_se(dup3(s[1], STDOUT_FILENO, 0) == STDOUT_FILENO);

                if (s[1] != STDIN_FILENO && s[1] != STDOUT_FILENO)
                        close_nointr_nofail(s[1]);

                fd_cloexec(STDIN_FILENO, false);
                fd_cloexec(STDOUT_FILENO, false);
                fd_nonblock(STDIN_FILENO, false);
                fd_nonblock(STDOUT_FILENO, false);

                if (b->exec_argv)
                        execvp(b->exec_path, b->exec_argv);
                else {
                        const char *argv[] = { b->exec_path, NULL };
                        execvp(b->exec_path, (char**) argv);
                }

                _exit(EXIT_FAILURE);
        }

        close_nointr_nofail(s[1]);
        b->fd = s[0];

        return bus_socket_start_auth(b);
}

int bus_socket_take_fd(sd_bus *b) {
        int  r;
        assert(b);

        r = bus_socket_setup(b);
        if (r < 0)
                return r;

        return bus_socket_start_auth(b);
}

int bus_socket_write_message(sd_bus *bus, sd_bus_message *m, size_t *idx) {
        struct msghdr mh;
        struct iovec *iov;
        ssize_t k;
        size_t n;
        unsigned j;

        assert(bus);
        assert(m);
        assert(idx);
        assert(bus->state == BUS_RUNNING || bus->state == BUS_HELLO);

        if (*idx >= m->size)
                return 0;
        zero(mh);

        if (m->n_fds > 0) {
                struct cmsghdr *control;
                control = alloca(CMSG_SPACE(sizeof(int) * m->n_fds));

                mh.msg_control = control;
                control->cmsg_level = SOL_SOCKET;
                control->cmsg_type = SCM_RIGHTS;
                mh.msg_controllen = control->cmsg_len = CMSG_LEN(sizeof(int) * m->n_fds);
                memcpy(CMSG_DATA(control), m->fds, sizeof(int) * m->n_fds);
        }

        n = m->n_iovec * sizeof(struct iovec);
        iov = alloca(n);
        memcpy(iov, m->iovec, n);

        j = 0;
        iovec_advance(iov, &j, *idx);

        mh.msg_iov = iov;
        mh.msg_iovlen = m->n_iovec;

        k = sendmsg(bus->fd, &mh, MSG_DONTWAIT|MSG_NOSIGNAL);
        if (k < 0)
                return errno == EAGAIN ? 0 : -errno;

        *idx += (size_t) k;
        return 1;
}

static int bus_socket_read_message_need(sd_bus *bus, size_t *need) {
        uint32_t a, b;
        uint8_t e;
        uint64_t sum;

        assert(bus);
        assert(need);
        assert(bus->state == BUS_RUNNING || bus->state == BUS_HELLO);

        if (bus->rbuffer_size < sizeof(struct bus_header)) {
                *need = sizeof(struct bus_header) + 8;

                /* Minimum message size:
                 *
                 * Header +
                 *
                 *  Method Call: +2 string headers
                 *       Signal: +3 string headers
                 * Method Error: +1 string headers
                 *               +1 uint32 headers
                 * Method Reply: +1 uint32 headers
                 *
                 * A string header is at least 9 bytes
                 * A uint32 header is at least 8 bytes
                 *
                 * Hence the minimum message size of a valid message
                 * is header + 8 bytes */

                return 0;
        }

        a = ((const uint32_t*) bus->rbuffer)[1];
        b = ((const uint32_t*) bus->rbuffer)[3];

        e = ((const uint8_t*) bus->rbuffer)[0];
        if (e == SD_BUS_LITTLE_ENDIAN) {
                a = le32toh(a);
                b = le32toh(b);
        } else if (e == SD_BUS_BIG_ENDIAN) {
                a = be32toh(a);
                b = be32toh(b);
        } else
                return -EBADMSG;

        sum = (uint64_t) sizeof(struct bus_header) + (uint64_t) ALIGN_TO(b, 8) + (uint64_t) a;
        if (sum >= BUS_MESSAGE_SIZE_MAX)
                return -ENOBUFS;

        *need = (size_t) sum;
        return 0;
}

static int bus_socket_make_message(sd_bus *bus, size_t size, sd_bus_message **m) {
        sd_bus_message *t;
        void *b;
        int r;

        assert(bus);
        assert(m);
        assert(bus->rbuffer_size >= size);
        assert(bus->state == BUS_RUNNING || bus->state == BUS_HELLO);

        if (bus->rbuffer_size > size) {
                b = memdup((const uint8_t*) bus->rbuffer + size,
                           bus->rbuffer_size - size);
                if (!b)
                        return -ENOMEM;
        } else
                b = NULL;

        r = bus_message_from_malloc(bus->rbuffer, size,
                                    bus->fds, bus->n_fds,
                                    bus->ucred_valid ? &bus->ucred : NULL,
                                    bus->label[0] ? bus->label : NULL,
                                    &t);
        if (r < 0) {
                free(b);
                return r;
        }

        bus->rbuffer = b;
        bus->rbuffer_size -= size;

        bus->fds = NULL;
        bus->n_fds = 0;

        *m = t;
        return 1;
}

int bus_socket_read_message(sd_bus *bus, sd_bus_message **m) {
        struct msghdr mh;
        struct iovec iov;
        ssize_t k;
        size_t need;
        int r;
        void *b;
        union {
                struct cmsghdr cmsghdr;
                uint8_t buf[CMSG_SPACE(sizeof(int) * BUS_FDS_MAX) +
                            CMSG_SPACE(sizeof(struct ucred)) +
                            CMSG_SPACE(NAME_MAX)]; /*selinux label */
        } control;
        struct cmsghdr *cmsg;

        assert(bus);
        assert(m);
        assert(bus->state == BUS_RUNNING || bus->state == BUS_HELLO);

        r = bus_socket_read_message_need(bus, &need);
        if (r < 0)
                return r;

        if (bus->rbuffer_size >= need)
                return bus_socket_make_message(bus, need, m);

        b = realloc(bus->rbuffer, need);
        if (!b)
                return -ENOMEM;

        bus->rbuffer = b;

        zero(iov);
        iov.iov_base = (uint8_t*) bus->rbuffer + bus->rbuffer_size;
        iov.iov_len = need - bus->rbuffer_size;

        zero(mh);
        mh.msg_iov = &iov;
        mh.msg_iovlen = 1;
        mh.msg_control = &control;
        mh.msg_controllen = sizeof(control);

        k = recvmsg(bus->fd, &mh, MSG_DONTWAIT|MSG_NOSIGNAL|MSG_CMSG_CLOEXEC);
        if (k < 0)
                return errno == EAGAIN ? 0 : -errno;
        if (k == 0)
                return -ECONNRESET;

        bus->rbuffer_size += k;

        for (cmsg = CMSG_FIRSTHDR(&mh); cmsg; cmsg = CMSG_NXTHDR(&mh, cmsg)) {
                if (cmsg->cmsg_level == SOL_SOCKET &&
                    cmsg->cmsg_type == SCM_RIGHTS) {
                        int n, *f;

                        n = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);

                        f = realloc(bus->fds, sizeof(int) + (bus->n_fds + n));
                        if (!f) {
                                close_many((int*) CMSG_DATA(cmsg), n);
                                return -ENOMEM;
                        }

                        memcpy(f + bus->n_fds, CMSG_DATA(cmsg), n * sizeof(int));
                        bus->fds = f;
                        bus->n_fds += n;
                } else if (cmsg->cmsg_level == SOL_SOCKET &&
                    cmsg->cmsg_type == SCM_CREDENTIALS &&
                    cmsg->cmsg_len == CMSG_LEN(sizeof(struct ucred))) {

                        memcpy(&bus->ucred, CMSG_DATA(cmsg), sizeof(struct ucred));
                        bus->ucred_valid = true;

                } else if (cmsg->cmsg_level == SOL_SOCKET &&
                         cmsg->cmsg_type == SCM_SECURITY) {

                        size_t l;
                        l = cmsg->cmsg_len - CMSG_LEN(0);
                        memcpy(&bus->label, CMSG_DATA(cmsg), l);
                        bus->label[l] = 0;
                }
        }

        r = bus_socket_read_message_need(bus, &need);
        if (r < 0)
                return r;

        if (bus->rbuffer_size >= need)
                return bus_socket_make_message(bus, need, m);

        return 1;
}

int bus_socket_process_opening(sd_bus *b) {
        int error = 0;
        socklen_t slen = sizeof(error);
        struct pollfd p;
        int r;

        assert(b);
        assert(b->state == BUS_OPENING);

        zero(p);
        p.fd = b->fd;
        p.events = POLLOUT;

        r = poll(&p, 1, 0);
        if (r < 0)
                return -errno;

        if (!(p.revents & (POLLOUT|POLLERR|POLLHUP)))
                return 0;

        r = getsockopt(b->fd, SOL_SOCKET, SO_ERROR, &error, &slen);
        if (r < 0)
                b->last_connect_error = errno;
        else if (error != 0)
                b->last_connect_error = error;
        else if (p.revents & (POLLERR|POLLHUP))
                b->last_connect_error = ECONNREFUSED;
        else
                return bus_socket_start_auth(b);

        return bus_next_address(b);
}

int bus_socket_process_authenticating(sd_bus *b) {
        int r;

        assert(b);
        assert(b->state == BUS_AUTHENTICATING);

        if (now(CLOCK_MONOTONIC) >= b->auth_timeout)
                return -ETIMEDOUT;

        r = bus_socket_write_auth(b);
        if (r != 0)
                return r;

        return bus_socket_read_auth(b);
}
