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
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>

#include "sd-daemon.h"
#include "util.h"
#include "macro.h"
#include "missing.h"
#include "utf8.h"
#include "formats-util.h"
#include "signal-util.h"

#include "sd-bus.h"
#include "bus-socket.h"
#include "bus-internal.h"
#include "bus-message.h"

#define SNDBUF_SIZE (8*1024*1024)

static void iovec_advance(struct iovec iov[], unsigned *idx, size_t size) {

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

static int append_iovec(sd_bus_message *m, const void *p, size_t sz) {
        assert(m);
        assert(p);
        assert(sz > 0);

        m->iovec[m->n_iovec].iov_base = (void*) p;
        m->iovec[m->n_iovec].iov_len = sz;
        m->n_iovec++;

        return 0;
}

static int bus_message_setup_iovec(sd_bus_message *m) {
        struct bus_body_part *part;
        unsigned n, i;
        int r;

        assert(m);
        assert(m->sealed);

        if (m->n_iovec > 0)
                return 0;

        assert(!m->iovec);

        n = 1 + m->n_body_parts;
        if (n < ELEMENTSOF(m->iovec_fixed))
                m->iovec = m->iovec_fixed;
        else {
                m->iovec = new(struct iovec, n);
                if (!m->iovec) {
                        r = -ENOMEM;
                        goto fail;
                }
        }

        r = append_iovec(m, m->header, BUS_MESSAGE_BODY_BEGIN(m));
        if (r < 0)
                goto fail;

        MESSAGE_FOREACH_PART(part, i, m)  {
                r = bus_body_part_map(part);
                if (r < 0)
                        goto fail;

                r = append_iovec(m, part->data, part->size);
                if (r < 0)
                        goto fail;
        }

        assert(n == m->n_iovec);

        return 0;

fail:
        m->poisoned = true;
        return r;
}

bool bus_socket_auth_needs_write(sd_bus *b) {

        unsigned i;

        if (b->auth_index >= ELEMENTSOF(b->auth_iovec))
                return false;

        for (i = b->auth_index; i < ELEMENTSOF(b->auth_iovec); i++) {
                struct iovec *j = b->auth_iovec + i;

                if (j->iov_len > 0)
                        return true;
        }

        return false;
}

static int bus_socket_write_auth(sd_bus *b) {
        ssize_t k;

        assert(b);
        assert(b->state == BUS_AUTHENTICATING);

        if (!bus_socket_auth_needs_write(b))
                return 0;

        if (b->prefer_writev)
                k = writev(b->output_fd, b->auth_iovec + b->auth_index, ELEMENTSOF(b->auth_iovec) - b->auth_index);
        else {
                struct msghdr mh;
                zero(mh);

                mh.msg_iov = b->auth_iovec + b->auth_index;
                mh.msg_iovlen = ELEMENTSOF(b->auth_iovec) - b->auth_index;

                k = sendmsg(b->output_fd, &mh, MSG_DONTWAIT|MSG_NOSIGNAL);
                if (k < 0 && errno == ENOTSOCK) {
                        b->prefer_writev = true;
                        k = writev(b->output_fd, b->auth_iovec + b->auth_index, ELEMENTSOF(b->auth_iovec) - b->auth_index);
                }
        }

        if (k < 0)
                return errno == EAGAIN ? 0 : -errno;

        iovec_advance(b->auth_iovec, &b->auth_index, (size_t) k);
        return 1;
}

static int bus_socket_auth_verify_client(sd_bus *b) {
        char *e, *f, *start;
        sd_id128_t peer;
        unsigned i;
        int r;

        assert(b);

        /* We expect two response lines: "OK" and possibly
         * "AGREE_UNIX_FD" */

        e = memmem_safe(b->rbuffer, b->rbuffer_size, "\r\n", 2);
        if (!e)
                return 0;

        if (b->hello_flags & KDBUS_HELLO_ACCEPT_FD) {
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

        b->auth = b->anonymous_auth ? BUS_AUTH_ANONYMOUS : BUS_AUTH_EXTERNAL;

        for (i = 0; i < 32; i += 2) {
                int x, y;

                x = unhexchar(((char*) b->rbuffer)[3 + i]);
                y = unhexchar(((char*) b->rbuffer)[3 + i + 1]);

                if (x < 0 || y < 0)
                        return -EINVAL;

                peer.bytes[i/2] = ((uint8_t) x << 4 | (uint8_t) y);
        }

        if (!sd_id128_equal(b->server_id, SD_ID128_NULL) &&
            !sd_id128_equal(b->server_id, peer))
                return -EPERM;

        b->server_id = peer;

        /* And possibly check the second line, too */

        if (f)
                b->can_fds =
                        (f - e == strlen("\r\nAGREE_UNIX_FD")) &&
                        memcmp(e + 2, "AGREE_UNIX_FD", strlen("AGREE_UNIX_FD")) == 0;

        b->rbuffer_size -= (start - (char*) b->rbuffer);
        memmove(b->rbuffer, start, b->rbuffer_size);

        r = bus_start_running(b);
        if (r < 0)
                return r;

        return 1;
}

static bool line_equals(const char *s, size_t m, const char *line) {
        size_t l;

        l = strlen(line);
        if (l != m)
                return false;

        return memcmp(s, line, l) == 0;
}

static bool line_begins(const char *s, size_t m, const char *word) {
        size_t l;

        l = strlen(word);
        if (m < l)
                return false;

        if (memcmp(s, word, l) != 0)
                return false;

        return m == l || (m > l && s[l] == ' ');
}

static int verify_anonymous_token(sd_bus *b, const char *p, size_t l) {
        _cleanup_free_ char *token = NULL;
        size_t len;
        int r;

        if (!b->anonymous_auth)
                return 0;

        if (l <= 0)
                return 1;

        assert(p[0] == ' ');
        p++; l--;

        if (l % 2 != 0)
                return 0;

        r = unhexmem(p, l, (void **) &token, &len);
        if (r < 0)
                return 0;

        if (memchr(token, 0, len))
                return 0;

        return !!utf8_is_valid(token);
}

static int verify_external_token(sd_bus *b, const char *p, size_t l) {
        _cleanup_free_ char *token = NULL;
        size_t len;
        uid_t u;
        int r;

        /* We don't do any real authentication here. Instead, we if
         * the owner of this bus wanted authentication he should have
         * checked SO_PEERCRED before even creating the bus object. */

        if (!b->anonymous_auth && !b->ucred_valid)
                return 0;

        if (l <= 0)
                return 1;

        assert(p[0] == ' ');
        p++; l--;

        if (l % 2 != 0)
                return 0;

        r = unhexmem(p, l, (void**) &token, &len);
        if (r < 0)
                return 0;

        if (memchr(token, 0, len))
                return 0;

        r = parse_uid(token, &u);
        if (r < 0)
                return 0;

        /* We ignore the passed value if anonymous authentication is
         * on anyway. */
        if (!b->anonymous_auth && u != b->ucred.uid)
                return 0;

        return 1;
}

static int bus_socket_auth_write(sd_bus *b, const char *t) {
        char *p;
        size_t l;

        assert(b);
        assert(t);

        /* We only make use of the first iovec */
        assert(b->auth_index == 0 || b->auth_index == 1);

        l = strlen(t);
        p = malloc(b->auth_iovec[0].iov_len + l);
        if (!p)
                return -ENOMEM;

        memcpy(p, b->auth_iovec[0].iov_base, b->auth_iovec[0].iov_len);
        memcpy(p + b->auth_iovec[0].iov_len, t, l);

        b->auth_iovec[0].iov_base = p;
        b->auth_iovec[0].iov_len += l;

        free(b->auth_buffer);
        b->auth_buffer = p;
        b->auth_index = 0;
        return 0;
}

static int bus_socket_auth_write_ok(sd_bus *b) {
        char t[3 + 32 + 2 + 1];

        assert(b);

        xsprintf(t, "OK " SD_ID128_FORMAT_STR "\r\n", SD_ID128_FORMAT_VAL(b->server_id));

        return bus_socket_auth_write(b, t);
}

static int bus_socket_auth_verify_server(sd_bus *b) {
        char *e;
        const char *line;
        size_t l;
        bool processed = false;
        int r;

        assert(b);

        if (b->rbuffer_size < 1)
                return 0;

        /* First char must be a NUL byte */
        if (*(char*) b->rbuffer != 0)
                return -EIO;

        if (b->rbuffer_size < 3)
                return 0;

        /* Begin with the first line */
        if (b->auth_rbegin <= 0)
                b->auth_rbegin = 1;

        for (;;) {
                /* Check if line is complete */
                line = (char*) b->rbuffer + b->auth_rbegin;
                e = memmem(line, b->rbuffer_size - b->auth_rbegin, "\r\n", 2);
                if (!e)
                        return processed;

                l = e - line;

                if (line_begins(line, l, "AUTH ANONYMOUS")) {

                        r = verify_anonymous_token(b, line + 14, l - 14);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                r = bus_socket_auth_write(b, "REJECTED\r\n");
                        else {
                                b->auth = BUS_AUTH_ANONYMOUS;
                                r = bus_socket_auth_write_ok(b);
                        }

                } else if (line_begins(line, l, "AUTH EXTERNAL")) {

                        r = verify_external_token(b, line + 13, l - 13);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                r = bus_socket_auth_write(b, "REJECTED\r\n");
                        else {
                                b->auth = BUS_AUTH_EXTERNAL;
                                r = bus_socket_auth_write_ok(b);
                        }

                } else if (line_begins(line, l, "AUTH"))
                        r = bus_socket_auth_write(b, "REJECTED EXTERNAL ANONYMOUS\r\n");
                else if (line_equals(line, l, "CANCEL") ||
                         line_begins(line, l, "ERROR")) {

                        b->auth = _BUS_AUTH_INVALID;
                        r = bus_socket_auth_write(b, "REJECTED\r\n");

                } else if (line_equals(line, l, "BEGIN")) {

                        if (b->auth == _BUS_AUTH_INVALID)
                                r = bus_socket_auth_write(b, "ERROR\r\n");
                        else {
                                /* We can't leave from the auth phase
                                 * before we haven't written
                                 * everything queued, so let's check
                                 * that */

                                if (bus_socket_auth_needs_write(b))
                                        return 1;

                                b->rbuffer_size -= (e + 2 - (char*) b->rbuffer);
                                memmove(b->rbuffer, e + 2, b->rbuffer_size);
                                return bus_start_running(b);
                        }

                } else if (line_begins(line, l, "DATA")) {

                        if (b->auth == _BUS_AUTH_INVALID)
                                r = bus_socket_auth_write(b, "ERROR\r\n");
                        else {
                                if (b->auth == BUS_AUTH_ANONYMOUS)
                                        r = verify_anonymous_token(b, line + 4, l - 4);
                                else
                                        r = verify_external_token(b, line + 4, l - 4);

                                if (r < 0)
                                        return r;
                                if (r == 0) {
                                        b->auth = _BUS_AUTH_INVALID;
                                        r = bus_socket_auth_write(b, "REJECTED\r\n");
                                } else
                                        r = bus_socket_auth_write_ok(b);
                        }
                } else if (line_equals(line, l, "NEGOTIATE_UNIX_FD")) {
                        if (b->auth == _BUS_AUTH_INVALID || !(b->hello_flags & KDBUS_HELLO_ACCEPT_FD))
                                r = bus_socket_auth_write(b, "ERROR\r\n");
                        else {
                                b->can_fds = true;
                                r = bus_socket_auth_write(b, "AGREE_UNIX_FD\r\n");
                        }
                } else
                        r = bus_socket_auth_write(b, "ERROR\r\n");

                if (r < 0)
                        return r;

                b->auth_rbegin = e + 2 - (char*) b->rbuffer;

                processed = true;
        }
}

static int bus_socket_auth_verify(sd_bus *b) {
        assert(b);

        if (b->is_server)
                return bus_socket_auth_verify_server(b);
        else
                return bus_socket_auth_verify_client(b);
}

static int bus_socket_read_auth(sd_bus *b) {
        struct msghdr mh;
        struct iovec iov = {};
        size_t n;
        ssize_t k;
        int r;
        void *p;
        union {
                struct cmsghdr cmsghdr;
                uint8_t buf[CMSG_SPACE(sizeof(int) * BUS_FDS_MAX)];
        } control;
        bool handle_cmsg = false;

        assert(b);
        assert(b->state == BUS_AUTHENTICATING);

        r = bus_socket_auth_verify(b);
        if (r != 0)
                return r;

        n = MAX(256u, b->rbuffer_size * 2);

        if (n > BUS_AUTH_SIZE_MAX)
                n = BUS_AUTH_SIZE_MAX;

        if (b->rbuffer_size >= n)
                return -ENOBUFS;

        p = realloc(b->rbuffer, n);
        if (!p)
                return -ENOMEM;

        b->rbuffer = p;

        iov.iov_base = (uint8_t*) b->rbuffer + b->rbuffer_size;
        iov.iov_len = n - b->rbuffer_size;

        if (b->prefer_readv)
                k = readv(b->input_fd, &iov, 1);
        else {
                zero(mh);
                mh.msg_iov = &iov;
                mh.msg_iovlen = 1;
                mh.msg_control = &control;
                mh.msg_controllen = sizeof(control);

                k = recvmsg(b->input_fd, &mh, MSG_DONTWAIT|MSG_NOSIGNAL|MSG_CMSG_CLOEXEC);
                if (k < 0 && errno == ENOTSOCK) {
                        b->prefer_readv = true;
                        k = readv(b->input_fd, &iov, 1);
                } else
                        handle_cmsg = true;
        }
        if (k < 0)
                return errno == EAGAIN ? 0 : -errno;
        if (k == 0)
                return -ECONNRESET;

        b->rbuffer_size += k;

        if (handle_cmsg) {
                struct cmsghdr *cmsg;

                CMSG_FOREACH(cmsg, &mh)
                        if (cmsg->cmsg_level == SOL_SOCKET &&
                            cmsg->cmsg_type == SCM_RIGHTS) {
                                int j;

                                /* Whut? We received fds during the auth
                                 * protocol? Somebody is playing games with
                                 * us. Close them all, and fail */
                                j = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
                                close_many((int*) CMSG_DATA(cmsg), j);
                                return -EIO;
                        } else
                                log_debug("Got unexpected auxiliary data with level=%d and type=%d",
                                          cmsg->cmsg_level, cmsg->cmsg_type);
        }

        r = bus_socket_auth_verify(b);
        if (r != 0)
                return r;

        return 1;
}

void bus_socket_setup(sd_bus *b) {
        assert(b);

        /* Increase the buffers to 8 MB */
        fd_inc_rcvbuf(b->input_fd, SNDBUF_SIZE);
        fd_inc_sndbuf(b->output_fd, SNDBUF_SIZE);

        b->is_kernel = false;
        b->message_version = 1;
        b->message_endian = 0;
}

static void bus_get_peercred(sd_bus *b) {
        int r;

        assert(b);

        /* Get the peer for socketpair() sockets */
        b->ucred_valid = getpeercred(b->input_fd, &b->ucred) >= 0;

        /* Get the SELinux context of the peer */
        r = getpeersec(b->input_fd, &b->label);
        if (r < 0 && r != -EOPNOTSUPP)
                log_debug_errno(r, "Failed to determine peer security context: %m");
}

static int bus_socket_start_auth_client(sd_bus *b) {
        size_t l;
        const char *auth_suffix, *auth_prefix;

        assert(b);

        if (b->anonymous_auth) {
                auth_prefix = "\0AUTH ANONYMOUS ";

                /* For ANONYMOUS auth we send some arbitrary "trace" string */
                l = 9;
                b->auth_buffer = hexmem("anonymous", l);
        } else {
                char text[DECIMAL_STR_MAX(uid_t) + 1];

                auth_prefix = "\0AUTH EXTERNAL ";

                xsprintf(text, UID_FMT, geteuid());

                l = strlen(text);
                b->auth_buffer = hexmem(text, l);
        }

        if (!b->auth_buffer)
                return -ENOMEM;

        if (b->hello_flags & KDBUS_HELLO_ACCEPT_FD)
                auth_suffix = "\r\nNEGOTIATE_UNIX_FD\r\nBEGIN\r\n";
        else
                auth_suffix = "\r\nBEGIN\r\n";

        b->auth_iovec[0].iov_base = (void*) auth_prefix;
        b->auth_iovec[0].iov_len = 1 + strlen(auth_prefix + 1);
        b->auth_iovec[1].iov_base = (void*) b->auth_buffer;
        b->auth_iovec[1].iov_len = l * 2;
        b->auth_iovec[2].iov_base = (void*) auth_suffix;
        b->auth_iovec[2].iov_len = strlen(auth_suffix);

        return bus_socket_write_auth(b);
}

int bus_socket_start_auth(sd_bus *b) {
        assert(b);

        bus_get_peercred(b);

        b->state = BUS_AUTHENTICATING;
        b->auth_timeout = now(CLOCK_MONOTONIC) + BUS_DEFAULT_TIMEOUT;

        if (sd_is_socket(b->input_fd, AF_UNIX, 0, 0) <= 0)
                b->hello_flags &= ~KDBUS_HELLO_ACCEPT_FD;

        if (b->output_fd != b->input_fd)
                if (sd_is_socket(b->output_fd, AF_UNIX, 0, 0) <= 0)
                        b->hello_flags &= ~KDBUS_HELLO_ACCEPT_FD;

        if (b->is_server)
                return bus_socket_read_auth(b);
        else
                return bus_socket_start_auth_client(b);
}

int bus_socket_connect(sd_bus *b) {
        int r;

        assert(b);
        assert(b->input_fd < 0);
        assert(b->output_fd < 0);
        assert(b->sockaddr.sa.sa_family != AF_UNSPEC);

        b->input_fd = socket(b->sockaddr.sa.sa_family, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (b->input_fd < 0)
                return -errno;

        b->output_fd = b->input_fd;

        bus_socket_setup(b);

        r = connect(b->input_fd, &b->sockaddr.sa, b->sockaddr_size);
        if (r < 0) {
                if (errno == EINPROGRESS)
                        return 1;

                return -errno;
        }

        return bus_socket_start_auth(b);
}

int bus_socket_exec(sd_bus *b) {
        int s[2], r;
        pid_t pid;

        assert(b);
        assert(b->input_fd < 0);
        assert(b->output_fd < 0);
        assert(b->exec_path);

        r = socketpair(AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0, s);
        if (r < 0)
                return -errno;

        pid = fork();
        if (pid < 0) {
                safe_close_pair(s);
                return -errno;
        }
        if (pid == 0) {
                /* Child */

                (void) reset_all_signal_handlers();
                (void) reset_signal_mask();

                close_all_fds(s+1, 1);

                assert_se(dup3(s[1], STDIN_FILENO, 0) == STDIN_FILENO);
                assert_se(dup3(s[1], STDOUT_FILENO, 0) == STDOUT_FILENO);

                if (s[1] != STDIN_FILENO && s[1] != STDOUT_FILENO)
                        safe_close(s[1]);

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

        safe_close(s[1]);
        b->output_fd = b->input_fd = s[0];

        bus_socket_setup(b);

        return bus_socket_start_auth(b);
}

int bus_socket_take_fd(sd_bus *b) {
        assert(b);

        bus_socket_setup(b);

        return bus_socket_start_auth(b);
}

int bus_socket_write_message(sd_bus *bus, sd_bus_message *m, size_t *idx) {
        struct iovec *iov;
        ssize_t k;
        size_t n;
        unsigned j;
        int r;

        assert(bus);
        assert(m);
        assert(idx);
        assert(bus->state == BUS_RUNNING || bus->state == BUS_HELLO);

        if (*idx >= BUS_MESSAGE_SIZE(m))
                return 0;

        r = bus_message_setup_iovec(m);
        if (r < 0)
                return r;

        n = m->n_iovec * sizeof(struct iovec);
        iov = alloca(n);
        memcpy(iov, m->iovec, n);

        j = 0;
        iovec_advance(iov, &j, *idx);

        if (bus->prefer_writev)
                k = writev(bus->output_fd, iov, m->n_iovec);
        else {
                struct msghdr mh = {
                        .msg_iov = iov,
                        .msg_iovlen = m->n_iovec,
                };

                if (m->n_fds > 0) {
                        struct cmsghdr *control;

                        mh.msg_control = control = alloca(CMSG_SPACE(sizeof(int) * m->n_fds));
                        mh.msg_controllen = control->cmsg_len = CMSG_LEN(sizeof(int) * m->n_fds);
                        control->cmsg_level = SOL_SOCKET;
                        control->cmsg_type = SCM_RIGHTS;
                        memcpy(CMSG_DATA(control), m->fds, sizeof(int) * m->n_fds);
                }

                k = sendmsg(bus->output_fd, &mh, MSG_DONTWAIT|MSG_NOSIGNAL);
                if (k < 0 && errno == ENOTSOCK) {
                        bus->prefer_writev = true;
                        k = writev(bus->output_fd, iov, m->n_iovec);
                }
        }

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
        if (e == BUS_LITTLE_ENDIAN) {
                a = le32toh(a);
                b = le32toh(b);
        } else if (e == BUS_BIG_ENDIAN) {
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

static int bus_socket_make_message(sd_bus *bus, size_t size) {
        sd_bus_message *t;
        void *b;
        int r;

        assert(bus);
        assert(bus->rbuffer_size >= size);
        assert(bus->state == BUS_RUNNING || bus->state == BUS_HELLO);

        r = bus_rqueue_make_room(bus);
        if (r < 0)
                return r;

        if (bus->rbuffer_size > size) {
                b = memdup((const uint8_t*) bus->rbuffer + size,
                           bus->rbuffer_size - size);
                if (!b)
                        return -ENOMEM;
        } else
                b = NULL;

        r = bus_message_from_malloc(bus,
                                    bus->rbuffer, size,
                                    bus->fds, bus->n_fds,
                                    NULL,
                                    &t);
        if (r < 0) {
                free(b);
                return r;
        }

        bus->rbuffer = b;
        bus->rbuffer_size -= size;

        bus->fds = NULL;
        bus->n_fds = 0;

        bus->rqueue[bus->rqueue_size++] = t;

        return 1;
}

int bus_socket_read_message(sd_bus *bus) {
        struct msghdr mh;
        struct iovec iov = {};
        ssize_t k;
        size_t need;
        int r;
        void *b;
        union {
                struct cmsghdr cmsghdr;
                uint8_t buf[CMSG_SPACE(sizeof(int) * BUS_FDS_MAX)];
        } control;
        bool handle_cmsg = false;

        assert(bus);
        assert(bus->state == BUS_RUNNING || bus->state == BUS_HELLO);

        r = bus_socket_read_message_need(bus, &need);
        if (r < 0)
                return r;

        if (bus->rbuffer_size >= need)
                return bus_socket_make_message(bus, need);

        b = realloc(bus->rbuffer, need);
        if (!b)
                return -ENOMEM;

        bus->rbuffer = b;

        iov.iov_base = (uint8_t*) bus->rbuffer + bus->rbuffer_size;
        iov.iov_len = need - bus->rbuffer_size;

        if (bus->prefer_readv)
                k = readv(bus->input_fd, &iov, 1);
        else {
                zero(mh);
                mh.msg_iov = &iov;
                mh.msg_iovlen = 1;
                mh.msg_control = &control;
                mh.msg_controllen = sizeof(control);

                k = recvmsg(bus->input_fd, &mh, MSG_DONTWAIT|MSG_NOSIGNAL|MSG_CMSG_CLOEXEC);
                if (k < 0 && errno == ENOTSOCK) {
                        bus->prefer_readv = true;
                        k = readv(bus->input_fd, &iov, 1);
                } else
                        handle_cmsg = true;
        }
        if (k < 0)
                return errno == EAGAIN ? 0 : -errno;
        if (k == 0)
                return -ECONNRESET;

        bus->rbuffer_size += k;

        if (handle_cmsg) {
                struct cmsghdr *cmsg;

                CMSG_FOREACH(cmsg, &mh)
                        if (cmsg->cmsg_level == SOL_SOCKET &&
                            cmsg->cmsg_type == SCM_RIGHTS) {
                                int n, *f;

                                n = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);

                                if (!bus->can_fds) {
                                        /* Whut? We received fds but this
                                         * isn't actually enabled? Close them,
                                         * and fail */

                                        close_many((int*) CMSG_DATA(cmsg), n);
                                        return -EIO;
                                }

                                f = realloc(bus->fds, sizeof(int) * (bus->n_fds + n));
                                if (!f) {
                                        close_many((int*) CMSG_DATA(cmsg), n);
                                        return -ENOMEM;
                                }

                                memcpy(f + bus->n_fds, CMSG_DATA(cmsg), n * sizeof(int));
                                bus->fds = f;
                                bus->n_fds += n;
                        } else
                                log_debug("Got unexpected auxiliary data with level=%d and type=%d",
                                          cmsg->cmsg_level, cmsg->cmsg_type);
        }

        r = bus_socket_read_message_need(bus, &need);
        if (r < 0)
                return r;

        if (bus->rbuffer_size >= need)
                return bus_socket_make_message(bus, need);

        return 1;
}

int bus_socket_process_opening(sd_bus *b) {
        int error = 0;
        socklen_t slen = sizeof(error);
        struct pollfd p = {
                .fd = b->output_fd,
                .events = POLLOUT,
        };
        int r;

        assert(b->state == BUS_OPENING);

        r = poll(&p, 1, 0);
        if (r < 0)
                return -errno;

        if (!(p.revents & (POLLOUT|POLLERR|POLLHUP)))
                return 0;

        r = getsockopt(b->output_fd, SOL_SOCKET, SO_ERROR, &error, &slen);
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
