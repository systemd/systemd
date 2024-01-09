/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <endian.h>
#include <poll.h>
#include <stdlib.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-daemon.h"

#include "alloc-util.h"
#include "bus-internal.h"
#include "bus-message.h"
#include "bus-socket.h"
#include "escape.h"
#include "fd-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "hexdecoct.h"
#include "io-util.h"
#include "iovec-util.h"
#include "macro.h"
#include "memory-util.h"
#include "path-util.h"
#include "process-util.h"
#include "random-util.h"
#include "signal-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "user-util.h"
#include "utf8.h"

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

                *i = IOVEC_MAKE(NULL, 0);

                (*idx)++;
        }
}

static int append_iovec(sd_bus_message *m, const void *p, size_t sz) {
        assert(m);
        assert(p);
        assert(sz > 0);

        m->iovec[m->n_iovec++] = IOVEC_MAKE((void*) p, sz);

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

static int bus_socket_auth_verify_client(sd_bus *b) {
        char *l, *lines[4] = {};
        sd_id128_t peer;
        size_t i, n;
        int r;

        assert(b);

        /*
         * We expect up to three response lines:
         *   "DATA\r\n"                 (optional)
         *   "OK <server-id>\r\n"
         *   "AGREE_UNIX_FD\r\n"        (optional)
         */

        n = 0;
        lines[n] = b->rbuffer;
        for (i = 0; i < 3; ++i) {
                l = memmem_safe(lines[n], b->rbuffer_size - (lines[n] - (char*) b->rbuffer), "\r\n", 2);
                if (l)
                        lines[++n] = l + 2;
                else
                        break;
        }

        /*
         * If we sent a non-empty initial response, then we just expect an OK
         * reply. We currently do this if, and only if, we picked ANONYMOUS.
         * If we did not send an initial response, then we expect a DATA
         * challenge, reply with our own DATA, and expect an OK reply. We do
         * this for EXTERNAL.
         * If FD negotiation was requested, we additionally expect
         * an AGREE_UNIX_FD response in all cases.
         */
        if (n < (b->anonymous_auth ? 1U : 2U) + !!b->accept_fd)
                return 0; /* wait for more data */

        i = 0;

        /* In case of EXTERNAL, verify the first response was DATA. */
        if (!b->anonymous_auth) {
                l = lines[i++];
                if (lines[i] - l == 4 + 2) {
                        if (memcmp(l, "DATA", 4))
                                return -EPERM;
                } else if (lines[i] - l == 3 + 32 + 2) {
                        /*
                         * Old versions of the server-side implementation of
                         * `sd-bus` replied with "OK <id>" to "AUTH" requests
                         * from a client, even if the "AUTH" line did not
                         * contain inlined arguments. Therefore, we also accept
                         * "OK <id>" here, even though it is technically the
                         * wrong reply. We ignore the "<id>" parameter, though,
                         * since it has no real value.
                         */
                        if (memcmp(l, "OK ", 3))
                                return -EPERM;
                } else
                        return -EPERM;
        }

        /* Now check the OK line. */
        l = lines[i++];

        if (lines[i] - l != 3 + 32 + 2)
                return -EPERM;
        if (memcmp(l, "OK ", 3))
                return -EPERM;

        b->auth = b->anonymous_auth ? BUS_AUTH_ANONYMOUS : BUS_AUTH_EXTERNAL;

        for (unsigned j = 0; j < 32; j += 2) {
                int x, y;

                x = unhexchar(l[3 + j]);
                y = unhexchar(l[3 + j + 1]);

                if (x < 0 || y < 0)
                        return -EINVAL;

                peer.bytes[j/2] = ((uint8_t) x << 4 | (uint8_t) y);
        }

        if (!sd_id128_is_null(b->server_id) &&
            !sd_id128_equal(b->server_id, peer))
                return -EPERM;

        b->server_id = peer;

        /* And possibly check the third line, too */
        if (b->accept_fd) {
                l = lines[i++];
                b->can_fds = memory_startswith(l, lines[i] - l, "AGREE_UNIX_FD");
        }

        assert(i == n);

        b->rbuffer_size -= (lines[i] - (char*) b->rbuffer);
        memmove(b->rbuffer, lines[i], b->rbuffer_size);

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
        const char *p;

        p = memory_startswith(s, m, word);
        return p && (p == (s + m) || *p == ' ');
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

        r = unhexmem_full(p, l, /* secure = */ false, (void**) &token, &len);
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

        /* We don't do any real authentication here. Instead, if
         * the owner of this bus wanted authentication they should have
         * checked SO_PEERCRED before even creating the bus object. */

        if (!b->anonymous_auth && !b->ucred_valid)
                return 0;

        if (l <= 0)
                return 1;

        assert(p[0] == ' ');
        p++; l--;

        if (l % 2 != 0)
                return 0;

        r = unhexmem_full(p, l, /* secure = */ false, (void**) &token, &len);
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
        assert(IN_SET(b->auth_index, 0, 1));

        l = strlen(t);
        p = malloc(b->auth_iovec[0].iov_len + l);
        if (!p)
                return -ENOMEM;

        memcpy_safe(p, b->auth_iovec[0].iov_base, b->auth_iovec[0].iov_len);
        memcpy(p + b->auth_iovec[0].iov_len, t, l);

        b->auth_iovec[0].iov_base = p;
        b->auth_iovec[0].iov_len += l;

        free_and_replace(b->auth_buffer, p);
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
                e = memmem_safe(line, b->rbuffer_size - b->auth_rbegin, "\r\n", 2);
                if (!e)
                        return processed;

                l = e - line;

                if (line_begins(line, l, "AUTH ANONYMOUS")) {

                        r = verify_anonymous_token(b,
                                                   line + strlen("AUTH ANONYMOUS"),
                                                   l - strlen("AUTH ANONYMOUS"));
                        if (r < 0)
                                return r;
                        if (r == 0)
                                r = bus_socket_auth_write(b, "REJECTED\r\n");
                        else {
                                b->auth = BUS_AUTH_ANONYMOUS;
                                if (l <= strlen("AUTH ANONYMOUS"))
                                        r = bus_socket_auth_write(b, "DATA\r\n");
                                else
                                        r = bus_socket_auth_write_ok(b);
                        }

                } else if (line_begins(line, l, "AUTH EXTERNAL")) {

                        r = verify_external_token(b,
                                                  line + strlen("AUTH EXTERNAL"),
                                                  l - strlen("AUTH EXTERNAL"));
                        if (r < 0)
                                return r;
                        if (r == 0)
                                r = bus_socket_auth_write(b, "REJECTED\r\n");
                        else {
                                b->auth = BUS_AUTH_EXTERNAL;
                                if (l <= strlen("AUTH EXTERNAL"))
                                        r = bus_socket_auth_write(b, "DATA\r\n");
                                else
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
                        if (b->auth == _BUS_AUTH_INVALID || !b->accept_fd)
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

static int bus_socket_write_auth(sd_bus *b) {
        ssize_t k;

        assert(b);
        assert(b->state == BUS_AUTHENTICATING);

        if (!bus_socket_auth_needs_write(b))
                return 0;

        if (b->prefer_writev)
                k = writev(b->output_fd, b->auth_iovec + b->auth_index, ELEMENTSOF(b->auth_iovec) - b->auth_index);
        else {
                struct msghdr mh = {
                        .msg_iov = b->auth_iovec + b->auth_index,
                        .msg_iovlen = ELEMENTSOF(b->auth_iovec) - b->auth_index,
                };

                k = sendmsg(b->output_fd, &mh, MSG_DONTWAIT|MSG_NOSIGNAL);
                if (k < 0 && errno == ENOTSOCK) {
                        b->prefer_writev = true;
                        k = writev(b->output_fd, b->auth_iovec + b->auth_index, ELEMENTSOF(b->auth_iovec) - b->auth_index);
                }
        }

        if (k < 0)
                return ERRNO_IS_TRANSIENT(errno) ? 0 : -errno;

        iovec_advance(b->auth_iovec, &b->auth_index, (size_t) k);

        /* Now crank the state machine since we might be able to make progress after writing. For example,
         * the server only processes "BEGIN" when the write buffer is empty.
         */
        return bus_socket_auth_verify(b);
}

static int bus_socket_read_auth(sd_bus *b) {
        struct msghdr mh;
        struct iovec iov = {};
        size_t n;
        ssize_t k;
        int r;
        void *p;
        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(int) * BUS_FDS_MAX)) control;
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

        iov = IOVEC_MAKE((uint8_t *)b->rbuffer + b->rbuffer_size, n - b->rbuffer_size);

        if (b->prefer_readv) {
                k = readv(b->input_fd, &iov, 1);
                if (k < 0)
                        k = -errno;
        } else {
                mh = (struct msghdr) {
                        .msg_iov = &iov,
                        .msg_iovlen = 1,
                        .msg_control = &control,
                        .msg_controllen = sizeof(control),
                };

                k = recvmsg_safe(b->input_fd, &mh, MSG_DONTWAIT|MSG_CMSG_CLOEXEC);
                if (k == -ENOTSOCK) {
                        b->prefer_readv = true;
                        k = readv(b->input_fd, &iov, 1);
                        if (k < 0)
                                k = -errno;
                } else
                        handle_cmsg = true;
        }
        if (ERRNO_IS_NEG_TRANSIENT(k))
                return 0;
        if (k < 0)
                return (int) k;
        if (k == 0) {
                if (handle_cmsg)
                        cmsg_close_all(&mh); /* paranoia, we shouldn't have gotten any fds on EOF */
                return -ECONNRESET;
        }

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
                                close_many(CMSG_TYPED_DATA(cmsg, int), j);
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
        (void) fd_increase_rxbuf(b->input_fd, SNDBUF_SIZE);
        (void) fd_inc_sndbuf(b->output_fd, SNDBUF_SIZE);

        b->message_version = 1;
        b->message_endian = 0;
}

static void bus_get_peercred(sd_bus *b) {
        int r;

        assert(b);
        assert(!b->ucred_valid);
        assert(!b->label);
        assert(b->n_groups == SIZE_MAX);

        /* Get the peer for socketpair() sockets */
        b->ucred_valid = getpeercred(b->input_fd, &b->ucred) >= 0;

        /* Get the SELinux context of the peer */
        r = getpeersec(b->input_fd, &b->label);
        if (r < 0 && !IN_SET(r, -EOPNOTSUPP, -ENOPROTOOPT))
                log_debug_errno(r, "Failed to determine peer security context: %m");

        /* Get the list of auxiliary groups of the peer */
        r = getpeergroups(b->input_fd, &b->groups);
        if (r >= 0)
                b->n_groups = (size_t) r;
        else if (!IN_SET(r, -EOPNOTSUPP, -ENOPROTOOPT))
                log_debug_errno(r, "Failed to determine peer's group list: %m");

        /* Let's query the peers socket address, it might carry information such as the peer's comm or
         * description string */
        zero(b->sockaddr_peer);
        b->sockaddr_size_peer = 0;

        socklen_t l = sizeof(b->sockaddr_peer) - 1; /* Leave space for a NUL */
        if (getpeername(b->input_fd, &b->sockaddr_peer.sa, &l) < 0)
                log_debug_errno(errno, "Failed to get peer's socket address, ignoring: %m");
        else
                b->sockaddr_size_peer = l;
}

static int bus_socket_start_auth_client(sd_bus *b) {
        static const char sasl_auth_anonymous[] = {
                /*
                 * We use an arbitrary trace-string for the ANONYMOUS authentication. It can be used by the
                 * message broker to aid debugging of clients. We fully anonymize the connection and use a
                 * static default.
                 */
                /*            HEX a n o n y m o u s */
                "\0AUTH ANONYMOUS 616e6f6e796d6f7573\r\n"
        };
        static const char sasl_auth_external[] = {
                "\0AUTH EXTERNAL\r\n"
                "DATA\r\n"
        };
        static const char sasl_negotiate_unix_fd[] = {
                "NEGOTIATE_UNIX_FD\r\n"
        };
        static const char sasl_begin[] = {
                "BEGIN\r\n"
        };
        size_t i = 0;

        assert(b);

        if (b->anonymous_auth)
                b->auth_iovec[i++] = IOVEC_MAKE((char*) sasl_auth_anonymous, sizeof(sasl_auth_anonymous) - 1);
        else
                b->auth_iovec[i++] = IOVEC_MAKE((char*) sasl_auth_external, sizeof(sasl_auth_external) - 1);

        if (b->accept_fd)
                b->auth_iovec[i++] = IOVEC_MAKE_STRING(sasl_negotiate_unix_fd);

        b->auth_iovec[i++] = IOVEC_MAKE_STRING(sasl_begin);

        return bus_socket_write_auth(b);
}

int bus_socket_start_auth(sd_bus *b) {
        assert(b);

        bus_get_peercred(b);

        bus_set_state(b, BUS_AUTHENTICATING);
        b->auth_timeout = now(CLOCK_MONOTONIC) + BUS_AUTH_TIMEOUT;

        if (sd_is_socket(b->input_fd, AF_UNIX, 0, 0) <= 0)
                b->accept_fd = false;

        if (b->output_fd != b->input_fd)
                if (sd_is_socket(b->output_fd, AF_UNIX, 0, 0) <= 0)
                        b->accept_fd = false;

        if (b->is_server)
                return bus_socket_read_auth(b);
        else
                return bus_socket_start_auth_client(b);
}

static int bus_socket_inotify_setup(sd_bus *b) {
        _cleanup_free_ int *new_watches = NULL;
        _cleanup_free_ char *absolute = NULL;
        size_t n = 0, done = 0, i;
        unsigned max_follow = 32;
        const char *p;
        int wd, r;

        assert(b);
        assert(b->watch_bind);
        assert(b->sockaddr.sa.sa_family == AF_UNIX);
        assert(b->sockaddr.un.sun_path[0] != 0);

        /* Sets up an inotify fd in case watch_bind is enabled: wait until the configured AF_UNIX file system socket
         * appears before connecting to it. The implemented is pretty simplistic: we just subscribe to relevant changes
         * to all prefix components of the path, and every time we get an event for that we try to reconnect again,
         * without actually caring what precisely the event we got told us. If we still can't connect we re-subscribe
         * to all relevant changes of anything in the path, so that our watches include any possibly newly created path
         * components. */

        if (b->inotify_fd < 0) {
                b->inotify_fd = inotify_init1(IN_NONBLOCK|IN_CLOEXEC);
                if (b->inotify_fd < 0)
                        return -errno;

                b->inotify_fd = fd_move_above_stdio(b->inotify_fd);
        }

        /* Make sure the path is NUL terminated */
        p = strndupa_safe(b->sockaddr.un.sun_path,
                          sizeof(b->sockaddr.un.sun_path));

        /* Make sure the path is absolute */
        r = path_make_absolute_cwd(p, &absolute);
        if (r < 0)
                goto fail;

        /* Watch all parent directories, and don't mind any prefix that doesn't exist yet. For the innermost directory
         * that exists we want to know when files are created or moved into it. For all parents of it we just care if
         * they are removed or renamed. */

        if (!GREEDY_REALLOC(new_watches, n + 1)) {
                r = -ENOMEM;
                goto fail;
        }

        /* Start with the top-level directory, which is a bit simpler than the rest, since it can't be a symlink, and
         * always exists */
        wd = inotify_add_watch(b->inotify_fd, "/", IN_CREATE|IN_MOVED_TO);
        if (wd < 0) {
                r = log_debug_errno(errno, "Failed to add inotify watch on /: %m");
                goto fail;
        } else
                new_watches[n++] = wd;

        for (;;) {
                _cleanup_free_ char *component = NULL, *prefix = NULL, *destination = NULL;
                size_t n_slashes, n_component;
                char *c = NULL;

                n_slashes = strspn(absolute + done, "/");
                n_component = n_slashes + strcspn(absolute + done + n_slashes, "/");

                if (n_component == 0) /* The end */
                        break;

                component = strndup(absolute + done, n_component);
                if (!component) {
                        r = -ENOMEM;
                        goto fail;
                }

                /* A trailing slash? That's a directory, and not a socket then */
                if (path_equal(component, "/")) {
                        r = -EISDIR;
                        goto fail;
                }

                /* A single dot? Let's eat this up */
                if (path_equal(component, "/.")) {
                        done += n_component;
                        continue;
                }

                prefix = strndup(absolute, done + n_component);
                if (!prefix) {
                        r = -ENOMEM;
                        goto fail;
                }

                if (!GREEDY_REALLOC(new_watches, n + 1)) {
                        r = -ENOMEM;
                        goto fail;
                }

                wd = inotify_add_watch(b->inotify_fd, prefix, IN_DELETE_SELF|IN_MOVE_SELF|IN_ATTRIB|IN_CREATE|IN_MOVED_TO|IN_DONT_FOLLOW);
                log_debug("Added inotify watch for %s on bus %s: %i", prefix, strna(b->description), wd);

                if (wd < 0) {
                        if (IN_SET(errno, ENOENT, ELOOP))
                                break; /* This component doesn't exist yet, or the path contains a cyclic symlink right now */

                        r = log_debug_errno(errno, "Failed to add inotify watch on %s: %m", empty_to_root(prefix));
                        goto fail;
                } else
                        new_watches[n++] = wd;

                /* Check if this is possibly a symlink. If so, let's follow it and watch it too. */
                r = readlink_malloc(prefix, &destination);
                if (r == -EINVAL) { /* not a symlink */
                        done += n_component;
                        continue;
                }
                if (r < 0)
                        goto fail;

                if (isempty(destination)) { /* Empty symlink target? Yuck! */
                        r = -EINVAL;
                        goto fail;
                }

                if (max_follow <= 0) { /* Let's make sure we don't follow symlinks forever */
                        r = -ELOOP;
                        goto fail;
                }

                if (path_is_absolute(destination)) {
                        /* For absolute symlinks we build the new path and start anew */
                        c = strjoin(destination, absolute + done + n_component);
                        done = 0;
                } else {
                        _cleanup_free_ char *t = NULL;

                        /* For relative symlinks we replace the last component, and try again */
                        t = strndup(absolute, done);
                        if (!t)
                                return -ENOMEM;

                        c = strjoin(t, "/", destination, absolute + done + n_component);
                }
                if (!c) {
                        r = -ENOMEM;
                        goto fail;
                }

                free_and_replace(absolute, c);

                max_follow--;
        }

        /* And now, let's remove all watches from the previous iteration we don't need anymore */
        for (i = 0; i < b->n_inotify_watches; i++) {
                bool found = false;
                size_t j;

                for (j = 0; j < n; j++)
                        if (new_watches[j] == b->inotify_watches[i]) {
                                found = true;
                                break;
                        }

                if (found)
                        continue;

                (void) inotify_rm_watch(b->inotify_fd, b->inotify_watches[i]);
        }

        free_and_replace(b->inotify_watches, new_watches);
        b->n_inotify_watches = n;

        return 0;

fail:
        bus_close_inotify_fd(b);
        return r;
}

static int bind_description(sd_bus *b, int fd, int family) {
        _cleanup_free_ char *bind_name = NULL, *comm = NULL;
        union sockaddr_union bsa;
        const char *d = NULL;
        int r;

        assert(b);
        assert(fd >= 0);

        /* If this is an AF_UNIX socket, let's set our client's socket address to carry the description
         * string for this bus connection. This is useful for debugging things, as the connection name is
         * visible in various socket-related tools, and can even be queried by the server side. */

        if (family != AF_UNIX)
                return 0;

        (void) sd_bus_get_description(b, &d);

        /* Generate a recognizable source address in the abstract namespace. We'll include:
         * - a random 64-bit value (to avoid collisions)
         * - our "comm" process name (suppressed if contains "/" to avoid parsing issues)
         * - the description string of the bus connection. */
        (void) pid_get_comm(0, &comm);
        if (comm && strchr(comm, '/'))
                comm = mfree(comm);

        if (!d && !comm) /* skip if we don't have either field, rely on kernel autobind instead */
                return 0;

        if (asprintf(&bind_name, "@%" PRIx64 "/bus/%s/%s", random_u64(), strempty(comm), strempty(d)) < 0)
                return -ENOMEM;

        strshorten(bind_name, sizeof_field(struct sockaddr_un, sun_path));

        r = sockaddr_un_set_path(&bsa.un, bind_name);
        if (r < 0)
                return r;

        if (bind(fd, &bsa.sa, r) < 0)
                return -errno;

        return 0;
}

int bus_socket_connect(sd_bus *b) {
        bool inotify_done = false;
        int r;

        assert(b);

        for (;;) {
                assert(b->input_fd < 0);
                assert(b->output_fd < 0);
                assert(b->sockaddr.sa.sa_family != AF_UNSPEC);

                if (DEBUG_LOGGING) {
                        _cleanup_free_ char *pretty = NULL;
                        (void) sockaddr_pretty(&b->sockaddr, b->sockaddr_size, false, true, &pretty);
                        log_debug("sd-bus: starting bus%s%s by connecting to %s...",
                                  b->description ? " " : "", strempty(b->description), strnull(pretty));
                }

                b->input_fd = socket(b->sockaddr.sa.sa_family, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
                if (b->input_fd < 0)
                        return -errno;

                r = bind_description(b, b->input_fd, b->sockaddr.sa.sa_family);
                if (r < 0)
                        return r;

                b->input_fd = fd_move_above_stdio(b->input_fd);

                b->output_fd = b->input_fd;
                bus_socket_setup(b);

                if (connect(b->input_fd, &b->sockaddr.sa, b->sockaddr_size) < 0) {
                        if (errno == EINPROGRESS) {

                                /* If we have any inotify watches open, close them now, we don't need them anymore, as
                                 * we have successfully initiated a connection */
                                bus_close_inotify_fd(b);

                                /* Note that very likely we are already in BUS_OPENING state here, as we enter it when
                                 * we start parsing the address string. The only reason we set the state explicitly
                                 * here, is to undo BUS_WATCH_BIND, in case we did the inotify magic. */
                                bus_set_state(b, BUS_OPENING);
                                return 1;
                        }

                        if (IN_SET(errno, ENOENT, ECONNREFUSED) &&  /* ENOENT → unix socket doesn't exist at all; ECONNREFUSED → unix socket stale */
                            b->watch_bind &&
                            b->sockaddr.sa.sa_family == AF_UNIX &&
                            b->sockaddr.un.sun_path[0] != 0) {

                                /* This connection attempt failed, let's release the socket for now, and start with a
                                 * fresh one when reconnecting. */
                                bus_close_io_fds(b);

                                if (inotify_done) {
                                        /* inotify set up already, don't do it again, just return now, and remember
                                         * that we are waiting for inotify events now. */
                                        bus_set_state(b, BUS_WATCH_BIND);
                                        return 1;
                                }

                                /* This is a file system socket, and the inotify logic is enabled. Let's create the necessary inotify fd. */
                                r = bus_socket_inotify_setup(b);
                                if (r < 0)
                                        return r;

                                /* Let's now try to connect a second time, because in theory there's otherwise a race
                                 * here: the socket might have been created in the time between our first connect() and
                                 * the time we set up the inotify logic. But let's remember that we set up inotify now,
                                 * so that we don't do the connect() more than twice. */
                                inotify_done = true;

                        } else
                                return -errno;
                } else
                        break;
        }

        /* Yay, established, we don't need no inotify anymore! */
        bus_close_inotify_fd(b);

        return bus_socket_start_auth(b);
}

int bus_socket_exec(sd_bus *b) {
        int s[2], r;

        assert(b);
        assert(b->input_fd < 0);
        assert(b->output_fd < 0);
        assert(b->exec_path);
        assert(b->busexec_pid == 0);

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *line = NULL;

                if (b->exec_argv)
                        line = quote_command_line(b->exec_argv, SHELL_ESCAPE_EMPTY);

                log_debug("sd-bus: starting bus%s%s with %s%s",
                          b->description ? " " : "", strempty(b->description),
                          line ?: b->exec_path,
                          b->exec_argv && !line ? "…" : "");
        }

        r = socketpair(AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0, s);
        if (r < 0)
                return -errno;

        r = safe_fork_full("(sd-busexec)",
                           (int[]) { s[1], s[1], STDERR_FILENO },
                           NULL, 0,
                           FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_REARRANGE_STDIO|FORK_RLIMIT_NOFILE_SAFE, &b->busexec_pid);
        if (r < 0) {
                safe_close_pair(s);
                return r;
        }
        if (r == 0) {
                /* Child */

                if (b->exec_argv)
                        execvp(b->exec_path, b->exec_argv);
                else
                        execvp(b->exec_path, STRV_MAKE(b->exec_path));

                _exit(EXIT_FAILURE);
        }

        safe_close(s[1]);
        b->output_fd = b->input_fd = fd_move_above_stdio(s[0]);

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
        assert(IN_SET(bus->state, BUS_RUNNING, BUS_HELLO));

        if (*idx >= BUS_MESSAGE_SIZE(m))
                return 0;

        r = bus_message_setup_iovec(m);
        if (r < 0)
                return r;

        n = m->n_iovec * sizeof(struct iovec);
        iov = newa(struct iovec, n);
        memcpy_safe(iov, m->iovec, n);

        j = 0;
        iovec_advance(iov, &j, *idx);

        if (bus->prefer_writev)
                k = writev(bus->output_fd, iov, m->n_iovec);
        else {
                struct msghdr mh = {
                        .msg_iov = iov,
                        .msg_iovlen = m->n_iovec,
                };

                if (m->n_fds > 0 && *idx == 0) {
                        struct cmsghdr *control;

                        mh.msg_controllen = CMSG_SPACE(sizeof(int) * m->n_fds);
                        mh.msg_control = alloca0(mh.msg_controllen);
                        control = CMSG_FIRSTHDR(&mh);
                        control->cmsg_len = CMSG_LEN(sizeof(int) * m->n_fds);
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
                return ERRNO_IS_TRANSIENT(errno) ? 0 : -errno;

        *idx += (size_t) k;
        return 1;
}

static int bus_socket_read_message_need(sd_bus *bus, size_t *need) {
        uint32_t a, b;
        uint8_t e;
        uint64_t sum;

        assert(bus);
        assert(need);
        assert(IN_SET(bus->state, BUS_RUNNING, BUS_HELLO));

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

        sum = (uint64_t) sizeof(struct bus_header) + (uint64_t) ALIGN8(b) + (uint64_t) a;
        if (sum >= BUS_MESSAGE_SIZE_MAX)
                return -ENOBUFS;

        *need = (size_t) sum;
        return 0;
}

static int bus_socket_make_message(sd_bus *bus, size_t size) {
        sd_bus_message *t = NULL;
        void *b;
        int r;

        assert(bus);
        assert(bus->rbuffer_size >= size);
        assert(IN_SET(bus->state, BUS_RUNNING, BUS_HELLO));

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
        if (r == -EBADMSG) {
                log_debug_errno(r, "Received invalid message from connection %s, dropping.", strna(bus->description));
                free(bus->rbuffer); /* We want to drop current rbuffer and proceed with whatever remains in b */
        } else if (r < 0) {
                free(b);
                return r;
        }

        /* rbuffer ownership was either transferred to t, or we got EBADMSG and dropped it. */
        bus->rbuffer = b;
        bus->rbuffer_size -= size;

        bus->fds = NULL;
        bus->n_fds = 0;

        if (t) {
                t->read_counter = ++bus->read_counter;
                bus->rqueue[bus->rqueue_size++] = bus_message_ref_queued(t, bus);
                sd_bus_message_unref(t);
        }

        return 1;
}

int bus_socket_read_message(sd_bus *bus) {
        struct msghdr mh;
        struct iovec iov = {};
        ssize_t k;
        size_t need;
        int r;
        void *b;
        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(int) * BUS_FDS_MAX)) control;
        bool handle_cmsg = false;

        assert(bus);
        assert(IN_SET(bus->state, BUS_RUNNING, BUS_HELLO));

        r = bus_socket_read_message_need(bus, &need);
        if (r < 0)
                return r;

        if (bus->rbuffer_size >= need)
                return bus_socket_make_message(bus, need);

        b = realloc(bus->rbuffer, need);
        if (!b)
                return -ENOMEM;

        bus->rbuffer = b;

        iov = IOVEC_MAKE((uint8_t *)bus->rbuffer + bus->rbuffer_size, need - bus->rbuffer_size);

        if (bus->prefer_readv) {
                k = readv(bus->input_fd, &iov, 1);
                if (k < 0)
                        k = -errno;
        } else {
                mh = (struct msghdr) {
                        .msg_iov = &iov,
                        .msg_iovlen = 1,
                        .msg_control = &control,
                        .msg_controllen = sizeof(control),
                };

                k = recvmsg_safe(bus->input_fd, &mh, MSG_DONTWAIT|MSG_CMSG_CLOEXEC);
                if (k == -ENOTSOCK) {
                        bus->prefer_readv = true;
                        k = readv(bus->input_fd, &iov, 1);
                        if (k < 0)
                                k = -errno;
                } else
                        handle_cmsg = true;
        }
        if (ERRNO_IS_NEG_TRANSIENT(k))
                return 0;
        if (k < 0)
                return (int) k;
        if (k == 0) {
                if (handle_cmsg)
                        cmsg_close_all(&mh); /* On EOF we shouldn't have gotten an fd, but let's make sure */
                return -ECONNRESET;
        }

        bus->rbuffer_size += k;

        if (handle_cmsg) {
                struct cmsghdr *cmsg;

                CMSG_FOREACH(cmsg, &mh)
                        if (cmsg->cmsg_level == SOL_SOCKET &&
                            cmsg->cmsg_type == SCM_RIGHTS) {
                                int n, *f, i;

                                n = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);

                                if (!bus->can_fds) {
                                        /* Whut? We received fds but this
                                         * isn't actually enabled? Close them,
                                         * and fail */

                                        close_many(CMSG_TYPED_DATA(cmsg, int), n);
                                        return -EIO;
                                }

                                f = reallocarray(bus->fds, bus->n_fds + n, sizeof(int));
                                if (!f) {
                                        close_many(CMSG_TYPED_DATA(cmsg, int), n);
                                        return -ENOMEM;
                                }

                                for (i = 0; i < n; i++)
                                        f[bus->n_fds++] = fd_move_above_stdio(CMSG_TYPED_DATA(cmsg, int)[i]);
                                bus->fds = f;
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
        int error = 0, events, r;
        socklen_t slen = sizeof(error);

        assert(b->state == BUS_OPENING);

        events = fd_wait_for_event(b->output_fd, POLLOUT, 0);
        if (ERRNO_IS_NEG_TRANSIENT(events))
                return 0;
        if (events < 0)
                return events;
        if (!(events & (POLLOUT|POLLERR|POLLHUP)))
                return 0;

        r = getsockopt(b->output_fd, SOL_SOCKET, SO_ERROR, &error, &slen);
        if (r < 0)
                b->last_connect_error = errno;
        else if (error != 0)
                b->last_connect_error = error;
        else if (events & (POLLERR|POLLHUP))
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

int bus_socket_process_watch_bind(sd_bus *b) {
        int r, q;

        assert(b);
        assert(b->state == BUS_WATCH_BIND);
        assert(b->inotify_fd >= 0);

        r = flush_fd(b->inotify_fd);
        if (r <= 0)
                return r;

        log_debug("Got inotify event on bus %s.", strna(b->description));

        /* We flushed events out of the inotify fd. In that case, maybe the socket is valid now? Let's try to connect
         * to it again */

        r = bus_socket_connect(b);
        if (r < 0)
                return r;

        q = bus_attach_io_events(b);
        if (q < 0)
                return q;

        q = bus_attach_inotify_event(b);
        if (q < 0)
                return q;

        return r;
}
