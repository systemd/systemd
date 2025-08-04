/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "iovec-util.h"
#include "journald-manager.h"
#include "journald-socket.h"
#include "log.h"
#include "stdio-util.h"
#include "socket-util.h"
#include "sparse-endian.h"
#include "time-util.h"

static int manager_open_forward_socket(Manager *m) {
        _cleanup_close_ int socket_fd = -EBADF;
        const SocketAddress *addr;
        int family;

        assert(m);

        /* Noop if there is nothing to do. */
        if (m->config.forward_to_socket.sockaddr.sa.sa_family == AF_UNSPEC || m->namespace)
                return 0;
        /* All ready, nothing to do. */
        if (m->forward_socket_fd >= 0)
                return 1;

        addr = &m->config.forward_to_socket;

        family = socket_address_family(addr);

        if (!IN_SET(family, AF_UNIX, AF_INET, AF_INET6, AF_VSOCK))
                return log_debug_errno(SYNTHETIC_ERRNO(ESOCKTNOSUPPORT),
                                       "Unsupported socket type for forward socket: %d", family);

        socket_fd = socket(family, SOCK_STREAM|SOCK_CLOEXEC, 0);
        if (socket_fd < 0)
                return log_debug_errno(errno, "Failed to create forward socket, ignoring: %m");

        if (connect(socket_fd, &addr->sockaddr.sa, addr->size) < 0)
                return log_debug_errno(errno, "Failed to connect to remote address for forwarding, ignoring: %m");

        m->forward_socket_fd = TAKE_FD(socket_fd);
        log_debug("Successfully connected to remote address for forwarding.");
        return 1;
}

static inline bool must_serialize(struct iovec iov) {
        /* checks an iovec of the form FIELD=VALUE to see if VALUE needs binary safe serialisation:
         * See https://systemd.io/JOURNAL_EXPORT_FORMATS/#journal-export-format for more information
         * on binary safe serialisation for the journal export format */

        assert(iov.iov_len == 0 || iov.iov_base);

        const uint8_t *s = iov.iov_base;
        bool before_value = true;

        FOREACH_ARRAY(c, s, iov.iov_len)
                if (before_value)
                        before_value = *c != (uint8_t)'=';
                else if (*c < (uint8_t)' ' && *c != (uint8_t)'\t')
                        return true;

        return false;
}

int manager_forward_socket(
                Manager *m,
                const struct iovec *iovec,
                size_t n_iovec,
                const dual_timestamp *ts,
                int priority) {

        _cleanup_free_ struct iovec *iov_alloc = NULL;
        struct iovec *iov;
        _cleanup_free_ le64_t *len_alloc = NULL;
        le64_t *len;
        int r;

        assert(m);
        assert(iovec);
        assert(n_iovec > 0);
        assert(ts);

        if (LOG_PRI(priority) > m->config.max_level_socket)
                return 0;

        r = manager_open_forward_socket(m);
        if (r <= 0)
                return r;

        /* We need a newline after each iovec + 4 for each we have to serialize in a binary safe way
         * + 2 for the final __REALTIME_TIMESTAMP and __MONOTONIC_TIMESTAMP metadata fields. */
        size_t n = n_iovec * 5 + 2;

        if (n < ALLOCA_MAX / (sizeof(struct iovec) + sizeof(le64_t)) / 2) {
                iov = newa(struct iovec, n);
                len = newa(le64_t, n_iovec);
        } else {
                iov_alloc = new(struct iovec, n);
                if (!iov_alloc)
                        return log_oom();

                iov = iov_alloc;

                len_alloc = new(le64_t, n_iovec);
                if (!len_alloc)
                        return log_oom();

                len = len_alloc;
        }

        struct iovec nl = IOVEC_MAKE_STRING("\n");
        size_t iov_idx = 0, len_idx = 0;
        FOREACH_ARRAY(i, iovec, n_iovec) {
                if (must_serialize(*i)) {
                        const uint8_t *c;
                        c = memchr(i->iov_base, '=', i->iov_len);

                        /* this should never happen */
                        if (_unlikely_(!c || c == i->iov_base))
                                return log_warning_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                         "Found invalid journal field, refusing to forward.");

                        /* write the field name */
                        iov[iov_idx++] = IOVEC_MAKE(i->iov_base, c - (uint8_t*) i->iov_base);
                        iov[iov_idx++] = nl;

                        /* write the length of the value */
                        len[len_idx] = htole64(i->iov_len - (c - (uint8_t*) i->iov_base) - 1);
                        iov[iov_idx++] = IOVEC_MAKE(&len[len_idx++], sizeof(le64_t));

                        /* write the raw binary value */
                        iov[iov_idx++] = IOVEC_MAKE(c + 1, i->iov_len - (c - (uint8_t*) i->iov_base) - 1);
                } else
                        /* if it doesn't need special treatment just write the value out */
                        iov[iov_idx++] = *i;

                iov[iov_idx++] = nl;
        }

        /* Synthesise __REALTIME_TIMESTAMP and __MONOTONIC_TIMESTAMP as the last arguments so
         * systemd-journal-upload can receive these export messages. */
        char realtime_buf[STRLEN("__REALTIME_TIMESTAMP=") + DECIMAL_STR_MAX(usec_t) + 1];
        xsprintf(realtime_buf, "__REALTIME_TIMESTAMP="USEC_FMT"\n", ts->realtime);
        iov[iov_idx++] = IOVEC_MAKE_STRING(realtime_buf);

        char monotonic_buf[STRLEN("__MONOTONIC_TIMESTAMP=") + DECIMAL_STR_MAX(usec_t) + 2];
        xsprintf(monotonic_buf, "__MONOTONIC_TIMESTAMP="USEC_FMT"\n\n", ts->monotonic);
        iov[iov_idx++] = IOVEC_MAKE_STRING(monotonic_buf);

        if (writev(m->forward_socket_fd, iov, iov_idx) < 0) {
                log_debug_errno(errno, "Failed to forward log message over socket: %m");

                /* If we failed to send once we will probably fail again so wait for a new connection to
                 * establish before attempting to forward again. */
                m->forward_socket_fd = safe_close(m->forward_socket_fd);
        }

        return 0;
}

void manager_reload_forward_socket(Manager *m, const SocketAddress *old) {
        assert(m);
        assert(old);

        /* The socket is not opened yet or already closed. There is nothing we need to do now. The socket
         * will be opened when necessary. */
        if (m->forward_socket_fd < 0)
                return;

        if (socket_address_equal(&m->config.forward_to_socket, old))
                return;

        /* A different socket address is specified. Let's close the old socket. New socket will be opened
         * when necessary. */
        m->forward_socket_fd = safe_close(m->forward_socket_fd);
}
