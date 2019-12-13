/* SPDX-License-Identifier: LGPL-2.1+ */
#include <sys/poll.h>

#include "fd-util.h"
#include "io-util.h"
#include "nscd-flush.h"
#include "socket-util.h"
#include "strv.h"
#include "time-util.h"

#define NSCD_FLUSH_CACHE_TIMEOUT_USEC (5*USEC_PER_SEC)

struct nscdInvalidateRequest {
        int32_t version;
        int32_t type; /* in glibc this is an enum. We don't replicate this here 1:1. Also, wtf, how unportable is that
                       * even? */
        int32_t key_len;
        char dbname[];
};

static const union sockaddr_union nscd_sa = {
        .un.sun_family = AF_UNIX,
        .un.sun_path = "/run/nscd/socket",
};

static int nscd_flush_cache_one(const char *database, usec_t end) {
        size_t req_size, has_written = 0, has_read = 0, l;
        struct nscdInvalidateRequest *req;
        _cleanup_close_ int fd = -1;
        int32_t resp;
        int events;

        assert(database);

        l = strlen(database);
        req_size = offsetof(struct nscdInvalidateRequest, dbname) + l + 1;

        req = alloca(req_size);
        *req = (struct nscdInvalidateRequest) {
                .version = 2,
                .type = 10,
                .key_len = l + 1,
        };

        strcpy(req->dbname, database);

        fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0)
                return log_debug_errno(errno, "Failed to allocate nscd socket: %m");

        /* Note: connect() returns EINPROGRESS if O_NONBLOCK is set and establishing a connection takes time. The
         * kernel lets us know this way that the connection is now being established, and we should watch with poll()
         * to learn when it is fully established. That said, AF_UNIX on Linux never triggers this IRL (connect() is
         * always instant on AF_UNIX), hence handling this is mostly just an exercise in defensive, protocol-agnostic
         * programming.
         *
         * connect() returns EAGAIN if the socket's backlog limit has been reached. When we see this we give up right
         * away, after all this entire function here is written in a defensive style so that a non-responding nscd
         * doesn't stall us for good. (Even if we wanted to handle this better: the Linux kernel doesn't really have a
         * nice way to connect() to a server synchronously with a time limit that would also cover dealing with the
         * backlog limit. After all SO_RCVTIMEO and SR_SNDTIMEO don't apply to connect(), and alarm() is frickin' ugly
         * and not really reasonably usable from threads-aware code.) */
        if (connect(fd, &nscd_sa.sa, SOCKADDR_UN_LEN(nscd_sa.un)) < 0) {
                if (errno == EAGAIN)
                        return log_debug_errno(errno, "nscd is overloaded (backlog limit reached) and refuses to take further connections: %m");
                if (errno != EINPROGRESS)
                        return log_debug_errno(errno, "Failed to connect to nscd socket: %m");

                /* Continue in case of EINPROGRESS, but don't bother with send() or recv() until being notified that
                 * establishing the connection is complete. */
                events = 0;
        } else
                events = POLLIN|POLLOUT; /* Let's assume initially that we can write and read to the fd, to suppress
                                          * one poll() invocation */
        for (;;) {
                usec_t p;

                if (events & POLLOUT) {
                        ssize_t m;

                        assert(has_written < req_size);

                        m = send(fd, (uint8_t*) req + has_written, req_size - has_written, MSG_NOSIGNAL);
                        if (m < 0) {
                                if (errno != EAGAIN) /* Note that EAGAIN is returned by the kernel whenever it can't
                                                      * take the data right now, and that includes if the connect() is
                                                      * asynchronous and we saw EINPROGRESS on it, and it hasn't
                                                      * completed yet. */
                                        return log_debug_errno(errno, "Failed to write to nscd socket: %m");
                        } else
                                has_written += m;
                }

                if (events & (POLLIN|POLLERR|POLLHUP)) {
                        ssize_t m;

                        if (has_read >= sizeof(resp))
                                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Response from nscd longer than expected: %m");

                        m = recv(fd, (uint8_t*) &resp + has_read, sizeof(resp) - has_read, 0);
                        if (m < 0) {
                                if (errno != EAGAIN)
                                        return log_debug_errno(errno, "Failed to read from nscd socket: %m");
                        } else if (m == 0) { /* EOF */
                                if (has_read == 0 && has_written >= req_size) /* Older nscd immediately terminated the
                                                                               * connection, accept that as OK */
                                        return 1;

                                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "nscd prematurely ended connection.");
                        } else
                                has_read += m;
                }

                if (has_written >= req_size && has_read >= sizeof(resp)) { /* done? */
                        if (resp < 0)
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "nscd sent us a negative error number: %i", resp);
                        if (resp > 0)
                                return log_debug_errno(resp, "nscd return failure code on invalidating '%s'.", database);
                        return 1;
                }

                p = now(CLOCK_MONOTONIC);
                if (p >= end)
                        return -ETIMEDOUT;

                events = fd_wait_for_event(fd, POLLIN | (has_written < req_size ? POLLOUT : 0), end - p);
                if (events < 0)
                        return events;
        }
}

int nscd_flush_cache(char **databases) {
        usec_t end;
        int r = 0;
        char **i;

        /* Tries to invalidate the specified database in nscd. We do this carefully, with a 5s time-out, so that we
         * don't block indefinitely on another service. */

        end = usec_add(now(CLOCK_MONOTONIC), NSCD_FLUSH_CACHE_TIMEOUT_USEC);

        STRV_FOREACH(i, databases) {
                int k;

                k = nscd_flush_cache_one(*i, end);
                if (k < 0 && r >= 0)
                        r = k;
        }

        return r;
}
