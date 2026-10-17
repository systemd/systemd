/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netdb.h>
#include <sys/socket.h>

#include "sd-event.h"
#include "sd-resolve.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "log.h"
#include "parse-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "time-util.h"
#include "timestampd.h"
#include "timestampd-request-internal.h"
#include "unaligned.h"

/* RFC 3161 default port for the TCP transport (IANA "pkix-timestamp"). */
#define TSA_TCP_PORT 318U

/* How many times we take an authority's time-to-check-back at face value before we start imposing a floor
 * of our own on it. */
#define POLL_BACKOFF_AFTER 8U

/* The floor applied to the first poll past POLL_BACKOFF_AFTER. It doubles with every further poll, so an
 * authority that keeps asking us to check back immediately gets backed off rather than busy-looped. */
#define POLL_BACKOFF_BASE_USEC USEC_PER_SEC

/* An upper bound on how long we wait between polls, whether the interval comes from the authority or from
 * our own backoff. RFC 3161 makes time-to-check-back a full 32 bit second count, and the overall request
 * timeout that would otherwise bound it is optional (ConnectionTimeoutSec=infinity). */
#define POLL_INTERVAL_MAX_USEC (5 * USEC_PER_MINUTE)

/* RFC 3161 TCP transport message flags. */
enum {
        TSP_TCP_MSG            = 0x00, /* tsaMsg: payload is a DER TSA message */
        TSP_TCP_POLL_REP       = 0x01, /* pollRep: polling reference + time-to-check-back */
        TSP_TCP_POLL_REQ       = 0x02, /* pollReq: polling reference */
        TSP_TCP_NEG_POLL_REP   = 0x03, /* negPollRep: no further responses */
        TSP_TCP_PARTIAL_MSG_REP = 0x04, /* partialMsgRep: partial TSA message */
        TSP_TCP_FINAL_MSG_REP  = 0x05, /* finalMsgRep: payload is a DER TSA message */
        TSP_TCP_ERROR_MSG_REP  = 0x06, /* errorMsgRep: human readable error message */
};

typedef enum TcpPhase {
        TCP_CONNECTING,
        TCP_SENDING,
        TCP_RECEIVING,
        TCP_POLL_WAITING, /* idling until the authority told us to check back */
} TcpPhase;

typedef struct TimestampRequestTCP {
        TimestampRequest base;

        sd_resolve_query *resolve_query;
        int fd;
        sd_event_source *io_event_source;
        sd_event_source *poll_event_source;
        TcpPhase phase;
        uint8_t *send_buf;
        size_t send_size, send_offset;
        uint8_t *recv_buf;
        size_t recv_size;
        unsigned poll_count;
} TimestampRequestTCP;

static TimestampRequestTCP* TCP(TimestampRequest *req) {
        assert(req);
        assert(req->vtable == &tcp_vtable);

        return (TimestampRequestTCP*) req;
}

static void tcp_init(TimestampRequest *req) {
        TCP(req)->fd = -EBADF;
}

static void tcp_done(TimestampRequest *req) {
        TimestampRequestTCP *tcp = TCP(req);

        tcp->resolve_query = sd_resolve_query_unref(tcp->resolve_query);
        tcp->io_event_source = sd_event_source_unref(tcp->io_event_source);
        tcp->poll_event_source = sd_event_source_unref(tcp->poll_event_source);
        tcp->fd = safe_close(tcp->fd);

        tcp->send_buf = mfree(tcp->send_buf);
        tcp->recv_buf = mfree(tcp->recv_buf);
}

static int tcp_want(TimestampRequestTCP *tcp, uint32_t events) {
        return sd_event_source_set_io_events(tcp->io_event_source, events);
}

static int tcp_build_frame(TimestampRequestTCP *tcp, uint8_t flag, const void *value, size_t value_size) {
        assert(value || value_size == 0);
        assert(!tcp->send_buf);

        /* frame = length (4, be) | flag (1) | value (length - 1) */
        size_t sz = 4 + 1 + value_size;
        tcp->send_buf = malloc(sz);
        if (!tcp->send_buf)
                return log_oom();

        unaligned_write_be32(tcp->send_buf, (uint32_t) (value_size + 1));
        tcp->send_buf[4] = flag;
        memcpy_safe(tcp->send_buf + 5, value, value_size);

        tcp->send_size = sz;
        tcp->send_offset = 0;
        return 0;
}

static int tcp_send_request(TimestampRequestTCP *tcp) {
        TimestampRequest *req = REQUEST(tcp);
        int r;

        /* Wrap the DER request in a tsaMsg frame and start writing it. */
        r = tcp_build_frame(tcp, TSP_TCP_MSG, req->request_der, req->request_der_size);
        if (r < 0)
                return r;

        tcp->phase = TCP_SENDING;
        return tcp_want(tcp, EPOLLOUT);
}

static int tcp_on_poll_timer(sd_event_source *s, uint64_t usec, void *userdata) {
        TimestampRequestTCP *tcp = ASSERT_PTR(userdata);
        _cleanup_(timestamp_request_unrefp) _unused_ TimestampRequest *ref = timestamp_request_ref(REQUEST(tcp));
        int r;

        tcp->poll_event_source = sd_event_source_unref(tcp->poll_event_source);

        tcp->phase = TCP_SENDING;

        r = sd_event_source_set_enabled(tcp->io_event_source, SD_EVENT_ON);
        if (r >= 0)
                r = tcp_want(tcp, EPOLLOUT);
        if (r < 0) {
                log_error_errno(r, "Failed to resume sending to the authority: %m");
                timestamp_request_fail_errno(REQUEST(tcp), r);
        }

        return 0;
}

/* How long to wait before the next poll. We honour what the authority asked for, but once it has put us off
 * POLL_BACKOFF_AFTER times we impose a floor that doubles with each further poll. This avoids busy looping
 * if an authority continuously answers "check back immediately". */
static usec_t tcp_poll_delay(TimestampRequestTCP *tcp, uint32_t check_back) {
        assert(tcp);
        assert(tcp->poll_count > 0);

        usec_t delay = check_back * USEC_PER_SEC;

        if (tcp->poll_count > POLL_BACKOFF_AFTER) {
                /* Clamped to 9 to keep the shift well-defined; this gives 512 seconds which is clamped
                 * by the ceiling at POLL_INTERVAL_MAX_USEC anyway. */
                unsigned shift = MIN(tcp->poll_count - POLL_BACKOFF_AFTER - 1, 9U);

                delay = MAX(delay, POLL_BACKOFF_BASE_USEC << shift);
        }

        return MIN(delay, POLL_INTERVAL_MAX_USEC);
}

/* Prepare the next pollReq from a pollRep's value (polling reference + time-to-check-back) and arm a timer
 * to send it. */
static int tcp_poll_again(TimestampRequestTCP *tcp, const uint8_t *value) {
        int r;

        assert(tcp);
        assert(value);
        assert(!tcp->poll_event_source);

        free(tcp->send_buf);
        tcp->send_buf = NULL;

        r = tcp_build_frame(tcp, TSP_TCP_POLL_REQ, value, 4); /* echo the polling reference */
        if (r < 0)
                return r;

        tcp->recv_size = 0;

        /* Nothing is expected on the socket while we idle. */
        r = sd_event_source_set_enabled(tcp->io_event_source, SD_EVENT_OFF);
        if (r < 0)
                return r;

        tcp->phase = TCP_POLL_WAITING;

        return sd_event_add_time_relative(
                        REQUEST(tcp)->manager->event, &tcp->poll_event_source, CLOCK_MONOTONIC,
                        tcp_poll_delay(tcp, unaligned_read_be32(value + 4)),
                        /* accuracy= */ USEC_PER_SEC, tcp_on_poll_timer, tcp);
}

static int tcp_dispatch_frame(TimestampRequestTCP *tcp, uint8_t flag, const uint8_t *value, size_t value_size) {
        int r;

        switch (flag) {

        case TSP_TCP_FINAL_MSG_REP:
                timestamp_request_succeed(REQUEST(tcp), value, value_size);
                return 0;

        case TSP_TCP_ERROR_MSG_REP: {
                _cleanup_free_ char *msg = memdup_suffix0(value, value_size);
                timestamp_request_fail(REQUEST(tcp), TIMESTAMP_FAILURE_CONNECTION,
                                       msg && !isempty(msg) ? msg : "Authority returned an error message");
                return 0;
        }

        case TSP_TCP_POLL_REP:
                /* value = polling reference (4) + time-to-check-back (4), both mandatory. */
                if (value_size < 8) {
                        timestamp_request_fail(REQUEST(tcp), TIMESTAMP_FAILURE_INVALID_RESPONSE,
                                               "Malformed pollRep from authority");
                        return 0;
                }

                tcp->poll_count++;

                r = tcp_poll_again(tcp, value);
                if (r < 0) {
                        log_error_errno(r, "Failed to schedule the next poll of the authority: %m");
                        timestamp_request_fail_errno(REQUEST(tcp), r);
                }
                return 0;

        case TSP_TCP_NEG_POLL_REP:
                timestamp_request_fail(REQUEST(tcp), TIMESTAMP_FAILURE_CONNECTION,
                                       "Authority declined to provide a token");
                return 0;

        case TSP_TCP_PARTIAL_MSG_REP:
                timestamp_request_fail(REQUEST(tcp), TIMESTAMP_FAILURE_INVALID_RESPONSE,
                                       "Authority used the unsupported partial-message response");
                return 0;

        default:
                timestamp_request_fail(REQUEST(tcp), TIMESTAMP_FAILURE_INVALID_RESPONSE,
                                       "Authority sent an unexpected message type");
                return 0;
        }
}

static int tcp_on_readable(TimestampRequestTCP *tcp) {
        /* Read whatever is available, then try to decode one complete frame:
         *   length (4, be) | flag (1) | value (length - 1) */
        for (;;) {
                uint8_t buf[64U*U64_KB];
                int n;

                n = RET_NERRNO(read(tcp->fd, buf, sizeof(buf)));
                if (n < 0) {
                        if (n == -EINTR)
                                continue;
                        if (n == -EAGAIN)
                                return 0; /* wait for the next EPOLLIN */
                        timestamp_request_fail(REQUEST(tcp), TIMESTAMP_FAILURE_CONNECTION,
                                               strjoina("Failed to read from authority: ", STRERROR(n)));
                        return 0;
                }
                if (n == 0)
                        break;

                if (tcp->recv_size + (size_t) n > RESPONSE_MAX) {
                        timestamp_request_fail(REQUEST(tcp), TIMESTAMP_FAILURE_INVALID_RESPONSE,
                                               "Response from authority too large");
                        return 0;
                }
                if (!GREEDY_REALLOC(tcp->recv_buf, tcp->recv_size + n)) {
                        timestamp_request_fail_errno(REQUEST(tcp), log_oom());
                        return 0;
                }
                memcpy(tcp->recv_buf + tcp->recv_size, buf, n);
                tcp->recv_size += n;
        }

        if (tcp->recv_size < 4) {
                /* Need at least the length. */
                timestamp_request_fail(REQUEST(tcp), TIMESTAMP_FAILURE_CONNECTION,
                                       "Authority closed the connection prematurely");
                return 0;
        }

        uint32_t length = unaligned_read_be32(tcp->recv_buf);
        if (length < 1) {
                /* The length is always at least 1. */
                timestamp_request_fail(REQUEST(tcp), TIMESTAMP_FAILURE_INVALID_RESPONSE,
                                       "Invalid length in authority response");
                return 0;
        }
        if (tcp->recv_size < 4 + (size_t) length) {
                timestamp_request_fail(REQUEST(tcp), TIMESTAMP_FAILURE_CONNECTION,
                                       "Authority closed the connection prematurely");
                return 0;
        }

        uint8_t flag = tcp->recv_buf[4];
        return tcp_dispatch_frame(tcp, flag, tcp->recv_buf + 5, length - 1);
}

static int tcp_on_writable(TimestampRequestTCP *tcp) {
        int r;

        if (tcp->phase == TCP_CONNECTING) {
                int err = 0;
                socklen_t l = sizeof(err);

                r = RET_NERRNO(getsockopt(tcp->fd, SOL_SOCKET, SO_ERROR, &err, &l));
                if (r < 0) {
                        timestamp_request_fail_errno(REQUEST(tcp), r);
                        return 0;
                }
                if (err != 0) {
                        timestamp_request_fail(REQUEST(tcp), TIMESTAMP_FAILURE_CONNECTION,
                                               strjoina("Failed to connect to authority: ", STRERROR(err)));
                        return 0;
                }

                r = tcp_send_request(tcp);
                if (r < 0) {
                        log_error_errno(r, "Failed to start sending the request to the authority: %m");
                        timestamp_request_fail_errno(REQUEST(tcp), r);
                }

                return 0;
        }

        assert(tcp->phase == TCP_SENDING);

        while (tcp->send_offset < tcp->send_size) {
                int n = RET_NERRNO(write(tcp->fd, tcp->send_buf + tcp->send_offset, tcp->send_size - tcp->send_offset));
                if (n < 0) {
                        if (n == -EINTR)
                                continue;
                        if (n == -EAGAIN)
                                return 0; /* wait for the next EPOLLOUT */
                        timestamp_request_fail(REQUEST(tcp), TIMESTAMP_FAILURE_CONNECTION,
                                               strjoina("Failed to send request to authority: ", STRERROR(n)));
                        return 0;
                }
                tcp->send_offset += n;
        }

        tcp->phase = TCP_RECEIVING;

        r = tcp_want(tcp, EPOLLIN);
        if (r < 0) {
                log_error_errno(r, "Failed to wait for the authority's response: %m");
                timestamp_request_fail_errno(REQUEST(tcp), r);
        }

        return 0;
}

static int tcp_io_handler(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        TimestampRequestTCP *tcp = ASSERT_PTR(userdata);
        _cleanup_(timestamp_request_unrefp) _unused_ TimestampRequest *ref = timestamp_request_ref(REQUEST(tcp));

        if (revents & (EPOLLHUP|EPOLLERR) && tcp->phase != TCP_RECEIVING) {
                timestamp_request_fail(REQUEST(tcp), TIMESTAMP_FAILURE_CONNECTION,
                                       "Connection to authority failed");
                return 0;
        }

        if (revents & EPOLLOUT)
                return tcp_on_writable(tcp);

        if (revents & (EPOLLIN|EPOLLHUP))
                return tcp_on_readable(tcp);

        return 0;
}

static int tcp_on_resolved(sd_resolve_query *q, int ret, const struct addrinfo *ai, void *userdata) {
        TimestampRequestTCP *tcp = ASSERT_PTR(userdata);
        _cleanup_(timestamp_request_unrefp) _unused_ TimestampRequest *ref = timestamp_request_ref(REQUEST(tcp));
        int r;

        tcp->resolve_query = sd_resolve_query_unref(tcp->resolve_query);

        if (ret != 0) {
                if (ret == EAI_MEMORY)
                        timestamp_request_fail_errno(REQUEST(tcp), -ENOMEM);
                else if (ret == EAI_SYSTEM)
                        timestamp_request_fail_errno(REQUEST(tcp), negative_errno());
                else
                        timestamp_request_fail(REQUEST(tcp), TIMESTAMP_FAILURE_NAME_RESOLUTION,
                                               gai_strerror(ret));
                return 0;
        }

        /* Try each address in turn; use the first for which a (non-blocking) connect gets under way,
         * remembering why the last one we gave up on failed. */
        int error = -ENOENT;
        for (const struct addrinfo *i = ai; i; i = i->ai_next) {
                _cleanup_close_ int fd = -EBADF;

                if (!IN_SET(i->ai_family, AF_INET, AF_INET6))
                        continue;

                /* The transport is TCP by definition, so don't take the socket type from the resolver
                 * result, even though our hints constrain it. */
                fd = RET_NERRNO(socket(i->ai_family, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, IPPROTO_TCP));
                if (fd < 0) {
                        error = fd;
                        continue;
                }

                bool connected;
                r = RET_NERRNO(connect(fd, i->ai_addr, i->ai_addrlen));
                if (r < 0) {
                        if (r != -EINPROGRESS) {
                                error = r;
                                continue;
                        }
                        connected = false;
                } else
                        connected = true;

                tcp->fd = TAKE_FD(fd);
                tcp->phase = TCP_CONNECTING;

                r = sd_event_add_io(REQUEST(tcp)->manager->event, &tcp->io_event_source, tcp->fd, EPOLLOUT, tcp_io_handler, tcp);
                if (r < 0) {
                        timestamp_request_fail_errno(REQUEST(tcp), r);
                        return 0;
                }

                /* If connect() completed immediately, proceed straight to sending. */
                if (connected) {
                        r = tcp_send_request(tcp);
                        if (r < 0) {
                                log_error_errno(r, "Failed to start sending the request to the authority: %m");
                                timestamp_request_fail_errno(REQUEST(tcp), r);
                        }
                }

                return 0;
        }

        timestamp_request_fail(REQUEST(tcp), TIMESTAMP_FAILURE_CONNECTION,
                               strjoina("Could not connect to any address of the authority: ", STRERROR(error)));
        return 0;
}

static int manager_ensure_resolve(Manager *m) {
        int r;

        assert(m);

        if (m->resolve)
                return 0;

        r = sd_resolve_default(&m->resolve);
        if (r < 0)
                return r;

        r = sd_resolve_attach_event(m->resolve, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0) {
                m->resolve = sd_resolve_unref(m->resolve);
                return r;
        }

        return 0;
}

static int parse_tcp_authority(const char *url, char **ret_host, uint16_t *ret_port) {
        _cleanup_free_ char *host = NULL;
        const char *rest;
        int r;

        assert(url);

        rest = ASSERT_PTR(startswith(url, "tcp://"));

        /* A tcp:// authority is a host and an optional port and nothing else. Reject anything carrying a
         * path, query or fragment rather than letting it end up inside the host or the port, where it
         * would turn into a resolver failure. */
        if (strpbrk(rest, "/?#"))
                return -EINVAL;

        if (*rest == '[') {
                /* Bracketed IPv6 literal: [addr] or [addr]:port */
                const char *end = strchr(rest, ']');
                if (!end || end == rest + 1)
                        return -EINVAL;

                host = strndup(rest + 1, end - rest - 1);
                if (!host)
                        return -ENOMEM;

                rest = end + 1;
                if (*rest == ':')
                        rest++;
                else if (*rest != '\0')
                        return -EINVAL;
                else
                        rest = NULL;
        } else {
                const char *colon = strchr(rest, ':');
                if (colon) {
                        host = strndup(rest, colon - rest);
                        rest = colon + 1;
                } else {
                        host = strdup(rest);
                        rest = NULL;
                }
                if (!host)
                        return -ENOMEM;
        }

        if (isempty(host))
                return -EINVAL;

        uint16_t port = TSA_TCP_PORT;
        if (!isempty(rest)) {
                r = parse_ip_port(rest, &port);
                if (r < 0)
                        return r;
        }

        if (ret_host)
                *ret_host = TAKE_PTR(host);
        if (ret_port)
                *ret_port = port;
        return 0;
}

static bool tcp_validate(const char *authority) {
        return parse_tcp_authority(authority, /* ret_host= */ NULL, /* ret_port= */ NULL) >= 0;
}

static int tcp_start(TimestampRequest *req) {
        static const struct addrinfo hints = {
                .ai_family = AF_UNSPEC,
                .ai_socktype = SOCK_STREAM,
                .ai_protocol = IPPROTO_TCP,
                .ai_flags = AI_NUMERICSERV,
        };
        TimestampRequestTCP *tcp = TCP(req);
        _cleanup_free_ char *host = NULL;
        char port[DECIMAL_STR_MAX(uint16_t)];
        uint16_t port_nr;
        int r;

        r = parse_tcp_authority(req->authority, &host, &port_nr);
        if (r < 0)
                return r;

        xsprintf(port, "%" PRIu16, port_nr);

        r = manager_ensure_resolve(req->manager);
        if (r < 0)
                return r;

        r = sd_resolve_getaddrinfo(req->manager->resolve, &tcp->resolve_query, host, port, &hints, tcp_on_resolved, tcp);
        if (r < 0)
                return r;

        return 0;
}

static const char* const tcp_schemes[] = {
        "tcp://",
        NULL,
};

const TransportVTable tcp_vtable = {
        .name = "TCP",
        .schemes = tcp_schemes,
        .object_size = sizeof(TimestampRequestTCP),
        .validate = tcp_validate,
        .init = tcp_init,
        .done = tcp_done,
        .start = tcp_start,
};
