/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <resolv.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "sd-resolve.h"

#include "alloc-util.h"
#include "dns-domain.h"
#include "fd-util.h"
#include "io-util.h"
#include "list.h"
#include "missing.h"
#include "socket-util.h"
#include "util.h"
#include "process-util.h"

#define WORKERS_MIN 1U
#define WORKERS_MAX 16U
#define QUERIES_MAX 256U
#define BUFSIZE 10240U

typedef enum {
        REQUEST_ADDRINFO,
        RESPONSE_ADDRINFO,
        REQUEST_NAMEINFO,
        RESPONSE_NAMEINFO,
        REQUEST_TERMINATE,
        RESPONSE_DIED
} QueryType;

enum {
        REQUEST_RECV_FD,
        REQUEST_SEND_FD,
        RESPONSE_RECV_FD,
        RESPONSE_SEND_FD,
        _FD_MAX
};

struct sd_resolve {
        unsigned n_ref;

        bool dead:1;
        pid_t original_pid;

        int fds[_FD_MAX];

        pthread_t workers[WORKERS_MAX];
        unsigned n_valid_workers;

        unsigned current_id;
        sd_resolve_query* query_array[QUERIES_MAX];
        unsigned n_queries, n_done, n_outstanding;

        sd_event_source *event_source;
        sd_event *event;

        sd_resolve_query *current;

        sd_resolve **default_resolve_ptr;
        pid_t tid;

        LIST_HEAD(sd_resolve_query, queries);
};

struct sd_resolve_query {
        unsigned n_ref;

        sd_resolve *resolve;

        QueryType type:4;
        bool done:1;
        bool floating:1;
        unsigned id;

        int ret;
        int _errno;
        int _h_errno;
        struct addrinfo *addrinfo;
        char *serv, *host;

        union {
                sd_resolve_getaddrinfo_handler_t getaddrinfo_handler;
                sd_resolve_getnameinfo_handler_t getnameinfo_handler;
        };

        void *userdata;
        sd_resolve_destroy_t destroy_callback;

        LIST_FIELDS(sd_resolve_query, queries);
};

typedef struct RHeader {
        QueryType type;
        unsigned id;
        size_t length;
} RHeader;

typedef struct AddrInfoRequest {
        struct RHeader header;
        bool hints_valid;
        int ai_flags;
        int ai_family;
        int ai_socktype;
        int ai_protocol;
        size_t node_len, service_len;
} AddrInfoRequest;

typedef struct AddrInfoResponse {
        struct RHeader header;
        int ret;
        int _errno;
        int _h_errno;
        /* followed by addrinfo_serialization[] */
} AddrInfoResponse;

typedef struct AddrInfoSerialization {
        int ai_flags;
        int ai_family;
        int ai_socktype;
        int ai_protocol;
        size_t ai_addrlen;
        size_t canonname_len;
        /* Followed by ai_addr amd ai_canonname with variable lengths */
} AddrInfoSerialization;

typedef struct NameInfoRequest {
        struct RHeader header;
        int flags;
        socklen_t sockaddr_len;
        bool gethost:1, getserv:1;
} NameInfoRequest;

typedef struct NameInfoResponse {
        struct RHeader header;
        size_t hostlen, servlen;
        int ret;
        int _errno;
        int _h_errno;
} NameInfoResponse;

typedef union Packet {
        RHeader rheader;
        AddrInfoRequest addrinfo_request;
        AddrInfoResponse addrinfo_response;
        NameInfoRequest nameinfo_request;
        NameInfoResponse nameinfo_response;
} Packet;

static int getaddrinfo_done(sd_resolve_query* q);
static int getnameinfo_done(sd_resolve_query *q);

static void resolve_query_disconnect(sd_resolve_query *q);

#define RESOLVE_DONT_DESTROY(resolve) \
        _cleanup_(sd_resolve_unrefp) _unused_ sd_resolve *_dont_destroy_##resolve = sd_resolve_ref(resolve)

static void query_assign_errno(sd_resolve_query *q, int ret, int error, int h_error) {
        assert(q);

        q->ret = ret;
        q->_errno = abs(error);
        q->_h_errno = h_error;
}

static int send_died(int out_fd) {
        RHeader rh = {
                .type = RESPONSE_DIED,
                .length = sizeof(RHeader),
        };

        assert(out_fd >= 0);

        if (send(out_fd, &rh, rh.length, MSG_NOSIGNAL) < 0)
                return -errno;

        return 0;
}

static void *serialize_addrinfo(void *p, const struct addrinfo *ai, size_t *length, size_t maxlength) {
        AddrInfoSerialization s;
        size_t cnl, l;

        assert(p);
        assert(ai);
        assert(length);
        assert(*length <= maxlength);

        cnl = ai->ai_canonname ? strlen(ai->ai_canonname)+1 : 0;
        l = sizeof(AddrInfoSerialization) + ai->ai_addrlen + cnl;

        if (*length + l > maxlength)
                return NULL;

        s = (AddrInfoSerialization) {
                .ai_flags = ai->ai_flags,
                .ai_family = ai->ai_family,
                .ai_socktype = ai->ai_socktype,
                .ai_protocol = ai->ai_protocol,
                .ai_addrlen = ai->ai_addrlen,
                .canonname_len = cnl,
        };

        memcpy((uint8_t*) p, &s, sizeof(AddrInfoSerialization));
        memcpy((uint8_t*) p + sizeof(AddrInfoSerialization), ai->ai_addr, ai->ai_addrlen);
        memcpy_safe((char*) p + sizeof(AddrInfoSerialization) + ai->ai_addrlen,
                    ai->ai_canonname, cnl);

        *length += l;
        return (uint8_t*) p + l;
}

static int send_addrinfo_reply(
                int out_fd,
                unsigned id,
                int ret,
                struct addrinfo *ai,
                int _errno,
                int _h_errno) {

        AddrInfoResponse resp = {};
        union {
                AddrInfoSerialization ais;
                uint8_t space[BUFSIZE];
        } buffer;
        struct iovec iov[2];
        struct msghdr mh;

        assert(out_fd >= 0);

        resp = (AddrInfoResponse) {
                .header.type = RESPONSE_ADDRINFO,
                .header.id = id,
                .header.length = sizeof(AddrInfoResponse),
                .ret = ret,
                ._errno = _errno,
                ._h_errno = _h_errno,
        };

        if (ret == 0 && ai) {
                void *p = &buffer;
                struct addrinfo *k;

                for (k = ai; k; k = k->ai_next) {
                        p = serialize_addrinfo(p, k, &resp.header.length, (uint8_t*) &buffer + BUFSIZE - (uint8_t*) p);
                        if (!p) {
                                freeaddrinfo(ai);
                                return -ENOBUFS;
                        }
                }
        }

        if (ai)
                freeaddrinfo(ai);

        iov[0] = (struct iovec) { .iov_base = &resp, .iov_len = sizeof(AddrInfoResponse) };
        iov[1] = (struct iovec) { .iov_base = &buffer, .iov_len = resp.header.length - sizeof(AddrInfoResponse) };

        mh = (struct msghdr) { .msg_iov = iov, .msg_iovlen = ELEMENTSOF(iov) };

        if (sendmsg(out_fd, &mh, MSG_NOSIGNAL) < 0)
                return -errno;

        return 0;
}

static int send_nameinfo_reply(
                int out_fd,
                unsigned id,
                int ret,
                const char *host,
                const char *serv,
                int _errno,
                int _h_errno) {

        NameInfoResponse resp = {};
        struct iovec iov[3];
        struct msghdr mh;
        size_t hl, sl;

        assert(out_fd >= 0);

        sl = serv ? strlen(serv)+1 : 0;
        hl = host ? strlen(host)+1 : 0;

        resp = (NameInfoResponse) {
                .header.type = RESPONSE_NAMEINFO,
                .header.id = id,
                .header.length = sizeof(NameInfoResponse) + hl + sl,
                .hostlen = hl,
                .servlen = sl,
                .ret = ret,
                ._errno = _errno,
                ._h_errno = _h_errno,
        };

        iov[0] = (struct iovec) { .iov_base = &resp, .iov_len = sizeof(NameInfoResponse) };
        iov[1] = (struct iovec) { .iov_base = (void*) host, .iov_len = hl };
        iov[2] = (struct iovec) { .iov_base = (void*) serv, .iov_len = sl };

        mh = (struct msghdr) { .msg_iov = iov, .msg_iovlen = ELEMENTSOF(iov) };

        if (sendmsg(out_fd, &mh, MSG_NOSIGNAL) < 0)
                return -errno;

        return 0;
}

static int handle_request(int out_fd, const Packet *packet, size_t length) {
        const RHeader *req;

        assert(out_fd >= 0);
        assert(packet);

        req = &packet->rheader;

        assert_return(length >= sizeof(RHeader), -EIO);
        assert_return(length == req->length, -EIO);

        switch (req->type) {

        case REQUEST_ADDRINFO: {
               const AddrInfoRequest *ai_req = &packet->addrinfo_request;
               struct addrinfo hints, *result = NULL;
               const char *node, *service;
               int ret;

               assert_return(length >= sizeof(AddrInfoRequest), -EBADMSG);
               assert_return(length == sizeof(AddrInfoRequest) + ai_req->node_len + ai_req->service_len, -EBADMSG);

               hints = (struct addrinfo) {
                       .ai_flags = ai_req->ai_flags,
                       .ai_family = ai_req->ai_family,
                       .ai_socktype = ai_req->ai_socktype,
                       .ai_protocol = ai_req->ai_protocol,
               };

               node = ai_req->node_len ? (const char*) ai_req + sizeof(AddrInfoRequest) : NULL;
               service = ai_req->service_len ? (const char*) ai_req + sizeof(AddrInfoRequest) + ai_req->node_len : NULL;

               ret = getaddrinfo(node, service,
                                 ai_req->hints_valid ? &hints : NULL,
                                 &result);

               /* send_addrinfo_reply() frees result */
               return send_addrinfo_reply(out_fd, req->id, ret, result, errno, h_errno);
        }

        case REQUEST_NAMEINFO: {
               const NameInfoRequest *ni_req = &packet->nameinfo_request;
               char hostbuf[NI_MAXHOST], servbuf[NI_MAXSERV];
               union sockaddr_union sa;
               int ret;

               assert_return(length >= sizeof(NameInfoRequest), -EBADMSG);
               assert_return(length == sizeof(NameInfoRequest) + ni_req->sockaddr_len, -EBADMSG);
               assert_return(ni_req->sockaddr_len <= sizeof(sa), -EBADMSG);

               memcpy(&sa, (const uint8_t *) ni_req + sizeof(NameInfoRequest), ni_req->sockaddr_len);

               ret = getnameinfo(&sa.sa, ni_req->sockaddr_len,
                                 ni_req->gethost ? hostbuf : NULL, ni_req->gethost ? sizeof(hostbuf) : 0,
                                 ni_req->getserv ? servbuf : NULL, ni_req->getserv ? sizeof(servbuf) : 0,
                                 ni_req->flags);

               return send_nameinfo_reply(out_fd, req->id, ret,
                                          ret == 0 && ni_req->gethost ? hostbuf : NULL,
                                          ret == 0 && ni_req->getserv ? servbuf : NULL,
                                          errno, h_errno);
        }

        case REQUEST_TERMINATE:
                 /* Quit */
                 return -ECONNRESET;

        default:
                assert_not_reached("Unknown request");
        }

        return 0;
}

static void* thread_worker(void *p) {
        sd_resolve *resolve = p;

        /* Assign a pretty name to this thread */
        (void) pthread_setname_np(pthread_self(), "sd-resolve");

        while (!resolve->dead) {
                union {
                        Packet packet;
                        uint8_t space[BUFSIZE];
                } buf;
                ssize_t length;

                length = recv(resolve->fds[REQUEST_RECV_FD], &buf, sizeof buf, 0);
                if (length < 0) {
                        if (errno == EINTR)
                                continue;

                        break;
                }
                if (length == 0)
                        break;

                if (handle_request(resolve->fds[RESPONSE_SEND_FD], &buf.packet, (size_t) length) < 0)
                        break;
        }

        send_died(resolve->fds[RESPONSE_SEND_FD]);

        return NULL;
}

static int start_threads(sd_resolve *resolve, unsigned extra) {
        sigset_t ss, saved_ss;
        unsigned n;
        int r, k;

        if (sigfillset(&ss) < 0)
                return -errno;

        /* No signals in forked off threads please. We set the mask before forking, so that the threads never exist
         * with a different mask than a fully blocked one */
        r = pthread_sigmask(SIG_BLOCK, &ss, &saved_ss);
        if (r > 0)
                return -r;

        n = resolve->n_outstanding + extra;
        n = CLAMP(n, WORKERS_MIN, WORKERS_MAX);

        while (resolve->n_valid_workers < n) {
                r = pthread_create(&resolve->workers[resolve->n_valid_workers], NULL, thread_worker, resolve);
                if (r > 0) {
                        r = -r;
                        goto finish;
                }

                resolve->n_valid_workers++;
        }

        r = 0;

finish:
        k = pthread_sigmask(SIG_SETMASK, &saved_ss, NULL);
        if (k > 0 && r >= 0)
                r = -k;

        return r;
}

static bool resolve_pid_changed(sd_resolve *r) {
        assert(r);

        /* We don't support people creating a resolver and keeping it
         * around after fork(). Let's complain. */

        return r->original_pid != getpid_cached();
}

_public_ int sd_resolve_new(sd_resolve **ret) {
        _cleanup_(sd_resolve_unrefp) sd_resolve *resolve = NULL;
        int i;

        assert_return(ret, -EINVAL);

        resolve = new0(sd_resolve, 1);
        if (!resolve)
                return -ENOMEM;

        resolve->n_ref = 1;
        resolve->original_pid = getpid_cached();

        for (i = 0; i < _FD_MAX; i++)
                resolve->fds[i] = -1;

        if (socketpair(PF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, resolve->fds + REQUEST_RECV_FD) < 0)
                return -errno;

        if (socketpair(PF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, resolve->fds + RESPONSE_RECV_FD) < 0)
                return -errno;

        for (i = 0; i < _FD_MAX; i++)
                resolve->fds[i] = fd_move_above_stdio(resolve->fds[i]);

        (void) fd_inc_sndbuf(resolve->fds[REQUEST_SEND_FD], QUERIES_MAX * BUFSIZE);
        (void) fd_inc_rcvbuf(resolve->fds[REQUEST_RECV_FD], QUERIES_MAX * BUFSIZE);
        (void) fd_inc_sndbuf(resolve->fds[RESPONSE_SEND_FD], QUERIES_MAX * BUFSIZE);
        (void) fd_inc_rcvbuf(resolve->fds[RESPONSE_RECV_FD], QUERIES_MAX * BUFSIZE);

        (void) fd_nonblock(resolve->fds[RESPONSE_RECV_FD], true);

        *ret = TAKE_PTR(resolve);
        return 0;
}

_public_ int sd_resolve_default(sd_resolve **ret) {
        static thread_local sd_resolve *default_resolve = NULL;
        sd_resolve *e = NULL;
        int r;

        if (!ret)
                return !!default_resolve;

        if (default_resolve) {
                *ret = sd_resolve_ref(default_resolve);
                return 0;
        }

        r = sd_resolve_new(&e);
        if (r < 0)
                return r;

        e->default_resolve_ptr = &default_resolve;
        e->tid = gettid();
        default_resolve = e;

        *ret = e;
        return 1;
}

_public_ int sd_resolve_get_tid(sd_resolve *resolve, pid_t *tid) {
        assert_return(resolve, -EINVAL);
        assert_return(tid, -EINVAL);
        assert_return(!resolve_pid_changed(resolve), -ECHILD);

        if (resolve->tid != 0) {
                *tid = resolve->tid;
                return 0;
        }

        if (resolve->event)
                return sd_event_get_tid(resolve->event, tid);

        return -ENXIO;
}

static sd_resolve *resolve_free(sd_resolve *resolve) {
        PROTECT_ERRNO;
        sd_resolve_query *q;
        unsigned i;

        assert(resolve);

        while ((q = resolve->queries)) {
                assert(q->floating);
                resolve_query_disconnect(q);
                sd_resolve_query_unref(q);
        }

        if (resolve->default_resolve_ptr)
                *(resolve->default_resolve_ptr) = NULL;

        resolve->dead = true;

        sd_resolve_detach_event(resolve);

        if (resolve->fds[REQUEST_SEND_FD] >= 0) {

                RHeader req = {
                        .type = REQUEST_TERMINATE,
                        .length = sizeof req,
                };

                /* Send one termination packet for each worker */
                for (i = 0; i < resolve->n_valid_workers; i++)
                        (void) send(resolve->fds[REQUEST_SEND_FD], &req, req.length, MSG_NOSIGNAL);
        }

        /* Now terminate them and wait until they are gone.
           If we get an error than most likely the thread already exited. */
        for (i = 0; i < resolve->n_valid_workers; i++)
                (void) pthread_join(resolve->workers[i], NULL);

        /* Close all communication channels */
        close_many(resolve->fds, _FD_MAX);

        return mfree(resolve);
}

DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(sd_resolve, sd_resolve, resolve_free);

_public_ int sd_resolve_get_fd(sd_resolve *resolve) {
        assert_return(resolve, -EINVAL);
        assert_return(!resolve_pid_changed(resolve), -ECHILD);

        return resolve->fds[RESPONSE_RECV_FD];
}

_public_ int sd_resolve_get_events(sd_resolve *resolve) {
        assert_return(resolve, -EINVAL);
        assert_return(!resolve_pid_changed(resolve), -ECHILD);

        return resolve->n_queries > resolve->n_done ? POLLIN : 0;
}

_public_ int sd_resolve_get_timeout(sd_resolve *resolve, uint64_t *usec) {
        assert_return(resolve, -EINVAL);
        assert_return(usec, -EINVAL);
        assert_return(!resolve_pid_changed(resolve), -ECHILD);

        *usec = (uint64_t) -1;
        return 0;
}

static sd_resolve_query *lookup_query(sd_resolve *resolve, unsigned id) {
        sd_resolve_query *q;

        assert(resolve);

        q = resolve->query_array[id % QUERIES_MAX];
        if (q)
                if (q->id == id)
                        return q;

        return NULL;
}

static int complete_query(sd_resolve *resolve, sd_resolve_query *q) {
        int r;

        assert(q);
        assert(!q->done);
        assert(q->resolve == resolve);

        q->done = true;
        resolve->n_done++;

        resolve->current = sd_resolve_query_ref(q);

        switch (q->type) {

        case REQUEST_ADDRINFO:
                r = getaddrinfo_done(q);
                break;

        case REQUEST_NAMEINFO:
                r = getnameinfo_done(q);
                break;

        default:
                assert_not_reached("Cannot complete unknown query type");
        }

        resolve->current = NULL;

        if (q->floating) {
                resolve_query_disconnect(q);
                sd_resolve_query_unref(q);
        }

        sd_resolve_query_unref(q);

        return r;
}

static int unserialize_addrinfo(const void **p, size_t *length, struct addrinfo **ret_ai) {
        AddrInfoSerialization s;
        struct addrinfo *ai;
        size_t l;

        assert(p);
        assert(*p);
        assert(ret_ai);
        assert(length);

        if (*length < sizeof(AddrInfoSerialization))
                return -EBADMSG;

        memcpy(&s, *p, sizeof(s));

        l = sizeof(AddrInfoSerialization) + s.ai_addrlen + s.canonname_len;
        if (*length < l)
                return -EBADMSG;

        ai = new(struct addrinfo, 1);
        if (!ai)
                return -ENOMEM;

        *ai = (struct addrinfo) {
                .ai_flags = s.ai_flags,
                .ai_family = s.ai_family,
                .ai_socktype = s.ai_socktype,
                .ai_protocol = s.ai_protocol,
                .ai_addrlen = s.ai_addrlen,
        };

        if (s.ai_addrlen > 0) {
                ai->ai_addr = memdup((const uint8_t*) *p + sizeof(AddrInfoSerialization), s.ai_addrlen);
                if (!ai->ai_addr) {
                        free(ai);
                        return -ENOMEM;
                }
        }

        if (s.canonname_len > 0) {
                ai->ai_canonname = memdup((const uint8_t*) *p + sizeof(AddrInfoSerialization) + s.ai_addrlen, s.canonname_len);
                if (!ai->ai_canonname) {
                        free(ai->ai_addr);
                        free(ai);
                        return -ENOMEM;
                }
        }

        *length -= l;
        *ret_ai = ai;
        *p = ((const uint8_t*) *p) + l;

        return 0;
}

static int handle_response(sd_resolve *resolve, const Packet *packet, size_t length) {
        const RHeader *resp;
        sd_resolve_query *q;
        int r;

        assert(resolve);
        assert(packet);

        resp = &packet->rheader;
        assert_return(length >= sizeof(RHeader), -EIO);
        assert_return(length == resp->length, -EIO);

        if (resp->type == RESPONSE_DIED) {
                resolve->dead = true;
                return 0;
        }

        assert(resolve->n_outstanding > 0);
        resolve->n_outstanding--;

        q = lookup_query(resolve, resp->id);
        if (!q)
                return 0;

        switch (resp->type) {

        case RESPONSE_ADDRINFO: {
                const AddrInfoResponse *ai_resp = &packet->addrinfo_response;
                const void *p;
                size_t l;
                struct addrinfo *prev = NULL;

                assert_return(length >= sizeof(AddrInfoResponse), -EBADMSG);
                assert_return(q->type == REQUEST_ADDRINFO, -EBADMSG);

                query_assign_errno(q, ai_resp->ret, ai_resp->_errno, ai_resp->_h_errno);

                l = length - sizeof(AddrInfoResponse);
                p = (const uint8_t*) resp + sizeof(AddrInfoResponse);

                while (l > 0 && p) {
                        struct addrinfo *ai = NULL;

                        r = unserialize_addrinfo(&p, &l, &ai);
                        if (r < 0) {
                                query_assign_errno(q, EAI_SYSTEM, r, 0);
                                freeaddrinfo(q->addrinfo);
                                q->addrinfo = NULL;
                                break;
                        }

                        if (prev)
                                prev->ai_next = ai;
                        else
                                q->addrinfo = ai;

                        prev = ai;
                }

                return complete_query(resolve, q);
        }

        case RESPONSE_NAMEINFO: {
                const NameInfoResponse *ni_resp = &packet->nameinfo_response;

                assert_return(length >= sizeof(NameInfoResponse), -EBADMSG);
                assert_return(q->type == REQUEST_NAMEINFO, -EBADMSG);

                if (ni_resp->hostlen > DNS_HOSTNAME_MAX ||
                    ni_resp->servlen > DNS_HOSTNAME_MAX ||
                    sizeof(NameInfoResponse) + ni_resp->hostlen + ni_resp->servlen > length)
                        query_assign_errno(q, EAI_SYSTEM, EIO, 0);
                else {
                        query_assign_errno(q, ni_resp->ret, ni_resp->_errno, ni_resp->_h_errno);

                        if (ni_resp->hostlen > 0) {
                                q->host = strndup((const char*) ni_resp + sizeof(NameInfoResponse),
                                                  ni_resp->hostlen-1);
                                if (!q->host)
                                        query_assign_errno(q, EAI_MEMORY, ENOMEM, 0);
                        }

                        if (ni_resp->servlen > 0) {
                                q->serv = strndup((const char*) ni_resp + sizeof(NameInfoResponse) + ni_resp->hostlen,
                                                  ni_resp->servlen-1);
                                if (!q->serv)
                                        query_assign_errno(q, EAI_MEMORY, ENOMEM, 0);
                        }
                }

                return complete_query(resolve, q);
        }

        default:
                return 0;
        }
}

_public_ int sd_resolve_process(sd_resolve *resolve) {
        RESOLVE_DONT_DESTROY(resolve);

        union {
                Packet packet;
                uint8_t space[BUFSIZE];
        } buf;
        ssize_t l;
        int r;

        assert_return(resolve, -EINVAL);
        assert_return(!resolve_pid_changed(resolve), -ECHILD);

        /* We don't allow recursively invoking sd_resolve_process(). */
        assert_return(!resolve->current, -EBUSY);

        l = recv(resolve->fds[RESPONSE_RECV_FD], &buf, sizeof buf, 0);
        if (l < 0) {
                if (errno == EAGAIN)
                        return 0;

                return -errno;
        }
        if (l == 0)
                return -ECONNREFUSED;

        r = handle_response(resolve, &buf.packet, (size_t) l);
        if (r < 0)
                return r;

        return 1;
}

_public_ int sd_resolve_wait(sd_resolve *resolve, uint64_t timeout_usec) {
        int r;

        assert_return(resolve, -EINVAL);
        assert_return(!resolve_pid_changed(resolve), -ECHILD);

        if (resolve->n_done >= resolve->n_queries)
                return 0;

        do {
                r = fd_wait_for_event(resolve->fds[RESPONSE_RECV_FD], POLLIN, timeout_usec);
        } while (r == -EINTR);

        if (r < 0)
                return r;
        if (r == 0)
                return -ETIMEDOUT;

        return sd_resolve_process(resolve);
}

static int alloc_query(sd_resolve *resolve, bool floating, sd_resolve_query **_q) {
        sd_resolve_query *q;
        int r;

        assert(resolve);
        assert(_q);

        if (resolve->n_queries >= QUERIES_MAX)
                return -ENOBUFS;

        r = start_threads(resolve, 1);
        if (r < 0)
                return r;

        while (resolve->query_array[resolve->current_id % QUERIES_MAX])
                resolve->current_id++;

        q = resolve->query_array[resolve->current_id % QUERIES_MAX] = new0(sd_resolve_query, 1);
        if (!q)
                return -ENOMEM;

        q->n_ref = 1;
        q->resolve = resolve;
        q->floating = floating;
        q->id = resolve->current_id++;

        if (!floating)
                sd_resolve_ref(resolve);

        LIST_PREPEND(queries, resolve->queries, q);
        resolve->n_queries++;

        *_q = q;
        return 0;
}

_public_ int sd_resolve_getaddrinfo(
                sd_resolve *resolve,
                sd_resolve_query **_q,
                const char *node, const char *service,
                const struct addrinfo *hints,
                sd_resolve_getaddrinfo_handler_t callback, void *userdata) {

        _cleanup_(sd_resolve_query_unrefp) sd_resolve_query *q = NULL;
        AddrInfoRequest req = {};
        struct iovec iov[3];
        struct msghdr mh = {};
        int r;
        size_t node_len, service_len;

        assert_return(resolve, -EINVAL);
        assert_return(node || service, -EINVAL);
        assert_return(callback, -EINVAL);
        assert_return(!resolve_pid_changed(resolve), -ECHILD);

        r = alloc_query(resolve, !_q, &q);
        if (r < 0)
                return r;

        q->type = REQUEST_ADDRINFO;
        q->getaddrinfo_handler = callback;
        q->userdata = userdata;

        node_len = node ? strlen(node) + 1 : 0;
        service_len = service ? strlen(service) + 1 : 0;

        req = (AddrInfoRequest) {
                .node_len = node_len,
                .service_len = service_len,

                .header.id = q->id,
                .header.type = REQUEST_ADDRINFO,
                .header.length = sizeof(AddrInfoRequest) + node_len + service_len,

                .hints_valid = hints,
                .ai_flags = hints ? hints->ai_flags : 0,
                .ai_family = hints ? hints->ai_family : 0,
                .ai_socktype = hints ? hints->ai_socktype : 0,
                .ai_protocol = hints ? hints->ai_protocol : 0,
        };

        iov[mh.msg_iovlen++] = (struct iovec) { .iov_base = &req, .iov_len = sizeof(AddrInfoRequest) };
        if (node)
                iov[mh.msg_iovlen++] = (struct iovec) { .iov_base = (void*) node, .iov_len = req.node_len };
        if (service)
                iov[mh.msg_iovlen++] = (struct iovec) { .iov_base = (void*) service, .iov_len = req.service_len };
        mh.msg_iov = iov;

        if (sendmsg(resolve->fds[REQUEST_SEND_FD], &mh, MSG_NOSIGNAL) < 0)
                return -errno;

        resolve->n_outstanding++;

        if (_q)
                *_q = q;
        TAKE_PTR(q);

        return 0;
}

static int getaddrinfo_done(sd_resolve_query* q) {
        assert(q);
        assert(q->done);
        assert(q->getaddrinfo_handler);

        errno = q->_errno;
        h_errno = q->_h_errno;

        return q->getaddrinfo_handler(q, q->ret, q->addrinfo, q->userdata);
}

_public_ int sd_resolve_getnameinfo(
                sd_resolve *resolve,
                sd_resolve_query**_q,
                const struct sockaddr *sa, socklen_t salen,
                int flags,
                uint64_t get,
                sd_resolve_getnameinfo_handler_t callback,
                void *userdata) {

        _cleanup_(sd_resolve_query_unrefp) sd_resolve_query *q = NULL;
        NameInfoRequest req = {};
        struct iovec iov[2];
        struct msghdr mh;
        int r;

        assert_return(resolve, -EINVAL);
        assert_return(sa, -EINVAL);
        assert_return(salen >= sizeof(struct sockaddr), -EINVAL);
        assert_return(salen <= sizeof(union sockaddr_union), -EINVAL);
        assert_return((get & ~SD_RESOLVE_GET_BOTH) == 0, -EINVAL);
        assert_return(callback, -EINVAL);
        assert_return(!resolve_pid_changed(resolve), -ECHILD);

        r = alloc_query(resolve, !_q, &q);
        if (r < 0)
                return r;

        q->type = REQUEST_NAMEINFO;
        q->getnameinfo_handler = callback;
        q->userdata = userdata;

        req = (NameInfoRequest) {
                .header.id = q->id,
                .header.type = REQUEST_NAMEINFO,
                .header.length = sizeof(NameInfoRequest) + salen,

                .flags = flags,
                .sockaddr_len = salen,
                .gethost = !!(get & SD_RESOLVE_GET_HOST),
                .getserv = !!(get & SD_RESOLVE_GET_SERVICE),
        };

        iov[0] = (struct iovec) { .iov_base = &req, .iov_len = sizeof(NameInfoRequest) };
        iov[1] = (struct iovec) { .iov_base = (void*) sa, .iov_len = salen };

        mh = (struct msghdr) { .msg_iov = iov, .msg_iovlen = ELEMENTSOF(iov) };

        if (sendmsg(resolve->fds[REQUEST_SEND_FD], &mh, MSG_NOSIGNAL) < 0)
                return -errno;

        if (_q)
                *_q = q;

        resolve->n_outstanding++;
        TAKE_PTR(q);

        return 0;
}

static int getnameinfo_done(sd_resolve_query *q) {

        assert(q);
        assert(q->done);
        assert(q->getnameinfo_handler);

        errno = q->_errno;
        h_errno = q->_h_errno;

        return q->getnameinfo_handler(q, q->ret, q->host, q->serv, q->userdata);
}

static void resolve_freeaddrinfo(struct addrinfo *ai) {
        while (ai) {
                struct addrinfo *next = ai->ai_next;

                free(ai->ai_addr);
                free(ai->ai_canonname);
                free(ai);
                ai = next;
        }
}

static void resolve_query_disconnect(sd_resolve_query *q) {
        sd_resolve *resolve;
        unsigned i;

        assert(q);

        if (!q->resolve)
                return;

        resolve = q->resolve;
        assert(resolve->n_queries > 0);

        if (q->done) {
                assert(resolve->n_done > 0);
                resolve->n_done--;
        }

        i = q->id % QUERIES_MAX;
        assert(resolve->query_array[i] == q);
        resolve->query_array[i] = NULL;
        LIST_REMOVE(queries, resolve->queries, q);
        resolve->n_queries--;

        q->resolve = NULL;
        if (!q->floating)
                sd_resolve_unref(resolve);
}

static sd_resolve_query *resolve_query_free(sd_resolve_query *q) {
        assert(q);

        resolve_query_disconnect(q);

        if (q->destroy_callback)
                q->destroy_callback(q->userdata);

        resolve_freeaddrinfo(q->addrinfo);
        free(q->host);
        free(q->serv);

        return mfree(q);
}

DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(sd_resolve_query, sd_resolve_query, resolve_query_free);

_public_ int sd_resolve_query_is_done(sd_resolve_query *q) {
        assert_return(q, -EINVAL);
        assert_return(!resolve_pid_changed(q->resolve), -ECHILD);

        return q->done;
}

_public_ void* sd_resolve_query_set_userdata(sd_resolve_query *q, void *userdata) {
        void *ret;

        assert_return(q, NULL);
        assert_return(!resolve_pid_changed(q->resolve), NULL);

        ret = q->userdata;
        q->userdata = userdata;

        return ret;
}

_public_ void* sd_resolve_query_get_userdata(sd_resolve_query *q) {
        assert_return(q, NULL);
        assert_return(!resolve_pid_changed(q->resolve), NULL);

        return q->userdata;
}

_public_ sd_resolve *sd_resolve_query_get_resolve(sd_resolve_query *q) {
        assert_return(q, NULL);
        assert_return(!resolve_pid_changed(q->resolve), NULL);

        return q->resolve;
}

_public_ int sd_resolve_query_get_destroy_callback(sd_resolve_query *q, sd_resolve_destroy_t *destroy_callback) {
        assert_return(q, -EINVAL);

        if (destroy_callback)
                *destroy_callback = q->destroy_callback;

        return !!q->destroy_callback;
}

_public_ int sd_resolve_query_set_destroy_callback(sd_resolve_query *q, sd_resolve_destroy_t destroy_callback) {
        assert_return(q, -EINVAL);

        q->destroy_callback = destroy_callback;
        return 0;
}

_public_ int sd_resolve_query_get_floating(sd_resolve_query *q) {
        assert_return(q, -EINVAL);

        return q->floating;
}

_public_ int sd_resolve_query_set_floating(sd_resolve_query *q, int b) {
        assert_return(q, -EINVAL);

        if (q->floating == !!b)
                return 0;

        if (!q->resolve) /* Already disconnected */
                return -ESTALE;

        q->floating = b;

        if (b) {
                sd_resolve_query_ref(q);
                sd_resolve_unref(q->resolve);
        } else {
                sd_resolve_ref(q->resolve);
                sd_resolve_query_unref(q);
        }

        return 1;
}

static int io_callback(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        sd_resolve *resolve = userdata;
        int r;

        assert(resolve);

        r = sd_resolve_process(resolve);
        if (r < 0)
                return r;

        return 1;
}

_public_ int sd_resolve_attach_event(sd_resolve *resolve, sd_event *event, int64_t priority) {
        int r;

        assert_return(resolve, -EINVAL);
        assert_return(!resolve->event, -EBUSY);

        assert(!resolve->event_source);

        if (event)
                resolve->event = sd_event_ref(event);
        else {
                r = sd_event_default(&resolve->event);
                if (r < 0)
                        return r;
        }

        r = sd_event_add_io(resolve->event, &resolve->event_source, resolve->fds[RESPONSE_RECV_FD], POLLIN, io_callback, resolve);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_priority(resolve->event_source, priority);
        if (r < 0)
                goto fail;

        return 0;

fail:
        sd_resolve_detach_event(resolve);
        return r;
}

_public_  int sd_resolve_detach_event(sd_resolve *resolve) {
        assert_return(resolve, -EINVAL);

        if (!resolve->event)
                return 0;

        if (resolve->event_source) {
                sd_event_source_set_enabled(resolve->event_source, SD_EVENT_OFF);
                resolve->event_source = sd_event_source_unref(resolve->event_source);
        }

        resolve->event = sd_event_unref(resolve->event);
        return 1;
}

_public_ sd_event *sd_resolve_get_event(sd_resolve *resolve) {
        assert_return(resolve, NULL);

        return resolve->event;
}
