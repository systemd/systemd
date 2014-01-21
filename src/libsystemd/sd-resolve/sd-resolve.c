/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2005-2008 Lennart Poettering

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

#include <assert.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <sys/select.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <pwd.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <dirent.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/prctl.h>

#include "sd-resolve.h"
#include "util.h"

#define MAX_WORKERS 16
#define MAX_QUERIES 256
#define BUFSIZE (10240)

typedef enum {
        REQUEST_ADDRINFO,
        RESPONSE_ADDRINFO,
        REQUEST_NAMEINFO,
        RESPONSE_NAMEINFO,
        REQUEST_RES_QUERY,
        REQUEST_RES_SEARCH,
        RESPONSE_RES,
        REQUEST_TERMINATE,
        RESPONSE_DIED
} QueryType;

enum {
        REQUEST_RECV_FD = 0,
        REQUEST_SEND_FD = 1,
        RESPONSE_RECV_FD = 2,
        RESPONSE_SEND_FD = 3,
        MESSAGE_FD_MAX = 4
};

struct sd_resolve {
        int fds[MESSAGE_FD_MAX];

        pthread_t workers[MAX_WORKERS];
        unsigned valid_workers;

        unsigned current_id, current_index;
        sd_resolve_query* queries[MAX_QUERIES];

        sd_resolve_query *done_head, *done_tail;

        int n_queries;
        int dead;
};

struct sd_resolve_query {
        sd_resolve *resolve;
        int done;
        unsigned id;
        QueryType type;
        sd_resolve_query *done_next, *done_prev;
        int ret;
        int _errno;
        int _h_errno;
        struct addrinfo *addrinfo;
        char *serv, *host;
        void *userdata;
};

typedef struct RHeader {
        QueryType type;
        unsigned id;
        size_t length;
} RHeader;

typedef struct AddrInfoRequest {
        struct RHeader header;
        int hints_is_null;
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
        int gethost, getserv;
} NameInfoRequest;

typedef struct NameInfoResponse {
        struct RHeader header;
        size_t hostlen, servlen;
        int ret;
        int _errno;
        int _h_errno;
} NameInfoResponse;

typedef struct ResRequest {
        struct RHeader header;
        int class;
        int type;
        size_t dname_len;
} ResRequest;

typedef struct ResResponse {
        struct RHeader header;
        int ret;
        int _errno;
        int _h_errno;
} ResResponse;

typedef union Packet {
        RHeader rheader;
        AddrInfoRequest addrinfo_request;
        AddrInfoResponse addrinfo_response;
        NameInfoRequest nameinfo_request;
        NameInfoResponse nameinfo_response;
        ResRequest res_request;
        ResResponse res_response;
} Packet;

static int send_died(int out_fd) {
        RHeader rh = {};
        assert(out_fd > 0);

        rh.type = RESPONSE_DIED;
        rh.id = 0;
        rh.length = sizeof(rh);

        return send(out_fd, &rh, rh.length, MSG_NOSIGNAL);
}

static void *serialize_addrinfo(void *p, const struct addrinfo *ai, size_t *length, size_t maxlength) {
        AddrInfoSerialization s;
        size_t cnl, l;
        assert(p);
        assert(ai);
        assert(length);
        assert(*length <= maxlength);

        cnl = (ai->ai_canonname ? strlen(ai->ai_canonname)+1 : 0);
        l = sizeof(AddrInfoSerialization) + ai->ai_addrlen + cnl;

        if (*length + l > maxlength)
                return NULL;

        s.ai_flags = ai->ai_flags;
        s.ai_family = ai->ai_family;
        s.ai_socktype = ai->ai_socktype;
        s.ai_protocol = ai->ai_protocol;
        s.ai_addrlen = ai->ai_addrlen;
        s.canonname_len = cnl;

        memcpy((uint8_t*) p, &s, sizeof(AddrInfoSerialization));
        memcpy((uint8_t*) p + sizeof(AddrInfoSerialization), ai->ai_addr, ai->ai_addrlen);

        if (ai->ai_canonname)
                strcpy((char*) p + sizeof(AddrInfoSerialization) + ai->ai_addrlen, ai->ai_canonname);

        *length += l;
        return (uint8_t*) p + l;
}

static int send_addrinfo_reply(int out_fd, unsigned id, int ret, struct addrinfo *ai, int _errno, int _h_errno) {
        AddrInfoResponse data[BUFSIZE/sizeof(AddrInfoResponse) + 1] = {};
        AddrInfoResponse *resp = data;
        assert(out_fd >= 0);

        resp->header.type = RESPONSE_ADDRINFO;
        resp->header.id = id;
        resp->header.length = sizeof(AddrInfoResponse);
        resp->ret = ret;
        resp->_errno = _errno;
        resp->_h_errno = _h_errno;

        if (ret == 0 && ai) {
                void *p = data + 1;
                struct addrinfo *k;

                for (k = ai; k; k = k->ai_next) {
                        p = serialize_addrinfo(p, k, &resp->header.length, (char*) data + BUFSIZE - (char*) p);
                        if (!p) {
                                resp->ret = EAI_MEMORY;
                                break;
                        }
                }
        }

        if (ai)
                freeaddrinfo(ai);

        return send(out_fd, resp, resp->header.length, MSG_NOSIGNAL);
}

static int send_nameinfo_reply(int out_fd, unsigned id, int ret, const char *host, const char *serv, int _errno, int _h_errno) {
        NameInfoResponse data[BUFSIZE/sizeof(NameInfoResponse) + 1] = {};
        size_t hl, sl;
        NameInfoResponse *resp = data;

        assert(out_fd >= 0);

        sl = serv ? strlen(serv)+1 : 0;
        hl = host ? strlen(host)+1 : 0;

        resp->header.type = RESPONSE_NAMEINFO;
        resp->header.id = id;
        resp->header.length = sizeof(NameInfoResponse) + hl + sl;
        resp->ret = ret;
        resp->_errno = _errno;
        resp->_h_errno = _h_errno;
        resp->hostlen = hl;
        resp->servlen = sl;

        assert(sizeof(data) >= resp->header.length);

        if (host)
                memcpy((uint8_t *)data + sizeof(NameInfoResponse), host, hl);

        if (serv)
                memcpy((uint8_t *)data + sizeof(NameInfoResponse) + hl, serv, sl);

        return send(out_fd, resp, resp->header.length, MSG_NOSIGNAL);
}

static int send_res_reply(int out_fd, unsigned id, const unsigned char *answer, int ret, int _errno, int _h_errno) {
        ResResponse data[BUFSIZE/sizeof(ResResponse) + 1] = {};
        ResResponse *resp = data;

        assert(out_fd >= 0);

        resp->header.type = RESPONSE_RES;
        resp->header.id = id;
        resp->header.length = sizeof(ResResponse) + (ret < 0 ? 0 : ret);
        resp->ret = ret;
        resp->_errno = _errno;
        resp->_h_errno = _h_errno;

        assert(sizeof(data) >= resp->header.length);

        if (ret > 0)
                memcpy((uint8_t *)data + sizeof(ResResponse), answer, ret);

        return send(out_fd, resp, resp->header.length, MSG_NOSIGNAL);
}

static int handle_request(int out_fd, const Packet *packet, size_t length) {
        const RHeader *req;
        assert(out_fd >= 0);

        req = &packet->rheader;
        assert(req);
        assert(length >= sizeof(RHeader));
        assert(length == req->length);

        switch (req->type) {
        case REQUEST_ADDRINFO: {
               struct addrinfo ai = {}, *result = NULL;
               const AddrInfoRequest *ai_req = &packet->addrinfo_request;
               const char *node, *service;
               int ret;

               assert(length >= sizeof(AddrInfoRequest));
               assert(length == sizeof(AddrInfoRequest) + ai_req->node_len + ai_req->service_len);

               ai.ai_flags = ai_req->ai_flags;
               ai.ai_family = ai_req->ai_family;
               ai.ai_socktype = ai_req->ai_socktype;
               ai.ai_protocol = ai_req->ai_protocol;

               node = ai_req->node_len ? (const char*) ai_req + sizeof(AddrInfoRequest) : NULL;
               service = ai_req->service_len ? (const char*) ai_req + sizeof(AddrInfoRequest) + ai_req->node_len : NULL;

               ret = getaddrinfo(node, service,
                               ai_req->hints_is_null ? NULL : &ai,
                               &result);

               /* send_addrinfo_reply() frees result */
               return send_addrinfo_reply(out_fd, req->id, ret, result, errno, h_errno);
        }

        case REQUEST_NAMEINFO: {
               int ret;
               const NameInfoRequest *ni_req = &packet->nameinfo_request;
               char hostbuf[NI_MAXHOST], servbuf[NI_MAXSERV];
               struct sockaddr_storage sa;

               assert(length >= sizeof(NameInfoRequest));
               assert(length == sizeof(NameInfoRequest) + ni_req->sockaddr_len);

               memcpy(&sa, (const uint8_t *) ni_req + sizeof(NameInfoRequest), ni_req->sockaddr_len);

               ret = getnameinfo((struct sockaddr *)&sa, ni_req->sockaddr_len,
                               ni_req->gethost ? hostbuf : NULL, ni_req->gethost ? sizeof(hostbuf) : 0,
                               ni_req->getserv ? servbuf : NULL, ni_req->getserv ? sizeof(servbuf) : 0,
                               ni_req->flags);

               return send_nameinfo_reply(out_fd, req->id, ret,
                               ret == 0 && ni_req->gethost ? hostbuf : NULL,
                               ret == 0 && ni_req->getserv ? servbuf : NULL,
                               errno, h_errno);
        }

        case REQUEST_RES_QUERY:
        case REQUEST_RES_SEARCH: {
                 int ret;
                 HEADER answer[BUFSIZE/sizeof(HEADER) + 1];
                 const ResRequest *res_req = &packet->res_request;
                 const char *dname;

                 assert(length >= sizeof(ResRequest));
                 assert(length == sizeof(ResRequest) + res_req->dname_len);

                 dname = (const char *) req + sizeof(ResRequest);

                 if (req->type == REQUEST_RES_QUERY)
                         ret = res_query(dname, res_req->class, res_req->type, (unsigned char *) answer, BUFSIZE);
                 else
                         ret = res_search(dname, res_req->class, res_req->type, (unsigned char *) answer, BUFSIZE);

                 return send_res_reply(out_fd, req->id, (unsigned char *) answer, ret, errno, h_errno);
        }

        case REQUEST_TERMINATE:
                 /* Quit */
                 return -1;

        default:
                 ;
        }

        return 0;
}

static void* thread_worker(void *p) {
        sd_resolve *resolve = p;
        sigset_t fullset;

        /* No signals in this thread please */
        sigfillset(&fullset);
        pthread_sigmask(SIG_BLOCK, &fullset, NULL);

        while (!resolve->dead) {
                Packet buf[BUFSIZE/sizeof(Packet) + 1];
                ssize_t length;

                length = recv(resolve->fds[REQUEST_RECV_FD], buf, sizeof(buf), 0);

                if (length <= 0) {
                        if (length < 0 && (errno == EAGAIN || errno == EINTR))
                                continue;
                        break;
                }

                if (resolve->dead)
                        break;

                if (handle_request(resolve->fds[RESPONSE_SEND_FD], buf, (size_t) length) < 0)
                        break;
        }

        send_died(resolve->fds[RESPONSE_SEND_FD]);

        return NULL;
}

_public_ sd_resolve* sd_resolve_new(unsigned n_proc) {
        sd_resolve *resolve = NULL;
        int i, r;

        assert(n_proc >= 1);

        if (n_proc > MAX_WORKERS)
                n_proc = MAX_WORKERS;

        resolve = new(sd_resolve, 1);
        if (!resolve) {
                errno = ENOMEM;
                goto fail;
        }

        resolve->dead = 0;
        resolve->valid_workers = 0;

        for (i = 0; i < MESSAGE_FD_MAX; i++)
                resolve->fds[i] = -1;

        memset(resolve->queries, 0, sizeof(resolve->queries));

        r = socketpair(PF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, resolve->fds);
        if (r < 0)
                goto fail;

        r = socketpair(PF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, resolve->fds+2);
        if (r < 0)
                goto fail;

        for (resolve->valid_workers = 0; resolve->valid_workers < n_proc; resolve->valid_workers++) {
                r = pthread_create(&resolve->workers[resolve->valid_workers], NULL, thread_worker, resolve);
                if (r) {
                        errno = r;
                        goto fail;
                }
        }

        resolve->current_index = resolve->current_id = 0;
        resolve->done_head = resolve->done_tail = NULL;
        resolve->n_queries = 0;

        fd_nonblock(resolve->fds[RESPONSE_RECV_FD], true);

        return resolve;

fail:
        if (resolve)
                sd_resolve_free(resolve);

        return NULL;
}

_public_ void sd_resolve_free(sd_resolve *resolve) {
        int i;
        int saved_errno = errno;
        unsigned p;

        assert(resolve);

        resolve->dead = 1;

        if (resolve->fds[REQUEST_SEND_FD] >= 0) {
                RHeader req = {};

                req.type = REQUEST_TERMINATE;
                req.length = sizeof(req);
                req.id = 0;

                /* Send one termination packet for each worker */
                for (p = 0; p < resolve->valid_workers; p++)
                        send(resolve->fds[REQUEST_SEND_FD], &req, req.length, MSG_NOSIGNAL);
        }

        /* Now terminate them and wait until they are gone. */
        for (p = 0; p < resolve->valid_workers; p++) {
                for (;;) {
                        if (pthread_join(resolve->workers[p], NULL) != EINTR)
                                break;
                }
        }

        /* Close all communication channels */
        for (i = 0; i < MESSAGE_FD_MAX; i++)
                if (resolve->fds[i] >= 0)
                        close(resolve->fds[i]);

        for (p = 0; p < MAX_QUERIES; p++)
                if (resolve->queries[p])
                        sd_resolve_cancel(resolve, resolve->queries[p]);

        free(resolve);

        errno = saved_errno;
}

_public_ int sd_resolve_fd(sd_resolve *resolve) {
        assert(resolve);

        return resolve->fds[RESPONSE_RECV_FD];
}

static sd_resolve_query *lookup_query(sd_resolve *resolve, unsigned id) {
        sd_resolve_query *q;
        assert(resolve);

        q = resolve->queries[id % MAX_QUERIES];
        if (q)
                if (q->id == id)
                        return q;

        return NULL;
}

static void complete_query(sd_resolve *resolve, sd_resolve_query *q) {
        assert(resolve);
        assert(q);
        assert(!q->done);

        q->done = 1;

        if ((q->done_prev = resolve->done_tail))
                resolve->done_tail->done_next = q;
        else
                resolve->done_head = q;

        resolve->done_tail = q;
        q->done_next = NULL;
}

static const void *unserialize_addrinfo(const void *p, struct addrinfo **ret_ai, size_t *length) {
        AddrInfoSerialization s;
        size_t l;
        struct addrinfo *ai;
        assert(p);
        assert(ret_ai);
        assert(length);

        if (*length < sizeof(AddrInfoSerialization))
                return NULL;

        memcpy(&s, p, sizeof(s));

        l = sizeof(AddrInfoSerialization) + s.ai_addrlen + s.canonname_len;
        if (*length < l)
                return NULL;

        ai = new(struct addrinfo, 1);
        if (!ai)
                goto fail;

        ai->ai_addr = NULL;
        ai->ai_canonname = NULL;
        ai->ai_next = NULL;

        if (s.ai_addrlen && !(ai->ai_addr = malloc(s.ai_addrlen)))
                goto fail;

        if (s.canonname_len && !(ai->ai_canonname = malloc(s.canonname_len)))
                goto fail;

        ai->ai_flags = s.ai_flags;
        ai->ai_family = s.ai_family;
        ai->ai_socktype = s.ai_socktype;
        ai->ai_protocol = s.ai_protocol;
        ai->ai_addrlen = s.ai_addrlen;

        if (ai->ai_addr)
                memcpy(ai->ai_addr, (const uint8_t*) p + sizeof(AddrInfoSerialization), s.ai_addrlen);

        if (ai->ai_canonname)
                memcpy(ai->ai_canonname, (const uint8_t*) p + sizeof(AddrInfoSerialization) + s.ai_addrlen, s.canonname_len);

        *length -= l;
        *ret_ai = ai;

        return (const uint8_t*) p + l;


fail:
        if (ai)
                sd_resolve_freeaddrinfo(ai);

        return NULL;
}

static int handle_response(sd_resolve *resolve, const Packet *packet, size_t length) {
        const RHeader *resp;
        sd_resolve_query *q;

        assert(resolve);

        resp = &packet->rheader;
        assert(resp);
        assert(length >= sizeof(RHeader));
        assert(length == resp->length);

        if (resp->type == RESPONSE_DIED) {
                resolve->dead = 1;
                return 0;
        }

        q = lookup_query(resolve, resp->id);
        if (!q)
                return 0;

        switch (resp->type) {
        case RESPONSE_ADDRINFO: {
                const AddrInfoResponse *ai_resp = &packet->addrinfo_response;
                const void *p;
                size_t l;
                struct addrinfo *prev = NULL;

                assert(length >= sizeof(AddrInfoResponse));
                assert(q->type == REQUEST_ADDRINFO);

                q->ret = ai_resp->ret;
                q->_errno = ai_resp->_errno;
                q->_h_errno = ai_resp->_h_errno;
                l = length - sizeof(AddrInfoResponse);
                p = (const uint8_t*) resp + sizeof(AddrInfoResponse);

                while (l > 0 && p) {
                        struct addrinfo *ai = NULL;
                        p = unserialize_addrinfo(p, &ai, &l);

                        if (!p || !ai) {
                                q->ret = EAI_MEMORY;
                                break;
                        }

                        if (prev)
                                prev->ai_next = ai;
                        else
                                q->addrinfo = ai;

                        prev = ai;
                }

                complete_query(resolve, q);
                break;
        }

        case RESPONSE_NAMEINFO: {
                const NameInfoResponse *ni_resp = &packet->nameinfo_response;

                assert(length >= sizeof(NameInfoResponse));
                assert(q->type == REQUEST_NAMEINFO);

                q->ret = ni_resp->ret;
                q->_errno = ni_resp->_errno;
                q->_h_errno = ni_resp->_h_errno;

                if (ni_resp->hostlen)
                        if (!(q->host = strndup((const char*) ni_resp + sizeof(NameInfoResponse), ni_resp->hostlen-1)))
                                q->ret = EAI_MEMORY;

                if (ni_resp->servlen)
                        if (!(q->serv = strndup((const char*) ni_resp + sizeof(NameInfoResponse) + ni_resp->hostlen, ni_resp->servlen-1)))
                                q->ret = EAI_MEMORY;

                complete_query(resolve, q);
                break;
        }

        case RESPONSE_RES: {
                const ResResponse *res_resp = &packet->res_response;

                assert(length >= sizeof(ResResponse));
                assert(q->type == REQUEST_RES_QUERY || q->type == REQUEST_RES_SEARCH);

                q->ret = res_resp->ret;
                q->_errno = res_resp->_errno;
                q->_h_errno = res_resp->_h_errno;

                if (res_resp->ret >= 0)  {
                        if (!(q->serv = malloc(res_resp->ret))) {
                                q->ret = -1;
                                q->_errno = ENOMEM;
                        } else
                                memcpy(q->serv, (const char *)resp + sizeof(ResResponse), res_resp->ret);
                }

                complete_query(resolve, q);
                break;
        }

        default:
                ;
        }

        return 0;
}

_public_ int sd_resolve_wait(sd_resolve *resolve, int block) {
        int handled = 0;
        assert(resolve);

        for (;;) {
                Packet buf[BUFSIZE/sizeof(Packet) + 1];
                ssize_t l;

                if (resolve->dead) {
                        errno = ECHILD;
                        return -1;
                }

                l = recv(resolve->fds[RESPONSE_RECV_FD], buf, sizeof(buf), 0);
                if (l < 0) {
                        fd_set fds;

                        if (errno != EAGAIN)
                                return -1;

                        if (!block || handled)
                                return 0;

                        FD_ZERO(&fds);
                        FD_SET(resolve->fds[RESPONSE_RECV_FD], &fds);

                        if (select(resolve->fds[RESPONSE_RECV_FD]+1, &fds, NULL, NULL, NULL) < 0)
                                return -1;

                        continue;
                }

                if (handle_response(resolve, buf, (size_t) l) < 0)
                        return -1;

                handled = 1;
        }
}

static sd_resolve_query *alloc_query(sd_resolve *resolve) {
        sd_resolve_query *q;
        assert(resolve);

        if (resolve->n_queries >= MAX_QUERIES) {
                errno = ENOMEM;
                return NULL;
        }

        while (resolve->queries[resolve->current_index]) {
                resolve->current_index++;
                resolve->current_id++;

                while (resolve->current_index >= MAX_QUERIES)
                        resolve->current_index -= MAX_QUERIES;
        }

        q = resolve->queries[resolve->current_index] = new(sd_resolve_query, 1);
        if (!q) {
                errno = ENOMEM;
                return NULL;
        }

        resolve->n_queries++;

        q->resolve = resolve;
        q->done = 0;
        q->id = resolve->current_id;
        q->done_next = q->done_prev = NULL;
        q->ret = 0;
        q->_errno = 0;
        q->_h_errno = 0;
        q->addrinfo = NULL;
        q->userdata = NULL;
        q->host = q->serv = NULL;

        return q;
}

_public_ sd_resolve_query* sd_resolve_getaddrinfo(sd_resolve *resolve, const char *node, const char *service, const struct addrinfo *hints) {
        AddrInfoRequest data[BUFSIZE/sizeof(AddrInfoRequest) + 1] = {};
        AddrInfoRequest *req = data;
        sd_resolve_query *q;
        assert(resolve);
        assert(node || service);

        if (resolve->dead) {
                errno = ECHILD;
                return NULL;
        }

        q = alloc_query(resolve);
        if (!q)
                return NULL;

        req->node_len = node ? strlen(node)+1 : 0;
        req->service_len = service ? strlen(service)+1 : 0;

        req->header.id = q->id;
        req->header.type = q->type = REQUEST_ADDRINFO;
        req->header.length = sizeof(AddrInfoRequest) + req->node_len + req->service_len;

        if (req->header.length > BUFSIZE) {
                errno = ENOMEM;
                goto fail;
        }

        if (!(req->hints_is_null = !hints)) {
                req->ai_flags = hints->ai_flags;
                req->ai_family = hints->ai_family;
                req->ai_socktype = hints->ai_socktype;
                req->ai_protocol = hints->ai_protocol;
        }

        if (node)
                strcpy((char*) req + sizeof(AddrInfoRequest), node);

        if (service)
                strcpy((char*) req + sizeof(AddrInfoRequest) + req->node_len, service);

        if (send(resolve->fds[REQUEST_SEND_FD], req, req->header.length, MSG_NOSIGNAL) < 0)
                goto fail;

        return q;

fail:
        if (q)
                sd_resolve_cancel(resolve, q);

        return NULL;
}

_public_ int sd_resolve_getaddrinfo_done(sd_resolve *resolve, sd_resolve_query* q, struct addrinfo **ret_res) {
        int ret;
        assert(resolve);
        assert(q);
        assert(q->resolve == resolve);
        assert(q->type == REQUEST_ADDRINFO);

        if (resolve->dead) {
                errno = ECHILD;
                return EAI_SYSTEM;
        }

        if (!q->done)
                return EAI_AGAIN;

        *ret_res = q->addrinfo;
        q->addrinfo = NULL;

        ret = q->ret;

        if (ret == EAI_SYSTEM)
                errno = q->_errno;

        if (ret != 0)
                h_errno = q->_h_errno;

        sd_resolve_cancel(resolve, q);

        return ret;
}

_public_ sd_resolve_query* sd_resolve_getnameinfo(sd_resolve *resolve, const struct sockaddr *sa, socklen_t salen, int flags, int gethost, int getserv) {
        NameInfoRequest data[BUFSIZE/sizeof(NameInfoRequest) + 1] = {};
        NameInfoRequest *req = data;
        sd_resolve_query *q;

        assert(resolve);
        assert(sa);
        assert(salen > 0);

        if (resolve->dead) {
                errno = ECHILD;
                return NULL;
        }

        q = alloc_query(resolve);
        if (!q)
                return NULL;

        req->header.id = q->id;
        req->header.type = q->type = REQUEST_NAMEINFO;
        req->header.length = sizeof(NameInfoRequest) + salen;

        if (req->header.length > BUFSIZE) {
                errno = ENOMEM;
                goto fail;
        }

        req->flags = flags;
        req->sockaddr_len = salen;
        req->gethost = gethost;
        req->getserv = getserv;

        memcpy((uint8_t*) req + sizeof(NameInfoRequest), sa, salen);

        if (send(resolve->fds[REQUEST_SEND_FD], req, req->header.length, MSG_NOSIGNAL) < 0)
                goto fail;

        return q;

fail:
        if (q)
                sd_resolve_cancel(resolve, q);

        return NULL;
}

_public_ int sd_resolve_getnameinfo_done(sd_resolve *resolve, sd_resolve_query* q, char *ret_host, size_t hostlen, char *ret_serv, size_t servlen) {
        int ret;
        assert(resolve);
        assert(q);
        assert(q->resolve == resolve);
        assert(q->type == REQUEST_NAMEINFO);
        assert(!ret_host || hostlen);
        assert(!ret_serv || servlen);

        if (resolve->dead) {
                errno = ECHILD;
                return EAI_SYSTEM;
        }

        if (!q->done)
                return EAI_AGAIN;

        if (ret_host && q->host) {
                strncpy(ret_host, q->host, hostlen);
                ret_host[hostlen-1] = 0;
        }

        if (ret_serv && q->serv) {
                strncpy(ret_serv, q->serv, servlen);
                ret_serv[servlen-1] = 0;
        }

        ret = q->ret;

        if (ret == EAI_SYSTEM)
                errno = q->_errno;

        if (ret != 0)
                h_errno = q->_h_errno;

        sd_resolve_cancel(resolve, q);

        return ret;
}

static sd_resolve_query * resolve_res(sd_resolve *resolve, QueryType qtype, const char *dname, int class, int type) {
        ResRequest data[BUFSIZE/sizeof(ResRequest) + 1];
        ResRequest *req = data;
        sd_resolve_query *q;

        assert(resolve);
        assert(dname);

        if (resolve->dead) {
                errno = ECHILD;
                return NULL;
        }

        q = alloc_query(resolve);
        if (!q)
                return NULL;

        req->dname_len = strlen(dname) + 1;

        req->header.id = q->id;
        req->header.type = q->type = qtype;
        req->header.length = sizeof(ResRequest) + req->dname_len;

        if (req->header.length > BUFSIZE) {
                errno = ENOMEM;
                goto fail;
        }

        req->class = class;
        req->type = type;

        strcpy((char*) req + sizeof(ResRequest), dname);

        if (send(resolve->fds[REQUEST_SEND_FD], req, req->header.length, MSG_NOSIGNAL) < 0)
                goto fail;

        return q;

fail:
        if (q)
                sd_resolve_cancel(resolve, q);

        return NULL;
}

_public_ sd_resolve_query* sd_resolve_res_query(sd_resolve *resolve, const char *dname, int class, int type) {
        return resolve_res(resolve, REQUEST_RES_QUERY, dname, class, type);
}

_public_ sd_resolve_query* sd_resolve_res_search(sd_resolve *resolve, const char *dname, int class, int type) {
        return resolve_res(resolve, REQUEST_RES_SEARCH, dname, class, type);
}

_public_ int sd_resolve_res_done(sd_resolve *resolve, sd_resolve_query* q, unsigned char **answer) {
        int ret;
        assert(resolve);
        assert(q);
        assert(q->resolve == resolve);
        assert(q->type == REQUEST_RES_QUERY || q->type == REQUEST_RES_SEARCH);
        assert(answer);

        if (resolve->dead) {
                errno = ECHILD;
                return -ECHILD;
        }

        if (!q->done) {
                errno = EAGAIN;
                return -EAGAIN;
        }

        *answer = (unsigned char *)q->serv;
        q->serv = NULL;

        ret = q->ret;

        if (ret < 0) {
                errno = q->_errno;
                h_errno = q->_h_errno;
        }

        sd_resolve_cancel(resolve, q);

        return ret < 0 ? -errno : ret;
}

_public_ sd_resolve_query* sd_resolve_get_next(sd_resolve *resolve) {
        assert(resolve);
        return resolve->done_head;
}

_public_ int sd_resolve_get_n_queries(sd_resolve *resolve) {
        assert(resolve);
        return resolve->n_queries;
}

_public_ void sd_resolve_cancel(sd_resolve *resolve, sd_resolve_query* q) {
        int i;
        int saved_errno = errno;

        assert(resolve);
        assert(q);
        assert(q->resolve == resolve);
        assert(resolve->n_queries > 0);

        if (q->done) {

                if (q->done_prev)
                        q->done_prev->done_next = q->done_next;
                else
                        resolve->done_head = q->done_next;

                if (q->done_next)
                        q->done_next->done_prev = q->done_prev;
                else
                        resolve->done_tail = q->done_prev;
        }

        i = q->id % MAX_QUERIES;
        assert(resolve->queries[i] == q);
        resolve->queries[i] = NULL;

        sd_resolve_freeaddrinfo(q->addrinfo);
        free(q->host);
        free(q->serv);

        resolve->n_queries--;
        free(q);

        errno = saved_errno;
}

_public_ void sd_resolve_freeaddrinfo(struct addrinfo *ai) {
        int saved_errno = errno;

        while (ai) {
                struct addrinfo *next = ai->ai_next;

                free(ai->ai_addr);
                free(ai->ai_canonname);
                free(ai);

                ai = next;
        }

        errno = saved_errno;
}

_public_ int sd_resolve_isdone(sd_resolve *resolve, sd_resolve_query*q) {
        assert(resolve);
        assert(q);
        assert(q->resolve == resolve);

        return q->done;
}

_public_ void sd_resolve_setuserdata(sd_resolve *resolve, sd_resolve_query *q, void *userdata) {
        assert(q);
        assert(resolve);
        assert(q->resolve = resolve);

        q->userdata = userdata;
}

_public_ void* sd_resolve_getuserdata(sd_resolve *resolve, sd_resolve_query *q) {
        assert(q);
        assert(resolve);
        assert(q->resolve = resolve);

        return q->userdata;
}
