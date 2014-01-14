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

#include "sd-resolv.h"
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
} query_type_t;

enum {
        REQUEST_RECV_FD = 0,
        REQUEST_SEND_FD = 1,
        RESPONSE_RECV_FD = 2,
        RESPONSE_SEND_FD = 3,
        MESSAGE_FD_MAX = 4
};

struct sd_resolv {
        int fds[MESSAGE_FD_MAX];

        pthread_t workers[MAX_WORKERS];
        unsigned valid_workers;

        unsigned current_id, current_index;
        sd_resolv_query_t* queries[MAX_QUERIES];

        sd_resolv_query_t *done_head, *done_tail;

        int n_queries;
        int dead;
};

struct sd_resolv_query {
        sd_resolv_t *resolv;
        int done;
        unsigned id;
        query_type_t type;
        sd_resolv_query_t *done_next, *done_prev;
        int ret;
        int _errno;
        int _h_errno;
        struct addrinfo *addrinfo;
        char *serv, *host;
        void *userdata;
};

typedef struct rheader {
        query_type_t type;
        unsigned id;
        size_t length;
} rheader_t;

typedef struct addrinfo_request {
        struct rheader header;
        int hints_is_null;
        int ai_flags;
        int ai_family;
        int ai_socktype;
        int ai_protocol;
        size_t node_len, service_len;
} addrinfo_request_t;

typedef struct addrinfo_response {
        struct rheader header;
        int ret;
        int _errno;
        int _h_errno;
        /* followed by addrinfo_serialization[] */
} addrinfo_response_t;

typedef struct addrinfo_serialization {
        int ai_flags;
        int ai_family;
        int ai_socktype;
        int ai_protocol;
        size_t ai_addrlen;
        size_t canonname_len;
        /* Followed by ai_addr amd ai_canonname with variable lengths */
} addrinfo_serialization_t;

typedef struct nameinfo_request {
        struct rheader header;
        int flags;
        socklen_t sockaddr_len;
        int gethost, getserv;
} nameinfo_request_t;

typedef struct nameinfo_response {
        struct rheader header;
        size_t hostlen, servlen;
        int ret;
        int _errno;
        int _h_errno;
} nameinfo_response_t;

typedef struct res_request {
        struct rheader header;
        int class;
        int type;
        size_t dname_len;
} res_request_t;

typedef struct res_response {
        struct rheader header;
        int ret;
        int _errno;
        int _h_errno;
} res_response_t;

typedef union packet {
        rheader_t rheader;
        addrinfo_request_t addrinfo_request;
        addrinfo_response_t addrinfo_response;
        nameinfo_request_t nameinfo_request;
        nameinfo_response_t nameinfo_response;
        res_request_t res_request;
        res_response_t res_response;
} packet_t;

static int send_died(int out_fd) {
        rheader_t rh = {};
        assert(out_fd > 0);

        rh.type = RESPONSE_DIED;
        rh.id = 0;
        rh.length = sizeof(rh);

        return send(out_fd, &rh, rh.length, MSG_NOSIGNAL);
}

static void *serialize_addrinfo(void *p, const struct addrinfo *ai, size_t *length, size_t maxlength) {
        addrinfo_serialization_t s;
        size_t cnl, l;
        assert(p);
        assert(ai);
        assert(length);
        assert(*length <= maxlength);

        cnl = (ai->ai_canonname ? strlen(ai->ai_canonname)+1 : 0);
        l = sizeof(addrinfo_serialization_t) + ai->ai_addrlen + cnl;

        if (*length + l > maxlength)
                return NULL;

        s.ai_flags = ai->ai_flags;
        s.ai_family = ai->ai_family;
        s.ai_socktype = ai->ai_socktype;
        s.ai_protocol = ai->ai_protocol;
        s.ai_addrlen = ai->ai_addrlen;
        s.canonname_len = cnl;

        memcpy((uint8_t*) p, &s, sizeof(addrinfo_serialization_t));
        memcpy((uint8_t*) p + sizeof(addrinfo_serialization_t), ai->ai_addr, ai->ai_addrlen);

        if (ai->ai_canonname)
                strcpy((char*) p + sizeof(addrinfo_serialization_t) + ai->ai_addrlen, ai->ai_canonname);

        *length += l;
        return (uint8_t*) p + l;
}

static int send_addrinfo_reply(int out_fd, unsigned id, int ret, struct addrinfo *ai, int _errno, int _h_errno) {
        addrinfo_response_t data[BUFSIZE/sizeof(addrinfo_response_t) + 1] = {};
        addrinfo_response_t *resp = data;
        assert(out_fd >= 0);

        resp->header.type = RESPONSE_ADDRINFO;
        resp->header.id = id;
        resp->header.length = sizeof(addrinfo_response_t);
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
        nameinfo_response_t data[BUFSIZE/sizeof(nameinfo_response_t) + 1] = {};
        size_t hl, sl;
        nameinfo_response_t *resp = data;

        assert(out_fd >= 0);

        sl = serv ? strlen(serv)+1 : 0;
        hl = host ? strlen(host)+1 : 0;

        resp->header.type = RESPONSE_NAMEINFO;
        resp->header.id = id;
        resp->header.length = sizeof(nameinfo_response_t) + hl + sl;
        resp->ret = ret;
        resp->_errno = _errno;
        resp->_h_errno = _h_errno;
        resp->hostlen = hl;
        resp->servlen = sl;

        assert(sizeof(data) >= resp->header.length);

        if (host)
                memcpy((uint8_t *)data + sizeof(nameinfo_response_t), host, hl);

        if (serv)
                memcpy((uint8_t *)data + sizeof(nameinfo_response_t) + hl, serv, sl);

        return send(out_fd, resp, resp->header.length, MSG_NOSIGNAL);
}

static int send_res_reply(int out_fd, unsigned id, const unsigned char *answer, int ret, int _errno, int _h_errno) {
        res_response_t data[BUFSIZE/sizeof(res_response_t) + 1] = {};
        res_response_t *resp = data;

        assert(out_fd >= 0);

        resp->header.type = RESPONSE_RES;
        resp->header.id = id;
        resp->header.length = sizeof(res_response_t) + (ret < 0 ? 0 : ret);
        resp->ret = ret;
        resp->_errno = _errno;
        resp->_h_errno = _h_errno;

        assert(sizeof(data) >= resp->header.length);

        if (ret > 0)
                memcpy((uint8_t *)data + sizeof(res_response_t), answer, ret);

        return send(out_fd, resp, resp->header.length, MSG_NOSIGNAL);
}

static int handle_request(int out_fd, const packet_t *packet, size_t length) {
        const rheader_t *req;
        assert(out_fd >= 0);

        req = &packet->rheader;
        assert(req);
        assert(length >= sizeof(rheader_t));
        assert(length == req->length);

        switch (req->type) {
        case REQUEST_ADDRINFO: {
               struct addrinfo ai = {}, *result = NULL;
               const addrinfo_request_t *ai_req = &packet->addrinfo_request;
               const char *node, *service;
               int ret;

               assert(length >= sizeof(addrinfo_request_t));
               assert(length == sizeof(addrinfo_request_t) + ai_req->node_len + ai_req->service_len);

               ai.ai_flags = ai_req->ai_flags;
               ai.ai_family = ai_req->ai_family;
               ai.ai_socktype = ai_req->ai_socktype;
               ai.ai_protocol = ai_req->ai_protocol;

               node = ai_req->node_len ? (const char*) ai_req + sizeof(addrinfo_request_t) : NULL;
               service = ai_req->service_len ? (const char*) ai_req + sizeof(addrinfo_request_t) + ai_req->node_len : NULL;

               ret = getaddrinfo(node, service,
                               ai_req->hints_is_null ? NULL : &ai,
                               &result);

               /* send_addrinfo_reply() frees result */
               return send_addrinfo_reply(out_fd, req->id, ret, result, errno, h_errno);
        }

        case REQUEST_NAMEINFO: {
               int ret;
               const nameinfo_request_t *ni_req = &packet->nameinfo_request;
               char hostbuf[NI_MAXHOST], servbuf[NI_MAXSERV];
               struct sockaddr_storage sa;

               assert(length >= sizeof(nameinfo_request_t));
               assert(length == sizeof(nameinfo_request_t) + ni_req->sockaddr_len);

               memcpy(&sa, (const uint8_t *) ni_req + sizeof(nameinfo_request_t), ni_req->sockaddr_len);

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
                 const res_request_t *res_req = &packet->res_request;
                 const char *dname;

                 assert(length >= sizeof(res_request_t));
                 assert(length == sizeof(res_request_t) + res_req->dname_len);

                 dname = (const char *) req + sizeof(res_request_t);

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
        sd_resolv_t *resolv = p;
        sigset_t fullset;

        /* No signals in this thread please */
        sigfillset(&fullset);
        pthread_sigmask(SIG_BLOCK, &fullset, NULL);

        while (!resolv->dead) {
                packet_t buf[BUFSIZE/sizeof(packet_t) + 1];
                ssize_t length;

                length = recv(resolv->fds[REQUEST_RECV_FD], buf, sizeof(buf), 0);

                if (length <= 0) {
                        if (length < 0 && (errno == EAGAIN || errno == EINTR))
                                continue;
                        break;
                }

                if (resolv->dead)
                        break;

                if (handle_request(resolv->fds[RESPONSE_SEND_FD], buf, (size_t) length) < 0)
                        break;
        }

        send_died(resolv->fds[RESPONSE_SEND_FD]);

        return NULL;
}

sd_resolv_t* sd_resolv_new(unsigned n_proc) {
        sd_resolv_t *resolv = NULL;
        int i, r;

        assert(n_proc >= 1);

        if (n_proc > MAX_WORKERS)
                n_proc = MAX_WORKERS;

        resolv = malloc(sizeof(sd_resolv_t));
        if (!resolv) {
                errno = ENOMEM;
                goto fail;
        }

        resolv->dead = 0;
        resolv->valid_workers = 0;

        for (i = 0; i < MESSAGE_FD_MAX; i++)
                resolv->fds[i] = -1;

        memset(resolv->queries, 0, sizeof(resolv->queries));

        r = socketpair(PF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, resolv->fds);
        if (r < 0)
                goto fail;

        r = socketpair(PF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, resolv->fds+2);
        if (r < 0)
                goto fail;

        for (resolv->valid_workers = 0; resolv->valid_workers < n_proc; resolv->valid_workers++) {
                r = pthread_create(&resolv->workers[resolv->valid_workers], NULL, thread_worker, resolv);
                if (r) {
                        errno = r;
                        goto fail;
                }
        }

        resolv->current_index = resolv->current_id = 0;
        resolv->done_head = resolv->done_tail = NULL;
        resolv->n_queries = 0;

        fd_nonblock(resolv->fds[RESPONSE_RECV_FD], true);

        return resolv;

fail:
        if (resolv)
                sd_resolv_free(resolv);

        return NULL;
}

void sd_resolv_free(sd_resolv_t *resolv) {
        int i;
        int saved_errno = errno;
        unsigned p;

        assert(resolv);

        resolv->dead = 1;

        if (resolv->fds[REQUEST_SEND_FD] >= 0) {
                rheader_t req = {};

                req.type = REQUEST_TERMINATE;
                req.length = sizeof(req);
                req.id = 0;

                /* Send one termination packet for each worker */
                for (p = 0; p < resolv->valid_workers; p++)
                        send(resolv->fds[REQUEST_SEND_FD], &req, req.length, MSG_NOSIGNAL);
        }

        /* Now terminate them and wait until they are gone. */
        for (p = 0; p < resolv->valid_workers; p++) {
                for (;;) {
                        if (pthread_join(resolv->workers[p], NULL) != EINTR)
                                break;
                }
        }

        /* Close all communication channels */
        for (i = 0; i < MESSAGE_FD_MAX; i++)
                if (resolv->fds[i] >= 0)
                        close(resolv->fds[i]);

        for (p = 0; p < MAX_QUERIES; p++)
                if (resolv->queries[p])
                        sd_resolv_cancel(resolv, resolv->queries[p]);

        free(resolv);

        errno = saved_errno;
}

int sd_resolv_fd(sd_resolv_t *resolv) {
        assert(resolv);

        return resolv->fds[RESPONSE_RECV_FD];
}

static sd_resolv_query_t *lookup_query(sd_resolv_t *resolv, unsigned id) {
        sd_resolv_query_t *q;
        assert(resolv);

        q = resolv->queries[id % MAX_QUERIES];
        if (q)
                if (q->id == id)
                        return q;

        return NULL;
}

static void complete_query(sd_resolv_t *resolv, sd_resolv_query_t *q) {
        assert(resolv);
        assert(q);
        assert(!q->done);

        q->done = 1;

        if ((q->done_prev = resolv->done_tail))
                resolv->done_tail->done_next = q;
        else
                resolv->done_head = q;

        resolv->done_tail = q;
        q->done_next = NULL;
}

static const void *unserialize_addrinfo(const void *p, struct addrinfo **ret_ai, size_t *length) {
        addrinfo_serialization_t s;
        size_t l;
        struct addrinfo *ai;
        assert(p);
        assert(ret_ai);
        assert(length);

        if (*length < sizeof(addrinfo_serialization_t))
                return NULL;

        memcpy(&s, p, sizeof(s));

        l = sizeof(addrinfo_serialization_t) + s.ai_addrlen + s.canonname_len;
        if (*length < l)
                return NULL;

        ai = malloc(sizeof(struct addrinfo));
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
                memcpy(ai->ai_addr, (const uint8_t*) p + sizeof(addrinfo_serialization_t), s.ai_addrlen);

        if (ai->ai_canonname)
                memcpy(ai->ai_canonname, (const uint8_t*) p + sizeof(addrinfo_serialization_t) + s.ai_addrlen, s.canonname_len);

        *length -= l;
        *ret_ai = ai;

        return (const uint8_t*) p + l;


fail:
        if (ai)
                sd_resolv_freeaddrinfo(ai);

        return NULL;
}

static int handle_response(sd_resolv_t *resolv, const packet_t *packet, size_t length) {
        const rheader_t *resp;
        sd_resolv_query_t *q;

        assert(resolv);

        resp = &packet->rheader;
        assert(resp);
        assert(length >= sizeof(rheader_t));
        assert(length == resp->length);

        if (resp->type == RESPONSE_DIED) {
                resolv->dead = 1;
                return 0;
        }

        q = lookup_query(resolv, resp->id);
        if (!q)
                return 0;

        switch (resp->type) {
        case RESPONSE_ADDRINFO: {
                const addrinfo_response_t *ai_resp = &packet->addrinfo_response;
                const void *p;
                size_t l;
                struct addrinfo *prev = NULL;

                assert(length >= sizeof(addrinfo_response_t));
                assert(q->type == REQUEST_ADDRINFO);

                q->ret = ai_resp->ret;
                q->_errno = ai_resp->_errno;
                q->_h_errno = ai_resp->_h_errno;
                l = length - sizeof(addrinfo_response_t);
                p = (const uint8_t*) resp + sizeof(addrinfo_response_t);

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

                complete_query(resolv, q);
                break;
        }

        case RESPONSE_NAMEINFO: {
                const nameinfo_response_t *ni_resp = &packet->nameinfo_response;

                assert(length >= sizeof(nameinfo_response_t));
                assert(q->type == REQUEST_NAMEINFO);

                q->ret = ni_resp->ret;
                q->_errno = ni_resp->_errno;
                q->_h_errno = ni_resp->_h_errno;

                if (ni_resp->hostlen)
                        if (!(q->host = strndup((const char*) ni_resp + sizeof(nameinfo_response_t), ni_resp->hostlen-1)))
                                q->ret = EAI_MEMORY;

                if (ni_resp->servlen)
                        if (!(q->serv = strndup((const char*) ni_resp + sizeof(nameinfo_response_t) + ni_resp->hostlen, ni_resp->servlen-1)))
                                q->ret = EAI_MEMORY;

                complete_query(resolv, q);
                break;
        }

        case RESPONSE_RES: {
                const res_response_t *res_resp = &packet->res_response;

                assert(length >= sizeof(res_response_t));
                assert(q->type == REQUEST_RES_QUERY || q->type == REQUEST_RES_SEARCH);

                q->ret = res_resp->ret;
                q->_errno = res_resp->_errno;
                q->_h_errno = res_resp->_h_errno;

                if (res_resp->ret >= 0)  {
                        if (!(q->serv = malloc(res_resp->ret))) {
                                q->ret = -1;
                                q->_errno = ENOMEM;
                        } else
                                memcpy(q->serv, (const char *)resp + sizeof(res_response_t), res_resp->ret);
                }

                complete_query(resolv, q);
                break;
        }

        default:
                ;
        }

        return 0;
}

int sd_resolv_wait(sd_resolv_t *resolv, int block) {
        int handled = 0;
        assert(resolv);

        for (;;) {
                packet_t buf[BUFSIZE/sizeof(packet_t) + 1];
                ssize_t l;

                if (resolv->dead) {
                        errno = ECHILD;
                        return -1;
                }

                l = recv(resolv->fds[RESPONSE_RECV_FD], buf, sizeof(buf), 0);
                if (l < 0) {
                        fd_set fds;

                        if (errno != EAGAIN)
                                return -1;

                        if (!block || handled)
                                return 0;

                        FD_ZERO(&fds);
                        FD_SET(resolv->fds[RESPONSE_RECV_FD], &fds);

                        if (select(resolv->fds[RESPONSE_RECV_FD]+1, &fds, NULL, NULL, NULL) < 0)
                                return -1;

                        continue;
                }

                if (handle_response(resolv, buf, (size_t) l) < 0)
                        return -1;

                handled = 1;
        }
}

static sd_resolv_query_t *alloc_query(sd_resolv_t *resolv) {
        sd_resolv_query_t *q;
        assert(resolv);

        if (resolv->n_queries >= MAX_QUERIES) {
                errno = ENOMEM;
                return NULL;
        }

        while (resolv->queries[resolv->current_index]) {
                resolv->current_index++;
                resolv->current_id++;

                while (resolv->current_index >= MAX_QUERIES)
                        resolv->current_index -= MAX_QUERIES;
        }

        q = resolv->queries[resolv->current_index] = malloc(sizeof(sd_resolv_query_t));
        if (!q) {
                errno = ENOMEM;
                return NULL;
        }

        resolv->n_queries++;

        q->resolv = resolv;
        q->done = 0;
        q->id = resolv->current_id;
        q->done_next = q->done_prev = NULL;
        q->ret = 0;
        q->_errno = 0;
        q->_h_errno = 0;
        q->addrinfo = NULL;
        q->userdata = NULL;
        q->host = q->serv = NULL;

        return q;
}

sd_resolv_query_t* sd_resolv_getaddrinfo(sd_resolv_t *resolv, const char *node, const char *service, const struct addrinfo *hints) {
        addrinfo_request_t data[BUFSIZE/sizeof(addrinfo_request_t) + 1] = {};
        addrinfo_request_t *req = data;
        sd_resolv_query_t *q;
        assert(resolv);
        assert(node || service);

        if (resolv->dead) {
                errno = ECHILD;
                return NULL;
        }

        q = alloc_query(resolv);
        if (!q)
                return NULL;

        req->node_len = node ? strlen(node)+1 : 0;
        req->service_len = service ? strlen(service)+1 : 0;

        req->header.id = q->id;
        req->header.type = q->type = REQUEST_ADDRINFO;
        req->header.length = sizeof(addrinfo_request_t) + req->node_len + req->service_len;

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
                strcpy((char*) req + sizeof(addrinfo_request_t), node);

        if (service)
                strcpy((char*) req + sizeof(addrinfo_request_t) + req->node_len, service);

        if (send(resolv->fds[REQUEST_SEND_FD], req, req->header.length, MSG_NOSIGNAL) < 0)
                goto fail;

        return q;

fail:
        if (q)
                sd_resolv_cancel(resolv, q);

        return NULL;
}

int sd_resolv_getaddrinfo_done(sd_resolv_t *resolv, sd_resolv_query_t* q, struct addrinfo **ret_res) {
        int ret;
        assert(resolv);
        assert(q);
        assert(q->resolv == resolv);
        assert(q->type == REQUEST_ADDRINFO);

        if (resolv->dead) {
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

        sd_resolv_cancel(resolv, q);

        return ret;
}

sd_resolv_query_t* sd_resolv_getnameinfo(sd_resolv_t *resolv, const struct sockaddr *sa, socklen_t salen, int flags, int gethost, int getserv) {
        nameinfo_request_t data[BUFSIZE/sizeof(nameinfo_request_t) + 1] = {};
        nameinfo_request_t *req = data;
        sd_resolv_query_t *q;

        assert(resolv);
        assert(sa);
        assert(salen > 0);

        if (resolv->dead) {
                errno = ECHILD;
                return NULL;
        }

        q = alloc_query(resolv);
        if (!q)
                return NULL;

        req->header.id = q->id;
        req->header.type = q->type = REQUEST_NAMEINFO;
        req->header.length = sizeof(nameinfo_request_t) + salen;

        if (req->header.length > BUFSIZE) {
                errno = ENOMEM;
                goto fail;
        }

        req->flags = flags;
        req->sockaddr_len = salen;
        req->gethost = gethost;
        req->getserv = getserv;

        memcpy((uint8_t*) req + sizeof(nameinfo_request_t), sa, salen);

        if (send(resolv->fds[REQUEST_SEND_FD], req, req->header.length, MSG_NOSIGNAL) < 0)
                goto fail;

        return q;

fail:
        if (q)
                sd_resolv_cancel(resolv, q);

        return NULL;
}

int sd_resolv_getnameinfo_done(sd_resolv_t *resolv, sd_resolv_query_t* q, char *ret_host, size_t hostlen, char *ret_serv, size_t servlen) {
        int ret;
        assert(resolv);
        assert(q);
        assert(q->resolv == resolv);
        assert(q->type == REQUEST_NAMEINFO);
        assert(!ret_host || hostlen);
        assert(!ret_serv || servlen);

        if (resolv->dead) {
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

        sd_resolv_cancel(resolv, q);

        return ret;
}

static sd_resolv_query_t * resolv_res(sd_resolv_t *resolv, query_type_t qtype, const char *dname, int class, int type) {
        res_request_t data[BUFSIZE/sizeof(res_request_t) + 1];
        res_request_t *req = data;
        sd_resolv_query_t *q;

        assert(resolv);
        assert(dname);

        if (resolv->dead) {
                errno = ECHILD;
                return NULL;
        }

        q = alloc_query(resolv);
        if (!q)
                return NULL;

        req->dname_len = strlen(dname) + 1;

        req->header.id = q->id;
        req->header.type = q->type = qtype;
        req->header.length = sizeof(res_request_t) + req->dname_len;

        if (req->header.length > BUFSIZE) {
                errno = ENOMEM;
                goto fail;
        }

        req->class = class;
        req->type = type;

        strcpy((char*) req + sizeof(res_request_t), dname);

        if (send(resolv->fds[REQUEST_SEND_FD], req, req->header.length, MSG_NOSIGNAL) < 0)
                goto fail;

        return q;

fail:
        if (q)
                sd_resolv_cancel(resolv, q);

        return NULL;
}

sd_resolv_query_t* sd_resolv_res_query(sd_resolv_t *resolv, const char *dname, int class, int type) {
        return resolv_res(resolv, REQUEST_RES_QUERY, dname, class, type);
}

sd_resolv_query_t* sd_resolv_res_search(sd_resolv_t *resolv, const char *dname, int class, int type) {
        return resolv_res(resolv, REQUEST_RES_SEARCH, dname, class, type);
}

int sd_resolv_res_done(sd_resolv_t *resolv, sd_resolv_query_t* q, unsigned char **answer) {
        int ret;
        assert(resolv);
        assert(q);
        assert(q->resolv == resolv);
        assert(q->type == REQUEST_RES_QUERY || q->type == REQUEST_RES_SEARCH);
        assert(answer);

        if (resolv->dead) {
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

        sd_resolv_cancel(resolv, q);

        return ret < 0 ? -errno : ret;
}

sd_resolv_query_t* sd_resolv_getnext(sd_resolv_t *resolv) {
        assert(resolv);
        return resolv->done_head;
}

int sd_resolv_getnqueries(sd_resolv_t *resolv) {
        assert(resolv);
        return resolv->n_queries;
}

void sd_resolv_cancel(sd_resolv_t *resolv, sd_resolv_query_t* q) {
        int i;
        int saved_errno = errno;

        assert(resolv);
        assert(q);
        assert(q->resolv == resolv);
        assert(resolv->n_queries > 0);

        if (q->done) {

                if (q->done_prev)
                        q->done_prev->done_next = q->done_next;
                else
                        resolv->done_head = q->done_next;

                if (q->done_next)
                        q->done_next->done_prev = q->done_prev;
                else
                        resolv->done_tail = q->done_prev;
        }

        i = q->id % MAX_QUERIES;
        assert(resolv->queries[i] == q);
        resolv->queries[i] = NULL;

        sd_resolv_freeaddrinfo(q->addrinfo);
        free(q->host);
        free(q->serv);

        resolv->n_queries--;
        free(q);

        errno = saved_errno;
}

void sd_resolv_freeaddrinfo(struct addrinfo *ai) {
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

void sd_resolv_freeanswer(unsigned char *answer) {
        int saved_errno = errno;

        if (!answer)
                return;

        free(answer);

        errno = saved_errno;
}

int sd_resolv_isdone(sd_resolv_t *resolv, sd_resolv_query_t*q) {
        assert(resolv);
        assert(q);
        assert(q->resolv == resolv);

        return q->done;
}

void sd_resolv_setuserdata(sd_resolv_t *resolv, sd_resolv_query_t *q, void *userdata) {
        assert(q);
        assert(resolv);
        assert(q->resolv = resolv);

        q->userdata = userdata;
}

void* sd_resolv_getuserdata(sd_resolv_t *resolv, sd_resolv_query_t *q) {
        assert(q);
        assert(resolv);
        assert(q->resolv = resolv);

        return q->userdata;
}
