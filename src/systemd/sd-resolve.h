/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foosdresolvehfoo
#define foosdresolvehfoo

/***
  This file is part of systemd.

  Copyright 2005-2014 Lennart Poettering

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

#include <inttypes.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "sd-event.h"
#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

/* An opaque sd-resolve session structure */
typedef struct sd_resolve sd_resolve;

/* An opaque sd-resolve query structure */
typedef struct sd_resolve_query sd_resolve_query;

/* A callback on completion */
typedef int (*sd_resolve_getaddrinfo_handler_t)(sd_resolve_query *q, int ret, const struct addrinfo *ai, void *userdata);
typedef int (*sd_resolve_getnameinfo_handler_t)(sd_resolve_query *q, int ret, const char *host, const char *serv, void *userdata);

enum {
        SD_RESOLVE_GET_HOST = 1ULL,
        SD_RESOLVE_GET_SERVICE = 2ULL,
        SD_RESOLVE_GET_BOTH = 3ULL
};

int sd_resolve_default(sd_resolve **ret);

/* Allocate a new sd-resolve session. */
int sd_resolve_new(sd_resolve **ret);

/* Free a sd-resolve session. This destroys all attached
 * sd_resolve_query objects automatically. */
sd_resolve* sd_resolve_unref(sd_resolve *resolve);
sd_resolve* sd_resolve_ref(sd_resolve *resolve);

/* Return the UNIX file descriptor to poll() for events on. Use this
 * function to integrate sd-resolve with your custom main loop. */
int sd_resolve_get_fd(sd_resolve *resolve);

/* Return the poll() events (a combination of flags like POLLIN,
 * POLLOUT, ...) to check for. */
int sd_resolve_get_events(sd_resolve *resolve);

/* Return the poll() timeout to pass. Returns (uint64_t) -1 as
 * timeout if no timeout is needed. */
int sd_resolve_get_timeout(sd_resolve *resolve, uint64_t *timeout_usec);

/* Process pending responses. After this function is called, you can
 * get the next completed query object(s) using
 * sd_resolve_get_next(). */
int sd_resolve_process(sd_resolve *resolve);

/* Wait for a resolve event to complete. */
int sd_resolve_wait(sd_resolve *resolve, uint64_t timeout_usec);

int sd_resolve_get_tid(sd_resolve *resolve, pid_t *tid);

int sd_resolve_attach_event(sd_resolve *resolve, sd_event *e, int priority);
int sd_resolve_detach_event(sd_resolve *resolve);
sd_event *sd_resolve_get_event(sd_resolve *resolve);

/* Issue a name-to-address query on the specified session. The
 * arguments are compatible with those of libc's
 * getaddrinfo(3). The function returns a new query object. When the
 * query is completed, you may retrieve the results using
 * sd_resolve_getaddrinfo_done(). */
int sd_resolve_getaddrinfo(sd_resolve *resolve, sd_resolve_query **q, const char *node, const char *service, const struct addrinfo *hints, sd_resolve_getaddrinfo_handler_t callback, void *userdata);

/* Issue an address-to-name query on the specified session. The
 * arguments are compatible with those of libc's
 * getnameinfo(3). The function returns a new query object. When the
 * query is completed, you may retrieve the results using
 * sd_resolve_getnameinfo_done(). Set gethost (resp. getserv) to non-zero
 * if you want to query the hostname (resp. the service name). */
int sd_resolve_getnameinfo(sd_resolve *resolve, sd_resolve_query **q, const struct sockaddr *sa, socklen_t salen, int flags, uint64_t get, sd_resolve_getnameinfo_handler_t callback, void *userdata);

sd_resolve_query *sd_resolve_query_ref(sd_resolve_query* q);
sd_resolve_query *sd_resolve_query_unref(sd_resolve_query* q);

/* Returns non-zero when the query operation specified by q has been completed. */
int sd_resolve_query_is_done(sd_resolve_query*q);

void *sd_resolve_query_get_userdata(sd_resolve_query *q);
void *sd_resolve_query_set_userdata(sd_resolve_query *q, void *userdata);

sd_resolve *sd_resolve_query_get_resolve(sd_resolve_query *q);

_SD_END_DECLARATIONS;

#endif
