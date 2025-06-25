/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef foosdresolvehfoo
#define foosdresolvehfoo

/***
  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <https://www.gnu.org/licenses/>.
***/

/* 'struct addrinfo' needs _GNU_SOURCE */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <sys/socket.h>

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

struct addrinfo;

typedef struct sd_event sd_event;

/* An opaque sd-resolve session structure */
typedef struct sd_resolve sd_resolve;

/* An opaque sd-resolve query structure */
typedef struct sd_resolve_query sd_resolve_query;

/* A callback on completion */
typedef int (*sd_resolve_getaddrinfo_handler_t)(sd_resolve_query *q, int ret, const struct addrinfo *ai, void *userdata);
typedef int (*sd_resolve_getnameinfo_handler_t)(sd_resolve_query *q, int ret, const char *host, const char *serv, void *userdata);
typedef _sd_destroy_t sd_resolve_destroy_t;

enum {
        SD_RESOLVE_GET_HOST    = 1 << 0,
        SD_RESOLVE_GET_SERVICE = 1 << 1,
        SD_RESOLVE_GET_BOTH = SD_RESOLVE_GET_HOST | SD_RESOLVE_GET_SERVICE
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

/* Return the poll() timeout to pass. Returns UINT64_MAX as
 * timeout if no timeout is needed. */
int sd_resolve_get_timeout(sd_resolve *resolve, uint64_t *timeout_usec);

/* Process pending responses. After this function is called, you can
 * get the next completed query object(s) using
 * sd_resolve_get_next(). */
int sd_resolve_process(sd_resolve *resolve);

/* Wait for a resolve event to complete. */
int sd_resolve_wait(sd_resolve *resolve, uint64_t timeout_usec);

int sd_resolve_get_tid(sd_resolve *resolve, pid_t *tid);

int sd_resolve_attach_event(sd_resolve *resolve, sd_event *e, int64_t priority);
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

sd_resolve_query *sd_resolve_query_ref(sd_resolve_query *q);
sd_resolve_query *sd_resolve_query_unref(sd_resolve_query *q);

/* Returns non-zero when the query operation specified by q has been completed. */
int sd_resolve_query_is_done(sd_resolve_query *q);

void *sd_resolve_query_get_userdata(sd_resolve_query *q);
void *sd_resolve_query_set_userdata(sd_resolve_query *q, void *userdata);
int sd_resolve_query_get_destroy_callback(sd_resolve_query *q, sd_resolve_destroy_t *destroy_callback);
int sd_resolve_query_set_destroy_callback(sd_resolve_query *q, sd_resolve_destroy_t destroy_callback);
int sd_resolve_query_get_floating(sd_resolve_query *q);
int sd_resolve_query_set_floating(sd_resolve_query *q, int b);

sd_resolve *sd_resolve_query_get_resolve(sd_resolve_query *q);

_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_resolve, sd_resolve_unref);
_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_resolve_query, sd_resolve_query_unref);

_SD_END_DECLARATIONS;

#endif
