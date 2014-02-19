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

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

/** An opaque sd-resolve session structure */
typedef struct sd_resolve sd_resolve;

/** An opaque sd-resolve query structure */
typedef struct sd_resolve_query sd_resolve_query;

/** Allocate a new sd-resolve session */
int sd_resolve_new(sd_resolve **ret);

/** Free a sd-resolve session. This destroys all attached
 * sd_resolve_query objects automatically */
sd_resolve* sd_resolve_unref(sd_resolve *resolve);

/** Return the UNIX file descriptor to poll() for events on. Use this
 * function to integrate sd-resolve with your custom main loop. */
int sd_resolve_get_fd(sd_resolve *resolve);

/** Return the poll() events (a combination of flags like POLLIN,
 * POLLOUT, ...) to check for. */
int sd_resolve_get_events(sd_resolve *resolve);

/** Return the poll() timeout to pass. Returns (uint64_t) -1 as time
 * out if no time out is needed */
int sd_resolve_get_timeout(sd_resolve *resolve, uint64_t *timeout_usec);

/** Process pending responses. After this function is called you can
 * get the next completed query object(s) using
 * sd_resolve_get_next(). */
int sd_resolve_process(sd_resolve *resolve);

/** Wait for a resolve event to complete */
int sd_resolve_wait(sd_resolve *resolve, uint64_t timeout_usec);

/** Issue a name to address query on the specified session. The
 * arguments are compatible with the ones of libc's
 * getaddrinfo(3). The function returns a new query object. When the
 * query is completed you may retrieve the results using
 * sd_resolve_getaddrinfo_done(). */
int sd_resolve_getaddrinfo(sd_resolve *resolve, sd_resolve_query **q, const char *node, const char *service, const struct addrinfo *hints);

/** Retrieve the results of a preceding sd_resolve_getaddrinfo()
 * call. Returns a addrinfo structure and a return value compatible
 * with libc's getaddrinfo(3). The query object q is destroyed by this
 * call and may not be used any further. Make sure to free the
 * returned addrinfo structure with sd_resolve_freeaddrinfo() and not
 * libc's freeaddrinfo(3)! If the query is not completed yet EAI_AGAIN
 * is returned. */
int sd_resolve_getaddrinfo_done(sd_resolve_query* q, struct addrinfo **ret_ai);

/** Free the addrinfo structure as returned by
 * sd_resolve_getaddrinfo_done(). Make sure to use this functions instead
 * of the libc's freeaddrinfo()! */
void sd_resolve_freeaddrinfo(struct addrinfo *ai);

/** Issue an address to name query on the specified session. The
 * arguments are compatible with the ones of libc's
 * getnameinfo(3). The function returns a new query object. When the
 * query is completed you may retrieve the results using
 * sd_resolve_getnameinfo_done(). Set gethost (resp. getserv) to non-zero
 * if you want to query the hostname (resp. the service name). */
int sd_resolve_getnameinfo(sd_resolve *resolve, sd_resolve_query **q, const struct sockaddr *sa, socklen_t salen, int flags, int gethost, int getserv);

/** Retrieve the results of a preceding sd_resolve_getnameinfo()
 * call. Returns the hostname and the service name in ret_host and
 * ret_serv. The query object q is destroyed by this call and may not
 * be used any further. If the query is not completed yet EAI_AGAIN is
 * returned. */
int sd_resolve_getnameinfo_done(sd_resolve_query* q, char **ret_host, char **ret_serv);

/** Issue a resolver query on the specified session. The arguments are
 * compatible with the ones of libc's res_query(3). The function returns a new
 * query object. When the query is completed you may retrieve the results using
 * sd_resolve_res_done().  */
int sd_resolve_res_query(sd_resolve *resolve, sd_resolve_query **q, const char *dname, int class, int type);

/** Issue an resolver query on the specified session. The arguments are
 * compatible with the ones of libc's res_search(3). The function returns a new
 * query object. When the query is completed you may retrieve the results using
 * sd_resolve_res_done().  */
int sd_resolve_res_search(sd_resolve *resolve, sd_resolve_query **q, const char *dname, int class, int type);

/** Retrieve the results of a preceding sd_resolve_res_query() or
 * resolve_res_search call.  The query object q is destroyed by this
 * call and may not be used any further. Returns a pointer to the
 * answer of the res_query call. If the query is not completed yet
 * -EAGAIN is returned, on failure -errno is returned, otherwise the
 * length of answer is returned. */
int sd_resolve_res_done(sd_resolve_query* q, unsigned char **answer);

/** Return the next completed query object. If no query has been
 * completed yet, return NULL. Please note that you need to run
 * sd_resolve_wait() before this function will return sensible data.  */
int sd_resolve_get_next(sd_resolve *resolve, sd_resolve_query **q);

/** Return the number of query objects (completed or not) attached to
 * this session */
int sd_resolve_get_n_queries(sd_resolve *resolve);

/** Cancel a currently running query. q is is destroyed by this call
 * and may not be used any futher. */
int sd_resolve_cancel(sd_resolve_query* q);

/** Returns non-zero when the query operation specified by q has been completed */
int sd_resolve_is_done(sd_resolve_query*q);

/** Assign some opaque userdata with a query object */
void* sd_resolve_set_userdata(sd_resolve_query *q, void *userdata);

/** Return userdata assigned to a query object. Use
 * sd_resolve_setuserdata() to set this data. If no data has been set
 * prior to this call it returns NULL. */
void* sd_resolve_get_userdata(sd_resolve_query *q);

_SD_END_DECLARATIONS;

#endif
