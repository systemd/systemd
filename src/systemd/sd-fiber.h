/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef foosdfiberhfoo
#define foosdfiberhfoo

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

#include <poll.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

#define SD_FIBER_PRIORITY_DEFAULT 0

typedef struct sd_bus sd_bus;
typedef struct sd_bus_error sd_bus_error;
typedef struct sd_bus_message sd_bus_message;
typedef struct sd_bus_slot sd_bus_slot;
typedef struct sd_event sd_event;
typedef struct sd_fiber sd_fiber;
typedef struct sd_fiber_waitgroup sd_fiber_waitgroup;
typedef int (*sd_fiber_func_t)(void *userdata);
typedef void (*sd_fiber_destroy_t)(void *userdata);

int sd_fiber_new_full(
                sd_event *e,
                const char *name,
                sd_fiber_func_t func,
                void *userdata,
                int64_t priority,
                sd_fiber **ret);

int sd_fiber_new(const char *name, sd_fiber_func_t func, void *userdata, sd_fiber **ret);

sd_fiber *sd_fiber_ref(sd_fiber *f);
sd_fiber *sd_fiber_unref(sd_fiber *f);
_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_fiber, sd_fiber_unref);

void sd_fiber_unref_many(sd_fiber **fibers, size_t size);

const char* sd_fiber_name(const sd_fiber *f);
sd_event* sd_fiber_event(const sd_fiber *f);

int sd_fiber_set_destroy_callback(sd_fiber *f, sd_fiber_destroy_t callback);
int sd_fiber_get_destroy_callback(sd_fiber *f, sd_fiber_destroy_t *ret);

int sd_fiber_set_exit_on_failure(sd_fiber *f, int b);

/* Get current fiber context (returns NULL if not in fiber) */
sd_fiber *sd_fiber_current(void);

/* Yield control to scheduler */
int sd_fiber_yield(void);
int sd_fiber_cancel(sd_fiber *f);
int sd_fiber_result(sd_fiber *f);

/* Fiber I/O operations - use sd-event for non-blocking I/O when in fiber context */
ssize_t sd_fiber_read(int fd, void *buf, size_t count);
ssize_t sd_fiber_write(int fd, const void *buf, size_t count);
ssize_t sd_fiber_readv(int fd, const struct iovec *iov, int iovcnt);
ssize_t sd_fiber_writev(int fd, const struct iovec *iov, int iovcnt);
ssize_t sd_fiber_recv(int sockfd, void *buf, size_t len, int flags);
ssize_t sd_fiber_send(int sockfd, const void *buf, size_t len, int flags);
int sd_fiber_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
ssize_t sd_fiber_recvmsg(int sockfd, struct msghdr *msg, int flags);
ssize_t sd_fiber_sendmsg(int sockfd, const struct msghdr *msg, int flags);
ssize_t sd_fiber_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
ssize_t sd_fiber_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
int sd_fiber_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);

int sd_fiber_ppoll(struct pollfd *fds, size_t n_fds, uint64_t timeout);
int sd_fiber_sleep(uint64_t usec);
int sd_fiber_wait_for(sd_fiber *target);

/* Waitgroup - coordinate completion of multiple fibers */
int sd_fiber_waitgroup_new(sd_fiber_waitgroup **ret);
sd_fiber_waitgroup *sd_fiber_waitgroup_free(sd_fiber_waitgroup *wg);
_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_fiber_waitgroup, sd_fiber_waitgroup_free);

int sd_fiber_waitgroup_add(sd_fiber_waitgroup *wg, sd_fiber *f);
int sd_fiber_waitgroup_wait(sd_fiber_waitgroup *wg);
int sd_fiber_waitgroup_check(sd_fiber_waitgroup *wg, sd_fiber **reterr);

/* Fiber sd-event operations - wrap sd-event operations for use in fibers */
int sd_event_run_suspend(sd_event *event, uint64_t timeout);
int sd_event_loop_suspend(sd_event *e);

/* Fiber sd-bus operations - wrap sd-bus async operations for use in fibers */
int sd_bus_call_suspend(sd_bus *bus, sd_bus_message *m, uint64_t usec, sd_bus_error *reterr_error, sd_bus_message **ret_reply);

_SD_END_DECLARATIONS;

#endif
