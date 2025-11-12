/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef foosdfuturefoo
#define foosdfuturefoo

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
#include <sys/socket.h>
#include <sys/uio.h>

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

typedef struct sd_bus sd_bus;
typedef struct sd_bus_error sd_bus_error;
typedef struct sd_bus_message sd_bus_message;
typedef int (*sd_bus_message_handler_t)(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error);
typedef struct sd_event sd_event;
typedef struct sd_future sd_future;
typedef int (*sd_future_func_t)(sd_future *f, void *userdata);
typedef int (*sd_fiber_func_t)(void *userdata);
typedef void (*sd_fiber_destroy_t)(void *userdata);

enum {
        SD_FUTURE_IO,
        SD_FUTURE_TIME,
        SD_FUTURE_CHILD,
        SD_FUTURE_WAIT,
        SD_FUTURE_FIBER,
        SD_FUTURE_BUS
};

enum {
        SD_FUTURE_PENDING,
        SD_FUTURE_RESOLVED
};

_SD_DECLARE_TRIVIAL_REF_UNREF_FUNC(sd_future);
_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_future, sd_future_unref);

int sd_future_cancel(sd_future *f);
sd_future* sd_fiber_cancel_wait_unref(sd_future *f);
_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_future, sd_fiber_cancel_wait_unref);

void sd_future_unref_many(sd_future **array, size_t n);

int sd_future_state(sd_future *f);
int sd_future_result(sd_future *f);
int sd_future_bus_reply(sd_future *f, sd_bus_message **ret);

int sd_future_set_callback(sd_future *f, sd_future_func_t callback, void *userdata);
int sd_future_set_priority(sd_future *f, int64_t priority);

int sd_future_new_io(sd_event *e, int fd, uint32_t events, sd_future **ret);
int sd_future_new_time(sd_event *e, clockid_t clock, uint64_t usec, uint64_t accuracy, sd_future **ret);
int sd_future_new_time_relative(sd_event *e, clockid_t clock, uint64_t usec, uint64_t accuracy, sd_future **ret);
int sd_future_new_child(sd_event *e, pid_t pid, int options, sd_future **ret);
int sd_future_new_child_pidfd(sd_event *e, int pidfd, int options, sd_future **ret);
int sd_future_new_wait(sd_future *target, sd_future **ret);
int sd_future_new_fiber(sd_event *e, const char *name, sd_fiber_func_t func, void *userdata, sd_fiber_destroy_t destroy, sd_future **ret);

int sd_future_get_child_pidfd_own(sd_future *f);
int sd_future_set_child_pidfd_own(sd_future *f, int own);

int sd_bus_call_future(sd_bus *bus, sd_bus_message *m, uint64_t usec, sd_future **ret);
int sd_bus_call_method_future(
                sd_bus *bus,
                sd_future **ret,
                const char *destination,
                const char *path,
                const char *interface,
                const char *member,
                const char *types,
                ...);

int sd_fiber_is_running(void);
const char* sd_fiber_get_name(void);
int64_t sd_fiber_get_priority(void);
sd_event* sd_fiber_get_event(void);

int sd_fiber_yield(void);
int sd_fiber_sleep(uint64_t usec);
int sd_fiber_await(sd_future *target);

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

/* Fiber sd-event operations - wrap sd-event operations for use in fibers */
int sd_event_run_suspend(sd_event *event, uint64_t timeout);
int sd_event_loop_suspend(sd_event *e);

/* Fiber sd-bus operations - wrap sd-bus async operations for use in fibers */
int sd_bus_call_suspend(sd_bus *bus, sd_bus_message *m, uint64_t usec, sd_bus_error *reterr_error, sd_bus_message **ret_reply);

_SD_END_DECLARATIONS;

#endif
