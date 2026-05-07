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

#include <sys/socket.h>

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

struct iovec;
struct pollfd;
struct sockaddr;
struct msghdr;

typedef struct sd_event sd_event;
typedef struct sd_future sd_future;
typedef struct sd_future_ops sd_future_ops;
typedef struct sd_promise sd_promise;
typedef int (*sd_future_func_t)(sd_future *f);
typedef int (*sd_fiber_func_t)(void *userdata);
typedef void (*sd_fiber_destroy_t)(void *userdata);

struct sd_future_ops {
        void* (*free)(void *userdata);
        int (*cancel)(void *userdata);
        int (*set_priority)(void *userdata, int64_t priority);
};

enum {
        SD_FUTURE_PENDING,
        SD_FUTURE_RESOLVED
};

int sd_future_new(const sd_future_ops *ops, void *impl, sd_future **ret);
int sd_future_cancel(sd_future *f);
int sd_promise_resolve(sd_promise *p, int result);

_SD_DECLARE_TRIVIAL_REF_UNREF_FUNC(sd_future);
_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_future, sd_future_unref);
void sd_future_unref_array_clear(sd_future **array, size_t n);
void sd_future_unref_array(sd_future **array, size_t n);

sd_future* sd_future_cancel_wait_unref(sd_future *f);
_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_future, sd_future_cancel_wait_unref);
void sd_future_cancel_wait_unref_array_clear(sd_future **array, size_t n);
void sd_future_cancel_wait_unref_array(sd_future **array, size_t n);

int sd_future_state(sd_future *f);
int sd_future_result(sd_future *f);
void* sd_future_get_userdata(sd_future *f);
void* sd_future_get_impl(sd_future *f);
const sd_future_ops* sd_future_get_ops(sd_future *f);

int sd_future_set_callback(sd_future *f, sd_future_func_t callback, void *userdata);
int sd_future_set_priority(sd_future *f, int64_t priority);

int sd_future_new_wait(sd_future *target, sd_future **ret);

int sd_fiber_new(sd_event *e, const char *name, sd_fiber_func_t func, void *userdata, sd_fiber_destroy_t destroy, sd_future **ret);

int sd_fiber_set_floating(sd_future *f, int b);
int sd_fiber_get_floating(sd_future *f);

int sd_fiber_is_running(void);
sd_future* sd_fiber_get_current(void);
const char* sd_fiber_get_name(sd_future *f);
int64_t sd_fiber_get_priority(void);
sd_event* sd_fiber_get_event(void);

int sd_fiber_yield(void);
int sd_fiber_sleep(uint64_t usec);
int sd_fiber_await(sd_future *target);
int sd_fiber_suspend(void);
int sd_fiber_resume(sd_future *f, int result);

sd_future* sd_fiber_timeout(uint64_t timeout);

#define SD_FIBER_TIMEOUT(timeout) _SD_FIBER_TIMEOUT(_SD_UNIQ, (timeout))
#define _SD_FIBER_TIMEOUT(uniq, timeout)                                                                                                        \
        sd_future *_SD_CONCATENATE(_sd_fto_, uniq) __attribute__((cleanup(sd_future_cancel_wait_unrefp), unused)) = sd_fiber_timeout(timeout)

#define SD_FIBER_WITH_TIMEOUT(timeout) _SD_FIBER_WITH_TIMEOUT(_SD_UNIQ, (timeout))
#define _SD_FIBER_WITH_TIMEOUT(uniq, timeout)                                                                                                                   \
        for (sd_future *_SD_CONCATENATE(_sd_fto_, uniq) __attribute__((cleanup(sd_future_cancel_wait_unrefp), unused)) = sd_fiber_timeout(timeout),             \
                       *_SD_CONCATENATE(_sd_fto_b_, uniq) = (sd_future *) 1;                                                                                    \
             _SD_CONCATENATE(_sd_fto_b_, uniq);                                                                                                                 \
             _SD_CONCATENATE(_sd_fto_b_, uniq) = NULL)

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
int sd_fiber_poll(struct pollfd *fds, size_t n_fds, uint64_t timeout);

_SD_END_DECLARATIONS;

#endif
