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
struct timespec;

typedef struct sd_channel sd_channel;
typedef struct sd_event sd_event;
typedef struct sd_future sd_future;
typedef struct sd_future_ops sd_future_ops;
typedef struct sd_future_slot sd_future_slot;
typedef int (*sd_future_func_t)(sd_future *f, void *userdata);
typedef int (*sd_fiber_func_t)(void *userdata);
typedef _sd_destroy_t sd_fiber_destroy_t;
typedef _sd_destroy_t sd_channel_destroy_t;

struct sd_future_ops {
        size_t size;
        size_t private_size;
        void (*free)(sd_future *f);
        int (*cancel)(sd_future *f);
        int (*set_priority)(sd_future *f, int64_t priority);
};

__extension__ typedef enum _SD_ENUM_TYPE_S64(sd_future_state_t) {
        SD_FUTURE_PENDING,
        SD_FUTURE_RESOLVED,
        _SD_ENUM_FORCE_S64(SD_FUTURE_STATE)
} sd_future_state_t;

/* SD_EVENT_DEFAULT selects the calling thread's existing default event loop, or fails with -ENOPKG. */
int sd_future_new(sd_event *e, const sd_future_ops *ops, sd_future **ret);
int sd_future_cancel(sd_future *f);
/* sd_future_resolve() only fails if f is NULL or already resolved. */
int sd_future_resolve(sd_future *f, int result);

/* A future must be RESOLVED before its last reference is released; dropping the last reference to a
 * PENDING future is a programming error that aborts the process. Use sd_future_cancel_unref() when
 * cancellation resolves synchronously, or sd_future_cancel_wait_unref() from a fiber when it must
 * wait for resolution. Plain sd_future_unref() does not cancel the future. */
_SD_DECLARE_TRIVIAL_REF_UNREF_FUNC(sd_future);
_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_future, sd_future_unref);
void sd_future_unref_array_clear(sd_future *array[], size_t n);
void sd_future_unref_array(sd_future *array[], size_t n);

sd_future* sd_future_cancel_unref(sd_future *f);
_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_future, sd_future_cancel_unref);
void sd_future_cancel_unref_array_clear(sd_future *array[], size_t n);
void sd_future_cancel_unref_array(sd_future *array[], size_t n);

/* Cancel and release the caller's reference after resolution. The target must not be the calling
 * fiber. Asynchronous cancellation must be awaited from a fiber on the same event loop. */
sd_future* sd_future_cancel_wait_unref(sd_future *f);
_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_future, sd_future_cancel_wait_unref);
void sd_future_cancel_wait_unref_array_clear(sd_future *array[], size_t n);
void sd_future_cancel_wait_unref_array(sd_future *array[], size_t n);

int sd_future_state(sd_future *f);
int sd_future_result(sd_future *f);
void* sd_future_get_private(sd_future *f);
/* sd_future_from_private() returns the future that p is the private data of. It is the inverse of
 * sd_future_get_private(). */
sd_future* sd_future_from_private(void *p);
const sd_future_ops* sd_future_get_ops(sd_future *f);
sd_event* sd_future_get_event(sd_future *f);

int sd_future_add_callback(sd_future *f, sd_future_slot **ret_slot, sd_future_func_t callback, void *userdata);

int sd_future_new_defer(sd_event *e, int result, sd_future **ret);

_SD_DECLARE_TRIVIAL_REF_UNREF_FUNC(sd_future_slot);
_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_future_slot, sd_future_slot_unref);

sd_future* sd_future_slot_get_future(sd_future_slot *s);

int sd_future_set_priority(sd_future *f, int64_t priority);

/* Group policies select an outcome as follows:
 * WAIT_ALL: first child error, or 0 once every child succeeds.
 * WAIT_ALL | IGNORE_ERRORS: wait for every child, then return the first error or 0.
 * WAIT_ANY: a successful child's result if any have succeeded, otherwise the first child error.
 * WAIT_ANY | IGNORE_ERRORS: wait for a success, or for every child to fail; return that success or
 *                         the first error, respectively.
 * "First" means insertion order among the children already resolved when the outcome is selected.
 * Once selected, the outcome is final: remaining children are cancelled, and the group resolves only
 * after every child has finished. IGNORE_ERRORS also suppresses cancellation of the parent fiber;
 * it does not turn an unsuccessful group result into success. Empty groups stay pending until cancelled. */
__extension__ typedef enum _SD_ENUM_TYPE_S64(sd_future_group_policy_t) {
        SD_FUTURE_GROUP_WAIT_ALL      = 0,
        SD_FUTURE_GROUP_WAIT_ANY      = 1 << 0,
        SD_FUTURE_GROUP_IGNORE_ERRORS = 1 << 1,
        _SD_FUTURE_GROUP_POLICY_MASK = SD_FUTURE_GROUP_WAIT_ANY | SD_FUTURE_GROUP_IGNORE_ERRORS,
        _SD_ENUM_FORCE_S64(SD_FUTURE_GROUP_POLICY)
} sd_future_group_policy_t;

/* The calling fiber becomes the parent only if it belongs to e. Unless IGNORE_ERRORS is set, a child
 * error cancels the parent if it is not awaiting the group with sd_fiber_await(). Explicit group
 * cancellation does not cancel the parent. */
int sd_future_group_new(sd_event *e, sd_future **ret);
int sd_future_group_set_policy(sd_future *f, uint64_t policy);
/* The group and all its children must belong to the same event loop. Adding a child takes a new
 * reference; it does not consume the caller's reference. To hand ownership to the group, release the
 * caller's reference with sd_future_unref(), not a cancellation cleanup helper. */
int sd_future_group_add(sd_future *f, sd_future *child);
int sd_future_group_add_many_internal(sd_future *f, ...) _sd_sentinel_;
#define sd_future_group_add_many(f, ...) sd_future_group_add_many_internal(f, __VA_ARGS__, NULL)
/* NULL is treated as an empty group. */
size_t sd_future_group_size(sd_future *f);

int sd_fiber_new(sd_event *e, const char *name, sd_fiber_func_t func, void *userdata, sd_fiber_destroy_t destroy, sd_future **ret);

int sd_fiber_set_floating(sd_future *f, int b);
int sd_fiber_get_floating(sd_future *f);

int sd_fiber_is_running(void);
sd_future* sd_fiber_get_current(void);
int sd_fiber_get_priority(int64_t *ret);
sd_event* sd_fiber_get_event(void);
/* The future a fiber is suspended in sd_fiber_await() or sd_future_cancel_wait_unref() for, if any.
 * The pointer is borrowed and only valid until the fiber runs again. */
sd_future* sd_fiber_get_awaiting(sd_future *f);

int sd_fiber_yield(void);
int sd_fiber_sleep(uint64_t usec);
/* Suspend until the target has resolved. Returns 0 once it has, and a negative error only if the wait
 * itself did not complete: the calling fiber was interrupted (-ECANCELED, -ETIME), woken for an
 * unrelated reason (-EBUSY), or the wait could not be set up. An interrupted wait does not imply that
 * the target has resolved. If the target resolved before the fiber saw the interruption, the wait
 * returns 0, and the next suspension point returns the interruption instead. The target's outcome is
 * available through sd_future_result() afterwards; the caller must hold its own reference to read it.
 * An already-resolved target returns 0 without consuming a pending interruption. The target must
 * belong to the calling fiber's event loop. */
int sd_fiber_await(sd_future *target);
/* sd_fiber_interrupted() returns a queued -ECANCELED or -ETIME and clears it, so that no later
 * suspension point returns it again. It returns 0 if no interruption is queued. Call it before starting
 * an operation that can complete without suspending. Otherwise a cancelled fiber never sees its
 * cancellation if none of its operations suspend. To report a cleared interruption later instead,
 * queue it again with sd_fiber_resume() on the current fiber. */
int sd_fiber_interrupted(void);
int sd_fiber_suspend(void);
int sd_fiber_resume(sd_future *f, int result);

sd_future* sd_fiber_timeout(uint64_t timeout);
/* sd_fiber_timeout_unref() ends the scope of a timer from sd_fiber_timeout(). It has to release every such
 * timer, in the reverse order of their creation. A queued -ETIME is dropped at the end of the scope, unless
 * the timer of an enclosing scope expired. */
sd_future* sd_fiber_timeout_unref(sd_future *timer);
_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_future, sd_fiber_timeout_unref);

#define SD_FIBER_TIMEOUT(timeout) _SD_FIBER_TIMEOUT(_SD_UNIQ, (timeout))
#define _SD_FIBER_TIMEOUT(uniq, timeout)                                                                                                        \
        sd_future *_SD_CONCATENATE(_sd_fto_, uniq) __attribute__((cleanup(sd_fiber_timeout_unrefp), unused)) = sd_fiber_timeout(timeout)

#define SD_FIBER_WITH_TIMEOUT(timeout) _SD_FIBER_WITH_TIMEOUT(_SD_UNIQ, (timeout))
#define _SD_FIBER_WITH_TIMEOUT(uniq, timeout)                                                                                                                   \
        for (sd_future *_SD_CONCATENATE(_sd_fto_, uniq) __attribute__((cleanup(sd_fiber_timeout_unrefp), unused)) = sd_fiber_timeout(timeout),                  \
                       *_SD_CONCATENATE(_sd_fto_b_, uniq) = (sd_future*) (uintptr_t) 1;                                                                         \
             _SD_CONCATENATE(_sd_fto_b_, uniq);                                                                                                                 \
             _SD_CONCATENATE(_sd_fto_b_, uniq) = NULL)

/* A channel buffers up to `capacity` items of type void*. An item must not be NULL. A receive waits on
 * its future while the channel is empty. The overflow policy controls the behavior of a send while the
 * channel is full:
 *
 *   SD_CHANNEL_OVERFLOW_WAIT: the send waits on its future until a receive frees a slot.
 *   SD_CHANNEL_OVERFLOW_DROP_OLDEST: the channel destroys its oldest item to make room, and the
 *                                    send succeeds immediately.
 *   SD_CHANNEL_OVERFLOW_DROP_LATEST: the channel destroys the item being sent, and the send
 *                                    succeeds immediately.
 *
 * sd_channel_try_push() only takes ownership of the item if it succeeds. sd_channel_send() and
 * sd_channel_push() always take ownership of the item, and the channel destroys the item if the send
 * fails. With SD_CHANNEL_OVERFLOW_DROP_LATEST, the channel can destroy the item even though the send
 * succeeds.
 *
 * The channel calls the destroy callback, if set, on every item that it owns and that nobody
 * received: items still buffered when the last reference is dropped, items of failed sends, items
 * that a receive future got but the caller never took with sd_channel_recv_get(), and items dropped by
 * the overflow policy. */

__extension__ typedef enum _SD_ENUM_TYPE_S64(sd_channel_overflow_t) {
        SD_CHANNEL_OVERFLOW_WAIT        = 0,
        SD_CHANNEL_OVERFLOW_DROP_OLDEST = 1,
        SD_CHANNEL_OVERFLOW_DROP_LATEST = 2,
        _SD_ENUM_FORCE_S64(SD_CHANNEL_OVERFLOW)
} sd_channel_overflow_t;

int sd_channel_new(sd_event *e, size_t capacity, sd_channel_overflow_t overflow, sd_channel_destroy_t destroy, sd_channel **ret);

/* sd_channel_new_conflated() creates a channel with capacity 1 and SD_CHANNEL_OVERFLOW_DROP_OLDEST.
 * A send never waits. The channel holds only the most recent item and destroys each item that a newer
 * one replaces. */
int sd_channel_new_conflated(sd_event *e, sd_channel_destroy_t destroy, sd_channel **ret);
int sd_channel_send(sd_channel *c, void *item, sd_future **ret);
int sd_channel_recv(sd_channel *c, sd_future **ret);
/* sd_channel_recv_get() returns the future's result if that is negative, and 1 with the received item
 * otherwise. As with sd_future_result(), the future has to be resolved. */
int sd_channel_recv_get(sd_future *f, void **ret);
int sd_channel_try_push(sd_channel *c, void *item);
int sd_channel_try_pop(sd_channel *c, void **ret);
int sd_channel_push(sd_channel *c, void *item);
int sd_channel_pop(sd_channel *c, void **ret);

int sd_channel_close(sd_channel *c);
int sd_channel_set_slot(sd_channel *c, void *slot, sd_channel_destroy_t destroy);

_SD_DECLARE_TRIVIAL_REF_UNREF_FUNC(sd_channel);
_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_channel, sd_channel_unref);

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
#ifndef __STRICT_ANSI__
int sd_fiber_ppoll(struct pollfd *fds, size_t n_fds, const struct timespec *timeout, const sigset_t *sigmask);
#endif

_SD_END_DECLARATIONS;

#endif
