/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  Copyright © 2009 Alan Jenkins <alan-jenkins@tuffmail.co.uk>
***/

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "io-util.h"
#include "libudev-private.h"

/**
 * SECTION:libudev-queue
 * @short_description: access to currently active events
 *
 * This exports the current state of the udev processing queue.
 */

/**
 * udev_queue:
 *
 * Opaque object representing the current event queue in the udev daemon.
 */
struct udev_queue {
        struct udev *udev;
        unsigned n_ref;
        int fd;
};

/**
 * udev_queue_new:
 * @udev: udev library context
 *
 * The initial refcount is 1, and needs to be decremented to
 * release the resources of the udev queue context.
 *
 * Returns: the udev queue context, or #NULL on error.
 **/
_public_ struct udev_queue *udev_queue_new(struct udev *udev) {
        struct udev_queue *udev_queue;

        udev_queue = new(struct udev_queue, 1);
        if (udev_queue == NULL) {
                errno = ENOMEM;
                return NULL;
        }

        *udev_queue = (struct udev_queue) {
                .udev = udev,
                .n_ref = 1,
                .fd = -1,
        };

        return udev_queue;
}

static struct udev_queue *udev_queue_free(struct udev_queue *udev_queue) {
        assert(udev_queue);

        safe_close(udev_queue->fd);
        return mfree(udev_queue);
}

/**
 * udev_queue_ref:
 * @udev_queue: udev queue context
 *
 * Take a reference of a udev queue context.
 *
 * Returns: the same udev queue context.
 **/

/**
 * udev_queue_unref:
 * @udev_queue: udev queue context
 *
 * Drop a reference of a udev queue context. If the refcount reaches zero,
 * the resources of the queue context will be released.
 *
 * Returns: #NULL
 **/
DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(struct udev_queue, udev_queue, udev_queue_free);

/**
 * udev_queue_get_udev:
 * @udev_queue: udev queue context
 *
 * Retrieve the udev library context the queue context was created with.
 *
 * Returns: the udev library context.
 **/
_public_ struct udev *udev_queue_get_udev(struct udev_queue *udev_queue)
{
        if (udev_queue == NULL) {
                errno = EINVAL;
                return NULL;
        }
        return udev_queue->udev;
}

/**
 * udev_queue_get_kernel_seqnum:
 * @udev_queue: udev queue context
 *
 * This function is deprecated.
 *
 * Returns: 0.
 **/
_public_ unsigned long long int udev_queue_get_kernel_seqnum(struct udev_queue *udev_queue)
{
        return 0;
}

/**
 * udev_queue_get_udev_seqnum:
 * @udev_queue: udev queue context
 *
 * This function is deprecated.
 *
 * Returns: 0.
 **/
_public_ unsigned long long int udev_queue_get_udev_seqnum(struct udev_queue *udev_queue)
{
        return 0;
}

/**
 * udev_queue_get_udev_is_active:
 * @udev_queue: udev queue context
 *
 * Check if udev is active on the system.
 *
 * Returns: a flag indicating if udev is active.
 **/
_public_ int udev_queue_get_udev_is_active(struct udev_queue *udev_queue)
{
        return access("/run/udev/control", F_OK) >= 0;
}

/**
 * udev_queue_get_queue_is_empty:
 * @udev_queue: udev queue context
 *
 * Check if udev is currently processing any events.
 *
 * Returns: a flag indicating if udev is currently handling events.
 **/
_public_ int udev_queue_get_queue_is_empty(struct udev_queue *udev_queue)
{
        return access("/run/udev/queue", F_OK) < 0;
}

/**
 * udev_queue_get_seqnum_sequence_is_finished:
 * @udev_queue: udev queue context
 * @start: first event sequence number
 * @end: last event sequence number
 *
 * This function is deprecated, it just returns the result of
 * udev_queue_get_queue_is_empty().
 *
 * Returns: a flag indicating if udev is currently handling events.
 **/
_public_ int udev_queue_get_seqnum_sequence_is_finished(struct udev_queue *udev_queue,
                                               unsigned long long int start, unsigned long long int end)
{
        return udev_queue_get_queue_is_empty(udev_queue);
}

/**
 * udev_queue_get_seqnum_is_finished:
 * @udev_queue: udev queue context
 * @seqnum: sequence number
 *
 * This function is deprecated, it just returns the result of
 * udev_queue_get_queue_is_empty().
 *
 * Returns: a flag indicating if udev is currently handling events.
 **/
_public_ int udev_queue_get_seqnum_is_finished(struct udev_queue *udev_queue, unsigned long long int seqnum)
{
        return udev_queue_get_queue_is_empty(udev_queue);
}

/**
 * udev_queue_get_queued_list_entry:
 * @udev_queue: udev queue context
 *
 * This function is deprecated.
 *
 * Returns: NULL.
 **/
_public_ struct udev_list_entry *udev_queue_get_queued_list_entry(struct udev_queue *udev_queue)
{
        errno = ENODATA;
        return NULL;
}

/**
 * udev_queue_get_fd:
 * @udev_queue: udev queue context
 *
 * Returns: a file descriptor to watch for a queue to become empty.
 */
_public_ int udev_queue_get_fd(struct udev_queue *udev_queue) {
        int fd;
        int r;

        if (udev_queue->fd >= 0)
                return udev_queue->fd;

        fd = inotify_init1(IN_CLOEXEC);
        if (fd < 0)
                return -errno;

        r = inotify_add_watch(fd, "/run/udev" , IN_DELETE);
        if (r < 0) {
                r = -errno;
                close(fd);
                return r;
        }

        udev_queue->fd = fd;
        return fd;
}

/**
 * udev_queue_flush:
 * @udev_queue: udev queue context
 *
 * Returns: the result of clearing the watch for queue changes.
 */
_public_ int udev_queue_flush(struct udev_queue *udev_queue) {
        int r;

        assert(udev_queue);

        if (udev_queue->fd < 0)
                return -EINVAL;

        r = flush_fd(udev_queue->fd);
        if (r < 0)
                return r;

        return 0;
}
