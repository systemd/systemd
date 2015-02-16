/***
  This file is part of systemd.

  Copyright 2008-2012 Kay Sievers <kay@vrfy.org>
  Copyright 2009 Alan Jenkins <alan-jenkins@tuffmail.co.uk>

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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/inotify.h>

#include "libudev.h"
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
        int refcount;
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
_public_ struct udev_queue *udev_queue_new(struct udev *udev)
{
        struct udev_queue *udev_queue;

        if (udev == NULL)
                return NULL;

        udev_queue = new0(struct udev_queue, 1);
        if (udev_queue == NULL)
                return NULL;

        udev_queue->refcount = 1;
        udev_queue->udev = udev;
        udev_queue->fd = -1;
        return udev_queue;
}

/**
 * udev_queue_ref:
 * @udev_queue: udev queue context
 *
 * Take a reference of a udev queue context.
 *
 * Returns: the same udev queue context.
 **/
_public_ struct udev_queue *udev_queue_ref(struct udev_queue *udev_queue)
{
        if (udev_queue == NULL)
                return NULL;

        udev_queue->refcount++;
        return udev_queue;
}

/**
 * udev_queue_unref:
 * @udev_queue: udev queue context
 *
 * Drop a reference of a udev queue context. If the refcount reaches zero,
 * the resources of the queue context will be released.
 *
 * Returns: #NULL
 **/
_public_ struct udev_queue *udev_queue_unref(struct udev_queue *udev_queue)
{
        if (udev_queue == NULL)
                return NULL;

        udev_queue->refcount--;
        if (udev_queue->refcount > 0)
                return NULL;

        safe_close(udev_queue->fd);

        free(udev_queue);
        return NULL;
}

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
        if (udev_queue == NULL)
                return NULL;
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
        if (udev_queue->fd < 0)
                return -EINVAL;

        return flush_fd(udev_queue->fd);
}
