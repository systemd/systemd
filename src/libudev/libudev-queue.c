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
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>

#include "libudev.h"
#include "libudev-private.h"

/**
 * SECTION:libudev-queue
 * @short_description: access to currently active events
 *
 * The udev daemon processes events asynchronously. All events which do not have
 * interdependencies run in parallel. This exports the current state of the
 * event processing queue, and the current event sequence numbers from the kernel
 * and the udev daemon.
 */

/**
 * udev_queue:
 *
 * Opaque object representing the current event queue in the udev daemon.
 */
struct udev_queue {
        struct udev *udev;
        int refcount;
        struct udev_list queue_list;
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
        udev_list_init(udev, &udev_queue->queue_list, false);
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
        udev_list_cleanup(&udev_queue->queue_list);
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

unsigned long long int udev_get_kernel_seqnum(struct udev *udev)
{
        unsigned long long int seqnum;
        int fd;
        char buf[32];
        ssize_t len;

        fd = open("/sys/kernel/uevent_seqnum", O_RDONLY|O_CLOEXEC);
        if (fd < 0)
                return 0;
        len = read(fd, buf, sizeof(buf));
        close(fd);
        if (len <= 2)
                return 0;
        buf[len-1] = '\0';
        seqnum = strtoull(buf, NULL, 10);
        return seqnum;
}

/**
 * udev_queue_get_kernel_seqnum:
 * @udev_queue: udev queue context
 *
 * Get the current kernel event sequence number.
 *
 * Returns: the sequence number.
 **/
_public_ unsigned long long int udev_queue_get_kernel_seqnum(struct udev_queue *udev_queue)
{
        unsigned long long int seqnum;

        if (udev_queue == NULL)
                return -EINVAL;

        seqnum = udev_get_kernel_seqnum(udev_queue->udev);
        return seqnum;
}

int udev_queue_read_seqnum(FILE *queue_file, unsigned long long int *seqnum)
{
        if (fread(seqnum, sizeof(unsigned long long int), 1, queue_file) != 1)
                return -1;

        return 0;
}

ssize_t udev_queue_skip_devpath(FILE *queue_file)
{
        unsigned short int len;

        if (fread(&len, sizeof(unsigned short int), 1, queue_file) == 1) {
                char *devpath = alloca(len);

                /* use fread to skip, fseek might drop buffered data */
                if (fread(devpath, 1, len, queue_file) == len)
                        return len;
        }

        return -1;
}

ssize_t udev_queue_read_devpath(FILE *queue_file, char *devpath, size_t size)
{
        unsigned short int read_bytes = 0;
        unsigned short int len;

        if (fread(&len, sizeof(unsigned short int), 1, queue_file) != 1)
                return -1;

        read_bytes = (len < size - 1) ? len : size - 1;
        if (fread(devpath, 1, read_bytes, queue_file) != read_bytes)
                return -1;
        devpath[read_bytes] = '\0';

        /* if devpath was too long, skip unread characters */
        if (read_bytes != len) {
                unsigned short int skip_bytes = len - read_bytes;
                char *buf = alloca(skip_bytes);

                if (fread(buf, 1, skip_bytes, queue_file) != skip_bytes)
                        return -1;
        }

        return read_bytes;
}

static FILE *open_queue_file(struct udev_queue *udev_queue, unsigned long long int *seqnum_start)
{
        FILE *queue_file;

        queue_file = fopen("/run/udev/queue.bin", "re");
        if (queue_file == NULL)
                return NULL;

        if (udev_queue_read_seqnum(queue_file, seqnum_start) < 0) {
                udev_err(udev_queue->udev, "corrupt queue file\n");
                fclose(queue_file);
                return NULL;
        }

        return queue_file;
}

/**
 * udev_queue_get_udev_seqnum:
 * @udev_queue: udev queue context
 *
 * Get the last known udev event sequence number.
 *
 * Returns: the sequence number.
 **/
_public_ unsigned long long int udev_queue_get_udev_seqnum(struct udev_queue *udev_queue)
{
        unsigned long long int seqnum_udev;
        FILE *queue_file;

        queue_file = open_queue_file(udev_queue, &seqnum_udev);
        if (queue_file == NULL)
                return 0;

        for (;;) {
                unsigned long long int seqnum;
                ssize_t devpath_len;

                if (udev_queue_read_seqnum(queue_file, &seqnum) < 0)
                        break;
                devpath_len = udev_queue_skip_devpath(queue_file);
                if (devpath_len < 0)
                        break;
                if (devpath_len > 0)
                        seqnum_udev = seqnum;
        }

        fclose(queue_file);
        return seqnum_udev;
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
        unsigned long long int seqnum_start;
        FILE *queue_file;

        queue_file = open_queue_file(udev_queue, &seqnum_start);
        if (queue_file == NULL)
                return 0;

        fclose(queue_file);
        return 1;
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
        unsigned long long int seqnum_kernel;
        unsigned long long int seqnum_udev = 0;
        int queued = 0;
        int is_empty = 0;
        FILE *queue_file;

        if (udev_queue == NULL)
                return -EINVAL;
        queue_file = open_queue_file(udev_queue, &seqnum_udev);
        if (queue_file == NULL)
                return 1;

        for (;;) {
                unsigned long long int seqnum;
                ssize_t devpath_len;

                if (udev_queue_read_seqnum(queue_file, &seqnum) < 0)
                        break;
                devpath_len = udev_queue_skip_devpath(queue_file);
                if (devpath_len < 0)
                        break;

                if (devpath_len > 0) {
                        queued++;
                        seqnum_udev = seqnum;
                } else {
                        queued--;
                }
        }

        if (queued > 0)
                goto out;

        seqnum_kernel = udev_queue_get_kernel_seqnum(udev_queue);
        if (seqnum_udev < seqnum_kernel)
                goto out;

        is_empty = 1;

out:
        fclose(queue_file);
        return is_empty;
}

/**
 * udev_queue_get_seqnum_sequence_is_finished:
 * @udev_queue: udev queue context
 * @start: first event sequence number
 * @end: last event sequence number
 *
 * Check if udev is currently processing any events in a given sequence number range.
 *
 * Returns: a flag indicating if any of the sequence numbers in the given range is currently active.
 **/
_public_ int udev_queue_get_seqnum_sequence_is_finished(struct udev_queue *udev_queue,
                                               unsigned long long int start, unsigned long long int end)
{
        unsigned long long int seqnum;
        ssize_t devpath_len;
        int unfinished;
        FILE *queue_file;

        if (udev_queue == NULL)
                return -EINVAL;
        queue_file = open_queue_file(udev_queue, &seqnum);
        if (queue_file == NULL)
                return 1;
        if (start < seqnum)
                start = seqnum;
        if (start > end) {
                fclose(queue_file);
                return 1;
        }
        if (end - start > INT_MAX - 1) {
                fclose(queue_file);
                return -EOVERFLOW;
        }

        /*
         * we might start with 0, and handle the initial seqnum
         * only when we find an entry in the queue file
         **/
        unfinished = end - start;

        do {
                if (udev_queue_read_seqnum(queue_file, &seqnum) < 0)
                        break;
                devpath_len = udev_queue_skip_devpath(queue_file);
                if (devpath_len < 0)
                        break;

                /*
                 * we might start with an empty or re-build queue file, where
                 * the initial seqnum is not recorded as finished
                 */
                if (start == seqnum && devpath_len > 0)
                        unfinished++;

                if (devpath_len == 0) {
                        if (seqnum >= start && seqnum <= end)
                                unfinished--;
                }
        } while (unfinished > 0);

        fclose(queue_file);

        return (unfinished == 0);
}

/**
 * udev_queue_get_seqnum_is_finished:
 * @udev_queue: udev queue context
 * @seqnum: sequence number
 *
 * Check if udev is currently processing a given sequence number.
 *
 * Returns: a flag indicating if the given sequence number is currently active.
 **/
_public_ int udev_queue_get_seqnum_is_finished(struct udev_queue *udev_queue, unsigned long long int seqnum)
{
        if (!udev_queue_get_seqnum_sequence_is_finished(udev_queue, seqnum, seqnum))
                return 0;

        return 1;
}

/**
 * udev_queue_get_queued_list_entry:
 * @udev_queue: udev queue context
 *
 * Get the first entry of the list of queued events.
 *
 * Returns: a udev_list_entry.
 **/
_public_ struct udev_list_entry *udev_queue_get_queued_list_entry(struct udev_queue *udev_queue)
{
        unsigned long long int seqnum;
        FILE *queue_file;

        if (udev_queue == NULL)
                return NULL;
        udev_list_cleanup(&udev_queue->queue_list);

        queue_file = open_queue_file(udev_queue, &seqnum);
        if (queue_file == NULL)
                return NULL;

        for (;;) {
                char syspath[UTIL_PATH_SIZE];
                char *s;
                size_t l;
                ssize_t len;
                char seqnum_str[32];
                struct udev_list_entry *list_entry;

                if (udev_queue_read_seqnum(queue_file, &seqnum) < 0)
                        break;
                snprintf(seqnum_str, sizeof(seqnum_str), "%llu", seqnum);

                s = syspath;
                l = strpcpy(&s, sizeof(syspath), "/sys");
                len = udev_queue_read_devpath(queue_file, s, l);
                if (len < 0)
                        break;

                if (len > 0) {
                        udev_list_entry_add(&udev_queue->queue_list, syspath, seqnum_str);
                } else {
                        udev_list_entry_foreach(list_entry, udev_list_get_entry(&udev_queue->queue_list)) {
                                if (streq(seqnum_str, udev_list_entry_get_value(list_entry))) {
                                        udev_list_entry_delete(list_entry);
                                        break;
                                }
                        }
                }
        }
        fclose(queue_file);

        return udev_list_get_entry(&udev_queue->queue_list);
}
