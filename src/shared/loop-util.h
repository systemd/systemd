/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <fcntl.h>

#include "sd-device.h"

#include "macro.h"
#include "time-util.h"

typedef struct LoopDevice LoopDevice;

/* Some helpers for setting up loopback block devices */

struct LoopDevice {
        unsigned n_ref;
        int fd;
        int lock_fd;
        int nr;         /* The loopback device index (i.e. 4 for /dev/loop4); if this object encapsulates a non-loopback block device, set to -1 */
        dev_t devno;    /* The loopback device's own dev_t */
        char *node;
        sd_device *dev;
        char *backing_file;
        bool relinquished;
        bool created;        /* If we created the device */
        dev_t backing_devno; /* The backing file's dev_t */
        ino_t backing_inode; /* The backing file's ino_t */
        uint64_t diskseq; /* Block device sequence number, monothonically incremented by the kernel on create/attach, or 0 if we don't know */
        uint64_t uevent_seqnum_not_before; /* uevent sequm right before we attached the loopback device, or UINT64_MAX if we don't know */
        usec_t timestamp_not_before; /* CLOCK_MONOTONIC timestamp taken immediately before attaching the loopback device, or USEC_INFINITY if we don't know */
        uint32_t sector_size;
        uint64_t device_size;
};

/* Returns true if LoopDevice object is not actually a loopback device but some other block device we just wrap */
#define LOOP_DEVICE_IS_FOREIGN(d) ((d)->nr < 0)

int loop_device_make(int fd, int open_flags, uint64_t offset, uint64_t size, uint32_t sector_size, uint32_t loop_flags, int lock_op, LoopDevice **ret);
int loop_device_make_by_path_at(int dir_fd, const char *path, int open_flags, uint32_t sector_size, uint32_t loop_flags, int lock_op, LoopDevice **ret);
static inline int loop_device_make_by_path(const char *path, int open_flags, uint32_t sector_size, uint32_t loop_flags, int lock_op, LoopDevice **ret) {
        return loop_device_make_by_path_at(AT_FDCWD, path, open_flags, sector_size, loop_flags, lock_op, ret);
}
int loop_device_make_by_path_memory(const char *path, int open_flags, uint32_t sector_size, uint32_t loop_flags, int lock_op, LoopDevice **ret);
int loop_device_open(sd_device *dev, int open_flags, int lock_op, LoopDevice **ret);
int loop_device_open_from_fd(int fd, int open_flags, int lock_op, LoopDevice **ret);
int loop_device_open_from_path(const char *path, int open_flags, int lock_op, LoopDevice **ret);

LoopDevice* loop_device_ref(LoopDevice *d);
LoopDevice* loop_device_unref(LoopDevice *d);
DEFINE_TRIVIAL_CLEANUP_FUNC(LoopDevice*, loop_device_unref);

void loop_device_relinquish(LoopDevice *d);
void loop_device_unrelinquish(LoopDevice *d);

int loop_device_refresh_size(LoopDevice *d, uint64_t offset, uint64_t size);

int loop_device_flock(LoopDevice *d, int operation);
int loop_device_sync(LoopDevice *d);

int loop_device_set_autoclear(LoopDevice *d, bool autoclear);
int loop_device_set_filename(LoopDevice *d, const char *name);
