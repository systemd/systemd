/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro.h"
#include "time-util.h"

typedef struct LoopDevice LoopDevice;

/* Some helpers for setting up loopback block devices */

struct LoopDevice {
        int fd;
        int nr;
        dev_t devno;
        char *node;
        bool relinquished;
        uint64_t diskseq; /* Block device sequence number, monothonically incremented by the kernel on create/attach, or 0 if we don't know */
        uint64_t uevent_seqnum_not_before; /* uevent sequm right before we attached the loopback device, or UINT64_MAX if we don't know */
        usec_t timestamp_not_before; /* CLOCK_MONOTONIC timestamp taken immediately before attaching the loopback device, or USEC_INFINITY if we don't know */
};

int loop_device_make(int fd, int open_flags, uint64_t offset, uint64_t size, uint32_t loop_flags, LoopDevice **ret);
int loop_device_make_by_path(const char *path, int open_flags, uint32_t loop_flags, LoopDevice **ret);
int loop_device_open(const char *loop_path, int open_flags, LoopDevice **ret);

LoopDevice* loop_device_unref(LoopDevice *d);
DEFINE_TRIVIAL_CLEANUP_FUNC(LoopDevice*, loop_device_unref);

void loop_device_relinquish(LoopDevice *d);

int loop_device_refresh_size(LoopDevice *d, uint64_t offset, uint64_t size);

int loop_device_flock(LoopDevice *d, int operation);
int loop_device_sync(LoopDevice *d);
