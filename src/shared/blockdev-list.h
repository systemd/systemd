/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef enum BlockDevListFlags {
        BLOCKDEV_LIST_SHOW_SYMLINKS              = 1 << 0,  /* Pick up symlinks to block devices too */
        BLOCKDEV_LIST_REQUIRE_PARTITION_SCANNING = 1 << 1,  /* Only consider block devices with partition scanning */
        BLOCKDEV_LIST_IGNORE_VIRTUAL             = 1 << 2,  /* Ignore virtual devices (devices under /sys/devices/virtual/), except loopback devices */
        BLOCKDEV_LIST_IGNORE_LOOP                = 1 << 3,  /* Ignore loopback devices */
        BLOCKDEV_LIST_IGNORE_PARTITIONS          = 1 << 4,  /* Ignore partitions */
        BLOCKDEV_LIST_IGNORE_ZRAM                = 1 << 5,  /* Ignore ZRAM */
        BLOCKDEV_LIST_IGNORE_ROOT                = 1 << 6,  /* Ignore the block device we are currently booted from */
        BLOCKDEV_LIST_IGNORE_EMPTY               = 1 << 7,  /* Ignore disks of zero size (usually drives without a medium) */
        BLOCKDEV_LIST_IGNORE_READ_ONLY           = 1 << 8,  /* Ignore read-only block devices */
        BLOCKDEV_LIST_REQUIRE_LUKS               = 1 << 9,  /* Only consider block devices with LUKS superblocks */
        BLOCKDEV_LIST_METADATA                   = 1 << 10, /* Fill in model, vendor, subsystem, read_only */
        BLOCKDEV_LIST_DISKSEQ                    = 1 << 11, /* Fill in the diskseq field */
        BLOCKDEV_LIST_RW_STATS                   = 1 << 12, /* Fill in read and write measurements */
} BlockDevListFlags;

/* The "dynamic" filters – ones the kernel can flip at runtime via sysattrs on a live device.
 * Useful for callers that want to distinguish "device is hard-filtered (never interesting)" from
 * "device just transitioned in or out of the candidate set". */
#define BLOCKDEV_LIST_DYNAMIC_FILTERS_MASK \
        (BLOCKDEV_LIST_IGNORE_EMPTY | BLOCKDEV_LIST_IGNORE_READ_ONLY)

typedef struct BlockDevice {
        char *node;
        char **symlinks;
        char *model;
        char *vendor;
        char *subsystem;
        uint64_t diskseq;
        uint64_t size;     /* in bytes */
        uint64_t read_bytes;
        uint64_t write_bytes;
        int read_only;
} BlockDevice;

#define BLOCK_DEVICE_NULL (BlockDevice) {           \
                .diskseq = UINT64_MAX,              \
                .size = UINT64_MAX,                 \
                .read_bytes = UINT64_MAX,           \
                .write_bytes = UINT64_MAX,          \
                .read_only = -1,                    \
        }

/* Return values of blockdev_list_one(). Not its own type – returned as int. */
enum {
        BLOCKDEV_LIST_MATCH_NO,       /* Hard-filtered out by a static filter (subsystem, ZRAM,
                                       * IGNORE_ROOT, REQUIRE_PARTITION_SCANNING, REQUIRE_LUKS, …). */
        BLOCKDEV_LIST_MATCH_YES,      /* Passes all filters. */
        BLOCKDEV_LIST_MATCH_FILTERED, /* Passes the static filters; fails at least one dynamic filter
                                       * (IGNORE_EMPTY, IGNORE_READ_ONLY). */
        BLOCKDEV_LIST_MATCH_SKIPPED,  /* Filter evaluation hit an unexpected error (failed sysattr
                                       * read, missing devname, …). Callers should typically treat
                                       * this like _FILTERED (device not currently a candidate),
                                       * but distinguishing it makes the soft failure visible
                                       * rather than silently swallowed inside blockdev_list_one(). */
};

void block_device_done(BlockDevice *d);
void block_device_array_free(BlockDevice *d, size_t n_devices);

int blockdev_list_get_root_devnos(BlockDevListFlags flags, dev_t *ret_root, dev_t *ret_whole_root);
int blockdev_list_one(
                sd_device *dev,
                BlockDevListFlags flags,
                dev_t root_devno,
                dev_t whole_root_devno,
                BlockDevice *ret);

int blockdev_list_full(
                BlockDevListFlags flags,
                dev_t root_devno,
                dev_t whole_root_devno,
                BlockDevice **ret_devices,
                size_t *ret_n_devices);

static inline int blockdev_list(BlockDevListFlags flags, BlockDevice **ret_devices, size_t *ret_n_devices) {
        return blockdev_list_full(flags, 0, 0, ret_devices, ret_n_devices);
}
