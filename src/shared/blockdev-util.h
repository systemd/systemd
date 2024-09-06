/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

#include "sd-device.h"

#include "macro.h"
#include "stdio-util.h"
#include "string-util.h"

#define SYS_BLOCK_PATH_MAX(suffix)                                      \
        (STRLEN("/sys/dev/block/") + DECIMAL_STR_MAX(dev_t) + 1 + DECIMAL_STR_MAX(dev_t) + strlen_ptr(suffix))
#define xsprintf_sys_block_path(buf, suffix, devno)                     \
        xsprintf(buf, "/sys/dev/block/%u:%u%s", major(devno), minor(devno), strempty(suffix))

typedef enum BlockDeviceLookupFlag {
        BLOCK_DEVICE_LOOKUP_WHOLE_DISK  = 1 << 0, /* whole block device, e.g. sda, nvme0n1, or loop0. */
        BLOCK_DEVICE_LOOKUP_BACKING     = 1 << 1, /* fd may be regular file or directory on file system, in
                                                   * which case backing block device is determined. */
        BLOCK_DEVICE_LOOKUP_ORIGINATING = 1 << 2, /* Try to find the underlying layer device for stacked
                                                   * block device, e.g. LUKS-style DM. */
} BlockDeviceLookupFlag;

int block_device_new_from_fd(int fd, BlockDeviceLookupFlag flag, sd_device **ret);
int block_device_new_from_path(const char *path, BlockDeviceLookupFlag flag, sd_device **ret);

int block_device_is_whole_disk(sd_device *dev);
int block_device_get_whole_disk(sd_device *dev, sd_device **ret);
int block_device_get_originating(sd_device *dev, sd_device **ret);

int block_get_whole_disk(dev_t d, dev_t *ret);
int block_get_originating(dev_t d, dev_t *ret);

int get_block_device_fd(int fd, dev_t *ret);
int get_block_device(const char *path, dev_t *dev);

int get_block_device_harder_fd(int fd, dev_t *dev);
int get_block_device_harder(const char *path, dev_t *dev);

int lock_whole_block_device(dev_t devt, int operation);

int blockdev_partscan_enabled(sd_device *d);
int blockdev_partscan_enabled_fd(int fd);

int fd_is_encrypted(int fd);
int path_is_encrypted(const char *path);

int fd_get_whole_disk(int fd, bool backing, dev_t *ret);
int path_get_whole_disk(const char *path, bool backing, dev_t *ret);

int block_device_add_partition(int fd, const char *name, int nr, uint64_t start, uint64_t size);
int block_device_remove_partition(int fd, const char *name, int nr);
int block_device_resize_partition(int fd, int nr, uint64_t start, uint64_t size);
int partition_enumerator_new(sd_device *dev, sd_device_enumerator **ret);
int block_device_remove_all_partitions(sd_device *dev, int fd);
int block_device_has_partitions(sd_device *dev);
int blockdev_reread_partition_table(sd_device *dev);

int blockdev_get_sector_size(int fd, uint32_t *ret);
int blockdev_get_device_size(int fd, uint64_t *ret);

int blockdev_get_root(int level, dev_t *ret);
