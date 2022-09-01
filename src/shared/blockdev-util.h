/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

#include "macro.h"
#include "stdio-util.h"
#include "string-util.h"

#define SYS_BLOCK_PATH_MAX(suffix)                                      \
        (STRLEN("/sys/dev/block/") + DECIMAL_STR_MAX(dev_t) + 1 + DECIMAL_STR_MAX(dev_t) + strlen_ptr(suffix))
#define xsprintf_sys_block_path(buf, suffix, devno)                     \
        xsprintf(buf, "/sys/dev/block/%u:%u%s", major(devno), minor(devno), strempty(suffix))

int block_get_whole_disk(dev_t d, dev_t *ret);
int block_get_originating(dev_t d, dev_t *ret);

int get_block_device_fd(int fd, dev_t *ret);
int get_block_device(const char *path, dev_t *dev);

int get_block_device_harder_fd(int fd, dev_t *dev);
int get_block_device_harder(const char *path, dev_t *dev);

int lock_whole_block_device(dev_t devt, int operation);

int blockdev_partscan_enabled(int fd);

int fd_is_encrypted(int fd);
int path_is_encrypted(const char *path);

int fd_get_whole_disk(int fd, bool backing, dev_t *ret);
int path_get_whole_disk(const char *path, bool backing, dev_t *ret);

int block_device_add_partition(int fd, const char *name, int nr, uint64_t start, uint64_t size);
int block_device_remove_partition(int fd, const char *name, int nr);
int block_device_resize_partition(int fd, int nr, uint64_t start, uint64_t size);
int block_device_remove_all_partitions(int fd);
