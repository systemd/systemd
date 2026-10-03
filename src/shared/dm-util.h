/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/dm-ioctl.h>

#include "forward.h"

typedef struct DmDeviceInfo {
        char name[DM_NAME_LEN];
        char uuid[DM_UUID_LEN];
        dev_t devnum;
        uint32_t flags;
        uint32_t target_count;
} DmDeviceInfo;

typedef struct DmTargetInfo {
        uint64_t start;
        uint64_t length;
        char type[DM_MAX_TYPE_NAME];
        char *parameters;
} DmTargetInfo;

void dm_target_info_done(DmTargetInfo *info);

int dm_device_info(dev_t devnum, DmDeviceInfo *ret);
int dm_device_info_from_path(const char *path, DmDeviceInfo *ret);
int dm_device_query_target(const char *name, bool table, DmTargetInfo *ret);
int dm_create_device(
                const char *name,
                const char *uuid,
                uint64_t start,
                uint64_t length,
                const char *target,
                const char *parameters);
int dm_target_message(const char *name, uint64_t sector, const char *message);
int dm_suspend_device(const char *name, bool suspend);

int dm_deferred_remove_cancel(const char *name);

int dm_create_linear(
                const char *name,
                const char *uuid,
                dev_t devnum,
                uint64_t offset,
                uint64_t size);
int dm_remove_device(const char *name);
