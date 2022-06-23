/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "sd-device.h"

typedef enum MatchInitializedType {
        MATCH_INITIALIZED_NO,     /* only devices without a db entry */
        MATCH_INITIALIZED_YES,    /* only devices with a db entry */
        MATCH_INITIALIZED_ALL,    /* all devices */
        MATCH_INITIALIZED_COMPAT, /* only devices that have no devnode/ifindex or have a db entry */
        _MATCH_INITIALIZED_MAX,
        _MATCH_INITIALIZED_INVALID = -EINVAL,
} MatchInitializedType;

int device_enumerator_scan_devices(sd_device_enumerator *enumerator);
int device_enumerator_scan_subsystems(sd_device_enumerator *enumerator);
int device_enumerator_scan_devices_and_subsystems(sd_device_enumerator *enumerator);
int device_enumerator_add_device(sd_device_enumerator *enumerator, sd_device *device);
int device_enumerator_add_parent_devices(sd_device_enumerator *enumerator, sd_device *device);
int device_enumerator_add_match_is_initialized(sd_device_enumerator *enumerator, MatchInitializedType type);
int device_enumerator_add_match_parent_incremental(sd_device_enumerator *enumerator, sd_device *parent);
int device_enumerator_add_prioritized_subsystem(sd_device_enumerator *enumerator, const char *subsystem);
sd_device *device_enumerator_get_first(sd_device_enumerator *enumerator);
sd_device *device_enumerator_get_next(sd_device_enumerator *enumerator);
sd_device **device_enumerator_get_devices(sd_device_enumerator *enumerator, size_t *ret_n_devices);

#define FOREACH_DEVICE_AND_SUBSYSTEM(enumerator, device)       \
        for (device = device_enumerator_get_first(enumerator); \
             device;                                           \
             device = device_enumerator_get_next(enumerator))
