/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-device.h"

#include "device-private.h"
#include "time-util.h"

typedef enum ResolveNameTiming {
        RESOLVE_NAME_NEVER,
        RESOLVE_NAME_LATE,
        RESOLVE_NAME_EARLY,
        _RESOLVE_NAME_TIMING_MAX,
        _RESOLVE_NAME_TIMING_INVALID = -1,
} ResolveNameTiming;

ResolveNameTiming resolve_name_timing_from_string(const char *s) _pure_;
const char *resolve_name_timing_to_string(ResolveNameTiming i) _const_;

int udev_parse_config_full(
                unsigned *ret_children_max,
                usec_t *ret_exec_delay_usec,
                usec_t *ret_event_timeout_usec,
                ResolveNameTiming *ret_resolve_name_timing,
                int *ret_timeout_signal);

static inline int udev_parse_config(void) {
        return udev_parse_config_full(NULL, NULL, NULL, NULL, NULL);
}

int device_wait_for_initialization(sd_device *device, const char *subsystem, usec_t deadline, sd_device **ret);
int device_wait_for_devlink(const char *path, const char *subsystem, usec_t deadline, sd_device **ret);
int device_is_renaming(sd_device *dev);
bool device_for_action(sd_device *dev, DeviceAction action);

int udev_rule_parse_value(char *str, char **ret_value, char **ret_endpos);
