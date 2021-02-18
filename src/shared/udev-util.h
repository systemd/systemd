/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-device.h"

#include "time-util.h"

#define UDEV_NAME_SIZE   512
#define UDEV_PATH_SIZE  1024
#define UDEV_LINE_SIZE 16384

typedef enum ResolveNameTiming {
        RESOLVE_NAME_NEVER,
        RESOLVE_NAME_LATE,
        RESOLVE_NAME_EARLY,
        _RESOLVE_NAME_TIMING_MAX,
        _RESOLVE_NAME_TIMING_INVALID = -EINVAL,
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

bool device_for_action(sd_device *dev, sd_device_action_t action);

void log_device_uevent(sd_device *device, const char *str);

int udev_rule_parse_value(char *str, char **ret_value, char **ret_endpos);
size_t udev_replace_whitespace(const char *str, char *to, size_t len);
size_t udev_replace_chars(char *str, const char *allow);
int udev_resolve_subsys_kernel(const char *string, char *result, size_t maxsize, bool read_value);

int udev_queue_is_empty(void);
int udev_queue_init(void);
