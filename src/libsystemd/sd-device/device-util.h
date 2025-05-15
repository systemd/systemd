/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-device.h"

#include "forward.h"
#include "log.h"

#define device_unref_and_replace(a, b)                                  \
        unref_and_replace_full(a, b, sd_device_ref, sd_device_unref)

#define FOREACH_DEVICE_PROPERTY(device, key, value)                     \
        for (const char *value, *key = sd_device_get_property_first(device, &value); \
             key;                                                       \
             key = sd_device_get_property_next(device, &value))

#define FOREACH_DEVICE_TAG(device, tag)                                 \
        for (const char *tag = sd_device_get_tag_first(device);         \
             tag;                                                       \
             tag = sd_device_get_tag_next(device))

#define FOREACH_DEVICE_CURRENT_TAG(device, tag)                         \
        for (const char *tag = sd_device_get_current_tag_first(device); \
             tag;                                                       \
             tag = sd_device_get_current_tag_next(device))

#define FOREACH_DEVICE_SYSATTR(device, attr)                            \
        for (const char *attr = sd_device_get_sysattr_first(device);    \
             attr;                                                      \
             attr = sd_device_get_sysattr_next(device))

#define FOREACH_DEVICE_DEVLINK(device, devlink)                         \
        for (const char *devlink = sd_device_get_devlink_first(device); \
             devlink;                                                   \
             devlink = sd_device_get_devlink_next(device))

#define _FOREACH_DEVICE_CHILD(device, child, suffix_ptr)                \
        for (sd_device *child = sd_device_get_child_first(device, suffix_ptr); \
             child;                                                     \
             child = sd_device_get_child_next(device, suffix_ptr))

#define FOREACH_DEVICE_CHILD(device, child)                             \
        _FOREACH_DEVICE_CHILD(device, child, NULL)

#define FOREACH_DEVICE_CHILD_WITH_SUFFIX(device, child, suffix)         \
        _FOREACH_DEVICE_CHILD(device, child, &suffix)

#define FOREACH_DEVICE(enumerator, device)                              \
        for (sd_device *device = sd_device_enumerator_get_device_first(enumerator); \
             device;                                                    \
             device = sd_device_enumerator_get_device_next(enumerator))

#define FOREACH_SUBSYSTEM(enumerator, device)                           \
        for (sd_device *device = sd_device_enumerator_get_subsystem_first(enumerator); \
             device;                                                    \
             device = sd_device_enumerator_get_subsystem_next(enumerator))

#define log_device_full_errno_zerook(device, level, error, ...)         \
        ({                                                              \
                const char *_sysname = NULL;                            \
                sd_device *_d = (device);                               \
                int _level = (level), _e = (error);                     \
                                                                        \
                if (_d && _unlikely_(log_get_max_level() >= LOG_PRI(_level))) \
                        (void) sd_device_get_sysname(_d, &_sysname);    \
                log_object_internal(_level, _e, PROJECT_FILE, __LINE__, __func__, \
                                    _sysname ? "DEVICE=" : NULL, _sysname, \
                                    NULL, NULL, __VA_ARGS__);           \
        })

#define log_device_full_errno(device, level, error, ...)                \
        ({                                                              \
                int _error = (error);                                   \
                ASSERT_NON_ZERO(_error);                                \
                log_device_full_errno_zerook(device, level, _error, __VA_ARGS__); \
        })

#define log_device_full(device, level, ...) (void) log_device_full_errno_zerook(device, level, 0, __VA_ARGS__)

#define log_device_debug(device, ...)   log_device_full(device, LOG_DEBUG,   __VA_ARGS__)
#define log_device_info(device, ...)    log_device_full(device, LOG_INFO,    __VA_ARGS__)
#define log_device_notice(device, ...)  log_device_full(device, LOG_NOTICE,  __VA_ARGS__)
#define log_device_warning(device, ...) log_device_full(device, LOG_WARNING, __VA_ARGS__)
#define log_device_error(device, ...)   log_device_full(device, LOG_ERR,     __VA_ARGS__)

#define log_device_debug_errno(device, error, ...)   log_device_full_errno(device, LOG_DEBUG,   error, __VA_ARGS__)
#define log_device_info_errno(device, error, ...)    log_device_full_errno(device, LOG_INFO,    error, __VA_ARGS__)
#define log_device_notice_errno(device, error, ...)  log_device_full_errno(device, LOG_NOTICE,  error, __VA_ARGS__)
#define log_device_warning_errno(device, error, ...) log_device_full_errno(device, LOG_WARNING, error, __VA_ARGS__)
#define log_device_error_errno(device, error, ...)   log_device_full_errno(device, LOG_ERR,     error, __VA_ARGS__)

int devname_from_devnum(mode_t mode, dev_t devnum, char **ret);
int devname_from_stat_rdev(const struct stat *st, char **ret);
int device_open_from_devnum(mode_t mode, dev_t devnum, int flags, char **ret_devname);

char** device_make_log_fields(sd_device *device);

int device_in_subsystem_strv(sd_device *device, char * const *subsystems);
#define device_in_subsystem(device, ...) \
        device_in_subsystem_strv(device, STRV_MAKE(__VA_ARGS__))

int device_is_devtype(sd_device *device, const char *devtype);

int device_is_subsystem_devtype(sd_device *device, const char *subsystem, const char *devtype);

int device_get_seat(sd_device *device, const char **ret);

int device_sysname_startswith_strv(sd_device *device, char * const *prefixes, const char **ret_suffix);
#define device_sysname_startswith(device, ...) \
        device_sysname_startswith_strv(device, STRV_MAKE(__VA_ARGS__), NULL)

bool device_property_can_set(const char *property) _pure_;
