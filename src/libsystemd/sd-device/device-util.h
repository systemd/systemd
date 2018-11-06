/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#define FOREACH_DEVICE_PROPERTY(device, key, value)                \
        for (key = sd_device_get_property_first(device, &(value)); \
             key;                                                  \
             key = sd_device_get_property_next(device, &(value)))

#define FOREACH_DEVICE_TAG(device, tag)             \
        for (tag = sd_device_get_tag_first(device); \
             tag;                                   \
             tag = sd_device_get_tag_next(device))

#define FOREACH_DEVICE_SYSATTR(device, attr)             \
        for (attr = sd_device_get_sysattr_first(device); \
             attr;                                       \
             attr = sd_device_get_sysattr_next(device))

#define FOREACH_DEVICE_DEVLINK(device, devlink)             \
        for (devlink = sd_device_get_devlink_first(device); \
             devlink;                                   \
             devlink = sd_device_get_devlink_next(device))

#define FOREACH_DEVICE(enumerator, device)                               \
        for (device = sd_device_enumerator_get_device_first(enumerator); \
             device;                                                     \
             device = sd_device_enumerator_get_device_next(enumerator))

#define FOREACH_SUBSYSTEM(enumerator, device)                               \
        for (device = sd_device_enumerator_get_subsystem_first(enumerator); \
             device;                                                        \
             device = sd_device_enumerator_get_subsystem_next(enumerator))

#define log_device_full(device, level, error, ...)                      \
        ({                                                              \
                const char *_sysname = NULL;                            \
                sd_device *_d = (device);                               \
                int _level = (level), _error = (error);                 \
                                                                        \
                if (_d && _unlikely_(log_get_max_level() >= _level))    \
                        (void) sd_device_get_sysname(_d, &_sysname);    \
                log_object_internal(_level, _error, __FILE__, __LINE__, __func__, \
                                    _sysname ? "DEVICE=" : NULL, _sysname, \
                                    NULL, NULL, ##__VA_ARGS__);         \
        })

#define log_device_debug(device, ...)   log_device_full(device, LOG_DEBUG, 0, ##__VA_ARGS__)
#define log_device_info(device, ...)    log_device_full(device, LOG_INFO, 0, ##__VA_ARGS__)
#define log_device_notice(device, ...)  log_device_full(device, LOG_NOTICE, 0, ##__VA_ARGS__)
#define log_device_warning(device, ...) log_device_full(device, LOG_WARNING, 0, ##__VA_ARGS__)
#define log_device_error(device, ...)   log_device_full(device, LOG_ERR, 0, ##__VA_ARGS__)

#define log_device_debug_errno(device, error, ...)   log_device_full(device, LOG_DEBUG, error, ##__VA_ARGS__)
#define log_device_info_errno(device, error, ...)    log_device_full(device, LOG_INFO, error, ##__VA_ARGS__)
#define log_device_notice_errno(device, error, ...)  log_device_full(device, LOG_NOTICE, error, ##__VA_ARGS__)
#define log_device_warning_errno(device, error, ...) log_device_full(device, LOG_WARNING, error, ##__VA_ARGS__)
#define log_device_error_errno(device, error, ...)   log_device_full(device, LOG_ERR, error, ##__VA_ARGS__)
