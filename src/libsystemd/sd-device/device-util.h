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
