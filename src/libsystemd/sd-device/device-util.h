/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2014-2015 Tom Gundersen <teg@jklm.no>

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "util.h"

DEFINE_TRIVIAL_CLEANUP_FUNC(sd_device*, sd_device_unref);
#define _cleanup_device_unref_ _cleanup_(sd_device_unrefp)

DEFINE_TRIVIAL_CLEANUP_FUNC(sd_device_enumerator*, sd_device_enumerator_unref);
#define _cleanup_device_enumerator_unref_ _cleanup_(sd_device_enumerator_unrefp)

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
