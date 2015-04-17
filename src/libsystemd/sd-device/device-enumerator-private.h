/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2015 Tom Gundersen <teg@jklm.no>

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

#include "sd-device.h"

int device_enumerator_scan_devices(sd_device_enumerator *enumeartor);
int device_enumerator_scan_subsystems(sd_device_enumerator *enumeartor);
int device_enumerator_add_device(sd_device_enumerator *enumerator, sd_device *device);
int device_enumerator_add_match_is_initialized(sd_device_enumerator *enumerator);
sd_device *device_enumerator_get_first(sd_device_enumerator *enumerator);
sd_device *device_enumerator_get_next(sd_device_enumerator *enumerator);

#define FOREACH_DEVICE_AND_SUBSYSTEM(enumerator, device)       \
        for (device = device_enumerator_get_first(enumerator); \
             device;                                           \
             device = device_enumerator_get_next(enumerator))
