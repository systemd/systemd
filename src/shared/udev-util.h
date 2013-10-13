/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2013 Zbigniew Jędrzejewski-Szmek

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

#include "udev.h"
#include "util.h"

define_trivial_cleanup_func(struct udev*, udev_unref)
define_trivial_cleanup_func(struct udev_device*, udev_device_unref)
define_trivial_cleanup_func(struct udev_enumerate*, udev_enumerate_unref)
define_trivial_cleanup_func(struct udev_event*, udev_event_unref)
define_trivial_cleanup_func(struct udev_rules*, udev_rules_unref)

#define _cleanup_udev_unref_ _cleanup_(udev_unrefp)
#define _cleanup_udev_device_unref_ _cleanup_(udev_device_unrefp)
#define _cleanup_udev_enumerate_unref_ _cleanup_(udev_enumerate_unrefp)
#define _cleanup_udev_event_unref_ _cleanup_(udev_event_unrefp)
#define _cleanup_udev_rules_unref_ _cleanup_(udev_rules_unrefp)
