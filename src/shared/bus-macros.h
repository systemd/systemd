/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

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

#include "sd-bus.h"

DEFINE_TRIVIAL_CLEANUP_FUNC(sd_bus*, sd_bus_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(sd_bus*, sd_bus_flush_close_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(sd_bus_slot*, sd_bus_slot_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(sd_bus_message*, sd_bus_message_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(sd_bus_creds*, sd_bus_creds_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(sd_bus_track*, sd_bus_track_unref);

#define _cleanup_bus_unref_ _cleanup_(sd_bus_unrefp)
#define _cleanup_bus_flush_close_unref_ _cleanup_(sd_bus_flush_close_unrefp)
#define _cleanup_bus_slot_unref_ _cleanup_(sd_bus_slot_unrefp)
#define _cleanup_bus_message_unref_ _cleanup_(sd_bus_message_unrefp)
#define _cleanup_bus_creds_unref_ _cleanup_(sd_bus_creds_unrefp)
#define _cleanup_bus_track_unref_ _cleanup_(sd_bus_slot_unrefp)
#define _cleanup_bus_error_free_ _cleanup_(sd_bus_error_free)
