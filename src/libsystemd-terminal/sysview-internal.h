/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright (C) 2014 David Herrmann <dh.herrmann@gmail.com>

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

#pragma once

#include <inttypes.h>
#include <libudev.h>
#include <stdbool.h>
#include <stdlib.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>
#include "hashmap.h"
#include "list.h"
#include "macro.h"
#include "sysview.h"
#include "util.h"

/*
 * Devices
 */

struct sysview_device {
        sysview_seat *seat;
        char *name;
        unsigned int type;

        union {
                struct {
                        struct udev_device *ud;
                } evdev, drm;
        };
};

sysview_device *sysview_find_device(sysview_context *c, const char *name);

int sysview_device_new(sysview_device **out, sysview_seat *seat, const char *name);
sysview_device *sysview_device_free(sysview_device *device);

DEFINE_TRIVIAL_CLEANUP_FUNC(sysview_device*, sysview_device_free);

/*
 * Sessions
 */

struct sysview_session {
        sysview_seat *seat;
        char *name;
        char *path;
        void *userdata;

        sd_bus_slot *slot_take_control;

        bool custom : 1;
        bool public : 1;
        bool wants_control : 1;
        bool has_control : 1;
};

sysview_session *sysview_find_session(sysview_context *c, const char *name);

int sysview_session_new(sysview_session **out, sysview_seat *seat, const char *name);
sysview_session *sysview_session_free(sysview_session *session);

DEFINE_TRIVIAL_CLEANUP_FUNC(sysview_session*, sysview_session_free);

/*
 * Seats
 */

struct sysview_seat {
        sysview_context *context;
        char *name;
        char *path;

        Hashmap *session_map;
        Hashmap *device_map;

        bool scanned : 1;
        bool public : 1;
};

sysview_seat *sysview_find_seat(sysview_context *c, const char *name);

int sysview_seat_new(sysview_seat **out, sysview_context *c, const char *name);
sysview_seat *sysview_seat_free(sysview_seat *seat);

DEFINE_TRIVIAL_CLEANUP_FUNC(sysview_seat*, sysview_seat_free);

/*
 * Contexts
 */

struct sysview_context {
        sd_event *event;
        sd_bus *sysbus;
        struct udev *ud;
        uint64_t custom_sid;
        unsigned int n_probe;

        Hashmap *seat_map;
        Hashmap *session_map;
        Hashmap *device_map;

        sd_event_source *scan_src;
        sysview_event_fn event_fn;
        void *userdata;

        /* udev scanner */
        struct udev_monitor *ud_monitor;
        sd_event_source *ud_monitor_src;

        /* logind scanner */
        sd_bus_slot *ld_slot_manager_signal;
        sd_bus_slot *ld_slot_list_seats;
        sd_bus_slot *ld_slot_list_sessions;

        bool scan_logind : 1;
        bool scan_evdev : 1;
        bool scan_drm : 1;
        bool running : 1;
        bool scanned : 1;
        bool rescan : 1;
        bool settled : 1;
};

int sysview_context_rescan(sysview_context *c);
