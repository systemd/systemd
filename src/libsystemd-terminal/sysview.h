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

/*
 * System View
 * The sysview interface scans and monitors the system for seats, sessions and
 * devices. It basically mirrors the state of logind on the application side.
 * It's meant as base for session services that require managed device access.
 * The logind controller API is employed to allow unprivileged access to all
 * devices of a user.
 * Furthermore, the sysview interface can be used for system services that run
 * in situations where logind is not available, but session-like services are
 * needed. For instance, the initrd does not run logind but might require
 * graphics access. It cannot run session services, though. The sysview
 * interface pretends that a session is available and provides the same
 * interface as to normal session services.
 */

#pragma once

#include <stdbool.h>
#include "sd-bus.h"
#include "sd-event.h"

typedef struct sysview_event            sysview_event;
typedef struct sysview_device           sysview_device;
typedef struct sysview_session          sysview_session;
typedef struct sysview_seat             sysview_seat;
typedef struct sysview_context          sysview_context;

/*
 * Events
 */

enum {
        SYSVIEW_EVENT_SETTLE,

        SYSVIEW_EVENT_SEAT_ADD,
        SYSVIEW_EVENT_SEAT_REMOVE,

        SYSVIEW_EVENT_SESSION_FILTER,
        SYSVIEW_EVENT_SESSION_ADD,
        SYSVIEW_EVENT_SESSION_REMOVE,
        SYSVIEW_EVENT_SESSION_ATTACH,
        SYSVIEW_EVENT_SESSION_DETACH,
        SYSVIEW_EVENT_SESSION_REFRESH,
        SYSVIEW_EVENT_SESSION_CONTROL,
};

struct sysview_event {
        unsigned int type;

        union {
                struct {
                        sysview_seat *seat;
                } seat_add, seat_remove;

                struct {
                        const char *id;
                        const char *seatid;
                        const char *username;
                        unsigned int uid;
                } session_filter;

                struct {
                        sysview_session *session;
                } session_add, session_remove;

                struct {
                        sysview_session *session;
                        sysview_device *device;
                } session_attach, session_detach;

                struct {
                        sysview_session *session;
                        sysview_device *device;
                        struct udev_device *ud;
                } session_refresh;

                struct {
                        sysview_session *session;
                        int error;
                } session_control;
        };
};

typedef int (*sysview_event_fn) (sysview_context *c, void *userdata, sysview_event *e);

/*
 * Devices
 */

enum {
        SYSVIEW_DEVICE_EVDEV,
        SYSVIEW_DEVICE_DRM,
        SYSVIEW_DEVICE_CNT
};

const char *sysview_device_get_name(sysview_device *device);
unsigned int sysview_device_get_type(sysview_device *device);
struct udev_device *sysview_device_get_ud(sysview_device *device);

/*
 * Sessions
 */

void sysview_session_set_userdata(sysview_session *session, void *userdata);
void *sysview_session_get_userdata(sysview_session *session);

const char *sysview_session_get_name(sysview_session *session);
sysview_seat *sysview_session_get_seat(sysview_session *session);

int sysview_session_take_control(sysview_session *session);
void sysview_session_release_control(sysview_session *session);

/*
 * Seats
 */

const char *sysview_seat_get_name(sysview_seat *seat);
int sysview_seat_switch_to(sysview_seat *seat, uint32_t nr);

/*
 * Contexts
 */

enum {
        SYSVIEW_CONTEXT_SCAN_LOGIND             = (1 << 0),
        SYSVIEW_CONTEXT_SCAN_EVDEV              = (1 << 1),
        SYSVIEW_CONTEXT_SCAN_DRM                = (1 << 2),
};

int sysview_context_new(sysview_context **out,
                        unsigned int flags,
                        sd_event *event,
                        sd_bus *sysbus,
                        struct udev *ud);
sysview_context *sysview_context_free(sysview_context *c);

DEFINE_TRIVIAL_CLEANUP_FUNC(sysview_context*, sysview_context_free);

bool sysview_context_is_running(sysview_context *c);
int sysview_context_start(sysview_context *c, sysview_event_fn event_fn, void *userdata);
void sysview_context_stop(sysview_context *c);
