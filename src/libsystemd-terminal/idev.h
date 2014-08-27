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
 * IDev
 */

#pragma once

#include <inttypes.h>
#include <libudev.h>
#include <linux/input.h>
#include <stdbool.h>
#include <stdlib.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>
#include "util.h"

typedef struct idev_data                idev_data;
typedef struct idev_data_evdev          idev_data_evdev;

typedef struct idev_event               idev_event;
typedef struct idev_device              idev_device;
typedef struct idev_session             idev_session;
typedef struct idev_context             idev_context;

/*
 * Types
 */

enum {
        IDEV_ELEMENT_EVDEV,
        IDEV_ELEMENT_CNT
};

enum {
        IDEV_DEVICE_CNT
};

/*
 * Evdev Elements
 */

struct idev_data_evdev {
        struct input_event event;
};

/*
 * Data Packets
 */

enum {
        IDEV_DATA_RESYNC,
        IDEV_DATA_EVDEV,
        IDEV_DATA_CNT
};

struct idev_data {
        unsigned int type;
        bool resync : 1;

        union {
                idev_data_evdev evdev;
        };
};

/*
 * Events
 */

enum {
        IDEV_EVENT_DEVICE_ADD,
        IDEV_EVENT_DEVICE_REMOVE,
        IDEV_EVENT_DEVICE_DATA,
        IDEV_EVENT_CNT
};

struct idev_event {
        unsigned int type;
        union {
                struct {
                        idev_device *device;
                } device_add, device_remove;

                struct {
                        idev_device *device;
                        idev_data data;
                } device_data;
        };
};

typedef int (*idev_event_fn) (idev_session *s, void *userdata, idev_event *ev);

/*
 * Devices
 */

void idev_device_enable(idev_device *d);
void idev_device_disable(idev_device *d);

/*
 * Sessions
 */

enum {
        IDEV_SESSION_CUSTOM                     = (1 << 0),
        IDEV_SESSION_MANAGED                    = (1 << 1),
};

int idev_session_new(idev_session **out,
                     idev_context *c,
                     unsigned int flags,
                     const char *name,
                     idev_event_fn event_fn,
                     void *userdata);
idev_session *idev_session_free(idev_session *s);

DEFINE_TRIVIAL_CLEANUP_FUNC(idev_session*, idev_session_free);

bool idev_session_is_enabled(idev_session *s);
void idev_session_enable(idev_session *s);
void idev_session_disable(idev_session *s);

int idev_session_add_evdev(idev_session *s, struct udev_device *ud);
int idev_session_remove_evdev(idev_session *s, struct udev_device *ud);

/*
 * Contexts
 */

int idev_context_new(idev_context **out, sd_event *event, sd_bus *sysbus);
idev_context *idev_context_ref(idev_context *c);
idev_context *idev_context_unref(idev_context *c);

DEFINE_TRIVIAL_CLEANUP_FUNC(idev_context*, idev_context_unref);
