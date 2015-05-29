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
#include <linux/input.h>
#include <stdbool.h>
#include <stdlib.h>
#include <xkbcommon/xkbcommon.h>
#include "sd-bus.h"
#include "sd-event.h"
#include "hashmap.h"
#include "list.h"
#include "util.h"
#include "idev.h"

typedef struct idev_link                idev_link;
typedef struct idev_device_vtable       idev_device_vtable;
typedef struct idev_element             idev_element;
typedef struct idev_element_vtable      idev_element_vtable;

/*
 * Evdev Elements
 */

bool idev_is_evdev(idev_element *e);
idev_element *idev_find_evdev(idev_session *s, dev_t devnum);
int idev_evdev_new(idev_element **out, idev_session *s, struct udev_device *ud);

/*
 * Keyboard Devices
 */

bool idev_is_keyboard(idev_device *d);
idev_device *idev_find_keyboard(idev_session *s, const char *name);
int idev_keyboard_new(idev_device **out, idev_session *s, const char *name);

/*
 * Element Links
 */

struct idev_link {
        /* element-to-device connection */
        LIST_FIELDS(idev_link, links_by_element);
        idev_element *element;

        /* device-to-element connection */
        LIST_FIELDS(idev_link, links_by_device);
        idev_device *device;
};

/*
 * Devices
 */

struct idev_device_vtable {
        void (*free) (idev_device *d);
        void (*attach) (idev_device *d, idev_link *l);
        void (*detach) (idev_device *d, idev_link *l);
        int (*feed) (idev_device *d, idev_data *data);
};

struct idev_device {
        const idev_device_vtable *vtable;
        idev_session *session;
        char *name;

        LIST_HEAD(idev_link, links);

        bool public : 1;
        bool enabled : 1;
};

#define IDEV_DEVICE_INIT(_vtable, _session) ((idev_device){ \
                .vtable = (_vtable), \
                .session = (_session), \
        })

idev_device *idev_find_device(idev_session *s, const char *name);

int idev_device_add(idev_device *d, const char *name);
idev_device *idev_device_free(idev_device *d);

DEFINE_TRIVIAL_CLEANUP_FUNC(idev_device*, idev_device_free);

int idev_device_feed(idev_device *d, idev_data *data);
void idev_device_feedback(idev_device *d, idev_data *data);

/*
 * Elements
 */

struct idev_element_vtable {
        void (*free) (idev_element *e);
        void (*enable) (idev_element *e);
        void (*disable) (idev_element *e);
        void (*open) (idev_element *e);
        void (*close) (idev_element *e);
        void (*resume) (idev_element *e, int fd);
        void (*pause) (idev_element *e, const char *mode);
        void (*feedback) (idev_element *e, idev_data *data);
};

struct idev_element {
        const idev_element_vtable *vtable;
        idev_session *session;
        unsigned long n_open;
        char *name;

        LIST_HEAD(idev_link, links);

        bool enabled : 1;
        bool readable : 1;
        bool writable : 1;
};

#define IDEV_ELEMENT_INIT(_vtable, _session) ((idev_element){ \
                .vtable = (_vtable), \
                .session = (_session), \
        })

idev_element *idev_find_element(idev_session *s, const char *name);

int idev_element_add(idev_element *e, const char *name);
idev_element *idev_element_free(idev_element *e);

DEFINE_TRIVIAL_CLEANUP_FUNC(idev_element*, idev_element_free);

int idev_element_feed(idev_element *e, idev_data *data);
void idev_element_feedback(idev_element *e, idev_data *data);

/*
 * Sessions
 */

struct idev_session {
        idev_context *context;
        char *name;
        char *path;
        sd_bus_slot *slot_resume_device;
        sd_bus_slot *slot_pause_device;

        Hashmap *element_map;
        Hashmap *device_map;

        idev_event_fn event_fn;
        void *userdata;

        bool custom : 1;
        bool managed : 1;
        bool enabled : 1;
};

idev_session *idev_find_session(idev_context *c, const char *name);
int idev_session_raise_device_data(idev_session *s, idev_device *d, idev_data *data);

/*
 * Contexts
 */

struct idev_context {
        unsigned long ref;
        sd_event *event;
        sd_bus *sysbus;

        Hashmap *session_map;
        Hashmap *data_map;
};
