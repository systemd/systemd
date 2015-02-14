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

#include <libudev.h>
#include <linux/input.h>
#include <stdbool.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>
#include <xkbcommon/xkbcommon.h>

typedef struct idev_data                idev_data;
typedef struct idev_data_evdev          idev_data_evdev;
typedef struct idev_data_keyboard       idev_data_keyboard;

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
        IDEV_DEVICE_KEYBOARD,
        IDEV_DEVICE_CNT
};

/*
 * Evdev Elements
 */

struct idev_data_evdev {
        struct input_event event;
};

/*
 * Keyboard Devices
 */

struct xkb_state;

enum {
        IDEV_KBDMOD_IDX_SHIFT,
        IDEV_KBDMOD_IDX_CTRL,
        IDEV_KBDMOD_IDX_ALT,
        IDEV_KBDMOD_IDX_LINUX,
        IDEV_KBDMOD_IDX_CAPS,
        IDEV_KBDMOD_CNT,

        IDEV_KBDMOD_SHIFT               = 1 << IDEV_KBDMOD_IDX_SHIFT,
        IDEV_KBDMOD_CTRL                = 1 << IDEV_KBDMOD_IDX_CTRL,
        IDEV_KBDMOD_ALT                 = 1 << IDEV_KBDMOD_IDX_ALT,
        IDEV_KBDMOD_LINUX               = 1 << IDEV_KBDMOD_IDX_LINUX,
        IDEV_KBDMOD_CAPS                = 1 << IDEV_KBDMOD_IDX_CAPS,
};

enum {
        IDEV_KBDLED_IDX_NUM,
        IDEV_KBDLED_IDX_CAPS,
        IDEV_KBDLED_IDX_SCROLL,
        IDEV_KBDLED_CNT,

        IDEV_KBDLED_NUM                 = 1 << IDEV_KBDLED_IDX_NUM,
        IDEV_KBDLED_CAPS                = 1 << IDEV_KBDLED_IDX_CAPS,
        IDEV_KBDLED_SCROLL              = 1 << IDEV_KBDLED_IDX_SCROLL,
};

struct idev_data_keyboard {
        struct xkb_state *xkb_state;
        int8_t ascii;
        uint8_t value;
        uint16_t keycode;
        uint32_t mods;
        uint32_t consumed_mods;
        uint32_t n_syms;
        uint32_t *keysyms;
        uint32_t *codepoints;
};

static inline bool idev_kbdmatch(idev_data_keyboard *kdata,
                                 uint32_t mods, uint32_t n_syms,
                                 const uint32_t *syms) {
        const uint32_t significant = IDEV_KBDMOD_SHIFT |
                                     IDEV_KBDMOD_CTRL |
                                     IDEV_KBDMOD_ALT |
                                     IDEV_KBDMOD_LINUX;
        uint32_t real;

        if (n_syms != kdata->n_syms)
                return false;

        real = kdata->mods & ~kdata->consumed_mods & significant;
        if (real != mods)
                return false;

        return !memcmp(syms, kdata->keysyms, n_syms * sizeof(*syms));
}

#define IDEV_KBDMATCH(_kdata, _mods, _sym) \
        idev_kbdmatch((_kdata), (_mods), 1, (const uint32_t[]){ (_sym) })

/*
 * Data Packets
 */

enum {
        IDEV_DATA_RESYNC,
        IDEV_DATA_EVDEV,
        IDEV_DATA_KEYBOARD,
        IDEV_DATA_CNT
};

struct idev_data {
        unsigned int type;
        bool resync : 1;

        union {
                idev_data_evdev evdev;
                idev_data_keyboard keyboard;
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
