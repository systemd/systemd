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
 * Graphics Devices
 * The grdev layer provides generic access to graphics devices. The device
 * types are hidden in the implementation and exported in a generic way. The
 * grdev_session object forms the base layer. It loads, configures and prepares
 * any graphics devices associated with that session. Each session is totally
 * independent of other sessions and can be controlled separately.
 * The target devices on a session are called display. A display always
 * corresponds to a real display regardless how many pipes are needed to drive
 * that display. That is, an exported display might internally be created out
 * of arbitrary combinations of target pipes. However, this is meant as
 * implementation detail and API users must never assume details below the
 * display-level. That is, a display is the most low-level object exported.
 * Therefore, pipe-configuration and any low-level modesetting is hidden from
 * the public API. It is provided by the implementation, and it is the
 * implementation that decides how pipes are driven.
 *
 * The API users are free to ignore specific displays or combine them to create
 * larger screens. This often requires user-configuration so is dictated by
 * policy. The underlying pipe-configuration might be affected by these
 * high-level policies, but is never directly controlled by those. That means,
 * depending on the displays you use, it might affect how underlying resources
 * are assigned. However, users can never directly apply policies to the pipes,
 * but only to displays. In case specific hardware needs quirks on the pipe
 * level, we support that via hwdb, not via public user configuration.
 *
 * Right now, displays are limited to rgb32 memory-mapped framebuffers on the
 * primary plane. However, the grdev implementation can be easily extended to
 * allow more powerful access (including hardware-acceleration for 2D and 3D
 * compositing). So far, this wasn't needed so it is not exposed.
 */

#pragma once

#include <libudev.h>
#include <stdbool.h>
#include <stdlib.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>
#include "util.h"

typedef struct grdev_fb                 grdev_fb;
typedef struct grdev_display_target     grdev_display_target;
typedef struct grdev_display            grdev_display;

typedef struct grdev_event              grdev_event;
typedef struct grdev_session            grdev_session;
typedef struct grdev_context            grdev_context;

enum {
        /* clockwise rotation; we treat this is abelian group Z4 with ADD */
        GRDEV_ROTATE_0                  = 0,
        GRDEV_ROTATE_90                 = 1,
        GRDEV_ROTATE_180                = 2,
        GRDEV_ROTATE_270                = 3,
};

enum {
        /* flip states; we treat this as abelian group V4 with XOR */
        GRDEV_FLIP_NONE                 = 0x0,
        GRDEV_FLIP_HORIZONTAL           = 0x1,
        GRDEV_FLIP_VERTICAL             = 0x2,
};

/*
 * Displays
 */

struct grdev_fb {
        uint32_t width;
        uint32_t height;
        uint32_t format;
        int32_t strides[4];
        void *maps[4];

        union {
                void *ptr;
                uint64_t u64;
        } data;

        void (*free_fn) (void *ptr);
};

struct grdev_display_target {
        uint32_t x;
        uint32_t y;
        uint32_t width;
        uint32_t height;
        unsigned int rotate;
        unsigned int flip;
        grdev_fb *front;
        grdev_fb *back;
};

void grdev_display_set_userdata(grdev_display *display, void *userdata);
void *grdev_display_get_userdata(grdev_display *display);

const char *grdev_display_get_name(grdev_display *display);
uint32_t grdev_display_get_width(grdev_display *display);
uint32_t grdev_display_get_height(grdev_display *display);

bool grdev_display_is_enabled(grdev_display *display);
void grdev_display_enable(grdev_display *display);
void grdev_display_disable(grdev_display *display);

const grdev_display_target *grdev_display_next_target(grdev_display *display, const grdev_display_target *prev);
void grdev_display_flip_target(grdev_display *display, const grdev_display_target *target);

#define GRDEV_DISPLAY_FOREACH_TARGET(_display, _t)                      \
        for ((_t) = grdev_display_next_target((_display), NULL);        \
             (_t);                                                      \
             (_t) = grdev_display_next_target((_display), (_t)))

/*
 * Events
 */

enum {
        GRDEV_EVENT_DISPLAY_ADD,
        GRDEV_EVENT_DISPLAY_REMOVE,
        GRDEV_EVENT_DISPLAY_CHANGE,
        GRDEV_EVENT_DISPLAY_FRAME,
};

typedef void (*grdev_event_fn) (grdev_session *session, void *userdata, grdev_event *ev);

struct grdev_event {
        unsigned int type;
        union {
                struct {
                        grdev_display *display;
                } display_add, display_remove, display_change;

                struct {
                        grdev_display *display;
                } display_frame;
        };
};

/*
 * Sessions
 */

enum {
        GRDEV_SESSION_CUSTOM                    = (1 << 0),
        GRDEV_SESSION_MANAGED                   = (1 << 1),
};

int grdev_session_new(grdev_session **out,
                      grdev_context *context,
                      unsigned int flags,
                      const char *name,
                      grdev_event_fn event_fn,
                      void *userdata);
grdev_session *grdev_session_free(grdev_session *session);

DEFINE_TRIVIAL_CLEANUP_FUNC(grdev_session*, grdev_session_free);

bool grdev_session_is_enabled(grdev_session *session);
void grdev_session_enable(grdev_session *session);
void grdev_session_disable(grdev_session *session);

void grdev_session_commit(grdev_session *session);
void grdev_session_restore(grdev_session *session);

void grdev_session_add_drm(grdev_session *session, struct udev_device *ud);
void grdev_session_remove_drm(grdev_session *session, struct udev_device *ud);
void grdev_session_hotplug_drm(grdev_session *session, struct udev_device *ud);

/*
 * Contexts
 */

int grdev_context_new(grdev_context **out, sd_event *event, sd_bus *sysbus);
grdev_context *grdev_context_ref(grdev_context *context);
grdev_context *grdev_context_unref(grdev_context *context);

DEFINE_TRIVIAL_CLEANUP_FUNC(grdev_context*, grdev_context_unref);
