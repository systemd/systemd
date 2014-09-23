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
#include "grdev.h"
#include "hashmap.h"
#include "list.h"
#include "util.h"

typedef struct grdev_tile               grdev_tile;
typedef struct grdev_display_cache      grdev_display_cache;

typedef struct grdev_pipe_vtable        grdev_pipe_vtable;
typedef struct grdev_pipe               grdev_pipe;
typedef struct grdev_card_vtable        grdev_card_vtable;
typedef struct grdev_card               grdev_card;

/*
 * DRM cards
 */

bool grdev_is_drm_card(grdev_card *card);
grdev_card *grdev_find_drm_card(grdev_session *session, dev_t devnum);
int grdev_drm_card_new(grdev_card **out, grdev_session *session, struct udev_device *ud);
void grdev_drm_card_hotplug(grdev_card *card, struct udev_device *ud);

/*
 * Displays
 */

enum {
        GRDEV_TILE_LEAF,
        GRDEV_TILE_NODE,
        GRDEV_TILE_CNT
};

struct grdev_tile {
        LIST_FIELDS(grdev_tile, children_by_node);
        grdev_tile *parent;
        grdev_display *display;

        uint32_t x;
        uint32_t y;
        unsigned int rotate;
        unsigned int flip;
        uint32_t cache_w;
        uint32_t cache_h;

        unsigned int type;

        union {
                struct {
                        grdev_pipe *pipe;
                } leaf;

                struct {
                        size_t n_children;
                        LIST_HEAD(grdev_tile, child_list);
                } node;
        };
};

int grdev_tile_new_leaf(grdev_tile **out, grdev_pipe *pipe);
int grdev_tile_new_node(grdev_tile **out);
grdev_tile *grdev_tile_free(grdev_tile *tile);

DEFINE_TRIVIAL_CLEANUP_FUNC(grdev_tile*, grdev_tile_free);

struct grdev_display {
        grdev_session *session;
        char *name;
        void *userdata;

        size_t n_leafs;
        grdev_tile *tile;

        size_t n_pipes;
        size_t max_pipes;

        uint32_t width;
        uint32_t height;

        struct grdev_display_cache {
                grdev_pipe *pipe;
                grdev_display_target target;

                bool incomplete : 1;
        } *pipes;

        bool enabled : 1;
        bool public : 1;
        bool modified : 1;
        bool framed : 1;
};

grdev_display *grdev_find_display(grdev_session *session, const char *name);

int grdev_display_new(grdev_display **out, grdev_session *session, const char *name);
grdev_display *grdev_display_free(grdev_display *display);

DEFINE_TRIVIAL_CLEANUP_FUNC(grdev_display*, grdev_display_free);

/*
 * Pipes
 */

struct grdev_pipe_vtable {
        void (*free) (grdev_pipe *pipe);
        void (*enable) (grdev_pipe *pipe);
        void (*disable) (grdev_pipe *pipe);
        grdev_fb *(*target) (grdev_pipe *pipe);
};

struct grdev_pipe {
        const grdev_pipe_vtable *vtable;
        grdev_card *card;
        char *name;

        grdev_tile *tile;
        grdev_display_cache *cache;
        sd_event_source *vsync_src;

        uint32_t width;
        uint32_t height;
        uint32_t vrefresh;

        size_t max_fbs;
        grdev_fb *front;
        grdev_fb *back;
        grdev_fb **fbs;

        bool enabled : 1;
        bool running : 1;
        bool flip : 1;
        bool flipping : 1;
};

#define GRDEV_PIPE_INIT(_vtable, _card) ((grdev_pipe){ \
                .vtable = (_vtable), \
                .card = (_card), \
        })

grdev_pipe *grdev_find_pipe(grdev_card *card, const char *name);

int grdev_pipe_add(grdev_pipe *pipe, const char *name, size_t n_fbs);
grdev_pipe *grdev_pipe_free(grdev_pipe *pipe);

DEFINE_TRIVIAL_CLEANUP_FUNC(grdev_pipe*, grdev_pipe_free);

void grdev_pipe_ready(grdev_pipe *pipe, bool running);
void grdev_pipe_frame(grdev_pipe *pipe);
void grdev_pipe_schedule(grdev_pipe *pipe, uint64_t frames);

/*
 * Cards
 */

struct grdev_card_vtable {
        void (*free) (grdev_card *card);
        void (*enable) (grdev_card *card);
        void (*disable) (grdev_card *card);
        void (*commit) (grdev_card *card);
        void (*restore) (grdev_card *card);
};

struct grdev_card {
        const grdev_card_vtable *vtable;
        grdev_session *session;
        char *name;

        Hashmap *pipe_map;

        bool enabled : 1;
        bool modified : 1;
};

#define GRDEV_CARD_INIT(_vtable, _session) ((grdev_card){ \
                .vtable = (_vtable), \
                .session = (_session), \
        })

grdev_card *grdev_find_card(grdev_session *session, const char *name);

int grdev_card_add(grdev_card *card, const char *name);
grdev_card *grdev_card_free(grdev_card *card);

DEFINE_TRIVIAL_CLEANUP_FUNC(grdev_card*, grdev_card_free);

/*
 * Sessions
 */

struct grdev_session {
        grdev_context *context;
        char *name;
        char *path;
        grdev_event_fn event_fn;
        void *userdata;

        unsigned long n_pins;

        Hashmap *card_map;
        Hashmap *display_map;

        bool custom : 1;
        bool managed : 1;
        bool enabled : 1;
        bool modified : 1;
};

grdev_session *grdev_session_pin(grdev_session *session);
grdev_session *grdev_session_unpin(grdev_session *session);

DEFINE_TRIVIAL_CLEANUP_FUNC(grdev_session*, grdev_session_unpin);

/*
 * Contexts
 */

struct grdev_context {
        unsigned long ref;
        sd_event *event;
        sd_bus *sysbus;

        Hashmap *session_map;
};
