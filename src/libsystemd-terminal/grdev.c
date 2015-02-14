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

#include <libudev.h>
#include <stdbool.h>
#include <stdlib.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>
#include "grdev.h"
#include "grdev-internal.h"
#include "hashmap.h"
#include "login-shared.h"
#include "macro.h"
#include "util.h"

static void pipe_enable(grdev_pipe *pipe);
static void pipe_disable(grdev_pipe *pipe);
static void card_modified(grdev_card *card);
static void session_frame(grdev_session *session, grdev_display *display);

/*
 * Displays
 */

static inline grdev_tile *tile_leftmost(grdev_tile *tile) {
        if (!tile)
                return NULL;

        while (tile->type == GRDEV_TILE_NODE && tile->node.child_list)
                tile = tile->node.child_list;

        return tile;
}

#define TILE_FOREACH(_root, _i) \
        for (_i = tile_leftmost(_root); _i; _i = tile_leftmost(_i->children_by_node_next) ? : _i->parent)

#define TILE_FOREACH_SAFE(_root, _i, _next) \
        for (_i = tile_leftmost(_root); _i && ((_next = tile_leftmost(_i->children_by_node_next) ? : _i->parent), true); _i = _next)

static void tile_link(grdev_tile *tile, grdev_tile *parent) {
        grdev_display *display;
        grdev_tile *t;

        assert(tile);
        assert(!tile->parent);
        assert(!tile->display);
        assert(parent);
        assert(parent->type == GRDEV_TILE_NODE);

        display = parent->display;

        assert(!display || !display->enabled);

        ++parent->node.n_children;
        LIST_PREPEND(children_by_node, parent->node.child_list, tile);
        tile->parent = parent;

        if (display) {
                display->modified = true;
                TILE_FOREACH(tile, t) {
                        t->display = display;
                        if (t->type == GRDEV_TILE_LEAF) {
                                ++display->n_leafs;
                                if (display->enabled)
                                        pipe_enable(t->leaf.pipe);
                        }
                }
        }
}

static void tile_unlink(grdev_tile *tile) {
        grdev_tile *parent, *t;
        grdev_display *display;

        assert(tile);

        display = tile->display;
        parent = tile->parent;
        if (!parent) {
                assert(!display);
                return;
        }

        assert(parent->type == GRDEV_TILE_NODE);
        assert(parent->display == display);
        assert(parent->node.n_children > 0);

        --parent->node.n_children;
        LIST_REMOVE(children_by_node, parent->node.child_list, tile);
        tile->parent = NULL;

        if (display) {
                display->modified = true;
                TILE_FOREACH(tile, t) {
                        t->display = NULL;
                        if (t->type == GRDEV_TILE_LEAF) {
                                --display->n_leafs;
                                t->leaf.pipe->cache = NULL;
                                pipe_disable(t->leaf.pipe);
                        }
                }
        }

        /* Tile trees are driven by leafs. Internal nodes have no owner, thus,
         * we must take care to not leave them around. Therefore, whenever we
         * unlink any part of a tree, we also destroy the parent, in case it's
         * now stale.
         * Parents are stale if they have no children and either have no display
         * or if they are intermediate nodes (i.e, they have a parent).
         * This means, you can easily create trees, but you can never partially
         * move or destruct them so far. They're always reduced to minimal form
         * if you cut them. This might change later, but so far we didn't need
         * partial destruction or the ability to move whole trees. */

        if (parent->node.n_children < 1 && (parent->parent || !parent->display))
                grdev_tile_free(parent);
}

static int tile_new(grdev_tile **out) {
        _cleanup_(grdev_tile_freep) grdev_tile *tile = NULL;

        assert(out);

        tile = new0(grdev_tile, 1);
        if (!tile)
                return -ENOMEM;

        tile->type = (unsigned)-1;

        *out = tile;
        tile = NULL;
        return 0;
}

int grdev_tile_new_leaf(grdev_tile **out, grdev_pipe *pipe) {
        _cleanup_(grdev_tile_freep) grdev_tile *tile = NULL;
        int r;

        assert_return(out, -EINVAL);
        assert_return(pipe, -EINVAL);
        assert_return(!pipe->tile, -EINVAL);

        r = tile_new(&tile);
        if (r < 0)
                return r;

        tile->type = GRDEV_TILE_LEAF;
        tile->leaf.pipe = pipe;

        if (out)
                *out = tile;
        tile = NULL;
        return 0;
}

int grdev_tile_new_node(grdev_tile **out) {
        _cleanup_(grdev_tile_freep) grdev_tile *tile = NULL;
        int r;

        assert_return(out, -EINVAL);

        r = tile_new(&tile);
        if (r < 0)
                return r;

        tile->type = GRDEV_TILE_NODE;

        *out = tile;
        tile = NULL;
        return 0;
}

grdev_tile *grdev_tile_free(grdev_tile *tile) {
        if (!tile)
                return NULL;

        tile_unlink(tile);

        switch (tile->type) {
        case GRDEV_TILE_LEAF:
                assert(!tile->parent);
                assert(!tile->display);
                assert(tile->leaf.pipe);

                break;
        case GRDEV_TILE_NODE:
                assert(!tile->parent);
                assert(!tile->display);
                assert(tile->node.n_children == 0);

                break;
        }

        free(tile);

        return NULL;
}

grdev_display *grdev_find_display(grdev_session *session, const char *name) {
        assert_return(session, NULL);
        assert_return(name, NULL);

        return hashmap_get(session->display_map, name);
}

int grdev_display_new(grdev_display **out, grdev_session *session, const char *name) {
        _cleanup_(grdev_display_freep) grdev_display *display = NULL;
        int r;

        assert(session);
        assert(name);

        display = new0(grdev_display, 1);
        if (!display)
                return -ENOMEM;

        display->session = session;

        display->name = strdup(name);
        if (!display->name)
                return -ENOMEM;

        r = grdev_tile_new_node(&display->tile);
        if (r < 0)
                return r;

        display->tile->display = display;

        r = hashmap_put(session->display_map, display->name, display);
        if (r < 0)
                return r;

        if (out)
                *out = display;
        display = NULL;
        return 0;
}

grdev_display *grdev_display_free(grdev_display *display) {
        if (!display)
                return NULL;

        assert(!display->public);
        assert(!display->enabled);
        assert(!display->modified);
        assert(display->n_leafs == 0);
        assert(display->n_pipes == 0);

        if (display->name)
                hashmap_remove_value(display->session->display_map, display->name, display);

        if (display->tile) {
                display->tile->display = NULL;
                grdev_tile_free(display->tile);
        }

        free(display->pipes);
        free(display->name);
        free(display);

        return NULL;
}

void grdev_display_set_userdata(grdev_display *display, void *userdata) {
        assert(display);

        display->userdata = userdata;
}

void *grdev_display_get_userdata(grdev_display *display) {
        assert_return(display, NULL);

        return display->userdata;
}

const char *grdev_display_get_name(grdev_display *display) {
        assert_return(display, NULL);

        return display->name;
}

uint32_t grdev_display_get_width(grdev_display *display) {
        assert_return(display, 0);

        return display->width;
}

uint32_t grdev_display_get_height(grdev_display *display) {
        assert_return(display, 0);

        return display->height;
}

bool grdev_display_is_enabled(grdev_display *display) {
        return display && display->enabled;
}

void grdev_display_enable(grdev_display *display) {
        grdev_tile *t;

        assert(display);

        if (!display->enabled) {
                display->enabled = true;
                TILE_FOREACH(display->tile, t)
                        if (t->type == GRDEV_TILE_LEAF)
                                pipe_enable(t->leaf.pipe);
        }
}

void grdev_display_disable(grdev_display *display) {
        grdev_tile *t;

        assert(display);

        if (display->enabled) {
                display->enabled = false;
                TILE_FOREACH(display->tile, t)
                        if (t->type == GRDEV_TILE_LEAF)
                                pipe_disable(t->leaf.pipe);
        }
}

const grdev_display_target *grdev_display_next_target(grdev_display *display, const grdev_display_target *prev) {
        grdev_display_cache *cache;
        size_t idx;

        assert_return(display, NULL);
        assert_return(!display->modified, NULL);
        assert_return(display->enabled, NULL);

        if (prev) {
                cache = container_of(prev, grdev_display_cache, target);

                assert(cache->pipe);
                assert(cache->pipe->tile->display == display);
                assert(display->pipes >= cache);

                idx = cache - display->pipes + 1;
        } else {
                idx = 0;
        }

        for (cache = display->pipes + idx; idx < display->n_pipes; ++idx, ++cache) {
                grdev_display_target *target;
                grdev_pipe *pipe;
                grdev_fb *fb;

                pipe = cache->pipe;
                target = &cache->target;

                if (!pipe->running || !pipe->enabled)
                        continue;

                /* find suitable back-buffer */
                if (!pipe->back) {
                        if (!pipe->vtable->target)
                                continue;
                        if (!(fb = pipe->vtable->target(pipe)))
                                continue;

                        assert(fb == pipe->back);
                }

                target->front = pipe->front;
                target->back = pipe->back;

                return target;
        }

        return NULL;
}

void grdev_display_flip_target(grdev_display *display, const grdev_display_target *target) {
        grdev_display_cache *cache;

        assert(display);
        assert(!display->modified);
        assert(display->enabled);
        assert(target);

        cache = container_of(target, grdev_display_cache, target);

        assert(cache->pipe);
        assert(cache->pipe->tile->display == display);

        cache->pipe->flip = true;
}

static void display_cache_apply(grdev_display_cache *c, grdev_tile *l) {
        uint32_t x, y, width, height;
        grdev_display_target *t;

        assert(c);
        assert(l);
        assert(l->cache_w >= c->target.width + c->target.x);
        assert(l->cache_h >= c->target.height + c->target.y);

        t = &c->target;

        /* rotate child */

        t->rotate = (t->rotate + l->rotate) & 0x3;

        x = t->x;
        y = t->y;
        width = t->width;
        height = t->height;

        switch (l->rotate) {
        case GRDEV_ROTATE_0:
                break;
        case GRDEV_ROTATE_90:
                t->x = l->cache_h - (height + y);
                t->y = x;
                t->width = height;
                t->height = width;
                break;
        case GRDEV_ROTATE_180:
                t->x = l->cache_w - (width + x);
                t->y = l->cache_h - (height + y);
                break;
        case GRDEV_ROTATE_270:
                t->x = y;
                t->y = l->cache_w - (width + x);
                t->width = height;
                t->height = width;
                break;
        }

        /* flip child */

        t->flip ^= l->flip;

        if (l->flip & GRDEV_FLIP_HORIZONTAL)
                t->x = l->cache_w - (t->width + t->x);
        if (l->flip & GRDEV_FLIP_VERTICAL)
                t->y = l->cache_h - (t->height + t->y);

        /* move child */

        t->x += l->x;
        t->y += l->y;
}

static void display_cache_targets(grdev_display *display) {
        grdev_display_cache *c;
        grdev_tile *tile;

        assert(display);

        /* depth-first with children before parent */
        for (tile = tile_leftmost(display->tile);
             tile;
             tile = tile_leftmost(tile->children_by_node_next) ? : tile->parent) {
                if (tile->type == GRDEV_TILE_LEAF) {
                        grdev_pipe *p;

                        /* We're at a leaf and no parent has been cached, yet.
                         * Copy the pipe information into the target cache and
                         * update our global pipe-caches if required. */

                        assert(tile->leaf.pipe);
                        assert(display->n_pipes + 1 <= display->max_pipes);

                        p = tile->leaf.pipe;
                        c = &display->pipes[display->n_pipes++];

                        zero(*c);
                        c->pipe = p;
                        c->pipe->cache = c;
                        c->target.width = p->width;
                        c->target.height = p->height;
                        tile->cache_w = p->width;
                        tile->cache_h = p->height;

                        /* all new tiles are incomplete due to geometry changes */
                        c->incomplete = true;

                        display_cache_apply(c, tile);
                } else {
                        grdev_tile *child, *l;

                        /* We're now at a node with all its children already
                         * computed (depth-first, child before parent). We
                         * first need to know the size of our tile, then we
                         * recurse into all leafs and update their cache. */

                        tile->cache_w = 0;
                        tile->cache_h = 0;

                        LIST_FOREACH(children_by_node, child, tile->node.child_list) {
                                if (child->x + child->cache_w > tile->cache_w)
                                        tile->cache_w = child->x + child->cache_w;
                                if (child->y + child->cache_h > tile->cache_h)
                                        tile->cache_h = child->y + child->cache_h;
                        }

                        assert(tile->cache_w > 0);
                        assert(tile->cache_h > 0);

                        TILE_FOREACH(tile, l)
                                if (l->type == GRDEV_TILE_LEAF)
                                        display_cache_apply(l->leaf.pipe->cache, tile);
                }
        }
}

static bool display_cache(grdev_display *display) {
        grdev_tile *tile;
        size_t n;
        void *t;
        int r;

        assert(display);

        if (!display->modified)
                return false;

        display->modified = false;
        display->framed = false;
        display->n_pipes = 0;
        display->width = 0;
        display->height = 0;

        if (display->n_leafs < 1)
                return false;

        TILE_FOREACH(display->tile, tile)
                if (tile->type == GRDEV_TILE_LEAF)
                        tile->leaf.pipe->cache = NULL;

        if (display->n_leafs > display->max_pipes) {
                n = ALIGN_POWER2(display->n_leafs);
                if (!n) {
                        r = -ENOMEM;
                        goto out;
                }

                t = realloc_multiply(display->pipes, sizeof(*display->pipes), n);
                if (!t) {
                        r = -ENOMEM;
                        goto out;
                }

                display->pipes = t;
                display->max_pipes = n;
        }

        display_cache_targets(display);
        display->width = display->tile->cache_w;
        display->height = display->tile->cache_h;

        r = 0;

out:
        if (r < 0)
                log_debug_errno(r, "grdev: %s/%s: cannot cache pipes: %m",
                                display->session->name, display->name);
        return true;
}

/*
 * Pipes
 */

grdev_pipe *grdev_find_pipe(grdev_card *card, const char *name) {
        assert_return(card, NULL);
        assert_return(name, NULL);

        return hashmap_get(card->pipe_map, name);
}

static int pipe_vsync_fn(sd_event_source *src, uint64_t usec, void *userdata) {
        grdev_pipe *pipe = userdata;

        grdev_pipe_frame(pipe);
        return 0;
}

int grdev_pipe_add(grdev_pipe *pipe, const char *name, size_t n_fbs) {
        int r;

        assert_return(pipe, -EINVAL);
        assert_return(pipe->vtable, -EINVAL);
        assert_return(pipe->vtable->free, -EINVAL);
        assert_return(pipe->card, -EINVAL);
        assert_return(pipe->card->session, -EINVAL);
        assert_return(!pipe->cache, -EINVAL);
        assert_return(pipe->width > 0, -EINVAL);
        assert_return(pipe->height > 0, -EINVAL);
        assert_return(pipe->vrefresh > 0, -EINVAL);
        assert_return(!pipe->enabled, -EINVAL);
        assert_return(!pipe->running, -EINVAL);
        assert_return(name, -EINVAL);

        pipe->name = strdup(name);
        if (!pipe->name)
                return -ENOMEM;

        if (n_fbs > 0) {
                pipe->fbs = new0(grdev_fb*, n_fbs);
                if (!pipe->fbs)
                        return -ENOMEM;

                pipe->max_fbs = n_fbs;
        }

        r = grdev_tile_new_leaf(&pipe->tile, pipe);
        if (r < 0)
                return r;

        r = sd_event_add_time(pipe->card->session->context->event,
                              &pipe->vsync_src,
                              CLOCK_MONOTONIC,
                              0,
                              10 * USEC_PER_MSEC,
                              pipe_vsync_fn,
                              pipe);
        if (r < 0)
                return r;

        r = sd_event_source_set_enabled(pipe->vsync_src, SD_EVENT_OFF);
        if (r < 0)
                return r;

        r = hashmap_put(pipe->card->pipe_map, pipe->name, pipe);
        if (r < 0)
                return r;

        card_modified(pipe->card);
        return 0;
}

grdev_pipe *grdev_pipe_free(grdev_pipe *pipe) {
        grdev_pipe tmp;

        if (!pipe)
                return NULL;

        assert(pipe->card);
        assert(pipe->vtable);
        assert(pipe->vtable->free);

        if (pipe->name)
                hashmap_remove_value(pipe->card->pipe_map, pipe->name, pipe);
        if (pipe->tile)
                tile_unlink(pipe->tile);

        assert(!pipe->cache);

        tmp = *pipe;
        pipe->vtable->free(pipe);

        sd_event_source_unref(tmp.vsync_src);
        grdev_tile_free(tmp.tile);
        card_modified(tmp.card);
        free(tmp.fbs);
        free(tmp.name);

        return NULL;
}

static void pipe_enable(grdev_pipe *pipe) {
        assert(pipe);

        if (!pipe->enabled) {
                pipe->enabled = true;
                if (pipe->vtable->enable)
                        pipe->vtable->enable(pipe);
        }
}

static void pipe_disable(grdev_pipe *pipe) {
        assert(pipe);

        if (pipe->enabled) {
                pipe->enabled = false;
                if (pipe->vtable->disable)
                        pipe->vtable->disable(pipe);
        }
}

void grdev_pipe_ready(grdev_pipe *pipe, bool running) {
        assert(pipe);

        /* grdev_pipe_ready() is used by backends to notify about pipe state
         * changed. If a pipe is ready, it can be fully used by us (available,
         * enabled and accessible). Backends can disable pipes at any time
         * (like for async revocation), but can only enable them from parent
         * context. Otherwise, we might call user-callbacks recursively. */

        if (pipe->running == running)
                return;

        pipe->running = running;

        /* runtime events for unused pipes are not interesting */
        if (pipe->cache && pipe->enabled) {
                grdev_display *display = pipe->tile->display;

                assert(display);

                if (running)
                        session_frame(display->session, display);
                else
                        pipe->cache->incomplete = true;
        }
}

void grdev_pipe_frame(grdev_pipe *pipe) {
        grdev_display *display;

        assert(pipe);

        /* if pipe is unused, ignore any frame events */
        if (!pipe->cache || !pipe->enabled)
                return;

        display = pipe->tile->display;
        assert(display);

        grdev_pipe_schedule(pipe, 0);
        session_frame(display->session, display);
}

void grdev_pipe_schedule(grdev_pipe *pipe, uint64_t frames) {
        int r;
        uint64_t ts;

        if (!frames) {
                sd_event_source_set_enabled(pipe->vsync_src, SD_EVENT_OFF);
                return;
        }

        r = sd_event_now(pipe->card->session->context->event, CLOCK_MONOTONIC, &ts);
        if (r < 0)
                goto error;

        ts += frames * USEC_PER_MSEC * 1000ULL / pipe->vrefresh;

        r = sd_event_source_set_time(pipe->vsync_src, ts);
        if (r < 0)
                goto error;

        r = sd_event_source_set_enabled(pipe->vsync_src, SD_EVENT_ONESHOT);
        if (r < 0)
                goto error;

        return;

error:
        log_debug_errno(r, "grdev: %s/%s/%s: cannot schedule vsync timer: %m",
                        pipe->card->session->name, pipe->card->name, pipe->name);
}

/*
 * Cards
 */

grdev_card *grdev_find_card(grdev_session *session, const char *name) {
        assert_return(session, NULL);
        assert_return(name, NULL);

        return hashmap_get(session->card_map, name);
}

int grdev_card_add(grdev_card *card, const char *name) {
        int r;

        assert_return(card, -EINVAL);
        assert_return(card->vtable, -EINVAL);
        assert_return(card->vtable->free, -EINVAL);
        assert_return(card->session, -EINVAL);
        assert_return(name, -EINVAL);

        card->name = strdup(name);
        if (!card->name)
                return -ENOMEM;

        card->pipe_map = hashmap_new(&string_hash_ops);
        if (!card->pipe_map)
                return -ENOMEM;

        r = hashmap_put(card->session->card_map, card->name, card);
        if (r < 0)
                return r;

        return 0;
}

grdev_card *grdev_card_free(grdev_card *card) {
        grdev_card tmp;

        if (!card)
                return NULL;

        assert(!card->enabled);
        assert(card->vtable);
        assert(card->vtable->free);

        if (card->name)
                hashmap_remove_value(card->session->card_map, card->name, card);

        tmp = *card;
        card->vtable->free(card);

        assert(hashmap_size(tmp.pipe_map) == 0);

        hashmap_free(tmp.pipe_map);
        free(tmp.name);

        return NULL;
}

static void card_modified(grdev_card *card) {
        assert(card);
        assert(card->session->n_pins > 0);

        card->modified = true;
}

static void grdev_card_enable(grdev_card *card) {
        assert(card);

        if (!card->enabled) {
                card->enabled = true;
                if (card->vtable->enable)
                        card->vtable->enable(card);
        }
}

static void grdev_card_disable(grdev_card *card) {
        assert(card);

        if (card->enabled) {
                card->enabled = false;
                if (card->vtable->disable)
                        card->vtable->disable(card);
        }
}

/*
 * Sessions
 */

static void session_raise(grdev_session *session, grdev_event *event) {
        session->event_fn(session, session->userdata, event);
}

static void session_raise_display_add(grdev_session *session, grdev_display *display) {
        grdev_event event = {
                .type = GRDEV_EVENT_DISPLAY_ADD,
                .display_add = {
                        .display = display,
                },
        };

        session_raise(session, &event);
}

static void session_raise_display_remove(grdev_session *session, grdev_display *display) {
        grdev_event event = {
                .type = GRDEV_EVENT_DISPLAY_REMOVE,
                .display_remove = {
                        .display = display,
                },
        };

        session_raise(session, &event);
}

static void session_raise_display_change(grdev_session *session, grdev_display *display) {
        grdev_event event = {
                .type = GRDEV_EVENT_DISPLAY_CHANGE,
                .display_change = {
                        .display = display,
                },
        };

        session_raise(session, &event);
}

static void session_raise_display_frame(grdev_session *session, grdev_display *display) {
        grdev_event event = {
                .type = GRDEV_EVENT_DISPLAY_FRAME,
                .display_frame = {
                        .display = display,
                },
        };

        session_raise(session, &event);
}

static void session_add_card(grdev_session *session, grdev_card *card) {
        assert(session);
        assert(card);

        log_debug("grdev: %s: add card '%s'", session->name, card->name);

        /* Cards are not exposed to users, but managed internally. Cards are
         * enabled if the session is enabled, and will track that state. The
         * backend can probe the card at any time, but only if enabled. It
         * will then add pipes according to hardware state.
         * That is, the card may create pipes as soon as we enable it here. */

        if (session->enabled)
                grdev_card_enable(card);
}

static void session_remove_card(grdev_session *session, grdev_card *card) {
        assert(session);
        assert(card);

        log_debug("grdev: %s: remove card '%s'", session->name, card->name);

        /* As cards are not exposed, it can never be accessed by outside
         * users and we can simply remove it. Disabling the card does not
         * necessarily drop all pipes of the card. This is usually deferred
         * to card destruction (as pipes are cached as long as FDs remain
         * open). Therefore, the card destruction might cause pipes, and thus
         * visible displays, to be removed. */

        grdev_card_disable(card);
        grdev_card_free(card);
}

static void session_add_display(grdev_session *session, grdev_display *display) {
        assert(session);
        assert(display);
        assert(!display->enabled);

        log_debug("grdev: %s: add display '%s'", session->name, display->name);

        /* Displays are the main entity for public API users. We create them
         * independent of card backends and they wrap any underlying display
         * architecture. Displays are public at all times, thus, may be entered
         * by outside users at any time. */

        display->public = true;
        session_raise_display_add(session, display);
}

static void session_remove_display(grdev_session *session, grdev_display *display) {
        assert(session);
        assert(display);

        log_debug("grdev: %s: remove display '%s'", session->name, display->name);

        /* Displays are public, so we have to be careful when removing them.
         * We first tell users about their removal, disable them and then drop
         * them. We now, after the notification, no external access will
         * happen. Therefore, we can release the tiles afterwards safely. */

        if (display->public) {
                display->public = false;
                session_raise_display_remove(session, display);
        }

        grdev_display_disable(display);
        grdev_display_free(display);
}

static void session_change_display(grdev_session *session, grdev_display *display) {
        bool changed;

        assert(session);
        assert(display);

        changed = display_cache(display);

        if (display->n_leafs == 0) {
                session_remove_display(session, display);
        } else if (!display->public) {
                session_add_display(session, display);
                session_frame(session, display);
        } else if (changed) {
                session_raise_display_change(session, display);
                session_frame(session, display);
        } else if (display->framed) {
                session_frame(session, display);
        }
}

static void session_frame(grdev_session *session, grdev_display *display) {
        assert(session);
        assert(display);

        display->framed = false;

        if (!display->enabled || !session->enabled)
                return;

        if (session->n_pins > 0)
                display->framed = true;
        else
                session_raise_display_frame(session, display);
}

int grdev_session_new(grdev_session **out,
                      grdev_context *context,
                      unsigned int flags,
                      const char *name,
                      grdev_event_fn event_fn,
                      void *userdata) {
        _cleanup_(grdev_session_freep) grdev_session *session = NULL;
        int r;

        assert(out);
        assert(context);
        assert(name);
        assert(event_fn);
        assert_return(session_id_valid(name) == !(flags & GRDEV_SESSION_CUSTOM), -EINVAL);
        assert_return(!(flags & GRDEV_SESSION_CUSTOM) || !(flags & GRDEV_SESSION_MANAGED), -EINVAL);
        assert_return(!(flags & GRDEV_SESSION_MANAGED) || context->sysbus, -EINVAL);

        session = new0(grdev_session, 1);
        if (!session)
                return -ENOMEM;

        session->context = grdev_context_ref(context);
        session->custom = flags & GRDEV_SESSION_CUSTOM;
        session->managed = flags & GRDEV_SESSION_MANAGED;
        session->event_fn = event_fn;
        session->userdata = userdata;

        session->name = strdup(name);
        if (!session->name)
                return -ENOMEM;

        if (session->managed) {
                r = sd_bus_path_encode("/org/freedesktop/login1/session",
                                       session->name, &session->path);
                if (r < 0)
                        return r;
        }

        session->card_map = hashmap_new(&string_hash_ops);
        if (!session->card_map)
                return -ENOMEM;

        session->display_map = hashmap_new(&string_hash_ops);
        if (!session->display_map)
                return -ENOMEM;

        r = hashmap_put(context->session_map, session->name, session);
        if (r < 0)
                return r;

        *out = session;
        session = NULL;
        return 0;
}

grdev_session *grdev_session_free(grdev_session *session) {
        grdev_card *card;

        if (!session)
                return NULL;

        grdev_session_disable(session);

        while ((card = hashmap_first(session->card_map)))
                session_remove_card(session, card);

        assert(hashmap_size(session->display_map) == 0);

        if (session->name)
                hashmap_remove_value(session->context->session_map, session->name, session);

        hashmap_free(session->display_map);
        hashmap_free(session->card_map);
        session->context = grdev_context_unref(session->context);
        free(session->path);
        free(session->name);
        free(session);

        return NULL;
}

bool grdev_session_is_enabled(grdev_session *session) {
        return session && session->enabled;
}

void grdev_session_enable(grdev_session *session) {
        grdev_card *card;
        Iterator iter;

        assert(session);

        if (!session->enabled) {
                session->enabled = true;
                HASHMAP_FOREACH(card, session->card_map, iter)
                        grdev_card_enable(card);
        }
}

void grdev_session_disable(grdev_session *session) {
        grdev_card *card;
        Iterator iter;

        assert(session);

        if (session->enabled) {
                session->enabled = false;
                HASHMAP_FOREACH(card, session->card_map, iter)
                        grdev_card_disable(card);
        }
}

void grdev_session_commit(grdev_session *session) {
        grdev_card *card;
        Iterator iter;

        assert(session);

        if (!session->enabled)
                return;

        HASHMAP_FOREACH(card, session->card_map, iter)
                if (card->vtable->commit)
                        card->vtable->commit(card);
}

void grdev_session_restore(grdev_session *session) {
        grdev_card *card;
        Iterator iter;

        assert(session);

        if (!session->enabled)
                return;

        HASHMAP_FOREACH(card, session->card_map, iter)
                if (card->vtable->restore)
                        card->vtable->restore(card);
}

void grdev_session_add_drm(grdev_session *session, struct udev_device *ud) {
        grdev_card *card;
        dev_t devnum;
        int r;

        assert(session);
        assert(ud);

        devnum = udev_device_get_devnum(ud);
        if (devnum == 0)
                return grdev_session_hotplug_drm(session, ud);

        card = grdev_find_drm_card(session, devnum);
        if (card)
                return;

        r = grdev_drm_card_new(&card, session, ud);
        if (r < 0) {
                log_debug_errno(r, "grdev: %s: cannot add DRM device for %s: %m",
                                session->name, udev_device_get_syspath(ud));
                return;
        }

        session_add_card(session, card);
}

void grdev_session_remove_drm(grdev_session *session, struct udev_device *ud) {
        grdev_card *card;
        dev_t devnum;

        assert(session);
        assert(ud);

        devnum = udev_device_get_devnum(ud);
        if (devnum == 0)
                return grdev_session_hotplug_drm(session, ud);

        card = grdev_find_drm_card(session, devnum);
        if (!card)
                return;

        session_remove_card(session, card);
}

void grdev_session_hotplug_drm(grdev_session *session, struct udev_device *ud) {
        grdev_card *card = NULL;
        struct udev_device *p;
        dev_t devnum;

        assert(session);
        assert(ud);

        for (p = ud; p; p = udev_device_get_parent_with_subsystem_devtype(p, "drm", NULL)) {
                devnum = udev_device_get_devnum(ud);
                if (devnum == 0)
                        continue;

                card = grdev_find_drm_card(session, devnum);
                if (card)
                        break;
        }

        if (!card)
                return;

        grdev_drm_card_hotplug(card, ud);
}

static void session_configure(grdev_session *session) {
        grdev_display *display;
        grdev_tile *tile;
        grdev_card *card;
        grdev_pipe *pipe;
        Iterator i, j;
        int r;

        assert(session);

        /*
         * Whenever backends add or remove pipes, we set session->modified and
         * require them to pin the session while modifying it. On release, we
         * reconfigure the device and re-assign displays to all modified pipes.
         *
         * So far, we configure each pipe as a separate display. We do not
         * support user-configuration, nor have we gotten any reports from
         * users with multi-pipe monitors (4k on DP-1.2 MST and so on). Until
         * we get reports, we keep the logic to a minimum.
         */

        /* create new displays for all unconfigured pipes */
        HASHMAP_FOREACH(card, session->card_map, i) {
                if (!card->modified)
                        continue;

                card->modified = false;

                HASHMAP_FOREACH(pipe, card->pipe_map, j) {
                        tile = pipe->tile;
                        if (tile->display)
                                continue;

                        assert(!tile->parent);

                        display = grdev_find_display(session, pipe->name);
                        if (display && display->tile) {
                                log_debug("grdev: %s/%s: occupied display for pipe %s",
                                          session->name, card->name, pipe->name);
                                continue;
                        } else if (!display) {
                                r = grdev_display_new(&display, session, pipe->name);
                                if (r < 0) {
                                        log_debug_errno(r, "grdev: %s/%s: cannot create display for pipe %s: %m",
                                                        session->name, card->name, pipe->name);
                                        continue;
                                }
                        }

                        tile_link(pipe->tile, display->tile);
                }
        }

        /* update displays */
        HASHMAP_FOREACH(display, session->display_map, i)
                session_change_display(session, display);
}

grdev_session *grdev_session_pin(grdev_session *session) {
        assert(session);

        ++session->n_pins;
        return session;
}

grdev_session *grdev_session_unpin(grdev_session *session) {
        if (!session)
                return NULL;

        assert(session->n_pins > 0);

        if (--session->n_pins == 0)
                session_configure(session);

        return NULL;
}

/*
 * Contexts
 */

int grdev_context_new(grdev_context **out, sd_event *event, sd_bus *sysbus) {
        _cleanup_(grdev_context_unrefp) grdev_context *context = NULL;

        assert_return(out, -EINVAL);
        assert_return(event, -EINVAL);

        context = new0(grdev_context, 1);
        if (!context)
                return -ENOMEM;

        context->ref = 1;
        context->event = sd_event_ref(event);

        if (sysbus)
                context->sysbus = sd_bus_ref(sysbus);

        context->session_map = hashmap_new(&string_hash_ops);
        if (!context->session_map)
                return -ENOMEM;

        *out = context;
        context = NULL;
        return 0;
}

static void context_cleanup(grdev_context *context) {
        assert(hashmap_size(context->session_map) == 0);

        hashmap_free(context->session_map);
        context->sysbus = sd_bus_unref(context->sysbus);
        context->event = sd_event_unref(context->event);
        free(context);
}

grdev_context *grdev_context_ref(grdev_context *context) {
        assert_return(context, NULL);
        assert_return(context->ref > 0, NULL);

        ++context->ref;
        return context;
}

grdev_context *grdev_context_unref(grdev_context *context) {
        if (!context)
                return NULL;

        assert_return(context->ref > 0, NULL);

        if (--context->ref == 0)
                context_cleanup(context);

        return NULL;
}
