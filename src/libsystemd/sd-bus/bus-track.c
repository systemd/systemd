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

#include "alloc-util.h"
#include "bus-internal.h"
#include "bus-track.h"
#include "bus-util.h"

struct track_item {
        unsigned n_ref;
        char *name;
        sd_bus_slot *slot;
};

struct sd_bus_track {
        unsigned n_ref;
        sd_bus *bus;
        sd_bus_track_handler_t handler;
        void *userdata;
        Hashmap *names;
        LIST_FIELDS(sd_bus_track, queue);
        Iterator iterator;
        bool in_queue:1;
        bool modified:1;
        bool recursive:1;
};

#define MATCH_PREFIX                                        \
        "type='signal',"                                    \
        "sender='org.freedesktop.DBus',"                    \
        "path='/org/freedesktop/DBus',"                     \
        "interface='org.freedesktop.DBus',"                 \
        "member='NameOwnerChanged',"                        \
        "arg0='"

#define MATCH_SUFFIX \
        "'"

#define MATCH_FOR_NAME(name)                                            \
        ({                                                              \
                char *_x;                                               \
                size_t _l = strlen(name);                               \
                _x = alloca(strlen(MATCH_PREFIX)+_l+strlen(MATCH_SUFFIX)+1); \
                strcpy(stpcpy(stpcpy(_x, MATCH_PREFIX), name), MATCH_SUFFIX); \
                _x;                                                     \
        })

static struct track_item* track_item_free(struct track_item *i) {

        if (!i)
                return NULL;

        sd_bus_slot_unref(i->slot);
        free(i->name);
        free(i);

        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(struct track_item*, track_item_free);

static void bus_track_add_to_queue(sd_bus_track *track) {
        assert(track);

        if (track->in_queue)
                return;

        if (!track->handler)
                return;

        LIST_PREPEND(queue, track->bus->track_queue, track);
        track->in_queue = true;
}

static void bus_track_remove_from_queue(sd_bus_track *track) {
        assert(track);

        if (!track->in_queue)
                return;

        LIST_REMOVE(queue, track->bus->track_queue, track);
        track->in_queue = false;
}

static int bus_track_remove_name_fully(sd_bus_track *track, const char *name) {
        struct track_item *i;

        assert(track);
        assert(name);

        i = hashmap_remove(track->names, name);
        if (!i)
                return 0;

        track_item_free(i);

        if (hashmap_isempty(track->names))
                bus_track_add_to_queue(track);

        track->modified = true;
        return 1;
}

_public_ int sd_bus_track_new(
                sd_bus *bus,
                sd_bus_track **track,
                sd_bus_track_handler_t handler,
                void *userdata) {

        sd_bus_track *t;

        assert_return(bus, -EINVAL);
        assert_return(track, -EINVAL);

        if (!bus->bus_client)
                return -EINVAL;

        t = new0(sd_bus_track, 1);
        if (!t)
                return -ENOMEM;

        t->n_ref = 1;
        t->handler = handler;
        t->userdata = userdata;
        t->bus = sd_bus_ref(bus);

        bus_track_add_to_queue(t);

        *track = t;
        return 0;
}

_public_ sd_bus_track* sd_bus_track_ref(sd_bus_track *track) {

        if (!track)
                return NULL;

        assert(track->n_ref > 0);

        track->n_ref++;

        return track;
}

_public_ sd_bus_track* sd_bus_track_unref(sd_bus_track *track) {
        struct track_item *i;

        if (!track)
                return NULL;

        assert(track->n_ref > 0);

        if (track->n_ref > 1) {
                track->n_ref--;
                return NULL;
        }

        while ((i = hashmap_steal_first(track->names)))
                track_item_free(i);

        bus_track_remove_from_queue(track);
        hashmap_free(track->names);
        sd_bus_unref(track->bus);
        free(track);

        return NULL;
}

static int on_name_owner_changed(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        sd_bus_track *track = userdata;
        const char *name, *old, *new;
        int r;

        assert(message);
        assert(track);

        r = sd_bus_message_read(message, "sss", &name, &old, &new);
        if (r < 0)
                return 0;

        bus_track_remove_name_fully(track, name);
        return 0;
}

_public_ int sd_bus_track_add_name(sd_bus_track *track, const char *name) {
        _cleanup_(track_item_freep) struct track_item *n = NULL;
        struct track_item *i;
        const char *match;
        int r;

        assert_return(track, -EINVAL);
        assert_return(service_name_is_valid(name), -EINVAL);

        i = hashmap_get(track->names, name);
        if (i) {
                if (track->recursive) {
                        unsigned k = track->n_ref + 1;

                        if (k < track->n_ref) /* Check for overflow */
                                return -EOVERFLOW;

                        track->n_ref = k;
                }

                bus_track_remove_from_queue(track);
                return 0;
        }

        r = hashmap_ensure_allocated(&track->names, &string_hash_ops);
        if (r < 0)
                return r;

        n = new0(struct track_item, 1);
        if (!n)
                return -ENOMEM;
        n->name = strdup(name);
        if (!n->name)
                return -ENOMEM;

        /* First, subscribe to this name */
        match = MATCH_FOR_NAME(name);
        r = sd_bus_add_match(track->bus, &n->slot, match, on_name_owner_changed, track);
        if (r < 0)
                return r;

        r = hashmap_put(track->names, n->name, n);
        if (r < 0)
                return r;

        /* Second, check if it is currently existing, or maybe doesn't, or maybe disappeared already. */
        r = sd_bus_get_name_creds(track->bus, name, 0, NULL);
        if (r < 0) {
                hashmap_remove(track->names, name);
                return r;
        }

        n->n_ref = 1;
        n = NULL;

        bus_track_remove_from_queue(track);
        track->modified = true;

        return 1;
}

_public_ int sd_bus_track_remove_name(sd_bus_track *track, const char *name) {
        struct track_item *i;

        assert_return(name, -EINVAL);

        if (!track) /* Treat a NULL track object as an empty track object */
                return 0;

        if (!track->recursive)
                return bus_track_remove_name_fully(track, name);

        i = hashmap_get(track->names, name);
        if (!i)
                return -EUNATCH;
        if (i->n_ref <= 0)
                return -EUNATCH;

        i->n_ref--;

        if (i->n_ref <= 0)
                return bus_track_remove_name_fully(track, name);

        return 1;
}

_public_ unsigned sd_bus_track_count(sd_bus_track *track) {

        if (!track) /* Let's consider a NULL object equivalent to an empty object */
                return 0;

        /* This signature really should have returned an int, so that we can propagate errors. But well, ... Also, note
         * that this returns the number of names being watched, and multiple references to the same name are not
         * counted. */

        return hashmap_size(track->names);
}

_public_ const char* sd_bus_track_contains(sd_bus_track *track, const char *name) {
        assert_return(name, NULL);

        if (!track) /* Let's consider a NULL object equivalent to an empty object */
                return NULL;

        return hashmap_get(track->names, (void*) name) ? name : NULL;
}

_public_ const char* sd_bus_track_first(sd_bus_track *track) {
        const char *n = NULL;

        if (!track)
                return NULL;

        track->modified = false;
        track->iterator = ITERATOR_FIRST;

        hashmap_iterate(track->names, &track->iterator, NULL, (const void**) &n);
        return n;
}

_public_ const char* sd_bus_track_next(sd_bus_track *track) {
        const char *n = NULL;

        if (!track)
                return NULL;

        if (track->modified)
                return NULL;

        hashmap_iterate(track->names, &track->iterator, NULL, (const void**) &n);
        return n;
}

_public_ int sd_bus_track_add_sender(sd_bus_track *track, sd_bus_message *m) {
        const char *sender;

        assert_return(track, -EINVAL);
        assert_return(m, -EINVAL);

        if (sd_bus_message_get_bus(m) != track->bus)
                return -EINVAL;

        sender = sd_bus_message_get_sender(m);
        if (!sender)
                return -EINVAL;

        return sd_bus_track_add_name(track, sender);
}

_public_ int sd_bus_track_remove_sender(sd_bus_track *track, sd_bus_message *m) {
        const char *sender;

        assert_return(m, -EINVAL);

        if (!track) /* Treat a NULL track object as an empty track object */
                return 0;

        if (sd_bus_message_get_bus(m) != track->bus)
                return -EINVAL;

        sender = sd_bus_message_get_sender(m);
        if (!sender)
                return -EINVAL;

        return sd_bus_track_remove_name(track, sender);
}

_public_ sd_bus* sd_bus_track_get_bus(sd_bus_track *track) {
        assert_return(track, NULL);

        return track->bus;
}

void bus_track_dispatch(sd_bus_track *track) {
        int r;

        assert(track);
        assert(track->in_queue);
        assert(track->handler);

        bus_track_remove_from_queue(track);

        sd_bus_track_ref(track);

        r = track->handler(track, track->userdata);
        if (r < 0)
                log_debug_errno(r, "Failed to process track handler: %m");
        else if (r == 0)
                bus_track_add_to_queue(track);

        sd_bus_track_unref(track);
}

_public_ void *sd_bus_track_get_userdata(sd_bus_track *track) {
        assert_return(track, NULL);

        return track->userdata;
}

_public_ void *sd_bus_track_set_userdata(sd_bus_track *track, void *userdata) {
        void *ret;

        assert_return(track, NULL);

        ret = track->userdata;
        track->userdata = userdata;

        return ret;
}

_public_ int sd_bus_track_set_recursive(sd_bus_track *track, int b) {
        assert_return(track, -EINVAL);

        if (track->recursive == !!b)
                return 0;

        if (!hashmap_isempty(track->names))
                return -EBUSY;

        track->recursive = b;
        return 0;
}

_public_ int sd_bus_track_get_recursive(sd_bus_track *track) {
        assert_return(track, -EINVAL);

        return track->recursive;
}

_public_ int sd_bus_track_count_sender(sd_bus_track *track, sd_bus_message *m) {
        const char *sender;

        assert_return(m, -EINVAL);

        if (!track) /* Let's consider a NULL object equivalent to an empty object */
                return 0;

        if (sd_bus_message_get_bus(m) != track->bus)
                return -EINVAL;

        sender = sd_bus_message_get_sender(m);
        if (!sender)
                return -EINVAL;

        return sd_bus_track_count_name(track, sender);
}

_public_ int sd_bus_track_count_name(sd_bus_track *track, const char *name) {
        struct track_item *i;

        assert_return(service_name_is_valid(name), -EINVAL);

        if (!track) /* Let's consider a NULL object equivalent to an empty object */
                return 0;

        i = hashmap_get(track->names, name);
        if (!i)
                return 0;

        return i->n_ref;
}
