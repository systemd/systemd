/* SPDX-License-Identifier: LGPL-2.1+ */

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
        unsigned n_adding; /* are we in the process of adding a new name? */
        sd_bus *bus;
        sd_bus_track_handler_t handler;
        void *userdata;
        Hashmap *names;
        LIST_FIELDS(sd_bus_track, queue);
        Iterator iterator;
        bool in_list:1;    /* In bus->tracks? */
        bool in_queue:1;   /* In bus->track_queue? */
        bool modified:1;
        bool recursive:1;
        sd_bus_destroy_t destroy_callback;

        LIST_FIELDS(sd_bus_track, tracks);
};

#define MATCH_FOR_NAME(name)                            \
        strjoina("type='signal',"                       \
                 "sender='org.freedesktop.DBus',"       \
                 "path='/org/freedesktop/DBus',"        \
                 "interface='org.freedesktop.DBus',"    \
                 "member='NameOwnerChanged',"           \
                 "arg0='", name, "'")

static struct track_item* track_item_free(struct track_item *i) {

        if (!i)
                return NULL;

        sd_bus_slot_unref(i->slot);
        free(i->name);
        return mfree(i);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(struct track_item*, track_item_free);

static void bus_track_add_to_queue(sd_bus_track *track) {
        assert(track);

        /* Adds the bus track object to the queue of objects we should dispatch next, subject to a number of
         * conditions. */

        /* Already in the queue? */
        if (track->in_queue)
                return;

        /* if we are currently in the process of adding a new name, then let's not enqueue this just yet, let's wait
         * until the addition is complete. */
        if (track->n_adding > 0)
                return;

        /* still referenced? */
        if (hashmap_size(track->names) > 0)
                return;

        /* Nothing to call? */
        if (!track->handler)
                return;

        /* Already closed? */
        if (!track->in_list)
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
        assert_return(bus = bus_resolve(bus), -ENOPKG);
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

        LIST_PREPEND(tracks, bus->tracks, t);
        t->in_list = true;

        bus_track_add_to_queue(t);

        *track = t;
        return 0;
}

static sd_bus_track *track_free(sd_bus_track *track) {
        assert(track);

        if (track->in_list)
                LIST_REMOVE(tracks, track->bus->tracks, track);

        bus_track_remove_from_queue(track);
        track->names = hashmap_free_with_destructor(track->names, track_item_free);
        track->bus = sd_bus_unref(track->bus);

        if (track->destroy_callback)
                track->destroy_callback(track->userdata);

        return mfree(track);
}

DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(sd_bus_track, sd_bus_track, track_free);

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

        bus_track_remove_from_queue(track); /* don't dispatch this while we work in it */

        r = sd_bus_add_match_async(track->bus, &n->slot, match, on_name_owner_changed, NULL, track);
        if (r < 0) {
                bus_track_add_to_queue(track);
                return r;
        }

        r = hashmap_put(track->names, n->name, n);
        if (r < 0) {
                bus_track_add_to_queue(track);
                return r;
        }

        /* Second, check if it is currently existing, or maybe doesn't, or maybe disappeared already. */
        track->n_adding++; /* again, make sure this isn't dispatch while we are working in it */
        r = sd_bus_get_name_creds(track->bus, name, 0, NULL);
        track->n_adding--;
        if (r < 0) {
                hashmap_remove(track->names, name);
                bus_track_add_to_queue(track);
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

void bus_track_close(sd_bus_track *track) {
        assert(track);

        /* Called whenever our bus connected is closed. If so, and our track object is non-empty, dispatch it
         * immediately, as we are closing now, but first flush out all names. */

        if (!track->in_list)
                return; /* We already closed this one, don't close it again. */

        /* Remember that this one is closed now */
        LIST_REMOVE(tracks, track->bus->tracks, track);
        track->in_list = false;

        /* If there's no name in this one anyway, we don't have to dispatch */
        if (hashmap_isempty(track->names))
                return;

        /* Let's flush out all names */
        hashmap_clear_with_destructor(track->names, track_item_free);

        /* Invoke handler */
        if (track->handler)
                bus_track_dispatch(track);
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

_public_ int sd_bus_track_set_destroy_callback(sd_bus_track *track, sd_bus_destroy_t callback) {
        assert_return(track, -EINVAL);

        track->destroy_callback = callback;
        return 0;
}

_public_ int sd_bus_track_get_destroy_callback(sd_bus_track *track, sd_bus_destroy_t *ret) {
        assert_return(track, -EINVAL);

        if (ret)
                *ret = track->destroy_callback;

        return !!track->destroy_callback;
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
