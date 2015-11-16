/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include "alloc-util.h"
#include "bus-internal.h"
#include "bus-introspect.h"
#include "bus-message.h"
#include "bus-objects.h"
#include "bus-signature.h"
#include "bus-slot.h"
#include "bus-type.h"
#include "bus-util.h"
#include "set.h"
#include "string-util.h"
#include "strv.h"

static int node_vtable_get_userdata(
                sd_bus *bus,
                const char *path,
                struct node_vtable *c,
                void **userdata,
                sd_bus_error *error) {

        sd_bus_slot *s;
        void *u;
        int r;

        assert(bus);
        assert(path);
        assert(c);

        s = container_of(c, sd_bus_slot, node_vtable);
        u = s->userdata;
        if (c->find) {
                bus->current_slot = sd_bus_slot_ref(s);
                bus->current_userdata = u;
                r = c->find(bus, path, c->interface, u, &u, error);
                bus->current_userdata = NULL;
                bus->current_slot = sd_bus_slot_unref(s);

                if (r < 0)
                        return r;
                if (sd_bus_error_is_set(error))
                        return -sd_bus_error_get_errno(error);
                if (r == 0)
                        return r;
        }

        if (userdata)
                *userdata = u;

        return 1;
}

static void *vtable_method_convert_userdata(const sd_bus_vtable *p, void *u) {
        assert(p);

        return (uint8_t*) u + p->x.method.offset;
}

static void *vtable_property_convert_userdata(const sd_bus_vtable *p, void *u) {
        assert(p);

        return (uint8_t*) u + p->x.property.offset;
}

static int vtable_property_get_userdata(
                sd_bus *bus,
                const char *path,
                struct vtable_member *p,
                void **userdata,
                sd_bus_error *error) {

        void *u;
        int r;

        assert(bus);
        assert(path);
        assert(p);
        assert(userdata);

        r = node_vtable_get_userdata(bus, path, p->parent, &u, error);
        if (r <= 0)
                return r;
        if (bus->nodes_modified)
                return 0;

        *userdata = vtable_property_convert_userdata(p->vtable, u);
        return 1;
}

static int add_enumerated_to_set(
                sd_bus *bus,
                const char *prefix,
                struct node_enumerator *first,
                Set *s,
                sd_bus_error *error) {

        struct node_enumerator *c;
        int r;

        assert(bus);
        assert(prefix);
        assert(s);

        LIST_FOREACH(enumerators, c, first) {
                char **children = NULL, **k;
                sd_bus_slot *slot;

                if (bus->nodes_modified)
                        return 0;

                slot = container_of(c, sd_bus_slot, node_enumerator);

                bus->current_slot = sd_bus_slot_ref(slot);
                bus->current_userdata = slot->userdata;
                r = c->callback(bus, prefix, slot->userdata, &children, error);
                bus->current_userdata = NULL;
                bus->current_slot = sd_bus_slot_unref(slot);

                if (r < 0)
                        return r;
                if (sd_bus_error_is_set(error))
                        return -sd_bus_error_get_errno(error);

                STRV_FOREACH(k, children) {
                        if (r < 0) {
                                free(*k);
                                continue;
                        }

                        if (!object_path_is_valid(*k)){
                                free(*k);
                                r = -EINVAL;
                                continue;
                        }

                        if (!object_path_startswith(*k, prefix)) {
                                free(*k);
                                continue;
                        }

                        r = set_consume(s, *k);
                        if (r == -EEXIST)
                                r = 0;
                }

                free(children);
                if (r < 0)
                        return r;
        }

        return 0;
}

enum {
        /* if set, add_subtree() works recursively */
        CHILDREN_RECURSIVE              = (1U << 1),
        /* if set, add_subtree() scans object-manager hierarchies recursively */
        CHILDREN_SUBHIERARCHIES         = (1U << 0),
};

static int add_subtree_to_set(
                sd_bus *bus,
                const char *prefix,
                struct node *n,
                unsigned int flags,
                Set *s,
                sd_bus_error *error) {

        struct node *i;
        int r;

        assert(bus);
        assert(prefix);
        assert(n);
        assert(s);

        r = add_enumerated_to_set(bus, prefix, n->enumerators, s, error);
        if (r < 0)
                return r;
        if (bus->nodes_modified)
                return 0;

        LIST_FOREACH(siblings, i, n->child) {
                char *t;

                if (!object_path_startswith(i->path, prefix))
                        continue;

                t = strdup(i->path);
                if (!t)
                        return -ENOMEM;

                r = set_consume(s, t);
                if (r < 0 && r != -EEXIST)
                        return r;

                if ((flags & CHILDREN_RECURSIVE) &&
                    ((flags & CHILDREN_SUBHIERARCHIES) || !i->object_managers)) {
                        r = add_subtree_to_set(bus, prefix, i, flags, s, error);
                        if (r < 0)
                                return r;
                        if (bus->nodes_modified)
                                return 0;
                }
        }

        return 0;
}

static int get_child_nodes(
                sd_bus *bus,
                const char *prefix,
                struct node *n,
                unsigned int flags,
                Set **_s,
                sd_bus_error *error) {

        Set *s = NULL;
        int r;

        assert(bus);
        assert(prefix);
        assert(n);
        assert(_s);

        s = set_new(&string_hash_ops);
        if (!s)
                return -ENOMEM;

        r = add_subtree_to_set(bus, prefix, n, flags, s, error);
        if (r < 0) {
                set_free_free(s);
                return r;
        }

        *_s = s;
        return 0;
}

static int node_callbacks_run(
                sd_bus *bus,
                sd_bus_message *m,
                struct node_callback *first,
                bool require_fallback,
                bool *found_object) {

        struct node_callback *c;
        int r;

        assert(bus);
        assert(m);
        assert(found_object);

        LIST_FOREACH(callbacks, c, first) {
                _cleanup_bus_error_free_ sd_bus_error error_buffer = SD_BUS_ERROR_NULL;
                sd_bus_slot *slot;

                if (bus->nodes_modified)
                        return 0;

                if (require_fallback && !c->is_fallback)
                        continue;

                *found_object = true;

                if (c->last_iteration == bus->iteration_counter)
                        continue;

                c->last_iteration = bus->iteration_counter;

                r = sd_bus_message_rewind(m, true);
                if (r < 0)
                        return r;

                slot = container_of(c, sd_bus_slot, node_callback);

                bus->current_slot = sd_bus_slot_ref(slot);
                bus->current_handler = c->callback;
                bus->current_userdata = slot->userdata;
                r = c->callback(m, slot->userdata, &error_buffer);
                bus->current_userdata = NULL;
                bus->current_handler = NULL;
                bus->current_slot = sd_bus_slot_unref(slot);

                r = bus_maybe_reply_error(m, r, &error_buffer);
                if (r != 0)
                        return r;
        }

        return 0;
}

#define CAPABILITY_SHIFT(x) (((x) >> __builtin_ctzll(_SD_BUS_VTABLE_CAPABILITY_MASK)) & 0xFFFF)

static int check_access(sd_bus *bus, sd_bus_message *m, struct vtable_member *c, sd_bus_error *error) {
        uint64_t cap;
        int r;

        assert(bus);
        assert(m);
        assert(c);

        /* If the entire bus is trusted let's grant access */
        if (bus->trusted)
                return 0;

        /* If the member is marked UNPRIVILEGED let's grant access */
        if (c->vtable->flags & SD_BUS_VTABLE_UNPRIVILEGED)
                return 0;

        /* Check have the caller has the requested capability
         * set. Note that the flags value contains the capability
         * number plus one, which we need to subtract here. We do this
         * so that we have 0 as special value for "default
         * capability". */
        cap = CAPABILITY_SHIFT(c->vtable->flags);
        if (cap == 0)
                cap = CAPABILITY_SHIFT(c->parent->vtable[0].flags);
        if (cap == 0)
                cap = CAP_SYS_ADMIN;
        else
                cap --;

        r = sd_bus_query_sender_privilege(m, cap);
        if (r < 0)
                return r;
        if (r > 0)
                return 0;

        return sd_bus_error_setf(error, SD_BUS_ERROR_ACCESS_DENIED, "Access to %s.%s() not permitted.", c->interface, c->member);
}

static int method_callbacks_run(
                sd_bus *bus,
                sd_bus_message *m,
                struct vtable_member *c,
                bool require_fallback,
                bool *found_object) {

        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *signature;
        void *u;
        int r;

        assert(bus);
        assert(m);
        assert(c);
        assert(found_object);

        if (require_fallback && !c->parent->is_fallback)
                return 0;

        r = check_access(bus, m, c, &error);
        if (r < 0)
                return bus_maybe_reply_error(m, r, &error);

        r = node_vtable_get_userdata(bus, m->path, c->parent, &u, &error);
        if (r <= 0)
                return bus_maybe_reply_error(m, r, &error);
        if (bus->nodes_modified)
                return 0;

        u = vtable_method_convert_userdata(c->vtable, u);

        *found_object = true;

        if (c->last_iteration == bus->iteration_counter)
                return 0;

        c->last_iteration = bus->iteration_counter;

        r = sd_bus_message_rewind(m, true);
        if (r < 0)
                return r;

        signature = sd_bus_message_get_signature(m, true);
        if (!signature)
                return -EINVAL;

        if (!streq(strempty(c->vtable->x.method.signature), signature))
                return sd_bus_reply_method_errorf(
                                m,
                                SD_BUS_ERROR_INVALID_ARGS,
                                "Invalid arguments '%s' to call %s.%s(), expecting '%s'.",
                                signature, c->interface, c->member, strempty(c->vtable->x.method.signature));

        /* Keep track what the signature of the reply to this message
         * should be, so that this can be enforced when sealing the
         * reply. */
        m->enforced_reply_signature = strempty(c->vtable->x.method.result);

        if (c->vtable->x.method.handler) {
                sd_bus_slot *slot;

                slot = container_of(c->parent, sd_bus_slot, node_vtable);

                bus->current_slot = sd_bus_slot_ref(slot);
                bus->current_handler = c->vtable->x.method.handler;
                bus->current_userdata = u;
                r = c->vtable->x.method.handler(m, u, &error);
                bus->current_userdata = NULL;
                bus->current_handler = NULL;
                bus->current_slot = sd_bus_slot_unref(slot);

                return bus_maybe_reply_error(m, r, &error);
        }

        /* If the method callback is NULL, make this a successful NOP */
        r = sd_bus_reply_method_return(m, NULL);
        if (r < 0)
                return r;

        return 1;
}

static int invoke_property_get(
                sd_bus *bus,
                sd_bus_slot *slot,
                const sd_bus_vtable *v,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        const void *p;
        int r;

        assert(bus);
        assert(slot);
        assert(v);
        assert(path);
        assert(interface);
        assert(property);
        assert(reply);

        if (v->x.property.get) {

                bus->current_slot = sd_bus_slot_ref(slot);
                bus->current_userdata = userdata;
                r = v->x.property.get(bus, path, interface, property, reply, userdata, error);
                bus->current_userdata = NULL;
                bus->current_slot = sd_bus_slot_unref(slot);

                if (r < 0)
                        return r;
                if (sd_bus_error_is_set(error))
                        return -sd_bus_error_get_errno(error);
                return r;
        }

        /* Automatic handling if no callback is defined. */

        if (streq(v->x.property.signature, "as"))
                return sd_bus_message_append_strv(reply, *(char***) userdata);

        assert(signature_is_single(v->x.property.signature, false));
        assert(bus_type_is_basic(v->x.property.signature[0]));

        switch (v->x.property.signature[0]) {

        case SD_BUS_TYPE_STRING:
        case SD_BUS_TYPE_SIGNATURE:
                p = strempty(*(char**) userdata);
                break;

        case SD_BUS_TYPE_OBJECT_PATH:
                p = *(char**) userdata;
                assert(p);
                break;

        default:
                p = userdata;
                break;
        }

        return sd_bus_message_append_basic(reply, v->x.property.signature[0], p);
}

static int invoke_property_set(
                sd_bus *bus,
                sd_bus_slot *slot,
                const sd_bus_vtable *v,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *value,
                void *userdata,
                sd_bus_error *error) {

        int r;

        assert(bus);
        assert(slot);
        assert(v);
        assert(path);
        assert(interface);
        assert(property);
        assert(value);

        if (v->x.property.set) {

                bus->current_slot = sd_bus_slot_ref(slot);
                bus->current_userdata = userdata;
                r = v->x.property.set(bus, path, interface, property, value, userdata, error);
                bus->current_userdata = NULL;
                bus->current_slot = sd_bus_slot_unref(slot);

                if (r < 0)
                        return r;
                if (sd_bus_error_is_set(error))
                        return -sd_bus_error_get_errno(error);
                return r;
        }

        /*  Automatic handling if no callback is defined. */

        assert(signature_is_single(v->x.property.signature, false));
        assert(bus_type_is_basic(v->x.property.signature[0]));

        switch (v->x.property.signature[0]) {

        case SD_BUS_TYPE_STRING:
        case SD_BUS_TYPE_OBJECT_PATH:
        case SD_BUS_TYPE_SIGNATURE: {
                const char *p;
                char *n;

                r = sd_bus_message_read_basic(value, v->x.property.signature[0], &p);
                if (r < 0)
                        return r;

                n = strdup(p);
                if (!n)
                        return -ENOMEM;

                free(*(char**) userdata);
                *(char**) userdata = n;

                break;
        }

        default:
                r = sd_bus_message_read_basic(value, v->x.property.signature[0], userdata);
                if (r < 0)
                        return r;

                break;
        }

        return 1;
}

static int property_get_set_callbacks_run(
                sd_bus *bus,
                sd_bus_message *m,
                struct vtable_member *c,
                bool require_fallback,
                bool is_get,
                bool *found_object) {

        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        sd_bus_slot *slot;
        void *u = NULL;
        int r;

        assert(bus);
        assert(m);
        assert(c);
        assert(found_object);

        if (require_fallback && !c->parent->is_fallback)
                return 0;

        r = vtable_property_get_userdata(bus, m->path, c, &u, &error);
        if (r <= 0)
                return bus_maybe_reply_error(m, r, &error);
        if (bus->nodes_modified)
                return 0;

        slot = container_of(c->parent, sd_bus_slot, node_vtable);

        *found_object = true;

        r = sd_bus_message_new_method_return(m, &reply);
        if (r < 0)
                return r;

        if (is_get) {
                /* Note that we do not protect against reexecution
                 * here (using the last_iteration check, see below),
                 * should the node tree have changed and we got called
                 * again. We assume that property Get() calls are
                 * ultimately without side-effects or if they aren't
                 * then at least idempotent. */

                r = sd_bus_message_open_container(reply, 'v', c->vtable->x.property.signature);
                if (r < 0)
                        return r;

                /* Note that we do not do an access check here. Read
                 * access to properties is always unrestricted, since
                 * PropertiesChanged signals broadcast contents
                 * anyway. */

                r = invoke_property_get(bus, slot, c->vtable, m->path, c->interface, c->member, reply, u, &error);
                if (r < 0)
                        return bus_maybe_reply_error(m, r, &error);

                if (bus->nodes_modified)
                        return 0;

                r = sd_bus_message_close_container(reply);
                if (r < 0)
                        return r;

        } else {
                const char *signature = NULL;
                char type = 0;

                if (c->vtable->type != _SD_BUS_VTABLE_WRITABLE_PROPERTY)
                        return sd_bus_reply_method_errorf(m, SD_BUS_ERROR_PROPERTY_READ_ONLY, "Property '%s' is not writable.", c->member);

                /* Avoid that we call the set routine more than once
                 * if the processing of this message got restarted
                 * because the node tree changed. */
                if (c->last_iteration == bus->iteration_counter)
                        return 0;

                c->last_iteration = bus->iteration_counter;

                r = sd_bus_message_peek_type(m, &type, &signature);
                if (r < 0)
                        return r;

                if (type != 'v' || !streq(strempty(signature), strempty(c->vtable->x.property.signature)))
                        return sd_bus_reply_method_errorf(m, SD_BUS_ERROR_INVALID_ARGS, "Incorrect parameters for property '%s', expected '%s', got '%s'.", c->member, strempty(c->vtable->x.property.signature), strempty(signature));

                r = sd_bus_message_enter_container(m, 'v', c->vtable->x.property.signature);
                if (r < 0)
                        return r;

                r = check_access(bus, m, c, &error);
                if (r < 0)
                        return bus_maybe_reply_error(m, r, &error);

                r = invoke_property_set(bus, slot, c->vtable, m->path, c->interface, c->member, m, u, &error);
                if (r < 0)
                        return bus_maybe_reply_error(m, r, &error);

                if (bus->nodes_modified)
                        return 0;

                r = sd_bus_message_exit_container(m);
                if (r < 0)
                        return r;
        }

        r = sd_bus_send(bus, reply, NULL);
        if (r < 0)
                return r;

        return 1;
}

static int vtable_append_one_property(
                sd_bus *bus,
                sd_bus_message *reply,
                const char *path,
                struct node_vtable *c,
                const sd_bus_vtable *v,
                void *userdata,
                sd_bus_error *error) {

        sd_bus_slot *slot;
        int r;

        assert(bus);
        assert(reply);
        assert(path);
        assert(c);
        assert(v);

        r = sd_bus_message_open_container(reply, 'e', "sv");
        if (r < 0)
                return r;

        r = sd_bus_message_append(reply, "s", v->x.property.member);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'v', v->x.property.signature);
        if (r < 0)
                return r;

        slot = container_of(c, sd_bus_slot, node_vtable);

        r = invoke_property_get(bus, slot, v, path, c->interface, v->x.property.member, reply, vtable_property_convert_userdata(v, userdata), error);
        if (r < 0)
                return r;
        if (bus->nodes_modified)
                return 0;

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return 0;
}

static int vtable_append_all_properties(
                sd_bus *bus,
                sd_bus_message *reply,
                const char *path,
                struct node_vtable *c,
                void *userdata,
                sd_bus_error *error) {

        const sd_bus_vtable *v;
        int r;

        assert(bus);
        assert(reply);
        assert(path);
        assert(c);

        if (c->vtable[0].flags & SD_BUS_VTABLE_HIDDEN)
                return 1;

        for (v = c->vtable+1; v->type != _SD_BUS_VTABLE_END; v++) {
                if (v->type != _SD_BUS_VTABLE_PROPERTY && v->type != _SD_BUS_VTABLE_WRITABLE_PROPERTY)
                        continue;

                if (v->flags & SD_BUS_VTABLE_HIDDEN)
                        continue;

                if (v->flags & SD_BUS_VTABLE_PROPERTY_EXPLICIT)
                        continue;

                r = vtable_append_one_property(bus, reply, path, c, v, userdata, error);
                if (r < 0)
                        return r;
                if (bus->nodes_modified)
                        return 0;
        }

        return 1;
}

static int property_get_all_callbacks_run(
                sd_bus *bus,
                sd_bus_message *m,
                struct node_vtable *first,
                bool require_fallback,
                const char *iface,
                bool *found_object) {

        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        struct node_vtable *c;
        bool found_interface;
        int r;

        assert(bus);
        assert(m);
        assert(found_object);

        r = sd_bus_message_new_method_return(m, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "{sv}");
        if (r < 0)
                return r;

        found_interface = !iface ||
                streq(iface, "org.freedesktop.DBus.Properties") ||
                streq(iface, "org.freedesktop.DBus.Peer") ||
                streq(iface, "org.freedesktop.DBus.Introspectable");

        LIST_FOREACH(vtables, c, first) {
                _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
                void *u;

                if (require_fallback && !c->is_fallback)
                        continue;

                r = node_vtable_get_userdata(bus, m->path, c, &u, &error);
                if (r < 0)
                        return bus_maybe_reply_error(m, r, &error);
                if (bus->nodes_modified)
                        return 0;
                if (r == 0)
                        continue;

                *found_object = true;

                if (iface && !streq(c->interface, iface))
                        continue;
                found_interface = true;

                r = vtable_append_all_properties(bus, reply, m->path, c, u, &error);
                if (r < 0)
                        return bus_maybe_reply_error(m, r, &error);
                if (bus->nodes_modified)
                        return 0;
        }

        if (!found_interface) {
                r = sd_bus_reply_method_errorf(
                                m,
                                SD_BUS_ERROR_UNKNOWN_INTERFACE,
                                "Unknown interface '%s'.", iface);
                if (r < 0)
                        return r;

                return 1;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        r = sd_bus_send(bus, reply, NULL);
        if (r < 0)
                return r;

        return 1;
}

static int bus_node_exists(
                sd_bus *bus,
                struct node *n,
                const char *path,
                bool require_fallback) {

        struct node_vtable *c;
        struct node_callback *k;
        int r;

        assert(bus);
        assert(n);
        assert(path);

        /* Tests if there's anything attached directly to this node
         * for the specified path */

        if (!require_fallback && (n->enumerators || n->object_managers))
                return true;

        LIST_FOREACH(callbacks, k, n->callbacks) {
                if (require_fallback && !k->is_fallback)
                        continue;

                return 1;
        }

        LIST_FOREACH(vtables, c, n->vtables) {
                _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;

                if (require_fallback && !c->is_fallback)
                        continue;

                r = node_vtable_get_userdata(bus, path, c, NULL, &error);
                if (r != 0)
                        return r;
                if (bus->nodes_modified)
                        return 0;
        }

        return 0;
}

static int process_introspect(
                sd_bus *bus,
                sd_bus_message *m,
                struct node *n,
                bool require_fallback,
                bool *found_object) {

        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_set_free_free_ Set *s = NULL;
        const char *previous_interface = NULL;
        struct introspect intro;
        struct node_vtable *c;
        bool empty;
        int r;

        assert(bus);
        assert(m);
        assert(n);
        assert(found_object);

        r = get_child_nodes(bus, m->path, n, 0, &s, &error);
        if (r < 0)
                return bus_maybe_reply_error(m, r, &error);
        if (bus->nodes_modified)
                return 0;

        r = introspect_begin(&intro, bus->trusted);
        if (r < 0)
                return r;

        r = introspect_write_default_interfaces(&intro, !require_fallback && n->object_managers);
        if (r < 0)
                return r;

        empty = set_isempty(s);

        LIST_FOREACH(vtables, c, n->vtables) {
                if (require_fallback && !c->is_fallback)
                        continue;

                r = node_vtable_get_userdata(bus, m->path, c, NULL, &error);
                if (r < 0) {
                        r = bus_maybe_reply_error(m, r, &error);
                        goto finish;
                }
                if (bus->nodes_modified) {
                        r = 0;
                        goto finish;
                }
                if (r == 0)
                        continue;

                empty = false;

                if (c->vtable[0].flags & SD_BUS_VTABLE_HIDDEN)
                        continue;

                if (!streq_ptr(previous_interface, c->interface)) {

                        if (previous_interface)
                                fputs(" </interface>\n", intro.f);

                        fprintf(intro.f, " <interface name=\"%s\">\n", c->interface);
                }

                r = introspect_write_interface(&intro, c->vtable);
                if (r < 0)
                        goto finish;

                previous_interface = c->interface;
        }

        if (previous_interface)
                fputs(" </interface>\n", intro.f);

        if (empty) {
                /* Nothing?, let's see if we exist at all, and if not
                 * refuse to do anything */
                r = bus_node_exists(bus, n, m->path, require_fallback);
                if (r <= 0)
                        goto finish;
                if (bus->nodes_modified) {
                        r = 0;
                        goto finish;
                }
        }

        *found_object = true;

        r = introspect_write_child_nodes(&intro, s, m->path);
        if (r < 0)
                goto finish;

        r = introspect_finish(&intro, bus, m, &reply);
        if (r < 0)
                goto finish;

        r = sd_bus_send(bus, reply, NULL);
        if (r < 0)
                goto finish;

        r = 1;

finish:
        introspect_free(&intro);
        return r;
}

static int object_manager_serialize_path(
                sd_bus *bus,
                sd_bus_message *reply,
                const char *prefix,
                const char *path,
                bool require_fallback,
                sd_bus_error *error) {

        const char *previous_interface = NULL;
        bool found_something = false;
        struct node_vtable *i;
        struct node *n;
        int r;

        assert(bus);
        assert(reply);
        assert(prefix);
        assert(path);
        assert(error);

        n = hashmap_get(bus->nodes, prefix);
        if (!n)
                return 0;

        LIST_FOREACH(vtables, i, n->vtables) {
                void *u;

                if (require_fallback && !i->is_fallback)
                        continue;

                r = node_vtable_get_userdata(bus, path, i, &u, error);
                if (r < 0)
                        return r;
                if (bus->nodes_modified)
                        return 0;
                if (r == 0)
                        continue;

                if (!found_something) {

                        /* Open the object part */

                        r = sd_bus_message_open_container(reply, 'e', "oa{sa{sv}}");
                        if (r < 0)
                                return r;

                        r = sd_bus_message_append(reply, "o", path);
                        if (r < 0)
                                return r;

                        r = sd_bus_message_open_container(reply, 'a', "{sa{sv}}");
                        if (r < 0)
                                return r;

                        found_something = true;
                }

                if (!streq_ptr(previous_interface, i->interface)) {

                        /* Maybe close the previous interface part */

                        if (previous_interface) {
                                r = sd_bus_message_close_container(reply);
                                if (r < 0)
                                        return r;

                                r = sd_bus_message_close_container(reply);
                                if (r < 0)
                                        return r;
                        }

                        /* Open the new interface part */

                        r = sd_bus_message_open_container(reply, 'e', "sa{sv}");
                        if (r < 0)
                                return r;

                        r = sd_bus_message_append(reply, "s", i->interface);
                        if (r < 0)
                                return r;

                        r = sd_bus_message_open_container(reply, 'a', "{sv}");
                        if (r < 0)
                                return r;
                }

                r = vtable_append_all_properties(bus, reply, path, i, u, error);
                if (r < 0)
                        return r;
                if (bus->nodes_modified)
                        return 0;

                previous_interface = i->interface;
        }

        if (previous_interface) {
                r = sd_bus_message_close_container(reply);
                if (r < 0)
                        return r;

                r = sd_bus_message_close_container(reply);
                if (r < 0)
                        return r;
        }

        if (found_something) {
                r = sd_bus_message_close_container(reply);
                if (r < 0)
                        return r;

                r = sd_bus_message_close_container(reply);
                if (r < 0)
                        return r;
        }

        return 1;
}

static int object_manager_serialize_path_and_fallbacks(
                sd_bus *bus,
                sd_bus_message *reply,
                const char *path,
                sd_bus_error *error) {

        char *prefix;
        int r;

        assert(bus);
        assert(reply);
        assert(path);
        assert(error);

        /* First, add all vtables registered for this path */
        r = object_manager_serialize_path(bus, reply, path, path, false, error);
        if (r < 0)
                return r;
        if (bus->nodes_modified)
                return 0;

        /* Second, add fallback vtables registered for any of the prefixes */
        prefix = alloca(strlen(path) + 1);
        OBJECT_PATH_FOREACH_PREFIX(prefix, path) {
                r = object_manager_serialize_path(bus, reply, prefix, path, true, error);
                if (r < 0)
                        return r;
                if (bus->nodes_modified)
                        return 0;
        }

        return 0;
}

static int process_get_managed_objects(
                sd_bus *bus,
                sd_bus_message *m,
                struct node *n,
                bool require_fallback,
                bool *found_object) {

        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_set_free_free_ Set *s = NULL;
        Iterator i;
        char *path;
        int r;

        assert(bus);
        assert(m);
        assert(n);
        assert(found_object);

        /* Spec says, GetManagedObjects() is only implemented on the root of a
         * sub-tree. Therefore, we require a registered object-manager on
         * exactly the queried path, otherwise, we refuse to respond. */

        if (require_fallback || !n->object_managers)
                return 0;

        r = get_child_nodes(bus, m->path, n, CHILDREN_RECURSIVE, &s, &error);
        if (r < 0)
                return r;
        if (bus->nodes_modified)
                return 0;

        r = sd_bus_message_new_method_return(m, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "{oa{sa{sv}}}");
        if (r < 0)
                return r;

        SET_FOREACH(path, s, i) {
                r = object_manager_serialize_path_and_fallbacks(bus, reply, path, &error);
                if (r < 0)
                        return r;

                if (bus->nodes_modified)
                        return 0;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        r = sd_bus_send(bus, reply, NULL);
        if (r < 0)
                return r;

        return 1;
}

static int object_find_and_run(
                sd_bus *bus,
                sd_bus_message *m,
                const char *p,
                bool require_fallback,
                bool *found_object) {

        struct node *n;
        struct vtable_member vtable_key, *v;
        int r;

        assert(bus);
        assert(m);
        assert(p);
        assert(found_object);

        n = hashmap_get(bus->nodes, p);
        if (!n)
                return 0;

        /* First, try object callbacks */
        r = node_callbacks_run(bus, m, n->callbacks, require_fallback, found_object);
        if (r != 0)
                return r;
        if (bus->nodes_modified)
                return 0;

        if (!m->interface || !m->member)
                return 0;

        /* Then, look for a known method */
        vtable_key.path = (char*) p;
        vtable_key.interface = m->interface;
        vtable_key.member = m->member;

        v = hashmap_get(bus->vtable_methods, &vtable_key);
        if (v) {
                r = method_callbacks_run(bus, m, v, require_fallback, found_object);
                if (r != 0)
                        return r;
                if (bus->nodes_modified)
                        return 0;
        }

        /* Then, look for a known property */
        if (streq(m->interface, "org.freedesktop.DBus.Properties")) {
                bool get = false;

                get = streq(m->member, "Get");

                if (get || streq(m->member, "Set")) {

                        r = sd_bus_message_rewind(m, true);
                        if (r < 0)
                                return r;

                        vtable_key.path = (char*) p;

                        r = sd_bus_message_read(m, "ss", &vtable_key.interface, &vtable_key.member);
                        if (r < 0)
                                return sd_bus_reply_method_errorf(m, SD_BUS_ERROR_INVALID_ARGS, "Expected interface and member parameters");

                        v = hashmap_get(bus->vtable_properties, &vtable_key);
                        if (v) {
                                r = property_get_set_callbacks_run(bus, m, v, require_fallback, get, found_object);
                                if (r != 0)
                                        return r;
                        }

                } else if (streq(m->member, "GetAll")) {
                        const char *iface;

                        r = sd_bus_message_rewind(m, true);
                        if (r < 0)
                                return r;

                        r = sd_bus_message_read(m, "s", &iface);
                        if (r < 0)
                                return sd_bus_reply_method_errorf(m, SD_BUS_ERROR_INVALID_ARGS, "Expected interface parameter");

                        if (iface[0] == 0)
                                iface = NULL;

                        r = property_get_all_callbacks_run(bus, m, n->vtables, require_fallback, iface, found_object);
                        if (r != 0)
                                return r;
                }

        } else if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus.Introspectable", "Introspect")) {

                if (!isempty(sd_bus_message_get_signature(m, true)))
                        return sd_bus_reply_method_errorf(m, SD_BUS_ERROR_INVALID_ARGS, "Expected no parameters");

                r = process_introspect(bus, m, n, require_fallback, found_object);
                if (r != 0)
                        return r;

        } else if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus.ObjectManager", "GetManagedObjects")) {

                if (!isempty(sd_bus_message_get_signature(m, true)))
                        return sd_bus_reply_method_errorf(m, SD_BUS_ERROR_INVALID_ARGS, "Expected no parameters");

                r = process_get_managed_objects(bus, m, n, require_fallback, found_object);
                if (r != 0)
                        return r;
        }

        if (bus->nodes_modified)
                return 0;

        if (!*found_object) {
                r = bus_node_exists(bus, n, m->path, require_fallback);
                if (r < 0)
                        return r;
                if (bus->nodes_modified)
                        return 0;
                if (r > 0)
                        *found_object = true;
        }

        return 0;
}

int bus_process_object(sd_bus *bus, sd_bus_message *m) {
        int r;
        size_t pl;
        bool found_object = false;

        assert(bus);
        assert(m);

        if (bus->hello_flags & KDBUS_HELLO_MONITOR)
                return 0;

        if (m->header->type != SD_BUS_MESSAGE_METHOD_CALL)
                return 0;

        if (hashmap_isempty(bus->nodes))
                return 0;

        /* Never respond to broadcast messages */
        if (bus->bus_client && !m->destination)
                return 0;

        assert(m->path);
        assert(m->member);

        pl = strlen(m->path);
        do {
                char prefix[pl+1];

                bus->nodes_modified = false;

                r = object_find_and_run(bus, m, m->path, false, &found_object);
                if (r != 0)
                        return r;

                /* Look for fallback prefixes */
                OBJECT_PATH_FOREACH_PREFIX(prefix, m->path) {

                        if (bus->nodes_modified)
                                break;

                        r = object_find_and_run(bus, m, prefix, true, &found_object);
                        if (r != 0)
                                return r;
                }

        } while (bus->nodes_modified);

        if (!found_object)
                return 0;

        if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus.Properties", "Get") ||
            sd_bus_message_is_method_call(m, "org.freedesktop.DBus.Properties", "Set"))
                r = sd_bus_reply_method_errorf(
                                m,
                                SD_BUS_ERROR_UNKNOWN_PROPERTY,
                                "Unknown property or interface.");
        else
                r = sd_bus_reply_method_errorf(
                                m,
                                SD_BUS_ERROR_UNKNOWN_METHOD,
                                "Unknown method '%s' or interface '%s'.", m->member, m->interface);

        if (r < 0)
                return r;

        return 1;
}

static struct node *bus_node_allocate(sd_bus *bus, const char *path) {
        struct node *n, *parent;
        const char *e;
        _cleanup_free_ char *s = NULL;
        char *p;
        int r;

        assert(bus);
        assert(path);
        assert(path[0] == '/');

        n = hashmap_get(bus->nodes, path);
        if (n)
                return n;

        r = hashmap_ensure_allocated(&bus->nodes, &string_hash_ops);
        if (r < 0)
                return NULL;

        s = strdup(path);
        if (!s)
                return NULL;

        if (streq(path, "/"))
                parent = NULL;
        else {
                e = strrchr(path, '/');
                assert(e);

                p = strndupa(path, MAX(1, e - path));

                parent = bus_node_allocate(bus, p);
                if (!parent)
                        return NULL;
        }

        n = new0(struct node, 1);
        if (!n)
                return NULL;

        n->parent = parent;
        n->path = s;
        s = NULL; /* do not free */

        r = hashmap_put(bus->nodes, n->path, n);
        if (r < 0) {
                free(n->path);
                free(n);
                return NULL;
        }

        if (parent)
                LIST_PREPEND(siblings, parent->child, n);

        return n;
}

void bus_node_gc(sd_bus *b, struct node *n) {
        assert(b);

        if (!n)
                return;

        if (n->child ||
            n->callbacks ||
            n->vtables ||
            n->enumerators ||
            n->object_managers)
                return;

        assert(hashmap_remove(b->nodes, n->path) == n);

        if (n->parent)
                LIST_REMOVE(siblings, n->parent->child, n);

        free(n->path);
        bus_node_gc(b, n->parent);
        free(n);
}

static int bus_find_parent_object_manager(sd_bus *bus, struct node **out, const char *path) {
        struct node *n;

        assert(bus);
        assert(path);

        n = hashmap_get(bus->nodes, path);
        if (!n) {
                char *prefix;

                prefix = alloca(strlen(path) + 1);
                OBJECT_PATH_FOREACH_PREFIX(prefix, path) {
                        n = hashmap_get(bus->nodes, prefix);
                        if (n)
                                break;
                }
        }

        while (n && !n->object_managers)
                n = n->parent;

        if (out)
                *out = n;
        return !!n;
}

static int bus_add_object(
                sd_bus *bus,
                sd_bus_slot **slot,
                bool fallback,
                const char *path,
                sd_bus_message_handler_t callback,
                void *userdata) {

        sd_bus_slot *s;
        struct node *n;
        int r;

        assert_return(bus, -EINVAL);
        assert_return(object_path_is_valid(path), -EINVAL);
        assert_return(callback, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        n = bus_node_allocate(bus, path);
        if (!n)
                return -ENOMEM;

        s = bus_slot_allocate(bus, !slot, BUS_NODE_CALLBACK, sizeof(struct node_callback), userdata);
        if (!s) {
                r = -ENOMEM;
                goto fail;
        }

        s->node_callback.callback = callback;
        s->node_callback.is_fallback = fallback;

        s->node_callback.node = n;
        LIST_PREPEND(callbacks, n->callbacks, &s->node_callback);
        bus->nodes_modified = true;

        if (slot)
                *slot = s;

        return 0;

fail:
        sd_bus_slot_unref(s);
        bus_node_gc(bus, n);

        return r;
}

_public_ int sd_bus_add_object(
                sd_bus *bus,
                sd_bus_slot **slot,
                const char *path,
                sd_bus_message_handler_t callback,
                void *userdata) {

        return bus_add_object(bus, slot, false, path, callback, userdata);
}

_public_ int sd_bus_add_fallback(
                sd_bus *bus,
                sd_bus_slot **slot,
                const char *prefix,
                sd_bus_message_handler_t callback,
                void *userdata) {

        return bus_add_object(bus, slot, true, prefix, callback, userdata);
}

static void vtable_member_hash_func(const void *a, struct siphash *state) {
        const struct vtable_member *m = a;

        assert(m);

        string_hash_func(m->path, state);
        string_hash_func(m->interface, state);
        string_hash_func(m->member, state);
}

static int vtable_member_compare_func(const void *a, const void *b) {
        const struct vtable_member *x = a, *y = b;
        int r;

        assert(x);
        assert(y);

        r = strcmp(x->path, y->path);
        if (r != 0)
                return r;

        r = strcmp(x->interface, y->interface);
        if (r != 0)
                return r;

        return strcmp(x->member, y->member);
}

static const struct hash_ops vtable_member_hash_ops = {
        .hash = vtable_member_hash_func,
        .compare = vtable_member_compare_func
};

static int add_object_vtable_internal(
                sd_bus *bus,
                sd_bus_slot **slot,
                const char *path,
                const char *interface,
                const sd_bus_vtable *vtable,
                bool fallback,
                sd_bus_object_find_t find,
                void *userdata) {

        sd_bus_slot *s = NULL;
        struct node_vtable *i, *existing = NULL;
        const sd_bus_vtable *v;
        struct node *n;
        int r;

        assert_return(bus, -EINVAL);
        assert_return(object_path_is_valid(path), -EINVAL);
        assert_return(interface_name_is_valid(interface), -EINVAL);
        assert_return(vtable, -EINVAL);
        assert_return(vtable[0].type == _SD_BUS_VTABLE_START, -EINVAL);
        assert_return(vtable[0].x.start.element_size == sizeof(struct sd_bus_vtable), -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);
        assert_return(!streq(interface, "org.freedesktop.DBus.Properties") &&
                      !streq(interface, "org.freedesktop.DBus.Introspectable") &&
                      !streq(interface, "org.freedesktop.DBus.Peer") &&
                      !streq(interface, "org.freedesktop.DBus.ObjectManager"), -EINVAL);

        r = hashmap_ensure_allocated(&bus->vtable_methods, &vtable_member_hash_ops);
        if (r < 0)
                return r;

        r = hashmap_ensure_allocated(&bus->vtable_properties, &vtable_member_hash_ops);
        if (r < 0)
                return r;

        n = bus_node_allocate(bus, path);
        if (!n)
                return -ENOMEM;

        LIST_FOREACH(vtables, i, n->vtables) {
                if (i->is_fallback != fallback) {
                        r = -EPROTOTYPE;
                        goto fail;
                }

                if (streq(i->interface, interface)) {

                        if (i->vtable == vtable) {
                                r = -EEXIST;
                                goto fail;
                        }

                        existing = i;
                }
        }

        s = bus_slot_allocate(bus, !slot, BUS_NODE_VTABLE, sizeof(struct node_vtable), userdata);
        if (!s) {
                r = -ENOMEM;
                goto fail;
        }

        s->node_vtable.is_fallback = fallback;
        s->node_vtable.vtable = vtable;
        s->node_vtable.find = find;

        s->node_vtable.interface = strdup(interface);
        if (!s->node_vtable.interface) {
                r = -ENOMEM;
                goto fail;
        }

        for (v = s->node_vtable.vtable+1; v->type != _SD_BUS_VTABLE_END; v++) {

                switch (v->type) {

                case _SD_BUS_VTABLE_METHOD: {
                        struct vtable_member *m;

                        if (!member_name_is_valid(v->x.method.member) ||
                            !signature_is_valid(strempty(v->x.method.signature), false) ||
                            !signature_is_valid(strempty(v->x.method.result), false) ||
                            !(v->x.method.handler || (isempty(v->x.method.signature) && isempty(v->x.method.result))) ||
                            v->flags & (SD_BUS_VTABLE_PROPERTY_CONST|SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE|SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION)) {
                                r = -EINVAL;
                                goto fail;
                        }

                        m = new0(struct vtable_member, 1);
                        if (!m) {
                                r = -ENOMEM;
                                goto fail;
                        }

                        m->parent = &s->node_vtable;
                        m->path = n->path;
                        m->interface = s->node_vtable.interface;
                        m->member = v->x.method.member;
                        m->vtable = v;

                        r = hashmap_put(bus->vtable_methods, m, m);
                        if (r < 0) {
                                free(m);
                                goto fail;
                        }

                        break;
                }

                case _SD_BUS_VTABLE_WRITABLE_PROPERTY:

                        if (!(v->x.property.set || bus_type_is_basic(v->x.property.signature[0]))) {
                                r = -EINVAL;
                                goto fail;
                        }

                        if (v->flags & SD_BUS_VTABLE_PROPERTY_CONST) {
                                r = -EINVAL;
                                goto fail;
                        }

                        /* Fall through */

                case _SD_BUS_VTABLE_PROPERTY: {
                        struct vtable_member *m;

                        if (!member_name_is_valid(v->x.property.member) ||
                            !signature_is_single(v->x.property.signature, false) ||
                            !(v->x.property.get || bus_type_is_basic(v->x.property.signature[0]) || streq(v->x.property.signature, "as")) ||
                            (v->flags & SD_BUS_VTABLE_METHOD_NO_REPLY) ||
                            (!!(v->flags & SD_BUS_VTABLE_PROPERTY_CONST) + !!(v->flags & SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE) + !!(v->flags & SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION)) > 1 ||
                            ((v->flags & SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE) && (v->flags & SD_BUS_VTABLE_PROPERTY_EXPLICIT)) ||
                            (v->flags & SD_BUS_VTABLE_UNPRIVILEGED && v->type == _SD_BUS_VTABLE_PROPERTY)) {
                                r = -EINVAL;
                                goto fail;
                        }

                        m = new0(struct vtable_member, 1);
                        if (!m) {
                                r = -ENOMEM;
                                goto fail;
                        }

                        m->parent = &s->node_vtable;
                        m->path = n->path;
                        m->interface = s->node_vtable.interface;
                        m->member = v->x.property.member;
                        m->vtable = v;

                        r = hashmap_put(bus->vtable_properties, m, m);
                        if (r < 0) {
                                free(m);
                                goto fail;
                        }

                        break;
                }

                case _SD_BUS_VTABLE_SIGNAL:

                        if (!member_name_is_valid(v->x.signal.member) ||
                            !signature_is_valid(strempty(v->x.signal.signature), false) ||
                            v->flags & SD_BUS_VTABLE_UNPRIVILEGED) {
                                r = -EINVAL;
                                goto fail;
                        }

                        break;

                default:
                        r = -EINVAL;
                        goto fail;
                }
        }

        s->node_vtable.node = n;
        LIST_INSERT_AFTER(vtables, n->vtables, existing, &s->node_vtable);
        bus->nodes_modified = true;

        if (slot)
                *slot = s;

        return 0;

fail:
        sd_bus_slot_unref(s);
        bus_node_gc(bus, n);

        return r;
}

_public_ int sd_bus_add_object_vtable(
                sd_bus *bus,
                sd_bus_slot **slot,
                const char *path,
                const char *interface,
                const sd_bus_vtable *vtable,
                void *userdata) {

        return add_object_vtable_internal(bus, slot, path, interface, vtable, false, NULL, userdata);
}

_public_ int sd_bus_add_fallback_vtable(
                sd_bus *bus,
                sd_bus_slot **slot,
                const char *prefix,
                const char *interface,
                const sd_bus_vtable *vtable,
                sd_bus_object_find_t find,
                void *userdata) {

        return add_object_vtable_internal(bus, slot, prefix, interface, vtable, true, find, userdata);
}

_public_ int sd_bus_add_node_enumerator(
                sd_bus *bus,
                sd_bus_slot **slot,
                const char *path,
                sd_bus_node_enumerator_t callback,
                void *userdata) {

        sd_bus_slot *s;
        struct node *n;
        int r;

        assert_return(bus, -EINVAL);
        assert_return(object_path_is_valid(path), -EINVAL);
        assert_return(callback, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        n = bus_node_allocate(bus, path);
        if (!n)
                return -ENOMEM;

        s = bus_slot_allocate(bus, !slot, BUS_NODE_ENUMERATOR, sizeof(struct node_enumerator), userdata);
        if (!s) {
                r = -ENOMEM;
                goto fail;
        }

        s->node_enumerator.callback = callback;

        s->node_enumerator.node = n;
        LIST_PREPEND(enumerators, n->enumerators, &s->node_enumerator);
        bus->nodes_modified = true;

        if (slot)
                *slot = s;

        return 0;

fail:
        sd_bus_slot_unref(s);
        bus_node_gc(bus, n);

        return r;
}

static int emit_properties_changed_on_interface(
                sd_bus *bus,
                const char *prefix,
                const char *path,
                const char *interface,
                bool require_fallback,
                bool *found_interface,
                char **names) {

        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        bool has_invalidating = false, has_changing = false;
        struct vtable_member key = {};
        struct node_vtable *c;
        struct node *n;
        char **property;
        void *u = NULL;
        int r;

        assert(bus);
        assert(prefix);
        assert(path);
        assert(interface);
        assert(found_interface);

        n = hashmap_get(bus->nodes, prefix);
        if (!n)
                return 0;

        r = sd_bus_message_new_signal(bus, &m, path, "org.freedesktop.DBus.Properties", "PropertiesChanged");
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "s", interface);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(m, 'a', "{sv}");
        if (r < 0)
                return r;

        key.path = prefix;
        key.interface = interface;

        LIST_FOREACH(vtables, c, n->vtables) {
                if (require_fallback && !c->is_fallback)
                        continue;

                if (!streq(c->interface, interface))
                        continue;

                r = node_vtable_get_userdata(bus, path, c, &u, &error);
                if (r < 0)
                        return r;
                if (bus->nodes_modified)
                        return 0;
                if (r == 0)
                        continue;

                *found_interface = true;

                if (names) {
                        /* If the caller specified a list of
                         * properties we include exactly those in the
                         * PropertiesChanged message */

                        STRV_FOREACH(property, names) {
                                struct vtable_member *v;

                                assert_return(member_name_is_valid(*property), -EINVAL);

                                key.member = *property;
                                v = hashmap_get(bus->vtable_properties, &key);
                                if (!v)
                                        return -ENOENT;

                                /* If there are two vtables for the same
                                 * interface, let's handle this property when
                                 * we come to that vtable. */
                                if (c != v->parent)
                                        continue;

                                assert_return(v->vtable->flags & SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE ||
                                              v->vtable->flags & SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION, -EDOM);

                                assert_return(!(v->vtable->flags & SD_BUS_VTABLE_HIDDEN), -EDOM);

                                if (v->vtable->flags & SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION) {
                                        has_invalidating = true;
                                        continue;
                                }

                                has_changing = true;

                                r = vtable_append_one_property(bus, m, m->path, c, v->vtable, u, &error);
                                if (r < 0)
                                        return r;
                                if (bus->nodes_modified)
                                        return 0;
                        }
                } else {
                        const sd_bus_vtable *v;

                        /* If the caller specified no properties list
                         * we include all properties that are marked
                         * as changing in the message. */

                        for (v = c->vtable+1; v->type != _SD_BUS_VTABLE_END; v++) {
                                if (v->type != _SD_BUS_VTABLE_PROPERTY && v->type != _SD_BUS_VTABLE_WRITABLE_PROPERTY)
                                        continue;

                                if (v->flags & SD_BUS_VTABLE_HIDDEN)
                                        continue;

                                if (v->flags & SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION) {
                                        has_invalidating = true;
                                        continue;
                                }

                                if (!(v->flags & SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE))
                                        continue;

                                has_changing = true;

                                r = vtable_append_one_property(bus, m, m->path, c, v, u, &error);
                                if (r < 0)
                                        return r;
                                if (bus->nodes_modified)
                                        return 0;
                        }
                }
        }

        if (!has_invalidating && !has_changing)
                return 0;

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(m, 'a', "s");
        if (r < 0)
                return r;

        if (has_invalidating) {
                LIST_FOREACH(vtables, c, n->vtables) {
                        if (require_fallback && !c->is_fallback)
                                continue;

                        if (!streq(c->interface, interface))
                                continue;

                        r = node_vtable_get_userdata(bus, path, c, &u, &error);
                        if (r < 0)
                                return r;
                        if (bus->nodes_modified)
                                return 0;
                        if (r == 0)
                                continue;

                        if (names) {
                                STRV_FOREACH(property, names) {
                                        struct vtable_member *v;

                                        key.member = *property;
                                        assert_se(v = hashmap_get(bus->vtable_properties, &key));
                                        assert(c == v->parent);

                                        if (!(v->vtable->flags & SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION))
                                                continue;

                                        r = sd_bus_message_append(m, "s", *property);
                                        if (r < 0)
                                                return r;
                                }
                        } else {
                                const sd_bus_vtable *v;

                                for (v = c->vtable+1; v->type != _SD_BUS_VTABLE_END; v++) {
                                        if (v->type != _SD_BUS_VTABLE_PROPERTY && v->type != _SD_BUS_VTABLE_WRITABLE_PROPERTY)
                                                continue;

                                        if (v->flags & SD_BUS_VTABLE_HIDDEN)
                                                continue;

                                        if (!(v->flags & SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION))
                                                continue;

                                        r = sd_bus_message_append(m, "s", v->x.property.member);
                                        if (r < 0)
                                                return r;
                                }
                        }
                }
        }

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return r;

        r = sd_bus_send(bus, m, NULL);
        if (r < 0)
                return r;

        return 1;
}

_public_ int sd_bus_emit_properties_changed_strv(
                sd_bus *bus,
                const char *path,
                const char *interface,
                char **names) {

        BUS_DONT_DESTROY(bus);
        bool found_interface = false;
        char *prefix;
        int r;

        assert_return(bus, -EINVAL);
        assert_return(object_path_is_valid(path), -EINVAL);
        assert_return(interface_name_is_valid(interface), -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        /* A non-NULL but empty names list means nothing needs to be
           generated. A NULL list OTOH indicates that all properties
           that are set to EMITS_CHANGE or EMITS_INVALIDATION shall be
           included in the PropertiesChanged message. */
        if (names && names[0] == NULL)
                return 0;

        do {
                bus->nodes_modified = false;

                r = emit_properties_changed_on_interface(bus, path, path, interface, false, &found_interface, names);
                if (r != 0)
                        return r;
                if (bus->nodes_modified)
                        continue;

                prefix = alloca(strlen(path) + 1);
                OBJECT_PATH_FOREACH_PREFIX(prefix, path) {
                        r = emit_properties_changed_on_interface(bus, prefix, path, interface, true, &found_interface, names);
                        if (r != 0)
                                return r;
                        if (bus->nodes_modified)
                                break;
                }

        } while (bus->nodes_modified);

        return found_interface ? 0 : -ENOENT;
}

_public_ int sd_bus_emit_properties_changed(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *name, ...)  {

        char **names;

        assert_return(bus, -EINVAL);
        assert_return(object_path_is_valid(path), -EINVAL);
        assert_return(interface_name_is_valid(interface), -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        if (!name)
                return 0;

        names = strv_from_stdarg_alloca(name);

        return sd_bus_emit_properties_changed_strv(bus, path, interface, names);
}

static int object_added_append_all_prefix(
                sd_bus *bus,
                sd_bus_message *m,
                Set *s,
                const char *prefix,
                const char *path,
                bool require_fallback) {

        const char *previous_interface = NULL;
        struct node_vtable *c;
        struct node *n;
        int r;

        assert(bus);
        assert(m);
        assert(s);
        assert(prefix);
        assert(path);

        n = hashmap_get(bus->nodes, prefix);
        if (!n)
                return 0;

        LIST_FOREACH(vtables, c, n->vtables) {
                _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
                void *u = NULL;

                if (require_fallback && !c->is_fallback)
                        continue;

                r = node_vtable_get_userdata(bus, path, c, &u, &error);
                if (r < 0)
                        return r;
                if (bus->nodes_modified)
                        return 0;
                if (r == 0)
                        continue;

                if (!streq_ptr(c->interface, previous_interface)) {
                        /* If a child-node already handled this interface, we
                         * skip it on any of its parents. The child vtables
                         * always fully override any conflicting vtables of
                         * any parent node. */
                        if (set_get(s, c->interface))
                                continue;

                        r = set_put(s, c->interface);
                        if (r < 0)
                                return r;

                        if (previous_interface) {
                                r = sd_bus_message_close_container(m);
                                if (r < 0)
                                        return r;
                                r = sd_bus_message_close_container(m);
                                if (r < 0)
                                        return r;
                        }

                        r = sd_bus_message_open_container(m, 'e', "sa{sv}");
                        if (r < 0)
                                return r;
                        r = sd_bus_message_append(m, "s", c->interface);
                        if (r < 0)
                                return r;
                        r = sd_bus_message_open_container(m, 'a', "{sv}");
                        if (r < 0)
                                return r;

                        previous_interface = c->interface;
                }

                r = vtable_append_all_properties(bus, m, path, c, u, &error);
                if (r < 0)
                        return r;
                if (bus->nodes_modified)
                        return 0;
        }

        if (previous_interface) {
                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return r;
                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int object_added_append_all(sd_bus *bus, sd_bus_message *m, const char *path) {
        _cleanup_set_free_ Set *s = NULL;
        char *prefix;
        int r;

        assert(bus);
        assert(m);
        assert(path);

        /*
         * This appends all interfaces registered on path @path. We first add
         * the builtin interfaces, which are always available and handled by
         * sd-bus. Then, we add all interfaces registered on the exact node,
         * followed by all fallback interfaces registered on any parent prefix.
         *
         * If an interface is registered multiple times on the same node with
         * different vtables, we merge all the properties across all vtables.
         * However, if a child node has the same interface registered as one of
         * its parent nodes has as fallback, we make the child overwrite the
         * parent instead of extending it. Therefore, we keep a "Set" of all
         * handled interfaces during parent traversal, so we skip interfaces on
         * a parent that were overwritten by a child.
         */

        s = set_new(&string_hash_ops);
        if (!s)
                return -ENOMEM;

        r = sd_bus_message_append(m, "{sa{sv}}", "org.freedesktop.DBus.Peer", 0);
        if (r < 0)
                return r;
        r = sd_bus_message_append(m, "{sa{sv}}", "org.freedesktop.DBus.Introspectable", 0);
        if (r < 0)
                return r;
        r = sd_bus_message_append(m, "{sa{sv}}", "org.freedesktop.DBus.Properties", 0);
        if (r < 0)
                return r;
        r = sd_bus_message_append(m, "{sa{sv}}", "org.freedesktop.DBus.ObjectManager", 0);
        if (r < 0)
                return r;

        r = object_added_append_all_prefix(bus, m, s, path, path, false);
        if (r < 0)
                return r;
        if (bus->nodes_modified)
                return 0;

        prefix = alloca(strlen(path) + 1);
        OBJECT_PATH_FOREACH_PREFIX(prefix, path) {
                r = object_added_append_all_prefix(bus, m, s, prefix, path, true);
                if (r < 0)
                        return r;
                if (bus->nodes_modified)
                        return 0;
        }

        return 0;
}

_public_ int sd_bus_emit_object_added(sd_bus *bus, const char *path) {
        BUS_DONT_DESTROY(bus);

        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        struct node *object_manager;
        int r;

        /*
         * This emits an InterfacesAdded signal on the given path, by iterating
         * all registered vtables and fallback vtables on the path. All
         * properties are queried and included in the signal.
         * This call is equivalent to sd_bus_emit_interfaces_added() with an
         * explicit list of registered interfaces. However, unlike
         * interfaces_added(), this call can figure out the list of supported
         * interfaces itself. Furthermore, it properly adds the builtin
         * org.freedesktop.DBus.* interfaces.
         */

        assert_return(bus, -EINVAL);
        assert_return(object_path_is_valid(path), -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        r = bus_find_parent_object_manager(bus, &object_manager, path);
        if (r < 0)
                return r;
        if (r == 0)
                return -ESRCH;

        do {
                bus->nodes_modified = false;
                m = sd_bus_message_unref(m);

                r = sd_bus_message_new_signal(bus, &m, object_manager->path, "org.freedesktop.DBus.ObjectManager", "InterfacesAdded");
                if (r < 0)
                        return r;

                r = sd_bus_message_append_basic(m, 'o', path);
                if (r < 0)
                        return r;

                r = sd_bus_message_open_container(m, 'a', "{sa{sv}}");
                if (r < 0)
                        return r;

                r = object_added_append_all(bus, m, path);
                if (r < 0)
                        return r;

                if (bus->nodes_modified)
                        continue;

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return r;

        } while (bus->nodes_modified);

        return sd_bus_send(bus, m, NULL);
}

static int object_removed_append_all_prefix(
                sd_bus *bus,
                sd_bus_message *m,
                Set *s,
                const char *prefix,
                const char *path,
                bool require_fallback) {

        const char *previous_interface = NULL;
        struct node_vtable *c;
        struct node *n;
        int r;

        assert(bus);
        assert(m);
        assert(s);
        assert(prefix);
        assert(path);

        n = hashmap_get(bus->nodes, prefix);
        if (!n)
                return 0;

        LIST_FOREACH(vtables, c, n->vtables) {
                _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
                void *u = NULL;

                if (require_fallback && !c->is_fallback)
                        continue;
                if (streq_ptr(c->interface, previous_interface))
                        continue;

                /* If a child-node already handled this interface, we
                 * skip it on any of its parents. The child vtables
                 * always fully override any conflicting vtables of
                 * any parent node. */
                if (set_get(s, c->interface))
                        continue;

                r = node_vtable_get_userdata(bus, path, c, &u, &error);
                if (r < 0)
                        return r;
                if (bus->nodes_modified)
                        return 0;
                if (r == 0)
                        continue;

                r = set_put(s, c->interface);
                if (r < 0)
                        return r;

                r = sd_bus_message_append(m, "s", c->interface);
                if (r < 0)
                        return r;

                previous_interface = c->interface;
        }

        return 0;
}

static int object_removed_append_all(sd_bus *bus, sd_bus_message *m, const char *path) {
        _cleanup_set_free_ Set *s = NULL;
        char *prefix;
        int r;

        assert(bus);
        assert(m);
        assert(path);

        /* see sd_bus_emit_object_added() for details */

        s = set_new(&string_hash_ops);
        if (!s)
                return -ENOMEM;

        r = sd_bus_message_append(m, "s", "org.freedesktop.DBus.Peer");
        if (r < 0)
                return r;
        r = sd_bus_message_append(m, "s", "org.freedesktop.DBus.Introspectable");
        if (r < 0)
                return r;
        r = sd_bus_message_append(m, "s", "org.freedesktop.DBus.Properties");
        if (r < 0)
                return r;
        r = sd_bus_message_append(m, "s", "org.freedesktop.DBus.ObjectManager");
        if (r < 0)
                return r;

        r = object_removed_append_all_prefix(bus, m, s, path, path, false);
        if (r < 0)
                return r;
        if (bus->nodes_modified)
                return 0;

        prefix = alloca(strlen(path) + 1);
        OBJECT_PATH_FOREACH_PREFIX(prefix, path) {
                r = object_removed_append_all_prefix(bus, m, s, prefix, path, true);
                if (r < 0)
                        return r;
                if (bus->nodes_modified)
                        return 0;
        }

        return 0;
}

_public_ int sd_bus_emit_object_removed(sd_bus *bus, const char *path) {
        BUS_DONT_DESTROY(bus);

        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        struct node *object_manager;
        int r;

        /*
         * This is like sd_bus_emit_object_added(), but emits an
         * InterfacesRemoved signal on the given path. This only includes any
         * registered interfaces but skips the properties. Note that this will
         * call into the find() callbacks of any registered vtable. Therefore,
         * you must call this function before destroying/unlinking your object.
         * Otherwise, the list of interfaces will be incomplete. However, note
         * that this will *NOT* call into any property callback. Therefore, the
         * object might be in an "destructed" state, as long as we can find it.
         */

        assert_return(bus, -EINVAL);
        assert_return(object_path_is_valid(path), -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        r = bus_find_parent_object_manager(bus, &object_manager, path);
        if (r < 0)
                return r;
        if (r == 0)
                return -ESRCH;

        do {
                bus->nodes_modified = false;
                m = sd_bus_message_unref(m);

                r = sd_bus_message_new_signal(bus, &m, object_manager->path, "org.freedesktop.DBus.ObjectManager", "InterfacesRemoved");
                if (r < 0)
                        return r;

                r = sd_bus_message_append_basic(m, 'o', path);
                if (r < 0)
                        return r;

                r = sd_bus_message_open_container(m, 'a', "s");
                if (r < 0)
                        return r;

                r = object_removed_append_all(bus, m, path);
                if (r < 0)
                        return r;

                if (bus->nodes_modified)
                        continue;

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return r;

        } while (bus->nodes_modified);

        return sd_bus_send(bus, m, NULL);
}

static int interfaces_added_append_one_prefix(
                sd_bus *bus,
                sd_bus_message *m,
                const char *prefix,
                const char *path,
                const char *interface,
                bool require_fallback) {

        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        bool found_interface = false;
        struct node_vtable *c;
        struct node *n;
        void *u = NULL;
        int r;

        assert(bus);
        assert(m);
        assert(prefix);
        assert(path);
        assert(interface);

        n = hashmap_get(bus->nodes, prefix);
        if (!n)
                return 0;

        LIST_FOREACH(vtables, c, n->vtables) {
                if (require_fallback && !c->is_fallback)
                        continue;

                if (!streq(c->interface, interface))
                        continue;

                r = node_vtable_get_userdata(bus, path, c, &u, &error);
                if (r < 0)
                        return r;
                if (bus->nodes_modified)
                        return 0;
                if (r == 0)
                        continue;

                if (!found_interface) {
                        r = sd_bus_message_append_basic(m, 's', interface);
                        if (r < 0)
                                return r;

                        r = sd_bus_message_open_container(m, 'a', "{sv}");
                        if (r < 0)
                                return r;

                        found_interface = true;
                }

                r = vtable_append_all_properties(bus, m, path, c, u, &error);
                if (r < 0)
                        return r;
                if (bus->nodes_modified)
                        return 0;
        }

        if (found_interface) {
                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return r;
        }

        return found_interface;
}

static int interfaces_added_append_one(
                sd_bus *bus,
                sd_bus_message *m,
                const char *path,
                const char *interface) {

        char *prefix;
        int r;

        assert(bus);
        assert(m);
        assert(path);
        assert(interface);

        r = interfaces_added_append_one_prefix(bus, m, path, path, interface, false);
        if (r != 0)
                return r;
        if (bus->nodes_modified)
                return 0;

        prefix = alloca(strlen(path) + 1);
        OBJECT_PATH_FOREACH_PREFIX(prefix, path) {
                r = interfaces_added_append_one_prefix(bus, m, prefix, path, interface, true);
                if (r != 0)
                        return r;
                if (bus->nodes_modified)
                        return 0;
        }

        return -ENOENT;
}

_public_ int sd_bus_emit_interfaces_added_strv(sd_bus *bus, const char *path, char **interfaces) {
        BUS_DONT_DESTROY(bus);

        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        struct node *object_manager;
        char **i;
        int r;

        assert_return(bus, -EINVAL);
        assert_return(object_path_is_valid(path), -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        if (strv_isempty(interfaces))
                return 0;

        r = bus_find_parent_object_manager(bus, &object_manager, path);
        if (r < 0)
                return r;
        if (r == 0)
                return -ESRCH;

        do {
                bus->nodes_modified = false;
                m = sd_bus_message_unref(m);

                r = sd_bus_message_new_signal(bus, &m, object_manager->path, "org.freedesktop.DBus.ObjectManager", "InterfacesAdded");
                if (r < 0)
                        return r;

                r = sd_bus_message_append_basic(m, 'o', path);
                if (r < 0)
                        return r;

                r = sd_bus_message_open_container(m, 'a', "{sa{sv}}");
                if (r < 0)
                        return r;

                STRV_FOREACH(i, interfaces) {
                        assert_return(interface_name_is_valid(*i), -EINVAL);

                        r = sd_bus_message_open_container(m, 'e', "sa{sv}");
                        if (r < 0)
                                return r;

                        r = interfaces_added_append_one(bus, m, path, *i);
                        if (r < 0)
                                return r;

                        if (bus->nodes_modified)
                                break;

                        r = sd_bus_message_close_container(m);
                        if (r < 0)
                                return r;
                }

                if (bus->nodes_modified)
                        continue;

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return r;

        } while (bus->nodes_modified);

        return sd_bus_send(bus, m, NULL);
}

_public_ int sd_bus_emit_interfaces_added(sd_bus *bus, const char *path, const char *interface, ...) {
        char **interfaces;

        assert_return(bus, -EINVAL);
        assert_return(object_path_is_valid(path), -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        interfaces = strv_from_stdarg_alloca(interface);

        return sd_bus_emit_interfaces_added_strv(bus, path, interfaces);
}

_public_ int sd_bus_emit_interfaces_removed_strv(sd_bus *bus, const char *path, char **interfaces) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        struct node *object_manager;
        int r;

        assert_return(bus, -EINVAL);
        assert_return(object_path_is_valid(path), -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        if (strv_isempty(interfaces))
                return 0;

        r = bus_find_parent_object_manager(bus, &object_manager, path);
        if (r < 0)
                return r;
        if (r == 0)
                return -ESRCH;

        r = sd_bus_message_new_signal(bus, &m, object_manager->path, "org.freedesktop.DBus.ObjectManager", "InterfacesRemoved");
        if (r < 0)
                return r;

        r = sd_bus_message_append_basic(m, 'o', path);
        if (r < 0)
                return r;

        r = sd_bus_message_append_strv(m, interfaces);
        if (r < 0)
                return r;

        return sd_bus_send(bus, m, NULL);
}

_public_ int sd_bus_emit_interfaces_removed(sd_bus *bus, const char *path, const char *interface, ...) {
        char **interfaces;

        assert_return(bus, -EINVAL);
        assert_return(object_path_is_valid(path), -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        interfaces = strv_from_stdarg_alloca(interface);

        return sd_bus_emit_interfaces_removed_strv(bus, path, interfaces);
}

_public_ int sd_bus_add_object_manager(sd_bus *bus, sd_bus_slot **slot, const char *path) {
        sd_bus_slot *s;
        struct node *n;
        int r;

        assert_return(bus, -EINVAL);
        assert_return(object_path_is_valid(path), -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        n = bus_node_allocate(bus, path);
        if (!n)
                return -ENOMEM;

        s = bus_slot_allocate(bus, !slot, BUS_NODE_OBJECT_MANAGER, sizeof(struct node_object_manager), NULL);
        if (!s) {
                r = -ENOMEM;
                goto fail;
        }

        s->node_object_manager.node = n;
        LIST_PREPEND(object_managers, n->object_managers, &s->node_object_manager);
        bus->nodes_modified = true;

        if (slot)
                *slot = s;

        return 0;

fail:
        sd_bus_slot_unref(s);
        bus_node_gc(bus, n);

        return r;
}
