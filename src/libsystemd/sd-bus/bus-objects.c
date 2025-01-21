/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "bus-internal.h"
#include "bus-introspect.h"
#include "bus-message.h"
#include "bus-objects.h"
#include "bus-signature.h"
#include "bus-slot.h"
#include "bus-type.h"
#include "missing_capability.h"
#include "string-util.h"
#include "strv.h"

static int node_vtable_get_userdata(
                sd_bus *bus,
                const char *path,
                struct node_vtable *c,
                void **userdata,
                sd_bus_error *error) {

        sd_bus_slot *s;
        void *u, *found_u = NULL;
        int r;

        assert(bus);
        assert(path);
        assert(c);

        s = container_of(c, sd_bus_slot, node_vtable);
        u = s->userdata;
        if (c->find) {
                bus->current_slot = sd_bus_slot_ref(s);
                bus->current_userdata = u;
                r = c->find(bus, path, c->interface, u, &found_u, error);
                bus->current_userdata = NULL;
                bus->current_slot = sd_bus_slot_unref(s);

                if (r < 0)
                        return r;
                if (sd_bus_error_is_set(error))
                        return -sd_bus_error_get_errno(error);
                if (r == 0)
                        return r;
        } else
                found_u = u;

        if (userdata)
                *userdata = found_u;

        return 1;
}

static void *vtable_method_convert_userdata(const sd_bus_vtable *p, void *u) {
        assert(p);

        if (!u || FLAGS_SET(p->flags, SD_BUS_VTABLE_ABSOLUTE_OFFSET))
                return SIZE_TO_PTR(p->x.method.offset); /* don't add offset on NULL, to make ubsan happy */

        return (uint8_t*) u + p->x.method.offset;
}

static void *vtable_property_convert_userdata(const sd_bus_vtable *p, void *u) {
        assert(p);

        if (!u || FLAGS_SET(p->flags, SD_BUS_VTABLE_ABSOLUTE_OFFSET))
                return SIZE_TO_PTR(p->x.property.offset); /* as above */

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
                OrderedSet *s,
                sd_bus_error *error) {

        int r;

        assert(bus);
        assert(prefix);
        assert(s);

        LIST_FOREACH(enumerators, c, first) {
                char **children = NULL;
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

                        if (!object_path_is_valid(*k)) {
                                free(*k);
                                r = -EINVAL;
                                continue;
                        }

                        if (!object_path_startswith(*k, prefix)) {
                                free(*k);
                                continue;
                        }

                        r = ordered_set_consume(s, *k);
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
        CHILDREN_RECURSIVE      = 1 << 0,
        /* if set, add_subtree() scans object-manager hierarchies recursively */
        CHILDREN_SUBHIERARCHIES = 1 << 1,
};

static int add_subtree_to_set(
                sd_bus *bus,
                const char *prefix,
                struct node *n,
                unsigned flags,
                OrderedSet *s,
                sd_bus_error *error) {

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

                r = ordered_set_consume(s, t);
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
                unsigned flags,
                OrderedSet **ret,
                sd_bus_error *error) {

        _cleanup_ordered_set_free_ OrderedSet *s = NULL;
        int r;

        assert(bus);
        assert(prefix);
        assert(n);
        assert(ret);

        s = ordered_set_new(&string_hash_ops_free);
        if (!s)
                return -ENOMEM;

        r = add_subtree_to_set(bus, prefix, n, flags, s, error);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(s);
        return 0;
}

static int node_callbacks_run(
                sd_bus *bus,
                sd_bus_message *m,
                struct node_callback *first,
                bool require_fallback,
                bool *found_object) {

        int r;

        assert(bus);
        assert(m);
        assert(found_object);

        LIST_FOREACH(callbacks, c, first) {
                _cleanup_(sd_bus_error_free) sd_bus_error error_buffer = SD_BUS_ERROR_NULL;
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

        /* Check that the caller has the requested capability set. Note that the flags value contains the
         * capability number plus one, which we need to subtract here. We do this so that we have 0 as
         * special value for the default. */
        cap = CAPABILITY_SHIFT(c->vtable->flags);
        if (cap == 0)
                cap = CAPABILITY_SHIFT(c->parent->vtable[0].flags);
        if (cap == 0)
                cap = CAP_SYS_ADMIN;
        else
                cap--;

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

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *signature;
        void *u;
        int r;

        assert(bus);
        assert(m);
        assert(c);
        assert(found_object);

        if (require_fallback && !c->parent->is_fallback)
                return 0;

        if (FLAGS_SET(c->vtable->flags, SD_BUS_VTABLE_SENSITIVE)) {
                r = sd_bus_message_sensitive(m);
                if (r < 0)
                        return r;
        }

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

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        sd_bus_slot *slot;
        void *u = NULL;
        int r;

        assert(bus);
        assert(m);
        assert(c);
        assert(found_object);

        if (require_fallback && !c->parent->is_fallback)
                return 0;

        if (FLAGS_SET(c->vtable->flags, SD_BUS_VTABLE_SENSITIVE)) {
                r = sd_bus_message_sensitive(m);
                if (r < 0)
                        return r;
        }

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

        if (FLAGS_SET(c->vtable->flags, SD_BUS_VTABLE_SENSITIVE)) {
                r = sd_bus_message_sensitive(reply);
                if (r < 0)
                        return r;
        }

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

                if (type != 'v')
                        return sd_bus_reply_method_errorf(m, SD_BUS_ERROR_INVALID_SIGNATURE,
                                                          "Incorrect signature when setting property '%s', expected 'v', got '%c'.",
                                                          c->member, type);
                if (!streq(strempty(signature), strempty(c->vtable->x.property.signature)))
                        return sd_bus_reply_method_errorf(m, SD_BUS_ERROR_INVALID_ARGS,
                                                          "Incorrect parameters for property '%s', expected '%s', got '%s'.",
                                                          c->member, strempty(c->vtable->x.property.signature), strempty(signature));

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

        if (FLAGS_SET(c->vtable->flags, SD_BUS_VTABLE_SENSITIVE)) {
                r = sd_bus_message_sensitive(reply);
                if (r < 0)
                        return r;
        }

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

        v = c->vtable;
        for (v = bus_vtable_next(c->vtable, v); v->type != _SD_BUS_VTABLE_END; v = bus_vtable_next(c->vtable, v)) {
                if (!IN_SET(v->type, _SD_BUS_VTABLE_PROPERTY, _SD_BUS_VTABLE_WRITABLE_PROPERTY))
                        continue;

                if (v->flags & SD_BUS_VTABLE_HIDDEN)
                        continue;

                /* Let's not include properties marked as "explicit" in any message that contains a generic
                 * dump of properties, but only in those generated as a response to an explicit request. */
                if (v->flags & SD_BUS_VTABLE_PROPERTY_EXPLICIT)
                        continue;

                /* Let's not include properties marked only for invalidation on change (i.e. in contrast to
                 * those whose new values are included in PropertiesChanges message) in any signals. This is
                 * useful to ensure they aren't included in InterfacesAdded messages. */
                if (reply->header->type != SD_BUS_MESSAGE_METHOD_RETURN &&
                    FLAGS_SET(v->flags, SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION))
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

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
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

        found_interface = !iface || STR_IN_SET(iface,
                                               "org.freedesktop.DBus.Properties",
                                               "org.freedesktop.DBus.Peer",
                                               "org.freedesktop.DBus.Introspectable");

        LIST_FOREACH(vtables, c, first) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
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

        if (!*found_object)
                return 0;

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
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

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

int introspect_path(
                sd_bus *bus,
                const char *path,
                struct node *n,
                bool require_fallback,
                bool ignore_nodes_modified,
                bool *found_object,
                char **ret,
                sd_bus_error *error) {

        _cleanup_ordered_set_free_ OrderedSet *s = NULL;
        _cleanup_(introspect_done) struct introspect intro = {};
        bool empty;
        int r;

        if (!n) {
                n = hashmap_get(bus->nodes, path);
                if (!n)
                        return -ENOENT;
        }

        r = get_child_nodes(bus, path, n, 0, &s, error);
        if (r < 0)
                return r;
        if (bus->nodes_modified && !ignore_nodes_modified)
                return 0;

        r = introspect_begin(&intro, bus->trusted);
        if (r < 0)
                return r;

        r = introspect_write_default_interfaces(&intro, !require_fallback && n->object_managers);
        if (r < 0)
                return r;

        empty = ordered_set_isempty(s);

        LIST_FOREACH(vtables, c, n->vtables) {
                if (require_fallback && !c->is_fallback)
                        continue;

                r = node_vtable_get_userdata(bus, path, c, NULL, error);
                if (r < 0)
                        return r;
                if (bus->nodes_modified && !ignore_nodes_modified)
                        return 0;
                if (r == 0)
                        continue;

                empty = false;

                if (c->vtable[0].flags & SD_BUS_VTABLE_HIDDEN)
                        continue;

                r = introspect_write_interface(&intro, c->interface, c->vtable);
                if (r < 0)
                        return r;
        }

        if (empty) {
                /* Nothing?, let's see if we exist at all, and if not
                 * refuse to do anything */
                r = bus_node_exists(bus, n, path, require_fallback);
                if (r <= 0)
                        return r;
                if (bus->nodes_modified && !ignore_nodes_modified)
                        return 0;
        }

        if (found_object)
                *found_object = true;

        r = introspect_write_child_nodes(&intro, s, path);
        if (r < 0)
                return r;

        r = introspect_finish(&intro, ret);
        if (r < 0)
                return r;

        return 1;
}

static int process_introspect(
                sd_bus *bus,
                sd_bus_message *m,
                struct node *n,
                bool require_fallback,
                bool *found_object) {

        _cleanup_free_ char *s = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        int r;

        assert(bus);
        assert(m);
        assert(n);
        assert(found_object);

        r = introspect_path(bus, m->path, n, require_fallback, false, found_object, &s, &error);
        if (r < 0)
                return bus_maybe_reply_error(m, r, &error);
        if (r == 0)
                /* nodes_modified == true */
                return 0;

        r = sd_bus_message_new_method_return(m, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_append(reply, "s", s);
        if (r < 0)
                return r;

        r = sd_bus_send(bus, reply, NULL);
        if (r < 0)
                return r;

        return 1;
}

static int object_manager_serialize_path(
                sd_bus *bus,
                sd_bus_message *reply,
                const char *prefix,
                const char *path,
                bool require_fallback,
                bool *found_object_manager,
                sd_bus_error *error) {

        const char *previous_interface = NULL;
        bool found_something = false;
        struct node *n;
        int r;

        assert(bus);
        assert(reply);
        assert(prefix);
        assert(path);
        assert(found_object_manager);
        assert(error);

        n = hashmap_get(bus->nodes, prefix);
        if (!n)
                return 0;

        if (!require_fallback && n->object_managers)
                *found_object_manager = true;

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

                        r = sd_bus_message_append(reply, "{sa{sv}}", "org.freedesktop.DBus.Peer", 0);
                        if (r < 0)
                                return r;

                        r = sd_bus_message_append(reply, "{sa{sv}}", "org.freedesktop.DBus.Introspectable", 0);
                        if (r < 0)
                                return r;

                        r = sd_bus_message_append(reply, "{sa{sv}}", "org.freedesktop.DBus.Properties", 0);
                        if (r < 0)
                                return r;

                        if (*found_object_manager) {
                                r = sd_bus_message_append(
                                                reply, "{sa{sv}}", "org.freedesktop.DBus.ObjectManager", 0);
                                if (r < 0)
                                        return r;
                        }

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

        _cleanup_free_ char *prefix = NULL;
        size_t pl;
        int r;
        bool found_object_manager = false;

        assert(bus);
        assert(reply);
        assert(path);
        assert(error);

        /* First, add all vtables registered for this path */
        r = object_manager_serialize_path(bus, reply, path, path, false, &found_object_manager, error);
        if (r < 0)
                return r;
        if (bus->nodes_modified)
                return 0;

        /* Second, add fallback vtables registered for any of the prefixes */
        pl = strlen(path);
        assert(pl <= BUS_PATH_SIZE_MAX);
        prefix = new(char, pl + 1);
        if (!prefix)
                return -ENOMEM;

        OBJECT_PATH_FOREACH_PREFIX(prefix, path) {
                r = object_manager_serialize_path(bus, reply, prefix, path, true, &found_object_manager, error);
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

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_ordered_set_free_ OrderedSet *s = NULL;
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
                return bus_maybe_reply_error(m, r, &error);
        if (bus->nodes_modified)
                return 0;

        r = sd_bus_message_new_method_return(m, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "{oa{sa{sv}}}");
        if (r < 0)
                return r;

        ORDERED_SET_FOREACH(path, s) {
                r = object_manager_serialize_path_and_fallbacks(bus, reply, path, &error);
                if (r < 0)
                        return bus_maybe_reply_error(m, r, &error);

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

        v = set_get(bus->vtable_methods, &vtable_key);
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

                        v = set_get(bus->vtable_properties, &vtable_key);
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
                        return bus_maybe_reply_error(m, r, NULL);
                if (bus->nodes_modified)
                        return 0;
                if (r > 0)
                        *found_object = true;
        }

        return 0;
}

int bus_process_object(sd_bus *bus, sd_bus_message *m) {
        _cleanup_free_ char *prefix = NULL;
        int r;
        size_t pl;
        bool found_object = false;

        assert(bus);
        assert(m);

        if (bus->is_monitor)
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
        assert(pl <= BUS_PATH_SIZE_MAX);
        prefix = new(char, pl + 1);
        if (!prefix)
                return -ENOMEM;

        do {
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
            sd_bus_message_is_method_call(m, "org.freedesktop.DBus.Properties", "Set")) {
                const char *interface = NULL, *property = NULL;

                (void) sd_bus_message_rewind(m, true);
                (void) sd_bus_message_read_basic(m, 's', &interface);
                (void) sd_bus_message_read_basic(m, 's', &property);

                r = sd_bus_reply_method_errorf(
                                m,
                                SD_BUS_ERROR_UNKNOWN_PROPERTY,
                                "Unknown interface %s or property %s.", strnull(interface), strnull(property));
        } else
                r = sd_bus_reply_method_errorf(
                                m,
                                SD_BUS_ERROR_UNKNOWN_METHOD,
                                "Unknown method %s or interface %s.", m->member, m->interface);

        if (r < 0)
                return r;

        return 1;
}

static struct node* bus_node_allocate(sd_bus *bus, const char *path) {
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
                assert_se(e = strrchr(path, '/'));

                p = strndupa_safe(path, MAX(1, e - path));

                parent = bus_node_allocate(bus, p);
                if (!parent)
                        return NULL;
        }

        n = new0(struct node, 1);
        if (!n)
                return NULL;

        n->parent = parent;
        n->path = TAKE_PTR(s);

        r = hashmap_put(bus->nodes, n->path, n);
        if (r < 0) {
                free(n->path);
                return mfree(n);
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

        assert_se(hashmap_remove(b->nodes, n->path) == n);

        if (n->parent)
                LIST_REMOVE(siblings, n->parent->child, n);

        free(n->path);
        bus_node_gc(b, n->parent);
        free(n);
}

static int bus_find_parent_object_manager(sd_bus *bus, struct node **out, const char *path, bool* path_has_object_manager) {
        struct node *n;

        assert(bus);
        assert(path);
        assert(path_has_object_manager);

        n = hashmap_get(bus->nodes, path);

        if (n)
                *path_has_object_manager = n->object_managers;

        if (!n) {
                _cleanup_free_ char *prefix = NULL;
                size_t pl;

                pl = strlen(path);
                assert(pl <= BUS_PATH_SIZE_MAX);
                prefix = new(char, pl + 1);
                if (!prefix)
                        return -ENOMEM;

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
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(object_path_is_valid(path), -EINVAL);
        assert_return(callback, -EINVAL);
        assert_return(!bus_origin_changed(bus), -ECHILD);

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

static void vtable_member_hash_func(const struct vtable_member *m, struct siphash *state) {
        assert(m);

        string_hash_func(m->path, state);
        string_hash_func(m->interface, state);
        string_hash_func(m->member, state);
}

static int vtable_member_compare_func(const struct vtable_member *x, const struct vtable_member *y) {
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

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
                vtable_member_hash_ops,
                struct vtable_member, vtable_member_hash_func, vtable_member_compare_func, free);

typedef enum {
        NAMES_FIRST_PART        = 1 << 0, /* first part of argument name list (input names). It is reset by names_are_valid() */
        NAMES_PRESENT           = 1 << 1, /* at least one argument name is present, so the names will checked.
                                             This flag is set and used internally by names_are_valid(), but needs to be stored across calls for 2-parts list  */
        NAMES_SINGLE_PART       = 1 << 2, /* argument name list consisting of a single part */
} names_flags;

static bool names_are_valid(const char *signature, const char **names, names_flags *flags) {
        int r;

        if ((*flags & NAMES_FIRST_PART || *flags & NAMES_SINGLE_PART) && **names != '\0')
                *flags |= NAMES_PRESENT;

        while (*flags & NAMES_PRESENT) {
                size_t l;

                if (!*signature)
                        break;

                r = signature_element_length(signature, &l);
                if (r < 0)
                        return false;

                if (**names != '\0') {
                        if (!member_name_is_valid(*names))
                                return false;
                        *names += strlen(*names) + 1;
                } else if (*flags & NAMES_PRESENT)
                        return false;

                signature += l;
        }
        /* let's check if there are more argument names specified than the signature allows */
        if (*flags & NAMES_PRESENT && **names != '\0' && !(*flags & NAMES_FIRST_PART))
                return false;
        *flags &= ~NAMES_FIRST_PART;
        return true;
}

/* the current version of this struct is defined in sd-bus-vtable.h, but we need to list here the historical versions
   to make sure the calling code is compatible with one of these */
struct sd_bus_vtable_221 {
        uint8_t type:8;
        uint64_t flags:56;
        union {
                struct {
                        size_t element_size;
                } start;
                struct {
                        const char *member;
                        const char *signature;
                        const char *result;
                        sd_bus_message_handler_t handler;
                        size_t offset;
                } method;
                struct {
                        const char *member;
                        const char *signature;
                } signal;
                struct {
                        const char *member;
                        const char *signature;
                        sd_bus_property_get_t get;
                        sd_bus_property_set_t set;
                        size_t offset;
                } property;
        } x;
};
/* Structure size up to v241 */
#define VTABLE_ELEMENT_SIZE_221 sizeof(struct sd_bus_vtable_221)

/* Size of the structure when "features" field was added. If the structure definition is augmented, a copy of
 * the structure definition will need to be made (similarly to the sd_bus_vtable_221 above), and this
 * definition updated to refer to it. */
#define VTABLE_ELEMENT_SIZE_242 sizeof(struct sd_bus_vtable)

static int vtable_features(const sd_bus_vtable *vtable) {
        if (vtable[0].x.start.element_size < VTABLE_ELEMENT_SIZE_242 ||
            !vtable[0].x.start.vtable_format_reference)
                return 0;
        return vtable[0].x.start.features;
}

bool bus_vtable_has_names(const sd_bus_vtable *vtable) {
        return vtable_features(vtable) & _SD_BUS_VTABLE_PARAM_NAMES;
}

const sd_bus_vtable* bus_vtable_next(const sd_bus_vtable *vtable, const sd_bus_vtable *v) {
        return (const sd_bus_vtable*) ((char*) v + vtable[0].x.start.element_size);
}

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
        struct node_vtable *existing = NULL;
        const sd_bus_vtable *v;
        struct node *n;
        int r;
        const char *names = "";
        names_flags nf;

        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(object_path_is_valid(path), -EINVAL);
        assert_return(interface_name_is_valid(interface), -EINVAL);
        assert_return(vtable, -EINVAL);
        assert_return(vtable[0].type == _SD_BUS_VTABLE_START, -EINVAL);
        assert_return(vtable[0].x.start.element_size == VTABLE_ELEMENT_SIZE_221 ||
                      vtable[0].x.start.element_size >= VTABLE_ELEMENT_SIZE_242,
                      -EINVAL);
        assert_return(!bus_origin_changed(bus), -ECHILD);
        assert_return(!streq(interface, "org.freedesktop.DBus.Properties") &&
                      !streq(interface, "org.freedesktop.DBus.Introspectable") &&
                      !streq(interface, "org.freedesktop.DBus.Peer") &&
                      !streq(interface, "org.freedesktop.DBus.ObjectManager"), -EINVAL);

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

        v = s->node_vtable.vtable;
        for (v = bus_vtable_next(vtable, v); v->type != _SD_BUS_VTABLE_END; v = bus_vtable_next(vtable, v)) {

                switch (v->type) {

                case _SD_BUS_VTABLE_METHOD: {
                        struct vtable_member *m;
                        nf = NAMES_FIRST_PART;

                        if (bus_vtable_has_names(vtable))
                                names = strempty(v->x.method.names);

                        if (!member_name_is_valid(v->x.method.member) ||
                            !signature_is_valid(strempty(v->x.method.signature), false) ||
                            !signature_is_valid(strempty(v->x.method.result), false) ||
                            !names_are_valid(strempty(v->x.method.signature), &names, &nf) ||
                            !names_are_valid(strempty(v->x.method.result), &names, &nf) ||
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

                        r = set_ensure_put(&bus->vtable_methods, &vtable_member_hash_ops, m);
                        if (r == 0)
                                r = -EEXIST;
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

                        _fallthrough_;
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

                        r = set_ensure_put(&bus->vtable_properties, &vtable_member_hash_ops, m);
                        if (r == 0)
                                r = -EEXIST;
                        if (r < 0) {
                                free(m);
                                goto fail;
                        }

                        break;
                }

                case _SD_BUS_VTABLE_SIGNAL:
                        nf = NAMES_SINGLE_PART;

                        if (bus_vtable_has_names(vtable))
                                names = strempty(v->x.signal.names);

                        if (!member_name_is_valid(v->x.signal.member) ||
                            !signature_is_valid(strempty(v->x.signal.signature), false) ||
                            !names_are_valid(strempty(v->x.signal.signature), &names, &nf) ||
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

/* This symbol exists solely to tell the linker that the "new" vtable format is used. */
_public_ const unsigned sd_bus_object_vtable_format = 242;

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
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(object_path_is_valid(path), -EINVAL);
        assert_return(callback, -EINVAL);
        assert_return(!bus_origin_changed(bus), -ECHILD);

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

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        bool has_invalidating = false, has_changing = false;
        struct vtable_member key = {};
        struct node *n;
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
                                v = set_get(bus->vtable_properties, &key);
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

                        v = c->vtable;
                        for (v = bus_vtable_next(c->vtable, v); v->type != _SD_BUS_VTABLE_END; v = bus_vtable_next(c->vtable, v)) {
                                if (!IN_SET(v->type, _SD_BUS_VTABLE_PROPERTY, _SD_BUS_VTABLE_WRITABLE_PROPERTY))
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
                                        assert_se(v = set_get(bus->vtable_properties, &key));
                                        assert(c == v->parent);

                                        if (!(v->vtable->flags & SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION))
                                                continue;

                                        r = sd_bus_message_append(m, "s", *property);
                                        if (r < 0)
                                                return r;
                                }
                        } else {
                                const sd_bus_vtable *v;

                                v = c->vtable;
                                for (v = bus_vtable_next(c->vtable, v); v->type != _SD_BUS_VTABLE_END; v = bus_vtable_next(c->vtable, v)) {
                                        if (!IN_SET(v->type, _SD_BUS_VTABLE_PROPERTY, _SD_BUS_VTABLE_WRITABLE_PROPERTY))
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

        _cleanup_free_ char *prefix = NULL;
        bool found_interface = false;
        size_t pl;
        int r;

        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(object_path_is_valid(path), -EINVAL);
        assert_return(interface_name_is_valid(interface), -EINVAL);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        /* A non-NULL but empty names list means nothing needs to be
           generated. A NULL list OTOH indicates that all properties
           that are set to EMITS_CHANGE or EMITS_INVALIDATION shall be
           included in the PropertiesChanged message. */
        if (names && names[0] == NULL)
                return 0;

        BUS_DONT_DESTROY(bus);

        pl = strlen(path);
        assert(pl <= BUS_PATH_SIZE_MAX);
        prefix = new(char, pl + 1);
        if (!prefix)
                return -ENOMEM;

        do {
                bus->nodes_modified = false;

                r = emit_properties_changed_on_interface(bus, path, path, interface, false, &found_interface, names);
                if (r != 0)
                        return r;
                if (bus->nodes_modified)
                        continue;

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
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(object_path_is_valid(path), -EINVAL);
        assert_return(interface_name_is_valid(interface), -EINVAL);
        assert_return(!bus_origin_changed(bus), -ECHILD);

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
                OrderedSet *s,
                const char *prefix,
                const char *path,
                bool require_fallback) {

        const char *previous_interface = NULL;
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
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
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
                        if (ordered_set_get(s, c->interface))
                                continue;

                        r = ordered_set_put(s, c->interface);
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

static int object_added_append_all(sd_bus *bus, sd_bus_message *m, const char *path, bool path_has_object_manager) {
        _cleanup_ordered_set_free_ OrderedSet *s = NULL;
        _cleanup_free_ char *prefix = NULL;
        size_t pl;
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

        s = ordered_set_new(&string_hash_ops);
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
        if (path_has_object_manager){
                r = sd_bus_message_append(m, "{sa{sv}}", "org.freedesktop.DBus.ObjectManager", 0);
                if (r < 0)
                        return r;
        }

        r = object_added_append_all_prefix(bus, m, s, path, path, false);
        if (r < 0)
                return r;
        if (bus->nodes_modified)
                return 0;

        pl = strlen(path);
        assert(pl <= BUS_PATH_SIZE_MAX);
        prefix = new(char, pl + 1);
        if (!prefix)
                return -ENOMEM;

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
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
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
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(object_path_is_valid(path), -EINVAL);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        bool path_has_object_manager = false;
        r = bus_find_parent_object_manager(bus, &object_manager, path, &path_has_object_manager);
        if (r < 0)
                return r;
        if (r == 0)
                return -ESRCH;

        BUS_DONT_DESTROY(bus);

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

                r = object_added_append_all(bus, m, path, path_has_object_manager);
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
                OrderedSet *s,
                const char *prefix,
                const char *path,
                bool require_fallback) {

        const char *previous_interface = NULL;
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
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                void *u = NULL;

                if (require_fallback && !c->is_fallback)
                        continue;
                if (streq_ptr(c->interface, previous_interface))
                        continue;

                /* If a child-node already handled this interface, we
                 * skip it on any of its parents. The child vtables
                 * always fully override any conflicting vtables of
                 * any parent node. */
                if (ordered_set_get(s, c->interface))
                        continue;

                r = node_vtable_get_userdata(bus, path, c, &u, &error);
                if (r < 0)
                        return r;
                if (bus->nodes_modified)
                        return 0;
                if (r == 0)
                        continue;

                r = ordered_set_put(s, c->interface);
                if (r < 0)
                        return r;

                r = sd_bus_message_append(m, "s", c->interface);
                if (r < 0)
                        return r;

                previous_interface = c->interface;
        }

        return 0;
}

static int object_removed_append_all(sd_bus *bus, sd_bus_message *m, const char *path, bool path_has_object_manager) {
        _cleanup_ordered_set_free_ OrderedSet *s = NULL;
        _cleanup_free_ char *prefix = NULL;
        size_t pl;
        int r;

        assert(bus);
        assert(m);
        assert(path);

        /* see sd_bus_emit_object_added() for details */

        s = ordered_set_new(&string_hash_ops);
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

        if (path_has_object_manager){
                r = sd_bus_message_append(m, "s", "org.freedesktop.DBus.ObjectManager");
                if (r < 0)
                        return r;
        }

        r = object_removed_append_all_prefix(bus, m, s, path, path, false);
        if (r < 0)
                return r;
        if (bus->nodes_modified)
                return 0;

        pl = strlen(path);
        assert(pl <= BUS_PATH_SIZE_MAX);
        prefix = new(char, pl + 1);
        if (!prefix)
                return -ENOMEM;

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
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
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
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(object_path_is_valid(path), -EINVAL);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        bool path_has_object_manager = false;
        r = bus_find_parent_object_manager(bus, &object_manager, path, &path_has_object_manager);
        if (r < 0)
                return r;
        if (r == 0)
                return -ESRCH;

        BUS_DONT_DESTROY(bus);

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

                r = object_removed_append_all(bus, m, path, path_has_object_manager);
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

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        bool found_interface = false;
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

        _cleanup_free_ char *prefix = NULL;
        size_t pl;
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

        pl = strlen(path);
        assert(pl <= BUS_PATH_SIZE_MAX);
        prefix = new(char, pl + 1);
        if (!prefix)
                return -ENOMEM;

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
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        struct node *object_manager;
        int r;

        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(object_path_is_valid(path), -EINVAL);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        if (strv_isempty(interfaces))
                return 0;

        bool path_has_object_manager = false;
        r = bus_find_parent_object_manager(bus, &object_manager, path, &path_has_object_manager);
        if (r < 0)
                return r;
        if (r == 0)
                return -ESRCH;

        BUS_DONT_DESTROY(bus);

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
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(object_path_is_valid(path), -EINVAL);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        interfaces = strv_from_stdarg_alloca(interface);

        return sd_bus_emit_interfaces_added_strv(bus, path, interfaces);
}

_public_ int sd_bus_emit_interfaces_removed_strv(sd_bus *bus, const char *path, char **interfaces) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        struct node *object_manager;
        int r;

        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(object_path_is_valid(path), -EINVAL);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        if (strv_isempty(interfaces))
                return 0;

        bool path_has_object_manager = false;
        r = bus_find_parent_object_manager(bus, &object_manager, path, &path_has_object_manager);
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
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(object_path_is_valid(path), -EINVAL);
        assert_return(!bus_origin_changed(bus), -ECHILD);

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
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(object_path_is_valid(path), -EINVAL);
        assert_return(!bus_origin_changed(bus), -ECHILD);

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
