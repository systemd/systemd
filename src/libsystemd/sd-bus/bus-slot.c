/* SPDX-License-Identifier: LGPL-2.1+ */

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-control.h"
#include "bus-objects.h"
#include "bus-slot.h"
#include "string-util.h"

sd_bus_slot *bus_slot_allocate(
                sd_bus *bus,
                bool floating,
                BusSlotType type,
                size_t extra,
                void *userdata) {

        sd_bus_slot *slot;

        assert(bus);

        slot = malloc0(offsetof(sd_bus_slot, reply_callback) + extra);
        if (!slot)
                return NULL;

        slot->n_ref = 1;
        slot->type = type;
        slot->bus = bus;
        slot->floating = floating;
        slot->userdata = userdata;

        if (!floating)
                sd_bus_ref(bus);

        LIST_PREPEND(slots, bus->slots, slot);

        return slot;
}

void bus_slot_disconnect(sd_bus_slot *slot, bool unref) {
        sd_bus *bus;

        assert(slot);

        if (!slot->bus)
                return;

        switch (slot->type) {

        case BUS_REPLY_CALLBACK:

                if (slot->reply_callback.cookie != 0)
                        ordered_hashmap_remove(slot->bus->reply_callbacks, &slot->reply_callback.cookie);

                if (slot->reply_callback.timeout_usec != 0)
                        prioq_remove(slot->bus->reply_callbacks_prioq, &slot->reply_callback, &slot->reply_callback.prioq_idx);

                break;

        case BUS_FILTER_CALLBACK:
                slot->bus->filter_callbacks_modified = true;
                LIST_REMOVE(callbacks, slot->bus->filter_callbacks, &slot->filter_callback);
                break;

        case BUS_MATCH_CALLBACK:

                if (slot->match_added)
                        (void) bus_remove_match_internal(slot->bus, slot->match_callback.match_string);

                if (slot->match_callback.install_slot) {
                        bus_slot_disconnect(slot->match_callback.install_slot, true);
                        slot->match_callback.install_slot = sd_bus_slot_unref(slot->match_callback.install_slot);
                }

                slot->bus->match_callbacks_modified = true;
                bus_match_remove(&slot->bus->match_callbacks, &slot->match_callback);

                slot->match_callback.match_string = mfree(slot->match_callback.match_string);

                break;

        case BUS_NODE_CALLBACK:

                if (slot->node_callback.node) {
                        LIST_REMOVE(callbacks, slot->node_callback.node->callbacks, &slot->node_callback);
                        slot->bus->nodes_modified = true;

                        bus_node_gc(slot->bus, slot->node_callback.node);
                }

                break;

        case BUS_NODE_ENUMERATOR:

                if (slot->node_enumerator.node) {
                        LIST_REMOVE(enumerators, slot->node_enumerator.node->enumerators, &slot->node_enumerator);
                        slot->bus->nodes_modified = true;

                        bus_node_gc(slot->bus, slot->node_enumerator.node);
                }

                break;

        case BUS_NODE_OBJECT_MANAGER:

                if (slot->node_object_manager.node) {
                        LIST_REMOVE(object_managers, slot->node_object_manager.node->object_managers, &slot->node_object_manager);
                        slot->bus->nodes_modified = true;

                        bus_node_gc(slot->bus, slot->node_object_manager.node);
                }

                break;

        case BUS_NODE_VTABLE:

                if (slot->node_vtable.node && slot->node_vtable.interface && slot->node_vtable.vtable) {
                        const sd_bus_vtable *v;

                        for (v = slot->node_vtable.vtable; v->type != _SD_BUS_VTABLE_END; v++) {
                                struct vtable_member *x = NULL;

                                switch (v->type) {

                                case _SD_BUS_VTABLE_METHOD: {
                                        struct vtable_member key;

                                        key.path = slot->node_vtable.node->path;
                                        key.interface = slot->node_vtable.interface;
                                        key.member = v->x.method.member;

                                        x = hashmap_remove(slot->bus->vtable_methods, &key);
                                        break;
                                }

                                case _SD_BUS_VTABLE_PROPERTY:
                                case _SD_BUS_VTABLE_WRITABLE_PROPERTY: {
                                        struct vtable_member key;

                                        key.path = slot->node_vtable.node->path;
                                        key.interface = slot->node_vtable.interface;
                                        key.member = v->x.method.member;

                                        x = hashmap_remove(slot->bus->vtable_properties, &key);
                                        break;
                                }}

                                free(x);
                        }
                }

                slot->node_vtable.interface = mfree(slot->node_vtable.interface);

                if (slot->node_vtable.node) {
                        LIST_REMOVE(vtables, slot->node_vtable.node->vtables, &slot->node_vtable);
                        slot->bus->nodes_modified = true;

                        bus_node_gc(slot->bus, slot->node_vtable.node);
                }

                break;

        default:
                assert_not_reached("Wut? Unknown slot type?");
        }

        bus = slot->bus;

        slot->type = _BUS_SLOT_INVALID;
        slot->bus = NULL;
        LIST_REMOVE(slots, bus->slots, slot);

        if (!slot->floating)
                sd_bus_unref(bus);
        else if (unref)
                sd_bus_slot_unref(slot);
}

static sd_bus_slot* bus_slot_free(sd_bus_slot *slot) {
        assert(slot);

        bus_slot_disconnect(slot, false);

        if (slot->destroy_callback)
                slot->destroy_callback(slot->userdata);

        free(slot->description);
        return mfree(slot);
}

DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(sd_bus_slot, sd_bus_slot, bus_slot_free);

_public_ sd_bus* sd_bus_slot_get_bus(sd_bus_slot *slot) {
        assert_return(slot, NULL);

        return slot->bus;
}

_public_ void *sd_bus_slot_get_userdata(sd_bus_slot *slot) {
        assert_return(slot, NULL);

        return slot->userdata;
}

_public_ void *sd_bus_slot_set_userdata(sd_bus_slot *slot, void *userdata) {
        void *ret;

        assert_return(slot, NULL);

        ret = slot->userdata;
        slot->userdata = userdata;

        return ret;
}

_public_ int sd_bus_slot_set_destroy_callback(sd_bus_slot *slot, sd_bus_destroy_t callback) {
        assert_return(slot, -EINVAL);

        slot->destroy_callback = callback;
        return 0;
}

_public_ int sd_bus_slot_get_destroy_callback(sd_bus_slot *slot, sd_bus_destroy_t *callback) {
        assert_return(slot, -EINVAL);

        if (callback)
                *callback = slot->destroy_callback;

        return !!slot->destroy_callback;
}

_public_ sd_bus_message *sd_bus_slot_get_current_message(sd_bus_slot *slot) {
        assert_return(slot, NULL);
        assert_return(slot->type >= 0, NULL);

        if (slot->bus->current_slot != slot)
                return NULL;

        return slot->bus->current_message;
}

_public_ sd_bus_message_handler_t sd_bus_slot_get_current_handler(sd_bus_slot *slot) {
        assert_return(slot, NULL);
        assert_return(slot->type >= 0, NULL);

        if (slot->bus->current_slot != slot)
                return NULL;

        return slot->bus->current_handler;
}

_public_ void* sd_bus_slot_get_current_userdata(sd_bus_slot *slot) {
        assert_return(slot, NULL);
        assert_return(slot->type >= 0, NULL);

        if (slot->bus->current_slot != slot)
                return NULL;

        return slot->bus->current_userdata;
}

_public_ int sd_bus_slot_get_floating(sd_bus_slot *slot) {
        assert_return(slot, -EINVAL);

        return slot->floating;
}

_public_ int sd_bus_slot_set_floating(sd_bus_slot *slot, int b) {
        assert_return(slot, -EINVAL);

        if (slot->floating == !!b)
                return 0;

        if (!slot->bus) /* already disconnected slots can't be reconnected */
                return -ESTALE;

        slot->floating = b;

        /* When a slot is "floating" then the bus references the slot. Otherwise the slot references the bus. Hence,
         * when we move from one to the other, let's increase one reference and decrease the other. */

        if (b) {
                sd_bus_slot_ref(slot);
                sd_bus_unref(slot->bus);
        } else {
                sd_bus_ref(slot->bus);
                sd_bus_slot_unref(slot);
        }

        return 1;
}

_public_ int sd_bus_slot_set_description(sd_bus_slot *slot, const char *description) {
        assert_return(slot, -EINVAL);

        return free_and_strdup(&slot->description, description);
}

_public_ int sd_bus_slot_get_description(sd_bus_slot *slot, const char **description) {
        assert_return(slot, -EINVAL);
        assert_return(description, -EINVAL);

        if (slot->description)
                *description = slot->description;
        else if (slot->type == BUS_MATCH_CALLBACK)
                *description = slot->match_callback.match_string;
        else
                return -ENXIO;

        return 0;
}
