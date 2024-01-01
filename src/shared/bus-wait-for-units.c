/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-error.h"
#include "bus-map-properties.h"
#include "bus-wait-for-units.h"
#include "hashmap.h"
#include "string-util.h"
#include "strv.h"
#include "unit-def.h"

typedef struct WaitForItem {
        BusWaitForUnits *parent;

        BusWaitForUnitsFlags flags;

        char *bus_path;

        sd_bus_slot *slot_get_all;
        sd_bus_slot *slot_properties_changed;

        bus_wait_for_units_unit_callback unit_callback;
        void *userdata;

        char *active_state;
        uint32_t job_id;
        char *clean_result;
} WaitForItem;

typedef struct BusWaitForUnits {
        sd_bus *bus;
        sd_bus_slot *slot_disconnected;

        Hashmap *items;

        bus_wait_for_units_ready_callback ready_callback;
        void *userdata;

        WaitForItem *current;

        BusWaitForUnitsState state;
        bool has_failed:1;
} BusWaitForUnits;

static WaitForItem *wait_for_item_free(WaitForItem *item) {
        int r;

        if (!item)
                return NULL;

        if (item->parent) {
                if (FLAGS_SET(item->flags, BUS_WAIT_REFFED) && item->bus_path && item->parent->bus) {
                        r = sd_bus_call_method_async(
                                        item->parent->bus,
                                        NULL,
                                        "org.freedesktop.systemd1",
                                        item->bus_path,
                                        "org.freedesktop.systemd1.Unit",
                                        "Unref",
                                        NULL,
                                        NULL,
                                        NULL);
                        if (r < 0)
                                log_debug_errno(r, "Failed to drop reference to unit %s, ignoring: %m", item->bus_path);
                }

                assert_se(hashmap_remove_value(item->parent->items, item->bus_path, item));

                if (item->parent->current == item)
                        item->parent->current = NULL;
        }

        sd_bus_slot_unref(item->slot_properties_changed);
        sd_bus_slot_unref(item->slot_get_all);

        free(item->bus_path);
        free(item->active_state);
        free(item->clean_result);

        return mfree(item);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(WaitForItem*, wait_for_item_free);

static void call_unit_callback_and_wait(BusWaitForUnits *d, WaitForItem *item, bool good) {
        d->current = item;

        if (item->unit_callback)
                item->unit_callback(d, item->bus_path, good, item->userdata);

        wait_for_item_free(item);
}

static void bus_wait_for_units_clear(BusWaitForUnits *d) {
        WaitForItem *item;

        assert(d);

        d->slot_disconnected = sd_bus_slot_unref(d->slot_disconnected);
        d->bus = sd_bus_unref(d->bus);

        while ((item = hashmap_first(d->items)))
                call_unit_callback_and_wait(d, item, false);

        d->items = hashmap_free(d->items);
}

static int match_disconnected(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        BusWaitForUnits *d = ASSERT_PTR(userdata);

        assert(m);

        log_error("Warning! D-Bus connection terminated.");

        bus_wait_for_units_clear(d);

        if (d->ready_callback)
                d->ready_callback(d, false, d->userdata);
        else /* If no ready callback is specified close the connection so that the event loop exits */
                sd_bus_close(sd_bus_message_get_bus(m));

        return 0;
}

int bus_wait_for_units_new(sd_bus *bus, BusWaitForUnits **ret) {
        _cleanup_(bus_wait_for_units_freep) BusWaitForUnits *d = NULL;
        int r;

        assert(bus);
        assert(ret);

        d = new(BusWaitForUnits, 1);
        if (!d)
                return -ENOMEM;

        *d = (BusWaitForUnits) {
                .state = BUS_WAIT_SUCCESS,
                .bus = sd_bus_ref(bus),
        };

        r = sd_bus_match_signal_async(
                        bus,
                        &d->slot_disconnected,
                        "org.freedesktop.DBus.Local",
                        NULL,
                        "org.freedesktop.DBus.Local",
                        "Disconnected",
                        match_disconnected, NULL, d);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(d);
        return 0;
}

BusWaitForUnits* bus_wait_for_units_free(BusWaitForUnits *d) {
        if (!d)
                return NULL;

        bus_wait_for_units_clear(d);
        sd_bus_slot_unref(d->slot_disconnected);
        sd_bus_unref(d->bus);

        return mfree(d);
}

static bool bus_wait_for_units_is_ready(BusWaitForUnits *d) {
        assert(d);

        if (!d->bus) /* Disconnected? */
                return true;

        return hashmap_isempty(d->items);
}

void bus_wait_for_units_set_ready_callback(BusWaitForUnits *d, bus_wait_for_units_ready_callback callback, void *userdata) {
        assert(d);

        d->ready_callback = callback;
        d->userdata = userdata;
}

static void bus_wait_for_units_check_ready(BusWaitForUnits *d) {
        assert(d);

        if (!bus_wait_for_units_is_ready(d))
                return;

        d->state = d->has_failed ? BUS_WAIT_FAILURE : BUS_WAIT_SUCCESS;

        if (d->ready_callback)
                d->ready_callback(d, d->state, d->userdata);
}

static void wait_for_item_check_ready(WaitForItem *item) {
        BusWaitForUnits *d;

        assert(item);
        assert_se(d = item->parent);

        if (FLAGS_SET(item->flags, BUS_WAIT_FOR_MAINTENANCE_END)) {

                if (item->clean_result && !streq(item->clean_result, "success"))
                        d->has_failed = true;

                if (!item->active_state || streq(item->active_state, "maintenance"))
                        return;
        }

        if (FLAGS_SET(item->flags, BUS_WAIT_NO_JOB) && item->job_id != 0)
                return;

        if (FLAGS_SET(item->flags, BUS_WAIT_FOR_INACTIVE)) {

                if (streq_ptr(item->active_state, "failed"))
                        d->has_failed = true;
                else if (!streq_ptr(item->active_state, "inactive"))
                        return;
        }

        call_unit_callback_and_wait(d, item, true);
        bus_wait_for_units_check_ready(d);
}

static int property_map_job(
                sd_bus *bus,
                const char *member,
                sd_bus_message *m,
                sd_bus_error *error,
                void *userdata) {

        WaitForItem *item = ASSERT_PTR(userdata);
        const char *path;
        uint32_t id;
        int r;

        r = sd_bus_message_read(m, "(uo)", &id, &path);
        if (r < 0)
                return r;

        item->job_id = id;
        return 0;
}

static int wait_for_item_parse_properties(WaitForItem *item, sd_bus_message *m) {

        static const struct bus_properties_map map[] = {
                { "ActiveState", "s",    NULL,             offsetof(WaitForItem, active_state) },
                { "Job",         "(uo)", property_map_job, 0                                   },
                { "CleanResult", "s",    NULL,             offsetof(WaitForItem, clean_result) },
                {}
        };

        int r;

        assert(item);
        assert(m);

        r = bus_message_map_all_properties(m, map, BUS_MAP_STRDUP, NULL, item);
        if (r < 0)
                return r;

        wait_for_item_check_ready(item);
        return 0;
}

static int on_properties_changed(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        WaitForItem *item = ASSERT_PTR(userdata);
        const char *interface;
        int r;

        r = sd_bus_message_read(m, "s", &interface);
        if (r < 0) {
                log_debug_errno(r, "Failed to parse PropertiesChanged signal: %m");
                return 0;
        }

        if (!streq(interface, "org.freedesktop.systemd1.Unit"))
                return 0;

        r = wait_for_item_parse_properties(item, m);
        if (r < 0)
                log_debug_errno(r, "Failed to process PropertiesChanged signal: %m");

        return 0;
}

static int on_get_all_properties(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        WaitForItem *item = ASSERT_PTR(userdata);
        const sd_bus_error *e;
        int r;

        e = sd_bus_message_get_error(m);
        if (e) {
                BusWaitForUnits *d = item->parent;

                d->has_failed = true;

                r = sd_bus_error_get_errno(e);
                log_debug_errno(r, "GetAll() failed for %s: %s",
                                item->bus_path, bus_error_message(e, r));

                call_unit_callback_and_wait(d, item, false);
                bus_wait_for_units_check_ready(d);
                return 0;
        }

        r = wait_for_item_parse_properties(item, m);
        if (r < 0)
                log_debug_errno(r, "Failed to process GetAll method reply: %m");

        return 0;
}

int bus_wait_for_units_add_unit(
                BusWaitForUnits *d,
                const char *unit,
                BusWaitForUnitsFlags flags,
                bus_wait_for_units_unit_callback callback,
                void *userdata) {

        _cleanup_(wait_for_item_freep) WaitForItem *item = NULL;
        int r;

        assert(d);
        assert(unit);

        assert(flags != 0);

        r = hashmap_ensure_allocated(&d->items, &string_hash_ops);
        if (r < 0)
                return r;

        item = new(WaitForItem, 1);
        if (!item)
                return -ENOMEM;

        *item = (WaitForItem) {
                .flags = flags,
                .bus_path = unit_dbus_path_from_name(unit),
                .unit_callback = callback,
                .userdata = userdata,
                .job_id = UINT32_MAX,
        };

        if (!item->bus_path)
                return -ENOMEM;

        if (!FLAGS_SET(item->flags, BUS_WAIT_REFFED)) {
                r = sd_bus_call_method_async(
                                d->bus,
                                NULL,
                                "org.freedesktop.systemd1",
                                item->bus_path,
                                "org.freedesktop.systemd1.Unit",
                                "Ref",
                                NULL,
                                NULL,
                                NULL);
                if (r < 0)
                        return log_debug_errno(r, "Failed to add reference to unit %s: %m", unit);

                item->flags |= BUS_WAIT_REFFED;
        }

        r = sd_bus_match_signal_async(
                        d->bus,
                        &item->slot_properties_changed,
                        "org.freedesktop.systemd1",
                        item->bus_path,
                        "org.freedesktop.DBus.Properties",
                        "PropertiesChanged",
                        on_properties_changed,
                        NULL,
                        item);
        if (r < 0)
                return log_debug_errno(r, "Failed to request match for PropertiesChanged signal: %m");

        r = sd_bus_call_method_async(
                        d->bus,
                        &item->slot_get_all,
                        "org.freedesktop.systemd1",
                        item->bus_path,
                        "org.freedesktop.DBus.Properties",
                        "GetAll",
                        on_get_all_properties,
                        item,
                        "s", FLAGS_SET(item->flags, BUS_WAIT_FOR_MAINTENANCE_END) ? NULL : "org.freedesktop.systemd1.Unit");
        if (r < 0)
                return log_debug_errno(r, "Failed to request properties of unit %s: %m", unit);

        r = hashmap_put(d->items, item->bus_path, item);
        if (r < 0)
                return r;

        d->state = BUS_WAIT_RUNNING;
        item->parent = d;
        TAKE_PTR(item);
        return 0;
}

int bus_wait_for_units_run(BusWaitForUnits *d) {
        int r;

        assert(d);

        while (d->state == BUS_WAIT_RUNNING) {

                r = sd_bus_process(d->bus, NULL);
                if (r < 0)
                        return r;
                if (r > 0)
                        continue;

                r = sd_bus_wait(d->bus, UINT64_MAX);
                if (r < 0)
                        return r;
        }

        return d->state;
}

BusWaitForUnitsState bus_wait_for_units_state(BusWaitForUnits *d) {
        assert(d);

        return d->state;
}
