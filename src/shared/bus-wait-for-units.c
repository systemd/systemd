/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-error.h"
#include "bus-map-properties.h"
#include "bus-wait-for-units.h"
#include "hashmap.h"
#include "log.h"
#include "string-util.h"
#include "unit-def.h"

typedef struct WaitForItem {
        BusWaitForUnits *parent;

        BusWaitForUnitsFlags flags;

        char *bus_path;

        sd_bus_slot *slot_get_all;
        sd_bus_slot *slot_properties_changed;

        bus_wait_for_units_unit_callback_t unit_callback;
        void *userdata;

        char *active_state;
        uint32_t job_id;
        char *clean_result;
        char *live_mount_result;
} WaitForItem;

typedef struct BusWaitForUnits {
        sd_bus *bus;
        sd_bus_slot *slot_disconnected;

        Hashmap *items;

        BusWaitForUnitsState state;
        bool has_failed:1;
} BusWaitForUnits;

static WaitForItem* wait_for_item_free(WaitForItem *item) {
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
        }

        sd_bus_slot_unref(item->slot_properties_changed);
        sd_bus_slot_unref(item->slot_get_all);

        free(item->bus_path);
        free(item->active_state);
        free(item->clean_result);
        free(item->live_mount_result);

        return mfree(item);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(WaitForItem*, wait_for_item_free);

static void call_unit_callback_and_wait(BusWaitForUnits *d, WaitForItem *item, bool good) {
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

static int match_disconnected(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        BusWaitForUnits *d = ASSERT_PTR(userdata);

        assert(m);

        log_warning("D-Bus connection terminated while waiting for unit.");

        bus_wait_for_units_clear(d);
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

static void bus_wait_for_units_check_ready(BusWaitForUnits *d) {
        assert(d);

        if (!bus_wait_for_units_is_ready(d))
                return;

        d->state = d->has_failed ? BUS_WAIT_FAILURE : BUS_WAIT_SUCCESS;
}

static void wait_for_item_check_ready(WaitForItem *item) {
        BusWaitForUnits *d;

        assert(item);
        assert_se(d = item->parent);

        if (FLAGS_SET(item->flags, BUS_WAIT_FOR_MAINTENANCE_END)) {

                if (item->clean_result && !streq(item->clean_result, "success"))
                        d->has_failed = true;

                if (item->live_mount_result && !streq(item->live_mount_result, "success"))
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

static int wait_for_item_parse_properties(WaitForItem *item, sd_bus_message *m) {

        static const struct bus_properties_map map[] = {
                { "ActiveState",     "s",    NULL,                offsetof(WaitForItem, active_state)      },
                { "Job",             "(uo)", bus_map_job_id,      offsetof(WaitForItem, job_id)            },
                { "CleanResult",     "s",    NULL,                offsetof(WaitForItem, clean_result)      },
                { "LiveMountResult", "s",    NULL,                offsetof(WaitForItem, live_mount_result) },
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

static int on_properties_changed(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
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

static int on_get_all_properties(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
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
                bus_wait_for_units_unit_callback_t callback,
                void *userdata) {

        _cleanup_(wait_for_item_freep) WaitForItem *item = NULL;
        _cleanup_free_ char *bus_path = NULL;
        int r;

        assert(d);
        assert(unit);
        assert((flags & _BUS_WAIT_FOR_TARGET) != 0);

        bus_path = unit_dbus_path_from_name(unit);
        if (!bus_path)
                return -ENOMEM;

        if (hashmap_contains(d->items, bus_path))
                return 0;

        item = new(WaitForItem, 1);
        if (!item)
                return -ENOMEM;

        *item = (WaitForItem) {
                .flags = flags,
                .bus_path = TAKE_PTR(bus_path),
                .unit_callback = callback,
                .userdata = userdata,
                .job_id = UINT32_MAX,
        };

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

        r = hashmap_ensure_put(&d->items, &string_hash_ops, item->bus_path, item);
        if (r < 0)
                return r;
        assert(r > 0);

        d->state = BUS_WAIT_RUNNING;
        item->parent = d;
        TAKE_PTR(item);

        return 1;
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
