/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-map-properties.h"
#include "bus-wait-for-units.h"
#include "hashmap.h"
#include "log.h"
#include "string-util.h"
#include "unit-def.h"
#include "unit-result.h"

typedef struct WaitForItem {
        BusWaitForUnits *parent;

        BusWaitForUnitsFlags flags;

        char *name;
        char *bus_path;

        /* The unit's primary name, as reported by the service manager. Might differ from what the caller
         * specified, if the caller used an alias. */
        char *id;

        sd_bus_slot *slot_get_all;
        sd_bus_slot *slot_properties_changed;
        sd_bus_slot *slot_collect_result;

        bus_wait_for_units_unit_callback_t unit_callback;
        void *userdata;

        char *load_state;
        char *active_state;
        uint32_t job_id;
        char *clean_result;
        char *live_mount_result;

        /* Set if we saw a UnitRemoved signal for this unit while the service manager was reloading, and
         * haven't verified yet whether it came back after the reload finished. */
        bool removed:1;

        /* Set if we should query the unit's properties again once the service manager finished reloading,
         * because we might have missed state changes in the meantime. */
        bool requery:1;

        UnitResult result;
} WaitForItem;

typedef struct BusWaitForUnits {
        sd_bus *bus;
        sd_bus_slot *slot_disconnected;
        sd_bus_slot *slot_subscribe;
        sd_bus_slot *slot_unit_removed;
        sd_bus_slot *slot_reloading;
        sd_bus_slot *slot_name_owner_changed;

        Hashmap *items;

        BusWaitForUnitsState state;
        bool has_failed:1;
        bool subscribed:1;  /* We successfully called Subscribe(), hence we should Unsubscribe() when done */
        bool reloading:1;   /* The service manager is currently reloading/reexecuting */
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
        sd_bus_slot_unref(item->slot_collect_result);

        unit_result_done(&item->result);

        free(item->name);
        free(item->bus_path);
        free(item->id);
        free(item->load_state);
        free(item->active_state);
        free(item->clean_result);
        free(item->live_mount_result);

        return mfree(item);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(WaitForItem*, wait_for_item_free);

static void call_unit_callback_and_wait(BusWaitForUnits *d, WaitForItem *item, bool good) {
        if (item->unit_callback)
                item->unit_callback(d,
                                    item->name,
                                    good,
                                    FLAGS_SET(item->flags, BUS_WAIT_COLLECT_RESULT) ? &item->result : NULL,
                                    item->userdata);

        wait_for_item_free(item);
}

static void bus_wait_for_units_clear(BusWaitForUnits *d) {
        WaitForItem *item;

        assert(d);

        d->slot_disconnected = sd_bus_slot_unref(d->slot_disconnected);
        d->slot_subscribe = sd_bus_slot_unref(d->slot_subscribe);
        d->slot_unit_removed = sd_bus_slot_unref(d->slot_unit_removed);
        d->slot_reloading = sd_bus_slot_unref(d->slot_reloading);
        d->slot_name_owner_changed = sd_bus_slot_unref(d->slot_name_owner_changed);
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

static void wait_for_item_fail(WaitForItem *item) {
        BusWaitForUnits *d;

        assert(item);
        assert_se(d = item->parent);

        d->has_failed = true;

        call_unit_callback_and_wait(d, item, false);
        bus_wait_for_units_check_ready(d);
}

static int on_collect_result(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        WaitForItem *item = ASSERT_PTR(userdata);
        BusWaitForUnits *d = ASSERT_PTR(item->parent);
        const sd_bus_error *e;
        bool good = true;
        int r;

        assert(m);

        e = sd_bus_message_get_error(m);
        if (e) {
                r = sd_bus_error_get_errno(e);

                if (d->reloading) {
                        /* The service manager is reloading or reexecuting right now, and might have dropped
                         * our request on the floor. Let's refresh the unit's properties once it is done,
                         * which will reissue this query if the unit is still in its final state. For that
                         * we must drop the slot here, as otherwise wait_for_item_check_ready() would
                         * consider the query still to be in progress. */
                        log_debug_errno(r, "Failed to query final state of unit %s while service manager is reloading, retrying later: %s",
                                        item->name, bus_error_message(e, r));
                        item->slot_collect_result = sd_bus_slot_unref(item->slot_collect_result);
                        item->requery = true;
                        return 0;
                }

                log_debug_errno(r, "Failed to query final state of unit %s: %s",
                                item->name, bus_error_message(e, r));
                good = false;
        } else {
                r = bus_message_map_all_properties(
                                m,
                                unit_result_property_map,
                                BUS_MAP_STRDUP,
                                /* reterr_error= */ NULL,
                                &item->result);
                if (r < 0) {
                        log_debug_errno(r, "Failed to parse final state of unit %s: %m", item->name);
                        good = false;
                }
        }

        /* If we couldn't determine how the unit finished, propagate this as failure, so that callers don't
         * mistake an empty result for a successfully collected one. */
        if (!good)
                d->has_failed = true;

        call_unit_callback_and_wait(d, item, good);
        bus_wait_for_units_check_ready(d);

        return 0;
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

        if (FLAGS_SET(item->flags, BUS_WAIT_COLLECT_RESULT)) {
                int r;

                if (item->slot_collect_result) /* Query already in progress? */
                        return;

                /* Now that the unit is done, query its final state and resource usage asynchronously, so
                 * that we can pass the data to the callback. Note that a full GetAll() query covering all
                 * interfaces is necessary for this, since the various resource accounting properties are not
                 * included in PropertiesChanged signals. */
                r = sd_bus_call_method_async(
                                d->bus,
                                &item->slot_collect_result,
                                "org.freedesktop.systemd1",
                                item->bus_path,
                                "org.freedesktop.DBus.Properties",
                                "GetAll",
                                on_collect_result,
                                item,
                                "s", "");
                if (r < 0) {
                        log_debug_errno(r, "Failed to query final state of unit %s: %m", item->name);
                        wait_for_item_fail(item);
                }

                return;
        }

        call_unit_callback_and_wait(d, item, true);
        bus_wait_for_units_check_ready(d);
}

static int on_properties_changed(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error);

static int wait_for_item_resolve_alias(WaitForItem *item) {
        _cleanup_(sd_bus_slot_unrefp) sd_bus_slot *slot = NULL;
        _cleanup_free_ char *bus_path = NULL;
        BusWaitForUnits *d;
        int r;

        assert(item);
        assert_se(d = item->parent);

        /* The caller might have specified the unit by one of its aliases, but the service manager emits its
         * signals (PropertiesChanged, UnitNew, UnitRemoved) with the object path derived from the unit's
         * primary name only. Hence, once we learnt the primary name from the GetAll() reply, switch over to
         * it, so that our signal match and our lookups line up with what the service manager sends. */

        if (!item->id)
                return 0;

        bus_path = unit_dbus_path_from_name(item->id);
        if (!bus_path)
                return -ENOMEM;

        if (streq(bus_path, item->bus_path))
                return 0;

        if (hashmap_contains(d->items, bus_path))
                return log_debug_errno(SYNTHETIC_ERRNO(EEXIST),
                                       "Unit %s is already being waited for under its primary name %s.",
                                       item->name, item->id);

        r = sd_bus_match_signal_async(
                        d->bus,
                        &slot,
                        "org.freedesktop.systemd1",
                        bus_path,
                        "org.freedesktop.DBus.Properties",
                        "PropertiesChanged",
                        on_properties_changed,
                        /* install_callback= */ NULL,
                        item);
        if (r < 0)
                return r;

        r = hashmap_put(d->items, bus_path, item);
        if (r < 0)
                return r;

        assert_se(hashmap_remove_value(d->items, item->bus_path, item));

        log_debug("Unit %s is an alias of %s, tracking the latter from now on.", item->name, item->id);

        free_and_replace(item->bus_path, bus_path);
        sd_bus_slot_unref(item->slot_properties_changed);
        item->slot_properties_changed = TAKE_PTR(slot);

        return 0;
}

static int wait_for_item_parse_properties(WaitForItem *item, sd_bus_message *m) {

        static const struct bus_properties_map map[] = {
                { "Id",              "s",    NULL,                offsetof(WaitForItem, id)                },
                { "LoadState",       "s",    NULL,                offsetof(WaitForItem, load_state)        },
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

        r = wait_for_item_resolve_alias(item);
        if (r < 0) {
                /* Without a signal match on the right object path we'd never learn about state changes of
                 * the unit, hence give up on it. */
                log_debug_errno(r, "Failed to track unit %s under its primary name: %m", item->name);
                wait_for_item_fail(item);
                return 0;
        }

        if (item->removed) {
                /* The unit was removed while the service manager was reloading, and we are now checking
                 * whether it came back. If it isn't loaded anymore it's gone for good. */
                if (streq_ptr(item->load_state, "not-found")) {
                        log_error("Unit %s has been removed during service manager reload while waiting for it.",
                                  item->name);
                        wait_for_item_fail(item);
                        return 0;
                }

                item->removed = false;
        }

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
                r = sd_bus_error_get_errno(e);

                if (item->parent->reloading) {
                        /* The service manager is reloading or reexecuting right now, and might have dropped
                         * our request on the floor. Let's try again once it is done. */
                        log_debug_errno(r, "GetAll() failed for %s while service manager is reloading, retrying later: %s",
                                        item->bus_path, bus_error_message(e, r));
                        item->requery = true;
                        return 0;
                }

                log_debug_errno(r, "GetAll() failed for %s: %s",
                                item->bus_path, bus_error_message(e, r));

                wait_for_item_fail(item);
                return 0;
        }

        r = wait_for_item_parse_properties(item, m);
        if (r < 0)
                log_debug_errno(r, "Failed to process GetAll method reply: %m");

        return 0;
}

static int wait_for_item_query(WaitForItem *item) {
        assert(item);
        assert(item->parent);

        item->slot_get_all = sd_bus_slot_unref(item->slot_get_all);

        return sd_bus_call_method_async(
                        item->parent->bus,
                        &item->slot_get_all,
                        "org.freedesktop.systemd1",
                        item->bus_path,
                        "org.freedesktop.DBus.Properties",
                        "GetAll",
                        on_get_all_properties,
                        item,
                        "s", FLAGS_SET(item->flags, BUS_WAIT_FOR_MAINTENANCE_END) ? NULL : "org.freedesktop.systemd1.Unit");
}

static int on_unit_removed(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        BusWaitForUnits *d = ASSERT_PTR(userdata);
        const char *id, *path;
        WaitForItem *item;
        int r;

        assert(m);

        r = sd_bus_message_read(m, "so", &id, &path);
        if (r < 0) {
                log_debug_errno(r, "Failed to parse UnitRemoved signal, ignoring: %m");
                return 0;
        }

        item = hashmap_get(d->items, path);
        if (!item)
                return 0;

        if (d->reloading) {
                /* While the service manager is reloading or reexecuting it removes all units and adds them
                 * back once it finished deserializing its state. Hence, don't fail right away, but remember
                 * the fact, and check again once reloading is complete. */
                log_debug("Unit %s has been removed while the service manager is reloading, deferring.", id);
                item->removed = true;
                return 0;
        }

        log_error("Unit %s has been removed while waiting for it.", id);
        wait_for_item_fail(item);

        return 0;
}

static int on_reloading(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        BusWaitForUnits *d = ASSERT_PTR(userdata);
        WaitForItem *item;
        int b, r;

        assert(m);

        r = sd_bus_message_read(m, "b", &b);
        if (r < 0) {
                log_debug_errno(r, "Failed to parse Reloading signal, ignoring: %m");
                return 0;
        }

        if (b) {
                log_debug("Service manager is reloading, deferring UnitRemoved handling.");
                d->reloading = true;
                return 0;
        }

        if (!d->reloading)
                return 0;

        log_debug("Service manager finished reloading, checking for removed units.");
        d->reloading = false;

        /* Reloading is complete. Any unit that was removed in the meantime typically has been added back
         * right after, but we cannot rely on being told about that: after a reexecution the service manager
         * doesn't send UnitNew for the units it deserialized, since at that point nobody is subscribed to
         * its signals yet. Hence query the properties of those units again, which tells us whether they are
         * still loaded, and refreshes our knowledge about them, since we might have missed state changes in
         * the meantime. */
        HASHMAP_FOREACH(item, d->items) {
                if (item->removed)
                        item->requery = true;

                if (!item->requery)
                        continue;

                item->requery = false;

                r = wait_for_item_query(item);
                if (r < 0) {
                        /* Without a fresh query we'd never learn about state changes we missed during the
                         * reload, hence give up on this unit. */
                        log_debug_errno(r, "Failed to request properties of unit %s: %m", item->bus_path);
                        wait_for_item_fail(item);
                }
        }

        return 0;
}

static int on_name_owner_changed(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        BusWaitForUnits *d = ASSERT_PTR(userdata);
        const char *name, *old_owner, *new_owner;
        int r;

        assert(m);

        r = sd_bus_message_read(m, "sss", &name, &old_owner, &new_owner);
        if (r < 0) {
                log_debug_errno(r, "Failed to parse NameOwnerChanged signal, ignoring: %m");
                return 0;
        }

        if (!streq(name, "org.freedesktop.systemd1") || !isempty(new_owner))
                return 0;

        if (d->reloading)
                return 0;

        /* The service manager gave up its bus name, which happens when it reexecutes: it sends
         * Reloading(true) right before, but without going through its event loop again, hence that signal
         * might never make it to the bus. The bus daemon however reliably tells us about the loss of the
         * name, hence use that as fallback to detect reexecution, and handle it the same way as a reload.
         * Once the service manager is back it will send us Reloading(false), since it keeps track of its
         * subscribers across reexecution. */
        log_debug("Service manager released its bus name, assuming it is reexecuting, deferring UnitRemoved handling.");
        d->reloading = true;

        return 0;
}

static int on_subscribe(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        BusWaitForUnits *d = ASSERT_PTR(userdata);
        const sd_bus_error *e;
        int r;

        assert(m);

        e = sd_bus_message_get_error(m);
        if (e) {
                /* If the caller already subscribed on this connection, that's fine, we'll get the signals
                 * either way. But let's leave the subscription in place in that case. */
                if (!sd_bus_error_has_name(e, BUS_ERROR_ALREADY_SUBSCRIBED)) {
                        r = sd_bus_error_get_errno(e);
                        log_debug_errno(r, "Failed to subscribe to service manager signals, ignoring: %s",
                                        bus_error_message(e, r));
                }

                return 0;
        }

        d->subscribed = true;
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

        r = bus_match_signal_async(
                        bus,
                        &d->slot_unit_removed,
                        bus_systemd_mgr,
                        "UnitRemoved",
                        on_unit_removed,
                        /* install_callback= */ NULL,
                        d);
        if (r < 0)
                return r;

        r = bus_match_signal_async(
                        bus,
                        &d->slot_reloading,
                        bus_systemd_mgr,
                        "Reloading",
                        on_reloading,
                        /* install_callback= */ NULL,
                        d);
        if (r < 0)
                return r;

        /* On reexecution the Reloading(true) signal might get lost, see on_name_owner_changed(). Hence also
         * watch the service manager's bus name. (This is only meaningful on bus client connections, as only
         * there a bus daemon exists that manages names.) */
        if (sd_bus_is_bus_client(bus) > 0) {
                r = sd_bus_add_match_async(
                                bus,
                                &d->slot_name_owner_changed,
                                "type='signal',"
                                "sender='org.freedesktop.DBus',"
                                "path='/org/freedesktop/DBus',"
                                "interface='org.freedesktop.DBus',"
                                "member='NameOwnerChanged',"
                                "arg0='org.freedesktop.systemd1'",
                                on_name_owner_changed,
                                /* install_callback= */ NULL,
                                d);
                if (r < 0)
                        return r;
        }

        /* The Reloading signal is only sent to subscribed clients on the API bus, hence subscribe. (The
         * UnitRemoved signal is also sent to clients holding a reference on the unit, which we always do,
         * but subscribing covers it too.) */
        r = bus_call_method_async(bus, &d->slot_subscribe, bus_systemd_mgr, "Subscribe", on_subscribe, d, NULL);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(d);
        return 0;
}

BusWaitForUnits* bus_wait_for_units_free(BusWaitForUnits *d) {
        int r;

        if (!d)
                return NULL;

        if (d->subscribed && d->bus) {
                r = bus_call_method_async(d->bus, NULL, bus_systemd_mgr, "Unsubscribe", NULL, NULL, NULL);
                if (r < 0)
                        log_debug_errno(r, "Failed to unsubscribe from service manager signals, ignoring: %m");
        }

        bus_wait_for_units_clear(d);

        return mfree(d);
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
                .result = UNIT_RESULT_INIT,
        };

        item->name = strdup(unit);
        if (!item->name)
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

        r = hashmap_ensure_put(&d->items, &string_hash_ops, item->bus_path, item);
        if (r < 0)
                return r;
        assert(r > 0);

        item->parent = d;

        r = wait_for_item_query(item);
        if (r < 0)
                return log_debug_errno(r, "Failed to request properties of unit %s: %m", unit);

        d->state = BUS_WAIT_RUNNING;
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
