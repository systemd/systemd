/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-get-properties.h"
#include "dbus-kill.h"
#include "dbus-util.h"
#include "kill.h"
#include "signal-util.h"

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_kill_mode, kill_mode, KillMode);

static int property_get_restart_kill_signal(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {
        KillContext *c = ASSERT_PTR(userdata);
        int s;

        s = restart_kill_signal(c);
        return sd_bus_message_append_basic(reply, 'i', &s);
}

const sd_bus_vtable bus_kill_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("KillMode", "s", property_get_kill_mode, offsetof(KillContext, kill_mode), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("KillSignal", "i", bus_property_get_int, offsetof(KillContext, kill_signal), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RestartKillSignal", "i", property_get_restart_kill_signal, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("FinalKillSignal", "i", bus_property_get_int, offsetof(KillContext, final_kill_signal), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("SendSIGKILL", "b", bus_property_get_bool, offsetof(KillContext, send_sigkill), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("SendSIGHUP", "b", bus_property_get_bool,  offsetof(KillContext, send_sighup), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("WatchdogSignal", "i", bus_property_get_int, offsetof(KillContext, watchdog_signal), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_VTABLE_END
};

static BUS_DEFINE_SET_TRANSIENT_PARSE(kill_mode, KillMode, kill_mode_from_string);
static BUS_DEFINE_SET_TRANSIENT_TO_STRING(kill_signal, "i", int32_t, int, "%" PRIi32, signal_to_string_with_check);
static BUS_DEFINE_SET_TRANSIENT_TO_STRING(restart_kill_signal, "i", int32_t, int, "%" PRIi32, signal_to_string_with_check);
static BUS_DEFINE_SET_TRANSIENT_TO_STRING(final_kill_signal, "i", int32_t, int, "%" PRIi32, signal_to_string_with_check);
static BUS_DEFINE_SET_TRANSIENT_TO_STRING(watchdog_signal, "i", int32_t, int, "%" PRIi32, signal_to_string_with_check);

int bus_kill_context_set_transient_property(
                Unit *u,
                KillContext *c,
                const char *name,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *error) {

        assert(u);
        assert(c);
        assert(name);
        assert(message);

        flags |= UNIT_PRIVATE;

        if (streq(name, "KillMode"))
                return bus_set_transient_kill_mode(u, name, &c->kill_mode, message, flags, error);

        if (streq(name, "SendSIGHUP"))
                return bus_set_transient_bool(u, name, &c->send_sighup, message, flags, error);

        if (streq(name, "SendSIGKILL"))
                return bus_set_transient_bool(u, name, &c->send_sigkill, message, flags, error);

        if (streq(name, "KillSignal"))
                return bus_set_transient_kill_signal(u, name, &c->kill_signal, message, flags, error);

        if (streq(name, "RestartKillSignal"))
                return bus_set_transient_restart_kill_signal(u, name, &c->restart_kill_signal, message, flags, error);

        if (streq(name, "FinalKillSignal"))
                return bus_set_transient_final_kill_signal(u, name, &c->final_kill_signal, message, flags, error);

        if (streq(name, "WatchdogSignal"))
                return bus_set_transient_watchdog_signal(u, name, &c->watchdog_signal, message, flags, error);

        return 0;
}
