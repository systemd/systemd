/* SPDX-License-Identifier: LGPL-2.1+ */

#include "bus-util.h"
#include "dbus-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "unit-printf.h"
#include "user-util.h"
#include "unit.h"

int bus_property_get_triggered_unit(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Unit *u = userdata, *trigger;

        assert(bus);
        assert(reply);
        assert(u);

        trigger = UNIT_TRIGGER(u);

        return sd_bus_message_append(reply, "s", trigger ? trigger->id : NULL);
}

BUS_DEFINE_SET_TRANSIENT(mode_t, "u", uint32_t, mode_t, "%040o");
BUS_DEFINE_SET_TRANSIENT(unsigned, "u", uint32_t, unsigned, "%" PRIu32);
BUS_DEFINE_SET_TRANSIENT_STRING_WITH_CHECK(user_compat, valid_user_group_name_or_id_compat);
BUS_DEFINE_SET_TRANSIENT_STRING_WITH_CHECK(path, path_is_absolute);

int bus_set_transient_string(
                Unit *u,
                const char *name,
                char **p,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *error) {

        const char *v;
        int r;

        assert(p);

        r = sd_bus_message_read(message, "s", &v);
        if (r < 0)
                return r;

        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                r = free_and_strdup(p, empty_to_null(v));
                if (r < 0)
                        return r;

                unit_write_settingf(u, flags|UNIT_ESCAPE_SPECIFIERS, name,
                                    "%s=%s", name, strempty(v));
        }

        return 1;
}

int bus_set_transient_bool(
                Unit *u,
                const char *name,
                bool *p,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *error) {

        int v, r;

        assert(p);

        r = sd_bus_message_read(message, "b", &v);
        if (r < 0)
                return r;

        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                *p = v;
                unit_write_settingf(u, flags, name, "%s=%s", name, yes_no(v));
        }

        return 1;
}

int bus_set_transient_usec_internal(
                Unit *u,
                const char *name,
                usec_t *p,
                bool fix_0,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *error) {

        uint64_t v;
        int r;

        assert(p);

        r = sd_bus_message_read(message, "t", &v);
        if (r < 0)
                return r;

        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                char *n, ts[FORMAT_TIMESPAN_MAX];

                if (fix_0)
                        *p = v != 0 ? v: USEC_INFINITY;
                else
                        *p = v;

                n = strndupa(name, strlen(name) - 4);
                unit_write_settingf(u, flags, name, "%sSec=%s", n,
                                    format_timespan(ts, sizeof(ts), v, USEC_PER_MSEC));
        }

        return 1;
}
