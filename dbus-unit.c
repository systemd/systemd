/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <errno.h>

#include "dbus.h"
#include "log.h"

static const char introspection[] =
        DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE
        "<node>"
        " <!-- you suck -->"
        " <interface name=\"org.freedesktop.systemd1.Unit\">"
        "  <property name=\"Id\" type=\"s\" access=\"read\"/>"
        "  <property name=\"Description\" type=\"s\" access=\"read\"/>"
        "  <property name=\"LoadState\" type=\"s\" access=\"read\"/>"
        "  <property name=\"ActiveState\" type=\"s\" access=\"read\"/>"
        " </interface>"
        BUS_PROPERTIES_INTERFACE
        BUS_INTROSPECTABLE_INTERFACE
        "</node>";

static int bus_unit_append_id(Manager *m, DBusMessageIter *i, const char *property, void *data) {
        Unit *u = data;
        const char *id;

        assert(m);
        assert(i);
        assert(property);
        assert(u);

        id = unit_id(u);

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_STRING, &id))
                return -ENOMEM;

        return 0;
}

static int bus_unit_append_description(Manager *m, DBusMessageIter *i, const char *property, void *data) {
        Unit *u = data;
        const char *d;

        assert(m);
        assert(i);
        assert(property);
        assert(u);

        d = unit_description(u);

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_STRING, &d))
                return -ENOMEM;

        return 0;
}

static int bus_unit_append_load_state(Manager *m, DBusMessageIter *i, const char *property, void *data) {
        Unit *u = data;
        const char *state;

        assert(m);
        assert(i);
        assert(property);
        assert(u);

        state = unit_load_state_to_string(u->meta.load_state);

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_STRING, &state))
                return -ENOMEM;

        return 0;
}

static int bus_unit_append_active_state(Manager *m, DBusMessageIter *i, const char *property, void *data) {
        Unit *u = data;
        const char *state;

        assert(m);
        assert(i);
        assert(property);
        assert(u);

        state = unit_active_state_to_string(unit_active_state(u));

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_STRING, &state))
                return -ENOMEM;

        return 0;
}

static DBusHandlerResult bus_unit_message_dispatch(Unit *u, DBusMessage *message) {

        const BusProperty properties[] = {
                { "org.freedesktop.systemd1.Unit", "Id",          bus_unit_append_id,           "s", u },
                { "org.freedesktop.systemd1.Unit", "Description", bus_unit_append_description,  "s", u },
                { "org.freedesktop.systemd1.Unit", "LoadState",   bus_unit_append_load_state,   "s", u },
                { "org.freedesktop.systemd1.Unit", "ActiveState", bus_unit_append_active_state, "s", u },
                { NULL, NULL, NULL, NULL, NULL }
        };

        return bus_default_message_handler(u->meta.manager, message, introspection, properties);
}

static DBusHandlerResult bus_unit_message_handler(DBusConnection  *connection, DBusMessage  *message, void *data) {
        Manager *m = data;
        Unit *u;
        int r;

        assert(connection);
        assert(message);
        assert(m);

        log_debug("Got D-Bus request: %s.%s() on %s",
                  dbus_message_get_interface(message),
                  dbus_message_get_member(message),
                  dbus_message_get_path(message));

        if ((r = manager_get_unit_from_dbus_path(m, dbus_message_get_path(message), &u)) < 0) {

                if (r == -ENOMEM)
                        return DBUS_HANDLER_RESULT_NEED_MEMORY;

                if (r == -ENOENT)
                        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

                return bus_send_error_reply(m, message, NULL, r);
        }

        return bus_unit_message_dispatch(u, message);
}

const DBusObjectPathVTable bus_unit_vtable = {
        .message_function = bus_unit_message_handler
};
