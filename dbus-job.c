/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include "dbus.h"
#include "log.h"

static const char introspection[] =
        DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE
        "<node>"
        " <interface name=\"org.freedesktop.systemd1.Job\">"
        " </interface>"
        BUS_PROPERTIES_INTERFACE
        BUS_INTROSPECTABLE_INTERFACE
        "</node>";

DBusHandlerResult bus_job_message_handler(DBusConnection  *connection, DBusMessage  *message, void *data) {
        Manager *m = data;

        assert(connection);
        assert(message);
        assert(m);

        log_debug("Got D-Bus request: %s.%s() on %s",
                  dbus_message_get_interface(message),
                  dbus_message_get_member(message),
                  dbus_message_get_path(message));

        return bus_default_message_handler(m, message, introspection, NULL);
}

const DBusObjectPathVTable bus_job_vtable = {
        .message_function = bus_job_message_handler
};
