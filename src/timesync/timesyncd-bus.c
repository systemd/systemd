/* SPDX-License-Identifier: LGPL-2.1+ */

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-internal.h"
#include "bus-protocol.h"
#include "bus-util.h"
#include "in-addr-util.h"
#include "log.h"
#include "macro.h"
#include "time-util.h"
#include "timesyncd-bus.h"

static int property_get_servers(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        ServerName *p, **s = userdata;
        int r;

        assert(s);
        assert(bus);
        assert(reply);

        r = sd_bus_message_open_container(reply, 'a', "s");
        if (r < 0)
                return r;

        LIST_FOREACH(names, p, *s) {
                r = sd_bus_message_append(reply, "s", p->string);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

static int property_get_current_server_name(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        ServerName **s = userdata;

        assert(s);
        assert(bus);
        assert(reply);

        return sd_bus_message_append(reply, "s", *s ? (*s)->string : "");
}

static int property_get_current_server_address(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        ServerAddress *a;
        int r;

        assert(bus);
        assert(reply);
        assert(userdata);

        a = *(ServerAddress **) userdata;

        if (!a)
                return sd_bus_message_append(reply, "(iay)", AF_UNSPEC, 0);

        r = sd_bus_message_open_container(reply, 'r', "iay");
        if (r < 0)
                return r;

        r = sd_bus_message_append(reply, "i", a->sockaddr.sa.sa_family);
        if (r < 0)
                return r;

        r = sd_bus_message_append_array(reply, 'y', &a->sockaddr.in.sin_addr, FAMILY_ADDRESS_SIZE(a->sockaddr.sa.sa_family));
        if (r < 0)
                return r;

        return sd_bus_message_close_container(reply);
}

static const sd_bus_vtable manager_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_PROPERTY("LinkNTPServers", "as", property_get_servers, offsetof(Manager, link_servers), 0),
        SD_BUS_PROPERTY("SystemNTPServers", "as", property_get_servers, offsetof(Manager, system_servers), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("FallbackNTPServers", "as", property_get_servers, offsetof(Manager, fallback_servers), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("ServerName", "s", property_get_current_server_name, offsetof(Manager, current_server_name), 0),
        SD_BUS_PROPERTY("ServerAddress", "(iay)", property_get_current_server_address, offsetof(Manager, current_server_address), 0),
        SD_BUS_PROPERTY("RootDistanceMaxUSec", "t", bus_property_get_usec, offsetof(Manager, max_root_distance_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("PollIntervalMinUSec", "t", bus_property_get_usec, offsetof(Manager, poll_interval_min_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("PollIntervalMaxUSec", "t", bus_property_get_usec, offsetof(Manager, poll_interval_max_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("PollIntervalUSec", "t", bus_property_get_usec, offsetof(Manager, poll_interval_usec), 0),

        SD_BUS_VTABLE_END
};

static int reload_dbus_handler(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        const sd_bus_error *e;
        int r;

        assert(m);

        e = sd_bus_message_get_error(m);
        if (e) {
                log_error_errno(sd_bus_error_get_errno(e), "Failed to reload DBus configuration: %s", e->message);
                return 1;
        }

        /* Here, use the default request name handler to avoid an infinite loop of reloading and requesting. */
        r = sd_bus_request_name_async(sd_bus_message_get_bus(m), NULL, "org.freedesktop.timesync1", 0, NULL, NULL);
        if (r < 0)
                log_error_errno(r, "Failed to request name: %m");

        return 1;
}

static int request_name_handler(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        uint32_t ret;
        int r;

        assert(m);

        if (sd_bus_message_is_method_error(m, NULL)) {
                const sd_bus_error *e = sd_bus_message_get_error(m);

                if (!sd_bus_error_has_name(e, SD_BUS_ERROR_ACCESS_DENIED)) {
                        log_debug_errno(sd_bus_error_get_errno(e),
                                        "Unable to request name, failing connection: %s",
                                        e->message);

                        bus_enter_closing(sd_bus_message_get_bus(m));
                        return 1;
                }

                log_debug_errno(sd_bus_error_get_errno(e),
                                "Unable to request name, retry after reloading DBus configuration: %s",
                                e->message);

                /* If systemd-timesyncd.service enables DynamicUser= and dbus.service
                 * started before the dynamic user is realized, then the DBus policy
                 * about timesyncd has not been enabled yet. So, let's try to reload
                 * DBus configuration, and after that request name again. Note that it
                 * seems that no privileges are necessary to call the following method. */

                r = sd_bus_call_method_async(
                                sd_bus_message_get_bus(m),
                                NULL,
                                "org.freedesktop.DBus",
                                "/org/freedesktop/DBus",
                                "org.freedesktop.DBus",
                                "ReloadConfig",
                                reload_dbus_handler,
                                NULL, NULL);
                if (r < 0) {
                        log_error_errno(r, "Failed to reload DBus configuration: %m");
                        bus_enter_closing(sd_bus_message_get_bus(m));
                }

                return 1;
        }

        r = sd_bus_message_read(m, "u", &ret);
        if (r < 0)
                return r;

        switch (ret) {

        case BUS_NAME_ALREADY_OWNER:
                log_debug("Already owner of requested service name, ignoring.");
                return 1;

        case BUS_NAME_IN_QUEUE:
                log_debug("In queue for requested service name.");
                return 1;

        case BUS_NAME_PRIMARY_OWNER:
                log_debug("Successfully acquired requested service name.");
                return 1;

        case BUS_NAME_EXISTS:
                log_debug("Requested service name already owned, failing connection.");
                bus_enter_closing(sd_bus_message_get_bus(m));
                return 1;
        }

        log_debug("Unexpected response from RequestName(), failing connection.");
        bus_enter_closing(sd_bus_message_get_bus(m));
        return 1;
}

int manager_connect_bus(Manager *m) {
        int r;

        assert(m);

        if (m->bus)
                return 0;

        r = bus_open_system_watch_bind_with_description(&m->bus, "bus-api-timesync");
        if (r < 0)
                return log_error_errno(r, "Failed to connect to bus: %m");

        r = sd_bus_add_object_vtable(m->bus, NULL, "/org/freedesktop/timesync1", "org.freedesktop.timesync1.Manager", manager_vtable, m);
        if (r < 0)
                return log_error_errno(r, "Failed to add manager object vtable: %m");

        r = sd_bus_request_name_async(m->bus, NULL, "org.freedesktop.timesync1", 0, request_name_handler, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to request name: %m");

        r = sd_bus_attach_event(m->bus, m->event, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to attach bus to event loop: %m");

        return 0;
}
