/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-error.h"
#include "bus-map-properties.h"
#include "bus-parse-xml.h"
#include "bus-util.h"
#include "networkd-manager.h"
#include "networkd-wwan-bus.h"
#include "networkd-wwan.h"

/* From ModemManager-enums.h */
typedef enum {
    MM_BEARER_IP_FAMILY_NONE    = 0,
    MM_BEARER_IP_FAMILY_IPV4    = 1 << 0,
    MM_BEARER_IP_FAMILY_IPV6    = 1 << 1,
    MM_BEARER_IP_FAMILY_IPV4V6  = 1 << 2,
    MM_BEARER_IP_FAMILY_ANY     = 0xFFFFFFFF
} MMBearerIpFamily;

static int map_name(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        Bearer *b = ASSERT_PTR(userdata);
        const char *s;
        int r;

        assert(m);

        r = sd_bus_message_read_basic(m, 's', &s);
        if (r < 0)
                return r;

        return bearer_set_name(b, s);
}

static int map_dns(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        Bearer *b = ASSERT_PTR(userdata);
        union in_addr_union a;
        const char *s;
        int family, r;

        assert(m);

        r = sd_bus_message_read_basic(m, 's', &s);
        if (r < 0)
                return r;

        r = in_addr_from_string_auto(s, &family, &a);
        if (r < 0)
                return r;

        if (!GREEDY_REALLOC(b->dns, b->n_dns + 1))
                return -ENOMEM;

        b->dns[b->n_dns++] = (struct in_addr_data) {
                .family = family,
                .address = a,
        };

        return 0;
}

static int map_in_addr(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata, int family) {
        union in_addr_union *addr = ASSERT_PTR(userdata);
        const char *s;
        int r;

        assert(m);

        r = sd_bus_message_read_basic(m, 's', &s);
        if (r < 0)
                return r;

        return in_addr_from_string(family, s, addr);
}

static int map_in4(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        return map_in_addr(bus, member, m, error, userdata, AF_INET);
}

static int map_in6(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        return map_in_addr(bus, member, m, error, userdata, AF_INET6);
}

static int map_ip4_config(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        static const struct bus_properties_map map[] = {
                { "method",  "u", NULL,    offsetof(Bearer, ip4_method)    },
                { "address", "s", map_in4, offsetof(Bearer, ip4_address)   },
                { "prefix",  "u", NULL,    offsetof(Bearer, ip4_prefixlen) },
                { "dns1",    "s", map_dns, 0,                              },
                { "dns2",    "s", map_dns, 0,                              },
                { "dns3",    "s", map_dns, 0,                              },
                { "gateway", "s", map_in4, offsetof(Bearer, ip4_gateway)   },
                { "mtu",     "u", NULL,    offsetof(Bearer, ip4_mtu)       },
                {}
        };

        return bus_message_map_all_properties(m, map, 0, error, userdata);
}

static int map_ip6_config(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        static const struct bus_properties_map map[] = {
                { "method",  "u", NULL,    offsetof(Bearer, ip6_method)    },
                { "address", "s", map_in6, offsetof(Bearer, ip6_address)   },
                { "prefix",  "u", NULL,    offsetof(Bearer, ip6_prefixlen) },
                { "dns1",    "s", map_dns, 0,                              },
                { "dns2",    "s", map_dns, 0,                              },
                { "dns3",    "s", map_dns, 0,                              },
                { "gateway", "s", map_in6, offsetof(Bearer, ip6_gateway)   },
                { "mtu",     "u", NULL,    offsetof(Bearer, ip6_mtu)       },
                {}
        };

        return bus_message_map_all_properties(m, map, 0, error, userdata);
}

static int map_ip_type(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        AddressFamily *ip_type = ASSERT_PTR(userdata);
        unsigned u;
        int r;

        assert(m);

        r = sd_bus_message_read_basic(m, 'u', &u);
        if (r < 0)
                return r;

        switch (u) {
        case MM_BEARER_IP_FAMILY_NONE:
                *ip_type = ADDRESS_FAMILY_NO;
                break;
        case MM_BEARER_IP_FAMILY_IPV4:
                *ip_type = ADDRESS_FAMILY_IPV4;
                break;
        case MM_BEARER_IP_FAMILY_IPV6:
                *ip_type = ADDRESS_FAMILY_IPV6;
                break;
        case MM_BEARER_IP_FAMILY_IPV4V6:
                *ip_type = ADDRESS_FAMILY_YES;
                break;
        }

        return 0;
}

static int map_properties(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        static const struct bus_properties_map map[] = {
                { "apn",     "s", NULL,        offsetof(Bearer, apn)     },
                { "ip-type", "u", map_ip_type, offsetof(Bearer, ip_type) },
                {}
        };

        return bus_message_map_all_properties(m, map, BUS_MAP_STRDUP, error, userdata);
}

static int bearer_get_all_handler(sd_bus_message *message, void *userdata, sd_bus_error *ret_error) {
        static const struct bus_properties_map map[] = {
                { "Interface",  "s",     map_name,       offsetof(Bearer, name)      },
                { "Connected",  "b",     NULL,           offsetof(Bearer, connected) },
                { "Ip4Config",  "a{sv}", map_ip4_config, 0,                          },
                { "Ip6Config",  "a{sv}", map_ip6_config, 0,                          },
                { "Properties", "a{sv}", map_properties, 0,                          },
                {}
        };

        Bearer *b = ASSERT_PTR(userdata);
        const sd_bus_error *e;
        int r;

        assert(message);

        b->slot = sd_bus_slot_unref(b->slot);

        e = sd_bus_message_get_error(message);
        if (e) {
                bool removed = false;

                if (sd_bus_error_has_name(e, SD_BUS_ERROR_UNKNOWN_METHOD))
                        /* The path is already removed? */
                        removed = true;

                r = sd_bus_error_get_errno(e);
                log_full_errno(removed ? LOG_DEBUG : LOG_WARNING, r,
                               "Could not get properties of bearer \"%s\": %s",
                               b->path, bus_error_message(e, r));

                bearer_drop(b);
                return 0;
        }

        r = bus_message_map_all_properties(message, map, BUS_MAP_BOOLEAN_AS_BOOL, ret_error, b);
        if (r < 0)
                return log_warning_errno(r, "Failed to parse properties of bearer \"%s\": %s", b->path, bus_error_message(ret_error, r));

        (void) bearer_update_link(b);
        return 0;
}

static int bearer_initialize(Bearer *b) {
        int r;

        assert(b);
        assert(b->manager);
        assert(sd_bus_is_ready(b->manager->bus) > 0);
        assert(b->path);

        b->slot = sd_bus_slot_unref(b->slot);

        r = sd_bus_call_method_async(
                        b->manager->bus,
                        &b->slot,
                        "org.freedesktop.ModemManager1",
                        b->path,
                        "org.freedesktop.DBus.Properties",
                        "GetAll",
                        bearer_get_all_handler,
                        b,
                        NULL);
        if (r < 0)
                return log_warning_errno(r, "Could not get properties of bearer \"%s\": %m", b->path);

        return 0;
}

static int bearer_new_and_initialize(Manager *manager, const char *path) {
        _cleanup_(bearer_freep) Bearer *b = NULL;
        int r;

        assert(manager);
        assert(path);

        r = bearer_new(manager, path, &b);
        if (r < 0)
                return log_warning_errno(r, "Failed to allocate new bearer \"%s\": %m", path);

        r = bearer_initialize(b);
        if (r < 0)
                return r;

        TAKE_PTR(b);
        return 0;
}

static int bearer_save_path(const char *path, void *userdata) {
        Set **set = ASSERT_PTR(userdata);

        return set_put_strdup(set, path);
}

static int enumerate_bearer_handler(sd_bus_message *message, void *userdata, sd_bus_error *ret_error) {
        static const XMLIntrospectOps ops = {
                .on_path = bearer_save_path,
        };

        Manager *manager = ASSERT_PTR(userdata);
        _cleanup_set_free_ Set *paths = NULL;
        const sd_bus_error *e;
        const char *xml, *path;
        int r;

        assert(message);

        e = sd_bus_message_get_error(message);
        if (e) {
                int level = LOG_WARNING;

                if (sd_bus_error_has_name(e, SD_BUS_ERROR_SERVICE_UNKNOWN))
                        /* ModemManager is not started yet. */
                        level = LOG_DEBUG;

                r = sd_bus_error_get_errno(e);
                log_full_errno(level, r, "Could not get bearers: %s", bus_error_message(e, r));
                return 0;
        }

        r = sd_bus_message_read(message, "s", &xml);
        if (r < 0)
                return bus_log_parse_error(r);

        r = parse_xml_introspect("/org/freedesktop/ModemManager/Bearer", xml, &ops, &paths);
        if (r < 0) {
                log_warning_errno(r, "Failed to parse DBus introspect XML, ignoring: %m");
                return 0;
        }

        SET_FOREACH(path, paths) {
                if (streq(path, "/org/freedesktop/ModemManager/Bearer"))
                        continue;

                (void) bearer_new_and_initialize(manager, path);
        }

        return 0;
}

int manager_enumerate_bearers(Manager *manager) {
        int r;

        assert(manager);
        assert(sd_bus_is_ready(manager->bus) > 0);

        r = sd_bus_call_method_async(
                        manager->bus,
                        NULL,
                        "org.freedesktop.ModemManager1",
                        "/org/freedesktop/ModemManager/Bearer",
                        "org.freedesktop.DBus.Introspectable",
                        "Introspect",
                        enumerate_bearer_handler,
                        manager,
                        NULL);
        if (r < 0)
                return log_error_errno(r, "Could not get bearers: %m");

        return 0;
}

static int bearer_properties_changed_handler(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *manager = ASSERT_PTR(userdata);
        const char *path;
        Bearer *b;

        assert(message);

        path = sd_bus_message_get_path(message);
        if (!path)
                return 0;

        if (streq(path, "/org/freedesktop/ModemManager/Bearer"))
                return 0;

        if (bearer_get_by_path(manager, path, &b) < 0) {
                /* New bearer. */
                (void) bearer_new_and_initialize(manager, path);
                return 0;
        }

        if (b->slot) {
                /* Not initialized yet. Re-initialize it. */
                (void) bearer_initialize(b);
                return 0;
        }

        (void) bearer_get_all_handler(message, b, error);
        return 0;
}


int manager_match_bearers_signal(Manager *manager) {
        static const char *expression =
                "type='signal',"
                "sender='org.freedesktop.ModemManager1',"
                "path_namespace='/org/freedesktop/ModemManager/Bearer',"
                "interface='org.freedesktop.DBus.Properties',"
                "member='PropertiesChanged'";
        int r;

        assert(manager);
        assert(manager->bus);

        r = sd_bus_add_match_async(manager->bus, NULL, expression, bearer_properties_changed_handler, NULL, manager);
        if (r < 0)
                return log_error_errno(r, "Failed to request match for PropertiesChanged in ModemManager bearers: %m");

        return 0;
}
