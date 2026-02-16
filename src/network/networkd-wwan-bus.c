/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * 1. ModemManager (MM) integration consists of two big parts: things
 * we do on the networkd start and what we do during the run-time.
 *
 * 2. Initialization phase
 * 2.1. Wait for networkd to connect to D-Bus
 * 2.2. Setup D-Bus handlers for the essential signals:
 *      - /org/freedesktop/DBus, org.freedesktop.DBus, NameOwnerChanged - to track MM service availability
 *      - /org/freedesktop/ModemManager1, org.freedesktop.DBus.ObjectManager Interfaces{Added|Removed} -
 *        to track modem plug/unplug
 *      - /org/freedesktop/ModemManager1/Bearer org.freedesktop.DBus.Properties PropertiesChanged
 *        to track bearers
 * 2.3. Check if MM service is yet available: for that call /org/freedesktop/DBus, org.freedesktop.DBus
 *      ListNames method and see if MM is available. If it is not, then wait for the NameOwnerChanged
 *      signal and see when it is; finish initialization phase.
 * 2.4. If MM is available - enumerate modems, see p.4.
 * 2.5. Finish initialization phase.
 *
 * 3. Run-time
 * 3.1. During the run-time we track MM service availability. When it is gone we remove all the modems
 *      and bearers.
 * 3.2. When MM is connected we do modem enumeration to get in sync with their current state.
 * 3.3. If a modem was removed we also remove all its bearers.
 * 3.4. If a modem was added we try to start a simple connect.
 * 3.5. If connection was interrupted, e.g. modem changed its network connection from connected state
 *      we start an automatic reconnect.
 *
 * 4. Modem enumeration
 * 4.1. Modem enumeration is done by calling GetManagedObjects.
 * 4.2. By receiving managed objects we try to instantiate all new modems found.
 * 4.3. For that we inspect all bearers available for that modem and add all new bearers found.
 * 4.4. We also read modem ports to detect WWAN interface name assigned to this modem, e.g. "wwan0" etc.
 *      N.B. As we only get the interface name known that late and the corresponding .network file was
 *      already used by the networkd to match interfaces etc. it is not possible
 *      to do things like matching APN to .network and so on.
 *
 * 5. Simple (re)connect
 * 5.1. Connection is done by calling org.freedesktop.ModemManager1.Modem.Simple Connect method for
 *      the relevant modem.
 * 5.2. It is possible that at the time of connect the operation may fail. For that reason and to ensure
 *      we are always connected we employ a periodic timer which will re-try connection hoping it will
 *      be successful this time or when modem has recovered after an error state and so on.
 * 5.3. networkd will automatically start reconnection if any external entity disconnects modem from
 *      the network.
 */

#include "af-list.h"
#include "alloc-util.h"
#include "bus-error.h"
#include "bus-internal.h"
#include "bus-map-properties.h"
#include "bus-message.h"
#include "bus-util.h"
#include "event-util.h"
#include "hashmap.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-wwan.h"
#include "networkd-wwan-bus.h"
#include "parse-util.h"
#include "string-util.h"
#include "strv.h"

#define RECONNECT_TIMEOUT_USEC  (30 * USEC_PER_SEC)

static const char * const modem_state_failed_reason_str[__MM_MODEM_STATE_FAILED_REASON_MAX] = {
        [MM_MODEM_STATE_FAILED_REASON_NONE]                  = "No error",
        [MM_MODEM_STATE_FAILED_REASON_UNKNOWN]               = "Unknown error",
        [MM_MODEM_STATE_FAILED_REASON_SIM_MISSING]           = "SIM is required, but missing",
        [MM_MODEM_STATE_FAILED_REASON_SIM_ERROR]             = "SIM is available, but unusable",
        [MM_MODEM_STATE_FAILED_REASON_UNKNOWN_CAPABILITIES]  = "Unknown modem capabilities",
        [MM_MODEM_STATE_FAILED_REASON_ESIM_WITHOUT_PROFILES] = "eSIM is not initialized",
};

static int map_name(
                sd_bus *bus,
                const char *member,
                sd_bus_message *m,
                sd_bus_error *error,
                void *userdata) {

        Bearer *b = ASSERT_PTR(userdata);
        const char *s;
        int r;

        assert(m);

        /*
         * If name is already set - do not wipe it on disconnect, so we can work with link and other code which
         * relies on the interface name.
         */
        r = sd_bus_message_read_basic(m, 's', &s);
        if (r < 0)
                return r;

        if (!isempty(b->name))
                return 0;

        return bearer_set_name(b, s);
}

static int map_dns(
                sd_bus *bus,
                const char *member,
                sd_bus_message *m,
                sd_bus_error *error,
                void *userdata) {

        Bearer *b = ASSERT_PTR(userdata);
        struct in_addr_full *a;
        const char *s;
        int r;

        assert(m);

        r = sd_bus_message_read_basic(m, 's', &s);
        if (r < 0)
                return r;

        r = in_addr_full_new_from_string(s, &a);
        if (r < 0)
                return r;

        if (!GREEDY_REALLOC(b->dns, b->n_dns + 1))
                return -ENOMEM;

        b->dns[b->n_dns++] = TAKE_PTR(a);

        return 0;
}

static int map_in_addr(
                sd_bus *bus,
                const char *member,
                sd_bus_message *m,
                sd_bus_error *error,
                void *userdata,
                int family) {

        union in_addr_union *addr = ASSERT_PTR(userdata);
        const char *s;
        int r;

        assert(m);
        assert(IN_SET(family, AF_INET, AF_INET6));

        r = sd_bus_message_read_basic(m, 's', &s);
        if (r < 0)
                return r;

        return in_addr_from_string(family, s, addr);
}

static int map_in4(
                sd_bus *bus,
                const char *member,
                sd_bus_message *m,
                sd_bus_error *error,
                void *userdata) {

        return map_in_addr(bus, member, m, error, userdata, AF_INET);
}

static int map_in6(
                sd_bus *bus,
                const char *member,
                sd_bus_message *m,
                sd_bus_error *error,
                void *userdata) {

        return map_in_addr(bus, member, m, error, userdata, AF_INET6);
}

static int map_prefixlen(
                sd_bus *bus,
                const char *member,
                sd_bus_message *m,
                sd_bus_error *error,
                void *userdata,
                int family) {

        unsigned *prefixlen = ASSERT_PTR(userdata);
        unsigned p;
        int r;

        assert(m);

        r = sd_bus_message_read_basic(m, 'u', &p);
        if (r < 0)
                return r;

        if (p > FAMILY_ADDRESS_SIZE(family) * 8)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Bearer has invalid prefix length %u for %s address, ignoring.",
                                       p, af_to_ipv4_ipv6(family));

        *prefixlen = p;

        return 0;
}

static int map_prefixlen4(
                sd_bus *bus,
                const char *member,
                sd_bus_message *m,
                sd_bus_error *error,
                void *userdata) {

        return map_prefixlen(bus, member, m, error, userdata, AF_INET);
}

static int map_prefixlen6(
                sd_bus *bus,
                const char *member,
                sd_bus_message *m,
                sd_bus_error *error,
                void *userdata) {

        return map_prefixlen(bus, member, m, error, userdata, AF_INET6);
}

static int map_ip4_config(
                sd_bus *bus,
                const char *member,
                sd_bus_message *m,
                sd_bus_error *error,
                void *userdata) {

        static const struct bus_properties_map map[] = {
                { "method",  "u", NULL,           offsetof(Bearer, ip4_method)    },
                { "address", "s", map_in4,        offsetof(Bearer, ip4_address)   },
                { "prefix",  "u", map_prefixlen4, offsetof(Bearer, ip4_prefixlen) },
                { "dns1",    "s", map_dns,        0,                              },
                { "dns2",    "s", map_dns,        0,                              },
                { "dns3",    "s", map_dns,        0,                              },
                { "gateway", "s", map_in4,        offsetof(Bearer, ip4_gateway)   },
                { "mtu",     "u", NULL,           offsetof(Bearer, ip4_mtu)       },
                {}
        };
        Bearer *b = ASSERT_PTR(userdata);

        /*
         * The "Ip4Config" property: if the bearer was configured for IPv4 addressing, upon activation this
         * property contains the addressing details for assignment to the data interface.
         * We may have both IPv4 and IPv6 configured.
         */
        b->ip_type |= ADDRESS_FAMILY_IPV4;

        return bus_message_map_all_properties(m, map, /* flags= */ 0, error, userdata);
}

static int map_ip6_config(
                sd_bus *bus,
                const char *member,
                sd_bus_message *m,
                sd_bus_error *error,
                void *userdata) {

        static const struct bus_properties_map map[] = {
                { "method",  "u", NULL,           offsetof(Bearer, ip6_method)    },
                { "address", "s", map_in6,        offsetof(Bearer, ip6_address)   },
                { "prefix",  "u", map_prefixlen6, offsetof(Bearer, ip6_prefixlen) },
                { "dns1",    "s", map_dns,        0,                              },
                { "dns2",    "s", map_dns,        0,                              },
                { "dns3",    "s", map_dns,        0,                              },
                { "gateway", "s", map_in6,        offsetof(Bearer, ip6_gateway)   },
                { "mtu",     "u", NULL,           offsetof(Bearer, ip6_mtu)       },
                {}
        };
        Bearer *b = ASSERT_PTR(userdata);

        /*
         * The "Ip6Config" property: if the bearer was configured for IPv6 addressing, upon activation this
         * property contains the addressing details for assignment to the data interface.
         * We may have both IPv4 and IPv6 configured.
         */
        b->ip_type |= ADDRESS_FAMILY_IPV6;

        return bus_message_map_all_properties(m, map, /* flags= */ 0, error, userdata);
}

static int map_properties(
                sd_bus *bus,
                const char *member,
                sd_bus_message *m,
                sd_bus_error *error,
                void *userdata) {

        static const struct bus_properties_map map[] = {
                { "apn", "s", NULL, offsetof(Bearer, apn) },
                {}
        };

        return bus_message_map_all_properties(m, map, BUS_MAP_STRDUP, error, userdata);
}

static int bus_message_contains_properties(
                sd_bus_message *m,
                const struct bus_properties_map *map,
                sd_bus_error *error) {

        unsigned found_cnt;
        int r;

        assert(m);
        assert(map);

        found_cnt = 0;

        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "{sv}");
        if (r < 0)
                return bus_log_parse_error_debug(r);

        while ((r = sd_bus_message_enter_container(m, SD_BUS_TYPE_DICT_ENTRY, "sv")) > 0) {
                const struct bus_properties_map *prop = NULL;
                const char *member;

                r = sd_bus_message_read_basic(m, SD_BUS_TYPE_STRING, &member);
                if (r < 0)
                        return bus_log_parse_error_debug(r);

                for (unsigned i = 0; map[i].member; i++)
                        if (streq(map[i].member, member)) {
                                prop = &map[i];
                                break;
                        }

                r = sd_bus_message_skip(m, "v");
                if (r < 0)
                        return bus_log_parse_error_debug(r);
                if (prop)
                        found_cnt++;

                r = sd_bus_message_exit_container(m);
                if (r < 0)
                        return bus_log_parse_error_debug(r);
        }
        if (r < 0)
                return bus_log_parse_error_debug(r);

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return bus_log_parse_error_debug(r);

        return found_cnt;
}

static int bearer_get_all_handler(sd_bus_message *message, void *userdata, sd_bus_error *ret_error) {
        static const struct bus_properties_map map[] = {
                { "Interface",  "s",     map_name,       0,                          },
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

        b->slot_getall = sd_bus_slot_unref(b->slot_getall);

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

        /* skip name: string "org.freedesktop.ModemManager1.Bearer" */
        r = sd_bus_message_skip(message, "s");
        if (r < 0)
                return log_warning_errno(r, "Failed while parsing properties of bearer \"%s\": %s",
                                         b->path, bus_error_message(ret_error, r));

        r = bus_message_contains_properties(message, map, ret_error);
        if (r < 0)
                return log_warning_errno(r, "Failed to check properties of bearer \"%s\": %s",
                                         b->path, bus_error_message(ret_error, r));

        /*
         * We do not want to update link status on properties change which come more or less frequently
         * and do not involve link state change, e.g. we do not want to bearer_update_link on Rx/Tx counters
         * change. So, see if this callback was called with the changes we want to track.
         */
        if (r == 0)
                return 0;

        r = sd_bus_message_rewind(message, true);
        if (r < 0)
                return log_warning_errno(r, "Failed to rewind properties of bearer \"%s\"", b->path);
        /* skip name: string "org.freedesktop.ModemManager1.Bearer" */
        r = sd_bus_message_skip(message, "s");
        if (r < 0)
                return log_warning_errno(r, "Failed while parsing properties of bearer \"%s\": %s",
                                         b->path, bus_error_message(ret_error, r));

        r = bus_message_map_all_properties(message, map, BUS_MAP_BOOLEAN_AS_BOOL, ret_error, b);
        if (r < 0)
                return log_warning_errno(r, "Failed to parse properties of bearer \"%s\": %s",
                                         b->path, bus_error_message(ret_error, r));

        if (b->name)
                log_info("%s: ModemManager announces %s %s is%s connected.",
                         b->name, b->modem->manufacturer, b->modem->model,
                         b->connected ? "" : " not");

        if (b->connected)
                b->modem->reconnect_state = MODEM_RECONNECT_DONE;

        return bearer_update_link(b);
}

static int bearer_initialize(Bearer *b) {
        int r;

        assert(b);
        assert(b->modem);
        assert(b->modem->manager);
        assert(sd_bus_is_ready(b->modem->manager->bus) > 0);
        assert(b->path);

        b->slot_getall = sd_bus_slot_unref(b->slot_getall);

        r = sd_bus_call_method_async(
                        b->modem->manager->bus,
                        &b->slot_getall,
                        "org.freedesktop.ModemManager1",
                        b->path,
                        "org.freedesktop.DBus.Properties",
                        "GetAll",
                        bearer_get_all_handler,
                        b, "s", "org.freedesktop.ModemManager1.Bearer");
        if (r < 0)
                return log_warning_errno(r, "Could not get properties of bearer \"%s\": %m", b->path);

        return 0;
}

static int bearer_new_and_initialize(Modem *modem, const char *path) {
        _cleanup_(bearer_freep) Bearer *b = NULL;
        int r;

        assert(modem);
        assert(modem->manager);
        assert(path);

        r = bearer_new(modem, path, &b);
        if (r < 0) {
                if (r == -EEXIST)
                        return 0;
                return log_warning_errno(r, "Failed to allocate new bearer \"%s\": %m", path);
        }

        r = bearer_initialize(b);
        if (r < 0)
                return r;

        TAKE_PTR(b);
        return 0;
}

static int modem_connect_handler(sd_bus_message *message, void *userdata, sd_bus_error *ret_error) {
        Modem *modem = ASSERT_PTR(userdata);
        const sd_bus_error *e;
        const char *new_bearer;
        int r;

        assert(message);

        modem->slot_connect = sd_bus_slot_unref(modem->slot_connect);

        e = sd_bus_message_get_error(message);
        if (e) {
                r = sd_bus_error_get_errno(e);
                log_full_errno(LOG_ERR, r,
                               "Could not connect modem %s %s: %s",
                               modem->manufacturer, modem->model,
                               bus_error_message(e, r));

                modem->reconnect_state = MODEM_RECONNECT_WAITING;
                return 0;
        }

        sd_bus_message_read(message, "o", &new_bearer);
        log_debug("ModemManager: %s %s connected, bearer is at %s",
                  modem->manufacturer, modem->model, new_bearer);

        return 0;
}

static MMBearerIpFamily prop_iptype_lookup(const char *key) {
        static const struct {
                MMBearerIpFamily family;
                const char *str;
        } table[] = {
                { MM_BEARER_IP_FAMILY_NONE,   "none"   },
                { MM_BEARER_IP_FAMILY_IPV4,   "ipv4"   },
                { MM_BEARER_IP_FAMILY_IPV6,   "ipv6"   },
                { MM_BEARER_IP_FAMILY_IPV4V6, "ipv4v6" },
                { MM_BEARER_IP_FAMILY_ANY,    "any"    },
                {}
        };

        assert(key);

        FOREACH_ELEMENT(item, table)
                if (streq(item->str, key))
                        return item->family;

        log_warning("ModemManager: ignoring unknown ip-type: %s, using any", key);
        return MM_BEARER_IP_FAMILY_ANY;
}

static MMBearerAllowedAuth prop_auth_lookup(const char *key) {
        static const struct {
                MMBearerAllowedAuth auth;
                const char *str;
        } table[] = {
                { MM_BEARER_ALLOWED_AUTH_NONE,     "none"     },
                { MM_BEARER_ALLOWED_AUTH_PAP,      "pap"      },
                { MM_BEARER_ALLOWED_AUTH_CHAP,     "chap"     },
                { MM_BEARER_ALLOWED_AUTH_MSCHAP,   "mschap"   },
                { MM_BEARER_ALLOWED_AUTH_MSCHAPV2, "mschapv2" },
                { MM_BEARER_ALLOWED_AUTH_EAP,      "eap"      },
                {}
        };

        assert(key);

        FOREACH_ELEMENT(item, table)
                if (streq(item->str, key))
                        return item->auth;

        log_warning("ModemManager: ignoring unknown allowed-auth: %s, using none", key);
        return MM_BEARER_ALLOWED_AUTH_NONE;
}

static const char* prop_type_lookup(const char *key) {
        static const struct {
                const char *prop;
                const char *type;
        } table[] = {
                { "apn",           "s" },
                { "allowed-auth",  "u" },
                { "user",          "s" },
                { "password",      "s" },
                { "ip-type",       "u" },
                { "allow-roaming", "b" },
                { "pin",           "s" },
                { "operator-id",   "s" },
                {}
        };

        if (!key)
                return NULL;

        FOREACH_ELEMENT(item, table)
                if (streq(item->prop, key))
                        return item->type;
        return NULL;
}

static int bus_call_method_async_props(
                sd_bus *bus,
                sd_bus_slot **slot,
                const char *destination,
                const char *path,
                const char *interface,
                const char *member,
                sd_bus_message_handler_t callback,
                void *userdata,
                Link *link) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        int r;

        assert(bus);

        r = sd_bus_message_new_method_call(bus, &m, destination, path, interface, member);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'a', "{sv}");
        if (r < 0)
                return bus_log_create_error(r);

        STRV_FOREACH(prop, link->network->mm_simple_connect_props) {
                const char *type;
                _cleanup_free_ char *left = NULL, *right = NULL;

                r = split_pair(*prop, "=", &left, &right);
                if (r < 0)
                        return log_warning_errno(SYNTHETIC_ERRNO(r),
                                                 "ModemManager: failed to parse simple connect option: %s, file: %s",
                                                 *prop, link->network->filename);

                type = prop_type_lookup(left);
                if (!type)
                        return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                                 "ModemManager: unknown simple connect option: %s, file: %s",
                                                 *prop, link->network->filename);

                if (streq(left, "ip-type")) {
                        MMBearerIpFamily ip_type = prop_iptype_lookup(right);

                        r = sd_bus_message_append(m, "{sv}", left, type, (uint32_t)ip_type);
                } if (streq(left, "allowed-auth")) {
                        MMBearerAllowedAuth auth = prop_auth_lookup(right);

                        r = sd_bus_message_append(m, "{sv}", left, type, (uint32_t)auth);
                } else if (streq(type, "b")) {
                        r = parse_boolean(right);
                        if (r < 0)
                                return -EINVAL;
                        r = sd_bus_message_append(m, "{sv}", left, type, r);
                } else if (streq(type, "s"))
                        r = sd_bus_message_append(m, "{sv}", left, type, right);

                if (r < 0)
                        return bus_log_create_error(r);
        }

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        return sd_bus_call_async(bus, slot, m, callback, userdata, 0);
}

static void modem_simple_connect(Modem *modem) {
        Link *link;
        int r;

        assert(modem);

        /* Already have simple connect in progress? */
        if (modem->slot_connect)
                return;

        if (modem->reconnect_state != MODEM_RECONNECT_SCHEDULED)
                return;

        /*
         * If port name is not known yet then wait for the reconnect
         * timer to trigger reconnection later on.
         */
        if (!modem->port_name)
                return;

        (void) link_get_by_name(modem->manager, modem->port_name, &link);
        if (!link)
                return (void) log_debug("ModemManager: cannot find link for %s", modem->port_name);

        /* Check if .network file found at all */
        if (!link->network)
                return (void) log_debug("ModemManager: no .network file provideded for %s",
                                        modem->port_name);

        /* Check if we are provided with simple connection properties */
        if (!link->network->mm_simple_connect_props)
                return (void) log_debug("ModemManager: no simple connect properties provided for %s",
                                        modem->port_name);

        log_info("ModemManager: starting simple connect on %s %s interface %s",
                 modem->manufacturer, modem->model, modem->port_name);
        r = bus_call_method_async_props(
                        modem->manager->bus,
                        &modem->slot_connect,
                        "org.freedesktop.ModemManager1",
                        modem->path,
                        "org.freedesktop.ModemManager1.Modem.Simple",
                        "Connect",
                        modem_connect_handler, modem, link);
        /*
         * If we failed to (re)start the connection now then rely on the periodic
         * timer and wait when it retries the connection attempt.
         */
        if (r < 0)
                log_warning_errno(r, "Could not start modem connection %s %s, will retry: %m",
                                  modem->manufacturer, modem->model);
}

static void modem_simple_disconnect(Modem *modem) {
        int r;

        assert(modem);

        r = sd_bus_call_method_async(
                        modem->manager->bus,
                        /* ret_slot= */ NULL,
                        "org.freedesktop.ModemManager1",
                        modem->path,
                        "org.freedesktop.ModemManager1.Modem.Simple",
                        "Disconnect",
                        /* callback= */ NULL,
                        /* userdata= */ NULL,
                        "o", "/");
        if (r < 0)
                log_warning_errno(r, "Could not disconnect modem %s %s: %m",
                                  modem->manufacturer, modem->model);
}

static int reset_timer(Manager *m, sd_event *e, sd_event_source **s);

static int on_periodic_timer(sd_event_source *s, uint64_t usec, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        Modem *modem;
        sd_event *e;
        int r;

        assert(s);

        e = sd_event_source_get_event(s);

        HASHMAP_FOREACH(modem, manager->modems_by_path) {
                /*
                 * We might be rate limiting the reconnection, e.g. if wrong simple connect options are
                 * provided modem manager might try to connect (registered->connecting) and fail soon
                 * (connecting->registered). To rate limit such a case we set MODEM_RECONNECT_WAITING state,
                 * so using this timer we can limit the requests and wait, for example, for network
                 * reconfigure wwanX. Still do not try to reconnect modems in failed state yet.
                 */
                if (modem->reconnect_state == MODEM_RECONNECT_WAITING) {
                        if (modem->state == MM_MODEM_STATE_LOCKED)
                                /* If SIM is locked do not try to make it worse with applying wrong configuration again. */
                                continue;
                        if (modem->state_fail_reason == MM_MODEM_STATE_FAILED_REASON_NONE)
                                modem->reconnect_state = MODEM_RECONNECT_SCHEDULED;
                }
                modem_simple_connect(modem);
        }

        r = reset_timer(manager, e, &s);
        if (r < 0)
                log_warning_errno(r, "ModemManager: Failed to reset periodic timer event source, ignoring: %m");

        return 0;
}

static int reset_timer(Manager *m, sd_event *e, sd_event_source **s) {
        return event_reset_time_relative(
                        e,
                        s,
                        CLOCK_MONOTONIC,
                        RECONNECT_TIMEOUT_USEC,
                        /* accuracy= */ 0,
                        on_periodic_timer,
                        m,
                        /* priority= */ 0,
                        "modem-periodic-timer-event-source",
                        /* force_reset= */ false);
}

static int setup_periodic_timer(Manager *m, sd_event *event) {
        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        int r;

        assert(event);
        assert(m);

        r = reset_timer(m, event, &s);
        if (r < 0)
                return r;

        return sd_event_source_set_floating(s, true);
}

int link_modem_reconfigure(Link *link) {
        Modem *modem;
        int r;

        assert(link);

        if (link_get_modem(link, &modem) >= 0) {
                modem_simple_disconnect(modem);
                /* .network has changed: start (re)connect if failed before. */
                if (modem->reconnect_state == MODEM_RECONNECT_WAITING &&
                    modem->state_fail_reason == MM_MODEM_STATE_FAILED_REASON_NONE) {
                        modem->reconnect_state = MODEM_RECONNECT_SCHEDULED;
                        modem_simple_connect(modem);
                }
        }

        r = link_apply_bearer(link);
        if (r < 0)
                return r;

        return 0;
}

static int modem_on_state_change(
                Modem *modem,
                MMModemState old_state,
                MMModemStateFailedReason old_fail_reason) {

        assert(modem);

        if (IN_SET(modem->state, MM_MODEM_STATE_CONNECTING, MM_MODEM_STATE_CONNECTED))
                /*
                 * Connection is ok or reconnect is already in progress: either initiataed by us or an
                 * external entity. Make sure we do not try to start reconnection logic and wait for th
                 * modem state change signal and then decide if need be.
                 * We assume that it is not possible to be in the above modem states e.g.
                 * connecting|connected if failed reason is not NONE, e.g. modem is all good.
                 */
                return 0;

        /* Check if modem is still in failed state. */
        if (modem->state_fail_reason != MM_MODEM_STATE_FAILED_REASON_NONE) {
                if (modem->state_fail_reason != old_fail_reason) {
                        log_error("ModemManager: cannot schedule reconnect for %s %s, modem is in failed state: %s",
                                  modem->manufacturer, modem->model,
                                  modem->state_fail_reason < __MM_MODEM_STATE_FAILED_REASON_MAX ?
                                  modem_state_failed_reason_str[modem->state_fail_reason] :
                                  "unknown reason");

                        /* Do not try to reconnect until modem has recovered. */
                        modem->reconnect_state = MODEM_RECONNECT_WAITING;
                }
                return 0;
        }

        if (modem->reconnect_state == MODEM_RECONNECT_SCHEDULED)
                /* We are reconnecting now. */
                return 0;

        /*
         * Modem is not in failed state and is not connected: try now. It is ok to fail and re-try to
         * connect with periodic timer later on.
         */
        modem->reconnect_state = MODEM_RECONNECT_SCHEDULED;
        modem_simple_connect(modem);

        return 0;
}

static int bearer_properties_changed_handler(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        Manager *manager = ASSERT_PTR(userdata);
        const char *path;
        Modem *modem;
        Bearer *b;

        assert(message);

        path = sd_bus_message_get_path(message);
        if (!path)
                return 0;

        if (bearer_get_by_path(manager, path, &modem, &b) < 0) {
                /*
                 * Have new bearer: check if we have the corresponding modem
                 * for it which we might not during initialization.
                 */
                if (modem)
                        (void) bearer_new_and_initialize(modem, path);
                return 0;
        }

        if (b->slot_getall) {
                /* Not initialized yet. Re-initialize it. */
                (void) bearer_initialize(b);
                return 0;
        }

        (void) bearer_get_all_handler(message, b, error);
        return 0;
}

static int modem_map_bearers(
                sd_bus *bus,
                const char *member,
                sd_bus_message *m,
                sd_bus_error *error,
                void *userdata) {

        Modem *modem = ASSERT_PTR(userdata);
        _cleanup_strv_free_ char **paths = NULL;
        int r;

        r = sd_bus_message_read_strv(m, &paths);
        if (r < 0)
                return bus_log_parse_error(r);

        STRV_FOREACH(path, paths) {
                log_info("ModemManager: bearer found at path %s", *path);
                (void) bearer_new_and_initialize(modem, *path);
        }

        return 0;
}

static int modem_map_ports(
                sd_bus *bus,
                const char *member,
                sd_bus_message *m,
                sd_bus_error *error,
                void *userdata) {

        Modem *modem = ASSERT_PTR(userdata);
        const char *port_name;
        uint32_t port_type;
        int r;

        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, NULL);
        if (r < 0)
                return bus_log_parse_error_debug(r);

        while ((r = sd_bus_message_read(m, "(su)", &port_name, &port_type)) > 0)
                if (port_type == MM_MODEM_PORT_TYPE_NET) {
                        r = free_and_strdup_warn(&modem->port_name, port_name);
                        if (r < 0)
                                return r;
                        break;
                }

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return bus_log_parse_error(r);

        return 0;
}

static int modem_properties_changed_signal(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *ret_error) {

        static const struct bus_properties_map map[] = {
                { "Bearers",       "a{sv}", modem_map_bearers, 0,                                 },
                { "State",             "i", NULL,              offsetof(Modem, state)             },
                { "StateFailedReason", "u", NULL,              offsetof(Modem, state_fail_reason) },
                { "Manufacturer",      "s", NULL,              offsetof(Modem, manufacturer)      },
                { "Model",             "s", NULL,              offsetof(Modem, model)             },
                { "Ports",         "a{su}", modem_map_ports,   0,                                 },
                {}
        };
        Modem *modem = ASSERT_PTR(userdata);
        MMModemState old_state;
        MMModemStateFailedReason old_fail_reason;
        int r;

        /* skip name: string "org.freedesktop.ModemManager1.Modem" */
        r = sd_bus_message_skip(message, "s");
        if (r < 0)
                return log_warning_errno(r, "Failed while parsing properties of modem %s: %s",
                                         modem->path, bus_error_message(ret_error, r));

        r = bus_message_contains_properties(message, map, ret_error);
        if (r < 0)
                return log_warning_errno(r, "Failed to check changed properties of modem %s: %s",
                                         modem->path, bus_error_message(ret_error, r));

        if (r == 0)
                return 0;

        r = sd_bus_message_rewind(message, true);
        if (r < 0)
                return log_warning_errno(r, "Failed to rewind properties of modem %s", modem->path);
        old_state = modem->state;
        old_fail_reason = modem->state_fail_reason;

        /* skip name: string "org.freedesktop.ModemManager1.Bearer" */
        r = sd_bus_message_skip(message, "s");
        if (r < 0)
                return log_warning_errno(r, "Failed while parsing properties of modem %s: %s",
                                         modem->path, bus_error_message(ret_error, r));

        r = bus_message_map_all_properties(message, map,
                                           BUS_MAP_BOOLEAN_AS_BOOL | BUS_MAP_STRDUP,
                                           ret_error, modem);
        if (r < 0)
                return log_warning_errno(r, "Failed to parse properties of modem %s: %s",
                                         modem->path, bus_error_message(ret_error, r));

        return modem_on_state_change(modem, old_state, old_fail_reason);
}

static int modem_properties_changed_installed(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *ret_error) {

        Modem *modem = ASSERT_PTR(userdata);

        /*
         * As soon as the signal handler installed we can start reconnect
         * so we don't miss any property changed.
         */
        return modem_on_state_change(modem, MM_MODEM_STATE_UNKNOWN, MM_MODEM_STATE_FAILED_REASON_UNKNOWN);
}

static int modem_match_properties_changed(Modem *modem, const char *path) {
        int r;

        assert(modem);
        assert(modem->manager);
        assert(modem->manager->bus);

        r = sd_bus_match_signal_async(modem->manager->bus, &modem->slot_propertieschanged,
                                      "org.freedesktop.ModemManager1", path,
                                      "org.freedesktop.DBus.Properties", "PropertiesChanged",
                                      modem_properties_changed_signal, modem_properties_changed_installed, modem);
        if (r < 0)
                return log_error_errno(r, "Failed to request match for PropertiesChanged for modem %s: %m", path);

        return 0;
}

static int modem_add(Manager *m, const char *path, sd_bus_message *message, sd_bus_error *ret_error) {
        static const struct bus_properties_map map[] = {
                { "Bearers",           "ao",    modem_map_bearers, 0,                                 },
                { "State",             "i",     NULL,              offsetof(Modem, state)             },
                { "StateFailedReason", "u",     NULL,              offsetof(Modem, state_fail_reason) },
                { "Manufacturer",      "s",     NULL,              offsetof(Modem, manufacturer)      },
                { "Model",             "s",     NULL,              offsetof(Modem, model)             },
                { "Ports",             "a{su}", modem_map_ports,   0,                                 },
                {}
        };
        Modem *modem;
        int r;

        r = modem_get_by_path(m, path, &modem);
        if (r != -ENOENT)
                return sd_bus_message_skip(message, "a{sv}");

        log_info("ModemManager: modem found at %s\n", path);

        r = modem_new(m, path, &modem);
        if (r < 0)
                return log_warning_errno(r, "Failed to initialize modem at %s, ignoring", path);

        r = modem_match_properties_changed(modem, path);
        if (r < 0)
                return log_warning_errno(r, "Failed to match on properties changed at %s, ignoring", path);

        r = bus_message_map_all_properties(message, map, BUS_MAP_STRDUP, ret_error, modem);
        if (r < 0)
                return log_warning_errno(r, "Failed to map properties at %s, ignoring", path);

        return 0;
}

static void modem_remove(Manager *m, const char *path) {
        Modem *modem;
        int r;

        r = modem_get_by_path(m, path, &modem);
        if (r < 0)
                return;

        log_error("ModemManager: %s %s %s removed", modem->manufacturer, modem->model, modem->port_name);
        modem_free(modem);
}

static int enumerate_modems_handler(sd_bus_message *message, void *userdata, sd_bus_error *ret_error) {
        Manager *manager = ASSERT_PTR(userdata);
        const sd_bus_error *e;
        const char *modem_path;
        int r;

        assert(message);

        e = sd_bus_message_get_error(message);
        if (e) {
                r = sd_bus_error_get_errno(e);
                log_warning_errno(r, "Could not get managed objects: %s", bus_error_message(e, r));
                return 0;
        }

        r = sd_bus_message_enter_container(message, SD_BUS_TYPE_ARRAY, "{oa{sa{sv}}}");
        if (r < 0)
                return bus_log_parse_error_debug(r);

        while ((r = sd_bus_message_enter_container(message, SD_BUS_TYPE_DICT_ENTRY, "oa{sa{sv}}")) > 0) {
                r = sd_bus_message_read_basic(message, SD_BUS_TYPE_OBJECT_PATH, &modem_path);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = sd_bus_message_enter_container(message, SD_BUS_TYPE_ARRAY, "{sa{sv}}");
                if (r < 0)
                        return bus_log_parse_error(r);

                while ((r = sd_bus_message_enter_container(message, SD_BUS_TYPE_DICT_ENTRY, "sa{sv}")) > 0) {
                        const char *interface_name = NULL;

                        r = sd_bus_message_read_basic(message, 's', &interface_name);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        if (streq("org.freedesktop.ModemManager1.Modem", interface_name)) {
                                r = modem_add(manager, modem_path, message, ret_error);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to add modem at %s: %m", modem_path);
                        } else {
                                r = sd_bus_message_skip(message, "a{sv}");
                                if (r < 0)
                                        return bus_log_parse_error(r);
                        }

                        r = sd_bus_message_exit_container(message);
                        if (r < 0)
                                return bus_log_parse_error(r);
                }

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return bus_log_parse_error(r);
        }

        r = sd_bus_message_exit_container(message);
        if (r < 0)
                return bus_log_parse_error(r);

        return 0;
}

static int enumerate_modems(Manager *manager) {
        int r;

        log_debug("ModemManager: enumerate modems");
        /* Enumerate all modems and add new and drop removed. */

        assert(manager);
        assert(sd_bus_is_ready(manager->bus) > 0);

        r = sd_bus_call_method_async(
                        manager->bus,
                        /* ret_slot= */ NULL,
                        "org.freedesktop.ModemManager1",
                        "/org/freedesktop/ModemManager1",
                        "org.freedesktop.DBus.ObjectManager",
                        "GetManagedObjects",
                        enumerate_modems_handler,
                        manager,
                        /* types= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Could not get managed objects: %m");

        return 0;
}

static int interface_add_remove_signal(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(manager);
        assert(message);

        manager->slot_mm = sd_bus_slot_unref(manager->slot_mm);

        if (streq(message->member, "InterfacesAdded"))
                log_info("ModemManager: modem(s) added");
        else {
                const char *path;

                r = sd_bus_message_read_basic(message, 'o', &path);
                if (r < 0)
                        return r;

                modem_remove(manager, path);
                return 0;
        }

        return enumerate_modems(manager);
}

static int name_owner_changed_signal(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *manager = ASSERT_PTR(userdata);
        const char *name;
        const char *new_owner;
        int r;

        assert(manager);
        assert(message);

        r = sd_bus_message_read(message, "sss", &name, NULL, &new_owner);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }

        if (!streq(name, "org.freedesktop.ModemManager1"))
                return 0;

        if (!isempty(new_owner))
                log_info("ModemManager: service is available");
        else {
                log_info("ModemManager: service is not available");
                hashmap_clear(manager->modems_by_path);
                return 0;
        }
        return enumerate_modems(manager);
}

int manager_match_mm_signals(Manager *manager) {
        int r;

        assert(manager);
        assert(manager->bus);

        r = sd_bus_match_signal_async(
                        manager->bus,
                        /* ret= */ NULL,
                        "org.freedesktop.DBus",
                        "/org/freedesktop/DBus",
                        "org.freedesktop.DBus",
                        "NameOwnerChanged",
                        name_owner_changed_signal,
                        /* install_callback= */ NULL,
                        manager);
        if (r < 0)
                return log_error_errno(r, "Failed to request signal for NameOwnerChanged");

        r = sd_bus_match_signal_async(
                        manager->bus,
                        /* ret= */ NULL,
                        "org.freedesktop.ModemManager1",
                        "/org/freedesktop/ModemManager1",
                        "org.freedesktop.DBus.ObjectManager",
                        "InterfacesAdded",
                        interface_add_remove_signal,
                        /* install_callback= */ NULL,
                        manager);
        if (r < 0)
                return log_error_errno(r, "Failed to request signal for IntefaceAdded");

        r = sd_bus_match_signal_async(
                        manager->bus,
                        /* ret= */ NULL,
                        "org.freedesktop.ModemManager1",
                        "/org/freedesktop/ModemManager1",
                        "org.freedesktop.DBus.ObjectManager",
                        "InterfacesRemoved",
                        interface_add_remove_signal,
                        /* install_callback= */ NULL,
                        manager);
        if (r < 0)
                return log_error_errno(r, "Failed to request signal for IntefaceRemoved");

        /* N.B. We need "path_namespace" for bearers, not "path", */
        r = sd_bus_add_match_async(
                        manager->bus,
                        /* ret_slot= */ NULL,
                        "type='signal',"
                        "sender='org.freedesktop.ModemManager1',"
                        "path_namespace='/org/freedesktop/ModemManager1/Bearer',"
                        "interface='org.freedesktop.DBus.Properties',"
                        "member='PropertiesChanged'",
                        bearer_properties_changed_handler,
                        /* install_callback= */ NULL,
                        manager);
        if (r < 0)
                return log_error_errno(r, "Failed to request signal for PropertiesChanged in ModemManager bearers");

        return 0;
}

static int list_names_handler(sd_bus_message *message, void *userdata, sd_bus_error *ret_error) {
        Manager *manager = ASSERT_PTR(userdata);
        _cleanup_strv_free_ char **names = NULL;
        int r;

        assert(manager);
        assert(message);

        manager->slot_mm = sd_bus_slot_unref(manager->slot_mm);

        /* Read the list of available services. */
        r = sd_bus_message_read_strv(message, &names);
        if (r < 0)
                return bus_log_parse_error(r);

        if (!strv_contains(names, "org.freedesktop.ModemManager1"))
                /* If not found yet then wait for NameOwnerChanged signal. */
                return 0;

        log_info("ModemManager: service available");
        return enumerate_modems(manager);
}

int manager_notify_mm_bus_connected(Manager *m) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        int r;

        /*
         * Called on D-Bus connected.
         * Check if ModemManager is available. If it is then initialize.
         * If not then wait for the serivce to be available.
         */
        assert(m);
        assert(sd_bus_is_ready(m->bus) > 0);

        m->slot_mm = sd_bus_slot_unref(m->slot_mm);

        r = sd_bus_call_method_async(
                        m->bus,
                        &m->slot_mm,
                        "org.freedesktop.DBus",
                        "/org/freedesktop/DBus",
                        "org.freedesktop.DBus",
                        "ListNames",
                        list_names_handler,
                        m,
                        /* types= */ NULL);
        if (r < 0)
                return log_warning_errno(r, "Could not LsitNames: %m");

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize sd-event: %m");

        r = setup_periodic_timer(m, event);
        if (r < 0)
                return log_error_errno(r, "Failed to set up periodic timer: %m");

        return 0;
}
