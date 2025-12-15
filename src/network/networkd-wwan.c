/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "bus-util.h"
#include "hashmap.h"
#include "networkd-address.h"
#include "networkd-dhcp4.h"
#include "networkd-dhcp6.h"
#include "networkd-link.h"
#include "networkd-setlink.h"
#include "networkd-manager.h"
#include "networkd-ndisc.h"
#include "networkd-route.h"
#include "networkd-wwan.h"
#include "parse-util.h"
#include "sd-dhcp-client.h"
#include "sd-dhcp6-client.h"
#include "sd-ndisc.h"
#include "set.h"
#include "string-util.h"

Bearer* bearer_free(Bearer *b) {
        if (!b)
                return NULL;

        if (b->modem) {
                if (b->path)
                        hashmap_remove_value(b->modem->bearers_by_path, b->path, b);
                if (b->name)
                        hashmap_remove_value(b->modem->bearers_by_name, b->name, b);
        }

        sd_bus_slot_unref(b->slot_getall);

        free(b->path);
        free(b->name);
        free(b->apn);

        in_addr_full_array_free(b->dns, b->n_dns);

        return mfree(b);
}

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
        bearer_hash_ops,
        char,
        string_hash_func,
        string_compare_func,
        Bearer,
        bearer_free);

int bearer_new(Modem *modem, const char *path, Bearer **ret) {
        _cleanup_(bearer_freep) Bearer *b = NULL;
        _cleanup_free_ char *p = NULL;
        int r;

        assert(modem);
        assert(path);

        if (hashmap_contains(modem->bearers_by_path, path))
                return -EEXIST;

        p = strdup(path);
        if (!p)
                return -ENOMEM;

        b = new(Bearer, 1);
        if (!b)
                return -ENOMEM;

        *b = (Bearer) {
                .modem = modem,
                .path = TAKE_PTR(p),
        };

        r = hashmap_ensure_put(&modem->bearers_by_path, &bearer_hash_ops, b->path, b);
        if (r < 0)
                return r;

        if (ret)
                *ret = b;
        TAKE_PTR(b);
        return 0;
}

int bearer_set_name(Bearer *b, const char *name) {
        Bearer *old;
        int r;

        assert(b);
        assert(b->modem);
        assert(name);

        if (streq_ptr(b->name, name))
                return 0;

        if (b->name)
                hashmap_remove_value(b->modem->bearers_by_name, b->name, b);

        if (isempty(name)) {
                b->name = mfree(b->name);
                return 0;
        }

        r = free_and_strdup(&b->name, name);
        if (r < 0)
                return r;

        /*
         * FIXME: it is possible during reconnect that an interface is already
         * registered in the hash map: if simple connect options
         * are changed, e.g. externally modified .network file and then
         * reloaded with 'networkctl reload'. This may create a new bearer
         * attached to the same inerface name, e.g. "wwan0". The order in which
         * we parse the bearer properties is undetermined and it can be that we
         * need to raplce the old one with the new one now, so only one bearer
         * with the given interface name exists.
         */
        old = hashmap_get(b->modem->bearers_by_name, name);
        if (old) {
                hashmap_remove_value(old->modem->bearers_by_name, name, old);
                old->name = mfree(old->name);
        }

        return hashmap_ensure_put(&b->modem->bearers_by_name, &bearer_hash_ops, b->name, b);
}

int bearer_get_by_path(Manager *manager, const char *path, Modem **ret_modem, Bearer **ret_bearer) {
        Modem *modem;
        Bearer *b;

        assert(manager);
        assert(path);

        HASHMAP_FOREACH(modem, manager->modems_by_path) {
                b = hashmap_get(modem->bearers_by_path, path);
                if (!b)
                        continue;

                if (ret_bearer)
                        *ret_bearer = b;
                if (ret_modem)
                        *ret_modem = modem;
                return 0;
        }

        return -ENOENT;
}

Modem* modem_free(Modem *modem) {
        if (!modem)
                return NULL;

        if (modem->bearers_by_name)
                hashmap_free(modem->bearers_by_name);

        if (modem->bearers_by_path)
                hashmap_free(modem->bearers_by_path);

        if (modem->manager)
                hashmap_remove_value(modem->manager->modems_by_path, modem->path, modem);

        sd_bus_slot_unref(modem->slot_propertieschanged);
        sd_bus_slot_unref(modem->slot_statechanged);
        sd_bus_slot_unref(modem->slot_connect);

        free(modem->path);
        free(modem->manufacturer);
        free(modem->model);
        free(modem->port_name);

        return mfree(modem);
}

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
        modems_hash_ops,
        char,
        string_hash_func,
        string_compare_func,
        Modem,
        modem_free);

int modem_new(Manager *m, const char *path, Modem **ret) {
        _cleanup_(modem_freep) Modem *modem = NULL;
        _cleanup_free_ char *p = NULL;
        int r;

        assert(m);
        assert(path);

        if (hashmap_contains(m->modems_by_path, path))
                return -EEXIST;

        p = strdup(path);
        if (!p)
                return -ENOMEM;

        modem = new(Modem, 1);
        if (!modem)
                return -ENOMEM;

        *modem = (Modem) {
                .manager = m,
                .path = TAKE_PTR(p),
        };

        r = hashmap_ensure_put(&m->modems_by_path, &modems_hash_ops, modem->path, modem);
        if (r < 0)
                return r;

        if (ret)
                *ret = modem;

        TAKE_PTR(modem);
        return 0;
}

int modem_get_by_path(Manager *m, const char *path, Modem **ret) {
        Modem *modem;

        assert(m);
        assert(path);

        modem = hashmap_get(m->modems_by_path, path);
        if (!modem)
                return -ENOENT;

        if (ret)
                *ret = modem;

        return 0;
}

int link_get_modem(Link *link, Modem **ret) {
        Modem *modem;

        assert(link);
        assert(link->manager);
        assert(link->ifname);

        HASHMAP_FOREACH(modem, link->manager->modems_by_path)
                if (modem->port_name && streq(modem->port_name, link->ifname)) {
                        *ret = modem;
                        return 0;
                }

        return -ENOENT;
}

int link_get_bearer(Link *link, Bearer **ret) {
        Modem *modem;

        assert(link);
        assert(link->manager);
        assert(link->ifname);

        HASHMAP_FOREACH(modem, link->manager->modems_by_path) {
                Bearer *b;

                b = hashmap_get(modem->bearers_by_name, link->ifname);
                if (!b)
                        continue;

                if (ret)
                        *ret = b;
                return 0;
        }

        return -ENOENT;
}

int link_dhcp_enabled_by_bearer(Link *link, int family) {
        Bearer *b;
        int r;

        assert(link);
        assert(IN_SET(family, AF_INET, AF_INET6));

        r = link_get_bearer(link, &b);
        if (r < 0)
                return r;

        if (!b->connected)
                return false;

        if (!FLAGS_SET(b->ip_type, family == AF_INET ? ADDRESS_FAMILY_IPV4 : ADDRESS_FAMILY_IPV6))
                return false;

        return (family == AF_INET ? b->ip4_method : b->ip6_method) == MM_BEARER_IP_METHOD_DHCP;
}

static int bearer_address_handler(
                sd_netlink *rtnl,
                sd_netlink_message *m,
                Request *req,
                Link *link,
                Address *address) {

        int r;

        assert(link);

        r = address_configure_handler_internal(m, link, address);
        if (r <= 0)
                return r;

        if (link->bearer_messages == 0) {
                link->bearer_configured = true;
                link_check_ready(link);
        }

        return 0;
}

static int link_request_bearer_address(
                Link *link,
                int family,
                const union in_addr_union *addr,
                unsigned prefixlen) {

        _cleanup_(address_unrefp) Address *address = NULL;
        Address *existing;
        int r;

        assert(link);
        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(addr);

        if (!in_addr_is_set(family, addr))
                return 0;

        r = address_new(&address);
        if (r < 0)
                return log_oom();

        address->source = NETWORK_CONFIG_SOURCE_MODEM_MANAGER;
        address->family = family;
        address->in_addr = *addr;
        address->prefixlen = prefixlen;

        if (address_get(link, address, &existing) < 0) /* The address is new. */
                link->bearer_configured = false;
        else
                address_unmark(existing);

        r = link_request_address(link, address, &link->bearer_messages,
                                 bearer_address_handler, /* ret = */ NULL);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to request address provided by bearer: %m");

        return 0;
}

static int bearer_route_handler(
                sd_netlink *rtnl,
                sd_netlink_message *m,
                Request *req,
                Link *link,
                Route *route) {

        int r;

        assert(link);

        r = route_configure_handler_internal(m, req, route);
        if (r <= 0)
                return r;

        if (link->bearer_messages == 0) {
                link->bearer_configured = true;
                link_check_ready(link);
        }

        return 0;
}

static int link_request_bearer_route(
                Link *link,
                int family,
                const union in_addr_union *gw,
                const union in_addr_union *prefsrc) {

        _cleanup_(route_unrefp) Route *route = NULL;
        Route *existing;
        int r;

        assert(link);
        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(gw);
        assert(prefsrc);

        if (!in_addr_is_set(family, gw))
                return 0;

        if (link->network->mm_use_gateway == 0)
                return 0;

        r = route_new(&route);
        if (r < 0)
                return log_oom();

        route->source = NETWORK_CONFIG_SOURCE_MODEM_MANAGER;
        route->family = family;
        route->nexthop.family = family;
        route->nexthop.gw = *gw;
        if (link->network->mm_route_metric_set) {
                route->priority = link->network->mm_route_metric;
                route->priority_set = true;
        }

        if (prefsrc)
                route->prefsrc = *prefsrc;

        if (route_get(link->manager, route, &existing) < 0) /* This is a new route. */
                link->bearer_configured = false;
        else
                route_unmark(existing);

        r = link_request_route(link, route, &link->bearer_messages, bearer_route_handler);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to request gateway provided by bearer: %m");

        return 0;
}

static int link_apply_bearer_impl(Link *link, Bearer *b) {
        Address *address;
        Route *route;
        int r, ret = 0;

        assert(link);

        if (!IN_SET(link->state, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED))
                return 0;

        /* First, mark bearer configs. */
        SET_FOREACH(address, link->addresses) {
                if (address->source != NETWORK_CONFIG_SOURCE_MODEM_MANAGER)
                        continue;

                address_mark(address);
        }

        SET_FOREACH(route, link->manager->routes) {
                if (route->source != NETWORK_CONFIG_SOURCE_MODEM_MANAGER)
                        continue;

                route_mark(route);
        }

        if (b && FLAGS_SET(b->ip_type, ADDRESS_FAMILY_IPV4)) {
                if (b->connected && b->ip4_method == MM_BEARER_IP_METHOD_STATIC) {
                        r = link_request_bearer_address(link, AF_INET, &b->ip4_address, b->ip4_prefixlen);
                        if (r < 0)
                                return r;

                        r = link_request_bearer_route(link, AF_INET, &b->ip4_gateway, &b->ip4_address);
                        if (r < 0)
                                return r;
                }

                if (b->connected && b->ip4_method == MM_BEARER_IP_METHOD_DHCP) {
                        if (!link_dhcp4_enabled(link))
                                log_link_notice(link, "The WWAN connection requested DHCPv4 client, but it is disabled.");

                        r = dhcp4_start(link);
                        if (r < 0)
                                return log_link_warning_errno(link, r, "Failed to start DHCPv4 client: %m");
                } else {
                        r = sd_dhcp_client_stop(link->dhcp_client);
                        if (r < 0)
                                ret = log_link_warning_errno(link, r, "Could not stop DHCPv4 client: %m");
                }
        }

        if (b && FLAGS_SET(b->ip_type, ADDRESS_FAMILY_IPV6)) {
                if (b->connected && b->ip6_method == MM_BEARER_IP_METHOD_STATIC) {
                        r = link_request_bearer_address(link, AF_INET6, &b->ip6_address, b->ip6_prefixlen);
                        if (r < 0)
                                return r;

                        r = link_request_bearer_route(link, AF_INET6, &b->ip6_gateway, NULL);
                        if (r < 0)
                                return r;
                }

                if (b->connected && b->ip6_method == MM_BEARER_IP_METHOD_DHCP) {
                        if (!link_ndisc_enabled(link) && !link_dhcp6_enabled(link))
                                log_link_notice(link,
                                                "The WWAN connection requested IPv6 dynamic address configuration,"
                                                "but both IPv6 Router Discovery and DHCPv6 client are disabled.");

                        r = ndisc_start(link);
                        if (r < 0)
                                return log_link_warning_errno(link, r, "Failed to start IPv6 Router Discovery: %m");

                        r = dhcp6_start(link);
                        if (r < 0)
                                return log_link_warning_errno(link, r, "Failed to start DHCPv6 client: %m");
                } else {
                        r = sd_dhcp6_client_stop(link->dhcp6_client);
                        if (r < 0)
                                ret = log_link_warning_errno(link, r, "Could not stop DHCPv6 client: %m");

                        r = sd_ndisc_stop(link->ndisc);
                        if (r < 0)
                                ret = log_link_warning_errno(link, r, "Could not stop IPv6 Router Discovery: %m");
                }
        }

        /* Finally, remove all marked configs. */
        SET_FOREACH(address, link->addresses) {
                if (address->source != NETWORK_CONFIG_SOURCE_MODEM_MANAGER)
                        continue;

                if (!address_is_marked(address))
                        continue;

                r = address_remove(address, link);
                if (r < 0)
                        ret = r;
        }

        SET_FOREACH(route, link->manager->routes) {
                if (route->source != NETWORK_CONFIG_SOURCE_MODEM_MANAGER)
                        continue;

                if (!route_is_marked(route))
                        continue;

                r = route_remove(route, link->manager);
                if (ret)
                        ret = r;
        }

        if (ret < 0)
                return ret;

        if (link->bearer_messages == 0)
                link->bearer_configured = true;

        if (!link->bearer_configured)
                link_set_state(link, LINK_STATE_CONFIGURING);

        link_check_ready(link);

        return 0;
}

int link_apply_bearer(Link *link) {
        Bearer *b = NULL;
        int r;

        assert(link);

        (void) link_get_bearer(link, &b);

        r = link_apply_bearer_impl(link, b);
        if (r < 0)
                link_enter_failed(link);

        return r;
}

int bearer_update_link(Bearer *b) {
        Link *link;
        int r;

        assert(b);
        assert(b->modem);
        assert(b->modem->manager);

        if (!b->name)
                return 0;

        if (link_get_by_name(b->modem->manager, b->name, &link) < 0)
                return 0;

        r = link_apply_bearer_impl(link, b);
        if (r < 0)
                link_enter_failed(link);

        /*
         * Need to bring up the interface after the modem has connected.
         * This is because ModemManger does the following while connecting:
         * <msg> [1755871777.322239] [modem2] state changed (registered -> connecting)
         * <dbg> [1755871777.325012] [modem2/bearer5] launching connection with QMI port (cdc-wdm0) and data port (wwan0) (multiplex none)
         * <dbg> [1755871777.327665] [cdc-wdm0/qmi] bringing down data interface 'wwan0'
         * <dbg> [1755871777.330108] [modem2/wwan0/net] interface index: 9
         * <dbg> [1755871777.335265] [cdc-wdm0/qmi] deleting all links in data interface 'wwan0'
         */

        r = link_request_to_bring_up_or_down(link, b->connected);
        if (r < 0)
                link_enter_failed(link);

        return 0;
}

void bearer_drop(Bearer *b) {
        assert(b);

        b->connected = false;
        b->apn = mfree(b->apn);

        (void) bearer_update_link(b);

        bearer_free(b);
}

int config_parse_mm_route_metric(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Network *network = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                network->mm_route_metric_set = false;
                return 0;
        }

        r = safe_atou32(rvalue, &network->mm_route_metric);
        if (r < 0)
                return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);

        network->mm_route_metric_set = true;
        return 0;
}
