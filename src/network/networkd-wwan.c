/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-error.h"
#include "bus-map-properties.h"
#include "bus-parse-xml.h"
#include "bus-util.h"
#include "networkd-address.h"
#include "networkd-dhcp4.h"
#include "networkd-dhcp6.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-ndisc.h"
#include "networkd-route.h"
#include "networkd-wwan.h"

/* From ModemManager-enums.h */
typedef enum {
    MM_BEARER_IP_METHOD_UNKNOWN = 0,
    MM_BEARER_IP_METHOD_PPP     = 1,
    MM_BEARER_IP_METHOD_STATIC  = 2,
    MM_BEARER_IP_METHOD_DHCP    = 3,
} MMBearerIpMethod;

Bearer *bearer_free(Bearer *b) {
        if (!b)
                return NULL;

        if (b->manager) {
                if (b->path)
                        hashmap_remove_value(b->manager->bearers_by_path, b->path, b);
                if (b->name)
                        hashmap_remove_value(b->manager->bearers_by_name, b->name, b);
        }

        sd_bus_slot_unref(b->slot);

        free(b->path);
        free(b->name);
        free(b->apn);

        free(b->dns);

        return mfree(b);
}

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
        bearer_hash_ops,
        char,
        string_hash_func,
        string_compare_func,
        Bearer,
        bearer_free);

int bearer_new(Manager *m, const char *path, Bearer **ret) {
        _cleanup_(bearer_freep) Bearer *b = NULL;
        _cleanup_free_ char *p = NULL;
        int r;

        assert(m);
        assert(path);

        p = strdup(path);
        if (!p)
                return log_oom();

        b = new(Bearer, 1);
        if (!b)
                return log_oom();

        *b = (Bearer) {
                .manager = m,
                .path = TAKE_PTR(p),
        };

        r = hashmap_ensure_put(&m->bearers_by_path, &bearer_hash_ops, b->path, b);
        if (r < 0)
                return r;

        if (ret)
                *ret = b;
        TAKE_PTR(b);
        return 0;
}

int bearer_set_name(Bearer *b, const char *name) {
        int r;

        assert(b);
        assert(b->manager);
        assert(name);

        if (streq_ptr(b->name, name))
                return 0;

        if (b->name)
                hashmap_remove_value(b->manager->bearers_by_name, b->name, b);

        r = free_and_strdup(&b->name, name);
        if (r < 0)
                return r;

        return hashmap_ensure_put(&b->manager->bearers_by_name, &bearer_hash_ops, b->name, b);
}

int bearer_get_by_path(Manager *m, const char *path, Bearer **ret) {
        Bearer *b;

        assert(m);
        assert(path);

        b = hashmap_get(m->bearers_by_path, path);
        if (!b)
                return -ENOENT;

        if (ret)
                *ret = b;

        return 0;
}

int link_get_bearer(Link *link, Bearer **ret) {
        Bearer *b;

        assert(link);
        assert(link->manager);
        assert(link->ifname);

        b = hashmap_get(link->manager->bearers_by_name, link->ifname);
        if (!b)
                return -ENOENT;

        if (ret)
                *ret = b;

        return 0;
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

static int bearer_address_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, Address *address) {
        int r;

        assert(link);

        r = address_configure_handler_internal(rtnl, m, link, "Could not set address provided by bearer");
        if (r <= 0)
                return r;

        if (link->bearer_messages == 0) {
                link->bearer_configured = true;
                link_check_ready(link);
        }

        return 0;
}

static int link_request_bearer_address(Link *link, int family, const union in_addr_union *addr, unsigned prefixlen) {
        _cleanup_(address_freep) Address *address = NULL;
        Address *existing;
        int r;

        assert(link);
        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(addr);

        if (!in_addr_is_set(family, addr))
                return 0;

        /* prefixlen is not checked when parsed DBus message. Let's check it here. */
        if (prefixlen > (family == AF_INET ? 32 : 128)) {
                log_link_debug(link, "Bearer has invalid prefix length %u for %s address, ignoring.",
                               prefixlen,
                               family == AF_INET ? "IPv4" : "IPv6");
                return 0;
        }

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

        r = link_request_address(link, TAKE_PTR(address), true, &link->bearer_messages,
                                 bearer_address_handler, NULL);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to request address provided by bearer: %m");

        return 0;
}

static int bearer_route_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, Route *route) {
        int r;

        assert(link);

        r = route_configure_handler_internal(rtnl, m, link, "Could not set gateway provided by bearer");
        if (r <= 0)
                return r;

        if (link->bearer_messages == 0) {
                link->bearer_configured = true;
                link_check_ready(link);
        }

        return 0;
}

static int link_request_bearer_route(Link *link, int family, const union in_addr_union *gw, const union in_addr_union *prefsrc) {
        _cleanup_(route_freep) Route *route = NULL;
        Route *existing;
        int r;

        assert(link);
        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(gw);
        assert(prefsrc);

        if (!in_addr_is_set(family, gw))
                return 0;

        r = route_new(&route);
        if (r < 0)
                return log_oom();

        route->source = NETWORK_CONFIG_SOURCE_MODEM_MANAGER;
        route->family = family;
        route->gw_family = family;
        route->gw = *gw;
        if (prefsrc)
                route->prefsrc = *prefsrc;

        if (route_get(NULL, link, route, &existing) < 0) /* This is a new route. */
                link->bearer_configured = false;
        else
                route_unmark(existing);

        r = link_request_route(link, TAKE_PTR(route), true, &link->bearer_messages,
                               bearer_route_handler, NULL);
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

        SET_FOREACH(route, link->routes) {
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
                        if (!link_ipv6_accept_ra_enabled(link) && !link_dhcp6_enabled(link))
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

                r = address_remove(address);
                if (r < 0)
                        ret = r;
        }

        SET_FOREACH(route, link->routes) {
                if (route->source != NETWORK_CONFIG_SOURCE_MODEM_MANAGER)
                        continue;

                if (!route_is_marked(route))
                        continue;

                r = route_remove(route);
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

        return ret;
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

        if (!b->name)
                return 0;

        if (link_get_by_name(b->manager, b->name, &link) < 0)
                return 0;

        r = link_reconfigure_impl(link, /* force = */ false);
        if (r < 0)
                link_enter_failed(link);
        if (r != 0) /* r > 0 means interface is reconfigured. */
                return r;

        r = link_apply_bearer_impl(link, b);
        if (r < 0)
                link_enter_failed(link);

        return r;
}

void bearer_drop(Bearer *b) {
        assert(b);

        b->connected = false;
        b->apn = mfree(b->apn);

        (void) bearer_update_link(b);

        bearer_free(b);
}
