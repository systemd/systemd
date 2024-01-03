/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/ipv6_route.h>

#include "dhcp6-lease-internal.h"
#include "hashmap.h"
#include "in-addr-prefix-util.h"
#include "networkd-address-generation.h"
#include "networkd-address.h"
#include "networkd-dhcp-prefix-delegation.h"
#include "networkd-dhcp6.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-queue.h"
#include "networkd-radv.h"
#include "networkd-route.h"
#include "networkd-setlink.h"
#include "parse-util.h"
#include "string-util.h"
#include "strv.h"
#include "tunnel.h"

bool link_dhcp_pd_is_enabled(Link *link) {
        assert(link);

        if (!link->network)
                return false;

        return link->network->dhcp_pd;
}

bool dhcp_pd_is_uplink(Link *link, Link *target, bool accept_auto) {
        assert(link);
        assert(target);

        if (!link_dhcp_pd_is_enabled(link))
                return false;

        if (link->network->dhcp_pd_uplink_name)
                return streq_ptr(target->ifname, link->network->dhcp_pd_uplink_name) ||
                        strv_contains(target->alternative_names, link->network->dhcp_pd_uplink_name);

        if (link->network->dhcp_pd_uplink_index > 0)
                return target->ifindex == link->network->dhcp_pd_uplink_index;

        if (link->network->dhcp_pd_uplink_index == UPLINK_INDEX_SELF)
                return link == target;

        assert(link->network->dhcp_pd_uplink_index == UPLINK_INDEX_AUTO);
        return accept_auto;
}

static void link_remove_dhcp_pd_subnet_prefix(Link *link, const struct in6_addr *prefix) {
        void *key;

        assert(link);
        assert(link->manager);
        assert(prefix);

        if (hashmap_get(link->manager->links_by_dhcp_pd_subnet_prefix, prefix) != link)
                return;

        hashmap_remove2(link->manager->links_by_dhcp_pd_subnet_prefix, prefix, &key);
        free(key);
}

static int link_add_dhcp_pd_subnet_prefix(Link *link, const struct in6_addr *prefix) {
        _cleanup_free_ struct in6_addr *copy = NULL;
        int r;

        assert(link);
        assert(prefix);

        copy = newdup(struct in6_addr, prefix, 1);
        if (!copy)
                return -ENOMEM;

        r = hashmap_ensure_put(&link->manager->links_by_dhcp_pd_subnet_prefix, &in6_addr_hash_ops_free, copy, link);
        if (r < 0)
                return r;
        if (r > 0)
                TAKE_PTR(copy);

        return 0;
}

static int link_get_by_dhcp_pd_subnet_prefix(Manager *manager, const struct in6_addr *prefix, Link **ret) {
        Link *link;

        assert(manager);
        assert(prefix);

        link = hashmap_get(manager->links_by_dhcp_pd_subnet_prefix, prefix);
        if (!link)
                return -ENODEV;

        if (ret)
                *ret = link;
        return 0;
}

static int dhcp_pd_get_assigned_subnet_prefix(Link *link, const struct in6_addr *pd_prefix, uint8_t pd_prefix_len, struct in6_addr *ret) {
        assert(link);
        assert(pd_prefix);

        if (!link_dhcp_pd_is_enabled(link))
                return -ENOENT;

        if (link->network->dhcp_pd_assign) {
                Address *address;

                SET_FOREACH(address, link->addresses) {
                        if (address->source != NETWORK_CONFIG_SOURCE_DHCP_PD)
                                continue;
                        assert(address->family == AF_INET6);

                        if (in6_addr_prefix_covers(pd_prefix, pd_prefix_len, &address->in_addr.in6) <= 0)
                                continue;

                        if (ret) {
                                struct in6_addr prefix = address->in_addr.in6;

                                in6_addr_mask(&prefix, 64);
                                *ret = prefix;
                        }
                        return 0;
                }
        } else {
                Route *route;

                SET_FOREACH(route, link->manager->routes) {
                        if (route->source != NETWORK_CONFIG_SOURCE_DHCP_PD)
                                continue;
                        assert(route->family == AF_INET6);

                        if (route->nexthop.ifindex != link->ifindex)
                                continue;

                        if (in6_addr_prefix_covers(pd_prefix, pd_prefix_len, &route->dst.in6) > 0) {
                                if (ret)
                                        *ret = route->dst.in6;
                                return 0;
                        }
                }
        }

        return -ENOENT;
}

int dhcp_pd_remove(Link *link, bool only_marked) {
        int ret = 0;

        assert(link);
        assert(link->manager);

        if (!link_dhcp_pd_is_enabled(link))
                return 0;

        if (!only_marked)
                link->dhcp_pd_configured = false;

        if (!link->network->dhcp_pd_assign) {
                Route *route;

                SET_FOREACH(route, link->manager->routes) {
                        if (route->source != NETWORK_CONFIG_SOURCE_DHCP_PD)
                                continue;
                        if (route->nexthop.ifindex != link->ifindex)
                                continue;
                        if (only_marked && !route_is_marked(route))
                                continue;

                        if (link->radv)
                                sd_radv_remove_prefix(link->radv, &route->dst.in6, 64);

                        link_remove_dhcp_pd_subnet_prefix(link, &route->dst.in6);

                        RET_GATHER(ret, route_remove_and_cancel(route, link->manager));
                }
        } else {
                Address *address;

                SET_FOREACH(address, link->addresses) {
                        struct in6_addr prefix;

                        if (address->source != NETWORK_CONFIG_SOURCE_DHCP_PD)
                                continue;
                        if (only_marked && !address_is_marked(address))
                                continue;

                        prefix = address->in_addr.in6;
                        in6_addr_mask(&prefix, 64);

                        if (link->radv)
                                sd_radv_remove_prefix(link->radv, &prefix, 64);

                        link_remove_dhcp_pd_subnet_prefix(link, &prefix);

                        RET_GATHER(ret, address_remove_and_cancel(address, link));
                }
        }

        return ret;
}

static int dhcp_pd_check_ready(Link *link);

static int dhcp_pd_address_ready_callback(Address *address) {
        Address *a;

        assert(address);
        assert(address->link);

        SET_FOREACH(a, address->link->addresses)
                if (a->source == NETWORK_CONFIG_SOURCE_DHCP_PD)
                        a->callback = NULL;

        return dhcp_pd_check_ready(address->link);
}

static int dhcp_pd_check_ready(Link *link) {
        int r;

        assert(link);
        assert(link->network);

        if (link->dhcp_pd_messages > 0) {
                log_link_debug(link, "%s(): DHCP-PD addresses and routes are not set.", __func__);
                return 0;
        }

        if (link->network->dhcp_pd_assign) {
                bool has_ready = false;
                Address *address;

                SET_FOREACH(address, link->addresses) {
                        if (address->source != NETWORK_CONFIG_SOURCE_DHCP_PD)
                                continue;
                        if (address_is_ready(address)) {
                                has_ready = true;
                                break;
                        }
                }

                if (!has_ready) {
                        SET_FOREACH(address, link->addresses)
                                if (address->source == NETWORK_CONFIG_SOURCE_DHCP_PD)
                                        address->callback = dhcp_pd_address_ready_callback;

                        log_link_debug(link, "%s(): no DHCP-PD address is ready.", __func__);
                        return 0;
                }
        }

        link->dhcp_pd_configured = true;

        log_link_debug(link, "DHCP-PD addresses and routes set.");

        r = dhcp_pd_remove(link, /* only_marked = */ true);
        if (r < 0)
                return r;

        link_check_ready(link);
        return 1;
}

static int dhcp_pd_route_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, Route *route) {
        int r;

        assert(link);

        r = route_configure_handler_internal(rtnl, m, link, route, "Failed to add prefix route for DHCP delegated subnet prefix");
        if (r <= 0)
                return r;

        r = dhcp_pd_check_ready(link);
        if (r < 0)
                link_enter_failed(link);

        return 1;
}

static int dhcp_pd_request_route(Link *link, const struct in6_addr *prefix, usec_t lifetime_usec) {
        _cleanup_(route_unrefp) Route *route = NULL;
        Route *existing;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->network);
        assert(prefix);

        if (link->network->dhcp_pd_assign)
                return 0;

        r = route_new(&route);
        if (r < 0)
                return r;

        route->source = NETWORK_CONFIG_SOURCE_DHCP_PD;
        route->family = AF_INET6;
        route->dst.in6 = *prefix;
        route->dst_prefixlen = 64;
        route->nexthop.ifindex = link->ifindex;
        route->protocol = RTPROT_DHCP;
        route->priority = link->network->dhcp_pd_route_metric;
        route->lifetime_usec = lifetime_usec;

        if (route_get(link->manager, route, &existing) < 0)
                link->dhcp_pd_configured = false;
        else
                route_unmark(existing);

        r = link_request_route(link, route, &link->dhcp_pd_messages, dhcp_pd_route_handler, NULL);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to request DHCP-PD prefix route: %m");

        return 0;
}

static int dhcp_pd_address_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, Address *address) {
        int r;

        assert(link);

        r = address_configure_handler_internal(rtnl, m, link, "Could not set DHCP-PD address");
        if (r <= 0)
                return r;

        r = dhcp_pd_check_ready(link);
        if (r < 0)
                link_enter_failed(link);

        return 1;
}

static void log_dhcp_pd_address(Link *link, const Address *address) {
        assert(address);
        assert(address->family == AF_INET6);

        int log_level = address_get_harder(link, address, NULL) >= 0 ? LOG_DEBUG : LOG_INFO;

        if (log_level < log_get_max_level())
                return;

        log_link_full(link, log_level, "DHCP-PD address %s (valid %s, preferred %s)",
                      IN6_ADDR_PREFIX_TO_STRING(&address->in_addr.in6, address->prefixlen),
                      FORMAT_LIFETIME(address->lifetime_valid_usec),
                      FORMAT_LIFETIME(address->lifetime_preferred_usec));
}

static int dhcp_pd_request_address(
                Link *link,
                const struct in6_addr *prefix,
                usec_t lifetime_preferred_usec,
                usec_t lifetime_valid_usec) {

        _cleanup_set_free_ Set *addresses = NULL;
        struct in6_addr *a;
        int r;

        assert(link);
        assert(link->network);
        assert(prefix);

        if (!link->network->dhcp_pd_assign)
                return 0;

        r = dhcp_pd_generate_addresses(link, prefix, &addresses);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to generate addresses for acquired DHCP delegated prefix: %m");

        SET_FOREACH(a, addresses) {
                _cleanup_(address_unrefp) Address *address = NULL;
                Address *existing;

                r = address_new(&address);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to allocate address for DHCP delegated prefix: %m");

                address->source = NETWORK_CONFIG_SOURCE_DHCP_PD;
                address->family = AF_INET6;
                address->in_addr.in6 = *a;
                address->prefixlen = 64;
                address->lifetime_preferred_usec = lifetime_preferred_usec;
                address->lifetime_valid_usec = lifetime_valid_usec;
                SET_FLAG(address->flags, IFA_F_MANAGETEMPADDR, link->network->dhcp_pd_manage_temporary_address);
                address->route_metric = link->network->dhcp_pd_route_metric;

                log_dhcp_pd_address(link, address);

                r = free_and_strdup_warn(&address->netlabel, link->network->dhcp_pd_netlabel);
                if (r < 0)
                        return r;

                if (address_get(link, address, &existing) < 0)
                        link->dhcp_pd_configured = false;
                else
                        address_unmark(existing);

                r = link_request_address(link, address, &link->dhcp_pd_messages,
                                         dhcp_pd_address_handler, NULL);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to request DHCP delegated prefix address: %m");
        }

        return 0;
}

static int dhcp_pd_calculate_subnet_prefix(
                const struct in6_addr *pd_prefix,
                uint8_t pd_prefix_len,
                uint64_t subnet_id,
                struct in6_addr *ret) {

        struct in6_addr prefix;

        assert(pd_prefix);
        assert(pd_prefix_len <= 64);
        assert(ret);

        if (subnet_id >= UINT64_C(1) << (64 - pd_prefix_len))
                return -ERANGE;

        prefix = *pd_prefix;

        if (pd_prefix_len < 32)
                prefix.s6_addr32[0] |= htobe32(subnet_id >> 32);

        prefix.s6_addr32[1] |= htobe32(subnet_id & 0xffffffff);

        *ret = prefix;
        return 0;
}

static int dhcp_pd_get_preferred_subnet_prefix(
                Link *link,
                const struct in6_addr *pd_prefix,
                uint8_t pd_prefix_len,
                struct in6_addr *ret) {

        struct in6_addr prefix;
        Link *assigned_link;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->network);
        assert(pd_prefix);

        if (link->network->dhcp_pd_subnet_id >= 0) {
                /* If the link has a preference for a particular subnet id try to allocate that */

                r = dhcp_pd_calculate_subnet_prefix(pd_prefix, pd_prefix_len, link->network->dhcp_pd_subnet_id, &prefix);
                if (r < 0)
                        return log_link_warning_errno(link, r,
                                                      "subnet id %" PRIi64 " is out of range. Only have %" PRIu64 " subnets.",
                                                      link->network->dhcp_pd_subnet_id, UINT64_C(1) << (64 - pd_prefix_len));

                *ret = prefix;
                return 0;
        }

        if (dhcp_pd_get_assigned_subnet_prefix(link, pd_prefix, pd_prefix_len, ret) >= 0)
                return 0;

        for (uint64_t n = 0; ; n++) {
                /* If we do not have an allocation preference just iterate
                 * through the address space and return the first free prefix. */

                r = dhcp_pd_calculate_subnet_prefix(pd_prefix, pd_prefix_len, n, &prefix);
                if (r < 0)
                        return log_link_warning_errno(link, r,
                                                      "Couldn't find a suitable prefix. Ran out of address space.");

                /* Do not use explicitly requested subnet IDs. Note that the corresponding link may not
                 * appear yet. So, we need to check the ID is not used in any .network files. */
                if (set_contains(link->manager->dhcp_pd_subnet_ids, &n))
                        continue;

                /* Check that the prefix is not assigned to another link. */
                if (link_get_by_dhcp_pd_subnet_prefix(link->manager, &prefix, &assigned_link) < 0 ||
                    assigned_link == link)
                        break;
        }

        r = link_add_dhcp_pd_subnet_prefix(link, &prefix);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to save acquired free subnet prefix: %m");

        *ret = prefix;
        return 0;
}

static int dhcp_pd_assign_subnet_prefix(
                Link *link,
                const struct in6_addr *pd_prefix,
                uint8_t pd_prefix_len,
                usec_t lifetime_preferred_usec,
                usec_t lifetime_valid_usec,
                bool is_uplink) {

        struct in6_addr prefix;
        int r;

        assert(link);
        assert(link->network);
        assert(pd_prefix);

        r = dhcp_pd_get_preferred_subnet_prefix(link, pd_prefix, pd_prefix_len, &prefix);
        if (r < 0)
                return r == -ERANGE ? 0 : r;

        const char *pretty = IN6_ADDR_PREFIX_TO_STRING(&prefix, 64);

        if (link_radv_enabled(link) && link->network->dhcp_pd_announce) {
                if (is_uplink)
                        log_link_debug(link, "Ignoring Announce= setting on upstream interface.");
                else {
                        r = radv_add_prefix(link, &prefix, 64, lifetime_preferred_usec, lifetime_valid_usec);
                        if (r < 0)
                                return log_link_warning_errno(link, r,
                                                              "Failed to assign/update prefix %s to IPv6 Router Advertisement: %m",
                                                              pretty);
                }
        }

        r = dhcp_pd_request_route(link, &prefix, lifetime_valid_usec);
        if (r < 0)
                return log_link_warning_errno(link, r,
                                              "Failed to assign/update route for prefix %s: %m", pretty);

        r = dhcp_pd_request_address(link, &prefix, lifetime_preferred_usec, lifetime_valid_usec);
        if (r < 0)
                return log_link_warning_errno(link, r,
                                              "Failed to assign/update address for prefix %s: %m", pretty);

        log_link_debug(link, "Assigned prefix %s", pretty);
        return 1;
}

static int dhcp_pd_prepare(Link *link) {
        if (!IN_SET(link->state, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED))
                return 0;

        if (!link_dhcp_pd_is_enabled(link))
                return 0;

        if (link_radv_enabled(link) && link->network->dhcp_pd_announce && !link->radv)
                return 0;

        link_mark_addresses(link, NETWORK_CONFIG_SOURCE_DHCP_PD);
        manager_mark_routes(link->manager, link, NETWORK_CONFIG_SOURCE_DHCP_PD);

        return 1;
}

static int dhcp_pd_finalize(Link *link) {
        int r;

        if (!IN_SET(link->state, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED))
                return 0;

        if (link->dhcp_pd_messages == 0) {
                link->dhcp_pd_configured = false;

                r = dhcp_pd_remove(link, /* only_marked = */ true);
                if (r < 0)
                        return r;
        }

        if (!link->dhcp_pd_configured)
                link_set_state(link, LINK_STATE_CONFIGURING);

        link_check_ready(link);
        return 0;
}

void dhcp_pd_prefix_lost(Link *uplink) {
        Route *route;
        Link *link;
        int r;

        assert(uplink);
        assert(uplink->manager);

        HASHMAP_FOREACH(link, uplink->manager->links_by_index) {
                if (!dhcp_pd_is_uplink(link, uplink, /* accept_auto = */ true))
                        continue;

                r = dhcp_pd_remove(link, /* only_marked = */ false);
                if (r < 0)
                        link_enter_failed(link);
        }

        SET_FOREACH(route, uplink->manager->routes) {
                if (!IN_SET(route->source, NETWORK_CONFIG_SOURCE_DHCP4, NETWORK_CONFIG_SOURCE_DHCP6))
                        continue;
                if (route->family != AF_INET6)
                        continue;
                if (route->type != RTN_UNREACHABLE)
                        continue;
                if (!set_contains(uplink->dhcp_pd_prefixes,
                                  &(struct in_addr_prefix) {
                                          .family = AF_INET6,
                                          .prefixlen = route->dst_prefixlen,
                                          .address = route->dst }))
                        continue;

                (void) route_remove_and_cancel(route, uplink->manager);
        }

        set_clear(uplink->dhcp_pd_prefixes);
}

void dhcp4_pd_prefix_lost(Link *uplink) {
        Link *tunnel;

        dhcp_pd_prefix_lost(uplink);

        if (uplink->dhcp4_6rd_tunnel_name &&
            link_get_by_name(uplink->manager, uplink->dhcp4_6rd_tunnel_name, &tunnel) >= 0)
                (void) link_remove(tunnel);
}

static int dhcp4_unreachable_route_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, Route *route) {
        int r;

        assert(link);

        r = route_configure_handler_internal(rtnl, m, link, route, "Failed to set unreachable route for DHCPv4 delegated prefix");
        if (r <= 0)
                return r;

        r = dhcp4_check_ready(link);
        if (r < 0)
                link_enter_failed(link);

        return 1;
}

static int dhcp6_unreachable_route_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, Route *route) {
        int r;

        assert(link);

        r = route_configure_handler_internal(rtnl, m, link, route, "Failed to set unreachable route for DHCPv6 delegated prefix");
        if (r <= 0)
                return r;

        r = dhcp6_check_ready(link);
        if (r < 0)
                link_enter_failed(link);

        return 1;
}

static int dhcp_request_unreachable_route(
                Link *link,
                const struct in6_addr *addr,
                uint8_t prefixlen,
                usec_t lifetime_usec,
                NetworkConfigSource source,
                const union in_addr_union *server_address,
                unsigned *counter,
                route_netlink_handler_t callback,
                bool *configured) {

        _cleanup_(route_unrefp) Route *route = NULL;
        Route *existing;
        int r;

        assert(link);
        assert(link->manager);
        assert(addr);
        assert(IN_SET(source, NETWORK_CONFIG_SOURCE_DHCP4, NETWORK_CONFIG_SOURCE_DHCP6));
        assert(server_address);
        assert(counter);
        assert(callback);
        assert(configured);

        if (prefixlen >= 64) {
                log_link_debug(link, "Not adding a blocking route for DHCP delegated prefix %s since the prefix has length >= 64.",
                               IN6_ADDR_PREFIX_TO_STRING(addr, prefixlen));
                return 0;
        }

        r = route_new(&route);
        if (r < 0)
                return log_oom();

        route->source = source;
        route->provider = *server_address;
        route->family = AF_INET6;
        route->dst.in6 = *addr;
        route->dst_prefixlen = prefixlen;
        route->type = RTN_UNREACHABLE;
        route->protocol = RTPROT_DHCP;
        route->priority = IP6_RT_PRIO_USER;
        route->lifetime_usec = lifetime_usec;

        if (route_get(link->manager, route, &existing) < 0)
                *configured = false;
        else
                route_unmark(existing);

        r = link_request_route(link, route, counter, callback, NULL);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to request unreachable route for DHCP delegated prefix %s: %m",
                                            IN6_ADDR_PREFIX_TO_STRING(addr, prefixlen));

        return 0;
}

static int dhcp4_request_unreachable_route(
                Link *link,
                const struct in6_addr *addr,
                uint8_t prefixlen,
                usec_t lifetime_usec,
                const union in_addr_union *server_address) {

        return dhcp_request_unreachable_route(link, addr, prefixlen, lifetime_usec,
                                              NETWORK_CONFIG_SOURCE_DHCP4, server_address,
                                              &link->dhcp4_messages, dhcp4_unreachable_route_handler,
                                              &link->dhcp4_configured);
}

static int dhcp6_request_unreachable_route(
                Link *link,
                const struct in6_addr *addr,
                uint8_t prefixlen,
                usec_t lifetime_usec,
                const union in_addr_union *server_address) {

        return dhcp_request_unreachable_route(link, addr, prefixlen, lifetime_usec,
                                              NETWORK_CONFIG_SOURCE_DHCP6, server_address,
                                              &link->dhcp6_messages, dhcp6_unreachable_route_handler,
                                              &link->dhcp6_configured);
}

static int dhcp_pd_prefix_add(Link *link, const struct in6_addr *prefix, uint8_t prefixlen) {
        struct in_addr_prefix *p;
        int r;

        assert(link);
        assert(prefix);

        p = new(struct in_addr_prefix, 1);
        if (!p)
                return log_oom();

        *p = (struct in_addr_prefix) {
                .family = AF_INET6,
                .prefixlen = prefixlen,
                .address.in6 = *prefix,
        };

        int log_level = set_contains(link->dhcp_pd_prefixes, p) ? LOG_DEBUG :
                               prefixlen > 64 || prefixlen < 48 ? LOG_WARNING : LOG_INFO;
        log_link_full(link,
                      log_level,
                      "DHCP: received delegated prefix %s%s",
                      IN6_ADDR_PREFIX_TO_STRING(prefix, prefixlen),
                      prefixlen > 64 ? " with prefix length > 64, ignoring." :
                      prefixlen < 48 ? " with prefix length < 48, looks unusual.": "");

        /* Store PD prefix even if prefixlen > 64, not to make logged at warning level so frequently. */
        r = set_ensure_consume(&link->dhcp_pd_prefixes, &in_addr_prefix_hash_ops_free, p);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to store DHCP delegated prefix %s: %m",
                                            IN6_ADDR_PREFIX_TO_STRING(prefix, prefixlen));
        return 0;
}

static int dhcp4_pd_request_default_gateway_on_6rd_tunnel(Link *link, const struct in_addr *br_address, usec_t lifetime_usec) {
        _cleanup_(route_unrefp) Route *route = NULL;
        Route *existing;
        int r;

        assert(link);
        assert(link->manager);
        assert(br_address);

        r = route_new(&route);
        if (r < 0)
                return log_link_debug_errno(link, r, "Failed to allocate default gateway for DHCP delegated prefix: %m");

        route->source = NETWORK_CONFIG_SOURCE_DHCP_PD;
        route->family = AF_INET6;
        route->nexthop.ifindex = link->ifindex;
        route->nexthop.family = AF_INET6;
        route->nexthop.gw.in6.s6_addr32[3] = br_address->s_addr;
        route->scope = RT_SCOPE_UNIVERSE;
        route->protocol = RTPROT_DHCP;
        route->priority = IP6_RT_PRIO_USER;
        route->lifetime_usec = lifetime_usec;

        if (route_get(link->manager, route, &existing) < 0) /* This is a new route. */
                link->dhcp_pd_configured = false;
        else
                route_unmark(existing);

        r = link_request_route(link, route, &link->dhcp_pd_messages, dhcp_pd_route_handler, NULL);
        if (r < 0)
                return log_link_debug_errno(link, r, "Failed to request default gateway for DHCP delegated prefix: %m");

        return 0;
}

static void dhcp4_calculate_pd_prefix(
                const struct in_addr *ipv4address,
                uint8_t ipv4masklen,
                const struct in6_addr *sixrd_prefix,
                uint8_t sixrd_prefixlen,
                struct in6_addr *ret_pd_prefix,
                uint8_t *ret_pd_prefixlen) {

        struct in6_addr pd_prefix;

        assert(ipv4address);
        assert(ipv4masklen <= 32);
        assert(sixrd_prefix);
        assert(32 - ipv4masklen + sixrd_prefixlen <= 128);
        assert(ret_pd_prefix);

        pd_prefix = *sixrd_prefix;
        for (unsigned i = 0; i < (unsigned) (32 - ipv4masklen); i++)
                if (ipv4address->s_addr & htobe32(UINT32_C(1) << (32 - ipv4masklen - i - 1)))
                        pd_prefix.s6_addr[(i + sixrd_prefixlen) / 8] |= 1 << (7 - (i + sixrd_prefixlen) % 8);

        *ret_pd_prefix = pd_prefix;
        if (ret_pd_prefixlen)
                *ret_pd_prefixlen = 32 - ipv4masklen + sixrd_prefixlen;
}

static int dhcp4_pd_assign_subnet_prefix(Link *link, Link *uplink) {
        uint8_t ipv4masklen, sixrd_prefixlen, pd_prefixlen;
        struct in6_addr sixrd_prefix, pd_prefix;
        const struct in_addr *br_addresses;
        struct in_addr ipv4address;
        usec_t lifetime_usec;
        int r;

        assert(link);
        assert(uplink);
        assert(uplink->manager);
        assert(uplink->dhcp_lease);

        r = sd_dhcp_lease_get_address(uplink->dhcp_lease, &ipv4address);
        if (r < 0)
                return log_link_warning_errno(uplink, r, "Failed to get DHCPv4 address: %m");

        r = sd_dhcp_lease_get_lifetime_timestamp(uplink->dhcp_lease, CLOCK_BOOTTIME, &lifetime_usec);
        if (r < 0)
                return log_link_warning_errno(uplink, r, "Failed to get lifetime of DHCPv4 lease: %m");

        r = sd_dhcp_lease_get_6rd(uplink->dhcp_lease, &ipv4masklen, &sixrd_prefixlen, &sixrd_prefix, &br_addresses, NULL);
        if (r < 0)
                return log_link_warning_errno(uplink, r, "Failed to get DHCPv4 6rd option: %m");

        dhcp4_calculate_pd_prefix(&ipv4address, ipv4masklen, &sixrd_prefix, sixrd_prefixlen, &pd_prefix, &pd_prefixlen);

        if (pd_prefixlen > 64)
                return 0;

        r = dhcp_pd_prepare(link);
        if (r <= 0)
                return r;

        if (streq_ptr(uplink->dhcp4_6rd_tunnel_name, link->ifname)) {
                r = dhcp4_pd_request_default_gateway_on_6rd_tunnel(link, &br_addresses[0], lifetime_usec);
                if (r < 0)
                        return r;
        }

        r = dhcp_pd_assign_subnet_prefix(link, &pd_prefix, pd_prefixlen, lifetime_usec, lifetime_usec, /* is_uplink = */ false);
        if (r < 0)
                return r;

        return dhcp_pd_finalize(link);
}

static int dhcp4_pd_6rd_tunnel_create_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(m);
        assert(link);
        assert(link->manager);
        assert(link->dhcp4_6rd_tunnel_name);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 0;

        r = sd_netlink_message_get_errno(m);
        if (r < 0) {
                log_link_message_warning_errno(link, m, r, "Failed to create tunnel device for DHCPv4 6rd");
                link_enter_failed(link);
                return 0;
        }

        return 0;
}

int dhcp4_pd_prefix_acquired(Link *uplink) {
        _cleanup_free_ char *tunnel_name = NULL;
        uint8_t ipv4masklen, sixrd_prefixlen, pd_prefixlen;
        struct in6_addr sixrd_prefix, pd_prefix;
        struct in_addr ipv4address;
        union in_addr_union server_address;
        const struct in_addr *br_addresses;
        usec_t lifetime_usec;
        Link *link;
        int r;

        assert(uplink);
        assert(uplink->manager);
        assert(uplink->dhcp_lease);

        r = sd_dhcp_lease_get_address(uplink->dhcp_lease, &ipv4address);
        if (r < 0)
                return log_link_warning_errno(uplink, r, "Failed to get DHCPv4 address: %m");

        r = sd_dhcp_lease_get_lifetime_timestamp(uplink->dhcp_lease, CLOCK_BOOTTIME, &lifetime_usec);
        if (r < 0)
                return log_link_warning_errno(uplink, r, "Failed to get lifetime of DHCPv4 lease: %m");

        r = sd_dhcp_lease_get_server_identifier(uplink->dhcp_lease, &server_address.in);
        if (r < 0)
                return log_link_warning_errno(uplink, r, "Failed to get server address of DHCPv4 lease: %m");

        r = sd_dhcp_lease_get_6rd(uplink->dhcp_lease, &ipv4masklen, &sixrd_prefixlen, &sixrd_prefix, &br_addresses, NULL);
        if (r < 0)
                return log_link_warning_errno(uplink, r, "Failed to get DHCPv4 6rd option: %m");

        if (DEBUG_LOGGING)
                log_link_debug(uplink, "DHCPv4: 6rd option is acquired: IPv4_masklen=%u, 6rd_prefix=%s, br_address="IPV4_ADDRESS_FMT_STR,
                               ipv4masklen,
                               IN6_ADDR_PREFIX_TO_STRING(&sixrd_prefix, sixrd_prefixlen),
                               IPV4_ADDRESS_FMT_VAL(*br_addresses));

        /* Calculate PD prefix */
        dhcp4_calculate_pd_prefix(&ipv4address, ipv4masklen, &sixrd_prefix, sixrd_prefixlen, &pd_prefix, &pd_prefixlen);

        /* Register and log PD prefix */
        r = dhcp_pd_prefix_add(uplink, &pd_prefix, pd_prefixlen);
        if (r < 0)
                return r;

        /* Request unreachable route */
        r = dhcp4_request_unreachable_route(uplink, &pd_prefix, pd_prefixlen, lifetime_usec, &server_address);
        if (r < 0)
                return r;

        /* Generate 6rd SIT tunnel device name. */
        r = dhcp4_pd_create_6rd_tunnel_name(uplink, &tunnel_name);
        if (r < 0)
                return r;

        /* Remove old tunnel device if exists. */
        if (!streq_ptr(uplink->dhcp4_6rd_tunnel_name, tunnel_name)) {
                Link *old_tunnel;

                if (uplink->dhcp4_6rd_tunnel_name &&
                    link_get_by_name(uplink->manager, uplink->dhcp4_6rd_tunnel_name, &old_tunnel) >= 0)
                        (void) link_remove(old_tunnel);

                free_and_replace(uplink->dhcp4_6rd_tunnel_name, tunnel_name);
        }

        /* Create 6rd SIT tunnel device if it does not exist yet. */
        if (link_get_by_name(uplink->manager, uplink->dhcp4_6rd_tunnel_name, NULL) < 0) {
                r = dhcp4_pd_create_6rd_tunnel(uplink, dhcp4_pd_6rd_tunnel_create_handler);
                if (r < 0)
                        return r;
        }

        /* Then, assign subnet prefixes to downstream interfaces. */
        HASHMAP_FOREACH(link, uplink->manager->links_by_index) {
                if (!dhcp_pd_is_uplink(link, uplink, /* accept_auto = */ true))
                        continue;

                r = dhcp4_pd_assign_subnet_prefix(link, uplink);
                if (r < 0) {
                        /* When failed on the upstream interface (i.e., the case link == uplink),
                         * immediately abort the assignment of the prefixes. As, the all assigned
                         * prefixes will be dropped soon in link_enter_failed(), and it is meaningless
                         * to continue the assignment. */
                        if (link == uplink)
                                return r;

                        link_enter_failed(link);
                }
        }

        return 0;
}

static int dhcp6_pd_assign_subnet_prefixes(Link *link, Link *uplink) {
        int r;

        assert(link);
        assert(uplink);
        assert(uplink->dhcp6_lease);

        r = dhcp_pd_prepare(link);
        if (r <= 0)
                return r;

        FOREACH_DHCP6_PD_PREFIX(uplink->dhcp6_lease) {
                usec_t lifetime_preferred_usec, lifetime_valid_usec;
                struct in6_addr pd_prefix;
                uint8_t pd_prefix_len;

                r = sd_dhcp6_lease_get_pd_prefix(uplink->dhcp6_lease, &pd_prefix, &pd_prefix_len);
                if (r < 0)
                        return r;

                if (pd_prefix_len > 64)
                        continue;

                /* Mask prefix for safety. */
                r = in6_addr_mask(&pd_prefix, pd_prefix_len);
                if (r < 0)
                        return r;

                r = sd_dhcp6_lease_get_pd_lifetime_timestamp(uplink->dhcp6_lease, CLOCK_BOOTTIME,
                                                             &lifetime_preferred_usec, &lifetime_valid_usec);
                if (r < 0)
                        return r;

                r = dhcp_pd_assign_subnet_prefix(link, &pd_prefix, pd_prefix_len,
                                                 lifetime_preferred_usec, lifetime_valid_usec,
                                                 /* is_uplink = */ link == uplink);
                if (r < 0)
                        return r;
        }

        return dhcp_pd_finalize(link);
}

int dhcp6_pd_prefix_acquired(Link *uplink) {
        union in_addr_union server_address;
        Link *link;
        int r;

        assert(uplink);
        assert(uplink->dhcp6_lease);

        r = sd_dhcp6_lease_get_server_address(uplink->dhcp6_lease, &server_address.in6);
        if (r < 0)
                return log_link_warning_errno(uplink, r, "Failed to get server address of DHCPv6 lease: %m");

        /* First, logs acquired prefixes and request unreachable routes. */
        FOREACH_DHCP6_PD_PREFIX(uplink->dhcp6_lease) {
                usec_t lifetime_valid_usec;
                struct in6_addr pd_prefix;
                uint8_t pd_prefix_len;

                r = sd_dhcp6_lease_get_pd_prefix(uplink->dhcp6_lease, &pd_prefix, &pd_prefix_len);
                if (r < 0)
                        return r;

                /* Mask prefix for safety. */
                r = in6_addr_mask(&pd_prefix, pd_prefix_len);
                if (r < 0)
                        return log_link_error_errno(uplink, r, "Failed to mask DHCPv6 delegated prefix: %m");

                r = dhcp_pd_prefix_add(uplink, &pd_prefix, pd_prefix_len);
                if (r < 0)
                        return r;

                r = sd_dhcp6_lease_get_pd_lifetime_timestamp(uplink->dhcp6_lease, CLOCK_BOOTTIME,
                                                             NULL, &lifetime_valid_usec);
                if (r < 0)
                        return r;

                r = dhcp6_request_unreachable_route(uplink, &pd_prefix, pd_prefix_len,
                                                    lifetime_valid_usec, &server_address);
                if (r < 0)
                        return r;
        }

        /* Then, assign subnet prefixes. */
        HASHMAP_FOREACH(link, uplink->manager->links_by_index) {
                if (!dhcp_pd_is_uplink(link, uplink, /* accept_auto = */ true))
                        continue;

                r = dhcp6_pd_assign_subnet_prefixes(link, uplink);
                if (r < 0) {
                        /* When failed on the upstream interface (i.e., the case link == uplink),
                         * immediately abort the assignment of the prefixes. As, the all assigned
                         * prefixes will be dropped soon in link_enter_failed(), and it is meaningless
                         * to continue the assignment. */
                        if (link == uplink)
                                return r;

                        link_enter_failed(link);
                }
        }

        return 0;
}

static bool dhcp4_pd_uplink_is_ready(Link *link) {
        assert(link);

        if (!link->network)
                return false;

        if (!link->network->dhcp_use_6rd)
                return false;

        if (!IN_SET(link->state, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED))
                return false;

        if (!link->dhcp_client)
                return false;

        if (sd_dhcp_client_is_running(link->dhcp_client) <= 0)
                return false;

        return sd_dhcp_lease_has_6rd(link->dhcp_lease);
}

static bool dhcp6_pd_uplink_is_ready(Link *link) {
        assert(link);

        if (!link->network)
                return false;

        if (!link->network->dhcp6_use_pd_prefix)
                return false;

        if (!IN_SET(link->state, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED))
                return false;

        if (!link->dhcp6_client)
                return false;

        if (sd_dhcp6_client_is_running(link->dhcp6_client) <= 0)
                return false;

        return sd_dhcp6_lease_has_pd_prefix(link->dhcp6_lease);
}

int dhcp_pd_find_uplink(Link *link, Link **ret) {
        Link *uplink = NULL;
        int r = 0;

        assert(link);
        assert(link->manager);
        assert(link_dhcp_pd_is_enabled(link));
        assert(ret);

        if (link->network->dhcp_pd_uplink_name)
                r = link_get_by_name(link->manager, link->network->dhcp_pd_uplink_name, &uplink);
        else if (link->network->dhcp_pd_uplink_index > 0)
                r = link_get_by_index(link->manager, link->network->dhcp_pd_uplink_index, &uplink);
        else if (link->network->dhcp_pd_uplink_index == UPLINK_INDEX_SELF)
                uplink = link;
        if (r < 0)
                return r;

        if (uplink) {
                if (dhcp4_pd_uplink_is_ready(uplink)) {
                        *ret = uplink;
                        return AF_INET;
                }

                if (dhcp6_pd_uplink_is_ready(uplink)) {
                        *ret = uplink;
                        return AF_INET6;
                }

                return -EBUSY;
        }

        HASHMAP_FOREACH(uplink, link->manager->links_by_index) {
                /* Assume that there exists at most one link which acquired delegated prefixes. */
                if (dhcp4_pd_uplink_is_ready(uplink)) {
                        *ret = uplink;
                        return AF_INET;
                }

                if (dhcp6_pd_uplink_is_ready(uplink)) {
                        *ret = uplink;
                        return AF_INET6;
                }
        }

        return -ENODEV;
}

int dhcp_request_prefix_delegation(Link *link) {
        Link *uplink;
        int r;

        assert(link);

        if (!link_dhcp_pd_is_enabled(link))
                return 0;

        r = dhcp_pd_find_uplink(link, &uplink);
        if (r < 0)
                return 0;

        log_link_debug(link, "Requesting subnets of delegated prefixes acquired by DHCPv%c client on %s",
                       r == AF_INET ? '4' : '6', uplink->ifname);

        return r == AF_INET ?
                dhcp4_pd_assign_subnet_prefix(link, uplink) :
                dhcp6_pd_assign_subnet_prefixes(link, uplink);
}

int config_parse_dhcp_pd_subnet_id(
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

        int64_t *p = ASSERT_PTR(data);
        uint64_t t;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue) || streq(rvalue, "auto")) {
                *p = -1;
                return 0;
        }

        r = safe_atoux64(rvalue, &t);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse %s=, ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }
        if (t > INT64_MAX) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid subnet id '%s', ignoring assignment.",
                           rvalue);
                return 0;
        }

        *p = (int64_t) t;

        return 0;
}
