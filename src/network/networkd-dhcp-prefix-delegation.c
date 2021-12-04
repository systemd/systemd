/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-dhcp6-client.h"

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
#include "parse-util.h"
#include "string-util.h"
#include "strv.h"

bool link_dhcp6_pd_is_enabled(Link *link) {
        assert(link);

        if (!link->network)
                return false;

        return link->network->dhcp6_pd;
}

bool dhcp6_pd_is_uplink(Link *link, Link *target, bool accept_auto) {
        assert(link);
        assert(target);

        if (!link_dhcp6_pd_is_enabled(link))
                return false;

        if (link->network->dhcp6_pd_uplink_name)
                return streq_ptr(target->ifname, link->network->dhcp6_pd_uplink_name) ||
                        strv_contains(target->alternative_names, link->network->dhcp6_pd_uplink_name);

        if (link->network->dhcp6_pd_uplink_index > 0)
                return target->ifindex == link->network->dhcp6_pd_uplink_index;

        if (link->network->dhcp6_pd_uplink_index == UPLINK_INDEX_SELF)
                return link == target;

        assert(link->network->dhcp6_pd_uplink_index == UPLINK_INDEX_AUTO);
        return accept_auto;
}

bool dhcp6_lease_has_pd_prefix(sd_dhcp6_lease *lease) {
        uint32_t lifetime_preferred_sec, lifetime_valid_sec;
        struct in6_addr pd_prefix;
        uint8_t pd_prefix_len;

        if (!lease)
                return false;

        sd_dhcp6_lease_reset_pd_prefix_iter(lease);

        return sd_dhcp6_lease_get_pd(lease, &pd_prefix, &pd_prefix_len, &lifetime_preferred_sec, &lifetime_valid_sec) >= 0;
}

static void link_remove_dhcp6_pd_prefix(Link *link, const struct in6_addr *prefix) {
        void *key;

        assert(link);
        assert(link->manager);
        assert(prefix);

        if (hashmap_get(link->manager->links_by_dhcp6_pd_prefix, prefix) != link)
                return;

        hashmap_remove2(link->manager->links_by_dhcp6_pd_prefix, prefix, &key);
        free(key);
}

static int link_add_dhcp6_pd_prefix(Link *link, const struct in6_addr *prefix) {
        _cleanup_free_ struct in6_addr *copy = NULL;
        int r;

        assert(link);
        assert(prefix);

        copy = newdup(struct in6_addr, prefix, 1);
        if (!copy)
                return -ENOMEM;

        r = hashmap_ensure_put(&link->manager->links_by_dhcp6_pd_prefix, &in6_addr_hash_ops_free, copy, link);
        if (r < 0)
                return r;
        if (r > 0)
                TAKE_PTR(copy);

        return 0;
}

static int link_get_by_dhcp6_pd_prefix(Manager *manager, const struct in6_addr *prefix, Link **ret) {
        Link *link;

        assert(manager);
        assert(prefix);

        link = hashmap_get(manager->links_by_dhcp6_pd_prefix, prefix);
        if (!link)
                return -ENODEV;

        if (ret)
                *ret = link;
        return 0;
}

static int dhcp6_pd_get_assigned_prefix(Link *link, const struct in6_addr *pd_prefix, uint8_t pd_prefix_len, struct in6_addr *ret) {
        assert(link);
        assert(pd_prefix);

        if (!link_dhcp6_pd_is_enabled(link))
                return -ENOENT;

        if (link->network->dhcp6_pd_assign) {
                Address *address;

                SET_FOREACH(address, link->addresses) {
                        if (address->source != NETWORK_CONFIG_SOURCE_DHCP6PD)
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

                SET_FOREACH(route, link->routes) {
                        if (route->source != NETWORK_CONFIG_SOURCE_DHCP6PD)
                                continue;
                        assert(route->family == AF_INET6);

                        if (in6_addr_prefix_covers(pd_prefix, pd_prefix_len, &route->dst.in6) > 0) {
                                if (ret)
                                        *ret = route->dst.in6;
                                return 0;
                        }
                }
        }

        return -ENOENT;
}

int dhcp6_pd_remove(Link *link, bool only_marked) {
        int k, r = 0;

        assert(link);
        assert(link->manager);

        if (!link_dhcp6_pd_is_enabled(link))
                return 0;

        if (!only_marked)
                link->dhcp6_pd_configured = false;

        if (!link->network->dhcp6_pd_assign) {
                Route *route;

                SET_FOREACH(route, link->routes) {
                        if (route->source != NETWORK_CONFIG_SOURCE_DHCP6PD)
                                continue;
                        if (only_marked && !route_is_marked(route))
                                continue;

                        if (link->radv)
                                (void) sd_radv_remove_prefix(link->radv, &route->dst.in6, 64);

                        link_remove_dhcp6_pd_prefix(link, &route->dst.in6);

                        k = route_remove(route);
                        if (k < 0)
                                r = k;

                        route_cancel_request(route, link);
                }
        } else {
                Address *address;

                SET_FOREACH(address, link->addresses) {
                        struct in6_addr prefix;

                        if (address->source != NETWORK_CONFIG_SOURCE_DHCP6PD)
                                continue;
                        if (only_marked && !address_is_marked(address))
                                continue;

                        prefix = address->in_addr.in6;
                        in6_addr_mask(&prefix, 64);

                        if (link->radv)
                                (void) sd_radv_remove_prefix(link->radv, &prefix, 64);

                        link_remove_dhcp6_pd_prefix(link, &prefix);

                        k = address_remove(address);
                        if (k < 0)
                                r = k;

                        address_cancel_request(address);
                }
        }

        return r;
}

static int dhcp6_pd_check_ready(Link *link);

static int dhcp6_pd_address_ready_callback(Address *address) {
        Address *a;

        assert(address);
        assert(address->link);

        SET_FOREACH(a, address->link->addresses)
                if (a->source == NETWORK_CONFIG_SOURCE_DHCP6PD)
                        a->callback = NULL;

        return dhcp6_pd_check_ready(address->link);
}

static int dhcp6_pd_check_ready(Link *link) {
        int r;

        assert(link);
        assert(link->network);

        if (link->dhcp6_pd_messages > 0) {
                log_link_debug(link, "%s(): DHCPv6PD addresses and routes are not set.", __func__);
                return 0;
        }

        if (link->network->dhcp6_pd_assign) {
                bool has_ready = false;
                Address *address;

                SET_FOREACH(address, link->addresses) {
                        if (address->source != NETWORK_CONFIG_SOURCE_DHCP6PD)
                                continue;
                        if (address_is_ready(address)) {
                                has_ready = true;
                                break;
                        }
                }

                if (!has_ready) {
                        SET_FOREACH(address, link->addresses)
                                if (address->source == NETWORK_CONFIG_SOURCE_DHCP6PD)
                                        address->callback = dhcp6_pd_address_ready_callback;

                        log_link_debug(link, "%s(): no DHCPv6PD address is ready.", __func__);
                        return 0;
                }
        }

        link->dhcp6_pd_configured = true;

        log_link_debug(link, "DHCPv6 PD addresses and routes set.");

        r = dhcp6_pd_remove(link, /* only_marked = */ true);
        if (r < 0)
                return r;

        link_check_ready(link);
        return 1;
}

static int dhcp6_pd_route_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);
        assert(link->dhcp6_pd_messages > 0);

        link->dhcp6_pd_messages--;

        r = route_configure_handler_internal(rtnl, m, link, "Failed to add DHCPv6 Prefix Delegation route");
        if (r <= 0)
                return r;

        r = dhcp6_pd_check_ready(link);
        if (r < 0)
                link_enter_failed(link);

        return 1;
}

static int dhcp6_pd_request_route(Link *link, const struct in6_addr *prefix, uint8_t prefixlen, usec_t lifetime_usec) {
        _cleanup_(route_freep) Route *route = NULL;
        Route *existing;
        int r;

        assert(link);
        assert(link->network);
        assert(prefix);

        if (link->network->dhcp6_pd_assign)
                return 0;

        r = route_new(&route);
        if (r < 0)
                return r;

        route->source = NETWORK_CONFIG_SOURCE_DHCP6PD;
        route->family = AF_INET6;
        route->dst.in6 = *prefix;
        route->dst_prefixlen = prefixlen;
        route->protocol = RTPROT_DHCP;
        route->priority = link->network->dhcp6_pd_route_metric;
        route->lifetime_usec = lifetime_usec;

        if (route_get(NULL, link, route, &existing) < 0)
                link->dhcp6_pd_configured = false;
        else
                route_unmark(existing);

        r = link_request_route(link, TAKE_PTR(route), true, &link->dhcp6_pd_messages,
                               dhcp6_pd_route_handler, NULL);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to request DHCPv6 prefix route: %m");

        return 0;
}

static int dhcp6_pd_address_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);
        assert(link->dhcp6_pd_messages > 0);

        link->dhcp6_pd_messages--;

        r = address_configure_handler_internal(rtnl, m, link, "Could not set DHCPv6 delegated prefix address");
        if (r <= 0)
                return r;

        r = dhcp6_pd_check_ready(link);
        if (r < 0)
                link_enter_failed(link);

        return 1;
}

static void log_dhcp6_pd_address(Link *link, const Address *address) {
        _cleanup_free_ char *buffer = NULL;
        int log_level;

        assert(address);
        assert(address->family == AF_INET6);

        log_level = address_get(link, address, NULL) >= 0 ? LOG_DEBUG : LOG_INFO;

        if (log_level < log_get_max_level())
                return;

        (void) in6_addr_prefix_to_string(&address->in_addr.in6, address->prefixlen, &buffer);

        log_link_full(link, log_level, "DHCPv6-PD address %s (valid %s, preferred %s)",
                      strna(buffer),
                      FORMAT_LIFETIME(address->lifetime_valid_usec),
                      FORMAT_LIFETIME(address->lifetime_preferred_usec));
}

static int dhcp6_pd_request_address(
                Link *link,
                const struct in6_addr *prefix,
                uint8_t prefixlen,
                usec_t lifetime_preferred_usec,
                usec_t lifetime_valid_usec) {

        _cleanup_set_free_ Set *addresses = NULL;
        struct in6_addr *a;
        int r;

        assert(link);
        assert(link->network);
        assert(prefix);

        if (!link->network->dhcp6_pd_assign)
                return 0;

        r = dhcp6_pd_generate_addresses(link, prefix, prefixlen, &addresses);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to generate addresses for acquired DHCPv6 delegated prefix: %m");

        SET_FOREACH(a, addresses) {
                _cleanup_(address_freep) Address *address = NULL;
                Address *existing;

                r = address_new(&address);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to allocate address for DHCPv6 delegated prefix: %m");

                address->source = NETWORK_CONFIG_SOURCE_DHCP6PD;
                address->family = AF_INET6;
                address->in_addr.in6 = *a;
                address->prefixlen = prefixlen;
                address->lifetime_preferred_usec = lifetime_preferred_usec;
                address->lifetime_valid_usec = lifetime_valid_usec;
                if (prefixlen == 64)
                        SET_FLAG(address->flags, IFA_F_MANAGETEMPADDR, link->network->dhcp6_pd_manage_temporary_address);
                address->route_metric = link->network->dhcp6_pd_route_metric;

                log_dhcp6_pd_address(link, address);

                if (address_get(link, address, &existing) < 0)
                        link->dhcp6_pd_configured = false;
                else
                        address_unmark(existing);

                r = link_request_address(link, TAKE_PTR(address), true, &link->dhcp6_pd_messages,
                                         dhcp6_pd_address_handler, NULL);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to request DHCPv6 delegated prefix address: %m");
        }

        return 0;
}

static int dhcp6_pd_calculate_prefix(
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

static int dhcp6_pd_get_preferred_prefix(
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

        if (link->network->dhcp6_pd_subnet_id >= 0) {
                /* If the link has a preference for a particular subnet id try to allocate that */

                r = dhcp6_pd_calculate_prefix(pd_prefix, pd_prefix_len, link->network->dhcp6_pd_subnet_id, &prefix);
                if (r < 0)
                        return log_link_warning_errno(link, r,
                                                      "subnet id %" PRIu64 " is out of range. Only have %" PRIu64 " subnets.",
                                                      link->network->dhcp6_pd_subnet_id, UINT64_C(1) << (64 - pd_prefix_len));

                if (link_get_by_dhcp6_pd_prefix(link->manager, &prefix, &assigned_link) >= 0 &&
                    assigned_link != link) {
                        _cleanup_free_ char *assigned_buf = NULL;

                        (void) in6_addr_to_string(&prefix, &assigned_buf);
                        return log_link_warning_errno(link, SYNTHETIC_ERRNO(EAGAIN),
                                                      "The requested prefix %s is already assigned to another link.",
                                                      strna(assigned_buf));
                }

                *ret = prefix;
                return 0;
        }

        for (uint64_t n = 0; ; n++) {
                /* If we do not have an allocation preference just iterate
                 * through the address space and return the first free prefix. */

                r = dhcp6_pd_calculate_prefix(pd_prefix, pd_prefix_len, n, &prefix);
                if (r < 0)
                        return log_link_warning_errno(link, r,
                                                      "Couldn't find a suitable prefix. Ran out of address space.");

                /* Do not use explicitly requested subnet IDs. Note that the corresponding link may not
                 * appear yet. So, we need to check the ID is not used in any .network files. */
                if (set_contains(link->manager->dhcp6_pd_subnet_ids, &n))
                        continue;

                /* Check that the prefix is not assigned to another link. */
                if (link_get_by_dhcp6_pd_prefix(link->manager, &prefix, &assigned_link) < 0 ||
                    assigned_link == link) {
                        *ret = prefix;
                        return 0;
                }
        }
}

static int dhcp6_pd_assign_prefix(
                Link *link,
                const struct in6_addr *pd_prefix,
                uint8_t pd_prefix_len,
                usec_t lifetime_preferred_usec,
                usec_t lifetime_valid_usec) {

        _cleanup_free_ char *buf = NULL;
        struct in6_addr prefix;
        int r;

        assert(link);
        assert(link->network);
        assert(pd_prefix);

        if (dhcp6_pd_get_assigned_prefix(link, pd_prefix, pd_prefix_len, &prefix) < 0 &&
            dhcp6_pd_get_preferred_prefix(link, pd_prefix, pd_prefix_len, &prefix) < 0)
                return 0;

        (void) in6_addr_prefix_to_string(&prefix, 64, &buf);

        if (link_radv_enabled(link) && link->network->dhcp6_pd_announce) {
                r = radv_add_prefix(link, &prefix, 64, lifetime_preferred_usec, lifetime_valid_usec);
                if (r < 0)
                        return log_link_warning_errno(link, r,
                                                      "Failed to assign/update prefix %s to IPv6 Router Advertisement: %m",
                                                      strna(buf));
        }

        r = dhcp6_pd_request_route(link, &prefix, 64, lifetime_valid_usec);
        if (r < 0)
                return log_link_warning_errno(link, r,
                                              "Failed to assign/update route for prefix %s: %m",
                                              strna(buf));

        r = dhcp6_pd_request_address(link, &prefix, 64, lifetime_preferred_usec, lifetime_valid_usec);
        if (r < 0)
                return log_link_warning_errno(link, r,
                                              "Failed to assign/update address for prefix %s: %m",
                                              strna(buf));

        r = link_add_dhcp6_pd_prefix(link, &prefix);
        if (r < 0)
                return log_link_warning_errno(link, r,
                                              "Failed to save assigned prefix %s: %m",
                                              strna(buf));

        log_link_debug(link, "Assigned prefix %s", strna(buf));
        return 1;
}

static int dhcp6_pd_assign_prefix_on_uplink(
                Link *link,
                const struct in6_addr *pd_prefix,
                uint8_t pd_prefix_len,
                usec_t lifetime_preferred_usec,
                usec_t lifetime_valid_usec) {

        _cleanup_free_ char *buf = NULL;
        int r;

        assert(link);
        assert(link->network);
        assert(pd_prefix);

        (void) in6_addr_prefix_to_string(pd_prefix, pd_prefix_len, &buf);

        if (link->network->dhcp6_pd_announce)
                log_link_debug(link, "Ignoring Announce= setting on upstream interface.");

        r = dhcp6_pd_request_route(link, pd_prefix, pd_prefix_len, lifetime_valid_usec);
        if (r < 0)
                return log_link_warning_errno(link, r,
                                              "Failed to assign/update route for prefix %s: %m",
                                              strna(buf));

        r = dhcp6_pd_request_address(link, pd_prefix, pd_prefix_len, lifetime_preferred_usec, lifetime_valid_usec);
        if (r < 0)
                return log_link_warning_errno(link, r,
                                              "Failed to assign/update address for prefix %s: %m",
                                              strna(buf));

        log_link_debug(link, "Assigned prefix %s", strna(buf));
        return 1;
}

static int dhcp6_pd_prepare(Link *link) {
        if (!IN_SET(link->state, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED))
                return 0;

        if (!link_dhcp6_pd_is_enabled(link))
                return 0;

        if (link_radv_enabled(link) && link->network->dhcp6_pd_announce && !link->radv)
                return 0;

        link_mark_addresses(link, NETWORK_CONFIG_SOURCE_DHCP6PD, NULL);
        link_mark_routes(link, NETWORK_CONFIG_SOURCE_DHCP6PD, NULL);

        return 1;
}

static int dhcp6_pd_finalize(Link *link) {
        int r;

        if (!IN_SET(link->state, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED))
                return 0;

        if (link->dhcp6_pd_messages == 0) {
                link->dhcp6_pd_configured = false;

                r = dhcp6_pd_remove(link, /* only_marked = */ true);
                if (r < 0)
                        return r;
        }

        if (!link->dhcp6_pd_configured)
                link_set_state(link, LINK_STATE_CONFIGURING);

        link_check_ready(link);
        return 0;
}

void dhcp6_pd_prefix_lost(Link *dhcp6_link) {
        Route *route;
        Link *link;
        int r;

        assert(dhcp6_link);
        assert(dhcp6_link->manager);

        HASHMAP_FOREACH(link, dhcp6_link->manager->links_by_index) {
                if (!dhcp6_pd_is_uplink(link, dhcp6_link, /* accept_auto = */ true))
                        continue;

                r = dhcp6_pd_remove(link, /* only_marked = */ false);
                if (r < 0)
                        link_enter_failed(link);
        }

        SET_FOREACH(route, dhcp6_link->manager->routes) {
                if (route->source != NETWORK_CONFIG_SOURCE_DHCP6)
                        continue;
                if (route->family != AF_INET6)
                        continue;
                if (route->type != RTN_UNREACHABLE)
                        continue;
                if (!set_contains(dhcp6_link->dhcp6_pd_prefixes,
                                  &(struct in_addr_prefix) {
                                          .family = AF_INET6,
                                          .prefixlen = route->dst_prefixlen,
                                          .address = route->dst }))
                        continue;

                (void) route_remove(route);

                route_cancel_request(route, dhcp6_link);
        }

        set_clear(dhcp6_link->dhcp6_pd_prefixes);
}

static int dhcp6_route_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);
        assert(link->dhcp6_messages > 0);

        link->dhcp6_messages--;

        r = route_configure_handler_internal(rtnl, m, link, "Failed to set unreachable route for DHCPv6 delegated subnet");
        if (r <= 0)
                return r;

        r = dhcp6_check_ready(link);
        if (r < 0)
                link_enter_failed(link);

        return 1;
}

static int dhcp6_request_unreachable_route(Link *link, const struct in6_addr *addr, uint8_t prefixlen, usec_t lifetime_usec) {
        _cleanup_(route_freep) Route *route = NULL;
        Route *existing;
        int r;

        assert(link);
        assert(addr);

        if (prefixlen >= 64) {
                _cleanup_free_ char *buf = NULL;

                (void) in6_addr_prefix_to_string(addr, prefixlen, &buf);
                log_link_debug(link, "Not adding a blocking route for DHCPv6 delegated prefix %s since the prefix has length >= 64.",
                               strna(buf));
                return 0;
        }

        r = route_new(&route);
        if (r < 0)
                return log_oom();

        route->source = NETWORK_CONFIG_SOURCE_DHCP6;
        route->family = AF_INET6;
        route->dst.in6 = *addr;
        route->dst_prefixlen = prefixlen;
        route->table = link_get_dhcp6_route_table(link);
        route->type = RTN_UNREACHABLE;
        route->protocol = RTPROT_DHCP;
        route->priority = DHCP_ROUTE_METRIC;
        route->lifetime_usec = lifetime_usec;

        if (route_get(link->manager, NULL, route, &existing) < 0)
                link->dhcp6_configured = false;
        else
                route_unmark(existing);

        r = link_request_route(link, TAKE_PTR(route), true, &link->dhcp6_messages,
                               dhcp6_route_handler, NULL);
        if (r < 0) {
                _cleanup_free_ char *buf = NULL;

                (void) in6_addr_prefix_to_string(addr, prefixlen, &buf);
                return log_link_error_errno(link, r, "Failed to request unreachable route for DHCPv6 delegated subnet %s: %m",
                                            strna(buf));
        }

        return 0;
}

static int dhcp6_pd_prefix_add(Link *link, const struct in6_addr *prefix, uint8_t prefixlen) {
        _cleanup_free_ char *buf = NULL;
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

        (void) in6_addr_prefix_to_string(prefix, prefixlen, &buf);

        log_link_full(link,
                      set_contains(link->dhcp6_pd_prefixes, p) ? LOG_DEBUG :
                      prefixlen > 64 || prefixlen < 48 ? LOG_WARNING : LOG_INFO,
                      "DHCPv6: received PD Prefix %s%s",
                      strna(buf),
                      prefixlen > 64 ? " with prefix length > 64, ignoring." :
                      prefixlen < 48 ? " with prefix length < 48, looks unusual.": "");

        /* Store PD prefix even if prefixlen > 64, not to make logged at warning level so frequently. */
        r = set_ensure_consume(&link->dhcp6_pd_prefixes, &in_addr_prefix_hash_ops_free, p);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to store DHCPv6 PD prefix %s: %m", strna(buf));

        return 0;
}

static int dhcp6_pd_assign_prefixes(Link *link, Link *uplink) {
        usec_t timestamp_usec;
        int r;

        assert(link);
        assert(uplink);
        assert(uplink->dhcp6_lease);

        r = dhcp6_pd_prepare(link);
        if (r <= 0)
                return r;

        r = sd_dhcp6_lease_get_timestamp(uplink->dhcp6_lease, clock_boottime_or_monotonic(), &timestamp_usec);
        if (r < 0)
                return r;

        for (sd_dhcp6_lease_reset_pd_prefix_iter(uplink->dhcp6_lease);;) {
                uint32_t lifetime_preferred_sec, lifetime_valid_sec;
                usec_t lifetime_preferred_usec, lifetime_valid_usec;
                struct in6_addr pd_prefix;
                uint8_t pd_prefix_len;

                r = sd_dhcp6_lease_get_pd(uplink->dhcp6_lease, &pd_prefix, &pd_prefix_len,
                                          &lifetime_preferred_sec, &lifetime_valid_sec);
                if (r < 0)
                        break;

                if (pd_prefix_len > 64)
                        continue;

                /* Mask prefix for safety. */
                r = in6_addr_mask(&pd_prefix, pd_prefix_len);
                if (r < 0)
                        return r;

                lifetime_preferred_usec = usec_add(lifetime_preferred_sec * USEC_PER_SEC, timestamp_usec);
                lifetime_valid_usec = usec_add(lifetime_valid_sec * USEC_PER_SEC, timestamp_usec);

                if (link == uplink)
                        r = dhcp6_pd_assign_prefix_on_uplink(link, &pd_prefix, pd_prefix_len, lifetime_preferred_usec, lifetime_valid_usec);
                else
                        r = dhcp6_pd_assign_prefix(link, &pd_prefix, pd_prefix_len, lifetime_preferred_usec, lifetime_valid_usec);
                if (r < 0)
                        return r;
        }

        return dhcp6_pd_finalize(link);
}

int dhcp6_pd_prefix_acquired(Link *dhcp6_link) {
        usec_t timestamp_usec;
        Link *link;
        int r;

        assert(dhcp6_link);
        assert(dhcp6_link->dhcp6_lease);

        r = sd_dhcp6_lease_get_timestamp(dhcp6_link->dhcp6_lease, clock_boottime_or_monotonic(), &timestamp_usec);
        if (r < 0)
                return log_link_warning_errno(dhcp6_link, r, "Failed to get timestamp of DHCPv6 lease: %m");

        /* First, logs acquired prefixes and request unreachable routes. */
        for (sd_dhcp6_lease_reset_pd_prefix_iter(dhcp6_link->dhcp6_lease);;) {
                uint32_t lifetime_preferred_sec, lifetime_valid_sec;
                usec_t lifetime_valid_usec;
                struct in6_addr pd_prefix;
                uint8_t pd_prefix_len;

                r = sd_dhcp6_lease_get_pd(dhcp6_link->dhcp6_lease, &pd_prefix, &pd_prefix_len,
                                          &lifetime_preferred_sec, &lifetime_valid_sec);
                if (r < 0)
                        break;

                /* Mask prefix for safety. */
                r = in6_addr_mask(&pd_prefix, pd_prefix_len);
                if (r < 0)
                        return log_link_error_errno(dhcp6_link, r, "Failed to mask DHCPv6 PD prefix: %m");

                lifetime_valid_usec = usec_add(lifetime_valid_sec * USEC_PER_SEC, timestamp_usec);

                r = dhcp6_pd_prefix_add(dhcp6_link, &pd_prefix, pd_prefix_len);
                if (r < 0)
                        return r;

                r = dhcp6_request_unreachable_route(dhcp6_link, &pd_prefix, pd_prefix_len, lifetime_valid_usec);
                if (r < 0)
                        return r;
        }

        /* Then, assign subnet prefixes. */
        HASHMAP_FOREACH(link, dhcp6_link->manager->links_by_index) {
                if (!dhcp6_pd_is_uplink(link, dhcp6_link, /* accept_auto = */ true))
                        continue;

                r = dhcp6_pd_assign_prefixes(link, dhcp6_link);
                if (r < 0) {
                        /* When failed on the upstream interface (i.e., the case link == dhcp6_link),
                         * immediately abort the assignment of the prefixes. As, the all assigned
                         * prefixes will be dropped soon in link_enter_failed(), and it is meaningless
                         * to continue the assignment. */
                        if (link == dhcp6_link)
                                return r;

                        link_enter_failed(link);
                }
        }

        return 0;
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

        if (!link->dhcp6_lease)
                return false;

        return dhcp6_lease_has_pd_prefix(link->dhcp6_lease);
}

int dhcp6_pd_find_uplink(Link *link, Link **ret) {
        Link *uplink = NULL;
        int r = 0;

        assert(link);
        assert(link->manager);
        assert(link_dhcp6_pd_is_enabled(link));
        assert(ret);

        if (link->network->dhcp6_pd_uplink_name)
                r = link_get_by_name(link->manager, link->network->dhcp6_pd_uplink_name, &uplink);
        else if (link->network->dhcp6_pd_uplink_index > 0)
                r = link_get_by_index(link->manager, link->network->dhcp6_pd_uplink_index, &uplink);
        else if (link->network->dhcp6_pd_uplink_index == UPLINK_INDEX_SELF)
                uplink = link;
        if (r < 0)
                return r;

        if (uplink) {
                if (!dhcp6_pd_uplink_is_ready(uplink))
                        return -EBUSY;

                *ret = uplink;
                return 0;
        }

        HASHMAP_FOREACH(uplink, link->manager->links_by_index) {
                if (!dhcp6_pd_uplink_is_ready(uplink))
                        continue;

                /* Assume that there exists at most one link which acquired delegated prefixes. */
                *ret = uplink;
                return 0;
        }

        return -ENODEV;
}

int dhcp6_request_prefix_delegation(Link *link) {
        Link *uplink;

        assert(link);

        if (!link_dhcp6_pd_is_enabled(link))
                return 0;

        if (dhcp6_pd_find_uplink(link, &uplink) < 0)
                return 0;

        log_link_debug(link, "Requesting subnets of delegated prefixes acquired by %s", uplink->ifname);
        return dhcp6_pd_assign_prefixes(link, uplink);
}

int config_parse_dhcp6_pd_subnet_id(
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

        int64_t *p = data;
        uint64_t t;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

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
