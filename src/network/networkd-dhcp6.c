/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2014 Intel Corporation. All rights reserved.
***/

#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_arp.h>

#include "sd-dhcp6-client.h"

#include "hashmap.h"
#include "hostname-setup.h"
#include "hostname-util.h"
#include "in-addr-prefix-util.h"
#include "missing_network.h"
#include "networkd-address-generation.h"
#include "networkd-address.h"
#include "networkd-dhcp6.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-queue.h"
#include "networkd-radv.h"
#include "networkd-route.h"
#include "siphash24.h"
#include "string-table.h"
#include "string-util.h"
#include "radv-internal.h"

bool link_dhcp6_with_address_enabled(Link *link) {
        if (!link_dhcp6_enabled(link))
                return false;

        return link->network->dhcp6_use_address;
}

bool link_dhcp6_pd_is_enabled(Link *link) {
        assert(link);

        if (!link->network)
                return false;

        return link->network->dhcp6_pd;
}

static bool dhcp6_lease_has_pd_prefix(sd_dhcp6_lease *lease) {
        uint32_t lifetime_preferred, lifetime_valid;
        struct in6_addr pd_prefix;
        uint8_t pd_prefix_len;

        if (!lease)
                return false;

        sd_dhcp6_lease_reset_pd_prefix_iter(lease);

        return sd_dhcp6_lease_get_pd(lease, &pd_prefix, &pd_prefix_len, &lifetime_preferred, &lifetime_valid) >= 0;
}

static int dhcp6_pd_get_link_by_prefix(Manager *manager, const struct in6_addr *prefix, Link **ret) {
        union in_addr_union u;
        Link *link;

        assert(manager);
        assert(prefix);

        u.in6 = *prefix;

        HASHMAP_FOREACH(link, manager->links_by_index) {
                if (!link_dhcp6_pd_is_enabled(link))
                        continue;

                if (link->network->dhcp6_pd_assign) {
                        Address *address;

                        SET_FOREACH(address, link->addresses) {
                                if (address->source != NETWORK_CONFIG_SOURCE_DHCP6PD)
                                        continue;
                                assert(address->family == AF_INET6);

                                if (in_addr_prefix_covers(AF_INET6, &u, 64, &address->in_addr) > 0) {
                                        if (ret)
                                                *ret = link;
                                        return 0;
                                }
                        }
                } else {
                        Route *route;

                        SET_FOREACH(route, link->routes) {
                                if (route->source != NETWORK_CONFIG_SOURCE_DHCP6PD)
                                        continue;
                                assert(route->family == AF_INET6);

                                if (in6_addr_equal(&route->dst.in6, prefix)) {
                                        if (ret)
                                                *ret = link;
                                        return 0;
                                }
                        }
                }
        }

        return -ENOENT;
}

static int dhcp6_pd_get_assigned_prefix(Link *link, const struct in6_addr *pd_prefix, uint8_t pd_prefix_len, struct in6_addr *ret) {
        union in_addr_union u;

        assert(link);
        assert(pd_prefix);

        if (!link_dhcp6_pd_is_enabled(link))
                return -ENOENT;

        u.in6 = *pd_prefix;

        if (link->network->dhcp6_pd_assign) {
                Address *address;

                SET_FOREACH(address, link->addresses) {
                        if (address->source != NETWORK_CONFIG_SOURCE_DHCP6PD)
                                continue;
                        assert(address->family == AF_INET6);

                        if (in_addr_prefix_covers(AF_INET6, &u, pd_prefix_len, &address->in_addr) <= 0)
                                continue;

                        if (ret) {
                                union in_addr_union prefix = address->in_addr;

                                in_addr_mask(AF_INET6, &prefix, 64);
                                *ret = prefix.in6;
                        }
                        return 0;
                }
        } else {
                Route *route;

                SET_FOREACH(route, link->routes) {
                        if (route->source != NETWORK_CONFIG_SOURCE_DHCP6PD)
                                continue;
                        assert(route->family == AF_INET6);

                        if (in_addr_prefix_covers(AF_INET6, &u, pd_prefix_len, &route->dst) > 0) {
                                if (ret)
                                        *ret = route->dst.in6;
                                return 0;
                        }
                }
        }

        return -ENOENT;
}

int dhcp6_pd_remove(Link *link, bool only_marked) {
        Address *address;
        Route *route;
        int k, r = 0;

        assert(link);
        assert(link->manager);

        if (!link_dhcp6_pd_is_enabled(link))
                return 0;

        if (!only_marked)
                link->dhcp6_pd_configured = false;

        SET_FOREACH(route, link->routes) {
                if (route->source != NETWORK_CONFIG_SOURCE_DHCP6PD)
                        continue;
                if (only_marked && !route_is_marked(route))
                        continue;

                if (link->radv)
                        (void) sd_radv_remove_prefix(link->radv, &route->dst.in6, 64);

                k = route_remove(route);
                if (k < 0)
                        r = k;

                route_cancel_request(route);
        }

        SET_FOREACH(address, link->addresses) {
                if (address->source != NETWORK_CONFIG_SOURCE_DHCP6PD)
                        continue;
                if (only_marked && !address_is_marked(address))
                        continue;

                if (link->radv) {
                        union in_addr_union prefix = address->in_addr;

                        in_addr_mask(AF_INET6, &prefix, 64);
                        (void) sd_radv_remove_prefix(link->radv, &prefix.in6, 64);
                }

                k = address_remove(address);
                if (k < 0)
                        r = k;

                address_cancel_request(address);
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

static int dhcp6_pd_request_route(Link *link, const struct in6_addr *prefix) {
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
        route->dst_prefixlen = 64;
        route->protocol = RTPROT_DHCP;
        route->priority = link->network->dhcp6_pd_route_metric;

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
                      FORMAT_LIFETIME(address->cinfo.ifa_valid),
                      FORMAT_LIFETIME(address->cinfo.ifa_prefered));
}

static int dhcp6_pd_request_address(
                Link *link,
                const struct in6_addr *prefix,
                uint32_t lifetime_preferred,
                uint32_t lifetime_valid) {

        _cleanup_set_free_ Set *addresses = NULL;
        struct in6_addr *a;
        int r;

        assert(link);
        assert(link->network);
        assert(prefix);

        if (!link->network->dhcp6_pd_assign)
                return 0;

        r = dhcp6_pd_generate_addresses(link, prefix, &addresses);
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
                address->prefixlen = 64;
                address->cinfo.ifa_prefered = lifetime_preferred;
                address->cinfo.ifa_valid = lifetime_valid;
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

static int dhcp6_pd_assign_prefix(
                Link *link,
                const struct in6_addr *prefix,
                uint32_t lifetime_preferred,
                uint32_t lifetime_valid) {

        int r;

        assert(link);
        assert(link->network);
        assert(prefix);

        if (link->network->dhcp6_pd_announce) {
                r = radv_add_prefix(link, prefix, 64, lifetime_preferred, lifetime_valid);
                if (r < 0)
                        return r;
        }

        r = dhcp6_pd_request_route(link, prefix);
        if (r < 0)
                return r;

        r = dhcp6_pd_request_address(link, prefix, lifetime_preferred, lifetime_valid);
        if (r < 0)
                return r;

        return 0;
}

static bool link_has_preferred_subnet_id(Link *link) {
        if (!link->network)
                return false;

        return link->network->dhcp6_pd_subnet_id >= 0;
}

static int dhcp6_get_preferred_delegated_prefix(
                Link *link,
                const struct in6_addr *pd_prefix,
                uint8_t pd_prefix_len,
                struct in6_addr *ret) {

        /* We start off with the original PD prefix we have been assigned and iterate from there */
        union in_addr_union prefix;
        uint64_t n_prefixes;
        Link *assigned_link;
        int r;

        assert(link);
        assert(link->manager);
        assert(pd_prefix);
        assert(pd_prefix_len <= 64);

        n_prefixes = UINT64_C(1) << (64 - pd_prefix_len);
        prefix.in6 = *pd_prefix;

        if (link_has_preferred_subnet_id(link)) {
                uint64_t subnet_id = link->network->dhcp6_pd_subnet_id;

                /* If the link has a preference for a particular subnet id try to allocate that */
                if (subnet_id >= n_prefixes)
                        return log_link_warning_errno(link, SYNTHETIC_ERRNO(ERANGE),
                                                      "subnet id %" PRIu64 " is out of range. Only have %" PRIu64 " subnets.",
                                                      subnet_id, n_prefixes);

                r = in_addr_prefix_nth(AF_INET6, &prefix, 64, subnet_id);
                if (r < 0)
                        return log_link_warning_errno(link, r,
                                                      "subnet id %" PRIu64 " is out of range. Only have %" PRIu64 " subnets.",
                                                      subnet_id, n_prefixes);

                /* Verify that the prefix we did calculate fits in the pd prefix.
                 * This should not fail as we checked the prefix size beforehand */
                assert_se(in_addr_prefix_covers(AF_INET6, (const union in_addr_union*) pd_prefix, pd_prefix_len, &prefix) > 0);

                if (dhcp6_pd_get_link_by_prefix(link->manager, &prefix.in6, &assigned_link) >= 0 &&
                    assigned_link != link) {
                        _cleanup_free_ char *assigned_buf = NULL;

                        (void) in6_addr_to_string(&prefix.in6, &assigned_buf);
                        return log_link_warning_errno(link, SYNTHETIC_ERRNO(EAGAIN),
                                                      "The requested prefix %s is already assigned to another link.",
                                                      strna(assigned_buf));
                }

                *ret = prefix.in6;
                return 0;
        }

        for (uint64_t n = 0; n < n_prefixes; n++) {
                /* If we do not have an allocation preference just iterate
                 * through the address space and return the first free prefix. */
                if (dhcp6_pd_get_link_by_prefix(link->manager, &prefix.in6, &assigned_link) < 0 ||
                    assigned_link == link) {
                        *ret = prefix.in6;
                        return 0;
                }

                r = in_addr_prefix_next(AF_INET6, &prefix, 64);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Can't allocate another prefix. Out of address space?: %m");
        }

        return log_link_warning_errno(link, SYNTHETIC_ERRNO(ERANGE), "Couldn't find a suitable prefix. Ran out of address space.");
}

static int dhcp6_pd_prefix_distribute(
                Link *dhcp6_link,
                const struct in6_addr *pd_prefix,
                uint8_t pd_prefix_len,
                uint32_t lifetime_preferred,
                uint32_t lifetime_valid,
                bool assign_preferred_subnet_id) {

        Link *link;
        int r;

        assert(dhcp6_link);
        assert(dhcp6_link->manager);
        assert(pd_prefix);
        assert(pd_prefix_len <= 64);

        HASHMAP_FOREACH(link, dhcp6_link->manager->links_by_index) {
                _cleanup_free_ char *buf = NULL;
                struct in6_addr assigned_prefix;

                if (!link_dhcp6_pd_is_enabled(link))
                        continue;

                if (link == dhcp6_link && !link->network->dhcp6_pd_assign)
                        continue;

                if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                        continue;

                if (assign_preferred_subnet_id != link_has_preferred_subnet_id(link))
                        continue;

                r = dhcp6_pd_get_assigned_prefix(link, pd_prefix, pd_prefix_len, &assigned_prefix);
                if (r < 0) {
                        r = dhcp6_get_preferred_delegated_prefix(link, pd_prefix, pd_prefix_len, &assigned_prefix);
                        if (r < 0)
                                continue;
                }

                (void) in6_addr_prefix_to_string(&assigned_prefix, 64, &buf);
                if (link == dhcp6_link) {
                        r = dhcp6_pd_request_address(link, &assigned_prefix, lifetime_preferred, lifetime_valid);
                        if (r < 0)
                                return log_link_warning_errno(link, r, "Failed to assign addresses in prefix %s: %m", strna(buf));

                        log_link_debug(link, "Assigned addresses in prefix %s: %m", strna(buf));
                } else {
                        r = dhcp6_pd_assign_prefix(link, &assigned_prefix, lifetime_preferred, lifetime_valid);
                        if (r < 0) {
                                log_link_error_errno(link, r, "Failed to assign/update prefix %s: %m", strna(buf));
                                link_enter_failed(link);
                        } else
                                log_link_debug(link, "Assigned prefix %s", strna(buf));
                }
        }

        return 0;
}

static int dhcp6_pd_prepare(Link *link) {
        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 0;

        if (!link_dhcp6_pd_is_enabled(link))
                return 0;

        link_mark_addresses(link, NETWORK_CONFIG_SOURCE_DHCP6PD, NULL);
        link_mark_routes(link, NETWORK_CONFIG_SOURCE_DHCP6PD, NULL);

        return 0;
}

static int dhcp6_pd_finalize(Link *link) {
        int r;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 0;

        if (!link_dhcp6_pd_is_enabled(link))
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

static void dhcp6_pd_prefix_lost(Link *dhcp6_link) {
        Link *link;
        int r;

        assert(dhcp6_link);
        assert(dhcp6_link->manager);

        HASHMAP_FOREACH(link, dhcp6_link->manager->links_by_index) {
                if (link == dhcp6_link)
                        continue;

                r = dhcp6_pd_remove(link, /* only_marked = */ false);
                if (r < 0)
                        link_enter_failed(link);
        }

        set_clear(dhcp6_link->dhcp6_pd_prefixes);
}

static int dhcp6_remove(Link *link, bool only_marked) {
        Address *address;
        Route *route;
        int k, r = 0;

        assert(link);

        if (!only_marked)
                link->dhcp6_configured = false;

        SET_FOREACH(route, link->routes) {
                if (route->source != NETWORK_CONFIG_SOURCE_DHCP6)
                        continue;
                if (only_marked && !route_is_marked(route))
                        continue;

                k = route_remove(route);
                if (k < 0)
                        r = k;

                route_cancel_request(route);
        }

        SET_FOREACH(address, link->addresses) {
                if (address->source != NETWORK_CONFIG_SOURCE_DHCP6)
                        continue;
                if (only_marked && !address_is_marked(address))
                        continue;

                k = address_remove(address);
                if (k < 0)
                        r = k;

                address_cancel_request(address);
        }

        return r;
}

static int dhcp6_check_ready(Link *link);

static int dhcp6_address_ready_callback(Address *address) {
        Address *a;

        assert(address);
        assert(address->link);

        SET_FOREACH(a, address->link->addresses)
                if (a->source == NETWORK_CONFIG_SOURCE_DHCP6)
                        a->callback = NULL;

        return dhcp6_check_ready(address->link);
}

static int dhcp6_check_ready(Link *link) {
        bool has_ready = false;
        Address *address;
        int r;

        assert(link);

        if (link->dhcp6_messages > 0) {
                log_link_debug(link, "%s(): DHCPv6 addresses and routes are not set.", __func__);
                return 0;
        }

        SET_FOREACH(address, link->addresses) {
                if (address->source != NETWORK_CONFIG_SOURCE_DHCP6)
                        continue;
                if (address_is_ready(address)) {
                        has_ready = true;
                        break;
                }
        }

        if (!has_ready) {
                SET_FOREACH(address, link->addresses)
                        if (address->source == NETWORK_CONFIG_SOURCE_DHCP6)
                                address->callback = dhcp6_address_ready_callback;

                log_link_debug(link, "%s(): no DHCPv6 address is ready.", __func__);
                return 0;
        }

        link->dhcp6_configured = true;
        log_link_debug(link, "DHCPv6 addresses and routes set.");

        r = dhcp6_remove(link, /* only_marked = */ true);
        if (r < 0)
                return r;

        link_check_ready(link);
        return 0;
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

static int dhcp6_request_unreachable_route(Link *link, const struct in6_addr *addr, uint8_t prefixlen) {
        _cleanup_(route_freep) Route *route = NULL;
        _cleanup_free_ char *buf = NULL;
        Route *existing;
        int r;

        assert(link);
        assert(addr);

        (void) in6_addr_prefix_to_string(addr, prefixlen, &buf);

        if (prefixlen == 64) {
                log_link_debug(link, "Not adding a blocking route for DHCPv6 delegated subnet %s since distributed prefix is 64",
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

        if (route_get(link->manager, NULL, route, &existing) < 0)
                link->dhcp6_configured = false;
        else
                route_unmark(existing);

        r = link_request_route(link, TAKE_PTR(route), true, &link->dhcp6_messages,
                               dhcp6_route_handler, NULL);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to request unreachable route for DHCPv6 delegated subnet %s: %m",
                                            strna(buf));

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

        return prefixlen <= 64;
}

static int dhcp6_pd_prefix_acquired(Link *dhcp6_link) {
        Link *link;
        int r;

        assert(dhcp6_link);
        assert(dhcp6_link->dhcp6_lease);

        HASHMAP_FOREACH(link, dhcp6_link->manager->links_by_index) {
                if (link == dhcp6_link)
                        continue;

                r = dhcp6_pd_prepare(link);
                if (r < 0)
                        link_enter_failed(link);
        }

        for (sd_dhcp6_lease_reset_pd_prefix_iter(dhcp6_link->dhcp6_lease);;) {
                uint32_t lifetime_preferred, lifetime_valid;
                struct in6_addr pd_prefix;
                union in_addr_union prefix;
                uint8_t pd_prefix_len;

                r = sd_dhcp6_lease_get_pd(dhcp6_link->dhcp6_lease, &pd_prefix, &pd_prefix_len,
                                          &lifetime_preferred, &lifetime_valid);
                if (r < 0)
                        break;

                r = dhcp6_pd_prefix_add(dhcp6_link, &pd_prefix, pd_prefix_len);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                r = dhcp6_request_unreachable_route(dhcp6_link, &pd_prefix, pd_prefix_len);
                if (r < 0)
                        return r;

                /* We are doing prefix allocation in two steps:
                 * 1. all those links that have a preferred subnet id will be assigned their subnet
                 * 2. all those links that remain will receive prefixes in sequential order. Prefixes
                 *    that were previously already allocated to another link will be skipped.
                 * The assignment has to be split in two phases since subnet id
                 * preferences should be honored. Meaning that any subnet id should be
                 * handed out to the requesting link and not to some link that didn't
                 * specify any preference. */

                assert(pd_prefix_len <= 64);

                prefix.in6 = pd_prefix;
                r = in_addr_mask(AF_INET6, &prefix, pd_prefix_len);
                if (r < 0)
                        return log_link_error_errno(dhcp6_link, r, "Failed to mask DHCPv6 PD prefix: %m");

                if (DEBUG_LOGGING) {
                        uint64_t n_prefixes = UINT64_C(1) << (64 - pd_prefix_len);
                        _cleanup_free_ char *buf = NULL;

                        (void) in6_addr_prefix_to_string(&prefix.in6, pd_prefix_len, &buf);
                        log_link_debug(dhcp6_link, "Assigning up to %" PRIu64 " prefixes from %s",
                                       n_prefixes, strna(buf));
                }

                r = dhcp6_pd_prefix_distribute(dhcp6_link,
                                               &prefix.in6,
                                               pd_prefix_len,
                                               lifetime_preferred,
                                               lifetime_valid,
                                               true);
                if (r < 0)
                        return r;

                r = dhcp6_pd_prefix_distribute(dhcp6_link,
                                               &prefix.in6,
                                               pd_prefix_len,
                                               lifetime_preferred,
                                               lifetime_valid,
                                               false);
                if (r < 0)
                        return r;
        }

        HASHMAP_FOREACH(link, dhcp6_link->manager->links_by_index) {
                if (link == dhcp6_link)
                        continue;

                r = dhcp6_pd_finalize(link);
                if (r < 0)
                        link_enter_failed(link);
        }

        return 0;
}

static int dhcp6_address_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);
        assert(link->dhcp6_messages > 0);

        link->dhcp6_messages--;

        r = address_configure_handler_internal(rtnl, m, link, "Could not set DHCPv6 address");
        if (r <= 0)
                return r;

        r = dhcp6_check_ready(link);
        if (r < 0)
                link_enter_failed(link);

        return 1;
}

static void log_dhcp6_address(Link *link, const Address *address) {
        _cleanup_free_ char *buffer = NULL;
        bool by_ndisc = false;
        Address *existing;
        int log_level;

        assert(link);
        assert(address);
        assert(address->family == AF_INET6);

        (void) in6_addr_to_string(&address->in_addr.in6, &buffer);

        if (address_get(link, address, &existing) < 0) {
                /* New address. */
                log_level = LOG_INFO;
                goto simple_log;
        } else
                log_level = LOG_DEBUG;

        if (address->prefixlen == existing->prefixlen)
                /* Currently, only conflict in prefix length is reported. */
                goto simple_log;

        if (existing->source == NETWORK_CONFIG_SOURCE_NDISC)
                by_ndisc = true;

        log_link_warning(link, "DHCPv6 address %s/%u (valid %s, preferred %s) conflicts the address %s/%u%s.",
                         strna(buffer), address->prefixlen,
                         FORMAT_LIFETIME(address->cinfo.ifa_valid),
                         FORMAT_LIFETIME(address->cinfo.ifa_prefered),
                         strna(buffer), existing->prefixlen,
                         by_ndisc ? " assigned by NDisc. Please try to use or update IPv6Token= setting "
                         "to change the address generated by NDISC, or disable UseAutonomousPrefix=" : "");
        return;

simple_log:
        log_link_full(link, log_level, "DHCPv6 address %s/%u (valid %s, preferred %s)",
                      strna(buffer), address->prefixlen,
                      FORMAT_LIFETIME(address->cinfo.ifa_valid),
                      FORMAT_LIFETIME(address->cinfo.ifa_prefered));
}

static int dhcp6_request_address(
                Link *link,
                const struct in6_addr *ip6_addr,
                uint32_t lifetime_preferred,
                uint32_t lifetime_valid) {

        _cleanup_(address_freep) Address *addr = NULL;
        Address *existing;
        int r;

        r = address_new(&addr);
        if (r < 0)
                return log_oom();

        addr->source = NETWORK_CONFIG_SOURCE_DHCP6;
        addr->family = AF_INET6;
        addr->in_addr.in6 = *ip6_addr;
        addr->flags = IFA_F_NOPREFIXROUTE;
        addr->prefixlen = 128;
        addr->cinfo.ifa_prefered = lifetime_preferred;
        addr->cinfo.ifa_valid = lifetime_valid;

        log_dhcp6_address(link, addr);

        if (address_get(link, addr, &existing) < 0)
                link->dhcp6_configured = false;
        else
                address_unmark(existing);

        r = link_request_address(link, TAKE_PTR(addr), true, &link->dhcp6_messages,
                                 dhcp6_address_handler, NULL);
        if (r < 0) {
                _cleanup_free_ char *buffer = NULL;

                (void) in6_addr_to_string(ip6_addr, &buffer);
                return log_link_error_errno(link, r, "Failed to request DHCPv6 address %s/128: %m", strna(buffer));
        }

        return 0;
}

static int dhcp6_address_acquired(Link *link) {
        int r;

        assert(link);
        assert(link->network);
        assert(link->dhcp6_lease);

        if (!link->network->dhcp6_use_address)
                return 0;

        for (sd_dhcp6_lease_reset_address_iter(link->dhcp6_lease);;) {
                uint32_t lifetime_preferred, lifetime_valid;
                struct in6_addr ip6_addr;

                r = sd_dhcp6_lease_get_address(link->dhcp6_lease, &ip6_addr, &lifetime_preferred, &lifetime_valid);
                if (r < 0)
                        break;

                r = dhcp6_request_address(link, &ip6_addr, lifetime_preferred, lifetime_valid);
                if (r < 0)
                        return r;
        }

        if (link->network->dhcp6_use_hostname) {
                const char *dhcpname = NULL;
                _cleanup_free_ char *hostname = NULL;

                (void) sd_dhcp6_lease_get_fqdn(link->dhcp6_lease, &dhcpname);

                if (dhcpname) {
                        r = shorten_overlong(dhcpname, &hostname);
                        if (r < 0)
                                log_link_warning_errno(link, r, "Unable to shorten overlong DHCP hostname '%s', ignoring: %m", dhcpname);
                        if (r == 1)
                                log_link_notice(link, "Overlong DHCP hostname received, shortened from '%s' to '%s'", dhcpname, hostname);
                }
                if (hostname) {
                        r = manager_set_hostname(link->manager, hostname);
                        if (r < 0)
                                log_link_error_errno(link, r, "Failed to set transient hostname to '%s': %m", hostname);
                }
        }

        return 0;
}

static int dhcp6_lease_ip_acquired(sd_dhcp6_client *client, Link *link) {
        _cleanup_(sd_dhcp6_lease_unrefp) sd_dhcp6_lease *lease_old = NULL;
        sd_dhcp6_lease *lease;
        int r;

        link_mark_addresses(link, NETWORK_CONFIG_SOURCE_DHCP6, NULL);
        link_mark_routes(link, NETWORK_CONFIG_SOURCE_DHCP6, NULL);

        r = sd_dhcp6_client_get_lease(client, &lease);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get DHCPv6 lease: %m");

        lease_old = TAKE_PTR(link->dhcp6_lease);
        link->dhcp6_lease = sd_dhcp6_lease_ref(lease);

        r = dhcp6_address_acquired(link);
        if (r < 0)
                return r;

        if (dhcp6_lease_has_pd_prefix(lease)) {
                r = dhcp6_pd_prefix_acquired(link);
                if (r < 0)
                        return r;
        } else if (dhcp6_lease_has_pd_prefix(lease_old))
                /* When we had PD prefixes but not now, we need to remove them. */
                dhcp6_pd_prefix_lost(link);

        if (link->dhcp6_messages == 0) {
                link->dhcp6_configured = true;

                r = dhcp6_remove(link, /* only_marked = */ true);
                if (r < 0)
                        return r;
        } else
                log_link_debug(link, "Setting DHCPv6 addresses and routes");

        if (!link->dhcp6_configured)
                link_set_state(link, LINK_STATE_CONFIGURING);

        link_check_ready(link);
        return 0;
}

static int dhcp6_lease_information_acquired(sd_dhcp6_client *client, Link *link) {
        return 0;
}

static int dhcp6_lease_lost(Link *link) {
        int r;

        assert(link);
        assert(link->manager);

        log_link_info(link, "DHCPv6 lease lost");

        if (dhcp6_lease_has_pd_prefix(link->dhcp6_lease))
                dhcp6_pd_prefix_lost(link);

        link->dhcp6_lease = sd_dhcp6_lease_unref(link->dhcp6_lease);

        r = dhcp6_remove(link, /* only_marked = */ false);
        if (r < 0)
                return r;

        return 0;
}

static void dhcp6_handler(sd_dhcp6_client *client, int event, void *userdata) {
        Link *link = userdata;
        int r;

        assert(link);
        assert(link->network);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return;

        switch (event) {
        case SD_DHCP6_CLIENT_EVENT_STOP:
        case SD_DHCP6_CLIENT_EVENT_RESEND_EXPIRE:
        case SD_DHCP6_CLIENT_EVENT_RETRANS_MAX:
                r = dhcp6_lease_lost(link);
                if (r < 0)
                        link_enter_failed(link);
                break;

        case SD_DHCP6_CLIENT_EVENT_IP_ACQUIRE:
                r = dhcp6_lease_ip_acquired(client, link);
                if (r < 0) {
                        link_enter_failed(link);
                        return;
                }

                _fallthrough_;
        case SD_DHCP6_CLIENT_EVENT_INFORMATION_REQUEST:
                r = dhcp6_lease_information_acquired(client, link);
                if (r < 0)
                        link_enter_failed(link);
                break;

        default:
                if (event < 0)
                        log_link_warning_errno(link, event, "DHCPv6 error: %m");
                else
                        log_link_warning(link, "DHCPv6 unknown event: %d", event);
                return;
        }
}

int dhcp6_request_information(Link *link, int ir) {
        int r, inf_req, pd;
        bool running;

        assert(link);
        assert(link->dhcp6_client);
        assert(link->network);
        assert(in6_addr_is_link_local(&link->ipv6ll_address));

        r = sd_dhcp6_client_is_running(link->dhcp6_client);
        if (r < 0)
                return r;
        running = r;

        r = sd_dhcp6_client_get_prefix_delegation(link->dhcp6_client, &pd);
        if (r < 0)
                return r;

        if (pd && ir && link->network->dhcp6_force_pd_other_information) {
                log_link_debug(link, "Enabling managed mode to request DHCPv6 PD with 'Other Information' set");

                r = sd_dhcp6_client_set_address_request(link->dhcp6_client, false);
                if (r < 0)
                        return r;

                ir = false;
        }

        if (running) {
                r = sd_dhcp6_client_get_information_request(link->dhcp6_client, &inf_req);
                if (r < 0)
                        return r;

                if (inf_req == ir)
                        return 0;

                r = sd_dhcp6_client_stop(link->dhcp6_client);
                if (r < 0)
                        return r;
        } else {
                r = sd_dhcp6_client_set_local_address(link->dhcp6_client, &link->ipv6ll_address);
                if (r < 0)
                        return r;
        }

        r = sd_dhcp6_client_set_information_request(link->dhcp6_client, ir);
        if (r < 0)
                return r;

        r = sd_dhcp6_client_start(link->dhcp6_client);
        if (r < 0)
                return r;

        return 0;
}

int dhcp6_start(Link *link) {
        int r;

        assert(link);

        if (!link->dhcp6_client)
                return 0;

        if (!link_dhcp6_enabled(link))
                return 0;

        if (!link_has_carrier(link))
                return 0;

        if (link->network->dhcp6_without_ra == DHCP6_CLIENT_START_MODE_NO)
                return 0;

        if (!in6_addr_is_link_local(&link->ipv6ll_address)) {
                log_link_debug(link, "IPv6 link-local address is not set, delaying to start DHCPv6 client.");
                return 0;
        }

        if (sd_dhcp6_client_is_running(link->dhcp6_client) > 0)
                return 0;

        r = dhcp6_request_information(link, link->network->dhcp6_without_ra == DHCP6_CLIENT_START_MODE_INFORMATION_REQUEST);
        if (r < 0)
                return r;

        return 1;
}

int dhcp6_request_prefix_delegation(Link *link) {
        Link *l;

        assert(link);
        assert(link->manager);

        if (!link_dhcp6_pd_is_enabled(link))
                return 0;

        log_link_debug(link, "Requesting DHCPv6 prefixes to be delegated for new link");

        HASHMAP_FOREACH(l, link->manager->links_by_index) {
                int r, enabled;

                if (l == link)
                        continue;

                if (!l->dhcp6_client)
                        continue;

                r = sd_dhcp6_client_get_prefix_delegation(l->dhcp6_client, &enabled);
                if (r < 0) {
                        log_link_warning_errno(l, r, "Cannot get prefix delegation when adding new link: %m");
                        link_enter_failed(l);
                        continue;
                }

                if (enabled == 0) {
                        r = sd_dhcp6_client_set_prefix_delegation(l->dhcp6_client, 1);
                        if (r < 0) {
                                log_link_warning_errno(l, r, "Cannot enable prefix delegation when adding new link: %m");
                                link_enter_failed(l);
                                continue;
                        }
                }

                r = sd_dhcp6_client_is_running(l->dhcp6_client);
                if (r <= 0)
                        continue;

                if (enabled != 0) {
                        if (dhcp6_lease_has_pd_prefix(l->dhcp6_lease)) {
                                log_link_debug(l, "Requesting re-assignment of delegated prefixes after adding new link");
                                r = dhcp6_pd_prefix_acquired(l);
                                if (r < 0)
                                        link_enter_failed(l);
                        }
                        continue;
                }

                r = sd_dhcp6_client_stop(l->dhcp6_client);
                if (r < 0) {
                        log_link_warning_errno(l, r, "Cannot stop DHCPv6 prefix delegation client after adding new link: %m");
                        link_enter_failed(l);
                        continue;
                }

                r = sd_dhcp6_client_start(l->dhcp6_client);
                if (r < 0) {
                        log_link_warning_errno(l, r, "Cannot restart DHCPv6 prefix delegation client after adding new link: %m");
                        link_enter_failed(l);
                        continue;
                }

                log_link_debug(l, "Restarted DHCPv6 client to acquire prefix delegations after adding new link");
        }

        /* dhcp6_pd_prefix_acquired() may make the link in failed state. */
        if (link->state == LINK_STATE_FAILED)
                return -ENOANO;

        return 0;
}

static int dhcp6_set_hostname(sd_dhcp6_client *client, Link *link) {
        _cleanup_free_ char *hostname = NULL;
        const char *hn;
        int r;

        assert(link);

        if (!link->network->dhcp_send_hostname)
                hn = NULL;
        else if (link->network->dhcp_hostname)
                hn = link->network->dhcp_hostname;
        else {
                r = gethostname_strict(&hostname);
                if (r < 0 && r != -ENXIO) /* ENXIO: no hostname set or hostname is "localhost" */
                        return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to get hostname: %m");

                hn = hostname;
        }

        r = sd_dhcp6_client_set_fqdn(client, hn);
        if (r == -EINVAL && hostname)
                /* Ignore error when the machine's hostname is not suitable to send in DHCP packet. */
                log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to set hostname from kernel hostname, ignoring: %m");
        else if (r < 0)
                return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to set hostname: %m");

        return 0;
}

static bool dhcp6_enable_prefix_delegation(Link *dhcp6_link) {
        Link *link;

        assert(dhcp6_link);
        assert(dhcp6_link->manager);

        HASHMAP_FOREACH(link, dhcp6_link->manager->links_by_index) {
                if (link == dhcp6_link)
                        continue;

                if (!link_dhcp6_pd_is_enabled(link))
                        continue;

                return true;
        }

        return false;
}

static int dhcp6_set_identifier(Link *link, sd_dhcp6_client *client) {
        const DUID *duid;
        int r;

        assert(link);
        assert(link->network);
        assert(client);

        r = sd_dhcp6_client_set_mac(client, link->hw_addr.bytes, link->hw_addr.length, link->iftype);
        if (r < 0)
                return r;

        if (link->network->dhcp6_iaid_set) {
                r = sd_dhcp6_client_set_iaid(client, link->network->dhcp6_iaid);
                if (r < 0)
                        return r;
        }

        duid = link_get_dhcp6_duid(link);
        if (duid->type == DUID_TYPE_LLT && duid->raw_data_len == 0)
                r = sd_dhcp6_client_set_duid_llt(client, duid->llt_time);
        else
                r = sd_dhcp6_client_set_duid(client,
                                             duid->type,
                                             duid->raw_data_len > 0 ? duid->raw_data : NULL,
                                             duid->raw_data_len);
        if (r < 0)
                return r;

        return 0;
}

static int dhcp6_configure(Link *link) {
        _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client = NULL;
        sd_dhcp6_option *vendor_option;
        sd_dhcp6_option *send_option;
        void *request_options;
        int r;

        assert(link);
        assert(link->network);

        if (link->dhcp6_client)
                return log_link_debug_errno(link, SYNTHETIC_ERRNO(EBUSY), "DHCPv6 client is already configured.");

        r = sd_dhcp6_client_new(&client);
        if (r == -ENOMEM)
                return log_oom_debug();
        if (r < 0)
                return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to create DHCPv6 client: %m");

        r = sd_dhcp6_client_attach_event(client, link->manager->event, 0);
        if (r < 0)
                return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to attach event: %m");

        r = dhcp6_set_identifier(link, client);
        if (r < 0)
                return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to set identifier: %m");

        ORDERED_HASHMAP_FOREACH(send_option, link->network->dhcp6_client_send_options) {
                r = sd_dhcp6_client_add_option(client, send_option);
                if (r == -EEXIST)
                        continue;
                if (r < 0)
                        return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to set option: %m");
        }

        r = dhcp6_set_hostname(client, link);
        if (r < 0)
                return r;

        r = sd_dhcp6_client_set_ifindex(client, link->ifindex);
        if (r < 0)
                return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to set ifindex: %m");

        if (link->network->dhcp6_mudurl) {
                r = sd_dhcp6_client_set_request_mud_url(client, link->network->dhcp6_mudurl);
                if (r < 0)
                        return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to set MUD URL: %m");
        }

        SET_FOREACH(request_options, link->network->dhcp6_request_options) {
                uint32_t option = PTR_TO_UINT32(request_options);

                r = sd_dhcp6_client_set_request_option(client, option);
                if (r == -EEXIST) {
                        log_link_debug(link, "DHCPv6 CLIENT: Failed to set request flag for '%u' already exists, ignoring.", option);
                        continue;
                }
                if (r < 0)
                        return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to set request flag for '%u': %m", option);
        }

        if (link->network->dhcp6_user_class) {
                r = sd_dhcp6_client_set_request_user_class(client, link->network->dhcp6_user_class);
                if (r < 0)
                        return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to set user class: %m");
        }

        if (link->network->dhcp6_vendor_class) {
                r = sd_dhcp6_client_set_request_vendor_class(client, link->network->dhcp6_vendor_class);
                if (r < 0)
                        return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to set vendor class: %m");
        }

        ORDERED_HASHMAP_FOREACH(vendor_option, link->network->dhcp6_client_send_vendor_options) {
                r = sd_dhcp6_client_add_vendor_option(client, vendor_option);
                if (r == -EEXIST)
                        continue;
                if (r < 0)
                        return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to set vendor option: %m");
        }

        r = sd_dhcp6_client_set_callback(client, dhcp6_handler, link);
        if (r < 0)
                return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to set callback: %m");

        if (dhcp6_enable_prefix_delegation(link)) {
                r = sd_dhcp6_client_set_prefix_delegation(client, true);
                if (r < 0)
                        return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to set prefix delegation: %m");
        }

        if (link->network->dhcp6_pd_length > 0) {
                r = sd_dhcp6_client_set_prefix_delegation_hint(client, link->network->dhcp6_pd_length, &link->network->dhcp6_pd_address);
                if (r < 0)
                        return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to set prefix hint: %m");
        }

        link->dhcp6_client = TAKE_PTR(client);

        return 0;
}

int dhcp6_update_mac(Link *link) {
        bool restart;
        int r;

        assert(link);

        if (!link->dhcp6_client)
                return 0;

        restart = sd_dhcp6_client_is_running(link->dhcp6_client) > 0;

        if (restart) {
                r = sd_dhcp6_client_stop(link->dhcp6_client);
                if (r < 0)
                        return r;
        }

        r = dhcp6_set_identifier(link, link->dhcp6_client);
        if (r < 0)
                return r;

        if (restart) {
                r = sd_dhcp6_client_start(link->dhcp6_client);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Could not restart DHCPv6 client: %m");
        }

        return 0;
}

int request_process_dhcp6_client(Request *req) {
        Link *link;
        int r;

        assert(req);
        assert(req->link);
        assert(req->type == REQUEST_TYPE_DHCP6_CLIENT);

        link = req->link;

        if (!IN_SET(link->state, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED))
                return 0;

        r = dhcp_configure_duid(link, link_get_dhcp6_duid(link));
        if (r <= 0)
                return r;

        r = dhcp6_configure(link);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to configure DHCPv6 client: %m");

        r = ndisc_start(link);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to start IPv6 Router Discovery: %m");

        r = dhcp6_start(link);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to start DHCPv6 client: %m");

        log_link_debug(link, "DHCPv6 client is configured%s.",
                       r > 0 ? ", acquiring DHCPv6 lease" : "");

        return 1;
}

int link_request_dhcp6_client(Link *link) {
        int r;

        assert(link);

        if (!link_dhcp6_enabled(link) && !link_ipv6_accept_ra_enabled(link))
                return 0;

        if (link->dhcp6_client)
                return 0;

        r = link_queue_request(link, REQUEST_TYPE_DHCP6_CLIENT, NULL, false, NULL, NULL, NULL);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to request configuring of the DHCPv6 client: %m");

        log_link_debug(link, "Requested configuring of the DHCPv6 client.");
        return 0;
}

int link_serialize_dhcp6_client(Link *link, FILE *f) {
        _cleanup_free_ char *duid = NULL;
        uint32_t iaid;
        int r;

        assert(link);

        if (!link->dhcp6_client)
                return 0;

        r = sd_dhcp6_client_get_iaid(link->dhcp6_client, &iaid);
        if (r >= 0)
                fprintf(f, "DHCP6_CLIENT_IAID=0x%x\n", iaid);

        r = sd_dhcp6_client_duid_as_string(link->dhcp6_client, &duid);
        if (r >= 0)
                fprintf(f, "DHCP6_CLIENT_DUID=%s\n", duid);

        return 0;
}

int config_parse_dhcp6_pd_hint(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Network *network = data;
        union in_addr_union u;
        unsigned char prefixlen;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = in_addr_prefix_from_string(rvalue, AF_INET6, &u, &prefixlen);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse %s=%s, ignoring assignment.", lvalue, rvalue);
                return 0;
        }

        if (prefixlen < 1 || prefixlen > 128) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid prefix length in %s=%s, ignoring assignment.", lvalue, rvalue);
                return 0;
        }

        network->dhcp6_pd_address = u.in6;
        network->dhcp6_pd_length = prefixlen;

        return 0;
}

DEFINE_CONFIG_PARSE_ENUM(config_parse_dhcp6_client_start_mode, dhcp6_client_start_mode, DHCP6ClientStartMode,
                         "Failed to parse WithoutRA= setting");

static const char* const dhcp6_client_start_mode_table[_DHCP6_CLIENT_START_MODE_MAX] = {
        [DHCP6_CLIENT_START_MODE_NO]                  = "no",
        [DHCP6_CLIENT_START_MODE_INFORMATION_REQUEST] = "information-request",
        [DHCP6_CLIENT_START_MODE_SOLICIT]             = "solicit",
};

DEFINE_STRING_TABLE_LOOKUP(dhcp6_client_start_mode, DHCP6ClientStartMode);

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
