/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2014 Intel Corporation. All rights reserved.
***/

#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_arp.h>

#include "sd-dhcp6-client.h"

#include "escape.h"
#include "hashmap.h"
#include "hostname-setup.h"
#include "hostname-util.h"
#include "missing_network.h"
#include "networkd-address.h"
#include "networkd-dhcp6.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-radv.h"
#include "siphash24.h"
#include "string-table.h"
#include "string-util.h"
#include "radv-internal.h"
#include "web-util.h"

bool link_dhcp6_pd_is_enabled(Link *link) {
        assert(link);

        if (!link->network)
                return false;

        return link->network->dhcp6_pd;
}

static bool dhcp6_lease_has_pd_prefix(sd_dhcp6_lease *lease) {
        uint32_t lifetime_preferred, lifetime_valid;
        union in_addr_union pd_prefix;
        uint8_t pd_prefix_len;

        if (!lease)
                return false;

        sd_dhcp6_lease_reset_pd_prefix_iter(lease);

        return sd_dhcp6_lease_get_pd(lease, &pd_prefix.in6, &pd_prefix_len, &lifetime_preferred, &lifetime_valid) >= 0;
}

DHCP6DelegatedPrefix *dhcp6_pd_free(DHCP6DelegatedPrefix *p) {
        if (!p)
                return NULL;

        if (p->link && p->link->manager) {
                hashmap_remove(p->link->manager->dhcp6_prefixes, &p->prefix);
                set_remove(p->link->manager->dhcp6_pd_prefixes, p);
        }

        link_unref(p->link);
        return mfree(p);
}

static void dhcp6_pd_hash_func(const DHCP6DelegatedPrefix *p, struct siphash *state) {
        assert(p);

        siphash24_compress(&p->pd_prefix, sizeof(p->pd_prefix), state);
        siphash24_compress(&p->link, sizeof(p->link), state);
}

static int dhcp6_pd_compare_func(const DHCP6DelegatedPrefix *a, const DHCP6DelegatedPrefix *b) {
        int r;

        r = memcmp(&a->pd_prefix, &b->pd_prefix, sizeof(a->pd_prefix));
        if (r != 0)
                return r;

        return CMP(a->link, b->link);
}

DEFINE_HASH_OPS(dhcp6_pd_hash_ops, DHCP6DelegatedPrefix, dhcp6_pd_hash_func, dhcp6_pd_compare_func);

static Link *dhcp6_pd_get_link_by_prefix(Link *link, const union in_addr_union *prefix) {
        DHCP6DelegatedPrefix *pd;

        assert(link);
        assert(link->manager);
        assert(prefix);

        pd = hashmap_get(link->manager->dhcp6_prefixes, &prefix->in6);
        if (!pd)
                return NULL;

        return pd->link;
}

static int dhcp6_pd_get_assigned_prefix(Link *link, const union in_addr_union *pd_prefix, union in_addr_union *ret_prefix) {
        DHCP6DelegatedPrefix *pd, in;

        assert(link);
        assert(link->manager);
        assert(pd_prefix);
        assert(ret_prefix);

        in = (DHCP6DelegatedPrefix) {
                .pd_prefix = pd_prefix->in6,
                .link = link,
        };

        pd = set_get(link->manager->dhcp6_pd_prefixes, &in);
        if (!pd)
                return -ENOENT;

        ret_prefix->in6 = pd->prefix;
        return 0;
}

static int dhcp6_pd_remove_old(Link *link, bool force);

static int dhcp6_pd_address_callback(Address *address) {
        Address *a;

        assert(address);
        assert(address->link);

        /* Make this called only once */
        SET_FOREACH(a, address->link->dhcp6_pd_addresses)
                a->callback = NULL;

        return dhcp6_pd_remove_old(address->link, true);
}

static int dhcp6_pd_remove_old(Link *link, bool force) {
        Address *address;
        Route *route;
        int k, r = 0;

        assert(link);
        assert(link->manager);

        if (!force && (link->dhcp6_pd_address_messages != 0 || link->dhcp6_pd_route_messages != 0))
                return 0;

        if (set_isempty(link->dhcp6_pd_addresses_old) && set_isempty(link->dhcp6_pd_routes_old))
                return 0;

        if (!force) {
                bool set_callback = !set_isempty(link->dhcp6_pd_addresses);

                SET_FOREACH(address, link->dhcp6_pd_addresses)
                        if (address_is_ready(address)) {
                                set_callback = false;
                                break;
                        }

                if (set_callback) {
                        SET_FOREACH(address, link->dhcp6_pd_addresses)
                                address->callback = dhcp6_pd_address_callback;
                        return 0;
                }
        }

        log_link_debug(link, "Removing old DHCPv6 Prefix Delegation addresses and routes.");

        SET_FOREACH(route, link->dhcp6_pd_routes_old) {
                k = route_remove(route, NULL, link, NULL);
                if (k < 0)
                        r = k;

                if (link->radv)
                        (void) sd_radv_remove_prefix(link->radv, &route->dst.in6, 64);
                dhcp6_pd_free(hashmap_get(link->manager->dhcp6_prefixes, &route->dst.in6));
        }

        SET_FOREACH(address, link->dhcp6_pd_addresses_old) {
                k = address_remove(address, link, NULL);
                if (k < 0)
                        r = k;
        }

        return r;
}

int dhcp6_pd_remove(Link *link) {
        Address *address;
        Route *route;
        int k, r = 0;

        assert(link);
        assert(link->manager);

        if (!link_dhcp6_pd_is_enabled(link))
                return 0;

        link->dhcp6_pd_address_configured = false;
        link->dhcp6_pd_route_configured = false;

        k = dhcp6_pd_remove_old(link, true);
        if (k < 0)
                r = k;

        if (set_isempty(link->dhcp6_pd_addresses) && set_isempty(link->dhcp6_pd_routes))
                return r;

        log_link_debug(link, "Removing DHCPv6 Prefix Delegation addresses and routes.");

        SET_FOREACH(route, link->dhcp6_pd_routes) {
                k = route_remove(route, NULL, link, NULL);
                if (k < 0)
                        r = k;

                if (link->radv)
                        (void) sd_radv_remove_prefix(link->radv, &route->dst.in6, 64);
                dhcp6_pd_free(hashmap_get(link->manager->dhcp6_prefixes, &route->dst.in6));
        }

        SET_FOREACH(address, link->dhcp6_pd_addresses) {
                k = address_remove(address, link, NULL);
                if (k < 0)
                        r = k;
        }

        return r;
}

static int dhcp6_pd_route_handler(sd_netlink *nl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);
        assert(link->dhcp6_pd_route_messages > 0);

        link->dhcp6_pd_route_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_message_warning_errno(link, m, r, "Failed to add DHCPv6 Prefix Delegation route");
                link_enter_failed(link);
                return 1;
        }

        if (link->dhcp6_pd_route_messages == 0) {
                log_link_debug(link, "DHCPv6 prefix delegation routes set");
                if (link->dhcp6_pd_prefixes_assigned)
                        link->dhcp6_pd_route_configured = true;

                r = dhcp6_pd_remove_old(link, false);
                if (r < 0) {
                        link_enter_failed(link);
                        return 1;
                }

                link_check_ready(link);
        }

        return 1;
}

static int dhcp6_set_pd_route(Link *link, const union in_addr_union *prefix, const union in_addr_union *pd_prefix) {
        _cleanup_(dhcp6_pd_freep) DHCP6DelegatedPrefix *pd = NULL;
        _cleanup_(route_freep) Route *route = NULL;
        Link *assigned_link;
        Route *ret;
        int r;

        assert(link);
        assert(link->manager);
        assert(prefix);
        assert(pd_prefix);

        r = route_new(&route);
        if (r < 0)
                return r;

        route->family = AF_INET6;
        route->dst = *prefix;
        route->dst_prefixlen = 64;
        route->protocol = RTPROT_DHCP;

        r = route_configure(route, link, dhcp6_pd_route_handler, &ret);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to set DHCPv6 prefix route: %m");
        if (r > 0)
                link->dhcp6_pd_route_configured = false;

        link->dhcp6_pd_route_messages++;

        r = set_ensure_put(&link->dhcp6_pd_routes, &route_hash_ops, ret);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to store DHCPv6 prefix route: %m");

        (void) set_remove(link->dhcp6_pd_routes_old, ret);

        assigned_link = dhcp6_pd_get_link_by_prefix(link, prefix);
        if (assigned_link) {
                assert(assigned_link == link);
                return 0;
        }

        pd = new(DHCP6DelegatedPrefix, 1);
        if (!pd)
                return log_oom();

        *pd = (DHCP6DelegatedPrefix) {
                .prefix = prefix->in6,
                .pd_prefix = pd_prefix->in6,
                .link = link_ref(link),
        };

        r = hashmap_ensure_put(&link->manager->dhcp6_prefixes, &in6_addr_hash_ops, &pd->prefix, pd);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to store DHCPv6 prefix route at manager: %m");

        r = set_ensure_put(&link->manager->dhcp6_pd_prefixes, &dhcp6_pd_hash_ops, pd);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to store DHCPv6 prefix route at manager: %m");

        TAKE_PTR(pd);
        return 0;
}

static int dhcp6_pd_address_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);
        assert(link->dhcp6_pd_address_messages > 0);

        link->dhcp6_pd_address_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_message_warning_errno(link, m, r, "Could not set DHCPv6 delegated prefix address");
                link_enter_failed(link);
                return 1;
        } else if (r >= 0)
                (void) manager_rtnl_process_address(rtnl, m, link->manager);

        if (link->dhcp6_pd_address_messages == 0) {
                log_link_debug(link, "DHCPv6 delegated prefix addresses set");
                if (link->dhcp6_pd_prefixes_assigned)
                        link->dhcp6_pd_address_configured = true;

                r = dhcp6_pd_remove_old(link, false);
                if (r < 0) {
                        link_enter_failed(link);
                        return 1;
                }
        }

        return 1;
}

static int dhcp6_set_pd_address(
                Link *link,
                const union in_addr_union *prefix,
                uint32_t lifetime_preferred,
                uint32_t lifetime_valid) {

        _cleanup_(address_freep) Address *address = NULL;
        Address *ret;
        int r;

        assert(link);
        assert(link->network);
        assert(prefix);

        if (!link->network->dhcp6_pd_assign)
                return 0;

        r = address_new(&address);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to allocate address for DHCPv6 delegated prefix: %m");

        address->in_addr = *prefix;

        if (in_addr_is_set(AF_INET6, &link->network->dhcp6_pd_token))
                memcpy(address->in_addr.in6.s6_addr + 8, link->network->dhcp6_pd_token.in6.s6_addr + 8, 8);
        else {
                r = generate_ipv6_eui_64_address(link, &address->in_addr.in6);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Failed to generate EUI64 address for acquired DHCPv6 delegated prefix: %m");
        }

        address->prefixlen = 64;
        address->family = AF_INET6;
        address->cinfo.ifa_prefered = lifetime_preferred;
        address->cinfo.ifa_valid = lifetime_valid;
        SET_FLAG(address->flags, IFA_F_MANAGETEMPADDR, link->network->dhcp6_pd_manage_temporary_address);

        r = address_configure(address, link, dhcp6_pd_address_handler, &ret);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to set DHCPv6 delegated prefix address: %m");
        if (r > 0)
                link->dhcp6_pd_address_configured = false;

        link->dhcp6_pd_address_messages++;

        r = set_ensure_put(&link->dhcp6_pd_addresses, &address_hash_ops, ret);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to store DHCPv6 delegated prefix address: %m");

        (void) set_remove(link->dhcp6_pd_addresses_old, ret);

        return 0;
}

static int dhcp6_pd_assign_prefix(
                Link *link,
                const union in_addr_union *prefix,
                const union in_addr_union *pd_prefix,
                uint32_t lifetime_preferred,
                uint32_t lifetime_valid) {

        int r;

        assert(link);
        assert(link->network);
        assert(prefix);

        if (link->network->dhcp6_pd_announce) {
                r = radv_add_prefix(link, &prefix->in6, 64, lifetime_preferred, lifetime_valid);
                if (r < 0)
                        return r;
        }

        r = dhcp6_set_pd_route(link, prefix, pd_prefix);
        if (r < 0)
                return r;

        r = dhcp6_set_pd_address(link, prefix, lifetime_preferred, lifetime_valid);
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
                const union in_addr_union *masked_pd_prefix,
                uint8_t pd_prefix_len,
                union in_addr_union *ret) {

        /* We start off with the original PD prefix we have been assigned and iterate from there */
        union in_addr_union prefix;
        uint64_t n_prefixes;
        Link *assigned_link;
        int r;

        assert(link);
        assert(link->manager);
        assert(masked_pd_prefix);
        assert(pd_prefix_len <= 64);

        n_prefixes = UINT64_C(1) << (64 - pd_prefix_len);
        prefix = *masked_pd_prefix;

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
                assert_se(in_addr_prefix_covers(AF_INET6, masked_pd_prefix, pd_prefix_len, &prefix) > 0);

                assigned_link = dhcp6_pd_get_link_by_prefix(link, &prefix);
                if (assigned_link && assigned_link != link) {
                        _cleanup_free_ char *assigned_buf = NULL;

                        (void) in_addr_to_string(AF_INET6, &prefix, &assigned_buf);
                        return log_link_warning_errno(link, SYNTHETIC_ERRNO(EAGAIN),
                                                      "The requested prefix %s is already assigned to another link.",
                                                      strna(assigned_buf));
                }

                *ret = prefix;
                return 0;
        }

        for (uint64_t n = 0; n < n_prefixes; n++) {
                /* If we do not have an allocation preference just iterate
                 * through the address space and return the first free prefix. */
                assigned_link = dhcp6_pd_get_link_by_prefix(link, &prefix);
                if (!assigned_link || assigned_link == link) {
                        *ret = prefix;
                        return 0;
                }

                r = in_addr_prefix_next(AF_INET6, &prefix, 64);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Can't allocate another prefix. Out of address space?: %m");
        }

        return log_link_warning_errno(link, SYNTHETIC_ERRNO(ERANGE), "Couldn't find a suitable prefix. Ran out of address space.");
}

static void dhcp6_pd_prefix_distribute(Link *dhcp6_link,
                                      const union in_addr_union *masked_pd_prefix,
                                      uint8_t pd_prefix_len,
                                      uint32_t lifetime_preferred,
                                      uint32_t lifetime_valid,
                                      bool assign_preferred_subnet_id) {

        Link *link;
        int r;

        assert(dhcp6_link);
        assert(dhcp6_link->manager);
        assert(masked_pd_prefix);
        assert(pd_prefix_len <= 64);

        HASHMAP_FOREACH(link, dhcp6_link->manager->links) {
                _cleanup_free_ char *assigned_buf = NULL;
                union in_addr_union assigned_prefix;

                if (link == dhcp6_link)
                        continue;

                if (!link_dhcp6_pd_is_enabled(link))
                        continue;

                if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                        continue;

                if (assign_preferred_subnet_id != link_has_preferred_subnet_id(link))
                        continue;

                r = dhcp6_pd_get_assigned_prefix(link, masked_pd_prefix, &assigned_prefix);
                if (r < 0) {
                        r = dhcp6_get_preferred_delegated_prefix(link, masked_pd_prefix, pd_prefix_len, &assigned_prefix);
                        if (r < 0) {
                                link->dhcp6_pd_prefixes_assigned = false;
                                continue;
                        }
                }

                (void) in_addr_to_string(AF_INET6, &assigned_prefix, &assigned_buf);
                r = dhcp6_pd_assign_prefix(link, &assigned_prefix, masked_pd_prefix,
                                           lifetime_preferred, lifetime_valid);
                if (r < 0) {
                        log_link_error_errno(link, r, "Unable to assign/update prefix %s/64: %m",
                                             strna(assigned_buf));
                        link_enter_failed(link);
                } else
                        log_link_debug(link, "Assigned prefix %s/64", strna(assigned_buf));
        }
}

static int dhcp6_pd_prepare(Link *link) {
        Address *address;
        Route *route;
        int r;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 0;

        if (!link_dhcp6_pd_is_enabled(link))
                return 0;

        link->dhcp6_pd_prefixes_assigned = true;

        while ((address = set_steal_first(link->dhcp6_pd_addresses))) {
                r = set_ensure_put(&link->dhcp6_pd_addresses_old, &address_hash_ops, address);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to store old DHCPv6 Prefix Delegation address: %m");
        }

        while ((route = set_steal_first(link->dhcp6_pd_routes))) {
                r = set_ensure_put(&link->dhcp6_pd_routes_old, &route_hash_ops, route);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to store old DHCPv6 Prefix Delegation route: %m");
        }

        return 0;
}

static int dhcp6_pd_finalize(Link *link) {
        int r;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 0;

        if (!link_dhcp6_pd_is_enabled(link))
                return 0;

        if (link->dhcp6_pd_address_messages == 0) {
                if (link->dhcp6_pd_prefixes_assigned)
                        link->dhcp6_pd_address_configured = true;
        } else
                log_link_debug(link, "Setting DHCPv6 PD addresses");

        if (link->dhcp6_pd_route_messages == 0) {
                if (link->dhcp6_pd_prefixes_assigned)
                        link->dhcp6_pd_route_configured = true;
        } else
                log_link_debug(link, "Setting DHCPv6 PD routes");

        r = dhcp6_pd_remove_old(link, false);
        if (r < 0)
                return r;

        if (link->dhcp6_pd_address_configured && link->dhcp6_pd_route_configured)
                link_check_ready(link);
        else
                link_set_state(link, LINK_STATE_CONFIGURING);

        return 0;
}

static void dhcp6_pd_prefix_lost(Link *dhcp6_link) {
        Link *link;
        int r;

        assert(dhcp6_link);
        assert(dhcp6_link->manager);

        HASHMAP_FOREACH(link, dhcp6_link->manager->links) {
                if (link == dhcp6_link)
                        continue;

                r = dhcp6_pd_remove(link);
                if (r < 0)
                        link_enter_failed(link);
        }
}

static int dhcp6_remove_old(Link *link, bool force);

static int dhcp6_address_callback(Address *address) {
        Address *a;

        assert(address);
        assert(address->link);

        /* Make this called only once */
        SET_FOREACH(a, address->link->dhcp6_addresses)
                a->callback = NULL;

        return dhcp6_remove_old(address->link, true);
}

static int dhcp6_remove_old(Link *link, bool force) {
        Address *address;
        Route *route;
        int k, r = 0;

        assert(link);

        if (!force && (!link->dhcp6_address_configured || !link->dhcp6_route_configured))
                return 0;

        if (set_isempty(link->dhcp6_addresses_old) && set_isempty(link->dhcp6_routes_old))
                return 0;

        if (!force) {
                bool set_callback = !set_isempty(link->dhcp6_addresses);

                SET_FOREACH(address, link->dhcp6_addresses)
                        if (address_is_ready(address)) {
                                set_callback = false;
                                break;
                        }

                if (set_callback) {
                        SET_FOREACH(address, link->dhcp6_addresses)
                                address->callback = dhcp6_address_callback;
                        return 0;
                }
        }

        log_link_debug(link, "Removing old DHCPv6 addresses and routes.");

        SET_FOREACH(route, link->dhcp6_routes_old) {
                k = route_remove(route, NULL, link, NULL);
                if (k < 0)
                        r = k;
        }

        SET_FOREACH(address, link->dhcp6_addresses_old) {
                k = address_remove(address, link, NULL);
                if (k < 0)
                        r = k;
        }

        return r;
}

static int dhcp6_remove(Link *link) {
        Address *address;
        Route *route;
        int k, r = 0;

        assert(link);

        link->dhcp6_address_configured = false;
        link->dhcp6_route_configured = false;

        k = dhcp6_remove_old(link, true);
        if (k < 0)
                r = k;

        if (set_isempty(link->dhcp6_addresses) && set_isempty(link->dhcp6_routes))
                return r;

        log_link_debug(link, "Removing DHCPv6 addresses and routes.");

        SET_FOREACH(route, link->dhcp6_routes) {
                k = route_remove(route, NULL, link, NULL);
                if (k < 0)
                        r = k;
        }

        SET_FOREACH(address, link->dhcp6_addresses) {
                k = address_remove(address, link, NULL);
                if (k < 0)
                        r = k;
        }

        return r;
}

static int dhcp6_route_handler(sd_netlink *nl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);
        assert(link->dhcp6_route_messages > 0);

        link->dhcp6_route_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_message_warning_errno(link, m, r, "Failed to add unreachable route for DHCPv6 delegated subnet");
                link_enter_failed(link);
                return 1;
        }

        if (link->dhcp6_route_messages == 0) {
                log_link_debug(link, "Unreachable routes for DHCPv6 delegated subnets set");
                link->dhcp6_route_configured = true;

                r = dhcp6_remove_old(link, false);
                if (r < 0) {
                        link_enter_failed(link);
                        return 1;
                }

                link_check_ready(link);
        }

        return 1;
}

static int dhcp6_set_unreachable_route(Link *link, const union in_addr_union *addr, uint8_t prefixlen) {
        _cleanup_(route_freep) Route *route = NULL;
        _cleanup_free_ char *buf = NULL;
        Route *ret;
        int r;

        assert(link);
        assert(addr);

        (void) in_addr_prefix_to_string(AF_INET6, addr, prefixlen, &buf);

        if (prefixlen > 64) {
                log_link_debug(link, "PD Prefix length > 64, ignoring prefix %s", strna(buf));
                return 0;
        }

        if (prefixlen == 64) {
                log_link_debug(link, "Not adding a blocking route for DHCPv6 delegated subnet %s since distributed prefix is 64",
                               strna(buf));
                return 1;
        }

        if (prefixlen < 48)
                log_link_warning(link, "PD Prefix length < 48, looks unusual: %s", strna(buf));

        r = route_new(&route);
        if (r < 0)
                return log_oom();

        route->family = AF_INET6;
        route->dst = *addr;
        route->dst_prefixlen = prefixlen;
        route->table = link_get_dhcp_route_table(link);
        route->type = RTN_UNREACHABLE;
        route->protocol = RTPROT_DHCP;

        r = route_configure(route, link, dhcp6_route_handler, &ret);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to set unreachable route for DHCPv6 delegated subnet %s: %m",
                                            strna(buf));
        if (r > 0)
                link->dhcp6_route_configured = false;

        link->dhcp6_route_messages++;

        r = set_ensure_put(&link->dhcp6_routes, &route_hash_ops, ret);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to store unreachable route for DHCPv6 delegated subnet %s: %m",
                                            strna(buf));

        (void) set_remove(link->dhcp6_routes_old, ret);

        return 1;
}

static int dhcp6_pd_prefix_acquired(Link *dhcp6_link) {
        Link *link;
        int r;

        assert(dhcp6_link);
        assert(dhcp6_link->dhcp6_lease);

        HASHMAP_FOREACH(link, dhcp6_link->manager->links) {
                if (link == dhcp6_link)
                        continue;

                r = dhcp6_pd_prepare(link);
                if (r < 0)
                        link_enter_failed(link);
        }

        for (sd_dhcp6_lease_reset_pd_prefix_iter(dhcp6_link->dhcp6_lease);;) {
                uint32_t lifetime_preferred, lifetime_valid;
                union in_addr_union pd_prefix, prefix;
                uint8_t pd_prefix_len;

                r = sd_dhcp6_lease_get_pd(dhcp6_link->dhcp6_lease, &pd_prefix.in6, &pd_prefix_len,
                                          &lifetime_preferred, &lifetime_valid);
                if (r < 0)
                        break;

                r = dhcp6_set_unreachable_route(dhcp6_link, &pd_prefix, pd_prefix_len);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                /* We are doing prefix allocation in two steps:
                 * 1. all those links that have a preferred subnet id will be assigned their subnet
                 * 2. all those links that remain will receive prefixes in sequential order. Prefixes
                 *    that were previously already allocated to another link will be skipped.
                 * The assignment has to be split in two phases since subnet id
                 * preferences should be honored. Meaning that any subnet id should be
                 * handed out to the requesting link and not to some link that didn't
                 * specify any preference. */

                assert(pd_prefix_len <= 64);

                prefix = pd_prefix;
                r = in_addr_mask(AF_INET6, &prefix, pd_prefix_len);
                if (r < 0)
                        return log_link_error_errno(dhcp6_link, r, "Failed to mask DHCPv6 PD prefix: %m");

                if (DEBUG_LOGGING) {
                        uint64_t n_prefixes = UINT64_C(1) << (64 - pd_prefix_len);
                        _cleanup_free_ char *buf = NULL;

                        (void) in_addr_prefix_to_string(AF_INET6, &prefix, pd_prefix_len, &buf);
                        log_link_debug(dhcp6_link, "Assigning up to %" PRIu64 " prefixes from %s",
                                       n_prefixes, strna(buf));
                }

                dhcp6_pd_prefix_distribute(dhcp6_link,
                                           &prefix,
                                           pd_prefix_len,
                                           lifetime_preferred,
                                           lifetime_valid,
                                           true);

                dhcp6_pd_prefix_distribute(dhcp6_link,
                                           &prefix,
                                           pd_prefix_len,
                                           lifetime_preferred,
                                           lifetime_valid,
                                           false);
        }

        HASHMAP_FOREACH(link, dhcp6_link->manager->links) {
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
        assert(link->dhcp6_address_messages > 0);

        link->dhcp6_address_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_message_warning_errno(link, m, r, "Could not set DHCPv6 address");
                link_enter_failed(link);
                return 1;
        } else if (r >= 0)
                (void) manager_rtnl_process_address(rtnl, m, link->manager);

        if (link->dhcp6_address_messages == 0) {
                log_link_debug(link, "DHCPv6 addresses set");
                link->dhcp6_address_configured = true;

                r = dhcp6_remove_old(link, false);
                if (r < 0) {
                        link_enter_failed(link);
                        return 1;
                }
        }

        return 1;
}

static void log_dhcp6_address(Link *link, const Address *address, char **ret) {
        char valid_buf[FORMAT_TIMESPAN_MAX], preferred_buf[FORMAT_TIMESPAN_MAX];
        const char *valid_str = NULL, *preferred_str = NULL;
        _cleanup_free_ char *buffer = NULL;
        bool by_ndisc = false;
        Address *existing;
        NDiscAddress *na;
        int log_level, r;

        assert(link);
        assert(address);

        (void) in_addr_prefix_to_string(address->family, &address->in_addr, address->prefixlen, &buffer);
        if (address->cinfo.ifa_valid != CACHE_INFO_INFINITY_LIFE_TIME)
                valid_str = format_timespan(valid_buf, FORMAT_TIMESPAN_MAX,
                                            address->cinfo.ifa_valid * USEC_PER_SEC,
                                            USEC_PER_SEC);
        if (address->cinfo.ifa_prefered != CACHE_INFO_INFINITY_LIFE_TIME)
                preferred_str = format_timespan(preferred_buf, FORMAT_TIMESPAN_MAX,
                                                address->cinfo.ifa_prefered * USEC_PER_SEC,
                                                USEC_PER_SEC);

        r = address_get(link, address, &existing);
        if (r < 0) {
                /* New address. */
                log_level = LOG_INFO;
                goto simple_log;
        } else
                log_level = LOG_DEBUG;

        if (set_contains(link->dhcp6_addresses, address))
                /* Already warned. */
                goto simple_log;

        if (address->prefixlen == existing->prefixlen)
                /* Currently, only conflict in prefix length is reported. */
                goto simple_log;

        SET_FOREACH(na, link->ndisc_addresses)
                if (address_compare_func(na->address, existing)) {
                        by_ndisc = true;
                        break;
                }

        log_link_warning(link, "DHCPv6 address %s (valid %s%s, preferred %s%s) conflicts the existing address %s %s.",
                         strna(buffer),
                         valid_str ? "for " : "forever", strempty(valid_str),
                         preferred_str ? "for " : "forever", strempty(preferred_str),
                         strna(buffer),
                         by_ndisc ? "assigned by NDISC. Please try to use or update IPv6Token= setting "
                         "to change the address generated by NDISC, or disable UseAutonomousPrefix=" : "");
        goto finalize;

simple_log:
        log_link_full(link, log_level, "DHCPv6 address %s (valid %s%s, preferred %s%s)",
                      strna(buffer),
                      valid_str ? "for " : "forever", strempty(valid_str),
                      preferred_str ? "for " : "forever", strempty(preferred_str));

finalize:
        if (ret)
                *ret = TAKE_PTR(buffer);
}

static int dhcp6_update_address(
                Link *link,
                const struct in6_addr *ip6_addr,
                uint32_t lifetime_preferred,
                uint32_t lifetime_valid) {

        _cleanup_(address_freep) Address *addr = NULL;
        _cleanup_free_ char *buffer = NULL;
        Address *ret;
        int r;

        r = address_new(&addr);
        if (r < 0)
                return log_oom();

        addr->family = AF_INET6;
        addr->in_addr.in6 = *ip6_addr;
        addr->flags = IFA_F_NOPREFIXROUTE;
        addr->prefixlen = 128;
        addr->cinfo.ifa_prefered = lifetime_preferred;
        addr->cinfo.ifa_valid = lifetime_valid;

        log_dhcp6_address(link, addr, &buffer);

        r = address_configure(addr, link, dhcp6_address_handler, &ret);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to set DHCPv6 address %s: %m", strna(buffer));
        if (r > 0)
                link->dhcp6_address_configured = false;

        link->dhcp6_address_messages++;

        r = set_ensure_put(&link->dhcp6_addresses, &address_hash_ops, ret);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to store DHCPv6 address %s: %m", strna(buffer));

        (void) set_remove(link->dhcp6_addresses_old, ret);

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

                r = dhcp6_update_address(link, &ip6_addr, lifetime_preferred, lifetime_valid);
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
        Address *a;
        Route *rt;
        int r;

        while ((a = set_steal_first(link->dhcp6_addresses))) {
                r = set_ensure_put(&link->dhcp6_addresses_old, &address_hash_ops, a);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to store old DHCPv6 address: %m");
        }

        while ((rt = set_steal_first(link->dhcp6_routes))) {
                r = set_ensure_put(&link->dhcp6_routes_old, &route_hash_ops, rt);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to store old DHCPv6 route: %m");
        }

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

        if (link->dhcp6_address_messages == 0)
                link->dhcp6_address_configured = true;
        else
                log_link_debug(link, "Setting DHCPv6 addresses");

        if (link->dhcp6_route_messages == 0)
                link->dhcp6_route_configured = true;
        else
                log_link_debug(link, "Setting unreachable routes for DHCPv6 delegated subnets");

        r = dhcp6_remove_old(link, false);
        if (r < 0)
                return r;

        if (link->dhcp6_address_configured && link->dhcp6_route_configured)
                link_check_ready(link);
        else
                link_set_state(link, LINK_STATE_CONFIGURING);

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

        r = dhcp6_remove(link);
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

int dhcp6_request_address(Link *link, int ir) {
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

int dhcp6_request_prefix_delegation(Link *link) {
        Link *l;

        assert(link);
        assert(link->manager);

        if (!link_dhcp6_pd_is_enabled(link))
                return 0;

        log_link_debug(link, "Requesting DHCPv6 prefixes to be delegated for new link");

        HASHMAP_FOREACH(l, link->manager->links) {
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
                        return r;

                hn = hostname;
        }

        r = sd_dhcp6_client_set_fqdn(client, hn);
        if (r == -EINVAL && hostname)
                /* Ignore error when the machine's hostname is not suitable to send in DHCP packet. */
                log_link_warning_errno(link, r, "DHCP6 CLIENT: Failed to set hostname from kernel hostname, ignoring: %m");
        else if (r < 0)
                return log_link_error_errno(link, r, "DHCP6 CLIENT: Failed to set hostname: %m");

        return 0;
}

static bool dhcp6_enable_prefix_delegation(Link *dhcp6_link) {
        Link *link;

        assert(dhcp6_link);
        assert(dhcp6_link->manager);

        HASHMAP_FOREACH(link, dhcp6_link->manager->links) {
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

        r = sd_dhcp6_client_set_mac(client, link->hw_addr.addr.bytes, link->hw_addr.length, link->iftype);
        if (r < 0)
                return r;

        if (link->network->iaid_set) {
                r = sd_dhcp6_client_set_iaid(client, link->network->iaid);
                if (r < 0)
                        return r;
        }

        duid = link_get_duid(link);
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

int dhcp6_configure(Link *link) {
        _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client = NULL;
        sd_dhcp6_option *vendor_option;
        sd_dhcp6_option *send_option;
        void *request_options;
        int r;

        assert(link);
        assert(link->network);

        if (!link_dhcp6_enabled(link) && !link_ipv6_accept_ra_enabled(link))
                return 0;

        if (link->dhcp6_client)
                return 0;

        r = sd_dhcp6_client_new(&client);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP6 CLIENT: Failed to create DHCP6 client: %m");

        r = sd_dhcp6_client_attach_event(client, link->manager->event, 0);
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP6 CLIENT: Failed to attach event: %m");

        r = dhcp6_set_identifier(link, client);
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP6 CLIENT: Failed to set identifier: %m");

        ORDERED_HASHMAP_FOREACH(send_option, link->network->dhcp6_client_send_options) {
                r = sd_dhcp6_client_add_option(client, send_option);
                if (r == -EEXIST)
                        continue;
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP6 CLIENT: Failed to set option: %m");
        }

        r = dhcp6_set_hostname(client, link);
        if (r < 0)
                return r;

        r = sd_dhcp6_client_set_ifindex(client, link->ifindex);
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP6 CLIENT: Failed to set ifindex: %m");

        if (link->network->dhcp6_rapid_commit) {
                r = sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_RAPID_COMMIT);
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP6 CLIENT: Failed to set request flag for rapid commit: %m");
        }

        if (link->network->dhcp6_mudurl) {
                r = sd_dhcp6_client_set_request_mud_url(client, link->network->dhcp6_mudurl);
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP6 CLIENT: Failed to set MUD URL: %m");
        }

        SET_FOREACH(request_options, link->network->dhcp6_request_options) {
                uint32_t option = PTR_TO_UINT32(request_options);

                r = sd_dhcp6_client_set_request_option(client, option);
                if (r == -EEXIST) {
                        log_link_debug(link, "DHCP6 CLIENT: Failed to set request flag for '%u' already exists, ignoring.", option);
                        continue;
                }
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP6 CLIENT: Failed to set request flag for '%u': %m", option);
        }

        if (link->network->dhcp6_user_class) {
                r = sd_dhcp6_client_set_request_user_class(client, link->network->dhcp6_user_class);
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP6 CLIENT: Failed to set user class: %m");
        }

        if (link->network->dhcp6_vendor_class) {
                r = sd_dhcp6_client_set_request_vendor_class(client, link->network->dhcp6_vendor_class);
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP6 CLIENT: Failed to set vendor class: %m");
        }

        ORDERED_HASHMAP_FOREACH(vendor_option, link->network->dhcp6_client_send_vendor_options) {
                r = sd_dhcp6_client_add_vendor_option(client, vendor_option);
                if (r == -EEXIST)
                        continue;
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP6 CLIENT: Failed to set vendor option: %m");
        }

        r = sd_dhcp6_client_set_callback(client, dhcp6_handler, link);
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP6 CLIENT: Failed to set callback: %m");

        if (dhcp6_enable_prefix_delegation(link)) {
                r = sd_dhcp6_client_set_prefix_delegation(client, true);
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP6 CLIENT: Failed to set prefix delegation: %m");
        }

        if (link->network->dhcp6_pd_length > 0) {
                r = sd_dhcp6_client_set_prefix_delegation_hint(client, link->network->dhcp6_pd_length, &link->network->dhcp6_pd_address);
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP6 CLIENT: Failed to set prefix hint: %m");
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

int config_parse_dhcp6_mud_url(
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

        _cleanup_free_ char *unescaped = NULL;
        Network *network = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                network->dhcp6_mudurl = mfree(network->dhcp6_mudurl);
                return 0;
        }

        r = cunescape(rvalue, 0, &unescaped);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to Failed to unescape MUD URL, ignoring: %s", rvalue);
                return 0;
        }

        if (!http_url_is_valid(unescaped) || strlen(unescaped) > UINT8_MAX) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Failed to parse MUD URL '%s', ignoring: %m", rvalue);
                return 0;
        }

        return free_and_replace(network->dhcp6_mudurl, unescaped);
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

int config_parse_dhcp6_pd_token(
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

        union in_addr_union *addr = data, tmp;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                *addr = IN_ADDR_NULL;
                return 0;
        }

        r = in_addr_from_string(AF_INET6, rvalue, &tmp);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse DHCPv6 Prefix Delegation token, ignoring: %s", rvalue);
                return 0;
        }

        if (in_addr_is_null(AF_INET6, &tmp)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "DHCPv6 Prefix Delegation token cannot be the ANY address, ignoring: %s", rvalue);
                return 0;
        }

        *addr = tmp;

        return 0;
}
