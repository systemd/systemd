/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  Copyright © 2014 Intel Corporation. All rights reserved.
***/

#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_arp.h>

#include "sd-dhcp6-client.h"

#include "escape.h"
#include "hashmap.h"
#include "hostname-util.h"
#include "missing_network.h"
#include "network-internal.h"
#include "networkd-dhcp6.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-radv.h"
#include "siphash24.h"
#include "string-table.h"
#include "string-util.h"
#include "radv-internal.h"
#include "web-util.h"

static Link *dhcp6_prefix_get(Manager *m, struct in6_addr *addr);
static int dhcp6_prefix_add(Manager *m, struct in6_addr *addr, Link *link);
static int dhcp6_prefix_remove_all(Manager *m, Link *link);
static int dhcp6_assign_delegated_prefix(Link *link, const struct in6_addr *prefix,
                                         uint8_t prefix_len,
                                         uint32_t lifetime_preferred,
                                         uint32_t lifetime_valid);

bool dhcp6_get_prefix_delegation(Link *link) {
        if (!link->network)
                return false;

        return IN_SET(link->network->router_prefix_delegation,
                      RADV_PREFIX_DELEGATION_DHCP6,
                      RADV_PREFIX_DELEGATION_BOTH);
}

static bool dhcp6_has_preferred_subnet_id(Link *link) {
        if (!link->network)
                return false;

        return link->network->router_prefix_subnet_id >= 0;
}

static int dhcp6_get_preferred_delegated_prefix(
                Manager* manager,
                Link *link,
                const struct in6_addr *pd_prefix,
                uint8_t pd_prefix_len,
                struct in6_addr *ret_addr) {

        int64_t subnet_id = link->network->router_prefix_subnet_id;
        uint8_t prefix_bits = 64 - pd_prefix_len;
        uint64_t n_prefixes = UINT64_C(1) << prefix_bits;
        _cleanup_free_ char *assigned_buf = NULL;
        union in_addr_union pd_prefix_union = {
                .in6 = *pd_prefix,
        };
        /* We start off with the original PD prefix we have been assigned and
         * iterate from there */
        union in_addr_union prefix = {
                .in6 = *pd_prefix,
        };
        int r;

        assert(pd_prefix_len <= 64);
        assert(manager);
        assert(link);
        assert(link->network);

        if (subnet_id >= 0) {
                /* If the link has a preference for a particular subnet id try to allocate that */
                if ((uint64_t) subnet_id >= n_prefixes)
                        return log_link_debug_errno(link,
                                        SYNTHETIC_ERRNO(ERANGE),
                                        "subnet id %" PRIi64 " is out of range. Only have %" PRIu64 " subnets.",
                                        subnet_id,
                                        n_prefixes);

                r = in_addr_prefix_nth(AF_INET6, &prefix, 64, subnet_id);
                if (r < 0)
                        return log_link_debug_errno(link,
                                        r,
                                        "subnet id %" PRIi64 " is out of range. Only have %" PRIu64 " subnets.",
                                        subnet_id,
                                        n_prefixes);

                /* Verify that the prefix we did calculate fits in the pd prefix.
                 * This should not fail as we checked the prefix size beforehand */
                assert_se(in_addr_prefix_covers(AF_INET6, &pd_prefix_union, pd_prefix_len, &prefix) > 0);

                Link* assigned_link = dhcp6_prefix_get(manager, &prefix.in6);

                (void) in_addr_to_string(AF_INET6, &prefix, &assigned_buf);

                if (assigned_link && assigned_link != link)
                        return log_link_error_errno(link, SYNTHETIC_ERRNO(EAGAIN),
                                       "The requested prefix %s is already assigned to another link: %s",
                                       strnull(assigned_buf),
                                       strnull(assigned_link->ifname));

                *ret_addr = prefix.in6;

                log_link_debug(link, "The requested prefix %s is available. Using it.",
                               strnull(assigned_buf));
                return 0;
        }

        for (uint64_t n = 0; n < n_prefixes; n++) {
                /* if we do not have an allocation preference just iterate
                 * through the address space and return the first free prefix. */
                Link* assigned_link = dhcp6_prefix_get(manager, &prefix.in6);

                if (!assigned_link || assigned_link == link) {
                        *ret_addr = prefix.in6;
                        return 0;
                }

                r = in_addr_prefix_next(AF_INET6, &prefix, 64);
                if (r < 0)
                        return log_link_error_errno(link, r, "Can't allocate another prefix. Out of address space?: %m");
        }

        return log_link_warning_errno(link, SYNTHETIC_ERRNO(ERANGE), "Couldn't find a suitable prefix. Ran out of address space.");
}

static bool dhcp6_enable_prefix_delegation(Link *dhcp6_link) {
        Manager *manager;
        Link *l;
        Iterator i;

        assert(dhcp6_link);

        manager = dhcp6_link->manager;
        assert(manager);

        HASHMAP_FOREACH(l, manager->links, i) {
                if (l == dhcp6_link)
                        continue;

                if (!dhcp6_get_prefix_delegation(l))
                        continue;

                return true;
        }

        return false;
}

static int dhcp6_lease_information_acquired(sd_dhcp6_client *client, Link *link) {
        return 0;
}

static int dhcp6_pd_prefix_assign(Link *link, struct in6_addr *prefix,
                                  uint8_t prefix_len,
                                  uint32_t lifetime_preferred,
                                  uint32_t lifetime_valid) {
        int r;

        r = radv_add_prefix(link, prefix, prefix_len, lifetime_preferred, lifetime_valid);
        if (r < 0)
                return r;

        r = dhcp6_prefix_add(link->manager, prefix, link);
        if (r < 0)
                return r;

        r = dhcp6_assign_delegated_prefix(link, prefix, prefix_len, lifetime_preferred, lifetime_valid);
        if (r < 0)
                return r;

        return 0;
}

static int dhcp6_route_remove_handler(sd_netlink *nl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0)
                log_link_message_warning_errno(link, m, r, "Received error on unreachable route removal for DHCPv6 delegated subnet");

        return 1;
}

int dhcp6_lease_pd_prefix_lost(sd_dhcp6_client *client, Link* link) {
        uint32_t lifetime_preferred, lifetime_valid;
        union in_addr_union pd_prefix;
        uint8_t pd_prefix_len;
        sd_dhcp6_lease *lease;
        int r;

        r = sd_dhcp6_client_get_lease(client, &lease);
        if (r < 0)
                return r;

        sd_dhcp6_lease_reset_pd_prefix_iter(lease);

        while (sd_dhcp6_lease_get_pd(lease, &pd_prefix.in6, &pd_prefix_len,
                                     &lifetime_preferred,
                                     &lifetime_valid) >= 0) {
                _cleanup_free_ char *buf = NULL;
                _cleanup_(route_freep) Route *route = NULL;

                if (pd_prefix_len >= 64)
                        continue;

                (void) in_addr_to_string(AF_INET6, &pd_prefix, &buf);

                r = route_new(&route);
                if (r < 0)
                        return r;

                route->family = AF_INET6;
                route->dst = pd_prefix;
                route->dst_prefixlen = pd_prefix_len;
                route->type = RTN_UNREACHABLE;

                r = route_remove(route, link, dhcp6_route_remove_handler);
                if (r < 0) {
                        log_link_warning_errno(link, r, "Cannot delete unreachable route for DHCPv6 delegated subnet %s/%u: %m",
                                               strnull(buf),
                                               pd_prefix_len);
                        continue;
                }

                log_link_debug(link, "Removing unreachable route %s/%u",
                               strnull(buf), pd_prefix_len);
        }

        return 0;
}

static int dhcp6_pd_prefix_distribute(Link *dhcp6_link,
                                      struct in6_addr *pd_prefix,
                                      uint8_t pd_prefix_len,
                                      uint32_t lifetime_preferred,
                                      uint32_t lifetime_valid,
                                      bool assign_preferred_subnet_id) {

        _cleanup_free_ char *assigned_buf = NULL, *buf = NULL;
        Manager *manager = dhcp6_link->manager;
        union in_addr_union prefix = {
                .in6 = *pd_prefix,
        };
        bool pool_depleted = false;
        uint64_t n_prefixes;
        Iterator i;
        Link *link;
        int r;

        assert(manager);
        assert(pd_prefix_len <= 64);

        r = in_addr_mask(AF_INET6, &prefix, pd_prefix_len);
        if (r < 0)
                return r;

        n_prefixes = UINT64_C(1) << (64 - pd_prefix_len);

        (void) in_addr_to_string(AF_INET6, &prefix, &buf);
        log_link_debug(dhcp6_link, "Assigning up to %" PRIu64 " prefixes from %s/%u",
                       n_prefixes, strnull(buf), pd_prefix_len);

        HASHMAP_FOREACH(link, manager->links, i) {
                union in_addr_union assigned_prefix;

                if (link == dhcp6_link)
                        continue;

                if (!dhcp6_get_prefix_delegation(link))
                        continue;

                if (assign_preferred_subnet_id != dhcp6_has_preferred_subnet_id(link))
                        continue;

                r = dhcp6_get_preferred_delegated_prefix(manager, link, &prefix.in6, pd_prefix_len,
                                                         &assigned_prefix.in6);

                if (assign_preferred_subnet_id && r == -EAGAIN) {
                        /* A link has a preferred subnet_id but that one is
                         * already taken by another link. Now all the remaining
                         * links will also not obtain a prefix. */
                        pool_depleted = true;
                        continue;
                } else if (r < 0)
                        return r;

                (void) in_addr_to_string(AF_INET6, &assigned_prefix, &assigned_buf);
                r = dhcp6_pd_prefix_assign(link, &assigned_prefix.in6, 64,
                                           lifetime_preferred, lifetime_valid);
                if (r < 0) {
                        log_link_error_errno(link, r, "Unable to assign/update prefix %s/64 from %s/%u for link: %m",
                                             strnull(assigned_buf),
                                             strnull(buf), pd_prefix_len);
                } else
                        log_link_debug(link, "Assigned prefix %s/64 from %s/%u to link",
                                       strnull(assigned_buf),
                                       strnull(buf), pd_prefix_len);
        }

        /* If one of the link requests couldn't be fulfilled, signal that we
           should try again with another prefix. */
        if (pool_depleted)
                return -EAGAIN;

        return 0;
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
                link_check_ready(link);
        }

        return 1;
}

static int dhcp6_lease_pd_prefix_acquired(sd_dhcp6_client *client, Link *link) {
        uint32_t lifetime_preferred, lifetime_valid;
        union in_addr_union pd_prefix;
        sd_dhcp6_lease *lease;
        uint8_t pd_prefix_len;
        int r;

        link->dhcp6_route_configured = false;

        r = sd_dhcp6_client_get_lease(client, &lease);
        if (r < 0)
                return r;

        sd_dhcp6_lease_reset_pd_prefix_iter(lease);

        while (sd_dhcp6_lease_get_pd(lease, &pd_prefix.in6, &pd_prefix_len,
                                     &lifetime_preferred,
                                     &lifetime_valid) >= 0) {

                _cleanup_free_ char *buf = NULL;

                (void) in_addr_to_string(AF_INET6, &pd_prefix, &buf);

                if (pd_prefix_len > 64) {
                        log_link_debug(link, "PD Prefix length > 64, ignoring prefix %s/%u",
                                       strnull(buf), pd_prefix_len);
                        continue;
                }

                if (pd_prefix_len < 48)
                        log_link_warning(link, "PD Prefix length < 48, looks unusual %s/%u",
                                       strnull(buf), pd_prefix_len);

                if (pd_prefix_len < 64) {
                        _cleanup_(route_freep) Route *route = NULL;

                        r = route_new(&route);
                        if (r < 0)
                                return r;

                        route->family = AF_INET6;
                        route->dst = pd_prefix;
                        route->dst_prefixlen = pd_prefix_len;
                        route->table = link_get_dhcp_route_table(link);
                        route->type = RTN_UNREACHABLE;

                        r = route_configure(route, link, dhcp6_route_handler);
                        if (r < 0) {
                                log_link_warning_errno(link, r, "Cannot configure unreachable route for delegated subnet %s/%u: %m",
                                                       strnull(buf),
                                                       pd_prefix_len);
                                continue;
                        }
                        if (r > 0)
                                link->dhcp6_route_messages++;

                        log_link_debug(link, "Configuring unreachable route for %s/%u",
                                       strnull(buf), pd_prefix_len);
                } else
                        log_link_debug(link, "Not adding a blocking route since distributed prefix is /64");

                /* We are doing prefix allocation in two steps:
                 * 1. all those links that have a preferred subnet id will be assigned their subnet
                 * 2. all those links that remain will receive prefixes in sequential
                 *    order. Prefixes that were previously already allocated to another
                 *    link will be skipped.

                 * If a subnet id request couldn't be fulfilled the failure will be logged (as error)
                 * and no further attempts at obtaining a prefix will be made.

                 * The assignment has to be split in two phases since subnet id
                 * preferences should be honored. Meaning that any subnet id should be
                 * handed out to the requesting link and not to some link that didn't
                 * specify any preference. */

                r = dhcp6_pd_prefix_distribute(link, &pd_prefix.in6,
                                               pd_prefix_len,
                                               lifetime_preferred,
                                               lifetime_valid,
                                               true);
                if (r < 0 && r != -EAGAIN)
                        return r;

                /* if r == -EAGAIN then the allocation failed because we ran
                 * out of addresses for the preferred subnet id's. This doesn't
                 * mean we can't fulfill other prefix requests.
                 *
                 * Since we do not have dedicated lists of links that request
                 * specific subnet id's and those that accept any prefix we
                 * *must* reset the iterator to the start as otherwise some
                 * links might not get their requested prefix. */

                r = dhcp6_pd_prefix_distribute(link, &pd_prefix.in6,
                                               pd_prefix_len,
                                               lifetime_preferred,
                                               lifetime_valid,
                                               false);
                if (r < 0 && r != -EAGAIN)
                        return r;

                /* If the prefix distribution did return -EAGAIN we will try to
                 * fulfill those with the next available pd delegated prefix. */
        }

        if (link->dhcp6_route_messages == 0) {
                link->dhcp6_route_configured = true;
                link_check_ready(link);
        } else {
                log_link_debug(link, "Setting unreachable routes for DHCPv6 delegated subnets");
                link_set_state(link, LINK_STATE_CONFIGURING);
        }

        return 0;
}

int dhcp6_request_prefix_delegation(Link *link) {
        Link *l;
        Iterator i;

        assert_return(link, -EINVAL);
        assert_return(link->manager, -EOPNOTSUPP);

        if (dhcp6_get_prefix_delegation(link) <= 0)
                return 0;

        log_link_debug(link, "Requesting DHCPv6 prefixes to be delegated for new link");

        HASHMAP_FOREACH(l, link->manager->links, i) {
                int r, enabled;

                if (l == link)
                        continue;

                if (!l->dhcp6_client)
                        continue;

                r = sd_dhcp6_client_get_prefix_delegation(l->dhcp6_client, &enabled);
                if (r < 0) {
                        log_link_warning_errno(l, r, "Cannot get prefix delegation when adding new link: %m");
                        continue;
                }

                if (enabled == 0) {
                        r = sd_dhcp6_client_set_prefix_delegation(l->dhcp6_client, 1);
                        if (r < 0) {
                                log_link_warning_errno(l, r, "Cannot enable prefix delegation when adding new link: %m");
                                continue;
                        }
                }

                r = sd_dhcp6_client_is_running(l->dhcp6_client);
                if (r <= 0)
                        continue;

                if (enabled != 0) {
                        log_link_debug(l, "Requesting re-assignment of delegated prefixes after adding new link");
                        (void) dhcp6_lease_pd_prefix_acquired(l->dhcp6_client, l);

                        continue;
                }

                r = sd_dhcp6_client_stop(l->dhcp6_client);
                if (r < 0) {
                        log_link_warning_errno(l, r, "Cannot stop DHCPv6 prefix delegation client after adding new link: %m");
                        continue;
                }

                r = sd_dhcp6_client_start(l->dhcp6_client);
                if (r < 0) {
                        log_link_warning_errno(l, r, "Cannot restart DHCPv6 prefix delegation client after adding new link: %m");
                        continue;
                }

                log_link_debug(l, "Restarted DHCPv6 client to acquire prefix delegations after adding new link");
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
                r = link_request_set_routes(link);
                if (r < 0) {
                        link_enter_failed(link);
                        return 1;
                }
        }

        return 1;
}

static int dhcp6_address_change(
                Link *link,
                struct in6_addr *ip6_addr,
                uint32_t lifetime_preferred,
                uint32_t lifetime_valid) {

        _cleanup_(address_freep) Address *addr = NULL;
        _cleanup_free_ char *buffer = NULL;
        int r;

        r = address_new(&addr);
        if (r < 0)
                return r;

        addr->family = AF_INET6;
        addr->in_addr.in6 = *ip6_addr;
        addr->flags = IFA_F_NOPREFIXROUTE;
        addr->prefixlen = 128;
        addr->cinfo.ifa_prefered = lifetime_preferred;
        addr->cinfo.ifa_valid = lifetime_valid;

        (void) in_addr_to_string(addr->family, &addr->in_addr, &buffer);
        log_link_info(link,
                      "DHCPv6 address %s/%d timeout preferred %d valid %d",
                      strnull(buffer), addr->prefixlen, lifetime_preferred, lifetime_valid);

        r = address_configure(addr, link, dhcp6_address_handler, true);
        if (r < 0)
                return log_link_warning_errno(link, r, "Could not assign DHCPv6 address: %m");
        if (r > 0)
                link->dhcp6_address_messages++;

        return 0;
}

static int dhcp6_lease_address_acquired(sd_dhcp6_client *client, Link *link) {
        int r;
        sd_dhcp6_lease *lease;
        struct in6_addr ip6_addr;
        uint32_t lifetime_preferred, lifetime_valid;

        link->dhcp6_address_configured = false;

        r = sd_dhcp6_client_get_lease(client, &lease);
        if (r < 0)
                return r;

        sd_dhcp6_lease_reset_address_iter(lease);
        while (sd_dhcp6_lease_get_address(lease, &ip6_addr,
                                                 &lifetime_preferred,
                                                 &lifetime_valid) >= 0) {

                r = dhcp6_address_change(link, &ip6_addr, lifetime_preferred, lifetime_valid);
                if (r < 0)
                        return r;
        }

        if (link->dhcp6_address_messages == 0) {
                link->dhcp6_address_configured = true;
                return link_request_set_routes(link);
        } else {
                log_link_debug(link, "Setting DHCPv6 addresses");
                /* address_handler calls link_request_set_routes() and link_request_set_nexthop().
                 * Before they are called, the related flags must be cleared. Otherwise, the link
                 * becomes configured state before routes are configured. */
                link->static_routes_configured = false;
                link->static_nexthops_configured = false;
                link_set_state(link, LINK_STATE_CONFIGURING);
        }

        return 0;
}

static void dhcp6_handler(sd_dhcp6_client *client, int event, void *userdata) {
        int r;
        Link *link = userdata;

        assert(link);
        assert(link->network);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return;

        switch(event) {
        case SD_DHCP6_CLIENT_EVENT_STOP:
        case SD_DHCP6_CLIENT_EVENT_RESEND_EXPIRE:
        case SD_DHCP6_CLIENT_EVENT_RETRANS_MAX:
                if (sd_dhcp6_client_get_lease(client, NULL) >= 0)
                        log_link_warning(link, "DHCPv6 lease lost");

                (void) dhcp6_lease_pd_prefix_lost(client, link);
                (void) dhcp6_prefix_remove_all(link->manager, link);

                link_dirty(link);
                break;

        case SD_DHCP6_CLIENT_EVENT_IP_ACQUIRE:
                r = dhcp6_lease_address_acquired(client, link);
                if (r < 0) {
                        link_enter_failed(link);
                        return;
                }

                r = dhcp6_lease_pd_prefix_acquired(client, link);
                if (r < 0)
                        log_link_debug_errno(link, r, "DHCPv6 did not receive prefixes to delegate: %m");

                _fallthrough_;
        case SD_DHCP6_CLIENT_EVENT_INFORMATION_REQUEST:
                r = dhcp6_lease_information_acquired(client, link);
                if (r < 0) {
                        link_enter_failed(link);
                        return;
                }

                link_dirty(link);
                break;

        default:
                if (event < 0)
                        log_link_warning_errno(link, event, "DHCPv6 error: %m");
                else
                        log_link_warning(link, "DHCPv6 unknown event: %d", event);
                return;
        }

        link_check_ready(link);
}

int dhcp6_request_address(Link *link, int ir) {
        int r, inf_req, pd;
        bool running;

        assert(link);
        assert(link->dhcp6_client);
        assert(link->network);
        assert(in_addr_is_link_local(AF_INET6, (const union in_addr_union*)&link->ipv6ll_address) > 0);

        r = sd_dhcp6_client_is_running(link->dhcp6_client);
        if (r < 0)
                return r;
        running = r;

        r = sd_dhcp6_client_get_prefix_delegation(link->dhcp6_client, &pd);
        if (r < 0)
                return r;

        if (pd && ir && link->network->dhcp6_force_pd_other_information) {
                log_link_debug(link, "Enabling managed mode to request DHCPv6 PD with 'Other Information' set");

                r = sd_dhcp6_client_set_address_request(link->dhcp6_client,
                                                        false);
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

int dhcp6_configure(Link *link) {
        _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client = NULL;
        sd_dhcp6_option *vendor_option;
        sd_dhcp6_option *send_option;
        void *request_options;
        const DUID *duid;
        Iterator i;
        int r;

        assert(link);
        assert(link->network);

        if (link->dhcp6_client)
                return 0;

        r = sd_dhcp6_client_new(&client);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP6 CLIENT: Failed to create DHCP6 client: %m");

        r = sd_dhcp6_client_attach_event(client, NULL, 0);
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP6 CLIENT: Failed to attach event: %m");

        r = sd_dhcp6_client_set_mac(client,
                                    (const uint8_t *) &link->mac,
                                    sizeof (link->mac), ARPHRD_ETHER);
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP6 CLIENT: Failed to set MAC address: %m");

        if (link->network->iaid_set) {
                r = sd_dhcp6_client_set_iaid(client, link->network->iaid);
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP6 CLIENT: Failed to set IAID: %m");
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
                return log_link_error_errno(link, r, "DHCP6 CLIENT: Failed to set DUID: %m");

        ORDERED_HASHMAP_FOREACH(send_option, link->network->dhcp6_client_send_options, i) {
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

        if (link->network->rapid_commit) {
                r = sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_RAPID_COMMIT);
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP6 CLIENT: Failed to set request flag for rapid commit: %m");
        }

        if (link->network->dhcp6_mudurl) {
                r = sd_dhcp6_client_set_request_mud_url(client, link->network->dhcp6_mudurl);
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP6 CLIENT: Failed to set MUD URL: %m");
        }

        SET_FOREACH(request_options, link->network->dhcp6_request_options, i) {
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

        ORDERED_HASHMAP_FOREACH(vendor_option, link->network->dhcp6_client_send_vendor_options, i) {
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

static Link *dhcp6_prefix_get(Manager *m, struct in6_addr *addr) {
        assert_return(m, NULL);
        assert_return(addr, NULL);

        return hashmap_get(m->dhcp6_prefixes, addr);
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
                link->dhcp6_pd_route_configured = true;
                link_check_ready(link);
        }

        return 1;
}

static int dhcp6_prefix_add(Manager *m, struct in6_addr *addr, Link *link) {
        _cleanup_(route_freep) Route *route = NULL;
        _cleanup_free_ struct in6_addr *a = NULL;
        _cleanup_free_ char *buf = NULL;
        Link *assigned_link;
        int r;

        assert_return(m, -EINVAL);
        assert_return(addr, -EINVAL);

        r = route_new(&route);
        if (r < 0)
                return r;

        route->family = AF_INET6;
        route->dst.in6 = *addr;
        route->dst_prefixlen = 64;

        link->dhcp6_pd_route_configured = false;
        link_set_state(link, LINK_STATE_CONFIGURING);

        r = route_configure(route, link, dhcp6_pd_route_handler);
        if (r < 0)
                return r;
        if (r > 0)
                link->dhcp6_pd_route_messages++;

        (void) in_addr_to_string(AF_INET6, (union in_addr_union *) addr, &buf);
        log_link_debug(link, "Adding prefix route %s/64", strnull(buf));

        assigned_link = hashmap_get(m->dhcp6_prefixes, addr);
        if (assigned_link) {
                assert(assigned_link == link);
                return 0;
        }

        a = newdup(struct in6_addr, addr, 1);
        if (!a)
                return -ENOMEM;

        r = hashmap_ensure_allocated(&m->dhcp6_prefixes, &in6_addr_hash_ops);
        if (r < 0)
                return r;

        r = hashmap_put(m->dhcp6_prefixes, a, link);
        if (r < 0)
                return r;

        TAKE_PTR(a);
        link_ref(link);
        return 0;
}

static int dhcp6_prefix_remove_handler(sd_netlink *nl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0) {
                log_link_message_warning_errno(link, m, r, "Received error on DHCPv6 Prefix Delegation route removal");
                link_enter_failed(link);
                return 1;
        }

        return 1;
}

int dhcp6_prefix_remove(Manager *m, struct in6_addr *addr) {
        _cleanup_free_ struct in6_addr *a = NULL;
        _cleanup_(link_unrefp) Link *l = NULL;
        _cleanup_(route_freep) Route *route = NULL;
        _cleanup_free_ char *buf = NULL;
        int r;

        assert_return(m, -EINVAL);
        assert_return(addr, -EINVAL);

        l = hashmap_remove2(m->dhcp6_prefixes, addr, (void **) &a);
        if (!l)
                return -EINVAL;

        (void) sd_radv_remove_prefix(l->radv, addr, 64);

        r = route_new(&route);
        if (r < 0)
                return r;

        route->family = AF_INET6;
        route->dst.in6 = *addr;
        route->dst_prefixlen = 64;

        r = route_remove(route, l, dhcp6_prefix_remove_handler);
        if (r < 0)
                return r;

        (void) in_addr_to_string(AF_INET6, (union in_addr_union *) addr, &buf);
        log_link_debug(l, "Removing prefix route %s/64", strnull(buf));

        return 0;
}

static int dhcp6_prefix_remove_all(Manager *m, Link *link) {
        struct in6_addr *addr;
        Iterator i;
        Link *l;

        assert_return(m, -EINVAL);
        assert_return(link, -EINVAL);

        HASHMAP_FOREACH_KEY(l, addr, m->dhcp6_prefixes, i)
                if (l == link)
                        (void) dhcp6_prefix_remove(m, addr);

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
                link->dhcp6_pd_address_configured = true;
                r = link_request_set_routes(link);
                if (r < 0) {
                        link_enter_failed(link);
                        return 1;
                }
        }

        return 1;
}

static int dhcp6_assign_delegated_prefix(Link *link,
                                         const struct in6_addr *prefix,
                                         uint8_t prefix_len,
                                         uint32_t lifetime_preferred,
                                         uint32_t lifetime_valid) {

        _cleanup_(address_freep) Address *address = NULL;
        int r;

        assert(link);
        assert(link->network);
        assert(prefix);

        if (!link->network->dhcp6_pd_assign_prefix) {
                link->dhcp6_pd_address_configured = true;
                return 0;
        }

        r = address_new(&address);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to allocate address for DHCPv6 delegated prefix: %m");

        address->in_addr.in6 = *prefix;

        if (!in_addr_is_null(AF_INET6, &link->network->dhcp6_delegation_prefix_token))
                memcpy(address->in_addr.in6.s6_addr + 8, link->network->dhcp6_delegation_prefix_token.in6.s6_addr + 8, 8);
        else {
                r = generate_ipv6_eui_64_address(link, &address->in_addr.in6);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Failed to generate EUI64 address for acquired DHCPv6 delegated prefix: %m");
        }

        address->prefixlen = prefix_len;
        address->family = AF_INET6;
        address->cinfo.ifa_prefered = lifetime_preferred;
        address->cinfo.ifa_valid = lifetime_valid;

        /* address_handler calls link_request_set_routes() and link_request_set_nexthop(). Before they
         * are called, the related flags must be cleared. Otherwise, the link becomes configured state
         * before routes are configured. */
        link->static_routes_configured = false;
        link->static_nexthops_configured = false;
        link->dhcp6_pd_address_configured = false;
        link_set_state(link, LINK_STATE_CONFIGURING);

        r = address_configure(address, link, dhcp6_pd_address_handler, true);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to set acquired DHCPv6 delegated prefix address: %m");
        if (r > 0)
                link->dhcp6_pd_address_messages++;

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
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = in_addr_prefix_from_string(rvalue, AF_INET6, (union in_addr_union *) &network->dhcp6_pd_address, &network->dhcp6_pd_length);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse PrefixDelegationHint=%s, ignoring assignment", rvalue);
                return 0;
        }

        if (network->dhcp6_pd_length < 1 || network->dhcp6_pd_length > 128) {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Invalid prefix length='%d', ignoring assignment", network->dhcp6_pd_length);
                network->dhcp6_pd_length = 0;
                return 0;
        }

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

int config_parse_dhcp6_delegated_prefix_token(
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

        Network *network = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                network->dhcp6_delegation_prefix_token = IN_ADDR_NULL;
                return 0;
        }

        r = in_addr_from_string(AF_INET6, rvalue, &network->dhcp6_delegation_prefix_token);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse DHCPv6 %s, ignoring: %s", lvalue, rvalue);
                return 0;
        }

        if (in_addr_is_null(AF_INET6, &network->dhcp6_delegation_prefix_token)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "DHCPv6 %s cannot be the ANY address, ignoring: %s", lvalue, rvalue);
                return 0;
        }

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
