/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  Copyright © 2014 Intel Corporation. All rights reserved.
***/

#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include "sd-radv.h"

#include "sd-dhcp6-client.h"

#include "hashmap.h"
#include "hostname-util.h"
#include "missing_network.h"
#include "network-internal.h"
#include "networkd-dhcp6.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "siphash24.h"
#include "string-util.h"
#include "radv-internal.h"

static int dhcp6_lease_address_acquired(sd_dhcp6_client *client, Link *link);
static Link *dhcp6_prefix_get(Manager *m, struct in6_addr *addr);
static int dhcp6_prefix_add(Manager *m, struct in6_addr *addr, Link *link);
static int dhcp6_prefix_remove_all(Manager *m, Link *link);

static bool dhcp6_get_prefix_delegation(Link *link) {
        if (!link->network)
                return false;

        return IN_SET(link->network->router_prefix_delegation,
                      RADV_PREFIX_DELEGATION_DHCP6,
                      RADV_PREFIX_DELEGATION_BOTH);
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

static int dhcp6_lease_information_acquired(sd_dhcp6_client *client,
                                        Link *link) {
        return 0;
}

static int dhcp6_pd_prefix_assign(Link *link, struct in6_addr *prefix,
                                  uint8_t prefix_len,
                                  uint32_t lifetime_preferred,
                                  uint32_t lifetime_valid) {
        sd_radv *radv = link->radv;
        int r;
        _cleanup_(sd_radv_prefix_unrefp) sd_radv_prefix *p = NULL;

        r = sd_radv_prefix_new(&p);
        if (r < 0)
                return r;

        r = sd_radv_prefix_set_prefix(p, prefix, prefix_len);
        if (r < 0)
                return r;

        r = sd_radv_prefix_set_preferred_lifetime(p, lifetime_preferred);
        if (r < 0)
                return r;

        r = sd_radv_prefix_set_valid_lifetime(p, lifetime_valid);
        if (r < 0)
                return r;

        r = sd_radv_stop(radv);
        if (r < 0)
                return r;

        r = sd_radv_add_prefix(radv, p, true);
        if (r < 0 && r != -EEXIST)
                return r;

        r = dhcp6_prefix_add(link->manager, prefix, link);
        if (r < 0)
                return r;

        return sd_radv_start(radv);
}

static int dhcp6_route_remove_handler(sd_netlink *nl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0)
                log_link_debug_errno(link, r, "Received error on unreachable route removal for DHCPv6 delegated subnet: %m");

        return 1;
}

int dhcp6_lease_pd_prefix_lost(sd_dhcp6_client *client, Link* link) {
        int r;
        sd_dhcp6_lease *lease;
        union in_addr_union pd_prefix;
        uint8_t pd_prefix_len;
        uint32_t lifetime_preferred, lifetime_valid;

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

static int dhcp6_pd_prefix_distribute(Link *dhcp6_link, Iterator *i,
                                      struct in6_addr *pd_prefix,
                                      uint8_t pd_prefix_len,
                                      uint32_t lifetime_preferred,
                                      uint32_t lifetime_valid) {
        Link *link;
        Manager *manager = dhcp6_link->manager;
        union in_addr_union prefix;
        uint64_t n_prefixes, n_used = 0;
        _cleanup_free_ char *buf = NULL;
        _cleanup_free_ char *assigned_buf = NULL;
        int r;

        assert(manager);
        assert(pd_prefix_len <= 64);

        prefix.in6 = *pd_prefix;

        r = in_addr_mask(AF_INET6, &prefix, pd_prefix_len);
        if (r < 0)
                return r;

        n_prefixes = UINT64_C(1) << (64 - pd_prefix_len);

        (void) in_addr_to_string(AF_INET6, &prefix, &buf);
        log_link_debug(dhcp6_link, "Assigning up to %" PRIu64 " prefixes from %s/%u",
                       n_prefixes, strnull(buf), pd_prefix_len);

        while (hashmap_iterate(manager->links, i, (void **)&link, NULL)) {
                Link *assigned_link;

                if (n_used == n_prefixes) {
                        log_link_debug(dhcp6_link, "Assigned %" PRIu64 "/%" PRIu64 " prefixes from %s/%u",
                                       n_used, n_prefixes, strnull(buf), pd_prefix_len);

                        return -EAGAIN;
                }

                if (link == dhcp6_link)
                        continue;

                if (!dhcp6_get_prefix_delegation(link))
                        continue;

                assigned_link = dhcp6_prefix_get(manager, &prefix.in6);
                if (assigned_link && assigned_link != link)
                        continue;

                (void) in_addr_to_string(AF_INET6, &prefix, &assigned_buf);
                r = dhcp6_pd_prefix_assign(link, &prefix.in6, 64,
                                           lifetime_preferred, lifetime_valid);
                if (r < 0) {
                        log_link_error_errno(link, r, "Unable to %s prefix %s/64 from %s/%u for link: %m",
                                             assigned_link ? "update": "assign",
                                             strnull(assigned_buf),
                                             strnull(buf), pd_prefix_len);

                        if (!assigned_link)
                                continue;

                } else
                        log_link_debug(link, "Assigned prefix %" PRIu64 "/%" PRIu64 " %s/64 from %s/%u to link",
                                       n_used + 1, n_prefixes,
                                       strnull(assigned_buf),
                                       strnull(buf), pd_prefix_len);

                n_used++;

                r = in_addr_prefix_next(AF_INET6, &prefix, 64);
                if (r < 0 && n_used < n_prefixes)
                        return r;
        }

        return 0;
}

static int dhcp6_route_handler(sd_netlink *nl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST)
                log_link_debug_errno(link, r, "Received error when adding unreachable route for DHCPv6 delegated subnet: %m");

        return 1;
}

static int dhcp6_lease_pd_prefix_acquired(sd_dhcp6_client *client, Link *link) {
        int r;
        sd_dhcp6_lease *lease;
        union in_addr_union pd_prefix;
        uint8_t pd_prefix_len;
        uint32_t lifetime_preferred, lifetime_valid;
        Iterator i = ITERATOR_FIRST;

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

                        log_link_debug(link, "Configuring unreachable route for %s/%u",
                                       strnull(buf), pd_prefix_len);
                } else
                        log_link_debug(link, "Not adding a blocking route since distributed prefix is /64");

                r = dhcp6_pd_prefix_distribute(link, &i, &pd_prefix.in6,
                                               pd_prefix_len,
                                               lifetime_preferred,
                                               lifetime_valid);
                if (r < 0 && r != -EAGAIN)
                        return r;

                if (r >= 0)
                        i = ITERATOR_FIRST;
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
                        log_link_warning_errno(l, r, "Cannot get prefix delegation when adding new link");
                        continue;
                }

                if (enabled == 0) {
                        r = sd_dhcp6_client_set_prefix_delegation(l->dhcp6_client, 1);
                        if (r < 0) {
                                log_link_warning_errno(l, r, "Cannot enable prefix delegation when adding new link");
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
                        log_link_warning_errno(l, r, "Cannot stop DHCPv6 prefix delegation client after adding new link");
                        continue;
                }

                r = sd_dhcp6_client_start(l->dhcp6_client);
                if (r < 0) {
                        log_link_warning_errno(l, r, "Cannot restart DHCPv6 prefix delegation client after adding new link");
                        continue;
                }

                log_link_debug(l, "Restarted DHCPv6 client to acquire prefix delegations after adding new link");
        }

        return 0;
}

static int dhcp6_address_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_error_errno(link, r, "Could not set DHCPv6 address: %m");
                link_enter_failed(link);
                return 1;
        } else if (r >= 0)
                (void) manager_rtnl_process_address(rtnl, m, link->manager);

        r = link_request_set_routes(link);
        if (r < 0) {
                link_enter_failed(link);
                return 1;
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

        return 0;
}

static int dhcp6_lease_address_acquired(sd_dhcp6_client *client, Link *link) {
        int r;
        sd_dhcp6_lease *lease;
        struct in6_addr ip6_addr;
        uint32_t lifetime_preferred, lifetime_valid;

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
                link->dhcp6_configured = false;
                break;

        case SD_DHCP6_CLIENT_EVENT_IP_ACQUIRE:
                r = dhcp6_lease_address_acquired(client, link);
                if (r < 0) {
                        link_enter_failed(link);
                        return;
                }

                r = dhcp6_lease_pd_prefix_acquired(client, link);
                if (r < 0)
                        log_link_debug(link, "DHCPv6 did not receive prefixes to delegate");

                _fallthrough_;
        case SD_DHCP6_CLIENT_EVENT_INFORMATION_REQUEST:
                r = dhcp6_lease_information_acquired(client, link);
                if (r < 0) {
                        link_enter_failed(link);
                        return;
                }

                link_dirty(link);
                link->dhcp6_configured = true;
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
                if (r < 0 )
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
        const DUID *duid;
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

        r = sd_dhcp6_client_set_callback(client, dhcp6_handler, link);
        if (r < 0)
                return log_link_error_errno(link, r, "DHCP6 CLIENT: Failed to set callback: %m");

        if (dhcp6_enable_prefix_delegation(link)) {
                r = sd_dhcp6_client_set_prefix_delegation(client, true);
                if (r < 0)
                        return log_link_error_errno(link, r, "DHCP6 CLIENT: Failed to set prefix delegation: %m");
        }

        link->dhcp6_client = TAKE_PTR(client);

        return 0;
}

static Link *dhcp6_prefix_get(Manager *m, struct in6_addr *addr) {
        assert_return(m, NULL);
        assert_return(addr, NULL);

        return hashmap_get(m->dhcp6_prefixes, addr);
}

static int dhcp6_route_add_handler(sd_netlink *nl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_debug_errno(link, r, "Received error adding DHCPv6 Prefix Delegation route: %m");
                link_enter_failed(link);
                return 1;
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

        r = route_configure(route, link, dhcp6_route_add_handler);
        if (r < 0)
                return r;

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
                log_link_debug_errno(link, r, "Received error on DHCPv6 Prefix Delegation route removal: %m");
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
