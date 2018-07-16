/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  Copyright © 2014 Intel Corporation. All rights reserved.
***/

#include <netinet/ether.h>
#include <linux/if.h>
#include "sd-radv.h"

#include "sd-dhcp6-client.h"

#include "hashmap.h"
#include "hostname-util.h"
#include "network-internal.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "siphash24.h"
#include "string-util.h"
#include "radv-internal.h"

static int dhcp6_lease_address_acquired(sd_dhcp6_client *client, Link *link);

static bool dhcp6_verify_link(Link *link) {
        if (!link->network) {
                log_link_info(link, "Link is not managed by us");
                return false;
        }

        if (!IN_SET(link->network->router_prefix_delegation,
                            RADV_PREFIX_DELEGATION_DHCP6,
                            RADV_PREFIX_DELEGATION_BOTH)) {
                log_link_debug(link, "Link does not request DHCPv6 prefix delegation");
                return false;
        }

        return true;
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

                if (!dhcp6_verify_link(l))
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

        r = manager_dhcp6_prefix_add(link->manager, &p->opt.in6_addr, link);
        if (r < 0)
                return r;

        return sd_radv_start(radv);
}

static Network *dhcp6_reset_pd_prefix_network(Link *link) {
        assert(link);
        assert(link->manager);
        assert(link->manager->networks);

        return link->manager->networks;
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
        int r;

        assert(manager);
        assert(pd_prefix_len <= 64);

        prefix.in6 = *pd_prefix;

        r = in_addr_mask(AF_INET6, &prefix, pd_prefix_len);
        if (r < 0)
                return r;

        n_prefixes = 1 << (64 - pd_prefix_len);

        (void) in_addr_to_string(AF_INET6, &prefix, &buf);
        log_link_debug(dhcp6_link, "Assigning up to %lu prefixes from %s/%u",
                       n_prefixes, strnull(buf), pd_prefix_len);

        while (hashmap_iterate(manager->links, i, (void **)&link, NULL)) {
                Link *assigned_link;

                if (n_used == n_prefixes) {
                        log_link_debug(dhcp6_link, "Assigned %lu/%lu prefixes from %s/%u",
                                       n_used, n_prefixes, strnull(buf), pd_prefix_len);

                        return -EAGAIN;
                }

                if (link == dhcp6_link)
                        continue;

                if (!dhcp6_verify_link(link))
                        continue;

                assigned_link = manager_dhcp6_prefix_get(manager, &prefix.in6);
                if (assigned_link != NULL && assigned_link != link)
                        continue;

                r = dhcp6_pd_prefix_assign(link, &prefix.in6, 64,
                                           lifetime_preferred, lifetime_valid);
                if (r < 0) {
                        log_link_error_errno(link, r, "Unable to %s prefix %s/%u for link: %m",
                                             assigned_link ? "update": "assign",
                                             strnull(buf), pd_prefix_len);

                        if (assigned_link == NULL)
                                continue;

                } else
                        log_link_debug(link, "Assigned prefix %lu/%lu %s/64 to link",
                                       n_used + 1, n_prefixes, strnull(buf));

                n_used++;

                r = in_addr_prefix_next(AF_INET6, &prefix, pd_prefix_len);
                if (r < 0 && n_used < n_prefixes)
                        return r;
        }

        if (n_used < n_prefixes) {
                Route *route;
                uint64_t n = n_used;

                r = route_new(&route);
                if (r < 0)
                        return r;

                route->family = AF_INET6;

                while (n < n_prefixes) {
                        route_update(route, &prefix, pd_prefix_len, NULL, NULL,
                                     0, 0, RTN_UNREACHABLE);

                        r = route_configure(route, dhcp6_link, NULL);
                        if (r < 0) {
                                route_free(route);
                                return r;
                        }

                        r = in_addr_prefix_next(AF_INET6, &prefix, pd_prefix_len);
                        if (r < 0)
                                return r;
                }
        }

        return n_used;
}

static int dhcp6_lease_pd_prefix_acquired(sd_dhcp6_client *client, Link *link) {
        int r;
        sd_dhcp6_lease *lease;
        struct in6_addr pd_prefix;
        uint8_t pd_prefix_len;
        uint32_t lifetime_preferred, lifetime_valid;
        _cleanup_free_ char *buf = NULL;
        Iterator i = ITERATOR_FIRST;

        r = sd_dhcp6_client_get_lease(client, &lease);
        if (r < 0)
                return r;

        (void) in_addr_to_string(AF_INET6, (union in_addr_union*) &pd_prefix, &buf);

        dhcp6_reset_pd_prefix_network(link);
        sd_dhcp6_lease_reset_pd_prefix_iter(lease);

        while (sd_dhcp6_lease_get_pd(lease, &pd_prefix, &pd_prefix_len,
                                     &lifetime_preferred,
                                     &lifetime_valid) >= 0) {

                if (pd_prefix_len > 64) {
                        log_link_debug(link, "PD Prefix length > 64, ignoring prefix %s/%u",
                                       strnull(buf), pd_prefix_len);
                        continue;
                }

                r = dhcp6_pd_prefix_distribute(link, &i, &pd_prefix,
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

static int dhcp6_address_handler(sd_netlink *rtnl, sd_netlink_message *m,
                                 void *userdata) {
        _cleanup_(link_unrefp) Link *link = userdata;
        int r;

        assert(link);

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                if (link->rtnl_extended_attrs) {
                        log_link_warning(link, "Could not set extended netlink attributes, reverting to fallback mechanism");

                        link->rtnl_extended_attrs = false;
                        dhcp6_lease_address_acquired(link->dhcp6_client, link);

                        return 1;
                }

                log_link_error_errno(link, r, "Could not set DHCPv6 address: %m");

                link_enter_failed(link);

        } else if (r >= 0)
                manager_rtnl_process_address(rtnl, m, link->manager);

        return 1;
}

static int dhcp6_address_change(
                Link *link,
                struct in6_addr *ip6_addr,
                uint32_t lifetime_preferred,
                uint32_t lifetime_valid) {

        _cleanup_(address_freep) Address *addr = NULL;
        char buffer[INET6_ADDRSTRLEN];
        int r;

        r = address_new(&addr);
        if (r < 0)
                return r;

        addr->family = AF_INET6;
        memcpy(&addr->in_addr.in6, ip6_addr, sizeof(*ip6_addr));

        addr->flags = IFA_F_NOPREFIXROUTE;
        addr->prefixlen = 128;

        addr->cinfo.ifa_prefered = lifetime_preferred;
        addr->cinfo.ifa_valid = lifetime_valid;

        log_link_info(link,
                      "DHCPv6 address %s/%d timeout preferred %d valid %d",
                      inet_ntop(AF_INET6, &addr->in_addr.in6, buffer, sizeof(buffer)),
                      addr->prefixlen, lifetime_preferred, lifetime_valid);

        r = address_configure(addr, link, dhcp6_address_handler, true);
        if (r < 0)
                log_link_warning_errno(link, r, "Could not assign DHCPv6 address: %m");

        return r;
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

                (void) manager_dhcp6_prefix_remove_all(link->manager, link);

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
        int r, inf_req;
        bool running;

        assert(link);
        assert(link->dhcp6_client);
        assert(in_addr_is_link_local(AF_INET6, (const union in_addr_union*)&link->ipv6ll_address) > 0);

        r = sd_dhcp6_client_is_running(link->dhcp6_client);
        if (r < 0)
                return r;
        else
                running = r;

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

        return sd_dhcp6_client_set_fqdn(client, hn);
}

int dhcp6_configure(Link *link) {
        sd_dhcp6_client *client = NULL;
        const DUID *duid;
        int r;

        assert(link);
        assert(link->network);

        if (link->dhcp6_client)
                return 0;

        r = sd_dhcp6_client_new(&client);
        if (r < 0)
                return r;

        r = sd_dhcp6_client_attach_event(client, NULL, 0);
        if (r < 0)
                goto error;

        r = sd_dhcp6_client_set_mac(client,
                                    (const uint8_t *) &link->mac,
                                    sizeof (link->mac), ARPHRD_ETHER);
        if (r < 0)
                goto error;

        r = sd_dhcp6_client_set_iaid(client, link->network->iaid);
        if (r < 0)
                goto error;

        duid = link_duid(link);
        r = sd_dhcp6_client_set_duid(client,
                                     duid->type,
                                     duid->raw_data_len > 0 ? duid->raw_data : NULL,
                                     duid->raw_data_len);
        if (r < 0)
                goto error;

        r = dhcp6_set_hostname(client, link);
        if (r < 0)
                goto error;

        r = sd_dhcp6_client_set_ifindex(client, link->ifindex);
        if (r < 0)
                goto error;

        if (link->network->rapid_commit) {
                r = sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_RAPID_COMMIT);
                if (r < 0)
                        goto error;
        }

        r = sd_dhcp6_client_set_callback(client, dhcp6_handler, link);
        if (r < 0)
                goto error;

        if (dhcp6_enable_prefix_delegation(link)) {
                r = sd_dhcp6_client_set_prefix_delegation(client, true);
                if (r < 0)
                        goto error;
        }

        link->dhcp6_client = client;

        return 0;

error:
        sd_dhcp6_client_unref(client);
        return r;
}
