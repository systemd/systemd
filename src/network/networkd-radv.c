/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright (C) 2017 Intel Corporation. All rights reserved.

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <netinet/icmp6.h>
#include <arpa/inet.h>

#include "networkd-address.h"
#include "networkd-manager.h"
#include "networkd-radv.h"
#include "sd-radv.h"

static int radv_get_ip6dns(Network *network, struct in6_addr **dns,
                           size_t *n_dns) {
        _cleanup_free_ struct in6_addr *addresses = NULL;
        size_t i, n_addresses = 0, n_allocated = 0;

        assert(network);
        assert(dns);
        assert(n_dns);

        for (i = 0; i < network->n_dns; i++) {
                union in_addr_union *addr;

                if (network->dns[i].family != AF_INET6)
                        continue;

                addr = &network->dns[i].address;

                if (in_addr_is_null(AF_INET6, addr) ||
                    in_addr_is_link_local(AF_INET6, addr) ||
                    in_addr_is_localhost(AF_INET6, addr))
                        continue;

                if (!GREEDY_REALLOC(addresses, n_allocated, n_addresses + 1))
                        return -ENOMEM;

                addresses[n_addresses++] = addr->in6;
        }

        if (addresses) {
                *dns = addresses;
                addresses = NULL;

                *n_dns = n_addresses;
        }

        return n_addresses;
}

static int radv_set_dns(Link *link, Link *uplink) {
        _cleanup_free_ struct in6_addr *dns = NULL;
        size_t n_dns;
        usec_t lifetime_usec;
        int r;

        if (!link->network->router_emit_dns)
                return 0;

        if (link->network->router_dns) {
                dns = newdup(struct in6_addr, link->network->router_dns,
                             link->network->n_router_dns);
                if (dns == NULL)
                        return -ENOMEM;

                n_dns = link->network->n_router_dns;
                lifetime_usec = link->network->router_dns_lifetime_usec;

                goto set_dns;
        }

        lifetime_usec = SD_RADV_DEFAULT_DNS_LIFETIME_USEC;

        r = radv_get_ip6dns(link->network, &dns, &n_dns);
        if (r > 0)
                goto set_dns;

        if (uplink) {
                if (uplink->network == NULL) {
                        log_link_debug(uplink, "Cannot fetch DNS servers as uplink interface is not managed by us");
                        return 0;
                }

                r = radv_get_ip6dns(uplink->network, &dns, &n_dns);
                if (r > 0)
                        goto set_dns;
        }

        return 0;

 set_dns:
        return sd_radv_set_rdnss(link->radv,
                                 DIV_ROUND_UP(lifetime_usec, USEC_PER_SEC),
                                 dns, n_dns);
}

static int radv_set_domains(Link *link, Link *uplink) {
        char **search_domains;
        usec_t lifetime_usec;

        if (!link->network->router_emit_domains)
                return 0;

        search_domains = link->network->router_search_domains;
        lifetime_usec = link->network->router_dns_lifetime_usec;

        if (search_domains)
                goto set_domains;

        lifetime_usec = SD_RADV_DEFAULT_DNS_LIFETIME_USEC;

        search_domains = link->network->search_domains;
        if (search_domains)
                goto set_domains;

        if (uplink) {
                if (uplink->network == NULL) {
                        log_link_debug(uplink, "Cannot fetch DNS search domains as uplink interface is not managed by us");
                        return 0;
                }

                search_domains = uplink->network->search_domains;
                if (search_domains)
                        goto set_domains;
        }

        return 0;

 set_domains:
        return sd_radv_set_dnssl(link->radv,
                                 DIV_ROUND_UP(lifetime_usec, USEC_PER_SEC),
                                 search_domains);

}

int radv_emit_dns(Link *link) {
        Link *uplink;
        int r;

        uplink = manager_find_uplink(link->manager, link);

        r = radv_set_dns(link, uplink);
        if (r < 0)
                log_link_warning_errno(link, r, "Could not set RA DNS: %m");

        r = radv_set_domains(link, uplink);
        if (r < 0)
                log_link_warning_errno(link, r, "Could not set RA Domains: %m");

        return 0;
}

int radv_configure(Link *link) {
        int r;
        Prefix *p;

        assert(link);
        assert(link->network);

        r = sd_radv_new(&link->radv);
        if (r < 0)
                return r;

        r = sd_radv_attach_event(link->radv, NULL, 0);
        if (r < 0)
                return r;

        r = sd_radv_set_mac(link->radv, &link->mac);
        if (r < 0)
                return r;

        r = sd_radv_set_ifindex(link->radv, link->ifindex);
        if (r < 0)
                return r;

        r = sd_radv_set_managed_information(link->radv, link->network->router_managed);
        if (r < 0)
                return r;

        r = sd_radv_set_other_information(link->radv, link->network->router_other_information);
        if (r < 0)
                return r;

        /* a value of 0xffffffff represents infinity, 0x0 means this host is
           not a router */
        r = sd_radv_set_router_lifetime(link->radv,
                                        DIV_ROUND_UP(link->network->router_lifetime_usec, USEC_PER_SEC));
        if (r < 0)
                return r;

        if (link->network->router_lifetime_usec > 0) {
                r = sd_radv_set_preference(link->radv,
                                           link->network->router_preference);
                if (r < 0)
                        return r;
        }

        LIST_FOREACH(prefixes, p, link->network->static_prefixes) {
                r = sd_radv_add_prefix(link->radv, p->radv_prefix);
                if (r != -EEXIST && r < 0)
                        return r;
        }

        return radv_emit_dns(link);
}
