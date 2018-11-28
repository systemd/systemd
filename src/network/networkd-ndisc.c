/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  Copyright © 2014 Intel Corporation. All rights reserved.
***/

#include <netinet/icmp6.h>
#include <arpa/inet.h>

#include "sd-ndisc.h"

#include "networkd-ndisc.h"
#include "networkd-route.h"
#include "strv.h"

#define NDISC_DNSSL_MAX 64U
#define NDISC_RDNSS_MAX 64U
#define NDISC_PREFIX_LFT_MIN 7200U

static int ndisc_netlink_message_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);
        assert(link->ndisc_messages > 0);

        link->ndisc_messages--;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST)
                log_link_error_errno(link, r, "Could not set NDisc route or address: %m");

        if (link->ndisc_messages == 0) {
                link->ndisc_configured = true;
                link_check_ready(link);
        }

        return 1;
}

static int ndisc_router_process_default(Link *link, sd_ndisc_router *rt) {
        _cleanup_(route_freep) Route *route = NULL;
        struct in6_addr gateway;
        uint16_t lifetime;
        unsigned preference;
        uint32_t mtu;
        usec_t time_now;
        int r;
        Address *address;
        Iterator i;

        assert(link);
        assert(rt);

        r = sd_ndisc_router_get_lifetime(rt, &lifetime);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get gateway address from RA: %m");

        if (lifetime == 0) /* not a default router */
                return 0;

        r = sd_ndisc_router_get_address(rt, &gateway);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get gateway address from RA: %m");

        SET_FOREACH(address, link->addresses, i)
                if (!memcmp(&gateway, &address->in_addr.in6, sizeof(address->in_addr.in6))) {
                        char buffer[INET6_ADDRSTRLEN];

                        log_link_debug(link, "No NDisc route added, gateway %s matches local address",
                                       inet_ntop(AF_INET6,
                                                 &address->in_addr.in6,
                                                 buffer, sizeof(buffer)));
                        return 0;
                }

        SET_FOREACH(address, link->addresses_foreign, i)
                if (!memcmp(&gateway, &address->in_addr.in6, sizeof(address->in_addr.in6))) {
                        char buffer[INET6_ADDRSTRLEN];

                        log_link_debug(link, "No NDisc route added, gateway %s matches local address",
                                       inet_ntop(AF_INET6,
                                                 &address->in_addr.in6,
                                                 buffer, sizeof(buffer)));
                        return 0;
                }

        r = sd_ndisc_router_get_preference(rt, &preference);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get default router preference from RA: %m");

        r = sd_ndisc_router_get_timestamp(rt, clock_boottime_or_monotonic(), &time_now);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get RA timestamp: %m");

        r = sd_ndisc_router_get_mtu(rt, &mtu);
        if (r == -ENODATA)
                mtu = 0;
        else if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get default router MTU from RA: %m");

        r = route_new(&route);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not allocate route: %m");

        route->family = AF_INET6;
        route->table = link->network->ipv6_accept_ra_route_table;
        route->priority = link->network->dhcp_route_metric;
        route->protocol = RTPROT_RA;
        route->pref = preference;
        route->gw.in6 = gateway;
        route->lifetime = time_now + lifetime * USEC_PER_SEC;
        route->mtu = mtu;

        r = route_configure(route, link, ndisc_netlink_message_handler);
        if (r < 0) {
                log_link_warning_errno(link, r, "Could not set default route: %m");
                link_enter_failed(link);
                return r;
        }

        link->ndisc_messages++;

        return 0;
}

static int ndisc_router_process_autonomous_prefix(Link *link, sd_ndisc_router *rt) {
        _cleanup_(address_freep) Address *address = NULL;
        Address *existing_address;
        uint32_t lifetime_valid, lifetime_preferred, lifetime_remaining;
        usec_t time_now;
        unsigned prefixlen;
        int r;

        assert(link);
        assert(rt);

        r = sd_ndisc_router_get_timestamp(rt, clock_boottime_or_monotonic(), &time_now);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get RA timestamp: %m");

        r = sd_ndisc_router_prefix_get_prefixlen(rt, &prefixlen);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get prefix length: %m");

        r = sd_ndisc_router_prefix_get_valid_lifetime(rt, &lifetime_valid);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get prefix valid lifetime: %m");

        r = sd_ndisc_router_prefix_get_preferred_lifetime(rt, &lifetime_preferred);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get prefix preferred lifetime: %m");

        /* The preferred lifetime is never greater than the valid lifetime */
        if (lifetime_preferred > lifetime_valid)
                return 0;

        r = address_new(&address);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not allocate address: %m");

        address->family = AF_INET6;
        r = sd_ndisc_router_prefix_get_address(rt, &address->in_addr.in6);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get prefix address: %m");

        if (in_addr_is_null(AF_INET6, (const union in_addr_union *) &link->network->ipv6_token) == 0)
                memcpy(((char *)&address->in_addr.in6) + 8, ((char *)&link->network->ipv6_token) + 8, 8);
        else {
                /* see RFC4291 section 2.5.1 */
                address->in_addr.in6.s6_addr[8]  = link->mac.ether_addr_octet[0];
                address->in_addr.in6.s6_addr[8] ^= 1 << 1;
                address->in_addr.in6.s6_addr[9]  = link->mac.ether_addr_octet[1];
                address->in_addr.in6.s6_addr[10] = link->mac.ether_addr_octet[2];
                address->in_addr.in6.s6_addr[11] = 0xff;
                address->in_addr.in6.s6_addr[12] = 0xfe;
                address->in_addr.in6.s6_addr[13] = link->mac.ether_addr_octet[3];
                address->in_addr.in6.s6_addr[14] = link->mac.ether_addr_octet[4];
                address->in_addr.in6.s6_addr[15] = link->mac.ether_addr_octet[5];
        }
        address->prefixlen = prefixlen;
        address->flags = IFA_F_NOPREFIXROUTE|IFA_F_MANAGETEMPADDR;
        address->cinfo.ifa_prefered = lifetime_preferred;

        /* see RFC4862 section 5.5.3.e */
        r = address_get(link, address->family, &address->in_addr, address->prefixlen, &existing_address);
        if (r > 0) {
                lifetime_remaining = existing_address->cinfo.tstamp / 100 + existing_address->cinfo.ifa_valid - time_now / USEC_PER_SEC;
                if (lifetime_valid > NDISC_PREFIX_LFT_MIN || lifetime_valid > lifetime_remaining)
                        address->cinfo.ifa_valid = lifetime_valid;
                else if (lifetime_remaining <= NDISC_PREFIX_LFT_MIN)
                        address->cinfo.ifa_valid = lifetime_remaining;
                else
                        address->cinfo.ifa_valid = NDISC_PREFIX_LFT_MIN;
        } else if (lifetime_valid > 0)
                address->cinfo.ifa_valid = lifetime_valid;
        else
                return 0; /* see RFC4862 section 5.5.3.d */

        if (address->cinfo.ifa_valid == 0)
                return 0;

        r = address_configure(address, link, ndisc_netlink_message_handler, true);
        if (r < 0) {
                log_link_warning_errno(link, r, "Could not set SLAAC address: %m");
                link_enter_failed(link);
                return r;
        }

        link->ndisc_messages++;

        return 0;
}

static int ndisc_router_process_onlink_prefix(Link *link, sd_ndisc_router *rt) {
        _cleanup_(route_freep) Route *route = NULL;
        usec_t time_now;
        uint32_t lifetime;
        unsigned prefixlen;
        int r;

        assert(link);
        assert(rt);

        r = sd_ndisc_router_get_timestamp(rt, clock_boottime_or_monotonic(), &time_now);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get RA timestamp: %m");

        r = sd_ndisc_router_prefix_get_prefixlen(rt, &prefixlen);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get prefix length: %m");

        r = sd_ndisc_router_prefix_get_valid_lifetime(rt, &lifetime);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get prefix lifetime: %m");

        r = route_new(&route);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not allocate route: %m");

        route->family = AF_INET6;
        route->table = link->network->ipv6_accept_ra_route_table;
        route->priority = link->network->dhcp_route_metric;
        route->protocol = RTPROT_RA;
        route->flags = RTM_F_PREFIX;
        route->dst_prefixlen = prefixlen;
        route->lifetime = time_now + lifetime * USEC_PER_SEC;

        r = sd_ndisc_router_prefix_get_address(rt, &route->dst.in6);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get prefix address: %m");

        r = route_configure(route, link, ndisc_netlink_message_handler);
        if (r < 0) {
                log_link_warning_errno(link, r, "Could not set prefix route: %m");
                link_enter_failed(link);
                return r;
        }

        link->ndisc_messages++;

        return 0;
}

static int ndisc_router_process_route(Link *link, sd_ndisc_router *rt) {
        _cleanup_(route_freep) Route *route = NULL;
        struct in6_addr gateway;
        uint32_t lifetime;
        unsigned preference, prefixlen;
        usec_t time_now;
        int r;

        assert(link);

        r = sd_ndisc_router_route_get_lifetime(rt, &lifetime);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get gateway address from RA: %m");

        if (lifetime == 0)
                return 0;

        r = sd_ndisc_router_get_address(rt, &gateway);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get gateway address from RA: %m");

        r = sd_ndisc_router_route_get_prefixlen(rt, &prefixlen);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get route prefix length: %m");

        r = sd_ndisc_router_route_get_preference(rt, &preference);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get default router preference from RA: %m");

        r = sd_ndisc_router_get_timestamp(rt, clock_boottime_or_monotonic(), &time_now);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get RA timestamp: %m");

        r = route_new(&route);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not allocate route: %m");

        route->family = AF_INET6;
        route->table = link->network->ipv6_accept_ra_route_table;
        route->protocol = RTPROT_RA;
        route->pref = preference;
        route->gw.in6 = gateway;
        route->dst_prefixlen = prefixlen;
        route->lifetime = time_now + lifetime * USEC_PER_SEC;

        r = sd_ndisc_router_route_get_address(rt, &route->dst.in6);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get route address: %m");

        r = route_configure(route, link, ndisc_netlink_message_handler);
        if (r < 0) {
                log_link_warning_errno(link, r, "Could not set additional route: %m");
                link_enter_failed(link);
                return r;
        }

        link->ndisc_messages++;

        return 0;
}

static void ndisc_rdnss_hash_func(const void *p, struct siphash *state) {
        const NDiscRDNSS *x = p;

        siphash24_compress(&x->address, sizeof(x->address), state);
}

static int ndisc_rdnss_compare_func(const void *_a, const void *_b) {
        const NDiscRDNSS *a = _a, *b = _b;

        return memcmp(&a->address, &b->address, sizeof(a->address));
}

static const struct hash_ops ndisc_rdnss_hash_ops = {
        .hash = ndisc_rdnss_hash_func,
        .compare = ndisc_rdnss_compare_func
};

static int ndisc_router_process_rdnss(Link *link, sd_ndisc_router *rt) {
        uint32_t lifetime;
        const struct in6_addr *a;
        usec_t time_now;
        int i, n, r;

        assert(link);
        assert(rt);

        r = sd_ndisc_router_get_timestamp(rt, clock_boottime_or_monotonic(), &time_now);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get RA timestamp: %m");

        r = sd_ndisc_router_rdnss_get_lifetime(rt, &lifetime);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get RDNSS lifetime: %m");

        n = sd_ndisc_router_rdnss_get_addresses(rt, &a);
        if (n < 0)
                return log_link_warning_errno(link, n, "Failed to get RDNSS addresses: %m");

        for (i = 0; i < n; i++) {
                _cleanup_free_ NDiscRDNSS *x = NULL;
                NDiscRDNSS d = {
                        .address = a[i],
                }, *y;

                if (lifetime == 0) {
                        (void) set_remove(link->ndisc_rdnss, &d);
                        link_dirty(link);
                        continue;
                }

                y = set_get(link->ndisc_rdnss, &d);
                if (y) {
                        y->valid_until = time_now + lifetime * USEC_PER_SEC;
                        continue;
                }

                ndisc_vacuum(link);

                if (set_size(link->ndisc_rdnss) >= NDISC_RDNSS_MAX) {
                        log_link_warning(link, "Too many RDNSS records per link, ignoring.");
                        continue;
                }

                r = set_ensure_allocated(&link->ndisc_rdnss, &ndisc_rdnss_hash_ops);
                if (r < 0)
                        return log_oom();

                x = new(NDiscRDNSS, 1);
                if (!x)
                        return log_oom();

                *x = (NDiscRDNSS) {
                        .address = a[i],
                        .valid_until = time_now + lifetime * USEC_PER_SEC,
                };

                r = set_put(link->ndisc_rdnss, x);
                if (r < 0)
                        return log_oom();

                TAKE_PTR(x);

                assert(r > 0);
                link_dirty(link);
        }

        return 0;
}

static void ndisc_dnssl_hash_func(const void *p, struct siphash *state) {
        const NDiscDNSSL *x = p;

        siphash24_compress(NDISC_DNSSL_DOMAIN(x), strlen(NDISC_DNSSL_DOMAIN(x)), state);
}

static int ndisc_dnssl_compare_func(const void *_a, const void *_b) {
        const NDiscDNSSL *a = _a, *b = _b;

        return strcmp(NDISC_DNSSL_DOMAIN(a), NDISC_DNSSL_DOMAIN(b));
}

static const struct hash_ops ndisc_dnssl_hash_ops = {
        .hash = ndisc_dnssl_hash_func,
        .compare = ndisc_dnssl_compare_func
};

static void ndisc_router_process_dnssl(Link *link, sd_ndisc_router *rt) {
        _cleanup_strv_free_ char **l = NULL;
        uint32_t lifetime;
        usec_t time_now;
        char **i;
        int r;

        assert(link);
        assert(rt);

        r = sd_ndisc_router_get_timestamp(rt, clock_boottime_or_monotonic(), &time_now);
        if (r < 0) {
                log_link_warning_errno(link, r, "Failed to get RA timestamp: %m");
                return;
        }

        r = sd_ndisc_router_dnssl_get_lifetime(rt, &lifetime);
        if (r < 0) {
                log_link_warning_errno(link, r, "Failed to get RDNSS lifetime: %m");
                return;
        }

        r = sd_ndisc_router_dnssl_get_domains(rt, &l);
        if (r < 0) {
                log_link_warning_errno(link, r, "Failed to get RDNSS addresses: %m");
                return;
        }

        STRV_FOREACH(i, l) {
                _cleanup_free_ NDiscDNSSL *s;
                NDiscDNSSL *x;

                s = malloc0(ALIGN(sizeof(NDiscDNSSL)) + strlen(*i) + 1);
                if (!s) {
                        log_oom();
                        return;
                }

                strcpy(NDISC_DNSSL_DOMAIN(s), *i);

                if (lifetime == 0) {
                        (void) set_remove(link->ndisc_dnssl, s);
                        link_dirty(link);
                        continue;
                }

                x = set_get(link->ndisc_dnssl, s);
                if (x) {
                        x->valid_until = time_now + lifetime * USEC_PER_SEC;
                        continue;
                }

                ndisc_vacuum(link);

                if (set_size(link->ndisc_dnssl) >= NDISC_DNSSL_MAX) {
                        log_link_warning(link, "Too many DNSSL records per link, ignoring.");
                        continue;
                }

                r = set_ensure_allocated(&link->ndisc_dnssl, &ndisc_dnssl_hash_ops);
                if (r < 0) {
                        log_oom();
                        return;
                }

                s->valid_until = time_now + lifetime * USEC_PER_SEC;

                r = set_put(link->ndisc_dnssl, s);
                if (r < 0) {
                        log_oom();
                        return;
                }

                s = NULL;
                assert(r > 0);
                link_dirty(link);
        }
}

static void ndisc_router_process_options(Link *link, sd_ndisc_router *rt) {
        int r;

        assert(link);
        assert(rt);

        r = sd_ndisc_router_option_rewind(rt);
        for (;;) {
                uint8_t type;

                if (r < 0) {
                        log_link_warning_errno(link, r, "Failed to iterate through options: %m");
                        return;
                }
                if (r == 0) /* EOF */
                        break;

                r = sd_ndisc_router_option_get_type(rt, &type);
                if (r < 0) {
                        log_link_warning_errno(link, r, "Failed to get RA option type: %m");
                        return;
                }

                switch (type) {

                case SD_NDISC_OPTION_PREFIX_INFORMATION: {
                        uint8_t flags;

                        r = sd_ndisc_router_prefix_get_flags(rt, &flags);
                        if (r < 0) {
                                log_link_warning_errno(link, r, "Failed to get RA prefix flags: %m");
                                return;
                        }

                        if (flags & ND_OPT_PI_FLAG_ONLINK)
                                (void) ndisc_router_process_onlink_prefix(link, rt);
                        if (flags & ND_OPT_PI_FLAG_AUTO)
                                (void) ndisc_router_process_autonomous_prefix(link, rt);

                        break;
                }

                case SD_NDISC_OPTION_ROUTE_INFORMATION:
                        (void) ndisc_router_process_route(link, rt);
                        break;

                case SD_NDISC_OPTION_RDNSS:
                        if (link->network->ipv6_accept_ra_use_dns)
                                (void) ndisc_router_process_rdnss(link, rt);
                        break;

                case SD_NDISC_OPTION_DNSSL:
                        if (link->network->ipv6_accept_ra_use_dns)
                                (void) ndisc_router_process_dnssl(link, rt);
                        break;
                }

                r = sd_ndisc_router_option_next(rt);
        }
}

static int ndisc_router_handler(Link *link, sd_ndisc_router *rt) {
        uint64_t flags;
        int r = 0;

        assert(link);
        assert(link->network);
        assert(link->manager);
        assert(rt);

        r = sd_ndisc_router_get_flags(rt, &flags);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get RA flags: %m");

        if (flags & (ND_RA_FLAG_MANAGED | ND_RA_FLAG_OTHER)) {
                /* (re)start DHCPv6 client in stateful or stateless mode according to RA flags */
                r = dhcp6_request_address(link, !(flags & ND_RA_FLAG_MANAGED));
                if (r < 0 && r != -EBUSY)
                        log_link_warning_errno(link, r, "Could not acquire DHCPv6 lease on NDisc request: %m");
                else {
                        log_link_debug(link, "Acquiring DHCPv6 lease on NDisc request");
                        r = 0;
                }
        }

        ndisc_router_process_default(link, rt);
        ndisc_router_process_options(link, rt);

        return r;
}

static void ndisc_handler(sd_ndisc *nd, sd_ndisc_event event, sd_ndisc_router *rt, void *userdata) {
        Link *link = userdata;

        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return;

        switch (event) {

        case SD_NDISC_EVENT_ROUTER:
                (void) ndisc_router_handler(link, rt);
                break;

        case SD_NDISC_EVENT_TIMEOUT:
                link->ndisc_configured = true;
                link_check_ready(link);

                break;
        default:
                log_link_warning(link, "IPv6 Neighbor Discovery unknown event: %d", event);
        }
}

int ndisc_configure(Link *link) {
        int r;

        assert(link);

        r = sd_ndisc_new(&link->ndisc);
        if (r < 0)
                return r;

        r = sd_ndisc_attach_event(link->ndisc, NULL, 0);
        if (r < 0)
                return r;

        r = sd_ndisc_set_mac(link->ndisc, &link->mac);
        if (r < 0)
                return r;

        r = sd_ndisc_set_ifindex(link->ndisc, link->ifindex);
        if (r < 0)
                return r;

        r = sd_ndisc_set_callback(link->ndisc, ndisc_handler, link);
        if (r < 0)
                return r;

        return 0;
}

void ndisc_vacuum(Link *link) {
        NDiscRDNSS *r;
        NDiscDNSSL *d;
        Iterator i;
        usec_t time_now;

        assert(link);

        /* Removes all RDNSS and DNSSL entries whose validity time has passed */

        time_now = now(clock_boottime_or_monotonic());

        SET_FOREACH(r, link->ndisc_rdnss, i)
                if (r->valid_until < time_now) {
                        free(set_remove(link->ndisc_rdnss, r));
                        link_dirty(link);
                }

        SET_FOREACH(d, link->ndisc_dnssl, i)
                if (d->valid_until < time_now) {
                        free(set_remove(link->ndisc_dnssl, d));
                        link_dirty(link);
                }
}

void ndisc_flush(Link *link) {
        assert(link);

        /* Removes all RDNSS and DNSSL entries, without exception */

        link->ndisc_rdnss = set_free_free(link->ndisc_rdnss);
        link->ndisc_dnssl = set_free_free(link->ndisc_dnssl);
}
