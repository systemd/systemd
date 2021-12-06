/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2014 Intel Corporation. All rights reserved.
***/

#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <linux/if.h>

#include "sd-ndisc.h"

#include "missing_network.h"
#include "networkd-address-generation.h"
#include "networkd-address.h"
#include "networkd-dhcp6.h"
#include "networkd-manager.h"
#include "networkd-ndisc.h"
#include "networkd-queue.h"
#include "networkd-route.h"
#include "networkd-state-file.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"

#define NDISC_DNSSL_MAX 64U
#define NDISC_RDNSS_MAX 64U

bool link_ipv6_accept_ra_enabled(Link *link) {
        assert(link);

        if (!socket_ipv6_is_supported())
                return false;

        if (link->flags & IFF_LOOPBACK)
                return false;

        if (!link->network)
                return false;

        if (!link_ipv6ll_enabled(link))
                return false;

        assert(link->network->ipv6_accept_ra >= 0);
        return link->network->ipv6_accept_ra;
}

void network_adjust_ipv6_accept_ra(Network *network) {
        assert(network);

        if (!FLAGS_SET(network->link_local, ADDRESS_FAMILY_IPV6)) {
                if (network->ipv6_accept_ra > 0)
                        log_warning("%s: IPv6AcceptRA= is enabled but IPv6 link local addressing is disabled or not supported. "
                                    "Disabling IPv6AcceptRA=.", network->filename);
                network->ipv6_accept_ra = false;
        }

        if (network->ipv6_accept_ra < 0)
                /* default to accept RA if ip_forward is disabled and ignore RA if ip_forward is enabled */
                network->ipv6_accept_ra = !FLAGS_SET(network->ip_forward, ADDRESS_FAMILY_IPV6);

        /* When RouterAllowList=, PrefixAllowList= or RouteAllowList= are specified, then
         * RouterDenyList=, PrefixDenyList= or RouteDenyList= are ignored, respectively. */
        if (!set_isempty(network->ndisc_allow_listed_router))
                network->ndisc_deny_listed_router = set_free_free(network->ndisc_deny_listed_router);
        if (!set_isempty(network->ndisc_allow_listed_prefix))
                network->ndisc_deny_listed_prefix = set_free_free(network->ndisc_deny_listed_prefix);
        if (!set_isempty(network->ndisc_allow_listed_route_prefix))
                network->ndisc_deny_listed_route_prefix = set_free_free(network->ndisc_deny_listed_route_prefix);
}

static int ndisc_remove(Link *link, struct in6_addr *router) {
        bool updated = false;
        NDiscDNSSL *dnssl;
        NDiscRDNSS *rdnss;
        Address *address;
        Route *route;
        int k, r = 0;

        assert(link);

        SET_FOREACH(route, link->routes) {
                if (route->source != NETWORK_CONFIG_SOURCE_NDISC)
                        continue;
                if (!route_is_marked(route))
                        continue;
                if (router && !in6_addr_equal(router, &route->provider.in6))
                        continue;

                k = route_remove(route);
                if (k < 0)
                        r = k;

                route_cancel_request(route, link);
        }

        SET_FOREACH(address, link->addresses) {
                if (address->source != NETWORK_CONFIG_SOURCE_NDISC)
                        continue;
                if (!address_is_marked(address))
                        continue;
                if (router && !in6_addr_equal(router, &address->provider.in6))
                        continue;

                k = address_remove(address);
                if (k < 0)
                        r = k;

                address_cancel_request(address);
        }

        SET_FOREACH(rdnss, link->ndisc_rdnss) {
                if (!rdnss->marked)
                        continue;
                if (router && !in6_addr_equal(router, &rdnss->router))
                        continue;

                free(set_remove(link->ndisc_rdnss, rdnss));
                updated = true;
        }

        SET_FOREACH(dnssl, link->ndisc_dnssl) {
                if (!dnssl->marked)
                        continue;
                if (router && !in6_addr_equal(router, &dnssl->router))
                        continue;

                free(set_remove(link->ndisc_dnssl, dnssl));
                updated = true;
        }

        if (updated)
                link_dirty(link);

        return r;
}

static int ndisc_check_ready(Link *link);

static int ndisc_address_ready_callback(Address *address) {
        Address *a;

        assert(address);
        assert(address->link);

        SET_FOREACH(a, address->link->addresses)
                if (a->source == NETWORK_CONFIG_SOURCE_NDISC)
                        a->callback = NULL;

        return ndisc_check_ready(address->link);
}

static int ndisc_check_ready(Link *link) {
        bool found = false, ready = false;
        Address *address;
        int r;

        assert(link);

        if (link->ndisc_messages > 0) {
                log_link_debug(link, "%s(): SLAAC addresses and routes are not set.", __func__);
                return 0;
        }

        SET_FOREACH(address, link->addresses) {
                if (address->source != NETWORK_CONFIG_SOURCE_NDISC)
                        continue;

                found = true;

                if (address_is_ready(address)) {
                        ready = true;
                        break;
                }
        }

        if (found && !ready) {
                SET_FOREACH(address, link->addresses)
                        if (address->source == NETWORK_CONFIG_SOURCE_NDISC)
                                address->callback = ndisc_address_ready_callback;

                log_link_debug(link, "%s(): no SLAAC address is ready.", __func__);
                return 0;
        }

        link->ndisc_configured = true;
        log_link_debug(link, "SLAAC addresses and routes set.");

        r = ndisc_remove(link, NULL);
        if (r < 0)
                return r;

        link_check_ready(link);
        return 0;
}

static int ndisc_route_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);
        assert(link->ndisc_messages > 0);

        link->ndisc_messages--;

        r = route_configure_handler_internal(rtnl, m, link, "Could not set NDisc route");
        if (r <= 0)
                return r;

        r = ndisc_check_ready(link);
        if (r < 0)
                link_enter_failed(link);

        return 1;
}

static int ndisc_request_route(Route *in, Link *link, sd_ndisc_router *rt) {
        _cleanup_(route_freep) Route *route = in;
        struct in6_addr router;
        Route *existing;
        int r;

        assert(route);
        assert(link);
        assert(rt);

        r = sd_ndisc_router_get_address(rt, &router);
        if (r < 0)
                return r;

        route->source = NETWORK_CONFIG_SOURCE_NDISC;
        route->provider.in6 = router;
        if (!route->table_set)
                route->table = link_get_ipv6_accept_ra_route_table(link);
        if (!route->priority_set)
                route->priority = link->network->ipv6_accept_ra_route_metric;
        if (!route->protocol_set)
                route->protocol = RTPROT_RA;

        if (route_get(NULL, link, route, &existing) < 0)
                link->ndisc_configured = false;
        else
                route_unmark(existing);

        return link_request_route(link, TAKE_PTR(route), true, &link->ndisc_messages,
                                  ndisc_route_handler, NULL);
}

static int ndisc_address_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);
        assert(link->ndisc_messages > 0);

        link->ndisc_messages--;

        r = address_configure_handler_internal(rtnl, m, link, "Could not set NDisc address");
        if (r <= 0)
                return r;

        r = ndisc_check_ready(link);
        if (r < 0)
                link_enter_failed(link);

        return 1;
}

static int ndisc_request_address(Address *in, Link *link, sd_ndisc_router *rt) {
        _cleanup_(address_freep) Address *address = in;
        struct in6_addr router;
        Address *existing;
        int r;

        assert(address);
        assert(link);
        assert(rt);

        r = sd_ndisc_router_get_address(rt, &router);
        if (r < 0)
                return r;

        address->source = NETWORK_CONFIG_SOURCE_NDISC;
        address->provider.in6 = router;

        if (address_get(link, address, &existing) < 0)
                link->ndisc_configured = false;
        else
                address_unmark(existing);

        return link_request_address(link, TAKE_PTR(address), true, &link->ndisc_messages,
                                 ndisc_address_handler, NULL);
}

static int ndisc_router_process_default(Link *link, sd_ndisc_router *rt) {
        usec_t lifetime_usec, timestamp_usec;
        struct in6_addr gateway;
        uint16_t lifetime_sec;
        unsigned preference;
        uint32_t mtu = 0;
        int r;

        assert(link);
        assert(link->network);
        assert(rt);

        if (!link->network->ipv6_accept_ra_use_gateway &&
            hashmap_isempty(link->network->routes_by_section))
                return 0;

        r = sd_ndisc_router_get_lifetime(rt, &lifetime_sec);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get gateway lifetime from RA: %m");

        if (lifetime_sec == 0) /* not a default router */
                return 0;

        r = sd_ndisc_router_get_timestamp(rt, clock_boottime_or_monotonic(), &timestamp_usec);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get RA timestamp: %m");

        lifetime_usec = usec_add(timestamp_usec, lifetime_sec * USEC_PER_SEC);

        r = sd_ndisc_router_get_address(rt, &gateway);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get gateway address from RA: %m");

        if (link_get_ipv6_address(link, &gateway, NULL) >= 0) {
                if (DEBUG_LOGGING) {
                        _cleanup_free_ char *buffer = NULL;

                        (void) in6_addr_to_string(&gateway, &buffer);
                        log_link_debug(link, "No NDisc route added, gateway %s matches local address",
                                       strna(buffer));
                }
                return 0;
        }

        r = sd_ndisc_router_get_preference(rt, &preference);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get default router preference from RA: %m");

        if (link->network->ipv6_accept_ra_use_mtu) {
                r = sd_ndisc_router_get_mtu(rt, &mtu);
                if (r < 0 && r != -ENODATA)
                        return log_link_error_errno(link, r, "Failed to get default router MTU from RA: %m");
        }

        if (link->network->ipv6_accept_ra_use_gateway) {
                _cleanup_(route_freep) Route *route = NULL;

                r = route_new(&route);
                if (r < 0)
                        return log_oom();

                route->family = AF_INET6;
                route->pref = preference;
                route->gw_family = AF_INET6;
                route->gw.in6 = gateway;
                route->lifetime_usec = lifetime_usec;
                route->mtu = mtu;

                r = ndisc_request_route(TAKE_PTR(route), link, rt);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not request default route: %m");
        }

        Route *route_gw;
        HASHMAP_FOREACH(route_gw, link->network->routes_by_section) {
                _cleanup_(route_freep) Route *route = NULL;

                if (!route_gw->gateway_from_dhcp_or_ra)
                        continue;

                if (route_gw->gw_family != AF_INET6)
                        continue;

                r = route_dup(route_gw, &route);
                if (r < 0)
                        return r;

                route->gw.in6 = gateway;
                if (!route->pref_set)
                        route->pref = preference;
                route->lifetime_usec = lifetime_usec;
                if (route->mtu == 0)
                        route->mtu = mtu;

                r = ndisc_request_route(TAKE_PTR(route), link, rt);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not request gateway: %m");
        }

        return 0;
}

static int ndisc_router_process_autonomous_prefix(Link *link, sd_ndisc_router *rt) {
        uint32_t lifetime_valid_sec, lifetime_preferred_sec;
        usec_t lifetime_valid_usec, lifetime_preferred_usec, timestamp_usec;
        _cleanup_set_free_ Set *addresses = NULL;
        struct in6_addr prefix, *a;
        unsigned prefixlen;
        int r;

        assert(link);
        assert(link->network);
        assert(rt);

        if (!link->network->ipv6_accept_ra_use_autonomous_prefix)
                return 0;

        r = sd_ndisc_router_get_timestamp(rt, clock_boottime_or_monotonic(), &timestamp_usec);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get RA timestamp: %m");

        r = sd_ndisc_router_prefix_get_address(rt, &prefix);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get prefix address: %m");

        r = sd_ndisc_router_prefix_get_prefixlen(rt, &prefixlen);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get prefix length: %m");

        /* ndisc_generate_addresses() below requires the prefix length <= 64. */
        if (prefixlen > 64) {
                _cleanup_free_ char *buf = NULL;

                (void) in6_addr_prefix_to_string(&prefix, prefixlen, &buf);
                log_link_debug(link, "Prefix is longer than 64, ignoring autonomous prefix %s.", strna(buf));
                return 0;
        }

        r = sd_ndisc_router_prefix_get_valid_lifetime(rt, &lifetime_valid_sec);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get prefix valid lifetime: %m");

        if (lifetime_valid_sec == 0) {
                log_link_debug(link, "Ignoring prefix as its valid lifetime is zero.");
                return 0;
        }

        r = sd_ndisc_router_prefix_get_preferred_lifetime(rt, &lifetime_preferred_sec);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get prefix preferred lifetime: %m");

        /* The preferred lifetime is never greater than the valid lifetime */
        if (lifetime_preferred_sec > lifetime_valid_sec)
                return 0;

        lifetime_valid_usec = usec_add(lifetime_valid_sec * USEC_PER_SEC, timestamp_usec);
        lifetime_preferred_usec = usec_add(lifetime_preferred_sec * USEC_PER_SEC, timestamp_usec);

        r = ndisc_generate_addresses(link, &prefix, prefixlen, &addresses);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to generate SLAAC addresses: %m");

        SET_FOREACH(a, addresses) {
                _cleanup_(address_freep) Address *address = NULL;
                Address *e;

                r = address_new(&address);
                if (r < 0)
                        return log_oom();

                address->family = AF_INET6;
                address->in_addr.in6 = *a;
                address->prefixlen = prefixlen;
                address->flags = IFA_F_NOPREFIXROUTE|IFA_F_MANAGETEMPADDR;
                address->lifetime_valid_usec = lifetime_valid_usec;
                address->lifetime_preferred_usec = lifetime_preferred_usec;

                /* See RFC4862, section 5.5.3.e. But the following logic is deviated from RFC4862 by
                 * honoring all valid lifetimes to improve the reaction of SLAAC to renumbering events.
                 * See draft-ietf-6man-slaac-renum-02, section 4.2. */
                r = address_get(link, address, &e);
                if (r > 0) {
                        /* If the address is already assigned, but not valid anymore, then refuse to
                         * update the address, and it will be removed. */
                        if (e->lifetime_valid_usec < timestamp_usec)
                                continue;
                }

                r = ndisc_request_address(TAKE_PTR(address), link, rt);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not request SLAAC address: %m");
        }

        return 0;
}

static int ndisc_router_process_onlink_prefix(Link *link, sd_ndisc_router *rt) {
        _cleanup_(route_freep) Route *route = NULL;
        usec_t timestamp_usec;
        uint32_t lifetime_sec;
        unsigned prefixlen;
        int r;

        assert(link);
        assert(link->network);
        assert(rt);

        if (!link->network->ipv6_accept_ra_use_onlink_prefix)
                return 0;

        r = sd_ndisc_router_prefix_get_valid_lifetime(rt, &lifetime_sec);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get prefix lifetime: %m");

        if (lifetime_sec == 0)
                return 0;

        r = sd_ndisc_router_get_timestamp(rt, clock_boottime_or_monotonic(), &timestamp_usec);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get RA timestamp: %m");

        r = sd_ndisc_router_prefix_get_prefixlen(rt, &prefixlen);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get prefix length: %m");

        r = route_new(&route);
        if (r < 0)
                return log_oom();

        route->family = AF_INET6;
        route->flags = RTM_F_PREFIX;
        route->dst_prefixlen = prefixlen;
        route->lifetime_usec = usec_add(timestamp_usec, lifetime_sec * USEC_PER_SEC);

        r = sd_ndisc_router_prefix_get_address(rt, &route->dst.in6);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get prefix address: %m");

        r = ndisc_request_route(TAKE_PTR(route), link, rt);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not request prefix route: %m");;

        return 0;
}

static int ndisc_router_process_prefix(Link *link, sd_ndisc_router *rt) {
        unsigned prefixlen;
        struct in6_addr a;
        uint8_t flags;
        int r;

        assert(link);
        assert(link->network);
        assert(rt);

        r = sd_ndisc_router_prefix_get_address(rt, &a);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get prefix address: %m");

        r = sd_ndisc_router_prefix_get_prefixlen(rt, &prefixlen);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get prefix length: %m");

        if (in6_prefix_is_filtered(&a, prefixlen, link->network->ndisc_allow_listed_prefix, link->network->ndisc_deny_listed_prefix)) {
                if (DEBUG_LOGGING) {
                        _cleanup_free_ char *b = NULL;

                        (void) in6_addr_prefix_to_string(&a, prefixlen, &b);
                        if (!set_isempty(link->network->ndisc_allow_listed_prefix))
                                log_link_debug(link, "Prefix '%s' is not in allow list, ignoring", strna(b));
                        else
                                log_link_debug(link, "Prefix '%s' is in deny list, ignoring", strna(b));
                }
                return 0;
        }

        r = sd_ndisc_router_prefix_get_flags(rt, &flags);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get RA prefix flags: %m");

        if (FLAGS_SET(flags, ND_OPT_PI_FLAG_ONLINK)) {
                r = ndisc_router_process_onlink_prefix(link, rt);
                if (r < 0)
                        return r;
        }

        if (FLAGS_SET(flags, ND_OPT_PI_FLAG_AUTO)) {
                r = ndisc_router_process_autonomous_prefix(link, rt);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int ndisc_router_process_route(Link *link, sd_ndisc_router *rt) {
        _cleanup_(route_freep) Route *route = NULL;
        unsigned preference, prefixlen;
        struct in6_addr gateway, dst;
        uint32_t lifetime_sec;
        usec_t timestamp_usec;
        int r;

        assert(link);

        if (!link->network->ipv6_accept_ra_use_route_prefix)
                return 0;

        r = sd_ndisc_router_route_get_lifetime(rt, &lifetime_sec);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get route lifetime from RA: %m");

        if (lifetime_sec == 0)
                return 0;

        r = sd_ndisc_router_route_get_address(rt, &dst);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get route destination address: %m");

        r = sd_ndisc_router_route_get_prefixlen(rt, &prefixlen);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get route prefix length: %m");

        if (in6_prefix_is_filtered(&dst, prefixlen, link->network->ndisc_allow_listed_route_prefix, link->network->ndisc_deny_listed_route_prefix)) {
                if (DEBUG_LOGGING) {
                        _cleanup_free_ char *buf = NULL;

                        (void) in6_addr_prefix_to_string(&dst, prefixlen, &buf);
                        if (!set_isempty(link->network->ndisc_allow_listed_route_prefix))
                                log_link_debug(link, "Route prefix '%s' is not in allow list, ignoring", strna(buf));
                        else
                                log_link_debug(link, "Route prefix '%s' is in deny list, ignoring", strna(buf));
                }
                return 0;
        }

        r = sd_ndisc_router_get_address(rt, &gateway);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get gateway address from RA: %m");

        if (link_get_ipv6_address(link, &gateway, NULL) >= 0) {
                if (DEBUG_LOGGING) {
                        _cleanup_free_ char *buf = NULL;

                        (void) in6_addr_to_string(&gateway, &buf);
                        log_link_debug(link, "Advertised route gateway %s is local to the link, ignoring route", strna(buf));
                }
                return 0;
        }

        r = sd_ndisc_router_route_get_preference(rt, &preference);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get default router preference from RA: %m");

        r = sd_ndisc_router_get_timestamp(rt, clock_boottime_or_monotonic(), &timestamp_usec);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get RA timestamp: %m");

        r = route_new(&route);
        if (r < 0)
                return log_oom();

        route->family = AF_INET6;
        route->pref = preference;
        route->gw.in6 = gateway;
        route->gw_family = AF_INET6;
        route->dst.in6 = dst;
        route->dst_prefixlen = prefixlen;
        route->lifetime_usec = usec_add(timestamp_usec, lifetime_sec * USEC_PER_SEC);

        r = ndisc_request_route(TAKE_PTR(route), link, rt);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not request additional route: %m");

        return 0;
}

static void ndisc_rdnss_hash_func(const NDiscRDNSS *x, struct siphash *state) {
        siphash24_compress(&x->address, sizeof(x->address), state);
}

static int ndisc_rdnss_compare_func(const NDiscRDNSS *a, const NDiscRDNSS *b) {
        return memcmp(&a->address, &b->address, sizeof(a->address));
}

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
                ndisc_rdnss_hash_ops,
                NDiscRDNSS,
                ndisc_rdnss_hash_func,
                ndisc_rdnss_compare_func,
                free);

static int ndisc_router_process_rdnss(Link *link, sd_ndisc_router *rt) {
        usec_t lifetime_usec, timestamp_usec;
        uint32_t lifetime_sec;
        const struct in6_addr *a;
        struct in6_addr router;
        bool updated = false;
        int n, r;

        assert(link);
        assert(link->network);
        assert(rt);

        if (!link->network->ipv6_accept_ra_use_dns)
                return 0;

        r = sd_ndisc_router_get_address(rt, &router);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get router address from RA: %m");

        r = sd_ndisc_router_get_timestamp(rt, clock_boottime_or_monotonic(), &timestamp_usec);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get RA timestamp: %m");

        r = sd_ndisc_router_rdnss_get_lifetime(rt, &lifetime_sec);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get RDNSS lifetime: %m");

        if (lifetime_sec == 0)
                return 0;

        lifetime_usec = usec_add(timestamp_usec, lifetime_sec * USEC_PER_SEC);

        n = sd_ndisc_router_rdnss_get_addresses(rt, &a);
        if (n < 0)
                return log_link_error_errno(link, n, "Failed to get RDNSS addresses: %m");

        if (n >= (int) NDISC_RDNSS_MAX) {
                log_link_warning(link, "Too many RDNSS records per link. Only first %i records will be used.", NDISC_RDNSS_MAX);
                n = NDISC_RDNSS_MAX;
        }

        for (int j = 0; j < n; j++) {
                _cleanup_free_ NDiscRDNSS *x = NULL;
                NDiscRDNSS *rdnss, d = {
                        .address = a[j],
                };

                rdnss = set_get(link->ndisc_rdnss, &d);
                if (rdnss) {
                        rdnss->marked = false;
                        rdnss->router = router;
                        rdnss->lifetime_usec = lifetime_usec;
                        continue;
                }

                x = new(NDiscRDNSS, 1);
                if (!x)
                        return log_oom();

                *x = (NDiscRDNSS) {
                        .address = a[j],
                        .router = router,
                        .lifetime_usec = lifetime_usec,
                };

                r = set_ensure_consume(&link->ndisc_rdnss, &ndisc_rdnss_hash_ops, TAKE_PTR(x));
                if (r < 0)
                        return log_oom();
                assert(r > 0);

                updated = true;
        }

        if (updated)
                link_dirty(link);

        return 0;
}

static void ndisc_dnssl_hash_func(const NDiscDNSSL *x, struct siphash *state) {
        siphash24_compress_string(NDISC_DNSSL_DOMAIN(x), state);
}

static int ndisc_dnssl_compare_func(const NDiscDNSSL *a, const NDiscDNSSL *b) {
        return strcmp(NDISC_DNSSL_DOMAIN(a), NDISC_DNSSL_DOMAIN(b));
}

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
                ndisc_dnssl_hash_ops,
                NDiscDNSSL,
                ndisc_dnssl_hash_func,
                ndisc_dnssl_compare_func,
                free);

static int ndisc_router_process_dnssl(Link *link, sd_ndisc_router *rt) {
        _cleanup_strv_free_ char **l = NULL;
        usec_t lifetime_usec, timestamp_usec;
        struct in6_addr router;
        uint32_t lifetime_sec;
        bool updated = false;
        char **j;
        int r;

        assert(link);
        assert(link->network);
        assert(rt);

        if (link->network->ipv6_accept_ra_use_domains == DHCP_USE_DOMAINS_NO)
                return 0;

        r = sd_ndisc_router_get_address(rt, &router);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get router address from RA: %m");

        r = sd_ndisc_router_get_timestamp(rt, clock_boottime_or_monotonic(), &timestamp_usec);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get RA timestamp: %m");

        r = sd_ndisc_router_dnssl_get_lifetime(rt, &lifetime_sec);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get DNSSL lifetime: %m");

        if (lifetime_sec == 0)
                return 0;

        lifetime_usec = usec_add(timestamp_usec, lifetime_sec * USEC_PER_SEC);

        r = sd_ndisc_router_dnssl_get_domains(rt, &l);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get DNSSL addresses: %m");

        if (strv_length(l) >= NDISC_DNSSL_MAX) {
                log_link_warning(link, "Too many DNSSL records per link. Only first %i records will be used.", NDISC_DNSSL_MAX);
                STRV_FOREACH(j, l + NDISC_DNSSL_MAX)
                        *j = mfree(*j);
        }

        STRV_FOREACH(j, l) {
                _cleanup_free_ NDiscDNSSL *s = NULL;
                NDiscDNSSL *dnssl;

                s = malloc0(ALIGN(sizeof(NDiscDNSSL)) + strlen(*j) + 1);
                if (!s)
                        return log_oom();

                strcpy(NDISC_DNSSL_DOMAIN(s), *j);

                dnssl = set_get(link->ndisc_dnssl, s);
                if (dnssl) {
                        dnssl->marked = false;
                        dnssl->router = router;
                        dnssl->lifetime_usec = lifetime_usec;
                        continue;
                }

                s->router = router;
                s->lifetime_usec = lifetime_usec;

                r = set_ensure_consume(&link->ndisc_dnssl, &ndisc_dnssl_hash_ops, TAKE_PTR(s));
                if (r < 0)
                        return log_oom();
                assert(r > 0);

                updated = true;
        }

        if (updated)
                link_dirty(link);

        return 0;
}

static int ndisc_router_process_options(Link *link, sd_ndisc_router *rt) {
        int r;

        assert(link);
        assert(link->network);
        assert(rt);

        for (r = sd_ndisc_router_option_rewind(rt); ; r = sd_ndisc_router_option_next(rt)) {
                uint8_t type;

                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to iterate through options: %m");
                if (r == 0) /* EOF */
                        return 0;

                r = sd_ndisc_router_option_get_type(rt, &type);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to get RA option type: %m");

                switch (type) {

                case SD_NDISC_OPTION_PREFIX_INFORMATION:
                        r = ndisc_router_process_prefix(link, rt);
                        if (r < 0)
                                return r;
                        break;

                case SD_NDISC_OPTION_ROUTE_INFORMATION:
                        r = ndisc_router_process_route(link, rt);
                        if (r < 0)
                                return r;
                        break;

                case SD_NDISC_OPTION_RDNSS:
                        r = ndisc_router_process_rdnss(link, rt);
                        if (r < 0)
                                return r;
                        break;

                case SD_NDISC_OPTION_DNSSL:
                        r = ndisc_router_process_dnssl(link, rt);
                        if (r < 0)
                                return r;
                        break;
                }
        }
}

static void ndisc_mark(Link *link, const struct in6_addr *router) {
        NDiscRDNSS *rdnss;
        NDiscDNSSL *dnssl;

        assert(link);
        assert(router);

        link_mark_addresses(link, NETWORK_CONFIG_SOURCE_NDISC, router);
        link_mark_routes(link, NETWORK_CONFIG_SOURCE_NDISC, router);

        SET_FOREACH(rdnss, link->ndisc_rdnss)
                if (in6_addr_equal(&rdnss->router, router))
                        rdnss->marked = true;

        SET_FOREACH(dnssl, link->ndisc_dnssl)
                if (in6_addr_equal(&dnssl->router, router))
                        dnssl->marked = true;
}

static int ndisc_start_dhcp6_client(Link *link, sd_ndisc_router *rt) {
        int r;

        assert(link);
        assert(link->network);

        switch (link->network->ipv6_accept_ra_start_dhcp6_client) {
        case IPV6_ACCEPT_RA_START_DHCP6_CLIENT_NO:
                return 0;

        case IPV6_ACCEPT_RA_START_DHCP6_CLIENT_YES: {
                uint64_t flags;

                r = sd_ndisc_router_get_flags(rt, &flags);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Failed to get RA flags: %m");

                if ((flags & (ND_RA_FLAG_MANAGED | ND_RA_FLAG_OTHER)) == 0)
                        return 0;

                /* (re)start DHCPv6 client in stateful or stateless mode according to RA flags.
                 * Note, if both managed and other information bits are set, then ignore other
                 * information bit. See RFC 4861. */
                r = dhcp6_start_on_ra(link, !(flags & ND_RA_FLAG_MANAGED));
                break;
        }
        case IPV6_ACCEPT_RA_START_DHCP6_CLIENT_ALWAYS:
                /* When IPv6AcceptRA.DHCPv6Client=always, start dhcp6 client in managed mode
                 * even if the router flags have neither M nor O flags. */
                r = dhcp6_start_on_ra(link, /* information_request = */ false);
                break;

        default:
                assert_not_reached();
        }

        if (r < 0)
                return log_link_error_errno(link, r, "Could not acquire DHCPv6 lease on NDisc request: %m");

        log_link_debug(link, "Acquiring DHCPv6 lease on NDisc request");
        return 0;
}

static int ndisc_router_handler(Link *link, sd_ndisc_router *rt) {
        struct in6_addr router;
        int r;

        assert(link);
        assert(link->network);
        assert(link->manager);
        assert(rt);

        r = sd_ndisc_router_get_address(rt, &router);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get router address from RA: %m");

        if (in6_prefix_is_filtered(&router, 128, link->network->ndisc_allow_listed_router, link->network->ndisc_deny_listed_router)) {
                if (DEBUG_LOGGING) {
                        _cleanup_free_ char *buf = NULL;

                        (void) in6_addr_to_string(&router, &buf);
                        if (!set_isempty(link->network->ndisc_allow_listed_router))
                                log_link_debug(link, "Router '%s' is not in allow list, ignoring", strna(buf));
                        else
                                log_link_debug(link, "Router '%s' is in deny list, ignoring", strna(buf));
                }
                return 0;
        }

        ndisc_mark(link, &router);

        r = ndisc_start_dhcp6_client(link, rt);
        if (r < 0)
                return r;

        r = ndisc_router_process_default(link, rt);
        if (r < 0)
                return r;

        r = ndisc_router_process_options(link, rt);
        if (r < 0)
                return r;

        if (link->ndisc_messages == 0) {
                link->ndisc_configured = true;

                r = ndisc_remove(link, &router);
                if (r < 0)
                        return r;
        } else
                log_link_debug(link, "Setting SLAAC addresses and router.");

        if (!link->ndisc_configured)
                link_set_state(link, LINK_STATE_CONFIGURING);

        link_check_ready(link);
        return 0;
}

static void ndisc_handler(sd_ndisc *nd, sd_ndisc_event_t event, sd_ndisc_router *rt, void *userdata) {
        Link *link = userdata;
        int r;

        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return;

        switch (event) {

        case SD_NDISC_EVENT_ROUTER:
                r = ndisc_router_handler(link, rt);
                if (r < 0) {
                        link_enter_failed(link);
                        return;
                }
                break;

        case SD_NDISC_EVENT_TIMEOUT:
                log_link_debug(link, "NDisc handler get timeout event");
                if (link->ndisc_messages == 0) {
                        link->ndisc_configured = true;
                        link_check_ready(link);
                }
                break;
        default:
                assert_not_reached();
        }
}

int ndisc_configure(Link *link) {
        int r;

        assert(link);

        if (!link_ipv6_accept_ra_enabled(link))
                return 0;

        if (link->ndisc)
                return -EBUSY; /* Already configured. */

        r = sd_ndisc_new(&link->ndisc);
        if (r < 0)
                return r;

        r = sd_ndisc_attach_event(link->ndisc, link->manager->event, 0);
        if (r < 0)
                return r;

        r = sd_ndisc_set_mac(link->ndisc, &link->hw_addr.ether);
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

int ndisc_start(Link *link) {
        assert(link);

        if (!link->ndisc || !link->dhcp6_client)
                return 0;

        if (!link_has_carrier(link))
                return 0;

        if (in6_addr_is_null(&link->ipv6ll_address))
                return 0;

        log_link_debug(link, "Discovering IPv6 routers");

        return sd_ndisc_start(link->ndisc);
}

void ndisc_vacuum(Link *link) {
        NDiscRDNSS *r;
        NDiscDNSSL *d;
        usec_t time_now;

        assert(link);

        /* Removes all RDNSS and DNSSL entries whose validity time has passed */

        time_now = now(clock_boottime_or_monotonic());

        SET_FOREACH(r, link->ndisc_rdnss)
                if (r->lifetime_usec < time_now)
                        free(set_remove(link->ndisc_rdnss, r));

        SET_FOREACH(d, link->ndisc_dnssl)
                if (d->lifetime_usec < time_now)
                        free(set_remove(link->ndisc_dnssl, d));
}

void ndisc_flush(Link *link) {
        assert(link);

        /* Removes all RDNSS and DNSSL entries, without exception */

        link->ndisc_rdnss = set_free(link->ndisc_rdnss);
        link->ndisc_dnssl = set_free(link->ndisc_dnssl);
}

static const char* const ipv6_accept_ra_start_dhcp6_client_table[_IPV6_ACCEPT_RA_START_DHCP6_CLIENT_MAX] = {
        [IPV6_ACCEPT_RA_START_DHCP6_CLIENT_NO]     = "no",
        [IPV6_ACCEPT_RA_START_DHCP6_CLIENT_ALWAYS] = "always",
        [IPV6_ACCEPT_RA_START_DHCP6_CLIENT_YES]    = "yes",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING_WITH_BOOLEAN(ipv6_accept_ra_start_dhcp6_client, IPv6AcceptRAStartDHCP6Client, IPV6_ACCEPT_RA_START_DHCP6_CLIENT_YES);

DEFINE_CONFIG_PARSE_ENUM(config_parse_ipv6_accept_ra_use_domains, dhcp_use_domains, DHCPUseDomains,
                         "Failed to parse UseDomains= setting");
DEFINE_CONFIG_PARSE_ENUM(config_parse_ipv6_accept_ra_start_dhcp6_client, ipv6_accept_ra_start_dhcp6_client, IPv6AcceptRAStartDHCP6Client,
                         "Failed to parse DHCPv6Client= setting");
