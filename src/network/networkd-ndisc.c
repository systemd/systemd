/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2014 Intel Corporation. All rights reserved.
***/

#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <net/if_arp.h>
#include <linux/if.h>

#include "sd-ndisc.h"

#include "missing_network.h"
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

#define DAD_CONFLICTS_IDGEN_RETRIES_RFC7217 3

/* https://tools.ietf.org/html/rfc5453 */
/* https://www.iana.org/assignments/ipv6-interface-ids/ipv6-interface-ids.xml */

#define SUBNET_ROUTER_ANYCAST_ADDRESS_RFC4291               ((struct in6_addr) { .s6_addr = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } })
#define SUBNET_ROUTER_ANYCAST_PREFIXLEN                     8
#define RESERVED_IPV6_INTERFACE_IDENTIFIERS_ADDRESS_RFC4291 ((struct in6_addr) { .s6_addr = { 0x02, 0x00, 0x5E, 0xFF, 0xFE } })
#define RESERVED_IPV6_INTERFACE_IDENTIFIERS_PREFIXLEN       5
#define RESERVED_SUBNET_ANYCAST_ADDRESSES_RFC4291           ((struct in6_addr) { .s6_addr = { 0xFD, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF } })
#define RESERVED_SUBNET_ANYCAST_PREFIXLEN                   7

#define NDISC_APP_ID SD_ID128_MAKE(13,ac,81,a7,d5,3f,49,78,92,79,5d,0c,29,3a,bc,7e)

typedef enum IPv6TokenAddressGeneration {
        IPV6_TOKEN_ADDRESS_GENERATION_NONE,
        IPV6_TOKEN_ADDRESS_GENERATION_STATIC,
        IPV6_TOKEN_ADDRESS_GENERATION_PREFIXSTABLE,
        _IPV6_TOKEN_ADDRESS_GENERATION_MAX,
        _IPV6_TOKEN_ADDRESS_GENERATION_INVALID = -EINVAL,
} IPv6TokenAddressGeneration;

typedef struct IPv6Token {
        IPv6TokenAddressGeneration address_generation_type;

        uint8_t dad_counter;
        struct in6_addr prefix;
} IPv6Token;

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

                route_cancel_request(route);
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
        _cleanup_(route_freep) Route *route = NULL;
        struct in6_addr gateway;
        uint32_t mtu = 0;
        unsigned preference;
        uint16_t lifetime;
        usec_t time_now;
        int r;

        assert(link);
        assert(rt);

        r = sd_ndisc_router_get_lifetime(rt, &lifetime);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get gateway lifetime from RA: %m");

        if (lifetime == 0) /* not a default router */
                return 0;

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

        r = sd_ndisc_router_get_timestamp(rt, clock_boottime_or_monotonic(), &time_now);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get RA timestamp: %m");

        if (link->network->ipv6_accept_ra_use_mtu) {
                r = sd_ndisc_router_get_mtu(rt, &mtu);
                if (r < 0 && r != -ENODATA)
                        return log_link_error_errno(link, r, "Failed to get default router MTU from RA: %m");
        }

        r = route_new(&route);
        if (r < 0)
                return log_oom();

        route->family = AF_INET6;
        route->pref = preference;
        route->gw_family = AF_INET6;
        route->gw.in6 = gateway;
        route->lifetime = usec_add(time_now, lifetime * USEC_PER_SEC);
        route->mtu = mtu;

        r = ndisc_request_route(TAKE_PTR(route), link, rt);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not request default route: %m");

        Route *route_gw;
        HASHMAP_FOREACH(route_gw, link->network->routes_by_section) {
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
                route->lifetime = usec_add(time_now, lifetime * USEC_PER_SEC);
                if (route->mtu == 0)
                        route->mtu = mtu;

                r = ndisc_request_route(TAKE_PTR(route), link, rt);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not request gateway: %m");
        }

        return 0;
}

static bool stable_private_address_is_valid(const struct in6_addr *addr) {
        assert(addr);

        /* According to rfc4291, generated address should not be in the following ranges. */

        if (memcmp(addr, &SUBNET_ROUTER_ANYCAST_ADDRESS_RFC4291, SUBNET_ROUTER_ANYCAST_PREFIXLEN) == 0)
                return false;

        if (memcmp(addr, &RESERVED_IPV6_INTERFACE_IDENTIFIERS_ADDRESS_RFC4291, RESERVED_IPV6_INTERFACE_IDENTIFIERS_PREFIXLEN) == 0)
                return false;

        if (memcmp(addr, &RESERVED_SUBNET_ANYCAST_ADDRESSES_RFC4291, RESERVED_SUBNET_ANYCAST_PREFIXLEN) == 0)
                return false;

        return true;
}

static int make_stable_private_address(Link *link, const struct in6_addr *prefix, uint8_t prefix_len, uint8_t dad_counter, struct in6_addr **ret) {
        _cleanup_free_ struct in6_addr *addr = NULL;
        sd_id128_t secret_key;
        struct siphash state;
        uint64_t rid;
        size_t l;
        int r;

        /* According to rfc7217 section 5.1
         * RID = F(Prefix, Net_Iface, Network_ID, DAD_Counter, secret_key) */

        r = sd_id128_get_machine_app_specific(NDISC_APP_ID, &secret_key);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to generate key for IPv6 stable private address: %m");

        siphash24_init(&state, secret_key.bytes);

        l = MAX(DIV_ROUND_UP(prefix_len, 8), 8);
        siphash24_compress(prefix, l, &state);
        siphash24_compress_string(link->ifname, &state);
        /* Only last 8 bytes of IB MAC are stable */
        if (link->iftype == ARPHRD_INFINIBAND)
                siphash24_compress(&link->hw_addr.infiniband[12], 8, &state);
        else
                siphash24_compress(link->hw_addr.bytes, link->hw_addr.length, &state);
        siphash24_compress(&dad_counter, sizeof(uint8_t), &state);

        rid = htole64(siphash24_finalize(&state));

        addr = new(struct in6_addr, 1);
        if (!addr)
                return log_oom();

        memcpy(addr->s6_addr, prefix->s6_addr, l);
        memcpy(addr->s6_addr + l, &rid, 16 - l);

        if (!stable_private_address_is_valid(addr)) {
                *ret = NULL;
                return 0;
        }

        *ret = TAKE_PTR(addr);
        return 1;
}

static int ndisc_router_generate_addresses(Link *link, struct in6_addr *address, uint8_t prefixlen, Set **ret) {
        _cleanup_set_free_free_ Set *addresses = NULL;
        IPv6Token *j;
        int r;

        assert(link);
        assert(address);
        assert(ret);

        addresses = set_new(&in6_addr_hash_ops);
        if (!addresses)
                return log_oom();

        ORDERED_SET_FOREACH(j, link->network->ipv6_tokens) {
                _cleanup_free_ struct in6_addr *new_address = NULL;

                if (j->address_generation_type == IPV6_TOKEN_ADDRESS_GENERATION_PREFIXSTABLE
                    && (in6_addr_is_null(&j->prefix) || in6_addr_equal(&j->prefix, address))) {
                        /* While this loop uses dad_counter and a retry limit as specified in RFC 7217, the loop
                         * does not actually attempt Duplicate Address Detection; the counter will be incremented
                         * only when the address generation algorithm produces an invalid address, and the loop
                         * may exit with an address which ends up being unusable due to duplication on the link. */
                        for (; j->dad_counter < DAD_CONFLICTS_IDGEN_RETRIES_RFC7217; j->dad_counter++) {
                                r = make_stable_private_address(link, address, prefixlen, j->dad_counter, &new_address);
                                if (r < 0)
                                        return r;
                                if (r > 0)
                                        break;
                        }
                } else if (j->address_generation_type == IPV6_TOKEN_ADDRESS_GENERATION_STATIC) {
                        new_address = new(struct in6_addr, 1);
                        if (!new_address)
                                return log_oom();

                        memcpy(new_address->s6_addr, address->s6_addr, 8);
                        memcpy(new_address->s6_addr + 8, j->prefix.s6_addr + 8, 8);
                }

                if (new_address) {
                        r = set_put(addresses, new_address);
                        if (r < 0)
                                return log_link_error_errno(link, r, "Failed to store SLAAC address: %m");
                        else if (r == 0)
                                log_link_debug_errno(link, r, "Generated SLAAC address is duplicated, ignoring.");
                        else
                                TAKE_PTR(new_address);
                }
        }

        /* fall back to EUI-64 if no tokens provided addresses */
        if (set_isempty(addresses)) {
                _cleanup_free_ struct in6_addr *new_address = NULL;

                new_address = newdup(struct in6_addr, address, 1);
                if (!new_address)
                        return log_oom();

                r = generate_ipv6_eui_64_address(link, new_address);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to generate EUI64 address: %m");

                r = set_put(addresses, new_address);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to store SLAAC address: %m");

                TAKE_PTR(new_address);
        }

        *ret = TAKE_PTR(addresses);

        return 0;
}

static int ndisc_router_process_autonomous_prefix(Link *link, sd_ndisc_router *rt) {
        uint32_t lifetime_valid, lifetime_preferred;
        _cleanup_set_free_free_ Set *addresses = NULL;
        struct in6_addr addr, *a;
        unsigned prefixlen;
        usec_t time_now;
        int r;

        assert(link);
        assert(rt);

        /* Do not use clock_boottime_or_monotonic() here, as the kernel internally manages cstamp and
         * tstamp with jiffies, and it is not increased while the system is suspended. */
        r = sd_ndisc_router_get_timestamp(rt, CLOCK_MONOTONIC, &time_now);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get RA timestamp: %m");

        r = sd_ndisc_router_prefix_get_prefixlen(rt, &prefixlen);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get prefix length: %m");

        r = sd_ndisc_router_prefix_get_valid_lifetime(rt, &lifetime_valid);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get prefix valid lifetime: %m");

        if (lifetime_valid == 0) {
                log_link_debug(link, "Ignoring prefix as its valid lifetime is zero.");
                return 0;
        }

        r = sd_ndisc_router_prefix_get_preferred_lifetime(rt, &lifetime_preferred);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get prefix preferred lifetime: %m");

        /* The preferred lifetime is never greater than the valid lifetime */
        if (lifetime_preferred > lifetime_valid)
                return 0;

        r = sd_ndisc_router_prefix_get_address(rt, &addr);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get prefix address: %m");

        r = ndisc_router_generate_addresses(link, &addr, prefixlen, &addresses);
        if (r < 0)
                return r;

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
                address->cinfo.ifa_valid = lifetime_valid;
                address->cinfo.ifa_prefered = lifetime_preferred;

                /* See RFC4862, section 5.5.3.e. But the following logic is deviated from RFC4862 by
                 * honoring all valid lifetimes to improve the reaction of SLAAC to renumbering events.
                 * See draft-ietf-6man-slaac-renum-02, section 4.2. */
                r = address_get(link, address, &e);
                if (r > 0) {
                        /* If the address is already assigned, but not valid anymore, then refuse to
                         * update the address, and it will be removed. */
                        if (e->cinfo.ifa_valid != CACHE_INFO_INFINITY_LIFE_TIME &&
                            usec_add(e->cinfo.tstamp / 100 * USEC_PER_SEC,
                                     e->cinfo.ifa_valid * USEC_PER_SEC) < time_now)
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
        usec_t time_now;
        uint32_t lifetime;
        unsigned prefixlen;
        int r;

        assert(link);
        assert(rt);

        r = sd_ndisc_router_get_timestamp(rt, clock_boottime_or_monotonic(), &time_now);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get RA timestamp: %m");

        r = sd_ndisc_router_prefix_get_prefixlen(rt, &prefixlen);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get prefix length: %m");

        r = sd_ndisc_router_prefix_get_valid_lifetime(rt, &lifetime);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get prefix lifetime: %m");

        r = route_new(&route);
        if (r < 0)
                return log_oom();

        route->family = AF_INET6;
        route->flags = RTM_F_PREFIX;
        route->dst_prefixlen = prefixlen;
        route->lifetime = usec_add(time_now, lifetime * USEC_PER_SEC);

        r = sd_ndisc_router_prefix_get_address(rt, &route->dst.in6);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get prefix address: %m");

        r = ndisc_request_route(TAKE_PTR(route), link, rt);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not request prefix route: %m");;

        return 0;
}

static int ndisc_router_process_route(Link *link, sd_ndisc_router *rt) {
        _cleanup_(route_freep) Route *route = NULL;
        struct in6_addr gateway, dst;
        uint32_t lifetime;
        unsigned preference, prefixlen;
        usec_t time_now;
        int r;

        assert(link);

        r = sd_ndisc_router_route_get_lifetime(rt, &lifetime);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get route lifetime from RA: %m");

        if (lifetime == 0)
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

        r = sd_ndisc_router_get_timestamp(rt, clock_boottime_or_monotonic(), &time_now);
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
        route->lifetime = usec_add(time_now, lifetime * USEC_PER_SEC);

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
        uint32_t lifetime;
        const struct in6_addr *a;
        struct in6_addr router;
        usec_t time_now;
        bool updated = false;
        int n, r;

        assert(link);
        assert(rt);

        r = sd_ndisc_router_get_address(rt, &router);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get router address from RA: %m");

        r = sd_ndisc_router_get_timestamp(rt, clock_boottime_or_monotonic(), &time_now);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get RA timestamp: %m");

        r = sd_ndisc_router_rdnss_get_lifetime(rt, &lifetime);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get RDNSS lifetime: %m");

        n = sd_ndisc_router_rdnss_get_addresses(rt, &a);
        if (n < 0)
                return log_link_error_errno(link, n, "Failed to get RDNSS addresses: %m");

        if (lifetime == 0)
                return 0;

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
                        rdnss->valid_until = usec_add(time_now, lifetime * USEC_PER_SEC);
                        continue;
                }

                x = new(NDiscRDNSS, 1);
                if (!x)
                        return log_oom();

                *x = (NDiscRDNSS) {
                        .address = a[j],
                        .router = router,
                        .valid_until = usec_add(time_now, lifetime * USEC_PER_SEC),
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
        struct in6_addr router;
        uint32_t lifetime;
        usec_t time_now;
        bool updated = false;
        char **j;
        int r;

        assert(link);
        assert(rt);

        r = sd_ndisc_router_get_address(rt, &router);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get router address from RA: %m");

        r = sd_ndisc_router_get_timestamp(rt, clock_boottime_or_monotonic(), &time_now);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get RA timestamp: %m");

        r = sd_ndisc_router_dnssl_get_lifetime(rt, &lifetime);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get DNSSL lifetime: %m");

        r = sd_ndisc_router_dnssl_get_domains(rt, &l);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get DNSSL addresses: %m");

        if (lifetime == 0)
                return 0;

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
                        dnssl->valid_until = usec_add(time_now, lifetime * USEC_PER_SEC);
                        continue;
                }

                s->router = router;
                s->valid_until = usec_add(time_now, lifetime * USEC_PER_SEC);

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
        assert(link);
        assert(link->network);
        assert(rt);

        for (int r = sd_ndisc_router_option_rewind(rt); ; r = sd_ndisc_router_option_next(rt)) {
                uint8_t type;

                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to iterate through options: %m");
                if (r == 0) /* EOF */
                        return 0;

                r = sd_ndisc_router_option_get_type(rt, &type);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to get RA option type: %m");

                switch (type) {

                case SD_NDISC_OPTION_PREFIX_INFORMATION: {
                        unsigned prefixlen;
                        struct in6_addr a;
                        uint8_t flags;

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
                                break;
                        }

                        r = sd_ndisc_router_prefix_get_flags(rt, &flags);
                        if (r < 0)
                                return log_link_error_errno(link, r, "Failed to get RA prefix flags: %m");

                        if (link->network->ipv6_accept_ra_use_onlink_prefix &&
                            FLAGS_SET(flags, ND_OPT_PI_FLAG_ONLINK)) {
                                r = ndisc_router_process_onlink_prefix(link, rt);
                                if (r < 0)
                                        return r;
                        }

                        if (link->network->ipv6_accept_ra_use_autonomous_prefix &&
                            FLAGS_SET(flags, ND_OPT_PI_FLAG_AUTO)) {
                                r = ndisc_router_process_autonomous_prefix(link, rt);
                                if (r < 0)
                                        return r;
                        }
                        break;
                }

                case SD_NDISC_OPTION_ROUTE_INFORMATION:
                        r = ndisc_router_process_route(link, rt);
                        if (r < 0)
                                return r;
                        break;

                case SD_NDISC_OPTION_RDNSS:
                        if (link->network->ipv6_accept_ra_use_dns) {
                                r = ndisc_router_process_rdnss(link, rt);
                                if (r < 0)
                                        return r;
                        }
                        break;

                case SD_NDISC_OPTION_DNSSL:
                        if (link->network->ipv6_accept_ra_use_dns) {
                                r = ndisc_router_process_dnssl(link, rt);
                                if (r < 0)
                                        return r;
                        }
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

static int ndisc_router_handler(Link *link, sd_ndisc_router *rt) {
        struct in6_addr router;
        uint64_t flags;
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

        r = sd_ndisc_router_get_flags(rt, &flags);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get RA flags: %m");

        if ((flags & (ND_RA_FLAG_MANAGED | ND_RA_FLAG_OTHER) &&
             link->network->ipv6_accept_ra_start_dhcp6_client != IPV6_ACCEPT_RA_START_DHCP6_CLIENT_NO) ||
            link->network->ipv6_accept_ra_start_dhcp6_client == IPV6_ACCEPT_RA_START_DHCP6_CLIENT_ALWAYS) {

                if (flags & (ND_RA_FLAG_MANAGED | ND_RA_FLAG_OTHER))
                        /* (re)start DHCPv6 client in stateful or stateless mode according to RA flags */
                        r = dhcp6_request_information(link, !(flags & ND_RA_FLAG_MANAGED));
                else
                        /* When IPv6AcceptRA.DHCPv6Client=always, start dhcp6 client in managed mode
                         * even if router does not have M or O flag. */
                        r = dhcp6_request_information(link, false);
                if (r < 0 && r != -EBUSY)
                        return log_link_error_errno(link, r, "Could not acquire DHCPv6 lease on NDisc request: %m");
                else
                        log_link_debug(link, "Acquiring DHCPv6 lease on NDisc request");
        }

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
                if (r->valid_until < time_now)
                        free(set_remove(link->ndisc_rdnss, r));

        SET_FOREACH(d, link->ndisc_dnssl)
                if (d->valid_until < time_now)
                        free(set_remove(link->ndisc_dnssl, d));
}

void ndisc_flush(Link *link) {
        assert(link);

        /* Removes all RDNSS and DNSSL entries, without exception */

        link->ndisc_rdnss = set_free(link->ndisc_rdnss);
        link->ndisc_dnssl = set_free(link->ndisc_dnssl);
}

static int ipv6token_new(IPv6Token **ret) {
        IPv6Token *p;

        p = new(IPv6Token, 1);
        if (!p)
                return -ENOMEM;

        *p = (IPv6Token) {
                 .address_generation_type = IPV6_TOKEN_ADDRESS_GENERATION_NONE,
        };

        *ret = TAKE_PTR(p);

        return 0;
}

static void ipv6_token_hash_func(const IPv6Token *p, struct siphash *state) {
        siphash24_compress(&p->address_generation_type, sizeof(p->address_generation_type), state);
        siphash24_compress(&p->prefix, sizeof(p->prefix), state);
}

static int ipv6_token_compare_func(const IPv6Token *a, const IPv6Token *b) {
        int r;

        r = CMP(a->address_generation_type, b->address_generation_type);
        if (r != 0)
                return r;

        return memcmp(&a->prefix, &b->prefix, sizeof(struct in6_addr));
}

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
                ipv6_token_hash_ops,
                IPv6Token,
                ipv6_token_hash_func,
                ipv6_token_compare_func,
                free);

int config_parse_address_generation_type(
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

        _cleanup_free_ IPv6Token *token = NULL;
        union in_addr_union buffer;
        Network *network = data;
        const char *p;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                network->ipv6_tokens = ordered_set_free(network->ipv6_tokens);
                return 0;
        }

        r = ipv6token_new(&token);
        if (r < 0)
                return log_oom();

        if ((p = startswith(rvalue, "prefixstable"))) {
                token->address_generation_type = IPV6_TOKEN_ADDRESS_GENERATION_PREFIXSTABLE;
                if (*p == ':')
                        p++;
                else if (*p == '\0')
                        p = NULL;
                else {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Invalid IPv6 token mode in %s=, ignoring assignment: %s",
                                   lvalue, rvalue);
                        return 0;
                }
        } else {
                token->address_generation_type = IPV6_TOKEN_ADDRESS_GENERATION_STATIC;
                p = startswith(rvalue, "static:");
                if (!p)
                        p = rvalue;
        }

        if (p) {
                r = in_addr_from_string(AF_INET6, p, &buffer);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse IP address in %s=, ignoring assignment: %s",
                                   lvalue, rvalue);
                        return 0;
                }
                if (token->address_generation_type == IPV6_TOKEN_ADDRESS_GENERATION_STATIC &&
                    in_addr_is_null(AF_INET6, &buffer)) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "IPv6 address in %s= cannot be the ANY address, ignoring assignment: %s",
                                   lvalue, rvalue);
                        return 0;
                }
                token->prefix = buffer.in6;
        }

        r = ordered_set_ensure_put(&network->ipv6_tokens, &ipv6_token_hash_ops, token);
        if (r == -ENOMEM)
                return log_oom();
        if (r == -EEXIST)
                log_syntax(unit, LOG_DEBUG, filename, line, r,
                           "IPv6 token '%s' is duplicated, ignoring: %m", rvalue);
        else if (r < 0)
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to store IPv6 token '%s', ignoring: %m", rvalue);
        else
                TAKE_PTR(token);

        return 0;
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
