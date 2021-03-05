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
#include "networkd-state-file.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"

#define NDISC_DNSSL_MAX 64U
#define NDISC_RDNSS_MAX 64U
#define NDISC_PREFIX_LFT_MIN 7200U

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

static int ndisc_remove_old_one(Link *link, const struct in6_addr *router, bool force);

static int ndisc_address_callback(Address *address) {
        struct in6_addr router = {};
        NDiscAddress *n;

        assert(address);
        assert(address->link);

        SET_FOREACH(n, address->link->ndisc_addresses)
                if (n->address == address) {
                        router = n->router;
                        break;
                }

        if (in6_addr_is_null(&router)) {
                _cleanup_free_ char *buf = NULL;

                (void) in_addr_prefix_to_string(address->family, &address->in_addr, address->prefixlen, &buf);
                log_link_debug(address->link, "%s is called for %s, but it is already removed, ignoring.",
                               __func__, strna(buf));
                return 0;
        }

        /* Make this called only once */
        SET_FOREACH(n, address->link->ndisc_addresses)
                if (IN6_ARE_ADDR_EQUAL(&n->router, &router))
                        n->address->callback = NULL;

        return ndisc_remove_old_one(address->link, &router, true);
}

static int ndisc_remove_old_one(Link *link, const struct in6_addr *router, bool force) {
        NDiscAddress *na;
        NDiscRoute *nr;
        NDiscDNSSL *dnssl;
        NDiscRDNSS *rdnss;
        int k, r = 0;
        bool updated = false;

        assert(link);
        assert(router);

        if (!force) {
                bool set_callback = false;

                if (!link->ndisc_addresses_configured || !link->ndisc_routes_configured)
                        return 0;

                SET_FOREACH(na, link->ndisc_addresses)
                        if (!na->marked && IN6_ARE_ADDR_EQUAL(&na->router, router)) {
                                set_callback = true;
                                break;
                        }

                if (set_callback)
                        SET_FOREACH(na, link->ndisc_addresses)
                                if (!na->marked && address_is_ready(na->address)) {
                                        set_callback = false;
                                        break;
                                }

                if (set_callback) {
                        SET_FOREACH(na, link->ndisc_addresses)
                                if (!na->marked && IN6_ARE_ADDR_EQUAL(&na->router, router))
                                        na->address->callback = ndisc_address_callback;

                        if (DEBUG_LOGGING) {
                                _cleanup_free_ char *buf = NULL;

                                (void) in_addr_to_string(AF_INET6, (const union in_addr_union*) router, &buf);
                                log_link_debug(link, "No SLAAC address obtained from %s is ready. "
                                               "The old NDisc information will be removed later.",
                                               strna(buf));
                        }
                        return 0;
                }
        }

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *buf = NULL;

                (void) in_addr_to_string(AF_INET6, (const union in_addr_union*) router, &buf);
                log_link_debug(link, "Removing old NDisc information obtained from %s.", strna(buf));
        }

        SET_FOREACH(na, link->ndisc_addresses)
                if (na->marked && IN6_ARE_ADDR_EQUAL(&na->router, router)) {
                        k = address_remove(na->address, link, NULL);
                        if (k < 0)
                                r = k;
                }

        SET_FOREACH(nr, link->ndisc_routes)
                if (nr->marked && IN6_ARE_ADDR_EQUAL(&nr->router, router)) {
                        k = route_remove(nr->route, NULL, link, NULL);
                        if (k < 0)
                                r = k;
                }

        SET_FOREACH(rdnss, link->ndisc_rdnss)
                if (rdnss->marked && IN6_ARE_ADDR_EQUAL(&rdnss->router, router)) {
                        free(set_remove(link->ndisc_rdnss, rdnss));
                        updated = true;
                }

        SET_FOREACH(dnssl, link->ndisc_dnssl)
                if (dnssl->marked && IN6_ARE_ADDR_EQUAL(&dnssl->router, router)) {
                        free(set_remove(link->ndisc_dnssl, dnssl));
                        updated = true;
                }

        if (updated)
                link_dirty(link);

        return r;
}

static int ndisc_remove_old(Link *link) {
        _cleanup_set_free_free_ Set *routers = NULL;
        _cleanup_free_ struct in6_addr *router = NULL;
        struct in6_addr *a;
        NDiscAddress *na;
        NDiscRoute *nr;
        NDiscDNSSL *dnssl;
        NDiscRDNSS *rdnss;
        int k, r;

        assert(link);

        routers = set_new(&in6_addr_hash_ops);
        if (!routers)
                return -ENOMEM;

        SET_FOREACH(na, link->ndisc_addresses)
                if (!set_contains(routers, &na->router)) {
                        router = newdup(struct in6_addr, &na->router, 1);
                        if (!router)
                                return -ENOMEM;

                        r = set_put(routers, router);
                        if (r < 0)
                                return r;

                        assert(r > 0);
                        TAKE_PTR(router);
                }

        SET_FOREACH(nr, link->ndisc_routes)
                if (!set_contains(routers, &nr->router)) {
                        router = newdup(struct in6_addr, &nr->router, 1);
                        if (!router)
                                return -ENOMEM;

                        r = set_put(routers, router);
                        if (r < 0)
                                return r;

                        assert(r > 0);
                        TAKE_PTR(router);
                }

        SET_FOREACH(rdnss, link->ndisc_rdnss)
                if (!set_contains(routers, &rdnss->router)) {
                        router = newdup(struct in6_addr, &rdnss->router, 1);
                        if (!router)
                                return -ENOMEM;

                        r = set_put(routers, router);
                        if (r < 0)
                                return r;

                        assert(r > 0);
                        TAKE_PTR(router);
                }

        SET_FOREACH(dnssl, link->ndisc_dnssl)
                if (!set_contains(routers, &dnssl->router)) {
                        router = newdup(struct in6_addr, &dnssl->router, 1);
                        if (!router)
                                return -ENOMEM;

                        r = set_put(routers, router);
                        if (r < 0)
                                return r;

                        assert(r > 0);
                        TAKE_PTR(router);
                }

        r = 0;
        SET_FOREACH(a, routers) {
                k = ndisc_remove_old_one(link, a, false);
                if (k < 0)
                        r = k;
        }

        return r;
}

static void ndisc_route_hash_func(const NDiscRoute *x, struct siphash *state) {
        route_hash_func(x->route, state);
}

static int ndisc_route_compare_func(const NDiscRoute *a, const NDiscRoute *b) {
        return route_compare_func(a->route, b->route);
}

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
                ndisc_route_hash_ops,
                NDiscRoute,
                ndisc_route_hash_func,
                ndisc_route_compare_func,
                free);

static int ndisc_route_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);
        assert(link->ndisc_routes_messages > 0);

        link->ndisc_routes_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_message_error_errno(link, m, r, "Could not set NDisc route");
                link_enter_failed(link);
                return 1;
        }

        if (link->ndisc_routes_messages == 0) {
                log_link_debug(link, "NDisc routes set.");
                link->ndisc_routes_configured = true;

                r = ndisc_remove_old(link);
                if (r < 0) {
                        link_enter_failed(link);
                        return 1;
                }

                link_check_ready(link);
        }

        return 1;
}

static int ndisc_route_configure(Route *route, Link *link, sd_ndisc_router *rt) {
        _cleanup_free_ NDiscRoute *nr = NULL;
        NDiscRoute *nr_exist;
        struct in6_addr router;
        Route *ret;
        int r;

        assert(route);
        assert(link);
        assert(rt);

        r = route_configure(route, link, ndisc_route_handler, &ret);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to set NDisc route: %m");
        if (r > 0)
                link->ndisc_routes_configured = false;

        link->ndisc_routes_messages++;

        r = sd_ndisc_router_get_address(rt, &router);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get router address from RA: %m");

        nr = new(NDiscRoute, 1);
        if (!nr)
                return log_oom();

        *nr = (NDiscRoute) {
                .router = router,
                .route = ret,
        };

        nr_exist = set_get(link->ndisc_routes, nr);
        if (nr_exist) {
                nr_exist->marked = false;
                nr_exist->router = router;
                return 0;
        }

        r = set_ensure_put(&link->ndisc_routes, &ndisc_route_hash_ops, nr);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to store NDisc SLAAC route: %m");
        assert(r > 0);
        TAKE_PTR(nr);

        return 0;
}

static void ndisc_address_hash_func(const NDiscAddress *x, struct siphash *state) {
        address_hash_func(x->address, state);
}

static int ndisc_address_compare_func(const NDiscAddress *a, const NDiscAddress *b) {
        return address_compare_func(a->address, b->address);
}

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
                ndisc_address_hash_ops,
                NDiscAddress,
                ndisc_address_hash_func,
                ndisc_address_compare_func,
                free);

static int ndisc_address_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);
        assert(link->ndisc_addresses_messages > 0);

        link->ndisc_addresses_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_message_error_errno(link, m, r, "Could not set NDisc address");
                link_enter_failed(link);
                return 1;
        } else if (r >= 0)
                (void) manager_rtnl_process_address(rtnl, m, link->manager);

        if (link->ndisc_addresses_messages == 0) {
                log_link_debug(link, "NDisc SLAAC addresses set.");
                link->ndisc_addresses_configured = true;

                r = ndisc_remove_old(link);
                if (r < 0) {
                        link_enter_failed(link);
                        return 1;
                }
        }

        return 1;
}

static int ndisc_address_configure(Address *address, Link *link, sd_ndisc_router *rt) {
        _cleanup_free_ NDiscAddress *na = NULL;
        NDiscAddress *na_exist;
        struct in6_addr router;
        Address *ret;
        int r;

        assert(address);
        assert(link);
        assert(rt);

        r = address_configure(address, link, ndisc_address_handler, &ret);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to set NDisc SLAAC address: %m");
        if (r > 0)
                link->ndisc_addresses_configured = false;

        link->ndisc_addresses_messages++;

        r = sd_ndisc_router_get_address(rt, &router);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get router address from RA: %m");

        na = new(NDiscAddress, 1);
        if (!na)
                return log_oom();

        *na = (NDiscAddress) {
                .router = router,
                .address = ret,
        };

        na_exist = set_get(link->ndisc_addresses, na);
        if (na_exist) {
                na_exist->marked = false;
                na_exist->router = router;
                return 0;
        }

        r = set_ensure_put(&link->ndisc_addresses, &ndisc_address_hash_ops, na);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to store NDisc SLAAC address: %m");
        assert(r > 0);
        TAKE_PTR(na);

        return 0;
}

static int ndisc_router_process_default(Link *link, sd_ndisc_router *rt) {
        _cleanup_(route_freep) Route *route = NULL;
        union in_addr_union gateway;
        uint16_t lifetime;
        unsigned preference;
        uint32_t table, mtu;
        usec_t time_now;
        int r;

        assert(link);
        assert(rt);

        r = sd_ndisc_router_get_lifetime(rt, &lifetime);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get gateway lifetime from RA: %m");

        if (lifetime == 0) /* not a default router */
                return 0;

        r = sd_ndisc_router_get_address(rt, &gateway.in6);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get gateway address from RA: %m");

        if (link_has_ipv6_address(link, &gateway.in6) > 0) {
                if (DEBUG_LOGGING) {
                        _cleanup_free_ char *buffer = NULL;

                        (void) in_addr_to_string(AF_INET6, &gateway, &buffer);
                        log_link_debug(link, "No NDisc route added, gateway %s matches local address",
                                       strnull(buffer));
                }
                return 0;
        }

        r = sd_ndisc_router_get_preference(rt, &preference);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get default router preference from RA: %m");

        r = sd_ndisc_router_get_timestamp(rt, clock_boottime_or_monotonic(), &time_now);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get RA timestamp: %m");

        r = sd_ndisc_router_get_mtu(rt, &mtu);
        if (r == -ENODATA)
                mtu = 0;
        else if (r < 0)
                return log_link_error_errno(link, r, "Failed to get default router MTU from RA: %m");

        table = link_get_ipv6_accept_ra_route_table(link);

        r = route_new(&route);
        if (r < 0)
                return log_oom();

        route->family = AF_INET6;
        route->table = table;
        route->priority = link->network->dhcp6_route_metric;
        route->protocol = RTPROT_RA;
        route->pref = preference;
        route->gw_family = AF_INET6;
        route->gw = gateway;
        route->lifetime = usec_add(time_now, lifetime * USEC_PER_SEC);
        route->mtu = mtu;

        r = ndisc_route_configure(route, link, rt);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set default route: %m");

        Route *route_gw;
        HASHMAP_FOREACH(route_gw, link->network->routes_by_section) {
                if (!route_gw->gateway_from_dhcp_or_ra)
                        continue;

                if (route_gw->gw_family != AF_INET6)
                        continue;

                route_gw->gw = gateway;
                if (!route_gw->table_set)
                        route_gw->table = table;
                if (!route_gw->priority_set)
                        route_gw->priority = link->network->dhcp6_route_metric;
                if (!route_gw->protocol_set)
                        route_gw->protocol = RTPROT_RA;
                if (!route_gw->pref_set)
                        route->pref = preference;
                route_gw->lifetime = usec_add(time_now, lifetime * USEC_PER_SEC);
                if (route_gw->mtu == 0)
                        route_gw->mtu = mtu;

                r = ndisc_route_configure(route_gw, link, rt);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not set gateway: %m");
        }

        return 0;
}

static bool stableprivate_address_is_valid(const struct in6_addr *addr) {
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

static int make_stableprivate_address(Link *link, const struct in6_addr *prefix, uint8_t prefix_len, uint8_t dad_counter, struct in6_addr **ret) {
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
                return log_error_errno(r, "Failed to generate key: %m");

        siphash24_init(&state, secret_key.bytes);

        l = MAX(DIV_ROUND_UP(prefix_len, 8), 8);
        siphash24_compress(prefix, l, &state);
        siphash24_compress_string(link->ifname, &state);
        /* Only last 8 bytes of IB MAC are stable */
        if (link->iftype == ARPHRD_INFINIBAND)
                siphash24_compress(&link->hw_addr.addr.infiniband[12], 8, &state);
        else
                siphash24_compress(link->hw_addr.addr.bytes, link->hw_addr.length, &state);
        siphash24_compress(&dad_counter, sizeof(uint8_t), &state);

        rid = htole64(siphash24_finalize(&state));

        addr = new(struct in6_addr, 1);
        if (!addr)
                return log_oom();

        memcpy(addr->s6_addr, prefix->s6_addr, l);
        memcpy(addr->s6_addr + l, &rid, 16 - l);

        if (!stableprivate_address_is_valid(addr)) {
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
                    && (in6_addr_is_null(&j->prefix) || IN6_ARE_ADDR_EQUAL(&j->prefix, address))) {
                        /* While this loop uses dad_counter and a retry limit as specified in RFC 7217, the loop
                         * does not actually attempt Duplicate Address Detection; the counter will be incremented
                         * only when the address generation algorithm produces an invalid address, and the loop
                         * may exit with an address which ends up being unusable due to duplication on the link. */
                        for (; j->dad_counter < DAD_CONFLICTS_IDGEN_RETRIES_RFC7217; j->dad_counter++) {
                                r = make_stableprivate_address(link, address, prefixlen, j->dad_counter, &new_address);
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
        uint32_t lifetime_valid, lifetime_preferred, lifetime_remaining;
        _cleanup_set_free_free_ Set *addresses = NULL;
        _cleanup_(address_freep) Address *address = NULL;
        struct in6_addr addr, *a;
        unsigned prefixlen;
        usec_t time_now;
        int r;

        assert(link);
        assert(rt);

        r = sd_ndisc_router_get_timestamp(rt, clock_boottime_or_monotonic(), &time_now);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get RA timestamp: %m");

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

        r = sd_ndisc_router_prefix_get_address(rt, &addr);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get prefix address: %m");

        r = ndisc_router_generate_addresses(link, &addr, prefixlen, &addresses);
        if (r < 0)
                return r;

        r = address_new(&address);
        if (r < 0)
                return log_oom();

        address->family = AF_INET6;
        address->prefixlen = prefixlen;
        address->flags = IFA_F_NOPREFIXROUTE|IFA_F_MANAGETEMPADDR;
        address->cinfo.ifa_prefered = lifetime_preferred;

        SET_FOREACH(a, addresses) {
                Address *existing_address;

                address->in_addr.in6 = *a;

                /* see RFC4862 section 5.5.3.e */
                r = address_get(link, address, &existing_address);
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
                        continue; /* see RFC4862 section 5.5.3.d */

                if (address->cinfo.ifa_valid == 0)
                        continue;

                r = ndisc_address_configure(address, link, rt);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not set SLAAC address: %m");
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
        route->table = link_get_ipv6_accept_ra_route_table(link);
        route->priority = link->network->dhcp6_route_metric;
        route->protocol = RTPROT_RA;
        route->flags = RTM_F_PREFIX;
        route->dst_prefixlen = prefixlen;
        route->lifetime = usec_add(time_now, lifetime * USEC_PER_SEC);

        r = sd_ndisc_router_prefix_get_address(rt, &route->dst.in6);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get prefix address: %m");

        r = ndisc_route_configure(route, link, rt);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set prefix route: %m");;

        return 0;
}

static int ndisc_router_process_route(Link *link, sd_ndisc_router *rt) {
        _cleanup_(route_freep) Route *route = NULL;
        union in_addr_union gateway, dst;
        uint32_t lifetime;
        unsigned preference, prefixlen;
        usec_t time_now;
        int r;

        assert(link);

        r = sd_ndisc_router_route_get_lifetime(rt, &lifetime);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get gateway lifetime from RA: %m");

        if (lifetime == 0)
                return 0;

        r = sd_ndisc_router_route_get_address(rt, &dst.in6);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get route address: %m");

        if ((!set_isempty(link->network->ndisc_allow_listed_route_prefix) &&
             !set_contains(link->network->ndisc_allow_listed_route_prefix, &dst.in6)) ||
            set_contains(link->network->ndisc_deny_listed_route_prefix, &dst.in6)) {
                if (DEBUG_LOGGING) {
                        _cleanup_free_ char *buf = NULL;

                        (void) in_addr_to_string(AF_INET6, &dst, &buf);
                        if (!set_isempty(link->network->ndisc_allow_listed_route_prefix))
                                log_link_debug(link, "Route prefix '%s' is not in allow list, ignoring", strnull(buf));
                        else
                                log_link_debug(link, "Route prefix '%s' is in deny list, ignoring", strnull(buf));
                }
                return 0;
        }

        r = sd_ndisc_router_get_address(rt, &gateway.in6);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get gateway address from RA: %m");

        if (link_has_ipv6_address(link, &gateway.in6) > 0) {
                if (DEBUG_LOGGING) {
                        _cleanup_free_ char *buf = NULL;

                        (void) in_addr_to_string(AF_INET6, &gateway, &buf);
                        log_link_debug(link, "Advertised route gateway, %s, is local to the link, ignoring route", strnull(buf));
                }
                return 0;
        }

        r = sd_ndisc_router_route_get_prefixlen(rt, &prefixlen);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get route prefix length: %m");

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
        route->table = link_get_ipv6_accept_ra_route_table(link);
        route->priority = link->network->dhcp6_route_metric;
        route->protocol = RTPROT_RA;
        route->pref = preference;
        route->gw = gateway;
        route->gw_family = AF_INET6;
        route->dst = dst;
        route->dst_prefixlen = prefixlen;
        route->lifetime = usec_add(time_now, lifetime * USEC_PER_SEC);

        r = ndisc_route_configure(route, link, rt);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set additional route: %m");

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
        NDiscRDNSS *rdnss;
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

        SET_FOREACH(rdnss, link->ndisc_rdnss)
                if (IN6_ARE_ADDR_EQUAL(&rdnss->router, &router))
                        rdnss->marked = true;

        if (lifetime == 0)
                return 0;

        if (n >= (int) NDISC_RDNSS_MAX) {
                log_link_warning(link, "Too many RDNSS records per link. Only first %i records will be used.", NDISC_RDNSS_MAX);
                n = NDISC_RDNSS_MAX;
        }

        for (int j = 0; j < n; j++) {
                _cleanup_free_ NDiscRDNSS *x = NULL;
                NDiscRDNSS d = {
                        .address = a[j],
                };

                rdnss = set_get(link->ndisc_rdnss, &d);
                if (rdnss) {
                        rdnss->marked = false;
                        rdnss->router = router;
                        rdnss->valid_until = time_now + lifetime * USEC_PER_SEC;
                        continue;
                }

                x = new(NDiscRDNSS, 1);
                if (!x)
                        return log_oom();

                *x = (NDiscRDNSS) {
                        .address = a[j],
                        .router = router,
                        .valid_until = time_now + lifetime * USEC_PER_SEC,
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
        NDiscDNSSL *dnssl;
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

        SET_FOREACH(dnssl, link->ndisc_dnssl)
                if (IN6_ARE_ADDR_EQUAL(&dnssl->router, &router))
                        dnssl->marked = true;

        if (lifetime == 0)
                return 0;

        if (strv_length(l) >= NDISC_DNSSL_MAX) {
                log_link_warning(link, "Too many DNSSL records per link. Only first %i records will be used.", NDISC_DNSSL_MAX);
                STRV_FOREACH(j, l + NDISC_DNSSL_MAX)
                        *j = mfree(*j);
        }

        STRV_FOREACH(j, l) {
                _cleanup_free_ NDiscDNSSL *s = NULL;

                s = malloc0(ALIGN(sizeof(NDiscDNSSL)) + strlen(*j) + 1);
                if (!s)
                        return log_oom();

                strcpy(NDISC_DNSSL_DOMAIN(s), *j);

                dnssl = set_get(link->ndisc_dnssl, s);
                if (dnssl) {
                        dnssl->marked = false;
                        dnssl->router = router;
                        dnssl->valid_until = time_now + lifetime * USEC_PER_SEC;
                        continue;
                }

                s->router = router;
                s->valid_until = time_now + lifetime * USEC_PER_SEC;

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
                        union in_addr_union a;
                        uint8_t flags;

                        r = sd_ndisc_router_prefix_get_address(rt, &a.in6);
                        if (r < 0)
                                return log_link_error_errno(link, r, "Failed to get prefix address: %m");

                        if ((!set_isempty(link->network->ndisc_allow_listed_prefix) &&
                             !set_contains(link->network->ndisc_allow_listed_prefix, &a.in6)) ||
                            set_contains(link->network->ndisc_deny_listed_prefix, &a.in6)) {
                                if (DEBUG_LOGGING) {
                                        _cleanup_free_ char *b = NULL;

                                        (void) in_addr_to_string(AF_INET6, &a, &b);
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

static int ndisc_router_handler(Link *link, sd_ndisc_router *rt) {
        union in_addr_union router;
        uint64_t flags;
        NDiscAddress *na;
        NDiscRoute *nr;
        int r;

        assert(link);
        assert(link->network);
        assert(link->manager);
        assert(rt);

        r = sd_ndisc_router_get_address(rt, &router.in6);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get router address from RA: %m");

        if ((!set_isempty(link->network->ndisc_allow_listed_router) &&
             !set_contains(link->network->ndisc_allow_listed_router, &router.in6)) ||
            set_contains(link->network->ndisc_deny_listed_router, &router.in6)) {
                if (DEBUG_LOGGING) {
                        _cleanup_free_ char *buf = NULL;

                        (void) in_addr_to_string(AF_INET6, &router, &buf);
                        if (!set_isempty(link->network->ndisc_allow_listed_router))
                                log_link_debug(link, "Router '%s' is not in allow list, ignoring", strna(buf));
                        else
                                log_link_debug(link, "Router '%s' is in deny list, ignoring", strna(buf));
                }
                return 0;
        }

        SET_FOREACH(na, link->ndisc_addresses)
                if (IN6_ARE_ADDR_EQUAL(&na->router, &router.in6))
                        na->marked = true;

        SET_FOREACH(nr, link->ndisc_routes)
                if (IN6_ARE_ADDR_EQUAL(&nr->router, &router.in6))
                        nr->marked = true;

        r = sd_ndisc_router_get_flags(rt, &flags);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get RA flags: %m");

        if ((flags & (ND_RA_FLAG_MANAGED | ND_RA_FLAG_OTHER) &&
             link->network->ipv6_accept_ra_start_dhcp6_client != IPV6_ACCEPT_RA_START_DHCP6_CLIENT_NO) ||
            link->network->ipv6_accept_ra_start_dhcp6_client == IPV6_ACCEPT_RA_START_DHCP6_CLIENT_ALWAYS) {

                if (flags & (ND_RA_FLAG_MANAGED | ND_RA_FLAG_OTHER))
                        /* (re)start DHCPv6 client in stateful or stateless mode according to RA flags */
                        r = dhcp6_request_address(link, !(flags & ND_RA_FLAG_MANAGED));
                else
                        /* When IPv6AcceptRA.DHCPv6Client=always, start dhcp6 client in managed mode
                         * even if router does not have M or O flag. */
                        r = dhcp6_request_address(link, false);
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

        if (link->ndisc_addresses_messages == 0)
                link->ndisc_addresses_configured = true;
        else
                log_link_debug(link, "Setting SLAAC addresses.");

        if (link->ndisc_routes_messages == 0)
                link->ndisc_routes_configured = true;
        else
                log_link_debug(link, "Setting NDisc routes.");

        r = ndisc_remove_old(link);
        if (r < 0)
                return r;

        if (link->ndisc_addresses_configured && link->ndisc_routes_configured)
                link_check_ready(link);
        else
                link_set_state(link, LINK_STATE_CONFIGURING);

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
                if (link->ndisc_addresses_messages == 0 && link->ndisc_routes_messages == 0) {
                        link->ndisc_addresses_configured = true;
                        link->ndisc_routes_configured = true;
                        link_check_ready(link);
                }
                break;
        default:
                assert_not_reached("Unknown NDisc event");
        }
}

int ndisc_configure(Link *link) {
        int r;

        assert(link);

        if (!link_ipv6_accept_ra_enabled(link))
                return 0;

        if (!link->ndisc) {
                r = sd_ndisc_new(&link->ndisc);
                if (r < 0)
                        return r;

                r = sd_ndisc_attach_event(link->ndisc, link->manager->event, 0);
                if (r < 0)
                        return r;
        }

        r = sd_ndisc_set_mac(link->ndisc, &link->hw_addr.addr.ether);
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

int ipv6token_new(IPv6Token **ret) {
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

DEFINE_HASH_OPS_WITH_KEY_DESTRUCTOR(
                ipv6_token_hash_ops,
                IPv6Token,
                ipv6_token_hash_func,
                ipv6_token_compare_func,
                free);

int config_parse_ndisc_address_filter(
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

        Set **list = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                *list = set_free_free(*list);
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *n = NULL;
                _cleanup_free_ struct in6_addr *a = NULL;
                union in_addr_union ip;

                r = extract_first_word(&p, &n, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse NDisc %s=, ignoring assignment: %s",
                                   lvalue, rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                r = in_addr_from_string(AF_INET6, n, &ip);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "NDisc %s= entry is invalid, ignoring assignment: %s",
                                   lvalue, n);
                        continue;
                }

                a = newdup(struct in6_addr, &ip.in6, 1);
                if (!a)
                        return log_oom();

                r = set_ensure_consume(list, &in6_addr_hash_ops, TAKE_PTR(a));
                if (r < 0)
                        return log_oom();
                if (r == 0)
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "NDisc %s= entry is duplicated, ignoring assignment: %s",
                                   lvalue, n);
        }
}

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

DEFINE_CONFIG_PARSE_ENUM(config_parse_ipv6_accept_ra_start_dhcp6_client, ipv6_accept_ra_start_dhcp6_client, IPv6AcceptRAStartDHCP6Client,
                         "Failed to parse DHCPv6Client= setting")
static const char* const ipv6_accept_ra_start_dhcp6_client_table[_IPV6_ACCEPT_RA_START_DHCP6_CLIENT_MAX] = {
        [IPV6_ACCEPT_RA_START_DHCP6_CLIENT_NO]     = "no",
        [IPV6_ACCEPT_RA_START_DHCP6_CLIENT_ALWAYS] = "always",
        [IPV6_ACCEPT_RA_START_DHCP6_CLIENT_YES]    = "yes",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(ipv6_accept_ra_start_dhcp6_client, IPv6AcceptRAStartDHCP6Client, IPV6_ACCEPT_RA_START_DHCP6_CLIENT_YES);
