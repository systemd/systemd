/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2014 Intel Corporation. All rights reserved.
***/

#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <linux/if.h>
#include <linux/if_arp.h>

#include "sd-ndisc.h"

#include "event-util.h"
#include "missing_network.h"
#include "ndisc-router-internal.h"
#include "networkd-address-generation.h"
#include "networkd-address.h"
#include "networkd-dhcp6.h"
#include "networkd-manager.h"
#include "networkd-ndisc.h"
#include "networkd-nexthop.h"
#include "networkd-queue.h"
#include "networkd-route.h"
#include "networkd-state-file.h"
#include "networkd-sysctl.h"
#include "sort-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "sysctl-util.h"

#define NDISC_DNSSL_MAX 64U
#define NDISC_RDNSS_MAX 64U
#define NDISC_ENCRYPTED_DNS_MAX 64U
/* Not defined in the RFC, but let's set an upper limit to make not consume much memory.
 * This should be safe as typically there should be at most 1 portal per network. */
#define NDISC_CAPTIVE_PORTAL_MAX 64U
/* Neither defined in the RFC. Just for safety. Otherwise, malformed messages can make clients trigger OOM.
 * Not sure if the threshold is high enough. Let's adjust later if not. */
#define NDISC_PREF64_MAX 64U

static int ndisc_drop_outdated(Link *link, const struct in6_addr *router, usec_t timestamp_usec);

bool link_ndisc_enabled(Link *link) {
        assert(link);

        if (!socket_ipv6_is_supported())
                return false;

        if (link->flags & IFF_LOOPBACK)
                return false;

        if (link->iftype == ARPHRD_CAN)
                return false;

        if (!link->network)
                return false;

        if (!link_may_have_ipv6ll(link, /* check_multicast = */ true))
                return false;

        /* Honor explicitly specified value. */
        if (link->network->ndisc >= 0)
                return link->network->ndisc;

        /* Disable if RADV is enabled. */
        if (link_radv_enabled(link))
                return false;

        /* Accept RAs if IPv6 forwarding is disabled, and ignore RAs if IPv6 forwarding is enabled. */
        int t = link_get_ip_forwarding(link, AF_INET6);
        if (t >= 0)
                return !t;

        /* Otherwise, defaults to true. */
        return true;
}

void network_adjust_ndisc(Network *network) {
        assert(network);

        if (!FLAGS_SET(network->link_local, ADDRESS_FAMILY_IPV6)) {
                if (network->ndisc > 0)
                        log_warning("%s: IPv6AcceptRA= is enabled but IPv6 link-local addressing is disabled or not supported. "
                                    "Disabling IPv6AcceptRA=.", network->filename);
                network->ndisc = false;
        }

        /* When RouterAllowList=, PrefixAllowList= or RouteAllowList= are specified, then
         * RouterDenyList=, PrefixDenyList= or RouteDenyList= are ignored, respectively. */
        if (!set_isempty(network->ndisc_allow_listed_router))
                network->ndisc_deny_listed_router = set_free_free(network->ndisc_deny_listed_router);
        if (!set_isempty(network->ndisc_allow_listed_prefix))
                network->ndisc_deny_listed_prefix = set_free_free(network->ndisc_deny_listed_prefix);
        if (!set_isempty(network->ndisc_allow_listed_route_prefix))
                network->ndisc_deny_listed_route_prefix = set_free_free(network->ndisc_deny_listed_route_prefix);
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

        link_check_ready(link);
        return 0;
}

static int ndisc_remove_unused_nexthop(Link *link, NextHop *nexthop) {
        int r;

        assert(link);
        assert(link->manager);
        assert(link->ifindex > 0);
        assert(nexthop);

        if (nexthop->source != NETWORK_CONFIG_SOURCE_NDISC)
                return 0;

        if (nexthop->ifindex != link->ifindex)
                return 0;

        Route *route;
        SET_FOREACH(route, nexthop->routes)
                if (route_exists(route) || route_is_requesting(route))
                        return 0;

        Request *req;
        ORDERED_SET_FOREACH(req, link->manager->request_queue) {
                if (req->type != REQUEST_TYPE_ROUTE)
                        continue;

                route = ASSERT_PTR(req->userdata);
                if (route->nexthop_id == nexthop->id)
                        return 0;
        }

        r = nexthop_remove_and_cancel(nexthop, link->manager);
        if (r < 0)
                return log_link_debug_errno(link, r, "Failed to remove unused nexthop: %m");

        return 0;
}

static int ndisc_remove_unused_nexthop_by_id(Link *link, uint32_t id) {
        assert(link);
        assert(link->manager);

        if (id == 0)
                return 0;

        NextHop *nexthop;
        if (nexthop_get_by_id(link->manager, id, &nexthop) < 0)
                return 0;

        return ndisc_remove_unused_nexthop(link, nexthop);
}

static int ndisc_remove_unused_nexthops(Link *link) {
        int ret = 0;

        assert(link);
        assert(link->manager);

        NextHop *nexthop;
        HASHMAP_FOREACH(nexthop, link->manager->nexthops_by_id)
                RET_GATHER(ret, ndisc_remove_unused_nexthop(link, nexthop));

        return ret;
}

#define NDISC_NEXTHOP_APP_ID SD_ID128_MAKE(76,d2,0f,1f,76,1e,44,d1,97,3a,52,5c,05,68,b5,0d)

static uint32_t ndisc_generate_nexthop_id(const NextHop *nexthop, Link *link, sd_id128_t app_id, uint64_t trial) {
        assert(nexthop);
        assert(link);

        struct siphash state;
        siphash24_init(&state, app_id.bytes);
        siphash24_compress_typesafe(nexthop->protocol, &state);
        siphash24_compress_string(link->ifname, &state);
        siphash24_compress_typesafe(nexthop->gw.address.in6, &state);
        siphash24_compress_typesafe(nexthop->provider.in6, &state);
        uint64_t n = htole64(trial);
        siphash24_compress_typesafe(n, &state);

        uint64_t result = htole64(siphash24_finalize(&state));
        return (uint32_t) ((result & 0xffffffff) ^ (result >> 32));
}

static bool ndisc_nexthop_equal(const NextHop *a, const NextHop *b) {
        assert(a);
        assert(b);

        if (a->source != b->source)
                return false;
        if (a->protocol != b->protocol)
                return false;
        if (a->ifindex != b->ifindex)
                return false;
        if (!in6_addr_equal(&a->provider.in6, &b->provider.in6))
                return false;
        if (!in6_addr_equal(&a->gw.address.in6, &b->gw.address.in6))
                return false;

        return true;
}

static bool ndisc_take_nexthop_id(NextHop *nexthop, const NextHop *existing, Manager *manager) {
        assert(nexthop);
        assert(nexthop->id == 0);
        assert(existing);
        assert(existing->id > 0);
        assert(manager);

        if (!ndisc_nexthop_equal(nexthop, existing))
                return false;

        log_nexthop_debug(existing, "Found matching", manager);
        nexthop->id = existing->id;
        return true;
}

static int ndisc_nexthop_find_id(NextHop *nexthop, Link *link) {
        NextHop *n;
        Request *req;
        int r;

        assert(nexthop);
        assert(link);
        assert(link->manager);

        sd_id128_t app_id;
        r = sd_id128_get_machine_app_specific(NDISC_NEXTHOP_APP_ID, &app_id);
        if (r < 0)
                return r;

        uint32_t id = ndisc_generate_nexthop_id(nexthop, link, app_id, 0);
        if (nexthop_get_by_id(link->manager, id, &n) >= 0 &&
            ndisc_take_nexthop_id(nexthop, n, link->manager))
                return true;
        if (nexthop_get_request_by_id(link->manager, id, &req) >= 0 &&
            ndisc_take_nexthop_id(nexthop, req->userdata, link->manager))
                return true;

        HASHMAP_FOREACH(n, link->manager->nexthops_by_id)
                if (ndisc_take_nexthop_id(nexthop, n, link->manager))
                        return true;

        ORDERED_SET_FOREACH(req, link->manager->request_queue) {
                if (req->type != REQUEST_TYPE_NEXTHOP)
                        continue;

                if (ndisc_take_nexthop_id(nexthop, req->userdata, link->manager))
                        return true;
        }

        return false;
}

static int ndisc_nexthop_new(const Route *route, Link *link, NextHop **ret) {
        _cleanup_(nexthop_unrefp) NextHop *nexthop = NULL;
        int r;

        assert(route);
        assert(link);
        assert(ret);

        r = nexthop_new(&nexthop);
        if (r < 0)
                return r;

        nexthop->source = NETWORK_CONFIG_SOURCE_NDISC;
        nexthop->provider = route->provider;
        nexthop->protocol = route->protocol == RTPROT_REDIRECT ? RTPROT_REDIRECT : RTPROT_RA;
        nexthop->family = AF_INET6;
        nexthop->gw.address = route->nexthop.gw;
        nexthop->ifindex = link->ifindex;

        r = ndisc_nexthop_find_id(nexthop, link);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(nexthop);
        return 0;
}

static int ndisc_nexthop_acquire_id(NextHop *nexthop, Link *link) {
        int r;

        assert(nexthop);
        assert(nexthop->id == 0);
        assert(link);
        assert(link->manager);

        sd_id128_t app_id;
        r = sd_id128_get_machine_app_specific(NDISC_NEXTHOP_APP_ID, &app_id);
        if (r < 0)
                return r;

        for (uint64_t trial = 0; trial < 100; trial++) {
                uint32_t id = ndisc_generate_nexthop_id(nexthop, link, app_id, trial);
                if (id == 0)
                        continue;

                if (set_contains(link->manager->nexthop_ids, UINT32_TO_PTR(id)))
                        continue; /* The ID is already used in a .network file. */

                if (nexthop_get_by_id(link->manager, id, NULL) >= 0)
                        continue; /* The ID is already used by an existing nexthop. */

                if (nexthop_get_request_by_id(link->manager, id, NULL) >= 0)
                        continue; /* The ID is already used by a nexthop being requested. */

                log_link_debug(link, "Generated new ndisc nexthop ID for %s with trial %"PRIu64": %"PRIu32,
                               IN6_ADDR_TO_STRING(&nexthop->gw.address.in6), trial, id);
                nexthop->id = id;
                return 0;
        }

        return log_link_debug_errno(link, SYNTHETIC_ERRNO(EBUSY), "Cannot find free nexthop ID for %s.",
                                    IN6_ADDR_TO_STRING(&nexthop->gw.address.in6));
}

static int ndisc_nexthop_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, NextHop *nexthop) {
        int r;

        assert(link);

        r = nexthop_configure_handler_internal(m, link, "Could not set NDisc route");
        if (r <= 0)
                return r;

        r = ndisc_check_ready(link);
        if (r < 0)
                link_enter_failed(link);

        return 1;
}

static int ndisc_request_nexthop(NextHop *nexthop, Link *link) {
        int r;

        assert(nexthop);
        assert(link);

        if (nexthop->id > 0)
                return 0;

        r = ndisc_nexthop_acquire_id(nexthop, link);
        if (r < 0)
                return r;

        r = link_request_nexthop(link, nexthop, &link->ndisc_messages, ndisc_nexthop_handler);
        if (r < 0)
                return r;
        if (r > 0)
                link->ndisc_configured = false;

        return 0;
}

static int ndisc_set_route_nexthop(Route *route, Link *link, bool request) {
        _cleanup_(nexthop_unrefp) NextHop *nexthop = NULL;
        int r;

        assert(route);
        assert(link);
        assert(link->manager);

        if (!link->manager->manage_foreign_nexthops)
                goto finalize;

        if (route->nexthop.family != AF_INET6 || in6_addr_is_null(&route->nexthop.gw.in6))
                goto finalize;

        r = ndisc_nexthop_new(route, link, &nexthop);
        if (r < 0)
                return r;

        if (nexthop->id == 0 && !request)
                goto finalize;

        r = ndisc_request_nexthop(nexthop, link);
        if (r < 0)
                return r;

        route->nexthop = (RouteNextHop) {};
        route->nexthop_id = nexthop->id;

finalize:
        return route_adjust_nexthops(route, link);
}

static int ndisc_route_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, Route *route) {
        int r;

        assert(req);
        assert(link);

        r = route_configure_handler_internal(rtnl, m, req, "Could not set NDisc route");
        if (r <= 0)
                return r;

        r = ndisc_check_ready(link);
        if (r < 0)
                link_enter_failed(link);

        return 1;
}

static void ndisc_set_route_priority(Link *link, Route *route) {
        assert(link);
        assert(route);

        if (route->priority_set)
                return; /* explicitly configured. */

        switch (route->pref) {
        case SD_NDISC_PREFERENCE_LOW:
                route->priority = link->network->ndisc_route_metric_low;
                break;
        case SD_NDISC_PREFERENCE_MEDIUM:
                route->priority = link->network->ndisc_route_metric_medium;
                break;
        case SD_NDISC_PREFERENCE_HIGH:
                route->priority = link->network->ndisc_route_metric_high;
                break;
        default:
                assert_not_reached();
        }
}

static int ndisc_request_route(Route *route, Link *link) {
        int r;

        assert(route);
        assert(link);
        assert(link->manager);
        assert(link->network);

        r = route_metric_set(&route->metric, RTAX_QUICKACK, link->network->ndisc_quickack);
        if (r < 0)
                return r;

        r = ndisc_set_route_nexthop(route, link, /* request = */ true);
        if (r < 0)
                return r;

        uint8_t pref, pref_original = route->pref;
        FOREACH_ARGUMENT(pref, SD_NDISC_PREFERENCE_LOW, SD_NDISC_PREFERENCE_MEDIUM, SD_NDISC_PREFERENCE_HIGH) {
                Route *existing;
                Request *req;

                /* If the preference is specified by the user config (that is, for semi-static routes),
                 * rather than RA, then only search conflicting routes that have the same preference. */
                if (route->pref_set && pref != pref_original)
                        continue;

                route->pref = pref;
                ndisc_set_route_priority(link, route);

                /* Note, here do not call route_remove_and_cancel() with 'route' directly, otherwise
                 * existing route(s) may be removed needlessly. */

                /* First, check if a conflicting route is already requested. If there is an existing route,
                 * and also an existing pending request, then the source may be updated by the request. So,
                 * we first need to check the source of the requested route. */
                if (route_get_request(link->manager, route, &req) >= 0) {
                        route->pref = pref_original;
                        ndisc_set_route_priority(link, route);

                        existing = ASSERT_PTR(req->userdata);
                        if (!route_can_update(existing, route)) {
                                if (existing->source == NETWORK_CONFIG_SOURCE_STATIC) {
                                        log_link_debug(link, "Found a pending route request that conflicts with new request based on a received RA, ignoring request.");
                                        return 0;
                                }

                                log_link_debug(link, "Found a pending route request that conflicts with new request based on a received RA, cancelling.");
                                r = route_remove_and_cancel(existing, link->manager);
                                if (r < 0)
                                        return r;
                        }
                }

                route->pref = pref;
                ndisc_set_route_priority(link, route);

                /* Then, check if a conflicting route exists. */
                if (route_get(link->manager, route, &existing) >= 0) {
                        route->pref = pref_original;
                        ndisc_set_route_priority(link, route);

                        if (!route_can_update(existing, route)) {
                                if (existing->source == NETWORK_CONFIG_SOURCE_STATIC) {
                                        log_link_debug(link, "Found an existing route that conflicts with new route based on a received RA, ignoring request.");
                                        return 0;
                                }

                                log_link_debug(link, "Found an existing route that conflicts with new route based on a received RA, removing.");
                                r = route_remove_and_cancel(existing, link->manager);
                                if (r < 0)
                                        return r;
                        }
                }
        }

        /* The preference (and priority) may be changed in the above loop. Restore it. */
        route->pref = pref_original;
        ndisc_set_route_priority(link, route);

        bool is_new = route_get(link->manager, route, NULL) < 0;

        r = link_request_route(link, route, &link->ndisc_messages, ndisc_route_handler);
        if (r < 0)
                return r;
        if (r > 0 && is_new)
                link->ndisc_configured = false;

        return 0;
}

static void ndisc_route_prepare(Route *route, Link *link) {
        assert(route);
        assert(link);

        route->source = NETWORK_CONFIG_SOURCE_NDISC;

        if (!route->table_set)
                route->table = link_get_ndisc_route_table(link);
}

static int ndisc_router_route_prepare(Route *route, Link *link, sd_ndisc_router *rt) {
        assert(route);
        assert(link);
        assert(rt);

        ndisc_route_prepare(route, link);

        if (!route->protocol_set)
                route->protocol = RTPROT_RA;

        return sd_ndisc_router_get_sender_address(rt, &route->provider.in6);
}

static int ndisc_request_router_route(Route *route, Link *link, sd_ndisc_router *rt) {
        int r;

        assert(route);
        assert(link);
        assert(rt);

        r = ndisc_router_route_prepare(route, link, rt);
        if (r < 0)
                return r;

        return ndisc_request_route(route, link);
}

static int ndisc_remove_route(Route *route, Link *link) {
        int r, ret = 0;

        assert(route);
        assert(link);
        assert(link->manager);

        r = ndisc_set_route_nexthop(route, link, /* request = */ false);
        if (r < 0)
                return r;

        uint8_t pref, pref_original = route->pref;
        FOREACH_ARGUMENT(pref, SD_NDISC_PREFERENCE_LOW, SD_NDISC_PREFERENCE_MEDIUM, SD_NDISC_PREFERENCE_HIGH) {
                Route *existing;
                Request *req;

                /* If the preference is specified by the user config (that is, for semi-static routes),
                 * rather than RA, then only search conflicting routes that have the same preference. */
                if (route->pref_set && pref != pref_original)
                        continue;

                route->pref = pref;
                ndisc_set_route_priority(link, route);

                /* Unfortunately, we cannot directly pass 'route' to route_remove_and_cancel() here, as the
                 * same or similar route may be configured or requested statically. */

                /* First, check if the route is already requested. If there is an existing route, and also an
                 * existing pending request, then the source may be updated by the request. So, we first need
                 * to check the source of the requested route. */
                if (route_get_request(link->manager, route, &req) >= 0) {
                        existing = ASSERT_PTR(req->userdata);
                        if (existing->source == NETWORK_CONFIG_SOURCE_STATIC)
                                continue;

                        RET_GATHER(ret, route_remove_and_cancel(existing, link->manager));
                }

                /* Then, check if the route exists. */
                if (route_get(link->manager, route, &existing) >= 0) {
                        if (existing->source == NETWORK_CONFIG_SOURCE_STATIC)
                                continue;

                        RET_GATHER(ret, route_remove_and_cancel(existing, link->manager));
                }
        }

        return RET_GATHER(ret, ndisc_remove_unused_nexthop_by_id(link, route->nexthop_id));
}

static int ndisc_remove_router_route(Route *route, Link *link, sd_ndisc_router *rt) {
        int r;

        assert(route);
        assert(link);
        assert(rt);

        r = ndisc_router_route_prepare(route, link, rt);
        if (r < 0)
                return r;

        return ndisc_remove_route(route, link);
}

static int ndisc_address_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, Address *address) {
        int r;

        assert(link);

        r = address_configure_handler_internal(rtnl, m, link, "Could not set NDisc address");
        if (r <= 0)
                return r;

        r = ndisc_check_ready(link);
        if (r < 0)
                link_enter_failed(link);

        return 1;
}

static int ndisc_request_address(Address *address, Link *link) {
        bool is_new;
        int r;

        assert(address);
        assert(link);

        address->source = NETWORK_CONFIG_SOURCE_NDISC;

        r = free_and_strdup_warn(&address->netlabel, link->network->ndisc_netlabel);
        if (r < 0)
                return r;

        Address *existing;
        if (address_get_harder(link, address, &existing) < 0)
                is_new = true;
        else if (address_can_update(existing, address))
                is_new = false;
        else if (existing->source == NETWORK_CONFIG_SOURCE_DHCP6) {
                /* SLAAC address is preferred over DHCPv6 address. */
                log_link_debug(link, "Conflicting DHCPv6 address %s exists, removing.",
                               IN_ADDR_PREFIX_TO_STRING(existing->family, &existing->in_addr, existing->prefixlen));
                r = address_remove(existing, link);
                if (r < 0)
                        return r;

                is_new = true;
        } else {
                /* Conflicting static address is configured?? */
                log_link_debug(link, "Conflicting address %s exists, ignoring request.",
                               IN_ADDR_PREFIX_TO_STRING(existing->family, &existing->in_addr, existing->prefixlen));
                return 0;
        }

        r = link_request_address(link, address, &link->ndisc_messages,
                                 ndisc_address_handler, NULL);
        if (r < 0)
                return r;
        if (r > 0 && is_new)
                link->ndisc_configured = false;

        return 0;
}

int ndisc_reconfigure_address(Address *address, Link *link) {
        int r;

        assert(address);
        assert(address->source == NETWORK_CONFIG_SOURCE_NDISC);
        assert(link);

        r = regenerate_address(address, link);
        if (r <= 0)
                return r;

        r = ndisc_request_address(address, link);
        if (r < 0)
                return r;

        if (!link->ndisc_configured)
                link_set_state(link, LINK_STATE_CONFIGURING);

        link_check_ready(link);
        return 0;
}

static int ndisc_redirect_route_new(sd_ndisc_redirect *rd, Route **ret) {
        _cleanup_(route_unrefp) Route *route = NULL;
        struct in6_addr gateway, destination;
        int r;

        assert(rd);
        assert(ret);

        r = sd_ndisc_redirect_get_target_address(rd, &gateway);
        if (r < 0)
                return r;

        r = sd_ndisc_redirect_get_destination_address(rd, &destination);
        if (r < 0)
                return r;

        r = route_new(&route);
        if (r < 0)
                return r;

        route->family = AF_INET6;
        if (!in6_addr_equal(&gateway, &destination)) {
                route->nexthop.gw.in6 = gateway;
                route->nexthop.family = AF_INET6;
        }
        route->dst.in6 = destination;
        route->dst_prefixlen = 128;
        route->protocol = RTPROT_REDIRECT;

        r = sd_ndisc_redirect_get_sender_address(rd, &route->provider.in6);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(route);
        return 0;
}

static int ndisc_remove_redirect_route(Link *link, sd_ndisc_redirect *rd) {
        _cleanup_(route_unrefp) Route *route = NULL;
        int r;

        assert(link);
        assert(rd);

        r = ndisc_redirect_route_new(rd, &route);
        if (r < 0)
                return r;

        ndisc_route_prepare(route, link);

        return ndisc_remove_route(route, link);
}

static void ndisc_redirect_hash_func(const sd_ndisc_redirect *x, struct siphash *state) {
        struct in6_addr dest = {};

        assert(x);
        assert(state);

        (void) sd_ndisc_redirect_get_destination_address((sd_ndisc_redirect*) x, &dest);

        siphash24_compress_typesafe(dest, state);
}

static int ndisc_redirect_compare_func(const sd_ndisc_redirect *x, const sd_ndisc_redirect *y) {
        struct in6_addr dest_x = {}, dest_y = {};

        assert(x);
        assert(y);

        (void) sd_ndisc_redirect_get_destination_address((sd_ndisc_redirect*) x, &dest_x);
        (void) sd_ndisc_redirect_get_destination_address((sd_ndisc_redirect*) y, &dest_y);

        return memcmp(&dest_x, &dest_y, sizeof(dest_x));
}

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
                ndisc_redirect_hash_ops,
                sd_ndisc_redirect,
                ndisc_redirect_hash_func,
                ndisc_redirect_compare_func,
                sd_ndisc_redirect_unref);

static int ndisc_redirect_equal(sd_ndisc_redirect *x, sd_ndisc_redirect *y) {
        struct in6_addr a, b;
        int r;

        assert(x);
        assert(y);

        r = sd_ndisc_redirect_get_destination_address(x, &a);
        if (r < 0)
                return r;

        r = sd_ndisc_redirect_get_destination_address(y, &b);
        if (r < 0)
                return r;

        if (!in6_addr_equal(&a, &b))
                return false;

        r = sd_ndisc_redirect_get_target_address(x, &a);
        if (r < 0)
                return r;

        r = sd_ndisc_redirect_get_target_address(y, &b);
        if (r < 0)
                return r;

        return in6_addr_equal(&a, &b);
}

static int ndisc_redirect_drop_conflict(Link *link, sd_ndisc_redirect *rd) {
        _cleanup_(sd_ndisc_redirect_unrefp) sd_ndisc_redirect *existing = NULL;
        int r;

        assert(link);
        assert(rd);

        existing = set_remove(link->ndisc_redirects, rd);
        if (!existing)
                return 0;

        r = ndisc_redirect_equal(rd, existing);
        if (r != 0)
                return r;

        return ndisc_remove_redirect_route(link, existing);
}

static int ndisc_redirect_verify_sender(Link *link, sd_ndisc_redirect *rd) {
        int r;

        assert(link);
        assert(rd);

        /* RFC 4861 section 8.1
        * The IP source address of the Redirect is the same as the current first-hop router for the specified
        * ICMP Destination Address. */

        struct in6_addr sender;
        r = sd_ndisc_redirect_get_sender_address(rd, &sender);
        if (r < 0)
                return r;

        /* We will reuse the sender's router lifetime as the lifetime of the redirect route. Hence, if we
         * have not remembered an RA from the sender, refuse the Redirect message. */
        sd_ndisc_router *router = hashmap_get(link->ndisc_routers_by_sender, &sender);
        if (!router)
                return false;

        sd_ndisc_redirect *existing = set_get(link->ndisc_redirects, rd);
        if (existing) {
                struct in6_addr target, dest;

                /* If we have received Redirect message for the host, the sender must be the previous target. */

                r = sd_ndisc_redirect_get_target_address(existing, &target);
                if (r < 0)
                        return r;

                if (in6_addr_equal(&sender, &target))
                        return true;

                /* If the existing redirect route is on-link, that is, the destination and target address are
                 * equivalent, then also accept Redirect message from the current default router. This is not
                 * mentioned by the RFC, but without this, we cannot update on-link redirect route. */
                r = sd_ndisc_redirect_get_destination_address(existing, &dest);
                if (r < 0)
                        return r;

                if (!in6_addr_equal(&dest, &target))
                        return false;
        }

        /* Check if the sender is one of the known router with highest priority. */
        uint8_t preference;
        r = sd_ndisc_router_get_preference(router, &preference);
        if (r < 0)
                return r;

        if (preference == SD_NDISC_PREFERENCE_HIGH)
                return true;

        sd_ndisc_router *rt;
        HASHMAP_FOREACH(rt, link->ndisc_routers_by_sender) {
                if (rt == router)
                        continue;

                uint8_t pref;
                if (sd_ndisc_router_get_preference(rt, &pref) < 0)
                        continue;

                if (pref == SD_NDISC_PREFERENCE_HIGH ||
                    (pref == SD_NDISC_PREFERENCE_MEDIUM && preference == SD_NDISC_PREFERENCE_LOW))
                        return false;
        }

        return true;
}

static int ndisc_redirect_handler(Link *link, sd_ndisc_redirect *rd) {
        int r;

        assert(link);
        assert(link->network);
        assert(rd);

        if (!link->network->ndisc_use_redirect)
                return 0;

        usec_t now_usec;
        r = sd_event_now(link->manager->event, CLOCK_BOOTTIME, &now_usec);
        if (r < 0)
                return r;

        r = ndisc_drop_outdated(link, /* router = */ NULL, now_usec);
        if (r < 0)
                return r;

        r = ndisc_redirect_verify_sender(link, rd);
        if (r <= 0)
                return r;

        /* First, drop conflicting redirect route, if exists. */
        r = ndisc_redirect_drop_conflict(link, rd);
        if (r < 0)
                return r;

        /* Then, remember the received message. */
        r = set_ensure_put(&link->ndisc_redirects, &ndisc_redirect_hash_ops, rd);
        if (r < 0)
                return r;

        sd_ndisc_redirect_ref(rd);

        /* Finally, request the corresponding route. */
        _cleanup_(route_unrefp) Route *route = NULL;
        r = ndisc_redirect_route_new(rd, &route);
        if (r < 0)
                return r;

        sd_ndisc_router *rt = hashmap_get(link->ndisc_routers_by_sender, &route->provider.in6);
        if (!rt)
                return -EADDRNOTAVAIL;

        r = sd_ndisc_router_get_lifetime_timestamp(rt, CLOCK_BOOTTIME, &route->lifetime_usec);
        if (r < 0)
                return r;

        ndisc_route_prepare(route, link);

        return ndisc_request_route(route, link);
}

static int ndisc_drop_redirect(Link *link, const struct in6_addr *router) {
        int r, ret = 0;

        assert(link);

        sd_ndisc_redirect *rd;
        SET_FOREACH(rd, link->ndisc_redirects) {
                if (router) {
                        struct in6_addr a;

                        if (!(sd_ndisc_redirect_get_sender_address(rd, &a) >= 0 && in6_addr_equal(&a, router)) &&
                            !(sd_ndisc_redirect_get_target_address(rd, &a) >= 0 && in6_addr_equal(&a, router)))
                                continue;
                }

                r = ndisc_remove_redirect_route(link, rd);
                if (r < 0)
                        RET_GATHER(ret, log_link_warning_errno(link, r, "Failed to remove redirect route, ignoring: %m"));

                sd_ndisc_redirect_unref(set_remove(link->ndisc_redirects, rd));
        }

        return ret;
}

static int ndisc_update_redirect_sender(Link *link, const struct in6_addr *original_address, const struct in6_addr *current_address) {
        int r;

        assert(link);
        assert(original_address);
        assert(current_address);

        sd_ndisc_redirect *rd;
        SET_FOREACH(rd, link->ndisc_redirects) {
                struct in6_addr sender;

                r = sd_ndisc_redirect_get_sender_address(rd, &sender);
                if (r < 0)
                        return r;

                if (!in6_addr_equal(&sender, original_address))
                        continue;

                r = sd_ndisc_redirect_set_sender_address(rd, current_address);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int ndisc_router_drop_default(Link *link, sd_ndisc_router *rt) {
        _cleanup_(route_unrefp) Route *route = NULL;
        struct in6_addr gateway;
        int r;

        assert(link);
        assert(link->network);
        assert(rt);

        r = sd_ndisc_router_get_sender_address(rt, &gateway);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get router address from RA: %m");

        r = route_new(&route);
        if (r < 0)
                return log_oom();

        route->family = AF_INET6;
        route->nexthop.family = AF_INET6;
        route->nexthop.gw.in6 = gateway;

        r = ndisc_remove_router_route(route, link, rt);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to remove the default gateway configured by RA: %m");

        Route *route_gw;
        HASHMAP_FOREACH(route_gw, link->network->routes_by_section) {
                _cleanup_(route_unrefp) Route *tmp = NULL;

                if (!route_gw->gateway_from_dhcp_or_ra)
                        continue;

                if (route_gw->nexthop.family != AF_INET6)
                        continue;

                r = route_dup(route_gw, NULL, &tmp);
                if (r < 0)
                        return r;

                tmp->nexthop.gw.in6 = gateway;

                r = ndisc_remove_router_route(tmp, link, rt);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Could not remove semi-static gateway: %m");
        }

        return 0;
}

static int ndisc_router_process_default(Link *link, sd_ndisc_router *rt) {
        usec_t lifetime_usec;
        struct in6_addr gateway;
        uint8_t preference;
        int r;

        assert(link);
        assert(link->network);
        assert(rt);

        /* If the router lifetime is zero, the router should not be used as the default gateway. */
        r = sd_ndisc_router_get_lifetime(rt, NULL);
        if (r < 0)
                return r;
        if (r == 0)
                return ndisc_router_drop_default(link, rt);

        if (!link->network->ndisc_use_gateway &&
            hashmap_isempty(link->network->routes_by_section))
                return 0;

        r = sd_ndisc_router_get_lifetime_timestamp(rt, CLOCK_BOOTTIME, &lifetime_usec);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get gateway lifetime from RA: %m");

        r = sd_ndisc_router_get_sender_address(rt, &gateway);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get gateway address from RA: %m");

        r = sd_ndisc_router_get_preference(rt, &preference);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get router preference from RA: %m");

        if (link->network->ndisc_use_gateway) {
                _cleanup_(route_unrefp) Route *route = NULL;

                r = route_new(&route);
                if (r < 0)
                        return log_oom();

                route->family = AF_INET6;
                route->pref = preference;
                route->nexthop.family = AF_INET6;
                route->nexthop.gw.in6 = gateway;
                route->lifetime_usec = lifetime_usec;

                r = ndisc_request_router_route(route, link, rt);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Could not request default route: %m");
        }

        Route *route_gw;
        HASHMAP_FOREACH(route_gw, link->network->routes_by_section) {
                _cleanup_(route_unrefp) Route *route = NULL;

                if (!route_gw->gateway_from_dhcp_or_ra)
                        continue;

                if (route_gw->nexthop.family != AF_INET6)
                        continue;

                r = route_dup(route_gw, NULL, &route);
                if (r < 0)
                        return r;

                route->nexthop.gw.in6 = gateway;
                if (!route->pref_set)
                        route->pref = preference;
                route->lifetime_usec = lifetime_usec;

                r = ndisc_request_router_route(route, link, rt);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Could not request gateway: %m");
        }

        return 0;
}

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                ndisc_router_hash_ops,
                struct in6_addr,
                in6_addr_hash_func,
                in6_addr_compare_func,
                sd_ndisc_router,
                sd_ndisc_router_unref);

static int ndisc_update_router_address(Link *link, const struct in6_addr *original_address, const struct in6_addr *current_address) {
        _cleanup_(sd_ndisc_router_unrefp) sd_ndisc_router *rt = NULL;
        int r;

        assert(link);
        assert(original_address);
        assert(current_address);

        rt = hashmap_remove(link->ndisc_routers_by_sender, original_address);
        if (!rt)
                return 0;

        /* If we already received an RA from the new address, then forget the RA from the old address. */
        if (hashmap_contains(link->ndisc_routers_by_sender, current_address))
                return 0;

        /* Otherwise, update the sender address of the previously received RA. */
        r = sd_ndisc_router_set_sender_address(rt, current_address);
        if (r < 0)
                return r;

        r = hashmap_put(link->ndisc_routers_by_sender, &rt->packet->sender_address, rt);
        if (r < 0)
                return r;

        TAKE_PTR(rt);
        return 0;
}

static int ndisc_drop_router_one(Link *link, sd_ndisc_router *rt, usec_t timestamp_usec) {
        usec_t lifetime_usec;
        int r;

        assert(link);
        assert(rt);
        assert(rt->packet);

        r = sd_ndisc_router_get_lifetime_timestamp(rt, CLOCK_BOOTTIME, &lifetime_usec);
        if (r < 0)
                return r;

        if (lifetime_usec > timestamp_usec)
                return 0;

        r = ndisc_drop_redirect(link, &rt->packet->sender_address);

        sd_ndisc_router_unref(hashmap_remove(link->ndisc_routers_by_sender, &rt->packet->sender_address));

        return r;
}

static int ndisc_drop_routers(Link *link, const struct in6_addr *router, usec_t timestamp_usec) {
        sd_ndisc_router *rt;
        int ret = 0;

        assert(link);

        if (router) {
                rt = hashmap_get(link->ndisc_routers_by_sender, router);
                if (!rt)
                        return 0;

                return ndisc_drop_router_one(link, rt, timestamp_usec);
        }

        HASHMAP_FOREACH_KEY(rt, router, link->ndisc_routers_by_sender)
                RET_GATHER(ret, ndisc_drop_router_one(link, rt, timestamp_usec));

        return ret;
}

static int ndisc_remember_router(Link *link, sd_ndisc_router *rt) {
        int r;

        assert(link);
        assert(rt);
        assert(rt->packet);

        sd_ndisc_router_unref(hashmap_remove(link->ndisc_routers_by_sender, &rt->packet->sender_address));

        /* Remember RAs with non-zero lifetime. */
        r = sd_ndisc_router_get_lifetime(rt, NULL);
        if (r <= 0)
                return r;

        r = hashmap_ensure_put(&link->ndisc_routers_by_sender, &ndisc_router_hash_ops, &rt->packet->sender_address, rt);
        if (r < 0)
                return r;

        sd_ndisc_router_ref(rt);
        return 0;
}

static int ndisc_router_process_reachable_time(Link *link, sd_ndisc_router *rt) {
        usec_t reachable_time, msec;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->network);
        assert(rt);

        if (!link->network->ndisc_use_reachable_time)
                return 0;

        r = sd_ndisc_router_get_reachable_time(rt, &reachable_time);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get reachable time from RA: %m");

        /* 0 is the unspecified value and must not be set (see RFC4861, 6.3.4) */
        if (!timestamp_is_set(reachable_time))
                return 0;

        msec = DIV_ROUND_UP(reachable_time, USEC_PER_MSEC);
        if (msec <= 0 || msec > UINT32_MAX) {
                log_link_debug(link, "Failed to get reachable time from RA - out of range (%"PRIu64"), ignoring", msec);
                return 0;
        }

        /* Set the reachable time for Neighbor Solicitations. */
        r = sysctl_write_ip_neighbor_property_uint32(AF_INET6, link->ifname, "base_reachable_time_ms", (uint32_t) msec, manager_get_sysctl_shadow(link->manager));
        if (r < 0)
                log_link_warning_errno(link, r, "Failed to apply neighbor reachable time (%"PRIu64"), ignoring: %m", msec);

        return 0;
}

static int ndisc_router_process_retransmission_time(Link *link, sd_ndisc_router *rt) {
        usec_t retrans_time, msec;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->network);
        assert(rt);

        if (!link->network->ndisc_use_retransmission_time)
                return 0;

        r = sd_ndisc_router_get_retransmission_time(rt, &retrans_time);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get retransmission time from RA: %m");

        /* 0 is the unspecified value and must not be set (see RFC4861, 6.3.4) */
        if (!timestamp_is_set(retrans_time))
                return 0;

        msec = DIV_ROUND_UP(retrans_time, USEC_PER_MSEC);
        if (msec <= 0 || msec > UINT32_MAX) {
                log_link_debug(link, "Failed to get retransmission time from RA - out of range (%"PRIu64"), ignoring", msec);
                return 0;
        }

        /* Set the retransmission time for Neighbor Solicitations. */
        r = sysctl_write_ip_neighbor_property_uint32(AF_INET6, link->ifname, "retrans_time_ms", (uint32_t) msec, manager_get_sysctl_shadow(link->manager));
        if (r < 0)
                log_link_warning_errno(link, r, "Failed to apply neighbor retransmission time (%"PRIu64"), ignoring: %m", msec);

        return 0;
}

static int ndisc_router_process_hop_limit(Link *link, sd_ndisc_router *rt) {
        uint8_t hop_limit;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->network);
        assert(rt);

        if (!link->network->ndisc_use_hop_limit)
                return 0;

        r = sd_ndisc_router_get_hop_limit(rt, &hop_limit);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get hop limit from RA: %m");

        /* 0 is the unspecified value and must not be set (see RFC4861, 6.3.4):
         *
         * A Router Advertisement field (e.g., Cur Hop Limit, Reachable Time, and Retrans Timer) may contain
         * a value denoting that it is unspecified. In such cases, the parameter should be ignored and the
         * host should continue using whatever value it is already using. In particular, a host MUST NOT
         * interpret the unspecified value as meaning change back to the default value that was in use before
         * the first Router Advertisement was received.
         *
         * If the received Cur Hop Limit value is non-zero, the host SHOULD set
         * its CurHopLimit variable to the received value. */
        if (hop_limit <= 0)
                return 0;

        r = sysctl_write_ip_property_uint32(AF_INET6, link->ifname, "hop_limit", (uint32_t) hop_limit, manager_get_sysctl_shadow(link->manager));
        if (r < 0)
                log_link_warning_errno(link, r, "Failed to apply hop_limit (%u), ignoring: %m", hop_limit);

        return 0;
}

static int ndisc_router_process_mtu(Link *link, sd_ndisc_router *rt) {
        uint32_t mtu;
        int r;

        assert(link);
        assert(link->network);
        assert(rt);

        if (!link->network->ndisc_use_mtu)
                return 0;

        r = sd_ndisc_router_get_mtu(rt, &mtu);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get MTU from RA: %m");

        link->ndisc_mtu = mtu;

        (void) link_set_ipv6_mtu(link, LOG_DEBUG);

        return 0;
}

static int ndisc_address_set_lifetime(Address *address, Link *link, sd_ndisc_router *rt) {
        Address *existing;
        usec_t t;
        int r;

        assert(address);
        assert(link);
        assert(rt);

        /* This is mostly based on RFC 4862 section 5.5.3 (e). However, the definition of 'RemainingLifetime'
         * is ambiguous, and there is no clear explanation when the address is not assigned yet. If we assume
         * that 'RemainingLifetime' is zero in that case, then IPv6 Core Conformance test [v6LC.3.2.5 Part C]
         * fails. So, in such case, we skip the conditions about 'RemainingLifetime'. */

        r = sd_ndisc_router_prefix_get_valid_lifetime_timestamp(rt, CLOCK_BOOTTIME, &address->lifetime_valid_usec);
        if (r < 0)
                return r;

        r = sd_ndisc_router_prefix_get_preferred_lifetime_timestamp(rt, CLOCK_BOOTTIME, &address->lifetime_preferred_usec);
        if (r < 0)
                return r;

        /* RFC 4862 section 5.5.3 (e)
         * 1. If the received Valid Lifetime is greater than 2 hours or greater than RemainingLifetime,
         *    set the valid lifetime of the corresponding address to the advertised Valid Lifetime. */
        r = sd_ndisc_router_prefix_get_valid_lifetime(rt, &t);
        if (r < 0)
                return r;

        if (t > 2 * USEC_PER_HOUR)
                return 0;

        if (address_get(link, address, &existing) < 0 || existing->source != NETWORK_CONFIG_SOURCE_NDISC)
                return 0;

        if (address->lifetime_valid_usec > existing->lifetime_valid_usec)
                return 0;

        /* 2. If RemainingLifetime is less than or equal to 2 hours, ignore the Prefix Information option
         *    with regards to the valid lifetime, unless the Router Advertisement from which this option was
         *    obtained has been authenticated (e.g., via Secure Neighbor Discovery [RFC3971]). If the Router
         *    Advertisement was authenticated, the valid lifetime of the corresponding address should be set
         *    to the Valid Lifetime in the received option.
         *
         * Currently, authentication is not supported. So check the lifetime of the existing address. */
        r = sd_ndisc_router_get_timestamp(rt, CLOCK_BOOTTIME, &t);
        if (r < 0)
                return r;

        if (existing->lifetime_valid_usec <= usec_add(t, 2 * USEC_PER_HOUR)) {
                address->lifetime_valid_usec = existing->lifetime_valid_usec;
                return 0;
        }

        /* 3. Otherwise, reset the valid lifetime of the corresponding address to 2 hours. */
        address->lifetime_valid_usec = usec_add(t, 2 * USEC_PER_HOUR);
        return 0;
}

static int ndisc_router_process_autonomous_prefix(Link *link, sd_ndisc_router *rt) {
        usec_t lifetime_valid_usec, lifetime_preferred_usec;
        struct in6_addr prefix, router;
        uint8_t prefixlen;
        int r;

        assert(link);
        assert(link->network);
        assert(rt);

        if (!link->network->ndisc_use_autonomous_prefix)
                return 0;

        r = sd_ndisc_router_get_sender_address(rt, &router);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get router address: %m");

        r = sd_ndisc_router_prefix_get_address(rt, &prefix);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get prefix address: %m");

        r = sd_ndisc_router_prefix_get_prefixlen(rt, &prefixlen);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get prefix length: %m");

        /* ndisc_generate_addresses() below requires the prefix length <= 64. */
        if (prefixlen > 64) {
                log_link_debug(link, "Prefix is longer than 64, ignoring autonomous prefix %s.",
                               IN6_ADDR_PREFIX_TO_STRING(&prefix, prefixlen));
                return 0;
        }

        r = sd_ndisc_router_prefix_get_valid_lifetime(rt, &lifetime_valid_usec);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get prefix valid lifetime: %m");

        r = sd_ndisc_router_prefix_get_preferred_lifetime(rt, &lifetime_preferred_usec);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get prefix preferred lifetime: %m");

        /* RFC 4862 section 5.5.3 (c)
         * If the preferred lifetime is greater than the valid lifetime, silently ignore the Prefix
         * Information option. */
        if (lifetime_preferred_usec > lifetime_valid_usec)
                return 0;

        _cleanup_hashmap_free_ Hashmap *tokens_by_address = NULL;
        r = ndisc_generate_addresses(link, &prefix, prefixlen, &tokens_by_address);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to generate SLAAC addresses: %m");

        IPv6Token *token;
        struct in6_addr *a;
        HASHMAP_FOREACH_KEY(token, a, tokens_by_address) {
                _cleanup_(address_unrefp) Address *address = NULL;

                r = address_new(&address);
                if (r < 0)
                        return log_oom();

                address->provider.in6 = router;
                address->family = AF_INET6;
                address->in_addr.in6 = *a;
                address->prefixlen = prefixlen;
                address->flags = IFA_F_NOPREFIXROUTE|IFA_F_MANAGETEMPADDR;
                address->token = ipv6_token_ref(token);

                r = ndisc_address_set_lifetime(address, link, rt);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Failed to set lifetime of SLAAC address: %m");

                assert(address->lifetime_preferred_usec <= address->lifetime_valid_usec);

                r = ndisc_request_address(address, link);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Could not request SLAAC address: %m");
        }

        return 0;
}

static int ndisc_router_process_onlink_prefix(Link *link, sd_ndisc_router *rt) {
        _cleanup_(route_unrefp) Route *route = NULL;
        uint8_t prefixlen, preference;
        usec_t lifetime_usec;
        struct in6_addr prefix;
        int r;

        assert(link);
        assert(link->network);
        assert(rt);

        if (!link->network->ndisc_use_onlink_prefix)
                return 0;

        r = sd_ndisc_router_prefix_get_valid_lifetime_timestamp(rt, CLOCK_BOOTTIME, &lifetime_usec);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get prefix lifetime: %m");

        r = sd_ndisc_router_prefix_get_address(rt, &prefix);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get prefix address: %m");

        r = sd_ndisc_router_prefix_get_prefixlen(rt, &prefixlen);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get prefix length: %m");

        /* Prefix Information option does not have preference, hence we use the 'main' preference here */
        r = sd_ndisc_router_get_preference(rt, &preference);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get router preference from RA: %m");

        r = route_new(&route);
        if (r < 0)
                return log_oom();

        route->family = AF_INET6;
        route->dst.in6 = prefix;
        route->dst_prefixlen = prefixlen;
        route->pref = preference;
        route->lifetime_usec = lifetime_usec;

        /* RFC 4861 section 6.3.4:
         * - If the prefix is not already present in the Prefix List, and the Prefix Information option's
         *   Valid Lifetime field is non-zero, create a new entry for the prefix and initialize its
         *   invalidation timer to the Valid Lifetime value in the Prefix Information option.
         *
         * - If the prefix is already present in the host's Prefix List as the result of a previously
         *   received advertisement, reset its invalidation timer to the Valid Lifetime value in the Prefix
         *   Information option. If the new Lifetime value is zero, timeout the prefix immediately. */
        if (lifetime_usec == 0) {
                r = ndisc_remove_router_route(route, link, rt);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Failed to remove prefix route: %m");
        } else {
                r = ndisc_request_router_route(route, link, rt);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Failed to request prefix route: %m");
        }

        return 0;
}

static int ndisc_router_process_prefix(Link *link, sd_ndisc_router *rt, bool zero_lifetime) {
        uint8_t flags, prefixlen;
        struct in6_addr a;
        int r;

        assert(link);
        assert(link->network);
        assert(rt);

        usec_t lifetime_usec;
        r = sd_ndisc_router_prefix_get_valid_lifetime(rt, &lifetime_usec);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get prefix lifetime: %m");

        if ((lifetime_usec == 0) != zero_lifetime)
                return 0;

        r = sd_ndisc_router_prefix_get_address(rt, &a);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get prefix address: %m");

        /* RFC 4861 Section 4.6.2:
         * A router SHOULD NOT send a prefix option for the link-local prefix and a host SHOULD ignore such
         * a prefix option. */
        if (in6_addr_is_link_local(&a)) {
                log_link_debug(link, "Received link-local prefix, ignoring prefix.");
                return 0;
        }

        r = sd_ndisc_router_prefix_get_prefixlen(rt, &prefixlen);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get prefix length: %m");

        if (in6_prefix_is_filtered(&a, prefixlen, link->network->ndisc_allow_listed_prefix, link->network->ndisc_deny_listed_prefix)) {
                if (set_isempty(link->network->ndisc_allow_listed_prefix))
                        log_link_debug(link, "Prefix '%s' is in deny list, ignoring.",
                                       IN6_ADDR_PREFIX_TO_STRING(&a, prefixlen));
                else
                        log_link_debug(link, "Prefix '%s' is not in allow list, ignoring.",
                                       IN6_ADDR_PREFIX_TO_STRING(&a, prefixlen));
                return 0;
        }

        r = sd_ndisc_router_prefix_get_flags(rt, &flags);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get RA prefix flags: %m");

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

static int ndisc_router_process_route(Link *link, sd_ndisc_router *rt, bool zero_lifetime) {
        _cleanup_(route_unrefp) Route *route = NULL;
        uint8_t preference, prefixlen;
        struct in6_addr gateway, dst;
        usec_t lifetime_usec;
        int r;

        assert(link);

        if (!link->network->ndisc_use_route_prefix)
                return 0;

        r = sd_ndisc_router_route_get_lifetime_timestamp(rt, CLOCK_BOOTTIME, &lifetime_usec);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get route lifetime from RA: %m");

        if ((lifetime_usec == 0) != zero_lifetime)
                return 0;

        r = sd_ndisc_router_route_get_address(rt, &dst);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get route destination address: %m");

        r = sd_ndisc_router_route_get_prefixlen(rt, &prefixlen);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get route prefix length: %m");

        if (in6_prefix_is_filtered(&dst, prefixlen,
                                   link->network->ndisc_allow_listed_route_prefix,
                                   link->network->ndisc_deny_listed_route_prefix)) {
                if (set_isempty(link->network->ndisc_allow_listed_route_prefix))
                        log_link_debug(link, "Route prefix '%s' is in deny list, ignoring.",
                                       IN6_ADDR_PREFIX_TO_STRING(&dst, prefixlen));
                else
                        log_link_debug(link, "Route prefix '%s' is not in allow list, ignoring.",
                                       IN6_ADDR_PREFIX_TO_STRING(&dst, prefixlen));
                return 0;
        }

        r = sd_ndisc_router_get_sender_address(rt, &gateway);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get gateway address from RA: %m");

        if (link_get_ipv6_address(link, &gateway, NULL) >= 0) {
                if (DEBUG_LOGGING)
                        log_link_debug(link, "Advertised route gateway %s is local to the link, ignoring route",
                                       IN6_ADDR_TO_STRING(&gateway));
                return 0;
        }

        r = sd_ndisc_router_route_get_preference(rt, &preference);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get router preference from RA: %m");

        r = route_new(&route);
        if (r < 0)
                return log_oom();

        route->family = AF_INET6;
        route->pref = preference;
        route->nexthop.gw.in6 = gateway;
        route->nexthop.family = AF_INET6;
        route->dst.in6 = dst;
        route->dst_prefixlen = prefixlen;
        route->lifetime_usec = lifetime_usec;

        if (lifetime_usec != 0) {
                r = ndisc_request_router_route(route, link, rt);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Could not request additional route: %m");
        } else {
                r = ndisc_remove_router_route(route, link, rt);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Could not remove additional route with zero lifetime: %m");
        }

        return 0;
}

static void ndisc_rdnss_hash_func(const NDiscRDNSS *x, struct siphash *state) {
        siphash24_compress_typesafe(x->address, state);
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

static int ndisc_router_process_rdnss(Link *link, sd_ndisc_router *rt, bool zero_lifetime) {
        usec_t lifetime_usec;
        const struct in6_addr *a;
        struct in6_addr router;
        bool updated = false, logged_about_too_many = false;
        int n, r;

        assert(link);
        assert(link->network);
        assert(rt);

        if (!link_get_use_dns(link, NETWORK_CONFIG_SOURCE_NDISC))
                return 0;

        r = sd_ndisc_router_get_sender_address(rt, &router);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get router address from RA: %m");

        r = sd_ndisc_router_rdnss_get_lifetime_timestamp(rt, CLOCK_BOOTTIME, &lifetime_usec);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get RDNSS lifetime: %m");

        if ((lifetime_usec == 0) != zero_lifetime)
                return 0;

        n = sd_ndisc_router_rdnss_get_addresses(rt, &a);
        if (n < 0)
                return log_link_warning_errno(link, n, "Failed to get RDNSS addresses: %m");

        for (int j = 0; j < n; j++) {
                _cleanup_free_ NDiscRDNSS *x = NULL;
                NDiscRDNSS *rdnss, d = {
                        .address = a[j],
                };

                if (lifetime_usec == 0) {
                        /* The entry is outdated. */
                        free(set_remove(link->ndisc_rdnss, &d));
                        updated = true;
                        continue;
                }

                rdnss = set_get(link->ndisc_rdnss, &d);
                if (rdnss) {
                        rdnss->router = router;
                        rdnss->lifetime_usec = lifetime_usec;
                        continue;
                }

                if (set_size(link->ndisc_rdnss) >= NDISC_RDNSS_MAX) {
                        if (!logged_about_too_many)
                                log_link_warning(link, "Too many RDNSS records per link. Only first %u records will be used.", NDISC_RDNSS_MAX);
                        logged_about_too_many = true;
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

static int ndisc_router_process_dnssl(Link *link, sd_ndisc_router *rt, bool zero_lifetime) {
        char **l;
        usec_t lifetime_usec;
        struct in6_addr router;
        bool updated = false, logged_about_too_many = false;
        int r;

        assert(link);
        assert(link->network);
        assert(rt);

        if (link_get_use_domains(link, NETWORK_CONFIG_SOURCE_NDISC) <= 0)
                return 0;

        r = sd_ndisc_router_get_sender_address(rt, &router);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get router address from RA: %m");

        r = sd_ndisc_router_dnssl_get_lifetime_timestamp(rt, CLOCK_BOOTTIME, &lifetime_usec);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get DNSSL lifetime: %m");

        if ((lifetime_usec == 0) != zero_lifetime)
                return 0;

        r = sd_ndisc_router_dnssl_get_domains(rt, &l);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get DNSSL addresses: %m");

        STRV_FOREACH(j, l) {
                _cleanup_free_ NDiscDNSSL *s = NULL;
                NDiscDNSSL *dnssl;

                s = malloc0(ALIGN(sizeof(NDiscDNSSL)) + strlen(*j) + 1);
                if (!s)
                        return log_oom();

                strcpy(NDISC_DNSSL_DOMAIN(s), *j);

                if (lifetime_usec == 0) {
                        /* The entry is outdated. */
                        free(set_remove(link->ndisc_dnssl, s));
                        updated = true;
                        continue;
                }

                dnssl = set_get(link->ndisc_dnssl, s);
                if (dnssl) {
                        dnssl->router = router;
                        dnssl->lifetime_usec = lifetime_usec;
                        continue;
                }

                if (set_size(link->ndisc_dnssl) >= NDISC_DNSSL_MAX) {
                        if (!logged_about_too_many)
                                log_link_warning(link, "Too many DNSSL records per link. Only first %u records will be used.", NDISC_DNSSL_MAX);
                        logged_about_too_many = true;
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

static NDiscCaptivePortal* ndisc_captive_portal_free(NDiscCaptivePortal *x) {
        if (!x)
                return NULL;

        free(x->captive_portal);
        return mfree(x);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(NDiscCaptivePortal*, ndisc_captive_portal_free);

static void ndisc_captive_portal_hash_func(const NDiscCaptivePortal *x, struct siphash *state) {
        assert(x);
        siphash24_compress_string(x->captive_portal, state);
}

static int ndisc_captive_portal_compare_func(const NDiscCaptivePortal *a, const NDiscCaptivePortal *b) {
        assert(a);
        assert(b);
        return strcmp_ptr(a->captive_portal, b->captive_portal);
}

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
                ndisc_captive_portal_hash_ops,
                NDiscCaptivePortal,
                ndisc_captive_portal_hash_func,
                ndisc_captive_portal_compare_func,
                ndisc_captive_portal_free);

static int ndisc_router_process_captive_portal(Link *link, sd_ndisc_router *rt, bool zero_lifetime) {
        _cleanup_(ndisc_captive_portal_freep) NDiscCaptivePortal *new_entry = NULL;
        _cleanup_free_ char *captive_portal = NULL;
        const char *uri;
        usec_t lifetime_usec;
        NDiscCaptivePortal *exist;
        struct in6_addr router;
        int r;

        assert(link);
        assert(link->network);
        assert(rt);

        if (!link->network->ndisc_use_captive_portal)
                return 0;

        r = sd_ndisc_router_get_sender_address(rt, &router);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get router address from RA: %m");

        /* RFC 4861 section 4.2. states that the lifetime in the message header should be used only for the
         * default gateway, but the captive portal option does not have a lifetime field, hence, we use the
         * main lifetime for the portal. */
        r = sd_ndisc_router_get_lifetime_timestamp(rt, CLOCK_BOOTTIME, &lifetime_usec);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get lifetime of RA message: %m");

        if ((lifetime_usec == 0) != zero_lifetime)
                return 0;

        r = sd_ndisc_router_get_captive_portal(rt, &uri);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get captive portal from RA: %m");

        captive_portal = strdup(uri);
        if (!captive_portal)
                return log_oom();

        if (lifetime_usec == 0) {
                /* Drop the portal with zero lifetime. */
                ndisc_captive_portal_free(set_remove(link->ndisc_captive_portals,
                                                     &(const NDiscCaptivePortal) {
                                                             .captive_portal = captive_portal,
                                                     }));
                return 0;
        }

        exist = set_get(link->ndisc_captive_portals,
                        &(const NDiscCaptivePortal) {
                                .captive_portal = captive_portal,
                        });
        if (exist) {
                /* update existing entry */
                exist->router = router;
                exist->lifetime_usec = lifetime_usec;
                return 1;
        }

        if (set_size(link->ndisc_captive_portals) >= NDISC_CAPTIVE_PORTAL_MAX) {
                NDiscCaptivePortal *c, *target = NULL;

                /* Find the portal who has the minimal lifetime and drop it to store new one. */
                SET_FOREACH(c, link->ndisc_captive_portals)
                        if (!target || c->lifetime_usec < target->lifetime_usec)
                                target = c;

                assert(target);
                assert(set_remove(link->ndisc_captive_portals, target) == target);
                ndisc_captive_portal_free(target);
        }

        new_entry = new(NDiscCaptivePortal, 1);
        if (!new_entry)
                return log_oom();

        *new_entry = (NDiscCaptivePortal) {
                .router = router,
                .lifetime_usec = lifetime_usec,
                .captive_portal = TAKE_PTR(captive_portal),
        };

        r = set_ensure_put(&link->ndisc_captive_portals, &ndisc_captive_portal_hash_ops, new_entry);
        if (r < 0)
                return log_oom();
        assert(r > 0);
        TAKE_PTR(new_entry);

        link_dirty(link);
        return 1;
}

static void ndisc_pref64_hash_func(const NDiscPREF64 *x, struct siphash *state) {
        assert(x);

        siphash24_compress_typesafe(x->prefix_len, state);
        siphash24_compress_typesafe(x->prefix, state);
}

static int ndisc_pref64_compare_func(const NDiscPREF64 *a, const NDiscPREF64 *b) {
        int r;

        assert(a);
        assert(b);

        r = CMP(a->prefix_len, b->prefix_len);
        if (r != 0)
                return r;

        return memcmp(&a->prefix, &b->prefix, sizeof(a->prefix));
}

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
                ndisc_pref64_hash_ops,
                NDiscPREF64,
                ndisc_pref64_hash_func,
                ndisc_pref64_compare_func,
                mfree);

static int ndisc_router_process_pref64(Link *link, sd_ndisc_router *rt, bool zero_lifetime) {
        _cleanup_free_ NDiscPREF64 *new_entry = NULL;
        usec_t lifetime_usec;
        struct in6_addr a, router;
        uint8_t prefix_len;
        NDiscPREF64 *exist;
        int r;

        assert(link);
        assert(link->network);
        assert(rt);

        if (!link->network->ndisc_use_pref64)
                return 0;

        r = sd_ndisc_router_get_sender_address(rt, &router);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get router address from RA: %m");

        r = sd_ndisc_router_prefix64_get_prefix(rt, &a);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get pref64 prefix: %m");

        r = sd_ndisc_router_prefix64_get_prefixlen(rt, &prefix_len);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get pref64 prefix length: %m");

        r = sd_ndisc_router_prefix64_get_lifetime_timestamp(rt, CLOCK_BOOTTIME, &lifetime_usec);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get pref64 prefix lifetime: %m");

        if ((lifetime_usec == 0) != zero_lifetime)
                return 0;

        if (lifetime_usec == 0) {
                free(set_remove(link->ndisc_pref64,
                                &(NDiscPREF64) {
                                        .prefix = a,
                                        .prefix_len = prefix_len
                                }));
                return 0;
        }

        exist = set_get(link->ndisc_pref64,
                        &(NDiscPREF64) {
                                .prefix = a,
                                .prefix_len = prefix_len
                });
        if (exist) {
                /* update existing entry */
                exist->router = router;
                exist->lifetime_usec = lifetime_usec;
                return 0;
        }

        if (set_size(link->ndisc_pref64) >= NDISC_PREF64_MAX) {
                log_link_debug(link, "Too many PREF64 records received. Only first %u records will be used.", NDISC_PREF64_MAX);
                return 0;
        }

        new_entry = new(NDiscPREF64, 1);
        if (!new_entry)
                return log_oom();

        *new_entry = (NDiscPREF64) {
                .router = router,
                .lifetime_usec = lifetime_usec,
                .prefix = a,
                .prefix_len = prefix_len,
        };

        r = set_ensure_put(&link->ndisc_pref64, &ndisc_pref64_hash_ops, new_entry);
        if (r < 0)
                return log_oom();

        assert(r > 0);
        TAKE_PTR(new_entry);

        return 0;
}

static NDiscDNR* ndisc_dnr_free(NDiscDNR *x) {
        if (!x)
                return NULL;

        sd_dns_resolver_done(&x->resolver);
        return mfree(x);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(NDiscDNR*, ndisc_dnr_free);

static int ndisc_dnr_compare_func(const NDiscDNR *a, const NDiscDNR *b) {
        return CMP(a->resolver.priority, b->resolver.priority) ||
                strcmp_ptr(a->resolver.auth_name, b->resolver.auth_name) ||
                CMP(a->resolver.transports, b->resolver.transports) ||
                CMP(a->resolver.port, b->resolver.port) ||
                strcmp_ptr(a->resolver.dohpath, b->resolver.dohpath) ||
                CMP(a->resolver.family, b->resolver.family) ||
                CMP(a->resolver.n_addrs, b->resolver.n_addrs) ||
                memcmp(a->resolver.addrs, b->resolver.addrs, sizeof(a->resolver.addrs[0]) * a->resolver.n_addrs);
}

static void ndisc_dnr_hash_func(const NDiscDNR *x, struct siphash *state) {
        assert(x);

        siphash24_compress_resolver(&x->resolver, state);
}

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
                ndisc_dnr_hash_ops,
                NDiscDNR,
                ndisc_dnr_hash_func,
                ndisc_dnr_compare_func,
                ndisc_dnr_free);

static int sd_dns_resolver_copy(const sd_dns_resolver *a, sd_dns_resolver *b) {
        int r;

        assert(a);
        assert(b);

        _cleanup_(sd_dns_resolver_done) sd_dns_resolver c = {
                .priority = a->priority,
                .transports = a->transports,
                .port = a->port,
                /* .auth_name */
                .family = a->family,
                /* .addrs */
                /* .n_addrs */
                /* .dohpath */
        };

        /* auth_name */
        r = strdup_to(&c.auth_name, a->auth_name);
        if (r < 0)
                return r;

        /* addrs, n_addrs */
        c.addrs = newdup(union in_addr_union, a->addrs, a->n_addrs);
        if (!c.addrs)
                return r;
        c.n_addrs = a->n_addrs;

        /* dohpath */
        r = strdup_to(&c.dohpath, a->dohpath);
        if (r < 0)
                return r;

        *b = TAKE_STRUCT(c);
        return 0;
}

static int ndisc_router_process_encrypted_dns(Link *link, sd_ndisc_router *rt, bool zero_lifetime) {
        int r;

        assert(link);
        assert(link->network);
        assert(rt);

        struct in6_addr router;
        usec_t lifetime_usec;
        sd_dns_resolver *res;
        _cleanup_(ndisc_dnr_freep) NDiscDNR *new_entry = NULL;

        if (!link_get_use_dnr(link, NETWORK_CONFIG_SOURCE_NDISC))
                return 0;

        r = sd_ndisc_router_get_sender_address(rt, &router);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get gateway address from RA: %m");

        r = sd_ndisc_router_encrypted_dns_get_lifetime_timestamp(rt, CLOCK_BOOTTIME, &lifetime_usec);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get lifetime of RA message: %m");

        if ((lifetime_usec == 0) != zero_lifetime)
                return 0;

        r = sd_ndisc_router_encrypted_dns_get_resolver(rt, &res);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get encrypted dns resolvers: %m");

        NDiscDNR *dnr, d = { .resolver = *res };
        if (lifetime_usec == 0) {
                dnr = set_remove(link->ndisc_dnr, &d);
                if (dnr) {
                        ndisc_dnr_free(dnr);
                        link_dirty(link);
                }
                return 0;
        }

        dnr = set_get(link->ndisc_dnr, &d);
        if (dnr) {
                dnr->router = router;
                dnr->lifetime_usec = lifetime_usec;
                return 0;
        }

        if (set_size(link->ndisc_dnr) >= NDISC_ENCRYPTED_DNS_MAX) {
                log_link_warning(link, "Too many Encrypted DNS records received. Only first %u records will be used.", NDISC_ENCRYPTED_DNS_MAX);
                return 0;
        }

        new_entry = new(NDiscDNR, 1);
        if (!new_entry)
                return log_oom();

        *new_entry = (NDiscDNR) {
                .router = router,
                /* .resolver, */
                .lifetime_usec = lifetime_usec,
        };
        r = sd_dns_resolver_copy(res, &new_entry->resolver);
        if (r < 0)
                return log_oom();

        /* Not sorted by priority */
        r = set_ensure_put(&link->ndisc_dnr, &ndisc_dnr_hash_ops, new_entry);
        if (r < 0)
                return log_oom();

        assert(r > 0);
        TAKE_PTR(new_entry);

        link_dirty(link);

        return 0;
}

static int ndisc_router_process_options(Link *link, sd_ndisc_router *rt, bool zero_lifetime) {
        size_t n_captive_portal = 0;
        int r;

        assert(link);
        assert(link->network);
        assert(rt);

        for (r = sd_ndisc_router_option_rewind(rt); ; r = sd_ndisc_router_option_next(rt)) {
                uint8_t type;

                if (r < 0)
                        return log_link_warning_errno(link, r, "Failed to iterate through options: %m");
                if (r == 0) /* EOF */
                        return 0;

                r = sd_ndisc_router_option_get_type(rt, &type);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Failed to get RA option type: %m");

                switch (type) {
                case SD_NDISC_OPTION_PREFIX_INFORMATION:
                        r = ndisc_router_process_prefix(link, rt, zero_lifetime);
                        break;

                case SD_NDISC_OPTION_ROUTE_INFORMATION:
                        r = ndisc_router_process_route(link, rt, zero_lifetime);
                        break;

                case SD_NDISC_OPTION_RDNSS:
                        r = ndisc_router_process_rdnss(link, rt, zero_lifetime);
                        break;

                case SD_NDISC_OPTION_DNSSL:
                        r = ndisc_router_process_dnssl(link, rt, zero_lifetime);
                        break;
                case SD_NDISC_OPTION_CAPTIVE_PORTAL:
                        if (n_captive_portal > 0) {
                                if (n_captive_portal == 1)
                                        log_link_notice(link, "Received RA with multiple captive portals, only using the first one.");

                                n_captive_portal++;
                                continue;
                        }
                        r = ndisc_router_process_captive_portal(link, rt, zero_lifetime);
                        if (r > 0)
                                n_captive_portal++;
                        break;
                case SD_NDISC_OPTION_PREF64:
                        r = ndisc_router_process_pref64(link, rt, zero_lifetime);
                        break;
                case SD_NDISC_OPTION_ENCRYPTED_DNS:
                        r = ndisc_router_process_encrypted_dns(link, rt, zero_lifetime);
                        break;
                }
                if (r < 0 && r != -EBADMSG)
                        return r;
        }
}

static int ndisc_drop_outdated(Link *link, const struct in6_addr *router, usec_t timestamp_usec) {
        bool updated = false;
        NDiscDNSSL *dnssl;
        NDiscRDNSS *rdnss;
        NDiscCaptivePortal *cp;
        NDiscPREF64 *p64;
        NDiscDNR *dnr;
        Address *address;
        Route *route;
        int r, ret = 0;

        assert(link);
        assert(link->manager);

        /* If an address or friends is already assigned, but not valid anymore, then refuse to update it,
         * and let's immediately remove it.
         * See RFC4862, section 5.5.3.e. But the following logic is deviated from RFC4862 by honoring all
         * valid lifetimes to improve the reaction of SLAAC to renumbering events.
         * See draft-ietf-6man-slaac-renum-02, section 4.2. */

        r = ndisc_drop_routers(link, router, timestamp_usec);
        if (r < 0)
                RET_GATHER(ret, log_link_warning_errno(link, r, "Failed to drop outdated default router, ignoring: %m"));

        SET_FOREACH(route, link->manager->routes) {
                if (route->source != NETWORK_CONFIG_SOURCE_NDISC)
                        continue;

                if (!route_is_bound_to_link(route, link))
                        continue;

                if (route->protocol == RTPROT_REDIRECT)
                        continue; /* redirect route will be dropped by ndisc_drop_redirect(). */

                if (route->lifetime_usec > timestamp_usec)
                        continue; /* the route is still valid */

                if (router && !in6_addr_equal(&route->provider.in6, router))
                        continue;

                r = route_remove_and_cancel(route, link->manager);
                if (r < 0)
                        RET_GATHER(ret, log_link_warning_errno(link, r, "Failed to remove outdated SLAAC route, ignoring: %m"));
        }

        RET_GATHER(ret, ndisc_remove_unused_nexthops(link));

        SET_FOREACH(address, link->addresses) {
                if (address->source != NETWORK_CONFIG_SOURCE_NDISC)
                        continue;

                if (address->lifetime_valid_usec > timestamp_usec)
                        continue; /* the address is still valid */

                if (router && !in6_addr_equal(&address->provider.in6, router))
                        continue;

                r = address_remove_and_cancel(address, link);
                if (r < 0)
                        RET_GATHER(ret, log_link_warning_errno(link, r, "Failed to remove outdated SLAAC address, ignoring: %m"));
        }

        SET_FOREACH(rdnss, link->ndisc_rdnss) {
                if (rdnss->lifetime_usec > timestamp_usec)
                        continue; /* the DNS server is still valid */

                if (router && !in6_addr_equal(&rdnss->router, router))
                        continue;

                free(set_remove(link->ndisc_rdnss, rdnss));
                updated = true;
        }

        SET_FOREACH(dnssl, link->ndisc_dnssl) {
                if (dnssl->lifetime_usec > timestamp_usec)
                        continue; /* the DNS domain is still valid */

                if (router && !in6_addr_equal(&dnssl->router, router))
                        continue;

                free(set_remove(link->ndisc_dnssl, dnssl));
                updated = true;
        }

        SET_FOREACH(cp, link->ndisc_captive_portals) {
                if (cp->lifetime_usec > timestamp_usec)
                        continue; /* the captive portal is still valid */

                if (router && !in6_addr_equal(&cp->router, router))
                        continue;

                ndisc_captive_portal_free(set_remove(link->ndisc_captive_portals, cp));
                updated = true;
        }

        SET_FOREACH(p64, link->ndisc_pref64) {
                if (p64->lifetime_usec > timestamp_usec)
                        continue; /* the pref64 prefix is still valid */

                if (router && !in6_addr_equal(&p64->router, router))
                        continue;

                free(set_remove(link->ndisc_pref64, p64));
                /* The pref64 prefix is not exported through the state file, hence it is not necessary to set
                 * the 'updated' flag. */
        }

        SET_FOREACH(dnr, link->ndisc_dnr) {
                if (dnr->lifetime_usec > timestamp_usec)
                        continue; /* The resolver is still valid */

                ndisc_dnr_free(set_remove(link->ndisc_dnr, dnr));
                updated = true;
        }

        RET_GATHER(ret, link_request_stacked_netdevs(link, NETDEV_LOCAL_ADDRESS_SLAAC));

        if (updated)
                link_dirty(link);

        return ret;
}

static int ndisc_setup_expire(Link *link);

static int ndisc_expire_handler(sd_event_source *s, uint64_t usec, void *userdata) {
        Link *link = ASSERT_PTR(userdata);
        usec_t now_usec;

        assert(link->manager);

        assert_se(sd_event_now(link->manager->event, CLOCK_BOOTTIME, &now_usec) >= 0);

        (void) ndisc_drop_outdated(link, /* router = */ NULL, now_usec);
        (void) ndisc_setup_expire(link);
        return 0;
}

static int ndisc_setup_expire(Link *link) {
        usec_t lifetime_usec = USEC_INFINITY;
        NDiscCaptivePortal *cp;
        NDiscDNSSL *dnssl;
        NDiscRDNSS *rdnss;
        NDiscPREF64 *p64;
        NDiscDNR *dnr;
        Address *address;
        Route *route;
        int r;

        assert(link);
        assert(link->manager);

        sd_ndisc_router *rt;
        HASHMAP_FOREACH(rt, link->ndisc_routers_by_sender) {
                usec_t t;

                if (sd_ndisc_router_get_lifetime_timestamp(rt, CLOCK_BOOTTIME, &t) < 0)
                        continue;

                lifetime_usec = MIN(lifetime_usec, t);
        }

        SET_FOREACH(route, link->manager->routes) {
                if (route->source != NETWORK_CONFIG_SOURCE_NDISC)
                        continue;

                if (!route_is_bound_to_link(route, link))
                        continue;

                if (!route_exists(route))
                        continue;

                lifetime_usec = MIN(lifetime_usec, route->lifetime_usec);
        }

        SET_FOREACH(address, link->addresses) {
                if (address->source != NETWORK_CONFIG_SOURCE_NDISC)
                        continue;

                if (!address_exists(address))
                        continue;

                lifetime_usec = MIN(lifetime_usec, address->lifetime_valid_usec);
        }

        SET_FOREACH(rdnss, link->ndisc_rdnss)
                lifetime_usec = MIN(lifetime_usec, rdnss->lifetime_usec);

        SET_FOREACH(dnssl, link->ndisc_dnssl)
                lifetime_usec = MIN(lifetime_usec, dnssl->lifetime_usec);

        SET_FOREACH(cp, link->ndisc_captive_portals)
                lifetime_usec = MIN(lifetime_usec, cp->lifetime_usec);

        SET_FOREACH(p64, link->ndisc_pref64)
                lifetime_usec = MIN(lifetime_usec, p64->lifetime_usec);

        SET_FOREACH(dnr, link->ndisc_dnr)
                lifetime_usec = MIN(lifetime_usec, dnr->lifetime_usec);

        if (lifetime_usec == USEC_INFINITY)
                return 0;

        r = event_reset_time(link->manager->event, &link->ndisc_expire, CLOCK_BOOTTIME,
                             lifetime_usec, 0, ndisc_expire_handler, link, 0, "ndisc-expiration", true);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to update expiration timer for ndisc: %m");

        return 0;
}

static int ndisc_start_dhcp6_client(Link *link, sd_ndisc_router *rt) {
        int r;

        assert(link);
        assert(link->network);

        switch (link->network->ndisc_start_dhcp6_client) {
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
                 * Note, if both "managed" and "other configuration" bits are set, then ignore
                 * "other configuration" bit. See RFC 4861. */
                r = dhcp6_start_on_ra(link, !(flags & ND_RA_FLAG_MANAGED));
                break;
        }
        case IPV6_ACCEPT_RA_START_DHCP6_CLIENT_ALWAYS:
                /* When IPv6AcceptRA.DHCPv6Client=always, start dhcp6 client in solicit mode
                 * even if the router flags have neither M nor O flags. */
                r = dhcp6_start_on_ra(link, /* information_request = */ false);
                break;

        default:
                assert_not_reached();
        }

        if (r < 0)
                return log_link_warning_errno(link, r, "Could not acquire DHCPv6 lease on NDisc request: %m");

        log_link_debug(link, "Acquiring DHCPv6 lease on NDisc request");
        return 0;
}

static int ndisc_router_handler(Link *link, sd_ndisc_router *rt) {
        struct in6_addr router;
        usec_t timestamp_usec;
        int r;

        assert(link);
        assert(link->network);
        assert(link->manager);
        assert(rt);

        r = sd_ndisc_router_get_sender_address(rt, &router);
        if (r == -ENODATA) {
                log_link_debug(link, "Received RA without router address, ignoring.");
                return 0;
        }
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get router address from RA: %m");

        if (in6_prefix_is_filtered(&router, 128, link->network->ndisc_allow_listed_router, link->network->ndisc_deny_listed_router)) {
                if (!set_isempty(link->network->ndisc_allow_listed_router))
                        log_link_debug(link, "Router %s is not in allow list, ignoring.", IN6_ADDR_TO_STRING(&router));
                else
                        log_link_debug(link, "Router %s is in deny list, ignoring.", IN6_ADDR_TO_STRING(&router));
                return 0;
        }

        r = sd_ndisc_router_get_timestamp(rt, CLOCK_BOOTTIME, &timestamp_usec);
        if (r == -ENODATA) {
                log_link_debug(link, "Received RA without timestamp, ignoring.");
                return 0;
        }
        if (r < 0)
                return r;

        r = ndisc_drop_outdated(link, /* router = */ NULL, timestamp_usec);
        if (r < 0)
                return r;

        r = ndisc_remember_router(link, rt);
        if (r < 0)
                return r;

        r = ndisc_start_dhcp6_client(link, rt);
        if (r < 0)
                return r;

        r = ndisc_router_process_reachable_time(link, rt);
        if (r < 0)
                return r;

        r = ndisc_router_process_retransmission_time(link, rt);
        if (r < 0)
                return r;

        r = ndisc_router_process_hop_limit(link, rt);
        if (r < 0)
                return r;

        r = ndisc_router_process_mtu(link, rt);
        if (r < 0)
                return r;

        r = ndisc_router_process_options(link, rt, /* zero_lifetime = */ true);
        if (r < 0)
                return r;

        r = ndisc_router_process_default(link, rt);
        if (r < 0)
                return r;

        r = ndisc_router_process_options(link, rt, /* zero_lifetime = */ false);
        if (r < 0)
                return r;

        r = ndisc_setup_expire(link);
        if (r < 0)
                return r;

        if (sd_ndisc_router_get_lifetime(rt, NULL) <= 0)
                (void) ndisc_drop_redirect(link, &router);

        if (link->ndisc_messages == 0)
                link->ndisc_configured = true;
        else
                log_link_debug(link, "Setting SLAAC addresses and router.");

        if (!link->ndisc_configured)
                link_set_state(link, LINK_STATE_CONFIGURING);

        link_check_ready(link);
        return 0;
}

static int ndisc_neighbor_handle_non_router_message(Link *link, sd_ndisc_neighbor *na) {
        struct in6_addr address;
        int r;

        assert(link);
        assert(na);

        /* Received Neighbor Advertisement message without Router flag. The node might have been a router,
         * and now it is not. Let's drop all configurations based on RAs sent from the node. */

        r = sd_ndisc_neighbor_get_target_address(na, &address);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return r;

        (void) ndisc_drop_outdated(link, /* router = */ &address, /* timestamp_usec = */ USEC_INFINITY);
        (void) ndisc_drop_redirect(link, &address);

        return 0;
}

static int ndisc_neighbor_handle_router_message(Link *link, sd_ndisc_neighbor *na) {
        struct in6_addr current_address, original_address;
        int r;

        assert(link);
        assert(link->manager);
        assert(na);

        /* Received Neighbor Advertisement message with Router flag. If the router address is changed, update
         * the provider field of configurations. */

        r = sd_ndisc_neighbor_get_sender_address(na, &current_address);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return r;

        r = sd_ndisc_neighbor_get_target_address(na, &original_address);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return r;

        if (in6_addr_equal(&current_address, &original_address))
                return 0; /* the router address is not changed */

        r = ndisc_update_router_address(link, &original_address, &current_address);
        if (r < 0)
                return r;

        r = ndisc_update_redirect_sender(link, &original_address, &current_address);
        if (r < 0)
                return r;

        Route *route;
        SET_FOREACH(route, link->manager->routes) {
                if (route->source != NETWORK_CONFIG_SOURCE_NDISC)
                        continue;

                if (!route_is_bound_to_link(route, link))
                        continue;

                if (!in6_addr_equal(&route->provider.in6, &original_address))
                        continue;

                route->provider.in6 = current_address;
        }

        Address *address;
        SET_FOREACH(address, link->addresses) {
                if (address->source != NETWORK_CONFIG_SOURCE_NDISC)
                        continue;

                if (!in6_addr_equal(&address->provider.in6, &original_address))
                        continue;

                address->provider.in6 = current_address;
        }

        NDiscRDNSS *rdnss;
        SET_FOREACH(rdnss, link->ndisc_rdnss) {
                if (!in6_addr_equal(&rdnss->router, &original_address))
                        continue;

                rdnss->router = current_address;
        }

        NDiscDNSSL *dnssl;
        SET_FOREACH(dnssl, link->ndisc_dnssl) {
                if (!in6_addr_equal(&dnssl->router, &original_address))
                        continue;

                dnssl->router = current_address;
        }

        NDiscCaptivePortal *cp;
        SET_FOREACH(cp, link->ndisc_captive_portals) {
                if (!in6_addr_equal(&cp->router, &original_address))
                        continue;

                cp->router = current_address;
        }

        NDiscPREF64 *p64;
        SET_FOREACH(p64, link->ndisc_pref64) {
                if (!in6_addr_equal(&p64->router, &original_address))
                        continue;

                p64->router = current_address;
        }

        NDiscDNR *dnr;
        SET_FOREACH(dnr, link->ndisc_dnr) {
                if (!in6_addr_equal(&dnr->router, &original_address))
                        continue;

                dnr->router = current_address;
        }

        return 0;
}

static int ndisc_neighbor_handler(Link *link, sd_ndisc_neighbor *na) {
        int r;

        assert(link);
        assert(na);

        r = sd_ndisc_neighbor_is_router(na);
        if (r < 0)
                return r;
        if (r == 0)
                r = ndisc_neighbor_handle_non_router_message(link, na);
        else
                r = ndisc_neighbor_handle_router_message(link, na);
        if (r < 0)
                return r;

        return 0;
}

static void ndisc_handler(sd_ndisc *nd, sd_ndisc_event_t event, void *message, void *userdata) {
        Link *link = ASSERT_PTR(userdata);
        int r;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return;

        switch (event) {

        case SD_NDISC_EVENT_ROUTER:
                r = ndisc_router_handler(link, ASSERT_PTR(message));
                if (r < 0 && r != -EBADMSG) {
                        link_enter_failed(link);
                        return;
                }
                break;

        case SD_NDISC_EVENT_NEIGHBOR:
                r = ndisc_neighbor_handler(link, ASSERT_PTR(message));
                if (r < 0 && r != -EBADMSG) {
                        link_enter_failed(link);
                        return;
                }
                break;

        case SD_NDISC_EVENT_REDIRECT:
                r = ndisc_redirect_handler(link, ASSERT_PTR(message));
                if (r < 0 && r != -EBADMSG) {
                        log_link_warning_errno(link, r, "Failed to process Redirect message: %m");
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
                log_link_debug(link, "Received unsupported NDisc event, ignoring.");
        }
}

static int ndisc_configure(Link *link) {
        int r;

        assert(link);

        if (!link_ndisc_enabled(link))
                return 0;

        if (link->ndisc)
                return -EBUSY; /* Already configured. */

        r = sd_ndisc_new(&link->ndisc);
        if (r < 0)
                return r;

        r = sd_ndisc_attach_event(link->ndisc, link->manager->event, 0);
        if (r < 0)
                return r;

        if (link->hw_addr.length == ETH_ALEN) {
                r = sd_ndisc_set_mac(link->ndisc, &link->hw_addr.ether);
                if (r < 0)
                        return r;
        }

        r = sd_ndisc_set_ifindex(link->ndisc, link->ifindex);
        if (r < 0)
                return r;

        r = sd_ndisc_set_callback(link->ndisc, ndisc_handler, link);
        if (r < 0)
                return r;

        return 0;
}

int ndisc_start(Link *link) {
        int r;

        assert(link);

        if (!link->ndisc || !link->dhcp6_client)
                return 0;

        if (!link_has_carrier(link))
                return 0;

        if (in6_addr_is_null(&link->ipv6ll_address))
                return 0;

        r = sd_ndisc_set_link_local_address(link->ndisc, &link->ipv6ll_address);
        if (r < 0)
                return r;

        log_link_debug(link, "Discovering IPv6 routers");

        r = sd_ndisc_start(link->ndisc);
        if (r < 0)
                return r;

        return 1;
}

static int ndisc_process_request(Request *req, Link *link, void *userdata) {
        int r;

        assert(link);

        if (!link_is_ready_to_configure(link, /* allow_unmanaged = */ false))
                return 0;

        r = ndisc_configure(link);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to configure IPv6 Router Discovery: %m");

        r = ndisc_start(link);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to start IPv6 Router Discovery: %m");

        log_link_debug(link, "IPv6 Router Discovery is configured%s.",
                       r > 0 ? " and started" : "");
        return 1;
}

int link_request_ndisc(Link *link) {
        int r;

        assert(link);

        if (!link_ndisc_enabled(link))
                return 0;

        if (link->ndisc)
                return 0;

        r = link_queue_request(link, REQUEST_TYPE_NDISC, ndisc_process_request, NULL);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to request configuring of the IPv6 Router Discovery: %m");

        log_link_debug(link, "Requested configuring of the IPv6 Router Discovery.");
        return 0;
}

int link_drop_ndisc_config(Link *link, Network *network) {
        int r, ret = 0;

        assert(link);
        assert(link->network);

        if (link->network == network)
                return 0; /* .network file is unchanged. It is not necessary to reconfigure the client. */

        if (!link_ndisc_enabled(link)) {
                /* NDisc is disabled. Stop the client if it is running and flush configs. */
                ret = ndisc_stop(link);
                ndisc_flush(link);
                link->ndisc = sd_ndisc_unref(link->ndisc);
                return ret;
        }

        /* Even if the client was previously enabled and also enabled in the new .network file, detailed
         * settings for the client may be different. Let's unref() the client. */
        link->ndisc = sd_ndisc_unref(link->ndisc);

        /* Get if NDisc was enabled or not. */
        Network *current = link->network;
        link->network = network;
        bool enabled = link_ndisc_enabled(link);
        link->network = current;

        /* If previously explicitly disabled, there should be nothing to drop.
         * If we do not know the previous setting of the client, e.g. when networkd is restarted, in that
         * case we do not have the previous .network file assigned to the interface, then  let's assume no
         * detailed configuration is changed. Hopefully, unmatching configurations will be dropped after
         * their lifetime. */
        if (!enabled)
                return 0;

        assert(network);

        /* Redirect messages will be ignored. Drop configurations based on the previously received redirect
         * messages. */
        if (!network->ndisc_use_redirect)
                (void) ndisc_drop_redirect(link, /* router = */ NULL);

        /* If one of the route setting is changed, drop all routes. */
        if (link->network->ndisc_use_gateway != network->ndisc_use_gateway ||
            link->network->ndisc_use_route_prefix != network->ndisc_use_route_prefix ||
            link->network->ndisc_use_onlink_prefix != network->ndisc_use_onlink_prefix ||
            link->network->ndisc_quickack != network->ndisc_quickack ||
            link->network->ndisc_route_metric_high != network->ndisc_route_metric_high ||
            link->network->ndisc_route_metric_medium != network->ndisc_route_metric_medium ||
            link->network->ndisc_route_metric_low != network->ndisc_route_metric_low ||
            !set_equal(link->network->ndisc_deny_listed_router, network->ndisc_deny_listed_router) ||
            !set_equal(link->network->ndisc_allow_listed_router, network->ndisc_allow_listed_router) ||
            !set_equal(link->network->ndisc_deny_listed_prefix, network->ndisc_deny_listed_prefix) ||
            !set_equal(link->network->ndisc_allow_listed_prefix, network->ndisc_allow_listed_prefix) ||
            !set_equal(link->network->ndisc_deny_listed_route_prefix, network->ndisc_deny_listed_route_prefix) ||
            !set_equal(link->network->ndisc_allow_listed_route_prefix, network->ndisc_allow_listed_route_prefix)) {
                Route *route;
                SET_FOREACH(route, link->manager->routes) {
                        if (route->source != NETWORK_CONFIG_SOURCE_NDISC)
                                continue;

                        if (!route_is_bound_to_link(route, link))
                                continue;

                        if (route->protocol == RTPROT_REDIRECT)
                                continue; /* redirect route is handled by ndisc_drop_redirect(). */

                        r = route_remove_and_cancel(route, link->manager);
                        if (r < 0)
                                RET_GATHER(ret, log_link_warning_errno(link, r, "Failed to remove SLAAC route, ignoring: %m"));
                }

                RET_GATHER(ret, ndisc_remove_unused_nexthops(link));
        }

        /* If SLAAC address is disabled, drop all addresses. */
        if (!network->ndisc_use_autonomous_prefix ||
            !set_equal(link->network->ndisc_tokens, network->ndisc_tokens) ||
            !set_equal(link->network->ndisc_deny_listed_prefix, network->ndisc_deny_listed_prefix) ||
            !set_equal(link->network->ndisc_allow_listed_prefix, network->ndisc_allow_listed_prefix)) {
                Address *address;
                SET_FOREACH(address, link->addresses) {
                        if (address->source != NETWORK_CONFIG_SOURCE_NDISC)
                                continue;

                        r = address_remove_and_cancel(address, link);
                        if (r < 0)
                                RET_GATHER(ret, log_link_warning_errno(link, r, "Failed to remove SLAAC address, ignoring: %m"));
                }
        }

        if (!network->ndisc_use_mtu)
                link->ndisc_mtu = 0;

        return ret;
}

int ndisc_stop(Link *link) {
        assert(link);

        link->ndisc_expire = sd_event_source_disable_unref(link->ndisc_expire);

        return sd_ndisc_stop(link->ndisc);
}

void ndisc_flush(Link *link) {
        assert(link);

        /* Remove all addresses, routes, RDNSS, DNSSL, DNR, and Captive Portal entries, without exception. */
        (void) ndisc_drop_outdated(link, /* router = */ NULL, /* timestamp_usec = */ USEC_INFINITY);
        (void) ndisc_drop_redirect(link, /* router = */ NULL);

        link->ndisc_routers_by_sender = hashmap_free(link->ndisc_routers_by_sender);
        link->ndisc_rdnss = set_free(link->ndisc_rdnss);
        link->ndisc_dnssl = set_free(link->ndisc_dnssl);
        link->ndisc_captive_portals = set_free(link->ndisc_captive_portals);
        link->ndisc_pref64 = set_free(link->ndisc_pref64);
        link->ndisc_redirects = set_free(link->ndisc_redirects);
        link->ndisc_dnr = set_free(link->ndisc_dnr);
        link->ndisc_mtu = 0;
}

static const char* const ndisc_start_dhcp6_client_table[_IPV6_ACCEPT_RA_START_DHCP6_CLIENT_MAX] = {
        [IPV6_ACCEPT_RA_START_DHCP6_CLIENT_NO]     = "no",
        [IPV6_ACCEPT_RA_START_DHCP6_CLIENT_ALWAYS] = "always",
        [IPV6_ACCEPT_RA_START_DHCP6_CLIENT_YES]    = "yes",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING_WITH_BOOLEAN(ndisc_start_dhcp6_client, IPv6AcceptRAStartDHCP6Client, IPV6_ACCEPT_RA_START_DHCP6_CLIENT_YES);

DEFINE_CONFIG_PARSE_ENUM(config_parse_ndisc_start_dhcp6_client, ndisc_start_dhcp6_client, IPv6AcceptRAStartDHCP6Client);
