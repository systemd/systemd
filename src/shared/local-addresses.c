/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <endian.h>
#include <net/if.h>

#include "sd-netlink.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "in-addr-util.h"
#include "local-addresses.h"
#include "log.h"
#include "netlink-util.h"
#include "set.h"
#include "siphash24.h"
#include "socket-util.h"
#include "sort-util.h"

static int address_compare(const struct local_address *a, const struct local_address *b) {
        int r;

        /* Order lowest scope first, IPv4 before IPv6, lowest interface index first. */

        if (a->family == AF_INET && b->family == AF_INET6)
                return -1;
        if (a->family == AF_INET6 && b->family == AF_INET)
                return 1;

        r = CMP(a->scope, b->scope);
        if (r != 0)
                return r;

        r = CMP(a->priority, b->priority);
        if (r != 0)
                return r;

        r = CMP(a->weight, b->weight);
        if (r != 0)
                return r;

        r = CMP(a->ifindex, b->ifindex);
        if (r != 0)
                return r;

        r = memcmp(&a->address, &b->address, FAMILY_ADDRESS_SIZE(a->family));
        if (r != 0)
                return r;

        return memcmp(&a->prefsrc, &b->prefsrc, FAMILY_ADDRESS_SIZE(a->family));
}

bool has_local_address(const struct local_address *addresses, size_t n_addresses, const struct local_address *needle) {
        assert(addresses || n_addresses == 0);
        assert(needle);

        FOREACH_ARRAY(i, addresses, n_addresses)
                if (address_compare(i, needle) == 0)
                        return true;

        return false;
}

static void suppress_duplicates(struct local_address *list, size_t *n_list) {
        size_t old_size, new_size;

        POINTER_MAY_BE_NULL(list);
        assert(n_list);

        /* Removes duplicate entries, assumes the list of addresses is already sorted. Updates in-place. */

        if (*n_list < 2) /* list with less than two entries can't have duplicates */
                return;

        old_size = *n_list;
        new_size = 1;

        for (size_t i = 1; i < old_size; i++) {

                if (address_compare(list + i, list + new_size - 1) == 0)
                        continue;

                list[new_size++] = list[i];
        }

        *n_list = new_size;
}

static int add_local_address_full(
                struct local_address **list,
                size_t *n_list,
                int ifindex,
                unsigned char scope,
                uint32_t priority,
                uint32_t weight,
                int family,
                const union in_addr_union *address,
                const union in_addr_union *prefsrc) {

        assert(list);
        assert(n_list);
        assert(ifindex > 0);
        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(address);
        POINTER_MAY_BE_NULL(prefsrc);

        if (!GREEDY_REALLOC(*list, *n_list + 1))
                return -ENOMEM;

        (*list)[(*n_list)++] = (struct local_address) {
                .ifindex = ifindex,
                .scope = scope,
                .priority = priority,
                .weight = weight,
                .family = family,
                .address = *address,
                .prefsrc = prefsrc ? *prefsrc : IN_ADDR_NULL,
        };

        return 1;
}

int add_local_address(
                struct local_address **list,
                size_t *n_list,
                int ifindex,
                unsigned char scope,
                int family,
                const union in_addr_union *address) {

        return add_local_address_full(
                        list, n_list, ifindex,
                        scope, /* priority= */ 0, /* weight= */ 0,
                        family, address, /* prefsrc= */ NULL);
}

int local_addresses(
                sd_netlink *context,
                int ifindex,
                int af,
                struct local_address **ret) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_free_ struct local_address *list = NULL;
        size_t n_list = 0;
        int r;

        if (context)
                rtnl = sd_netlink_ref(context);
        else {
                r = sd_netlink_open(&rtnl);
                if (r < 0)
                        return r;
        }

        r = sd_rtnl_message_new_addr(rtnl, &req, RTM_GETADDR, ifindex, af);
        if (r < 0)
                return r;

        r = sd_netlink_message_set_request_dump(req, true);
        if (r < 0)
                return r;

        r = sd_netlink_call(rtnl, req, 0, &reply);
        if (r < 0)
                return r;

        for (sd_netlink_message *m = reply; m; m = sd_netlink_message_next(m)) {
                union in_addr_union a;
                unsigned char scope;
                uint16_t type;
                int ifi, family;

                r = sd_netlink_message_get_errno(m);
                if (r < 0)
                        return r;

                r = sd_netlink_message_get_type(m, &type);
                if (r < 0)
                        return r;
                if (type != RTM_NEWADDR)
                        continue;

                r = sd_rtnl_message_addr_get_ifindex(m, &ifi);
                if (r < 0)
                        return r;
                if (ifindex > 0 && ifi != ifindex)
                        continue;

                r = sd_rtnl_message_addr_get_family(m, &family);
                if (r < 0)
                        return r;
                if (!IN_SET(family, AF_INET, AF_INET6))
                        continue;
                if (af != AF_UNSPEC && af != family)
                        continue;

                uint32_t flags;
                r = sd_netlink_message_read_u32(m, IFA_FLAGS, &flags);
                if (r < 0)
                        return r;
                if ((flags & (IFA_F_DEPRECATED|IFA_F_TENTATIVE)) != 0)
                        continue;

                r = sd_rtnl_message_addr_get_scope(m, &scope);
                if (r < 0)
                        return r;

                if (ifindex == 0 && IN_SET(scope, RT_SCOPE_HOST, RT_SCOPE_NOWHERE))
                        continue;

                switch (family) {

                case AF_INET:
                        r = sd_netlink_message_read_in_addr(m, IFA_LOCAL, &a.in);
                        if (r < 0) {
                                r = sd_netlink_message_read_in_addr(m, IFA_ADDRESS, &a.in);
                                if (r < 0)
                                        continue;
                        }
                        break;

                case AF_INET6:
                        r = sd_netlink_message_read_in6_addr(m, IFA_LOCAL, &a.in6);
                        if (r < 0) {
                                r = sd_netlink_message_read_in6_addr(m, IFA_ADDRESS, &a.in6);
                                if (r < 0)
                                        continue;
                        }
                        break;

                default:
                        assert_not_reached();
                }

                r = add_local_address(&list, &n_list, ifi, scope, family, &a);
                if (r < 0)
                        return r;
        };

        typesafe_qsort(list, n_list, address_compare);
        suppress_duplicates(list, &n_list);

        if (ret)
                *ret = TAKE_PTR(list);

        return (int) n_list;
}

static int add_local_gateway(
                struct local_address **list,
                size_t *n_list,
                int ifindex,
                uint32_t priority,
                uint32_t weight,
                int family,
                const union in_addr_union *address,
                const union in_addr_union *prefsrc) {

        return add_local_address_full(
                        list, n_list,
                        ifindex,
                        /* scope= */ 0, priority, weight,
                        family, address, prefsrc);
}

/* A gateway-less default route or nexthop that may be backed by a point-to-point peer.
 * Candidates collapse by (ifindex, family, prefsrc), so only the best metric survives:
 * lower priority wins, and weight follows that winning candidate. */
typedef struct GatewayCandidate {
        int ifindex;
        uint32_t priority;
        uint32_t weight;
        int family;
        union in_addr_union prefsrc;
} GatewayCandidate;

/* Key for facts that are scoped by link and address family. */
typedef struct GatewayLinkKey {
        int ifindex;
        int family;
} GatewayLinkKey;

/* The usable peer endpoint for a key, or ambiguous if distinct peers were found. */
typedef struct GatewayPeerInfo {
        union in_addr_union peer;
        bool ambiguous;
} GatewayPeerInfo;

/* Peer selected for a link/family pair when the route has no RTA_PREFSRC. */
typedef struct GatewayPeerByLink {
        int ifindex;
        int family;
        GatewayPeerInfo info;
} GatewayPeerByLink;

/* Peer selected for one local endpoint when the route carries RTA_PREFSRC. */
typedef struct GatewayPeerByLocal {
        int ifindex;
        int family;
        union in_addr_union local;
        GatewayPeerInfo info;
} GatewayPeerByLocal;

/* Link flags collected from one RTM_GETLINK dump. */
typedef struct GatewayLinkInfo {
        int ifindex;
        unsigned flags;
} GatewayLinkInfo;

static void gateway_candidate_hash_func(const GatewayCandidate *c, struct siphash *state) {
        assert(c);
        assert(state);

        siphash24_compress_typesafe(c->ifindex, state);
        siphash24_compress_typesafe(c->family, state);
        in_addr_hash_func(&c->prefsrc, c->family, state);
}

static int gateway_candidate_compare_func(const GatewayCandidate *a, const GatewayCandidate *b) {
        int r;

        assert(a);
        assert(b);

        r = CMP(a->ifindex, b->ifindex);
        if (r != 0)
                return r;

        r = CMP(a->family, b->family);
        if (r != 0)
                return r;

        return memcmp(&a->prefsrc, &b->prefsrc, FAMILY_ADDRESS_SIZE(a->family));
}

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
                gateway_candidate_hash_ops,
                GatewayCandidate,
                gateway_candidate_hash_func,
                gateway_candidate_compare_func,
                free);

static void gateway_link_key_hash_func(const GatewayLinkKey *k, struct siphash *state) {
        assert(k);
        assert(state);

        siphash24_compress_typesafe(k->ifindex, state);
        siphash24_compress_typesafe(k->family, state);
}

static int gateway_link_key_compare_func(const GatewayLinkKey *a, const GatewayLinkKey *b) {
        int r;

        assert(a);
        assert(b);

        r = CMP(a->ifindex, b->ifindex);
        if (r != 0)
                return r;

        return CMP(a->family, b->family);
}

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
                gateway_link_key_hash_ops,
                GatewayLinkKey,
                gateway_link_key_hash_func,
                gateway_link_key_compare_func,
                free);

static void gateway_peer_by_link_hash_func(const GatewayPeerByLink *p, struct siphash *state) {
        assert(p);
        assert(state);

        siphash24_compress_typesafe(p->ifindex, state);
        siphash24_compress_typesafe(p->family, state);
}

static int gateway_peer_by_link_compare_func(const GatewayPeerByLink *a, const GatewayPeerByLink *b) {
        int r;

        assert(a);
        assert(b);

        r = CMP(a->ifindex, b->ifindex);
        if (r != 0)
                return r;

        return CMP(a->family, b->family);
}

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
                gateway_peer_by_link_hash_ops,
                GatewayPeerByLink,
                gateway_peer_by_link_hash_func,
                gateway_peer_by_link_compare_func,
                free);

static void gateway_peer_by_local_hash_func(const GatewayPeerByLocal *k, struct siphash *state) {
        assert(k);
        assert(state);

        siphash24_compress_typesafe(k->ifindex, state);
        siphash24_compress_typesafe(k->family, state);
        in_addr_hash_func(&k->local, k->family, state);
}

static int gateway_peer_by_local_compare_func(const GatewayPeerByLocal *a, const GatewayPeerByLocal *b) {
        int r;

        assert(a);
        assert(b);

        r = CMP(a->ifindex, b->ifindex);
        if (r != 0)
                return r;

        r = CMP(a->family, b->family);
        if (r != 0)
                return r;

        return memcmp(&a->local, &b->local, FAMILY_ADDRESS_SIZE(a->family));
}

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
                gateway_peer_by_local_hash_ops,
                GatewayPeerByLocal,
                gateway_peer_by_local_hash_func,
                gateway_peer_by_local_compare_func,
                free);

static void gateway_link_info_hash_func(const GatewayLinkInfo *i, struct siphash *state) {
        assert(i);
        assert(state);

        siphash24_compress_typesafe(i->ifindex, state);
}

static int gateway_link_info_compare_func(const GatewayLinkInfo *a, const GatewayLinkInfo *b) {
        assert(a);
        assert(b);

        return CMP(a->ifindex, b->ifindex);
}

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
                gateway_link_info_hash_ops,
                GatewayLinkInfo,
                gateway_link_info_hash_func,
                gateway_link_info_compare_func,
                free);

static int add_gateway_candidate(
                Set **candidates,
                int ifindex,
                uint32_t priority,
                uint32_t weight,
                int family,
                const union in_addr_union *prefsrc) {

        int r;

        assert(candidates);
        assert(ifindex > 0);
        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(prefsrc);

        GatewayCandidate lookup = {
                .ifindex = ifindex,
                .family = family,
                .prefsrc = *prefsrc,
        };
        GatewayCandidate *candidate = set_get(*candidates, &lookup);
        if (candidate) {
                if (priority < candidate->priority) {
                        candidate->priority = priority;
                        candidate->weight = weight;
                }

                return 0;
        }

        _cleanup_free_ GatewayCandidate *new_candidate = new(GatewayCandidate, 1);
        if (!new_candidate)
                return -ENOMEM;

        *new_candidate = (GatewayCandidate) {
                .ifindex = ifindex,
                .priority = priority,
                .weight = weight,
                .family = family,
                .prefsrc = *prefsrc,
        };

        r = set_ensure_consume(candidates, &gateway_candidate_hash_ops, TAKE_PTR(new_candidate));
        if (r < 0)
                return r;

        return 1;
}

static int add_gateway_link_info(
                Set **links,
                int ifindex,
                unsigned flags) {

        assert(links);
        assert(ifindex > 0);

        _cleanup_free_ GatewayLinkInfo *new_link = new(GatewayLinkInfo, 1);
        if (!new_link)
                return -ENOMEM;

        *new_link = (GatewayLinkInfo) {
                .ifindex = ifindex,
                .flags = flags,
        };

        return set_ensure_consume(links, &gateway_link_info_hash_ops, TAKE_PTR(new_link));
}

static int collect_gateway_link_infos(sd_netlink *rtnl, Set **links) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;
        int r;

        assert(rtnl);
        assert(links);

        r = sd_rtnl_message_new_link(rtnl, &req, RTM_GETLINK, 0);
        if (r < 0)
                return r;

        r = sd_netlink_message_set_request_dump(req, true);
        if (r < 0)
                return r;

        r = sd_netlink_call(rtnl, req, 0, &reply);
        if (r < 0)
                return r;

        for (sd_netlink_message *m = reply; m; m = sd_netlink_message_next(m)) {
                uint16_t type;
                unsigned flags;
                int ifindex;

                r = sd_netlink_message_get_errno(m);
                if (r < 0) {
                        log_debug_errno(r, "Failed to process link dump message, ignoring: %m");
                        continue;
                }

                r = sd_netlink_message_get_type(m, &type);
                if (r < 0) {
                        log_debug_errno(r, "Failed to get link message type, ignoring: %m");
                        continue;
                }
                if (type != RTM_NEWLINK)
                        continue;

                r = sd_rtnl_message_link_get_ifindex(m, &ifindex);
                if (r < 0) {
                        log_debug_errno(r, "Failed to get link interface index, ignoring: %m");
                        continue;
                }
                if (ifindex <= 0)
                        continue;

                r = sd_rtnl_message_link_get_flags(m, &flags);
                if (r < 0) {
                        log_debug_errno(r, "Failed to get link flags, ignoring: %m");
                        continue;
                }

                r = add_gateway_link_info(links, ifindex, flags);
                if (r < 0)
                        return r;
        }

        return 0;
}

/* Remember one usable peer per lookup key. If we see a different peer for the same
 * key later, the result becomes ambiguous and we stop publishing a synthetic gateway
 * for that key instead of guessing which peer to return. */
static void update_gateway_peer_info(
                GatewayPeerInfo *info,
                int family,
                const union in_addr_union *peer) {

        assert(info);
        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(peer);

        if (info->ambiguous)
                return;

        /* Multiple local endpoints may point to the same peer. Distinct peers for the same lookup key
         * are ambiguous, so no synthetic gateway will be published for that key. */
        if (in_addr_equal(family, &info->peer, peer) <= 0)
                info->ambiguous = true;
}

static int add_gateway_peer_by_link(
                Set **peers_by_link,
                int ifindex,
                int family,
                const union in_addr_union *peer) {

        int r;

        assert(peers_by_link);
        assert(ifindex > 0);
        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(peer);

        GatewayPeerByLink lookup = {
                .ifindex = ifindex,
                .family = family,
        };
        GatewayPeerByLink *info = set_get(*peers_by_link, &lookup);
        if (info) {
                update_gateway_peer_info(&info->info, family, peer);
                return 0;
        }

        _cleanup_free_ GatewayPeerByLink *new_info = new(GatewayPeerByLink, 1);
        if (!new_info)
                return -ENOMEM;

        *new_info = (GatewayPeerByLink) {
                .ifindex = ifindex,
                .family = family,
                .info = {
                        .peer = *peer,
                        .ambiguous = false,
                },
        };

        r = set_ensure_consume(peers_by_link, &gateway_peer_by_link_hash_ops, TAKE_PTR(new_info));
        if (r < 0)
                return r;

        return 1;
}

static int add_gateway_peer_by_local(
                Set **peers_by_local,
                int ifindex,
                int family,
                const union in_addr_union *local,
                const union in_addr_union *peer) {

        int r;

        assert(peers_by_local);
        assert(ifindex > 0);
        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(local);
        assert(peer);

        GatewayPeerByLocal lookup = {
                .ifindex = ifindex,
                .family = family,
                .local = *local,
        };
        GatewayPeerByLocal *p = set_get(*peers_by_local, &lookup);
        if (p) {
                update_gateway_peer_info(&p->info, family, peer);
                return 0;
        }

        _cleanup_free_ GatewayPeerByLocal *new_info = new(GatewayPeerByLocal, 1);
        if (!new_info)
                return -ENOMEM;

        *new_info = (GatewayPeerByLocal) {
                .ifindex = ifindex,
                .family = family,
                .local = *local,
                .info = {
                        .peer = *peer,
                        .ambiguous = false,
                },
        };

        r = set_ensure_consume(peers_by_local, &gateway_peer_by_local_hash_ops, TAKE_PTR(new_info));
        if (r < 0)
                return r;

        return 1;
}

static int add_gateway_peer(
                Set **peers_by_link,
                Set **peers_by_local,
                int ifindex,
                int family,
                const union in_addr_union *local,
                const union in_addr_union *peer) {

        int r;

        assert(peers_by_link);
        assert(peers_by_local);
        assert(ifindex > 0);
        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(local);
        assert(peer);

        r = add_gateway_peer_by_link(peers_by_link, ifindex, family, peer);
        if (r < 0)
                return r;

        r = add_gateway_peer_by_local(peers_by_local, ifindex, family, local, peer);
        if (r < 0)
                return r;

        return 1;
}

static int parse_nexthop_one(
                struct local_address **list,
                size_t *n_list,
                Set **candidates,
                bool allow_via,
                bool allow_candidate,
                int family,
                uint32_t priority,
                const union in_addr_union *prefsrc,
                const struct rtnexthop *rtnh) {

        bool has_gw = false;
        int r;

        assert(rtnh);

        size_t len = rtnh->rtnh_len - sizeof(struct rtnexthop);
        for (struct rtattr *attr = RTNH_DATA(rtnh); RTA_OK(attr, len); attr = RTA_NEXT(attr, len))

                switch (attr->rta_type) {
                case RTA_GATEWAY:
                        if (has_gw)
                                return -EBADMSG;

                        has_gw = true;

                        if (attr->rta_len != RTA_LENGTH(FAMILY_ADDRESS_SIZE(family)))
                                return -EBADMSG;

                        union in_addr_union a;
                        memcpy(&a, RTA_DATA(attr), FAMILY_ADDRESS_SIZE(family));
                        r = add_local_gateway(list, n_list, rtnh->rtnh_ifindex, priority, rtnh->rtnh_hops, family, &a, prefsrc);
                        if (r < 0)
                                return r;

                        break;

                case RTA_VIA:
                        if (has_gw)
                                return -EBADMSG;

                        has_gw = true;

                        if (!allow_via)
                                continue;

                        if (family != AF_INET)
                                return -EBADMSG; /* RTA_VIA is only supported for IPv4 routes. */

                        if (attr->rta_len != RTA_LENGTH(sizeof(RouteVia)))
                                return -EBADMSG;

                        RouteVia *via = RTA_DATA(attr);
                        if (via->family != AF_INET6)
                                return -EBADMSG; /* gateway address should be always IPv6. */

                        r = add_local_gateway(list, n_list, rtnh->rtnh_ifindex, priority, rtnh->rtnh_hops, via->family,
                                              &(union in_addr_union) { .in6 = via->address.in6 },
                                              /* prefsrc= */ NULL);
                        if (r < 0)
                                return r;

                        break;
                }

        if (!has_gw && allow_candidate && rtnh->rtnh_ifindex > 0)
                return add_gateway_candidate(
                                candidates, rtnh->rtnh_ifindex, priority, rtnh->rtnh_hops,
                                family, prefsrc);

        return 0;
}

static int parse_nexthops(
                struct local_address **list,
                size_t *n_list,
                Set **candidates,
                int ifindex,
                bool allow_via,
                bool allow_candidate,
                int family,
                uint32_t priority,
                const union in_addr_union *prefsrc,
                const struct rtnexthop *rtnh,
                size_t size) {

        int r;

        assert(list);
        assert(n_list);
        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(rtnh || size == 0);

        if (size < sizeof(struct rtnexthop))
                return -EBADMSG;

        for (; size >= sizeof(struct rtnexthop); ) {
                if (NLMSG_ALIGN(rtnh->rtnh_len) > size)
                        return -EBADMSG;

                if (rtnh->rtnh_len < sizeof(struct rtnexthop))
                        return -EBADMSG;

                if (ifindex > 0 && rtnh->rtnh_ifindex != ifindex)
                        goto next_nexthop;

                r = parse_nexthop_one(
                                list, n_list, candidates,
                                allow_via, allow_candidate, family, priority, prefsrc, rtnh);
                if (r < 0)
                        return r;

        next_nexthop:
                size -= NLMSG_ALIGN(rtnh->rtnh_len);
                rtnh = RTNH_NEXT(rtnh);
        }

        return 0;
}

static int append_gateways_from_peer_maps(
                struct local_address **list,
                size_t *n_list,
                Set *candidates,
                Set *peers_by_link,
                Set *peers_by_local) {

        int r;

        assert(list);
        assert(n_list);

        GatewayCandidate *candidate;
        SET_FOREACH(candidate, candidates) {
                if (in_addr_is_set(candidate->family, &candidate->prefsrc)) {
                        /* A candidate with prefsrc already narrows the lookup down to one
                         * local address. In that case we only need to check whether this
                         * exact local endpoint has a unique peer on the same link/family. */
                        GatewayPeerByLocal *p = set_get(
                                        peers_by_local,
                                        &(GatewayPeerByLocal) {
                                                .ifindex = candidate->ifindex,
                                                .family = candidate->family,
                                                .local = candidate->prefsrc,
                                        });

                        if (!p || p->info.ambiguous)
                                continue;

                        r = add_local_gateway(
                                        list, n_list,
                                        candidate->ifindex,
                                        candidate->priority,
                                        candidate->weight,
                                        candidate->family,
                                        &p->info.peer,
                                        &candidate->prefsrc);
                        if (r < 0)
                                return r;
                        continue;
                }

                /* Without prefsrc we can only publish a synthetic gateway if the whole
                 * link/family pair has exactly one usable peer. Otherwise the result is
                 * ambiguous and we must skip it. */
                GatewayPeerByLink *p = set_get(
                                peers_by_link,
                                &(GatewayPeerByLink) {
                                        .ifindex = candidate->ifindex,
                                        .family = candidate->family,
                                });
                if (!p || p->info.ambiguous)
                        continue;

                r = add_local_gateway(
                                list, n_list,
                                candidate->ifindex,
                                candidate->priority,
                                candidate->weight,
                                candidate->family,
                                &p->info.peer,
                                &candidate->prefsrc);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int add_gateway_peers(
                sd_netlink *rtnl,
                struct local_address **list,
                size_t *n_list,
                int ifindex,
                int af,
                Set *candidates) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;
        _cleanup_set_free_ Set *links = NULL, *p2p_candidate_links = NULL, *peers_by_link = NULL, *peers_by_local = NULL;
        int r;

        assert(rtnl);
        assert(IN_SET(af, AF_UNSPEC, AF_INET, AF_INET6));
        assert(list);
        assert(n_list);

        if (set_isempty(candidates))
                return 0;

        r = collect_gateway_link_infos(rtnl, &links);
        if (r < 0)
                return r;

        /* First narrow the candidate links down to links that are actually
         * point-to-point. Only those can expose a peer address that is safe to
         * publish as a synthetic _gateway result. */
        GatewayCandidate *candidate;
        SET_FOREACH(candidate, candidates) {
                GatewayLinkInfo *link = set_get(
                                links,
                                &(GatewayLinkInfo) {
                                        .ifindex = candidate->ifindex,
                                });
                if (!link)
                        continue;

                if (!FLAGS_SET(link->flags, IFF_POINTOPOINT))
                        continue;

                _cleanup_free_ GatewayLinkKey *new_link = new(GatewayLinkKey, 1);
                if (!new_link)
                        return -ENOMEM;

                *new_link = (GatewayLinkKey) {
                        .ifindex = candidate->ifindex,
                        .family = candidate->family,
                };
                r = set_ensure_consume(&p2p_candidate_links, &gateway_link_key_hash_ops, TAKE_PTR(new_link));
                if (r < 0)
                        return r;
        }

        if (set_isempty(p2p_candidate_links))
                return 0;

        /* Now dump addresses only for the filtered point-to-point links. This keeps
         * the address scan small and avoids examining unrelated interfaces that can
         * never contribute a synthetic gateway. */
        r = sd_rtnl_message_new_addr(rtnl, &req, RTM_GETADDR, ifindex, af);
        if (r < 0)
                return r;

        r = sd_netlink_message_set_request_dump(req, true);
        if (r < 0)
                return r;

        r = sd_netlink_call(rtnl, req, 0, &reply);
        if (r < 0)
                return r;

        for (sd_netlink_message *m = reply; m; m = sd_netlink_message_next(m)) {
                union in_addr_union local, peer;
                unsigned char scope;
                uint16_t type;
                int ifi, family;

                r = sd_netlink_message_get_errno(m);
                if (r < 0) {
                        log_debug_errno(r, "Failed to process address dump message, ignoring: %m");
                        continue;
                }

                r = sd_netlink_message_get_type(m, &type);
                if (r < 0) {
                        log_debug_errno(r, "Failed to get address message type, ignoring: %m");
                        continue;
                }
                if (type != RTM_NEWADDR)
                        continue;

                r = sd_rtnl_message_addr_get_ifindex(m, &ifi);
                if (r < 0) {
                        log_debug_errno(r, "Failed to get address interface index, ignoring: %m");
                        continue;
                }
                if (ifi <= 0)
                        continue;
                if (ifindex > 0 && ifi != ifindex)
                        continue;

                r = sd_rtnl_message_addr_get_family(m, &family);
                if (r < 0) {
                        log_debug_errno(r, "Failed to get address family, ignoring: %m");
                        continue;
                }
                if (!IN_SET(family, AF_INET, AF_INET6))
                        continue;
                if (af != AF_UNSPEC && family != af)
                        continue;
                if (!set_contains(p2p_candidate_links,
                                  &(GatewayLinkKey) {
                                          .ifindex = ifi,
                                          .family = family,
                                  }))
                        continue;

                uint8_t prefixlen;
                r = sd_rtnl_message_addr_get_prefixlen(m, &prefixlen);
                if (r < 0) {
                        log_debug_errno(r, "Failed to get address prefix length, ignoring: %m");
                        continue;
                }
                if (prefixlen != FAMILY_ADDRESS_SIZE(family) * 8)
                        continue;

                r = sd_rtnl_message_addr_get_scope(m, &scope);
                if (r < 0) {
                        log_debug_errno(r, "Failed to get address scope, ignoring: %m");
                        continue;
                }
                if (IN_SET(scope, RT_SCOPE_HOST, RT_SCOPE_NOWHERE))
                        continue;

                /* Point-to-point addresses carry the local endpoint in IFA_LOCAL and the peer endpoint in
                 * IFA_ADDRESS. On regular interfaces, the two addresses are identical. */
                r = netlink_message_read_in_addr_union(m, IFA_LOCAL, family, &local);
                if (r == -ENODATA)
                        continue;
                if (r < 0) {
                        log_debug_errno(r, "Failed to read local address, ignoring: %m");
                        continue;
                }

                r = netlink_message_read_in_addr_union(m, IFA_ADDRESS, family, &peer);
                if (r == -ENODATA)
                        continue;
                if (r < 0) {
                        log_debug_errno(r, "Failed to read peer address, ignoring: %m");
                        continue;
                }

                if (in_addr_equal(family, &local, &peer) > 0)
                        continue;
                if (!in_addr_is_set(family, &peer))
                        continue;
                if (family == AF_INET && be32toh(peer.in.s_addr) == INADDR_BROADCAST)
                        continue;
                if (in_addr_is_localhost(family, &peer) > 0)
                        continue;
                if (in_addr_is_multicast(family, &peer) > 0)
                        continue;

                /* Record the peer both by link and by local endpoint so the final
                 * pass can choose between link-based and prefsrc-based lookup. */
                r = add_gateway_peer(&peers_by_link, &peers_by_local, ifi, family, &local, &peer);
                if (r < 0)
                        return r;
        }

        return append_gateways_from_peer_maps(list, n_list, candidates, peers_by_link, peers_by_local);
}

int local_gateways(
                sd_netlink *context,
                int ifindex,
                int af,
                struct local_address **ret) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_free_ struct local_address *list = NULL;
        _cleanup_set_free_ Set *candidates = NULL;
        size_t n_list = 0;
        int r;

        /* The RTA_VIA attribute is used only for IPv4 routes with an IPv6 gateway. If IPv4 gateways are
         * requested (af == AF_INET), then we do not return IPv6 gateway addresses. Similarly, if IPv6
         * gateways are requested (af == AF_INET6), then we do not return gateway addresses for IPv4 routes.
         * We still parse RTA_VIA for family-specific requests to distinguish explicit next hops from
         * gateway-less routes. */
        bool allow_via = af == AF_UNSPEC;

        if (context)
                rtnl = sd_netlink_ref(context);
        else {
                r = sd_netlink_open(&rtnl);
                if (r < 0)
                        return r;
        }

        r = sd_rtnl_message_new_route(rtnl, &req, RTM_GETROUTE, af, RTPROT_UNSPEC);
        if (r < 0)
                return r;

        r = sd_rtnl_message_route_set_type(req, RTN_UNICAST);
        if (r < 0)
                return r;

        r = sd_rtnl_message_route_set_table(req, RT_TABLE_MAIN);
        if (r < 0)
                return r;

        r = sd_netlink_message_set_request_dump(req, true);
        if (r < 0)
                return r;

        r = sd_netlink_call(rtnl, req, 0, &reply);
        if (r < 0)
                return r;

        for (sd_netlink_message *m = reply; m; m = sd_netlink_message_next(m)) {
                union in_addr_union prefsrc = IN_ADDR_NULL;
                uint16_t type;
                unsigned char dst_len, route_type, src_len, table;
                uint32_t ifi = 0, priority = 0;
                int family;

                r = sd_netlink_message_get_errno(m);
                if (r < 0)
                        return r;

                r = sd_netlink_message_get_type(m, &type);
                if (r < 0)
                        return r;
                if (type != RTM_NEWROUTE)
                        continue;

                r = sd_rtnl_message_route_get_type(m, &route_type);
                if (r < 0) {
                        log_debug_errno(r, "Failed to get route type, ignoring: %m");
                        continue;
                }

                /* We only care for default routes */
                r = sd_rtnl_message_route_get_dst_prefixlen(m, &dst_len);
                if (r < 0)
                        return r;
                if (dst_len != 0)
                        continue;

                r = sd_rtnl_message_route_get_src_prefixlen(m, &src_len);
                if (r < 0)
                        return r;
                if (src_len != 0)
                        continue;

                r = sd_rtnl_message_route_get_table(m, &table);
                if (r < 0)
                        return r;
                if (table != RT_TABLE_MAIN)
                        continue;

                r = sd_netlink_message_read_u32(m, RTA_PRIORITY, &priority);
                if (r < 0 && r != -ENODATA)
                        return r;

                r = sd_rtnl_message_route_get_family(m, &family);
                if (r < 0)
                        return r;
                if (!IN_SET(family, AF_INET, AF_INET6))
                        continue;
                if (af != AF_UNSPEC && af != family)
                        continue;

                r = netlink_message_read_in_addr_union(m, RTA_PREFSRC, family, &prefsrc);
                if (r < 0 && r != -ENODATA)
                        return r;

                r = sd_netlink_message_read_u32(m, RTA_OIF, &ifi);
                if (r < 0 && r != -ENODATA)
                        return r;
                if (r >= 0) {
                        if (ifi <= 0)
                                return -EINVAL;
                        if (ifindex > 0 && (int) ifi != ifindex)
                                continue;

                        union in_addr_union gateway;
                        r = netlink_message_read_in_addr_union(m, RTA_GATEWAY, family, &gateway);
                        if (r < 0 && r != -ENODATA)
                                return r;
                        if (r >= 0) {
                                r = add_local_gateway(&list, &n_list, ifi, priority, 0, family, &gateway, &prefsrc);
                                if (r < 0)
                                        return r;

                                continue;
                        }

                        if (family == AF_INET) {
                                RouteVia via;
                                r = sd_netlink_message_read(m, RTA_VIA, sizeof(via), &via);
                                if (r < 0 && r != -ENODATA)
                                        return r;
                                if (r >= 0) {
                                        if (!allow_via)
                                                continue;

                                        if (via.family != AF_INET6)
                                                return -EBADMSG;

                                        /* Ignore prefsrc, and let's take the source address by socket command, if necessary. */
                                        r = add_local_gateway(&list, &n_list, ifi, priority, 0, via.family,
                                                              &(union in_addr_union) { .in6 = via.address.in6 },
                                                              /* prefsrc= */ NULL);
                                        if (r < 0)
                                                return r;

                                        continue;
                                }
                        }

                        if (route_type != RTN_UNICAST)
                                continue;

                        r = add_gateway_candidate(
                                        &candidates, ifi, priority, 0, family, &prefsrc);
                        if (r < 0)
                                return r;

                        /* If the route has RTA_OIF, it does not have RTA_MULTIPATH. */
                        continue;
                }

                size_t rta_len;
                _cleanup_free_ void *rta_multipath = NULL;
                r = sd_netlink_message_read_data(m, RTA_MULTIPATH, &rta_len, &rta_multipath);
                if (r < 0 && r != -ENODATA)
                        return r;
                if (r >= 0) {
                        r = parse_nexthops(
                                        &list, &n_list, &candidates,
                                        ifindex, allow_via, route_type == RTN_UNICAST, family, priority, &prefsrc,
                                        rta_multipath, rta_len);
                        if (r < 0)
                                return r;
                }
        }

        r = add_gateway_peers(rtnl, &list, &n_list, ifindex, af, candidates);
        if (ERRNO_IS_NEG_RESOURCE(r))
                return r;
        if (r < 0)
                log_debug_errno(r, "Failed to look up point-to-point peers, ignoring: %m");

        typesafe_qsort(list, n_list, address_compare);
        suppress_duplicates(list, &n_list);

        if (ret)
                *ret = TAKE_PTR(list);

        return (int) n_list;
}

static int add_local_outbound(
                struct local_address **list,
                size_t *n_list,
                int ifindex,
                int family,
                const union in_addr_union *address) {

        return add_local_address_full(
                        list, n_list, ifindex,
                        /* scope= */ 0, /* priority= */ 0, /* weight= */ 0,
                        family, address, /* prefsrc= */ NULL);
}

static int add_local_outbound_by_prefsrc(
                struct local_address **list,
                size_t *n_list,
                const struct local_address *gateway,
                const struct local_address *addresses,
                size_t n_addresses) {

        int r;

        assert(list);
        assert(n_list);
        assert(gateway);

        if (!in_addr_is_set(gateway->family, &gateway->prefsrc))
                return 0;

        /* If the gateway has prefsrc, then let's honor the field. But, check if the address is assigned to
         * the same interface, like we do with SO_BINDTOINDEX. */

        bool found = false;
        FOREACH_ARRAY(a, addresses, n_addresses) {
                if (a->ifindex != gateway->ifindex)
                        continue;
                if (a->family != gateway->family)
                        continue;
                if (in_addr_equal(a->family, &a->address, &gateway->prefsrc) <= 0)
                        continue;

                found = true;
                break;
        }
        if (!found)
                return -EHOSTUNREACH;

        r = add_local_outbound(list, n_list, gateway->ifindex, gateway->family, &gateway->prefsrc);
        if (r < 0)
                return r;

        return 1;
}

int local_outbounds(
                sd_netlink *context,
                int ifindex,
                int af,
                struct local_address **ret) {

        _cleanup_free_ struct local_address *list = NULL, *gateways = NULL, *addresses = NULL;
        size_t n_list = 0;
        int r, n_gateways, n_addresses;

        /* Determines our default outbound addresses, i.e. the "primary" local addresses we use to talk to IP
         * addresses behind the default routes. This is still an address of the local host (i.e. this doesn't
         * resolve NAT or so), but it's the set of addresses the local IP stack most likely uses to talk to
         * other hosts.
         *
         * This works by connect()ing a SOCK_DGRAM socket to the local gateways, and then reading the IP
         * address off the socket that was chosen for the routing decision. */

        n_gateways = local_gateways(context, ifindex, af, &gateways);
        if (n_gateways < 0)
                return n_gateways;
        if (n_gateways == 0) {
                /* No gateways? Then we have no outbound addresses either. */
                if (ret)
                        *ret = NULL;

                return 0;
        }

        n_addresses = local_addresses(context, ifindex, af, &addresses);
        if (n_addresses < 0)
                return n_addresses;

        FOREACH_ARRAY(i, gateways, n_gateways) {
                _cleanup_close_ int fd = -EBADF;
                union sockaddr_union sa;
                socklen_t salen;

                r = add_local_outbound_by_prefsrc(&list, &n_list, i, addresses, n_addresses);
                if (r > 0 || r == -EHOSTUNREACH)
                        continue;
                if (r < 0)
                        return r;

                fd = socket(i->family, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
                if (fd < 0)
                        return -errno;

                switch (i->family) {

                case AF_INET:
                        sa.in = (struct sockaddr_in) {
                                .sin_family = AF_INET,
                                .sin_addr = i->address.in,
                                .sin_port = htobe16(53), /* doesn't really matter which port we pick —
                                                          * we just care about the routing decision */
                        };

                        break;

                case AF_INET6:
                        sa.in6 = (struct sockaddr_in6) {
                                .sin6_family = AF_INET6,
                                .sin6_addr = i->address.in6,
                                .sin6_port = htobe16(53),
                                .sin6_scope_id = i->ifindex,
                        };

                        break;

                default:
                        assert_not_reached();
                }

                /* So ideally we'd just use IP_UNICAST_IF here to pass the ifindex info to the kernel before
                 * connect()ing, sot that it influences the routing decision. However, on current kernels
                 * IP_UNICAST_IF doesn't actually influence the routing decision for UDP — which I think
                 * should probably just be considered a bug. Once that bug is fixed this is the best API to
                 * use, since it is the most lightweight. */
                r = socket_set_unicast_if(fd, i->family, i->ifindex);
                if (r < 0)
                        log_debug_errno(r, "Failed to set unicast interface index %i, ignoring: %m", i->ifindex);

                /* We'll also use SO_BINDTOINDEX. This requires CAP_NET_RAW on old kernels, hence there's a
                 * good chance this fails. Since 5.7 this restriction was dropped and the first
                 * SO_BINDTOINDEX on a socket may be done without privileges. This one has the benefit of
                 * really influencing the routing decision, i.e. this one definitely works for us — as long
                 * as we have the privileges for it. */
                r = socket_bind_to_ifindex(fd, i->ifindex);
                if (r < 0)
                        log_debug_errno(r, "Failed to bind socket to interface %i, ignoring: %m", i->ifindex);

                /* Let's now connect() to the UDP socket, forcing the kernel to make a routing decision and
                 * auto-bind the socket. We ignore failures on this, since that failure might happen for a
                 * multitude of reasons (policy/firewall issues, who knows?) and some of them might be
                 * *after* the routing decision and the auto-binding already took place. If so we can still
                 * make use of the binding and return it. Hence, let's not unnecessarily fail early here: we
                 * can still easily detect if the auto-binding worked or not, by comparing the bound IP
                 * address with zero — which we do below. */
                if (connect(fd, &sa.sa, sockaddr_len(&sa)) < 0)
                        log_debug_errno(errno, "Failed to connect SOCK_DGRAM socket to gateway, ignoring: %m");

                /* Let's now read the socket address of the socket. A routing decision should have been
                 * made. Let's verify that and use the data. */
                salen = sockaddr_len(&sa);
                if (getsockname(fd, &sa.sa, &salen) < 0)
                        return -errno;
                assert(sa.sa.sa_family == i->family);
                assert(salen == sockaddr_len(&sa));

                switch (i->family) {

                case AF_INET:
                        if (in4_addr_is_null(&sa.in.sin_addr)) /* Auto-binding didn't work. :-( */
                                continue;

                        r = add_local_outbound(&list, &n_list, i->ifindex, i->family,
                                               &(union in_addr_union) { .in = sa.in.sin_addr });
                        if (r < 0)
                                return r;
                        break;

                case AF_INET6:
                        if (in6_addr_is_null(&sa.in6.sin6_addr))
                                continue;

                        r = add_local_outbound(&list, &n_list, i->ifindex, i->family,
                                               &(union in_addr_union) { .in6 = sa.in6.sin6_addr });
                        if (r < 0)
                                return r;
                        break;

                default:
                        assert_not_reached();
                }
        }

        typesafe_qsort(list, n_list, address_compare);
        suppress_duplicates(list, &n_list);

        if (ret)
                *ret = TAKE_PTR(list);

        return (int) n_list;
}
