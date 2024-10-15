/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if_arp.h>

#include "sd-netlink.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "local-addresses.h"
#include "macro.h"
#include "netlink-util.h"
#include "sort-util.h"

static int address_compare(const struct local_address *a, const struct local_address *b) {
        int r;

        /* Order lowest scope first, IPv4 before IPv6, lowest interface index first */

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

        return memcmp(&a->address, &b->address, FAMILY_ADDRESS_SIZE(a->family));
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
                        scope, /* priority = */ 0, /* weight = */ 0,
                        family, address, /* prefsrc = */ NULL);
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
                unsigned char flags, scope;
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

                r = sd_rtnl_message_addr_get_flags(m, &flags);
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
                        /* scope = */ 0, priority, weight,
                        family, address, prefsrc);
}

static int parse_nexthop_one(
                struct local_address **list,
                size_t *n_list,
                bool allow_via,
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
                                              /* prefsrc = */ NULL);
                        if (r < 0)
                                return r;

                        break;
                }

        return 0;
}

static int parse_nexthops(
                struct local_address **list,
                size_t *n_list,
                int ifindex,
                bool allow_via,
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

                r = parse_nexthop_one(list, n_list, allow_via, family, priority, prefsrc, rtnh);
                if (r < 0)
                        return r;

        next_nexthop:
                size -= NLMSG_ALIGN(rtnh->rtnh_len);
                rtnh = RTNH_NEXT(rtnh);
        }

        return 0;
}

int local_gateways(
                sd_netlink *context,
                int ifindex,
                int af,
                struct local_address **ret) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_free_ struct local_address *list = NULL;
        size_t n_list = 0;
        int r;

        /* The RTA_VIA attribute is used only for IPv4 routes with an IPv6 gateway. If IPv4 gateways are
         * requested (af == AF_INET), then we do not return IPv6 gateway addresses. Similarly, if IPv6
         * gateways are requested (af == AF_INET6), then we do not return gateway addresses for IPv4 routes.
         * So, the RTA_VIA attribute is only parsed when af == AF_UNSPEC. */
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
                unsigned char dst_len, src_len, table;
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

                        if (!allow_via)
                                continue;

                        if (family != AF_INET)
                                continue;

                        RouteVia via;
                        r = sd_netlink_message_read(m, RTA_VIA, sizeof(via), &via);
                        if (r < 0 && r != -ENODATA)
                                return r;
                        if (r >= 0) {
                                if (via.family != AF_INET6)
                                        return -EBADMSG;

                                /* Ignore prefsrc, and let's take the source address by socket command, if necessary. */
                                r = add_local_gateway(&list, &n_list, ifi, priority, 0, via.family,
                                                      &(union in_addr_union) { .in6 = via.address.in6 },
                                                      /* prefsrc = */ NULL);
                                if (r < 0)
                                        return r;
                        }

                        /* If the route has RTA_OIF, it does not have RTA_MULTIPATH. */
                        continue;
                }

                size_t rta_len;
                _cleanup_free_ void *rta_multipath = NULL;
                r = sd_netlink_message_read_data(m, RTA_MULTIPATH, &rta_len, &rta_multipath);
                if (r < 0 && r != -ENODATA)
                        return r;
                if (r >= 0) {
                        r = parse_nexthops(&list, &n_list, ifindex, allow_via, family, priority, &prefsrc, rta_multipath, rta_len);
                        if (r < 0)
                                return r;
                }
        }

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
                        /* scope = */ 0, /* priority = */ 0, /* weight = */ 0,
                        family, address, /* prefsrc = */ NULL);
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
                if (connect(fd, &sa.sa, SOCKADDR_LEN(sa)) < 0)
                        log_debug_errno(errno, "Failed to connect SOCK_DGRAM socket to gateway, ignoring: %m");

                /* Let's now read the socket address of the socket. A routing decision should have been
                 * made. Let's verify that and use the data. */
                salen = SOCKADDR_LEN(sa);
                if (getsockname(fd, &sa.sa, &salen) < 0)
                        return -errno;
                assert(sa.sa.sa_family == i->family);
                assert(salen == SOCKADDR_LEN(sa));

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
