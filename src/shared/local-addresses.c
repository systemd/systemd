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

        r = CMP(a->metric, b->metric);
        if (r != 0)
                return r;

        r = CMP(a->ifindex, b->ifindex);
        if (r != 0)
                return r;

        return memcmp(&a->address, &b->address, FAMILY_ADDRESS_SIZE(a->family));
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
                struct local_address *a;
                unsigned char flags;
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
                if (af != AF_UNSPEC && af != family)
                        continue;

                r = sd_rtnl_message_addr_get_flags(m, &flags);
                if (r < 0)
                        return r;
                if (flags & IFA_F_DEPRECATED)
                        continue;

                if (!GREEDY_REALLOC0(list, n_list+1))
                        return -ENOMEM;

                a = list + n_list;

                r = sd_rtnl_message_addr_get_scope(m, &a->scope);
                if (r < 0)
                        return r;

                if (ifindex == 0 && IN_SET(a->scope, RT_SCOPE_HOST, RT_SCOPE_NOWHERE))
                        continue;

                switch (family) {

                case AF_INET:
                        r = sd_netlink_message_read_in_addr(m, IFA_LOCAL, &a->address.in);
                        if (r < 0) {
                                r = sd_netlink_message_read_in_addr(m, IFA_ADDRESS, &a->address.in);
                                if (r < 0)
                                        continue;
                        }
                        break;

                case AF_INET6:
                        r = sd_netlink_message_read_in6_addr(m, IFA_LOCAL, &a->address.in6);
                        if (r < 0) {
                                r = sd_netlink_message_read_in6_addr(m, IFA_ADDRESS, &a->address.in6);
                                if (r < 0)
                                        continue;
                        }
                        break;

                default:
                        continue;
                }

                a->ifindex = ifi;
                a->family = family;

                n_list++;
        };

        if (ret) {
                typesafe_qsort(list, n_list, address_compare);
                suppress_duplicates(list, &n_list);
                *ret = TAKE_PTR(list);
        }

        return (int) n_list;
}

static int add_local_gateway(
                struct local_address **list,
                size_t *n_list,
                int af,
                int ifindex,
                uint32_t metric,
                const RouteVia *via) {

        assert(list);
        assert(n_list);
        assert(via);

        if (af != AF_UNSPEC && af != via->family)
                return 0;

        if (!GREEDY_REALLOC(*list, *n_list + 1))
                return -ENOMEM;

        (*list)[(*n_list)++] = (struct local_address) {
                .ifindex = ifindex,
                .metric = metric,
                .family = via->family,
                .address = via->address,
        };

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
                _cleanup_ordered_set_free_free_ OrderedSet *multipath_routes = NULL;
                _cleanup_free_ void *rta_multipath = NULL;
                union in_addr_union gateway;
                uint16_t type;
                unsigned char dst_len, src_len, table;
                uint32_t ifi = 0, metric = 0;
                size_t rta_len;
                int family;
                RouteVia via;

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

                r = sd_netlink_message_read_u32(m, RTA_PRIORITY, &metric);
                if (r < 0 && r != -ENODATA)
                        return r;

                r = sd_rtnl_message_route_get_family(m, &family);
                if (r < 0)
                        return r;
                if (!IN_SET(family, AF_INET, AF_INET6))
                        continue;

                r = sd_netlink_message_read_u32(m, RTA_OIF, &ifi);
                if (r < 0 && r != -ENODATA)
                        return r;
                if (r >= 0) {
                        if (ifi <= 0)
                                return -EINVAL;
                        if (ifindex > 0 && (int) ifi != ifindex)
                                continue;

                        r = netlink_message_read_in_addr_union(m, RTA_GATEWAY, family, &gateway);
                        if (r < 0 && r != -ENODATA)
                                return r;
                        if (r >= 0) {
                                via.family = family;
                                via.address = gateway;
                                r = add_local_gateway(&list, &n_list, af, ifi, metric, &via);
                                if (r < 0)
                                        return r;

                                continue;
                        }

                        if (family != AF_INET)
                                continue;

                        r = sd_netlink_message_read(m, RTA_VIA, sizeof(via), &via);
                        if (r < 0 && r != -ENODATA)
                                return r;
                        if (r >= 0) {
                                r = add_local_gateway(&list, &n_list, af, ifi, metric, &via);
                                if (r < 0)
                                        return r;

                                continue;
                        }
                }

                r = sd_netlink_message_read_data(m, RTA_MULTIPATH, &rta_len, &rta_multipath);
                if (r < 0 && r != -ENODATA)
                        return r;
                if (r >= 0) {
                        MultipathRoute *mr;

                        r = rtattr_read_nexthop(rta_multipath, rta_len, family, &multipath_routes);
                        if (r < 0)
                                return r;

                        ORDERED_SET_FOREACH(mr, multipath_routes) {
                                if (ifindex > 0 && mr->ifindex != ifindex)
                                        continue;

                                r = add_local_gateway(&list, &n_list, af, ifi, metric, &mr->gateway);
                                if (r < 0)
                                        return r;
                        }
                }
        }

        if (ret) {
                typesafe_qsort(list, n_list, address_compare);
                suppress_duplicates(list, &n_list);
                *ret = TAKE_PTR(list);
        }

        return (int) n_list;
}

int local_outbounds(
                sd_netlink *context,
                int ifindex,
                int af,
                struct local_address **ret) {

        _cleanup_free_ struct local_address *list = NULL, *gateways = NULL;
        size_t n_list = 0;
        int r, n_gateways;

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

        for (int i = 0; i < n_gateways; i++) {
                _cleanup_close_ int fd = -1;
                union sockaddr_union sa;
                socklen_t salen;

                fd = socket(gateways[i].family, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
                if (fd < 0)
                        return -errno;

                switch (gateways[i].family) {

                case AF_INET:
                        sa.in = (struct sockaddr_in) {
                                .sin_family = AF_INET,
                                .sin_addr = gateways[i].address.in,
                                .sin_port = htobe16(53), /* doesn't really matter which port we pick —
                                                          * we just care about the routing decision */
                        };

                        break;

                case AF_INET6:
                        sa.in6 = (struct sockaddr_in6) {
                                .sin6_family = AF_INET6,
                                .sin6_addr = gateways[i].address.in6,
                                .sin6_port = htobe16(53),
                                .sin6_scope_id = gateways[i].ifindex,
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
                r = socket_set_unicast_if(fd, gateways[i].family, gateways[i].ifindex);
                if (r < 0)
                        log_debug_errno(r, "Failed to set unicast interface index %i, ignoring: %m", gateways[i].ifindex);

                /* We'll also use SO_BINDTOINDEX. This requires CAP_NET_RAW on old kernels, hence there's a
                 * good chance this fails. Since 5.7 this restriction was dropped and the first
                 * SO_BINDTOINDEX on a socket may be done without privileges. This one has the benefit of
                 * really influencing the routing decision, i.e. this one definitely works for us — as long
                 * as we have the privileges for it. */
                r = socket_bind_to_ifindex(fd, gateways[i].ifindex);
                if (r < 0)
                        log_debug_errno(r, "Failed to bind socket to interface %i, ignoring: %m", gateways[i].ifindex);

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
                assert(sa.sa.sa_family == gateways[i].family);
                assert(salen == SOCKADDR_LEN(sa));

                switch (gateways[i].family) {

                case AF_INET:
                        if (in4_addr_is_null(&sa.in.sin_addr)) /* Auto-binding didn't work. :-( */
                                continue;

                        if (!GREEDY_REALLOC(list, n_list+1))
                                return -ENOMEM;

                        list[n_list++] = (struct local_address) {
                                .family = gateways[i].family,
                                .ifindex = gateways[i].ifindex,
                                .address.in = sa.in.sin_addr,
                        };

                        break;

                case AF_INET6:
                        if (in6_addr_is_null(&sa.in6.sin6_addr))
                                continue;

                        if (!GREEDY_REALLOC(list, n_list+1))
                                return -ENOMEM;

                        list[n_list++] = (struct local_address) {
                                .family = gateways[i].family,
                                .ifindex = gateways[i].ifindex,
                                .address.in6 = sa.in6.sin6_addr,
                        };
                        break;

                default:
                        assert_not_reached();
                }
        }

        if (ret) {
                typesafe_qsort(list, n_list, address_compare);
                suppress_duplicates(list, &n_list);
                *ret = TAKE_PTR(list);
        }

        return (int) n_list;
}
