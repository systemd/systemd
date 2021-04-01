/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-netlink.h"

#include "alloc-util.h"
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

int local_addresses(sd_netlink *context, int ifindex, int af, struct local_address **ret) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_free_ struct local_address *list = NULL;
        size_t n_list = 0, n_allocated = 0;
        sd_netlink_message *m;
        int r;

        if (context)
                rtnl = sd_netlink_ref(context);
        else {
                r = sd_netlink_open(&rtnl);
                if (r < 0)
                        return r;
        }

        r = sd_rtnl_message_new_addr(rtnl, &req, RTM_GETADDR, 0, af);
        if (r < 0)
                return r;

        r = sd_netlink_call(rtnl, req, 0, &reply);
        if (r < 0)
                return r;

        for (m = reply; m; m = sd_netlink_message_next(m)) {
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

                if (!GREEDY_REALLOC0(list, n_allocated, n_list+1))
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
                *ret = TAKE_PTR(list);
        }

        return (int) n_list;
}

static int add_local_gateway(
                struct local_address **list,
                size_t *n_list,
                size_t *n_allocated,
                int af,
                int ifindex,
                uint32_t metric,
                const RouteVia *via) {

        assert(list);
        assert(n_list);
        assert(n_allocated);
        assert(via);

        if (af != AF_UNSPEC && af != via->family)
                return 0;

        if (!GREEDY_REALLOC(*list, *n_allocated, *n_list + 1))
                return -ENOMEM;

        (*list)[(*n_list)++] = (struct local_address) {
                .ifindex = ifindex,
                .metric = metric,
                .family = via->family,
                .address = via->address,
        };

        return 0;
}

int local_gateways(sd_netlink *context, int ifindex, int af, struct local_address **ret) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_free_ struct local_address *list = NULL;
        size_t n_list = 0, n_allocated = 0;
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

        r = sd_netlink_message_request_dump(req, true);
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
                                r = add_local_gateway(&list, &n_list, &n_allocated, af, ifi, metric, &via);
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
                                r = add_local_gateway(&list, &n_list, &n_allocated, af, ifi, metric, &via);
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

                                r = add_local_gateway(&list, &n_list, &n_allocated, af, ifi, metric, &mr->gateway);
                                if (r < 0)
                                        return r;
                        }
                }
        }

        if (ret) {
                typesafe_qsort(list, n_list, address_compare);
                *ret = TAKE_PTR(list);
        }

        return (int) n_list;
}
