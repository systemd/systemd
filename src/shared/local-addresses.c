/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <poll.h>

#include "sd-netlink.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "io-util.h"
#include "iovec-util.h"
#include "local-addresses.h"
#include "log.h"
#include "netlink-util.h"
#include "socket-util.h"
#include "sort-util.h"
#include "time-util.h"

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
                                              /* prefsrc= */ NULL);
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

static int local_gateway_from_message(
                sd_netlink_message *m,
                int ifindex,
                bool allow_via,
                struct local_address **list,
                size_t *n_list) {

        union in_addr_union prefsrc = IN_ADDR_NULL;
        uint16_t type;
        unsigned char dst_len, src_len, table;
        uint32_t ifi = 0, priority = 0;
        int r, family;

        r = sd_netlink_message_get_errno(m);
        if (r < 0)
                return r;

        r = sd_netlink_message_get_type(m, &type);
        if (r < 0)
                return r;
        if (type != RTM_NEWROUTE)
                return 0;

        /* We only care for default routes */
        r = sd_rtnl_message_route_get_dst_prefixlen(m, &dst_len);
        if (r < 0)
                return r;
        if (dst_len != 0)
                return 0;

        r = sd_rtnl_message_route_get_src_prefixlen(m, &src_len);
        if (r < 0)
                return r;
        if (src_len != 0)
                return 0;

        r = sd_rtnl_message_route_get_table(m, &table);
        if (r < 0)
                return r;
        if (table != RT_TABLE_MAIN)
                return 0;

        r = sd_netlink_message_read_u32(m, RTA_PRIORITY, &priority);
        if (r < 0 && r != -ENODATA)
                return r;

        r = sd_rtnl_message_route_get_family(m, &family);
        if (r < 0)
                return r;
        if (!IN_SET(family, AF_INET, AF_INET6))
                return 0;

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
                        return 0;

                union in_addr_union gateway;
                r = netlink_message_read_in_addr_union(m, RTA_GATEWAY, family, &gateway);
                if (r < 0 && r != -ENODATA)
                        return r;
                if (r >= 0) {
                        r = add_local_gateway(list, n_list, ifi, priority, 0, family, &gateway, &prefsrc);
                        if (r < 0)
                                return r;

                        return 0;
                }

                if (!allow_via)
                        return 0;

                if (family != AF_INET)
                        return 0;

                RouteVia via;
                r = sd_netlink_message_read(m, RTA_VIA, sizeof(via), &via);
                if (r < 0 && r != -ENODATA)
                        return r;
                if (r >= 0) {
                        if (via.family != AF_INET6)
                                return -EBADMSG;

                        /* Ignore prefsrc, and let's take the source address by socket command, if necessary. */
                        r = add_local_gateway(list, n_list, ifi, priority, 0, via.family,
                                              &(union in_addr_union) { .in6 = via.address.in6 },
                                              /* prefsrc= */ NULL);
                        if (r < 0)
                                return r;
                }

                /* If the route has RTA_OIF, it does not have RTA_MULTIPATH. */
                return 0;
        }

        size_t rta_len;
        _cleanup_free_ void *rta_multipath = NULL;
        r = sd_netlink_message_read_data(m, RTA_MULTIPATH, &rta_len, &rta_multipath);
        if (r < 0 && r != -ENODATA)
                return r;
        if (r >= 0) {
                r = parse_nexthops(list, n_list, ifindex, allow_via, family, priority, &prefsrc,
                                   rta_multipath, rta_len);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int local_gateways_full_dump(
                sd_netlink *context,
                int af,
                int ifindex,
                bool allow_via,
                struct local_address **list,
                size_t *n_list) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
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
                r = local_gateway_from_message(m, ifindex, allow_via, list, n_list);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int local_gateway_from_raw_message(
                const struct nlmsghdr *hdr,
                int ifindex,
                bool allow_via,
                struct local_address **list,
                size_t *n_list) {

        const struct rtmsg *rtm;
        size_t rta_len, multipath_size = 0;
        bool has_oif = false, has_gateway = false, has_via = false;
        uint32_t oif = 0, priority = 0;
        union in_addr_union prefsrc = IN_ADDR_NULL, gateway = IN_ADDR_NULL;
        RouteVia via = {};
        const struct rtnexthop *multipath = NULL;
        int r;

        assert(hdr);

        rtm = NLMSG_DATA(hdr);

        /* We only care for default routes. The kernel dumps the IPv4 routes in order of their keys, and all
         * default routes are the first ones in that order, hence as soon as we have seen a route with a
         * non-zero destination prefix length, no more default routes can follow. */
        if (rtm->rtm_dst_len != 0)
                return 1;

        if (rtm->rtm_src_len != 0)
                return 0;

        if (rtm->rtm_table != RT_TABLE_MAIN)
                return 0;

        if (rtm->rtm_family != AF_INET)
                return 0;

        rta_len = hdr->nlmsg_len - NLMSG_LENGTH(sizeof(struct rtmsg));
        for (struct rtattr *attr = RTM_RTA(rtm); RTA_OK(attr, rta_len); attr = RTA_NEXT(attr, rta_len))
                switch (attr->rta_type & NLA_TYPE_MASK) {
                case RTA_PRIORITY: {
                        uint32_t v;

                        if (RTA_PAYLOAD(attr) != sizeof(uint32_t))
                                return -EIO;

                        memcpy(&v, RTA_DATA(attr), sizeof(v));
                        priority = FLAGS_SET(attr->rta_type, NLA_F_NET_BYTEORDER) ? be32toh(v) : v;
                        break;
                }

                case RTA_PREFSRC:
                        if (RTA_PAYLOAD(attr) != sizeof(struct in_addr))
                                return -EIO;

                        memcpy(&prefsrc.in, RTA_DATA(attr), sizeof(struct in_addr));
                        break;

                case RTA_OIF: {
                        uint32_t v;

                        if (RTA_PAYLOAD(attr) != sizeof(uint32_t))
                                return -EIO;

                        memcpy(&v, RTA_DATA(attr), sizeof(v));
                        oif = FLAGS_SET(attr->rta_type, NLA_F_NET_BYTEORDER) ? be32toh(v) : v;
                        has_oif = true;
                        break;
                }

                case RTA_GATEWAY:
                        if (RTA_PAYLOAD(attr) != sizeof(struct in_addr))
                                return -EIO;

                        memcpy(&gateway.in, RTA_DATA(attr), sizeof(struct in_addr));
                        has_gateway = true;
                        break;

                case RTA_VIA:
                        if (RTA_PAYLOAD(attr) != sizeof(RouteVia))
                                return -EIO;

                        memcpy(&via, RTA_DATA(attr), sizeof(RouteVia));
                        has_via = true;
                        break;

                case RTA_MULTIPATH:
                        multipath = RTA_DATA(attr);
                        multipath_size = RTA_PAYLOAD(attr);
                        break;
                }

        if (has_oif) {
                if (oif <= 0)
                        return -EINVAL;
                if (ifindex > 0 && (int) oif != ifindex)
                        return 0;

                if (has_gateway) {
                        r = add_local_gateway(list, n_list, oif, priority, /* weight= */ 0, AF_INET,
                                              &gateway, &prefsrc);
                        if (r < 0)
                                return r;

                        return 0;
                }

                if (!allow_via || !has_via)
                        return 0;

                if (via.family != AF_INET6)
                        return -EBADMSG;

                /* Ignore prefsrc, and let's take the source address by socket command, if necessary. */
                r = add_local_gateway(list, n_list, oif, priority, /* weight= */ 0, AF_INET6,
                                      &(union in_addr_union) { .in6 = via.address.in6 },
                                      /* prefsrc= */ NULL);
                if (r < 0)
                        return r;

                /* If the route has RTA_OIF, it does not have RTA_MULTIPATH. */
                return 0;
        }

        if (multipath) {
                r = parse_nexthops(list, n_list, ifindex, allow_via, AF_INET, priority, &prefsrc,
                                   multipath, multipath_size);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int local_gateways_ipv4_dump(
                int fd,
                int ifindex,
                bool allow_via,
                struct local_address **list,
                size_t *n_list) {

        _cleanup_free_ void *buf = NULL;
        size_t buf_size = 0;
        int r;

        struct {
                struct nlmsghdr nlh;
                struct rtmsg rtm;
        } request = {
                .nlh = {
                        .nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
                        .nlmsg_type = RTM_GETROUTE,
                        .nlmsg_flags = NLM_F_REQUEST|NLM_F_DUMP,
                        .nlmsg_seq = 1,
                },
                .rtm = {
                        .rtm_family = AF_INET,
                        .rtm_protocol = RTPROT_UNSPEC,
                        .rtm_type = RTN_UNICAST,
                        .rtm_table = RT_TABLE_MAIN,
                },
        };

        union sockaddr_union sa = {
                .nl = {
                        .nl_family = AF_NETLINK,
                },
        };

        r = bind(fd, &sa.sa, sizeof(sa.nl));
        if (r < 0)
                return -errno;

        r = sendto(fd, &request, sizeof(request), 0, &sa.sa, sizeof(sa.nl));
        if (r < 0)
                return -errno;

        for (;;) {
                struct iovec iov = IOVEC_MAKE(buf, buf_size);
                struct msghdr msg = {
                        .msg_iov = &iov,
                        .msg_iovlen = 1,
                };
                ssize_t k;

                /* The kernel generates the messages of the dump on demand, i.e. only as we read them.
                 * Hence, wait for each message with a timeout, so that we cannot block indefinitely. */
                r = fd_wait_for_event(fd, POLLIN, 25 * USEC_PER_SEC); /* same default timeout as for sd_netlink_call() */
                if (r == -EINTR)
                        continue;
                if (r < 0)
                        return r;
                if (r == 0)
                        return -ETIMEDOUT;
                if (!FLAGS_SET(r, POLLIN))
                        return -EIO;

                k = recvmsg_safe(fd, &msg, MSG_PEEK|MSG_TRUNC);
                if (k == -EINTR)
                        continue;
                if (k < 0)
                        return (int) k;
                if (k == 0)
                        continue;

                if ((size_t) k > buf_size) {
                        if (!greedy_realloc(&buf, k, sizeof(uint8_t)))
                                return -ENOMEM;
                        buf_size = k;
                        continue;
                }

                iov = IOVEC_MAKE(buf, buf_size);
                msg = (struct msghdr) {
                        .msg_iov = &iov,
                        .msg_iovlen = 1,
                };

                k = recvmsg_safe(fd, &msg, 0);
                if (k < 0)
                        return (int) k;
                if (k == 0)
                        continue;

                size_t len = (size_t) k;
                for (struct nlmsghdr *hdr = buf; NLMSG_OK(hdr, len); hdr = NLMSG_NEXT(hdr, len)) {

                        if (hdr->nlmsg_type == NLMSG_DONE)
                                return 0;

                        if (hdr->nlmsg_type == NLMSG_ERROR) {
                                const struct nlmsgerr *err = NLMSG_DATA(hdr);

                                if (err->error != 0)
                                        return err->error;

                                continue;
                        }

                        if (hdr->nlmsg_type != RTM_NEWROUTE)
                                continue;

                        r = local_gateway_from_raw_message(hdr, ifindex, allow_via, list, n_list);
                        if (r < 0)
                                return r;
                        if (r > 0) /* First non-default route, hence no more default routes follow. */
                                return 0;
                }
        }
}

static int local_gateways_ipv4(
                sd_netlink *context,
                int ifindex,
                bool allow_via,
                struct local_address **list,
                size_t *n_list) {

        _cleanup_close_ int fd = -EBADF;
        int r;

        /* For IPv4, the kernel stores the default routes in the single trie node with key 0, and dumps the
         * routes of the trie in order of the keys, starting with key 0. Hence, the default routes are the
         * first messages of the dump, and all of them are emitted before any other route. This means we can
         * stop reading the dump as soon as we have seen the first non-default route. For IPv6, the kernel
         * walks its route trie in post-order, and the default routes are stored at the root of the trie,
         * hence they are the last messages of the dump, and we have to read the whole dump.
         *
         * Stopping the dump early would leave the remaining messages pending in the kernel, which would
         * then disturb the next request on the same socket. Hence, we use a socket of our own, and simply
         * close it once we are done, which also makes the kernel cancel the rest of the dump. This is only
         * possible when the kernel supports strict dump filtering, as otherwise it would not only dump the
         * main table, and the default routes of other tables would be interleaved with the non-default
         * routes of the main table. If strict dump filtering is not available, we fall back to the full
         * dump below. */
        fd = socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_ROUTE);
        if (fd < 0)
                return -errno;

        r = setsockopt_int(fd, SOL_NETLINK, NETLINK_GET_STRICT_CHK, true);
        if (r < 0) {
                log_debug_errno(r, "Failed to enable strict netlink route dump checks, "
                                   "falling back to full dump: %m");

                // FIXME: This compatibility code path shall be removed once kernel 4.20
                //        becomes the new minimal baseline
                return local_gateways_full_dump(context, AF_INET, ifindex, allow_via, list, n_list);
        }

        return local_gateways_ipv4_dump(fd, ifindex, allow_via, list, n_list);
}

int local_gateways(
                sd_netlink *context,
                int ifindex,
                int af,
                struct local_address **ret) {

        _cleanup_free_ struct local_address *list = NULL;
        size_t n_list = 0;
        int r;

        /* The RTA_VIA attribute is used only for IPv4 routes with an IPv6 gateway. If IPv4 gateways are
         * requested (af == AF_INET), then we do not return IPv6 gateway addresses. Similarly, if IPv6
         * gateways are requested (af == AF_INET6), then we do not return gateway addresses for IPv4 routes.
         * So, the RTA_VIA attribute is only parsed when af == AF_UNSPEC. */
        bool allow_via = af == AF_UNSPEC;

        if (IN_SET(af, AF_UNSPEC, AF_INET)) {
                r = local_gateways_ipv4(context, ifindex, allow_via, &list, &n_list);
                if (r < 0)
                        return r;
        }

        if (IN_SET(af, AF_UNSPEC, AF_INET6)) {
                r = local_gateways_full_dump(context, AF_INET6, ifindex, /* allow_via= */ false,
                                             &list, &n_list);
                if (r < 0)
                        return r;
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
