/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <linux/fib_rules.h>
#include <linux/if_addrlabel.h>
#include <linux/if_bridge.h>
#include <linux/nexthop.h>
#include <stdbool.h>
#include <unistd.h>

#include "sd-netlink.h"

#include "format-util.h"
#include "netlink-internal.h"
#include "netlink-types.h"
#include "netlink-util.h"
#include "socket-util.h"

static bool rtnl_message_type_is_neigh(uint16_t type) {
        return IN_SET(type, RTM_NEWNEIGH, RTM_GETNEIGH, RTM_DELNEIGH);
}

static bool rtnl_message_type_is_route(uint16_t type) {
        return IN_SET(type, RTM_NEWROUTE, RTM_GETROUTE, RTM_DELROUTE);
}

static bool rtnl_message_type_is_nexthop(uint16_t type) {
        return IN_SET(type, RTM_NEWNEXTHOP, RTM_GETNEXTHOP, RTM_DELNEXTHOP);
}

static bool rtnl_message_type_is_link(uint16_t type) {
        return IN_SET(type,
                      RTM_NEWLINK, RTM_SETLINK, RTM_GETLINK, RTM_DELLINK,
                      RTM_NEWLINKPROP, RTM_DELLINKPROP, RTM_GETLINKPROP);
}

static bool rtnl_message_type_is_addr(uint16_t type) {
        return IN_SET(type, RTM_NEWADDR, RTM_GETADDR, RTM_DELADDR);
}

static bool rtnl_message_type_is_addrlabel(uint16_t type) {
        return IN_SET(type, RTM_NEWADDRLABEL, RTM_DELADDRLABEL, RTM_GETADDRLABEL);
}

static bool rtnl_message_type_is_routing_policy_rule(uint16_t type) {
        return IN_SET(type, RTM_NEWRULE, RTM_DELRULE, RTM_GETRULE);
}

static bool rtnl_message_type_is_traffic_control(uint16_t type) {
        return IN_SET(type,
                      RTM_NEWQDISC, RTM_DELQDISC, RTM_GETQDISC,
                      RTM_NEWTCLASS, RTM_DELTCLASS, RTM_GETTCLASS);
}

static bool rtnl_message_type_is_mdb(uint16_t type) {
        return IN_SET(type, RTM_NEWMDB, RTM_DELMDB, RTM_GETMDB);
}

static bool rtnl_message_type_is_nsid(uint16_t type) {
        return IN_SET(type, RTM_NEWNSID, RTM_DELNSID, RTM_GETNSID);
}

int sd_rtnl_message_route_set_dst_prefixlen(sd_netlink_message *m, uint8_t prefixlen) {
        struct rtmsg *rtm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_route(m->hdr->nlmsg_type), -EINVAL);

        rtm = NLMSG_DATA(m->hdr);

        if ((rtm->rtm_family == AF_INET && prefixlen > 32) ||
            (rtm->rtm_family == AF_INET6 && prefixlen > 128))
                return -ERANGE;

        rtm->rtm_dst_len = prefixlen;

        return 0;
}

int sd_rtnl_message_route_set_src_prefixlen(sd_netlink_message *m, uint8_t prefixlen) {
        struct rtmsg *rtm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_route(m->hdr->nlmsg_type), -EINVAL);

        rtm = NLMSG_DATA(m->hdr);

        if ((rtm->rtm_family == AF_INET && prefixlen > 32) ||
            (rtm->rtm_family == AF_INET6 && prefixlen > 128))
                return -ERANGE;

        rtm->rtm_src_len = prefixlen;

        return 0;
}

int sd_rtnl_message_route_set_tos(sd_netlink_message *m, uint8_t tos) {
        struct rtmsg *rtm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_route(m->hdr->nlmsg_type), -EINVAL);

        rtm = NLMSG_DATA(m->hdr);

        rtm->rtm_tos = tos;

        return 0;
}

int sd_rtnl_message_route_set_scope(sd_netlink_message *m, uint8_t scope) {
        struct rtmsg *rtm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_route(m->hdr->nlmsg_type), -EINVAL);

        rtm = NLMSG_DATA(m->hdr);

        rtm->rtm_scope = scope;

        return 0;
}

int sd_rtnl_message_route_set_flags(sd_netlink_message *m, uint32_t flags) {
        struct rtmsg *rtm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_route(m->hdr->nlmsg_type), -EINVAL);

        rtm = NLMSG_DATA(m->hdr);

        rtm->rtm_flags = flags;

        return 0;
}

int sd_rtnl_message_route_get_flags(sd_netlink_message *m, uint32_t *ret) {
        struct rtmsg *rtm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_route(m->hdr->nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        rtm = NLMSG_DATA(m->hdr);

        *ret = rtm->rtm_flags;

        return 0;
}

int sd_rtnl_message_route_set_table(sd_netlink_message *m, uint8_t table) {
        struct rtmsg *rtm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_route(m->hdr->nlmsg_type), -EINVAL);

        rtm = NLMSG_DATA(m->hdr);

        rtm->rtm_table = table;

        return 0;
}

int sd_rtnl_message_route_get_family(sd_netlink_message *m, int *ret) {
        struct rtmsg *rtm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_route(m->hdr->nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        rtm = NLMSG_DATA(m->hdr);

        *ret = rtm->rtm_family;

        return 0;
}

int sd_rtnl_message_route_get_type(sd_netlink_message *m, uint8_t *ret) {
        struct rtmsg *rtm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_route(m->hdr->nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        rtm = NLMSG_DATA(m->hdr);

        *ret = rtm->rtm_type;

        return 0;
}

int sd_rtnl_message_route_set_type(sd_netlink_message *m, uint8_t type) {
        struct rtmsg *rtm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_route(m->hdr->nlmsg_type), -EINVAL);

        rtm = NLMSG_DATA(m->hdr);

        rtm->rtm_type = type;

        return 0;
}

int sd_rtnl_message_route_get_protocol(sd_netlink_message *m, uint8_t *ret) {
        struct rtmsg *rtm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_route(m->hdr->nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        rtm = NLMSG_DATA(m->hdr);

        *ret = rtm->rtm_protocol;

        return 0;
}

int sd_rtnl_message_route_get_scope(sd_netlink_message *m, uint8_t *ret) {
        struct rtmsg *rtm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_route(m->hdr->nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        rtm = NLMSG_DATA(m->hdr);

        *ret = rtm->rtm_scope;

        return 0;
}

int sd_rtnl_message_route_get_tos(sd_netlink_message *m, uint8_t *ret) {
        struct rtmsg *rtm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_route(m->hdr->nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        rtm = NLMSG_DATA(m->hdr);

        *ret = rtm->rtm_tos;

        return 0;
}

int sd_rtnl_message_route_get_table(sd_netlink_message *m, uint8_t *ret) {
        struct rtmsg *rtm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_route(m->hdr->nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        rtm = NLMSG_DATA(m->hdr);

        *ret = rtm->rtm_table;

        return 0;
}

int sd_rtnl_message_route_get_dst_prefixlen(sd_netlink_message *m, uint8_t *ret) {
        struct rtmsg *rtm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_route(m->hdr->nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        rtm = NLMSG_DATA(m->hdr);

        *ret = rtm->rtm_dst_len;

        return 0;
}

int sd_rtnl_message_route_get_src_prefixlen(sd_netlink_message *m, uint8_t *ret) {
        struct rtmsg *rtm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_route(m->hdr->nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        rtm = NLMSG_DATA(m->hdr);

        *ret = rtm->rtm_src_len;

        return 0;
}

int sd_rtnl_message_new_route(
                sd_netlink *rtnl,
                sd_netlink_message **ret,
                uint16_t nlmsg_type,
                int family,
                uint8_t protocol) {

        struct rtmsg *rtm;
        int r;

        assert_return(rtnl_message_type_is_route(nlmsg_type), -EINVAL);
        assert_return((nlmsg_type == RTM_GETROUTE && family == AF_UNSPEC) ||
                      IN_SET(family, AF_INET, AF_INET6), -EINVAL);
        assert_return(ret, -EINVAL);

        r = message_new(rtnl, ret, nlmsg_type);
        if (r < 0)
                return r;

        if (nlmsg_type == RTM_NEWROUTE)
                (*ret)->hdr->nlmsg_flags |= NLM_F_CREATE | NLM_F_APPEND;

        rtm = NLMSG_DATA((*ret)->hdr);

        rtm->rtm_family = family;
        rtm->rtm_protocol = protocol;

        return 0;
}

int sd_rtnl_message_new_nexthop(sd_netlink *rtnl, sd_netlink_message **ret,
                                uint16_t nlmsg_type, int family,
                                uint8_t protocol) {
        struct nhmsg *nhm;
        int r;

        assert_return(rtnl_message_type_is_nexthop(nlmsg_type), -EINVAL);
        switch (nlmsg_type) {
        case RTM_DELNEXTHOP:
                assert_return(family == AF_UNSPEC, -EINVAL);
                _fallthrough_;
        case RTM_GETNEXTHOP:
                assert_return(protocol == RTPROT_UNSPEC, -EINVAL);
                break;
        case RTM_NEWNEXTHOP:
                assert_return(IN_SET(family, AF_UNSPEC, AF_INET, AF_INET6), -EINVAL);
                break;
        default:
                assert_not_reached();
        }
        assert_return(ret, -EINVAL);

        r = message_new(rtnl, ret, nlmsg_type);
        if (r < 0)
                return r;

        if (nlmsg_type == RTM_NEWNEXTHOP)
                (*ret)->hdr->nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;

        nhm = NLMSG_DATA((*ret)->hdr);

        nhm->nh_family = family;
        nhm->nh_scope = RT_SCOPE_UNIVERSE;
        nhm->nh_protocol = protocol;

        return 0;
}

int sd_rtnl_message_nexthop_set_flags(sd_netlink_message *m, uint32_t flags) {
        struct nhmsg *nhm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(m->hdr->nlmsg_type == RTM_NEWNEXTHOP, -EINVAL);

        nhm = NLMSG_DATA(m->hdr);
        nhm->nh_flags = flags;

        return 0;
}

int sd_rtnl_message_nexthop_get_flags(sd_netlink_message *m, uint32_t *ret) {
        struct nhmsg *nhm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_nexthop(m->hdr->nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        nhm = NLMSG_DATA(m->hdr);
        *ret = nhm->nh_flags;

        return 0;
}

int sd_rtnl_message_nexthop_get_family(sd_netlink_message *m, int *ret) {
        struct nhmsg *nhm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_nexthop(m->hdr->nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        nhm = NLMSG_DATA(m->hdr);
        *ret = nhm->nh_family;

        return 0;
}

int sd_rtnl_message_nexthop_get_protocol(sd_netlink_message *m, uint8_t *ret) {
        struct nhmsg *nhm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_nexthop(m->hdr->nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        nhm = NLMSG_DATA(m->hdr);
        *ret = nhm->nh_protocol;

        return 0;
}

int sd_rtnl_message_neigh_set_flags(sd_netlink_message *m, uint8_t flags) {
        struct ndmsg *ndm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_neigh(m->hdr->nlmsg_type), -EINVAL);

        ndm = NLMSG_DATA(m->hdr);
        ndm->ndm_flags = flags;

        return 0;
}

int sd_rtnl_message_neigh_set_state(sd_netlink_message *m, uint16_t state) {
        struct ndmsg *ndm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_neigh(m->hdr->nlmsg_type), -EINVAL);

        ndm = NLMSG_DATA(m->hdr);
        ndm->ndm_state = state;

        return 0;
}

int sd_rtnl_message_neigh_get_flags(sd_netlink_message *m, uint8_t *ret) {
        struct ndmsg *ndm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_neigh(m->hdr->nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        ndm = NLMSG_DATA(m->hdr);
        *ret = ndm->ndm_flags;

        return 0;
}

int sd_rtnl_message_neigh_get_state(sd_netlink_message *m, uint16_t *ret) {
        struct ndmsg *ndm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_neigh(m->hdr->nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        ndm = NLMSG_DATA(m->hdr);
        *ret = ndm->ndm_state;

        return 0;
}

int sd_rtnl_message_neigh_get_family(sd_netlink_message *m, int *ret) {
        struct ndmsg *ndm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_neigh(m->hdr->nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        ndm = NLMSG_DATA(m->hdr);

        *ret = ndm->ndm_family;

        return 0;
}

int sd_rtnl_message_neigh_get_ifindex(sd_netlink_message *m, int *ret) {
        struct ndmsg *ndm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_neigh(m->hdr->nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        ndm = NLMSG_DATA(m->hdr);

        *ret = ndm->ndm_ifindex;

        return 0;
}

int sd_rtnl_message_new_neigh(
                sd_netlink *rtnl,
                sd_netlink_message **ret,
                uint16_t nlmsg_type,
                int ifindex,
                int family) {

        struct ndmsg *ndm;
        int r;

        assert_return(rtnl_message_type_is_neigh(nlmsg_type), -EINVAL);
        assert_return(IN_SET(family, AF_UNSPEC, AF_INET, AF_INET6, AF_BRIDGE), -EINVAL);
        assert_return(ret, -EINVAL);

        r = message_new(rtnl, ret, nlmsg_type);
        if (r < 0)
                return r;

        if (nlmsg_type == RTM_NEWNEIGH) {
                if (family == AF_BRIDGE)
                        (*ret)->hdr->nlmsg_flags |= NLM_F_CREATE | NLM_F_APPEND;
                else
                        (*ret)->hdr->nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;
        }

        ndm = NLMSG_DATA((*ret)->hdr);

        ndm->ndm_family = family;
        ndm->ndm_ifindex = ifindex;

        return 0;
}

int sd_rtnl_message_link_set_flags(sd_netlink_message *m, uint32_t flags, uint32_t change) {
        struct ifinfomsg *ifi;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_link(m->hdr->nlmsg_type), -EINVAL);
        assert_return(change != 0, -EINVAL);

        ifi = NLMSG_DATA(m->hdr);

        ifi->ifi_flags = flags;
        ifi->ifi_change = change;

        return 0;
}

int sd_rtnl_message_link_set_type(sd_netlink_message *m, uint16_t type) {
        struct ifinfomsg *ifi;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_link(m->hdr->nlmsg_type), -EINVAL);

        ifi = NLMSG_DATA(m->hdr);

        ifi->ifi_type = type;

        return 0;
}

int sd_rtnl_message_link_set_family(sd_netlink_message *m, int family) {
        struct ifinfomsg *ifi;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_link(m->hdr->nlmsg_type), -EINVAL);

        ifi = NLMSG_DATA(m->hdr);

        ifi->ifi_family = family;

        return 0;
}

int sd_rtnl_message_new_link(sd_netlink *rtnl, sd_netlink_message **ret, uint16_t nlmsg_type, int ifindex) {
        struct ifinfomsg *ifi;
        int r;

        assert_return(rtnl_message_type_is_link(nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        r = message_new(rtnl, ret, nlmsg_type);
        if (r < 0)
                return r;

        if (nlmsg_type == RTM_NEWLINK)
                (*ret)->hdr->nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
        else if (nlmsg_type == RTM_NEWLINKPROP)
                (*ret)->hdr->nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL | NLM_F_APPEND;

        ifi = NLMSG_DATA((*ret)->hdr);

        ifi->ifi_family = AF_UNSPEC;
        ifi->ifi_index = ifindex;

        return 0;
}

int sd_rtnl_message_addr_set_prefixlen(sd_netlink_message *m, uint8_t prefixlen) {
        struct ifaddrmsg *ifa;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_addr(m->hdr->nlmsg_type), -EINVAL);

        ifa = NLMSG_DATA(m->hdr);

        if ((ifa->ifa_family == AF_INET && prefixlen > 32) ||
            (ifa->ifa_family == AF_INET6 && prefixlen > 128))
                return -ERANGE;

        ifa->ifa_prefixlen = prefixlen;

        return 0;
}

int sd_rtnl_message_addr_set_flags(sd_netlink_message *m, uint8_t flags) {
        struct ifaddrmsg *ifa;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_addr(m->hdr->nlmsg_type), -EINVAL);

        ifa = NLMSG_DATA(m->hdr);

        ifa->ifa_flags = flags;

        return 0;
}

int sd_rtnl_message_addr_set_scope(sd_netlink_message *m, uint8_t scope) {
        struct ifaddrmsg *ifa;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_addr(m->hdr->nlmsg_type), -EINVAL);

        ifa = NLMSG_DATA(m->hdr);

        ifa->ifa_scope = scope;

        return 0;
}

int sd_rtnl_message_addr_get_family(sd_netlink_message *m, int *ret) {
        struct ifaddrmsg *ifa;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_addr(m->hdr->nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        ifa = NLMSG_DATA(m->hdr);

        *ret = ifa->ifa_family;

        return 0;
}

int sd_rtnl_message_addr_get_prefixlen(sd_netlink_message *m, uint8_t *ret) {
        struct ifaddrmsg *ifa;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_addr(m->hdr->nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        ifa = NLMSG_DATA(m->hdr);

        *ret = ifa->ifa_prefixlen;

        return 0;
}

int sd_rtnl_message_addr_get_scope(sd_netlink_message *m, uint8_t *ret) {
        struct ifaddrmsg *ifa;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_addr(m->hdr->nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        ifa = NLMSG_DATA(m->hdr);

        *ret = ifa->ifa_scope;

        return 0;
}

int sd_rtnl_message_addr_get_flags(sd_netlink_message *m, uint8_t *ret) {
        struct ifaddrmsg *ifa;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_addr(m->hdr->nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        ifa = NLMSG_DATA(m->hdr);

        *ret = ifa->ifa_flags;

        return 0;
}

int sd_rtnl_message_addr_get_ifindex(sd_netlink_message *m, int *ret) {
        struct ifaddrmsg *ifa;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_addr(m->hdr->nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        ifa = NLMSG_DATA(m->hdr);

        *ret = ifa->ifa_index;

        return 0;
}

int sd_rtnl_message_new_addr(
                sd_netlink *rtnl,
                sd_netlink_message **ret,
                uint16_t nlmsg_type,
                int ifindex,
                int family) {

        struct ifaddrmsg *ifa;
        int r;

        assert_return(rtnl_message_type_is_addr(nlmsg_type), -EINVAL);
        assert_return((nlmsg_type == RTM_GETADDR && ifindex == 0) ||
                      ifindex > 0, -EINVAL);
        assert_return((nlmsg_type == RTM_GETADDR && family == AF_UNSPEC) ||
                      IN_SET(family, AF_INET, AF_INET6), -EINVAL);
        assert_return(ret, -EINVAL);

        r = message_new(rtnl, ret, nlmsg_type);
        if (r < 0)
                return r;

        ifa = NLMSG_DATA((*ret)->hdr);

        ifa->ifa_index = ifindex;
        ifa->ifa_family = family;

        return 0;
}

int sd_rtnl_message_new_addr_update(
                sd_netlink *rtnl,
                sd_netlink_message **ret,
                int ifindex,
                int family) {
        int r;

        r = sd_rtnl_message_new_addr(rtnl, ret, RTM_NEWADDR, ifindex, family);
        if (r < 0)
                return r;

        (*ret)->hdr->nlmsg_flags |= NLM_F_REPLACE;

        return 0;
}

int sd_rtnl_message_link_get_ifindex(sd_netlink_message *m, int *ret) {
        struct ifinfomsg *ifi;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_link(m->hdr->nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        ifi = NLMSG_DATA(m->hdr);

        *ret = ifi->ifi_index;

        return 0;
}

int sd_rtnl_message_link_get_flags(sd_netlink_message *m, uint32_t *ret) {
        struct ifinfomsg *ifi;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_link(m->hdr->nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        ifi = NLMSG_DATA(m->hdr);

        *ret = ifi->ifi_flags;

        return 0;
}

int sd_rtnl_message_link_get_type(sd_netlink_message *m, uint16_t *ret) {
        struct ifinfomsg *ifi;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_link(m->hdr->nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        ifi = NLMSG_DATA(m->hdr);

        *ret = ifi->ifi_type;

        return 0;
}

int sd_rtnl_message_get_family(sd_netlink_message *m, int *ret) {
        assert_return(m, -EINVAL);
        assert_return(ret, -EINVAL);

        assert(m->hdr);

        if (rtnl_message_type_is_link(m->hdr->nlmsg_type)) {
                struct ifinfomsg *ifi;

                ifi = NLMSG_DATA(m->hdr);

                *ret = ifi->ifi_family;

                return 0;
        } else if (rtnl_message_type_is_route(m->hdr->nlmsg_type)) {
                struct rtmsg *rtm;

                rtm = NLMSG_DATA(m->hdr);

                *ret = rtm->rtm_family;

                return 0;
        } else if (rtnl_message_type_is_neigh(m->hdr->nlmsg_type)) {
                struct ndmsg *ndm;

                ndm = NLMSG_DATA(m->hdr);

                *ret = ndm->ndm_family;

                return 0;
        } else if (rtnl_message_type_is_addr(m->hdr->nlmsg_type)) {
                struct ifaddrmsg *ifa;

                ifa = NLMSG_DATA(m->hdr);

                *ret = ifa->ifa_family;

                return 0;
        } else if (rtnl_message_type_is_routing_policy_rule(m->hdr->nlmsg_type)) {
                struct rtmsg *rtm;

                rtm = NLMSG_DATA(m->hdr);

                *ret = rtm->rtm_family;

                return 0;
        } else if (rtnl_message_type_is_nexthop(m->hdr->nlmsg_type)) {
                struct nhmsg *nhm;

                nhm = NLMSG_DATA(m->hdr);

                *ret = nhm->nh_family;

                return 0;
        }

        return -EOPNOTSUPP;
}

int sd_rtnl_message_new_addrlabel(
                sd_netlink *rtnl,
                sd_netlink_message **ret,
                uint16_t nlmsg_type,
                int ifindex,
                int family) {

        struct ifaddrlblmsg *addrlabel;
        int r;

        assert_return(rtnl_message_type_is_addrlabel(nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        r = message_new(rtnl, ret, nlmsg_type);
        if (r < 0)
                return r;

        if (nlmsg_type == RTM_NEWADDRLABEL)
                (*ret)->hdr->nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;

        addrlabel = NLMSG_DATA((*ret)->hdr);

        addrlabel->ifal_family = family;
        addrlabel->ifal_index = ifindex;

        return 0;
}

int sd_rtnl_message_addrlabel_set_prefixlen(sd_netlink_message *m, uint8_t prefixlen) {
        struct ifaddrlblmsg *addrlabel;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_addrlabel(m->hdr->nlmsg_type), -EINVAL);

        addrlabel = NLMSG_DATA(m->hdr);

        if (prefixlen > 128)
                return -ERANGE;

        addrlabel->ifal_prefixlen = prefixlen;

        return 0;
}

int sd_rtnl_message_addrlabel_get_prefixlen(sd_netlink_message *m, uint8_t *ret) {
        struct ifaddrlblmsg *addrlabel;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_addrlabel(m->hdr->nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        addrlabel = NLMSG_DATA(m->hdr);

        *ret = addrlabel->ifal_prefixlen;

        return 0;
}

int sd_rtnl_message_new_routing_policy_rule(
                sd_netlink *rtnl,
                sd_netlink_message **ret,
                uint16_t nlmsg_type,
                int family) {

        struct fib_rule_hdr *frh;
        int r;

        assert_return(rtnl_message_type_is_routing_policy_rule(nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        r = message_new(rtnl, ret, nlmsg_type);
        if (r < 0)
                return r;

        if (nlmsg_type == RTM_NEWRULE)
                (*ret)->hdr->nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;

        frh = NLMSG_DATA((*ret)->hdr);
        frh->family = family;

        return 0;
}

int sd_rtnl_message_routing_policy_rule_set_tos(sd_netlink_message *m, uint8_t tos) {
        struct fib_rule_hdr *frh;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_routing_policy_rule(m->hdr->nlmsg_type), -EINVAL);

        frh = NLMSG_DATA(m->hdr);

        frh->tos = tos;

        return 0;
}

int sd_rtnl_message_routing_policy_rule_get_tos(sd_netlink_message *m, uint8_t *ret) {
        struct fib_rule_hdr *frh;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_routing_policy_rule(m->hdr->nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        frh = NLMSG_DATA(m->hdr);

        *ret = frh->tos;

        return 0;
}

int sd_rtnl_message_routing_policy_rule_set_table(sd_netlink_message *m, uint8_t table) {
        struct fib_rule_hdr *frh;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_routing_policy_rule(m->hdr->nlmsg_type), -EINVAL);

        frh = NLMSG_DATA(m->hdr);

        frh->table = table;

        return 0;
}

int sd_rtnl_message_routing_policy_rule_get_table(sd_netlink_message *m, uint8_t *ret) {
        struct fib_rule_hdr *frh;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_routing_policy_rule(m->hdr->nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        frh = NLMSG_DATA(m->hdr);

        *ret = frh->table;

        return 0;
}

int sd_rtnl_message_routing_policy_rule_set_flags(sd_netlink_message *m, uint32_t flags) {
        struct fib_rule_hdr *frh;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_routing_policy_rule(m->hdr->nlmsg_type), -EINVAL);

        frh = NLMSG_DATA(m->hdr);
        frh->flags = flags;

        return 0;
}

int sd_rtnl_message_routing_policy_rule_get_flags(sd_netlink_message *m, uint32_t *ret) {
        struct fib_rule_hdr *frh;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_routing_policy_rule(m->hdr->nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        frh = NLMSG_DATA(m->hdr);
        *ret = frh->flags;

        return 0;
}

int sd_rtnl_message_routing_policy_rule_set_fib_type(sd_netlink_message *m, uint8_t type) {
        struct fib_rule_hdr *frh;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_routing_policy_rule(m->hdr->nlmsg_type), -EINVAL);

        frh = NLMSG_DATA(m->hdr);

        frh->action = type;

        return 0;
}

int sd_rtnl_message_routing_policy_rule_get_fib_type(sd_netlink_message *m, uint8_t *ret) {
        struct fib_rule_hdr *frh;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_routing_policy_rule(m->hdr->nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        frh = NLMSG_DATA(m->hdr);

        *ret = frh->action;

        return 0;
}

int sd_rtnl_message_routing_policy_rule_set_fib_dst_prefixlen(sd_netlink_message *m, uint8_t prefixlen) {
        struct fib_rule_hdr *frh;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_routing_policy_rule(m->hdr->nlmsg_type), -EINVAL);

        frh = NLMSG_DATA(m->hdr);

        frh->dst_len = prefixlen;

        return 0;
}

int sd_rtnl_message_routing_policy_rule_get_fib_dst_prefixlen(sd_netlink_message *m, uint8_t *ret) {
        struct fib_rule_hdr *frh;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_routing_policy_rule(m->hdr->nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        frh = NLMSG_DATA(m->hdr);

        *ret = frh->dst_len;

        return 0;
}

int sd_rtnl_message_routing_policy_rule_set_fib_src_prefixlen(sd_netlink_message *m, uint8_t prefixlen) {
        struct fib_rule_hdr *frh;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_routing_policy_rule(m->hdr->nlmsg_type), -EINVAL);

        frh = NLMSG_DATA(m->hdr);

        frh->src_len = prefixlen;

        return 0;
}

int sd_rtnl_message_routing_policy_rule_get_fib_src_prefixlen(sd_netlink_message *m, uint8_t *ret) {
        struct fib_rule_hdr *frh;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_routing_policy_rule(m->hdr->nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        frh = NLMSG_DATA(m->hdr);

        *ret = frh->src_len;

        return 0;
}

int sd_rtnl_message_new_traffic_control(
                sd_netlink *rtnl,
                sd_netlink_message **ret,
                uint16_t nlmsg_type,
                int ifindex,
                uint32_t handle,
                uint32_t parent) {

        struct tcmsg *tcm;
        int r;

        assert_return(rtnl_message_type_is_traffic_control(nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        r = message_new(rtnl, ret, nlmsg_type);
        if (r < 0)
                return r;

        if (IN_SET(nlmsg_type, RTM_NEWQDISC, RTM_NEWTCLASS))
                (*ret)->hdr->nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;

        tcm = NLMSG_DATA((*ret)->hdr);
        tcm->tcm_ifindex = ifindex;
        tcm->tcm_handle = handle;
        tcm->tcm_parent = parent;

        return 0;
}

int sd_rtnl_message_traffic_control_get_ifindex(sd_netlink_message *m, int *ret) {
        struct tcmsg *tcm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_traffic_control(m->hdr->nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        tcm = NLMSG_DATA(m->hdr);
        *ret = tcm->tcm_ifindex;

        return 0;
}

int sd_rtnl_message_traffic_control_get_handle(sd_netlink_message *m, uint32_t *ret) {
        struct tcmsg *tcm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_traffic_control(m->hdr->nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        tcm = NLMSG_DATA(m->hdr);
        *ret = tcm->tcm_handle;

        return 0;
}

int sd_rtnl_message_traffic_control_get_parent(sd_netlink_message *m, uint32_t *ret) {
        struct tcmsg *tcm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_traffic_control(m->hdr->nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        tcm = NLMSG_DATA(m->hdr);
        *ret = tcm->tcm_parent;

        return 0;
}

int sd_rtnl_message_new_mdb(
                sd_netlink *rtnl,
                sd_netlink_message **ret,
                uint16_t nlmsg_type,
                int ifindex) {

        struct br_port_msg *bpm;
        int r;

        assert_return(rtnl_message_type_is_mdb(nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        r = message_new(rtnl, ret, nlmsg_type);
        if (r < 0)
                return r;

        if (nlmsg_type == RTM_NEWMDB)
                (*ret)->hdr->nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;

        bpm = NLMSG_DATA((*ret)->hdr);
        bpm->family = AF_BRIDGE;
        bpm->ifindex = ifindex;

        return 0;
}

int sd_rtnl_message_new_nsid(
                sd_netlink *rtnl,
                sd_netlink_message **ret,
                uint16_t nlmsg_type) {

        struct rtgenmsg *rt;
        int r;

        assert_return(rtnl_message_type_is_nsid(nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        r = message_new(rtnl, ret, nlmsg_type);
        if (r < 0)
                return r;

        rt = NLMSG_DATA((*ret)->hdr);
        rt->rtgen_family = AF_UNSPEC;

        return 0;
}
