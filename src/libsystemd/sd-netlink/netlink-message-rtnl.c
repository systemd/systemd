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

#define DEFINE_RTNL_MESSAGE_SETTER(class, header_type, element, name, value_type) \
        int sd_rtnl_message_##class##_set_##name(sd_netlink_message *m, value_type value) { \
                assert_return(m, -EINVAL);                              \
                assert_return(m->hdr, -EINVAL);                         \
                assert_return(rtnl_message_type_is_##class(m->hdr->nlmsg_type), -EINVAL); \
                                                                        \
                header_type *hdr = NLMSG_DATA(m->hdr);                  \
                hdr->element = value;                                   \
                return 0;                                               \
        }

#define DEFINE_RTNL_MESSAGE_PREFIXLEN_SETTER(class, header_type, family_element, element, name, value_type) \
        int sd_rtnl_message_##class##_set_##name(sd_netlink_message *m, value_type value) { \
                assert_return(m, -EINVAL);                              \
                assert_return(m->hdr, -EINVAL);                         \
                assert_return(rtnl_message_type_is_##class(m->hdr->nlmsg_type), -EINVAL); \
                                                                        \
                header_type *hdr = NLMSG_DATA(m->hdr);                  \
                                                                        \
                if (value > FAMILY_ADDRESS_SIZE_SAFE(hdr->family_element) * 8) \
                        return -ERANGE;                                 \
                                                                        \
                hdr->element = value;                                   \
                return 0;                                               \
        }

#define DEFINE_RTNL_MESSAGE_ADDR_SETTER(element, name, value_type)      \
        DEFINE_RTNL_MESSAGE_SETTER(addr, struct ifaddrmsg, element, name, value_type)
#define DEFINE_RTNL_MESSAGE_LINK_SETTER(element, name, value_type)      \
        DEFINE_RTNL_MESSAGE_SETTER(link, struct ifinfomsg, element, name, value_type)
#define DEFINE_RTNL_MESSAGE_ROUTE_SETTER(element, name, value_type)     \
        DEFINE_RTNL_MESSAGE_SETTER(route, struct rtmsg, element, name, value_type)
#define DEFINE_RTNL_MESSAGE_NEXTHOP_SETTER(element, name, value_type)   \
        DEFINE_RTNL_MESSAGE_SETTER(nexthop, struct nhmsg, element, name, value_type)
#define DEFINE_RTNL_MESSAGE_NEIGH_SETTER(element, name, value_type)     \
        DEFINE_RTNL_MESSAGE_SETTER(neigh, struct ndmsg, element, name, value_type)
#define DEFINE_RTNL_MESSAGE_ADDRLABEL_SETTER(element, name, value_type) \
        DEFINE_RTNL_MESSAGE_SETTER(addrlabel, struct ifaddrlblmsg, element, name, value_type)
#define DEFINE_RTNL_MESSAGE_ROUTING_POLICY_RULE_SETTER(element, name, value_type) \
        DEFINE_RTNL_MESSAGE_SETTER(routing_policy_rule, struct fib_rule_hdr, element, name, value_type)
#define DEFINE_RTNL_MESSAGE_TRAFFIC_CONTROL_SETTER(element, name, value_type) \
        DEFINE_RTNL_MESSAGE_SETTER(traffic_control, struct tcmsg, element, name, value_type)

#define DEFINE_RTNL_MESSAGE_GETTER(class, header_type, element, name, value_type) \
        int sd_rtnl_message_##class##_get_##name(sd_netlink_message *m, value_type *ret) { \
                assert_return(m, -EINVAL);                              \
                assert_return(m->hdr, -EINVAL);                         \
                assert_return(rtnl_message_type_is_##class(m->hdr->nlmsg_type), -EINVAL); \
                assert_return(ret, -EINVAL);                            \
                                                                        \
                header_type *hdr = NLMSG_DATA(m->hdr);                  \
                *ret = hdr->element;                                    \
                return 0;                                               \
        }

#define DEFINE_RTNL_MESSAGE_ADDR_GETTER(element, name, value_type)      \
        DEFINE_RTNL_MESSAGE_GETTER(addr, struct ifaddrmsg, element, name, value_type)
#define DEFINE_RTNL_MESSAGE_LINK_GETTER(element, name, value_type)      \
        DEFINE_RTNL_MESSAGE_GETTER(link, struct ifinfomsg, element, name, value_type)
#define DEFINE_RTNL_MESSAGE_ROUTE_GETTER(element, name, value_type)     \
        DEFINE_RTNL_MESSAGE_GETTER(route, struct rtmsg, element, name, value_type)
#define DEFINE_RTNL_MESSAGE_NEXTHOP_GETTER(element, name, value_type)   \
        DEFINE_RTNL_MESSAGE_GETTER(nexthop, struct nhmsg, element, name, value_type)
#define DEFINE_RTNL_MESSAGE_NEIGH_GETTER(element, name, value_type)     \
        DEFINE_RTNL_MESSAGE_GETTER(neigh, struct ndmsg, element, name, value_type)
#define DEFINE_RTNL_MESSAGE_ADDRLABEL_GETTER(element, name, value_type) \
        DEFINE_RTNL_MESSAGE_GETTER(addrlabel, struct ifaddrlblmsg, element, name, value_type)
#define DEFINE_RTNL_MESSAGE_ROUTING_POLICY_RULE_GETTER(element, name, value_type) \
        DEFINE_RTNL_MESSAGE_GETTER(routing_policy_rule, struct fib_rule_hdr, element, name, value_type)
#define DEFINE_RTNL_MESSAGE_TRAFFIC_CONTROL_GETTER(element, name, value_type) \
        DEFINE_RTNL_MESSAGE_GETTER(traffic_control, struct tcmsg, element, name, value_type)

DEFINE_RTNL_MESSAGE_ADDR_GETTER(ifa_index, ifindex, int);
DEFINE_RTNL_MESSAGE_ADDR_GETTER(ifa_family, family, int);
DEFINE_RTNL_MESSAGE_PREFIXLEN_SETTER(addr, struct ifaddrmsg, ifa_family, ifa_prefixlen, prefixlen, uint8_t);
DEFINE_RTNL_MESSAGE_ADDR_GETTER(ifa_prefixlen, prefixlen, uint8_t);
DEFINE_RTNL_MESSAGE_ADDR_SETTER(ifa_flags, flags, uint8_t);
DEFINE_RTNL_MESSAGE_ADDR_GETTER(ifa_flags, flags, uint8_t);
DEFINE_RTNL_MESSAGE_ADDR_SETTER(ifa_scope, scope, uint8_t);
DEFINE_RTNL_MESSAGE_ADDR_GETTER(ifa_scope, scope, uint8_t);

DEFINE_RTNL_MESSAGE_LINK_GETTER(ifi_index, ifindex, int);
DEFINE_RTNL_MESSAGE_LINK_SETTER(ifi_family, family, int);
DEFINE_RTNL_MESSAGE_LINK_GETTER(ifi_family, family, int);
DEFINE_RTNL_MESSAGE_LINK_SETTER(ifi_type, type, uint16_t);
DEFINE_RTNL_MESSAGE_LINK_GETTER(ifi_type, type, uint16_t);
DEFINE_RTNL_MESSAGE_LINK_GETTER(ifi_flags, flags, uint32_t);

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

DEFINE_RTNL_MESSAGE_ROUTE_GETTER(rtm_family, family, int);
DEFINE_RTNL_MESSAGE_PREFIXLEN_SETTER(route, struct rtmsg, rtm_family, rtm_dst_len, dst_prefixlen, uint8_t);
DEFINE_RTNL_MESSAGE_ROUTE_GETTER(rtm_dst_len, dst_prefixlen, uint8_t);
DEFINE_RTNL_MESSAGE_PREFIXLEN_SETTER(route, struct rtmsg, rtm_family, rtm_src_len, src_prefixlen, uint8_t);
DEFINE_RTNL_MESSAGE_ROUTE_GETTER(rtm_src_len, src_prefixlen, uint8_t);
DEFINE_RTNL_MESSAGE_ROUTE_SETTER(rtm_tos, tos, uint8_t);
DEFINE_RTNL_MESSAGE_ROUTE_GETTER(rtm_tos, tos, uint8_t);
DEFINE_RTNL_MESSAGE_ROUTE_SETTER(rtm_table, table, uint8_t);
DEFINE_RTNL_MESSAGE_ROUTE_GETTER(rtm_table, table, uint8_t);
DEFINE_RTNL_MESSAGE_ROUTE_GETTER(rtm_protocol, protocol, uint8_t);
DEFINE_RTNL_MESSAGE_ROUTE_SETTER(rtm_scope, scope, uint8_t);
DEFINE_RTNL_MESSAGE_ROUTE_GETTER(rtm_scope, scope, uint8_t);
DEFINE_RTNL_MESSAGE_ROUTE_SETTER(rtm_type, type, uint8_t);
DEFINE_RTNL_MESSAGE_ROUTE_GETTER(rtm_type, type, uint8_t);
DEFINE_RTNL_MESSAGE_ROUTE_SETTER(rtm_flags, flags, uint32_t);
DEFINE_RTNL_MESSAGE_ROUTE_GETTER(rtm_flags, flags, uint32_t);

DEFINE_RTNL_MESSAGE_NEXTHOP_GETTER(nh_family, family, int);
DEFINE_RTNL_MESSAGE_NEXTHOP_SETTER(nh_flags, flags, uint32_t);
DEFINE_RTNL_MESSAGE_NEXTHOP_GETTER(nh_flags, flags, uint32_t);
DEFINE_RTNL_MESSAGE_NEXTHOP_GETTER(nh_protocol, protocol, uint8_t);

DEFINE_RTNL_MESSAGE_NEIGH_GETTER(ndm_ifindex, ifindex, int);
DEFINE_RTNL_MESSAGE_NEIGH_GETTER(ndm_family, family, int);
DEFINE_RTNL_MESSAGE_NEIGH_SETTER(ndm_state, state, uint16_t);
DEFINE_RTNL_MESSAGE_NEIGH_GETTER(ndm_state, state, uint16_t);
DEFINE_RTNL_MESSAGE_NEIGH_SETTER(ndm_flags, flags, uint8_t);
DEFINE_RTNL_MESSAGE_NEIGH_GETTER(ndm_flags, flags, uint8_t);

DEFINE_RTNL_MESSAGE_ADDRLABEL_GETTER(ifal_prefixlen, prefixlen, uint8_t);

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

DEFINE_RTNL_MESSAGE_ROUTING_POLICY_RULE_GETTER(family, family, int);
DEFINE_RTNL_MESSAGE_PREFIXLEN_SETTER(routing_policy_rule, struct fib_rule_hdr, family, dst_len, dst_prefixlen, uint8_t);
DEFINE_RTNL_MESSAGE_ROUTING_POLICY_RULE_GETTER(dst_len, dst_prefixlen, uint8_t);
DEFINE_RTNL_MESSAGE_PREFIXLEN_SETTER(routing_policy_rule, struct fib_rule_hdr, family, src_len, src_prefixlen, uint8_t);
DEFINE_RTNL_MESSAGE_ROUTING_POLICY_RULE_GETTER(src_len, src_prefixlen, uint8_t);
DEFINE_RTNL_MESSAGE_ROUTING_POLICY_RULE_SETTER(tos, tos, uint8_t);
DEFINE_RTNL_MESSAGE_ROUTING_POLICY_RULE_GETTER(tos, tos, uint8_t);
DEFINE_RTNL_MESSAGE_ROUTING_POLICY_RULE_SETTER(table, table, uint8_t);
DEFINE_RTNL_MESSAGE_ROUTING_POLICY_RULE_GETTER(table, table, uint8_t);
DEFINE_RTNL_MESSAGE_ROUTING_POLICY_RULE_SETTER(action, action, uint8_t);
DEFINE_RTNL_MESSAGE_ROUTING_POLICY_RULE_GETTER(action, action, uint8_t);
DEFINE_RTNL_MESSAGE_ROUTING_POLICY_RULE_SETTER(flags, flags, uint32_t);
DEFINE_RTNL_MESSAGE_ROUTING_POLICY_RULE_GETTER(flags, flags, uint32_t);

DEFINE_RTNL_MESSAGE_TRAFFIC_CONTROL_GETTER(tcm_ifindex, ifindex, int);
DEFINE_RTNL_MESSAGE_TRAFFIC_CONTROL_GETTER(tcm_handle, handle, uint32_t);
DEFINE_RTNL_MESSAGE_TRAFFIC_CONTROL_GETTER(tcm_parent, parent, uint32_t);

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

int sd_rtnl_message_new_link(sd_netlink *rtnl, sd_netlink_message **ret, uint16_t nlmsg_type, int ifindex) {
        struct ifinfomsg *ifi;
        int r;

        assert_return(rtnl_message_type_is_link(nlmsg_type), -EINVAL);
        assert_return(ret, -EINVAL);

        r = message_new(rtnl, ret, nlmsg_type);
        if (r < 0)
                return r;

        if (nlmsg_type == RTM_NEWLINK && ifindex == 0)
                (*ret)->hdr->nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
        else if (nlmsg_type == RTM_NEWLINKPROP)
                (*ret)->hdr->nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL | NLM_F_APPEND;

        ifi = NLMSG_DATA((*ret)->hdr);

        ifi->ifi_family = AF_UNSPEC;
        ifi->ifi_index = ifindex;

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

int sd_rtnl_message_get_family(sd_netlink_message *m, int *ret) {
        assert_return(m, -EINVAL);
        assert_return(ret, -EINVAL);

        assert(m->hdr);

        if (rtnl_message_type_is_link(m->hdr->nlmsg_type))
                return sd_rtnl_message_link_get_family(m, ret);

        if (rtnl_message_type_is_route(m->hdr->nlmsg_type))
                return sd_rtnl_message_route_get_family(m, ret);

        if (rtnl_message_type_is_neigh(m->hdr->nlmsg_type))
                return sd_rtnl_message_neigh_get_family(m, ret);

        if (rtnl_message_type_is_addr(m->hdr->nlmsg_type))
                return sd_rtnl_message_addr_get_family(m, ret);

        if (rtnl_message_type_is_routing_policy_rule(m->hdr->nlmsg_type))
                return sd_rtnl_message_routing_policy_rule_get_family(m, ret);

        if (rtnl_message_type_is_nexthop(m->hdr->nlmsg_type))
                return sd_rtnl_message_nexthop_get_family(m, ret);

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
