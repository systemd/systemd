/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Tom Gundersen <teg@jklm.no>

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <netinet/in.h>
#include <stdbool.h>
#include <unistd.h>

#include "sd-netlink.h"

#include "formats-util.h"
#include "missing.h"
#include "netlink-internal.h"
#include "netlink-types.h"
#include "netlink-util.h"
#include "refcnt.h"
#include "socket-util.h"
#include "util.h"

int sd_rtnl_message_route_set_dst_prefixlen(sd_netlink_message *m, unsigned char prefixlen) {
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

int sd_rtnl_message_route_set_src_prefixlen(sd_netlink_message *m, unsigned char prefixlen) {
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

int sd_rtnl_message_route_set_scope(sd_netlink_message *m, unsigned char scope) {
        struct rtmsg *rtm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_route(m->hdr->nlmsg_type), -EINVAL);

        rtm = NLMSG_DATA(m->hdr);

        rtm->rtm_scope = scope;

        return 0;
}

int sd_rtnl_message_route_set_flags(sd_netlink_message *m, unsigned flags) {
        struct rtmsg *rtm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_route(m->hdr->nlmsg_type), -EINVAL);

        rtm = NLMSG_DATA(m->hdr);

        rtm->rtm_flags = flags;

        return 0;
}

int sd_rtnl_message_route_get_flags(sd_netlink_message *m, unsigned *flags) {
        struct rtmsg *rtm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_route(m->hdr->nlmsg_type), -EINVAL);
        assert_return(flags, -EINVAL);

        rtm = NLMSG_DATA(m->hdr);

        *flags = rtm->rtm_flags;

        return 0;
}

int sd_rtnl_message_route_get_family(sd_netlink_message *m, int *family) {
        struct rtmsg *rtm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_route(m->hdr->nlmsg_type), -EINVAL);
        assert_return(family, -EINVAL);

        rtm = NLMSG_DATA(m->hdr);

        *family = rtm->rtm_family;

        return 0;
}

int sd_rtnl_message_route_get_protocol(sd_netlink_message *m, unsigned char *protocol) {
        struct rtmsg *rtm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_route(m->hdr->nlmsg_type), -EINVAL);
        assert_return(protocol, -EINVAL);

        rtm = NLMSG_DATA(m->hdr);

        *protocol = rtm->rtm_protocol;

        return 0;
}

int sd_rtnl_message_route_get_scope(sd_netlink_message *m, unsigned char *scope) {
        struct rtmsg *rtm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_route(m->hdr->nlmsg_type), -EINVAL);
        assert_return(scope, -EINVAL);

        rtm = NLMSG_DATA(m->hdr);

        *scope = rtm->rtm_scope;

        return 0;
}

int sd_rtnl_message_route_get_tos(sd_netlink_message *m, unsigned char *tos) {
        struct rtmsg *rtm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_route(m->hdr->nlmsg_type), -EINVAL);
        assert_return(tos, -EINVAL);

        rtm = NLMSG_DATA(m->hdr);

        *tos = rtm->rtm_tos;

        return 0;
}

int sd_rtnl_message_route_get_table(sd_netlink_message *m, unsigned char *table) {
        struct rtmsg *rtm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_route(m->hdr->nlmsg_type), -EINVAL);
        assert_return(table, -EINVAL);

        rtm = NLMSG_DATA(m->hdr);

        *table = rtm->rtm_table;

        return 0;
}

int sd_rtnl_message_route_get_dst_prefixlen(sd_netlink_message *m, unsigned char *dst_len) {
        struct rtmsg *rtm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_route(m->hdr->nlmsg_type), -EINVAL);
        assert_return(dst_len, -EINVAL);

        rtm = NLMSG_DATA(m->hdr);

        *dst_len = rtm->rtm_dst_len;

        return 0;
}

int sd_rtnl_message_route_get_src_prefixlen(sd_netlink_message *m, unsigned char *src_len) {
        struct rtmsg *rtm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_route(m->hdr->nlmsg_type), -EINVAL);
        assert_return(src_len, -EINVAL);

        rtm = NLMSG_DATA(m->hdr);

        *src_len = rtm->rtm_src_len;

        return 0;
}

int sd_rtnl_message_new_route(sd_netlink *rtnl, sd_netlink_message **ret,
                              uint16_t nlmsg_type, int rtm_family,
                              unsigned char rtm_protocol) {
        struct rtmsg *rtm;
        int r;

        assert_return(rtnl_message_type_is_route(nlmsg_type), -EINVAL);
        assert_return((nlmsg_type == RTM_GETROUTE && rtm_family == AF_UNSPEC) ||
                      rtm_family == AF_INET || rtm_family == AF_INET6, -EINVAL);
        assert_return(ret, -EINVAL);

        r = message_new(rtnl, ret, nlmsg_type);
        if (r < 0)
                return r;

        if (nlmsg_type == RTM_NEWROUTE)
                (*ret)->hdr->nlmsg_flags |= NLM_F_CREATE | NLM_F_APPEND;

        rtm = NLMSG_DATA((*ret)->hdr);

        rtm->rtm_family = rtm_family;
        rtm->rtm_scope = RT_SCOPE_UNIVERSE;
        rtm->rtm_type = RTN_UNICAST;
        rtm->rtm_table = RT_TABLE_MAIN;
        rtm->rtm_protocol = rtm_protocol;

        return 0;
}

int sd_rtnl_message_neigh_set_flags(sd_netlink_message *m, uint8_t flags) {
        struct ndmsg *ndm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_neigh(m->hdr->nlmsg_type), -EINVAL);

        ndm = NLMSG_DATA(m->hdr);
        ndm->ndm_flags |= flags;

        return 0;
}

int sd_rtnl_message_neigh_set_state(sd_netlink_message *m, uint16_t state) {
        struct ndmsg *ndm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_neigh(m->hdr->nlmsg_type), -EINVAL);

        ndm = NLMSG_DATA(m->hdr);
        ndm->ndm_state |= state;

        return 0;
}

int sd_rtnl_message_neigh_get_flags(sd_netlink_message *m, uint8_t *flags) {
        struct ndmsg *ndm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_neigh(m->hdr->nlmsg_type), -EINVAL);

        ndm = NLMSG_DATA(m->hdr);
        *flags = ndm->ndm_flags;

        return 0;
}

int sd_rtnl_message_neigh_get_state(sd_netlink_message *m, uint16_t *state) {
        struct ndmsg *ndm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_neigh(m->hdr->nlmsg_type), -EINVAL);

        ndm = NLMSG_DATA(m->hdr);
        *state = ndm->ndm_state;

        return 0;
}

int sd_rtnl_message_neigh_get_family(sd_netlink_message *m, int *family) {
        struct ndmsg *ndm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_neigh(m->hdr->nlmsg_type), -EINVAL);
        assert_return(family, -EINVAL);

        ndm = NLMSG_DATA(m->hdr);

        *family = ndm->ndm_family;

        return 0;
}

int sd_rtnl_message_neigh_get_ifindex(sd_netlink_message *m, int *index) {
        struct ndmsg *ndm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_neigh(m->hdr->nlmsg_type), -EINVAL);
        assert_return(index, -EINVAL);

        ndm = NLMSG_DATA(m->hdr);

        *index = ndm->ndm_ifindex;

        return 0;
}

int sd_rtnl_message_new_neigh(sd_netlink *rtnl, sd_netlink_message **ret, uint16_t nlmsg_type, int index, int ndm_family) {
        struct ndmsg *ndm;
        int r;

        assert_return(rtnl_message_type_is_neigh(nlmsg_type), -EINVAL);
        assert_return(ndm_family == AF_INET  ||
                      ndm_family == AF_INET6 ||
                      ndm_family == PF_BRIDGE, -EINVAL);
        assert_return(ret, -EINVAL);

        r = message_new(rtnl, ret, nlmsg_type);
        if (r < 0)
                return r;

        if (nlmsg_type == RTM_NEWNEIGH)
                (*ret)->hdr->nlmsg_flags |= NLM_F_CREATE | NLM_F_APPEND;

        ndm = NLMSG_DATA((*ret)->hdr);

        ndm->ndm_family = ndm_family;
        ndm->ndm_ifindex = index;

        return 0;
}

int sd_rtnl_message_link_set_flags(sd_netlink_message *m, unsigned flags, unsigned change) {
        struct ifinfomsg *ifi;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_link(m->hdr->nlmsg_type), -EINVAL);
        assert_return(change, -EINVAL);

        ifi = NLMSG_DATA(m->hdr);

        ifi->ifi_flags = flags;
        ifi->ifi_change = change;

        return 0;
}

int sd_rtnl_message_link_set_type(sd_netlink_message *m, unsigned type) {
        struct ifinfomsg *ifi;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_link(m->hdr->nlmsg_type), -EINVAL);

        ifi = NLMSG_DATA(m->hdr);

        ifi->ifi_type = type;

        return 0;
}

int sd_rtnl_message_link_set_family(sd_netlink_message *m, unsigned family) {
        struct ifinfomsg *ifi;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_link(m->hdr->nlmsg_type), -EINVAL);

        ifi = NLMSG_DATA(m->hdr);

        ifi->ifi_family = family;

        return 0;
}

int sd_rtnl_message_new_link(sd_netlink *rtnl, sd_netlink_message **ret,
                             uint16_t nlmsg_type, int index) {
        struct ifinfomsg *ifi;
        int r;

        assert_return(rtnl_message_type_is_link(nlmsg_type), -EINVAL);
        assert_return(nlmsg_type != RTM_DELLINK || index > 0, -EINVAL);
        assert_return(ret, -EINVAL);

        r = message_new(rtnl, ret, nlmsg_type);
        if (r < 0)
                return r;

        if (nlmsg_type == RTM_NEWLINK)
                (*ret)->hdr->nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;

        ifi = NLMSG_DATA((*ret)->hdr);

        ifi->ifi_family = AF_UNSPEC;
        ifi->ifi_index = index;

        return 0;
}

int sd_rtnl_message_addr_set_prefixlen(sd_netlink_message *m, unsigned char prefixlen) {
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

int sd_rtnl_message_addr_set_flags(sd_netlink_message *m, unsigned char flags) {
        struct ifaddrmsg *ifa;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_addr(m->hdr->nlmsg_type), -EINVAL);

        ifa = NLMSG_DATA(m->hdr);

        ifa->ifa_flags = flags;

        return 0;
}

int sd_rtnl_message_addr_set_scope(sd_netlink_message *m, unsigned char scope) {
        struct ifaddrmsg *ifa;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_addr(m->hdr->nlmsg_type), -EINVAL);

        ifa = NLMSG_DATA(m->hdr);

        ifa->ifa_scope = scope;

        return 0;
}

int sd_rtnl_message_addr_get_family(sd_netlink_message *m, int *family) {
        struct ifaddrmsg *ifa;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_addr(m->hdr->nlmsg_type), -EINVAL);
        assert_return(family, -EINVAL);

        ifa = NLMSG_DATA(m->hdr);

        *family = ifa->ifa_family;

        return 0;
}

int sd_rtnl_message_addr_get_prefixlen(sd_netlink_message *m, unsigned char *prefixlen) {
        struct ifaddrmsg *ifa;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_addr(m->hdr->nlmsg_type), -EINVAL);
        assert_return(prefixlen, -EINVAL);

        ifa = NLMSG_DATA(m->hdr);

        *prefixlen = ifa->ifa_prefixlen;

        return 0;
}

int sd_rtnl_message_addr_get_scope(sd_netlink_message *m, unsigned char *scope) {
        struct ifaddrmsg *ifa;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_addr(m->hdr->nlmsg_type), -EINVAL);
        assert_return(scope, -EINVAL);

        ifa = NLMSG_DATA(m->hdr);

        *scope = ifa->ifa_scope;

        return 0;
}

int sd_rtnl_message_addr_get_flags(sd_netlink_message *m, unsigned char *flags) {
        struct ifaddrmsg *ifa;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_addr(m->hdr->nlmsg_type), -EINVAL);
        assert_return(flags, -EINVAL);

        ifa = NLMSG_DATA(m->hdr);

        *flags = ifa->ifa_flags;

        return 0;
}

int sd_rtnl_message_addr_get_ifindex(sd_netlink_message *m, int *ifindex) {
        struct ifaddrmsg *ifa;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_addr(m->hdr->nlmsg_type), -EINVAL);
        assert_return(ifindex, -EINVAL);

        ifa = NLMSG_DATA(m->hdr);

        *ifindex = ifa->ifa_index;

        return 0;
}

int sd_rtnl_message_new_addr(sd_netlink *rtnl, sd_netlink_message **ret,
                             uint16_t nlmsg_type, int index,
                             int family) {
        struct ifaddrmsg *ifa;
        int r;

        assert_return(rtnl_message_type_is_addr(nlmsg_type), -EINVAL);
        assert_return((nlmsg_type == RTM_GETADDR && index == 0) ||
                      index > 0, -EINVAL);
        assert_return((nlmsg_type == RTM_GETADDR && family == AF_UNSPEC) ||
                      family == AF_INET || family == AF_INET6, -EINVAL);
        assert_return(ret, -EINVAL);

        r = message_new(rtnl, ret, nlmsg_type);
        if (r < 0)
                return r;

        if (nlmsg_type == RTM_GETADDR)
                (*ret)->hdr->nlmsg_flags |= NLM_F_DUMP;

        ifa = NLMSG_DATA((*ret)->hdr);

        ifa->ifa_index = index;
        ifa->ifa_family = family;
        if (family == AF_INET)
                ifa->ifa_prefixlen = 32;
        else if (family == AF_INET6)
                ifa->ifa_prefixlen = 128;

        return 0;
}

int sd_rtnl_message_new_addr_update(sd_netlink *rtnl, sd_netlink_message **ret,
                             int index, int family) {
        int r;

        r = sd_rtnl_message_new_addr(rtnl, ret, RTM_NEWADDR, index, family);
        if (r < 0)
                return r;

        (*ret)->hdr->nlmsg_flags |= NLM_F_REPLACE;

        return 0;
}

int sd_rtnl_message_link_get_ifindex(sd_netlink_message *m, int *ifindex) {
        struct ifinfomsg *ifi;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_link(m->hdr->nlmsg_type), -EINVAL);
        assert_return(ifindex, -EINVAL);

        ifi = NLMSG_DATA(m->hdr);

        *ifindex = ifi->ifi_index;

        return 0;
}

int sd_rtnl_message_link_get_flags(sd_netlink_message *m, unsigned *flags) {
        struct ifinfomsg *ifi;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_link(m->hdr->nlmsg_type), -EINVAL);
        assert_return(flags, -EINVAL);

        ifi = NLMSG_DATA(m->hdr);

        *flags = ifi->ifi_flags;

        return 0;
}

int sd_rtnl_message_link_get_type(sd_netlink_message *m, unsigned *type) {
        struct ifinfomsg *ifi;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_link(m->hdr->nlmsg_type), -EINVAL);
        assert_return(type, -EINVAL);

        ifi = NLMSG_DATA(m->hdr);

        *type = ifi->ifi_type;

        return 0;
}

int sd_rtnl_message_get_family(sd_netlink_message *m, int *family) {
        assert_return(m, -EINVAL);
        assert_return(family, -EINVAL);

        assert(m->hdr);

        if (rtnl_message_type_is_link(m->hdr->nlmsg_type)) {
                struct ifinfomsg *ifi;

                ifi = NLMSG_DATA(m->hdr);

                *family = ifi->ifi_family;

                return 0;
        } else if (rtnl_message_type_is_route(m->hdr->nlmsg_type)) {
                struct rtmsg *rtm;

                rtm = NLMSG_DATA(m->hdr);

                *family = rtm->rtm_family;

                return 0;
        } else if (rtnl_message_type_is_neigh(m->hdr->nlmsg_type)) {
                struct ndmsg *ndm;

                ndm = NLMSG_DATA(m->hdr);

                *family = ndm->ndm_family;

                return 0;
        } else if (rtnl_message_type_is_addr(m->hdr->nlmsg_type)) {
                struct ifaddrmsg *ifa;

                ifa = NLMSG_DATA(m->hdr);

                *family = ifa->ifa_family;

                return 0;
        }

        return -EOPNOTSUPP;
}
