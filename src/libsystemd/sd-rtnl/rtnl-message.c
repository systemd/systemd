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
#include <netinet/ether.h>
#include <stdbool.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/veth.h>
#include <linux/if.h>
#include <linux/ip.h>
#include <linux/if_tunnel.h>
#include <linux/if_bridge.h>

#include "util.h"
#include "refcnt.h"
#include "missing.h"

#include "sd-rtnl.h"
#include "rtnl-util.h"
#include "rtnl-internal.h"
#include "rtnl-types.h"

#define GET_CONTAINER(m, i) ((i) < (m)->n_containers ? (struct rtattr*)((uint8_t*)(m)->hdr + (m)->container_offsets[i]) : NULL)
#define PUSH_CONTAINER(m, new) (m)->container_offsets[(m)->n_containers ++] = (uint8_t*)(new) - (uint8_t*)(m)->hdr;

static int message_new_empty(sd_rtnl *rtnl, sd_rtnl_message **ret) {
        sd_rtnl_message *m;

        assert_return(ret, -EINVAL);

        /* Note that 'rtnl' is curretly unused, if we start using it internally
           we must take care to avoid problems due to mutual references between
           busses and their queued messages. See sd-bus.
         */

        m = new0(sd_rtnl_message, 1);
        if (!m)
                return -ENOMEM;

        m->n_ref = REFCNT_INIT;

        m->sealed = false;

        *ret = m;

        return 0;
}

int message_new(sd_rtnl *rtnl, sd_rtnl_message **ret, uint16_t type) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *m = NULL;
        const NLType *nl_type;
        size_t size;
        int r;

        r = type_system_get_type(NULL, &nl_type, type);
        if (r < 0)
                return r;

        assert(nl_type->type == NLA_NESTED);

        r = message_new_empty(rtnl, &m);
        if (r < 0)
                return r;

        size = NLMSG_SPACE(nl_type->size);

        assert(size >= sizeof(struct nlmsghdr));
        m->hdr = malloc0(size);
        if (!m->hdr)
                return -ENOMEM;

        m->hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

        m->container_type_system[0] = nl_type->type_system;
        m->hdr->nlmsg_len = size;
        m->hdr->nlmsg_type = type;

        *ret = m;
        m = NULL;

        return 0;
}

int sd_rtnl_message_route_set_dst_prefixlen(sd_rtnl_message *m, unsigned char prefixlen) {
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

int sd_rtnl_message_route_set_scope(sd_rtnl_message *m, unsigned char scope) {
        struct rtmsg *rtm;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_route(m->hdr->nlmsg_type), -EINVAL);

        rtm = NLMSG_DATA(m->hdr);

        rtm->rtm_scope = scope;

        return 0;
}

int sd_rtnl_message_new_route(sd_rtnl *rtnl, sd_rtnl_message **ret,
                              uint16_t nlmsg_type, unsigned char rtm_family) {
        struct rtmsg *rtm;
        int r;

        assert_return(rtnl_message_type_is_route(nlmsg_type), -EINVAL);
        assert_return(rtm_family == AF_INET || rtm_family == AF_INET6, -EINVAL);
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
        rtm->rtm_protocol = RTPROT_BOOT;

        return 0;
}

int sd_rtnl_message_link_set_flags(sd_rtnl_message *m, unsigned flags, unsigned change) {
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

int sd_rtnl_message_link_set_type(sd_rtnl_message *m, unsigned type) {
        struct ifinfomsg *ifi;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_link(m->hdr->nlmsg_type), -EINVAL);

        ifi = NLMSG_DATA(m->hdr);

        ifi->ifi_type = type;

        return 0;
}

int sd_rtnl_message_new_link(sd_rtnl *rtnl, sd_rtnl_message **ret,
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

int sd_rtnl_message_request_dump(sd_rtnl_message *m, int dump) {
        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(m->hdr->nlmsg_type == RTM_GETLINK ||
                      m->hdr->nlmsg_type == RTM_GETADDR ||
                      m->hdr->nlmsg_type == RTM_GETROUTE,
                      -EINVAL);

        if (dump)
                m->hdr->nlmsg_flags |= NLM_F_DUMP;
        else
                m->hdr->nlmsg_flags &= ~NLM_F_DUMP;

        return 0;
}

int sd_rtnl_message_addr_set_prefixlen(sd_rtnl_message *m, unsigned char prefixlen) {
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

int sd_rtnl_message_addr_set_flags(sd_rtnl_message *m, unsigned char flags) {
        struct ifaddrmsg *ifa;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_addr(m->hdr->nlmsg_type), -EINVAL);

        ifa = NLMSG_DATA(m->hdr);

        ifa->ifa_flags = flags;

        return 0;
}

int sd_rtnl_message_addr_set_scope(sd_rtnl_message *m, unsigned char scope) {
        struct ifaddrmsg *ifa;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_addr(m->hdr->nlmsg_type), -EINVAL);

        ifa = NLMSG_DATA(m->hdr);

        ifa->ifa_scope = scope;

        return 0;
}

int sd_rtnl_message_addr_get_family(sd_rtnl_message *m, unsigned char *family) {
        struct ifaddrmsg *ifa;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_addr(m->hdr->nlmsg_type), -EINVAL);
        assert_return(family, -EINVAL);

        ifa = NLMSG_DATA(m->hdr);

        *family = ifa->ifa_family;

        return 0;
}

int sd_rtnl_message_addr_get_prefixlen(sd_rtnl_message *m, unsigned char *prefixlen) {
        struct ifaddrmsg *ifa;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_addr(m->hdr->nlmsg_type), -EINVAL);
        assert_return(prefixlen, -EINVAL);

        ifa = NLMSG_DATA(m->hdr);

        *prefixlen = ifa->ifa_prefixlen;

        return 0;
}

int sd_rtnl_message_addr_get_scope(sd_rtnl_message *m, unsigned char *scope) {
        struct ifaddrmsg *ifa;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_addr(m->hdr->nlmsg_type), -EINVAL);
        assert_return(scope, -EINVAL);

        ifa = NLMSG_DATA(m->hdr);

        *scope = ifa->ifa_scope;

        return 0;
}

int sd_rtnl_message_addr_get_flags(sd_rtnl_message *m, unsigned char *flags) {
        struct ifaddrmsg *ifa;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_addr(m->hdr->nlmsg_type), -EINVAL);
        assert_return(flags, -EINVAL);

        ifa = NLMSG_DATA(m->hdr);

        *flags = ifa->ifa_flags;

        return 0;
}

int sd_rtnl_message_addr_get_ifindex(sd_rtnl_message *m, int *ifindex) {
        struct ifaddrmsg *ifa;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_addr(m->hdr->nlmsg_type), -EINVAL);
        assert_return(ifindex, -EINVAL);

        ifa = NLMSG_DATA(m->hdr);

        *ifindex = ifa->ifa_index;

        return 0;
}

int sd_rtnl_message_new_addr(sd_rtnl *rtnl, sd_rtnl_message **ret,
                             uint16_t nlmsg_type, int index,
                             unsigned char family) {
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

int sd_rtnl_message_new_addr_update(sd_rtnl *rtnl, sd_rtnl_message **ret,
                             int index, unsigned char family) {
        int r;

        r = sd_rtnl_message_new_addr(rtnl, ret, RTM_NEWADDR, index, family);
        if (r < 0)
                return r;

        (*ret)->hdr->nlmsg_flags |= NLM_F_REPLACE;

        return 0;
}

sd_rtnl_message *sd_rtnl_message_ref(sd_rtnl_message *m) {
        if (m)
                assert_se(REFCNT_INC(m->n_ref) >= 2);

        return m;
}

sd_rtnl_message *sd_rtnl_message_unref(sd_rtnl_message *m) {
        if (m && REFCNT_DEC(m->n_ref) <= 0) {
                unsigned i;

                free(m->hdr);

                for (i = 0; i <= m->n_containers; i++)
                        free(m->rta_offset_tb[i]);

                sd_rtnl_message_unref(m->next);

                free(m);
        }

        return NULL;
}

int sd_rtnl_message_get_type(sd_rtnl_message *m, uint16_t *type) {
        assert_return(m, -EINVAL);
        assert_return(type, -EINVAL);

        *type = m->hdr->nlmsg_type;

        return 0;
}

int sd_rtnl_message_is_broadcast(sd_rtnl_message *m) {
        assert_return(m, -EINVAL);

        return !m->hdr->nlmsg_pid;
}

int sd_rtnl_message_link_get_ifindex(sd_rtnl_message *m, int *ifindex) {
        struct ifinfomsg *ifi;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_link(m->hdr->nlmsg_type), -EINVAL);
        assert_return(ifindex, -EINVAL);

        ifi = NLMSG_DATA(m->hdr);

        *ifindex = ifi->ifi_index;

        return 0;
}

int sd_rtnl_message_link_get_flags(sd_rtnl_message *m, unsigned *flags) {
        struct ifinfomsg *ifi;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(rtnl_message_type_is_link(m->hdr->nlmsg_type), -EINVAL);
        assert_return(flags, -EINVAL);

        ifi = NLMSG_DATA(m->hdr);

        *flags = ifi->ifi_flags;

        return 0;
}

/* If successful the updated message will be correctly aligned, if
   unsuccessful the old message is untouched. */
static int add_rtattr(sd_rtnl_message *m, unsigned short type, const void *data, size_t data_length) {
        uint32_t rta_length;
        size_t message_length, padding_length;
        struct nlmsghdr *new_hdr;
        struct rtattr *rta;
        char *padding;
        unsigned i;
        int offset;

        assert(m);
        assert(m->hdr);
        assert(!m->sealed);
        assert(NLMSG_ALIGN(m->hdr->nlmsg_len) == m->hdr->nlmsg_len);
        assert(!data || data_length);

        /* get offset of the new attribute */
        offset = m->hdr->nlmsg_len;

        /* get the size of the new rta attribute (with padding at the end) */
        rta_length = RTA_LENGTH(data_length);

        /* get the new message size (with padding at the end) */
        message_length = offset + RTA_ALIGN(rta_length);

        /* realloc to fit the new attribute */
        new_hdr = realloc(m->hdr, message_length);
        if (!new_hdr)
                return -ENOMEM;
        m->hdr = new_hdr;

        /* get pointer to the attribute we are about to add */
        rta = (struct rtattr *) ((uint8_t *) m->hdr + offset);

        /* if we are inside containers, extend them */
        for (i = 0; i < m->n_containers; i++)
                GET_CONTAINER(m, i)->rta_len += message_length - offset;

        /* fill in the attribute */
        rta->rta_type = type;
        rta->rta_len = rta_length;
        if (data)
                /* we don't deal with the case where the user lies about the type
                 * and gives us too little data (so don't do that)
                 */
                padding = mempcpy(RTA_DATA(rta), data, data_length);
        else {
                /* if no data was passed, make sure we still initialize the padding
                   note that we can have data_length > 0 (used by some containers) */
                padding = RTA_DATA(rta);
                data_length = 0;
        }

        /* make sure also the padding at the end of the message is initialized */
        padding_length = (uint8_t*)m->hdr + message_length - (uint8_t*)padding;
        memzero(padding, padding_length);

        /* update message size */
        m->hdr->nlmsg_len = message_length;

        return offset;
}

static int message_attribute_has_type(sd_rtnl_message *m, uint16_t attribute_type, uint16_t data_type) {
        const NLType *type;
        int r;

        r = type_system_get_type(m->container_type_system[m->n_containers], &type, attribute_type);
        if (r < 0)
                return r;

        if (type->type != data_type)
                return -EINVAL;

        return type->size;
}

int sd_rtnl_message_append_string(sd_rtnl_message *m, unsigned short type, const char *data) {
        size_t length, size;
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(data, -EINVAL);

        r = message_attribute_has_type(m, type, NLA_STRING);
        if (r < 0)
                return r;
        else
                size = (size_t)r;

        if (size) {
                length = strnlen(data, size);
                if (length >= size)
                        return -EINVAL;
        } else
                length = strlen(data);

        r = add_rtattr(m, type, data, length + 1);
        if (r < 0)
                return r;

        return 0;
}

int sd_rtnl_message_append_u8(sd_rtnl_message *m, unsigned short type, uint8_t data) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);

        r = message_attribute_has_type(m, type, NLA_U8);
        if (r < 0)
                return r;

        r = add_rtattr(m, type, &data, sizeof(uint8_t));
        if (r < 0)
                return r;

        return 0;
}


int sd_rtnl_message_append_u16(sd_rtnl_message *m, unsigned short type, uint16_t data) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);

        r = message_attribute_has_type(m, type, NLA_U16);
        if (r < 0)
                return r;

        r = add_rtattr(m, type, &data, sizeof(uint16_t));
        if (r < 0)
                return r;

        return 0;
}

int sd_rtnl_message_append_u32(sd_rtnl_message *m, unsigned short type, uint32_t data) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);

        r = message_attribute_has_type(m, type, NLA_U32);
        if (r < 0)
                return r;

        r = add_rtattr(m, type, &data, sizeof(uint32_t));
        if (r < 0)
                return r;

        return 0;
}

int sd_rtnl_message_append_in_addr(sd_rtnl_message *m, unsigned short type, const struct in_addr *data) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(data, -EINVAL);

        r = message_attribute_has_type(m, type, NLA_IN_ADDR);
        if (r < 0)
                return r;

        r = add_rtattr(m, type, data, sizeof(struct in_addr));
        if (r < 0)
                return r;

        return 0;
}

int sd_rtnl_message_append_in6_addr(sd_rtnl_message *m, unsigned short type, const struct in6_addr *data) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(data, -EINVAL);

        r = message_attribute_has_type(m, type, NLA_IN_ADDR);
        if (r < 0)
                return r;

        r = add_rtattr(m, type, data, sizeof(struct in6_addr));
        if (r < 0)
                return r;

        return 0;
}

int sd_rtnl_message_append_ether_addr(sd_rtnl_message *m, unsigned short type, const struct ether_addr *data) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(data, -EINVAL);

        r = message_attribute_has_type(m, type, NLA_ETHER_ADDR);
        if (r < 0)
                return r;

        r = add_rtattr(m, type, data, ETH_ALEN);
        if (r < 0)
                return r;

        return 0;
}

int sd_rtnl_message_append_cache_info(sd_rtnl_message *m, unsigned short type, const struct ifa_cacheinfo *info) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(info, -EINVAL);

        r = message_attribute_has_type(m, type, NLA_CACHE_INFO);
        if (r < 0)
                return r;

        r = add_rtattr(m, type, info, sizeof(struct ifa_cacheinfo));
        if (r < 0)
                return r;

        return 0;
}

int sd_rtnl_message_open_container(sd_rtnl_message *m, unsigned short type) {
        size_t size;
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(m->n_containers < RTNL_CONTAINER_DEPTH, -ERANGE);

        r = message_attribute_has_type(m, type, NLA_NESTED);
        if (r < 0)
                return r;
        else
                size = (size_t)r;

        r = type_system_get_type_system(m->container_type_system[m->n_containers],
                                        &m->container_type_system[m->n_containers + 1],
                                        type);
        if (r < 0)
                return r;

        r = add_rtattr(m, type, NULL, size);
        if (r < 0)
                return r;

        m->container_offsets[m->n_containers ++] = r;

        return 0;
}

int sd_rtnl_message_open_container_union(sd_rtnl_message *m, unsigned short type, const char *key) {
        const NLTypeSystemUnion *type_system_union;
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);

        r = type_system_get_type_system_union(m->container_type_system[m->n_containers], &type_system_union, type);
        if (r < 0)
                return r;

        r = type_system_union_get_type_system(type_system_union,
                                              &m->container_type_system[m->n_containers + 1],
                                              key);
        if (r < 0)
                return r;

        r = sd_rtnl_message_append_string(m, type_system_union->match, key);
        if (r < 0)
                return r;

        /* do we evere need non-null size */
        r = add_rtattr(m, type, NULL, 0);
        if (r < 0)
                return r;

        m->container_offsets[m->n_containers ++] = r;

        return 0;
}


int sd_rtnl_message_close_container(sd_rtnl_message *m) {
        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(m->n_containers > 0, -EINVAL);

        m->container_type_system[m->n_containers] = NULL;
        m->n_containers --;

        return 0;
}

int rtnl_message_read_internal(sd_rtnl_message *m, unsigned short type, void **data) {
        struct rtattr *rta;

        assert_return(m, -EINVAL);
        assert_return(m->sealed, -EPERM);
        assert_return(data, -EINVAL);
        assert(m->n_containers <= RTNL_CONTAINER_DEPTH);
        assert(m->rta_offset_tb[m->n_containers]);
        assert(type < m->rta_tb_size[m->n_containers]);

        if(!m->rta_offset_tb[m->n_containers][type])
                return -ENODATA;

        rta = (struct rtattr*)((uint8_t *) m->hdr + m->rta_offset_tb[m->n_containers][type]);

        *data = RTA_DATA(rta);

        return RTA_PAYLOAD(rta);
}

int sd_rtnl_message_read_string(sd_rtnl_message *m, unsigned short type, char **data) {
        int r;
        void *attr_data;

        r = message_attribute_has_type(m, type, NLA_STRING);
        if (r < 0)
                return r;

        r = rtnl_message_read_internal(m, type, &attr_data);
        if (r < 0)
                return r;
        else if (strnlen(attr_data, r) >= (size_t) r)
                return -EIO;

        *data = (char *) attr_data;

        return 0;
}

int sd_rtnl_message_read_u8(sd_rtnl_message *m, unsigned short type, uint8_t *data) {
        int r;
        void *attr_data;

        r = message_attribute_has_type(m, type, NLA_U8);
        if (r < 0)
                return r;

        r = rtnl_message_read_internal(m, type, &attr_data);
        if (r < 0)
                return r;
        else if ((size_t) r < sizeof(uint8_t))
                return -EIO;

        *data = *(uint8_t *) attr_data;

        return 0;
}

int sd_rtnl_message_read_u16(sd_rtnl_message *m, unsigned short type, uint16_t *data) {
        int r;
        void *attr_data;

        r = message_attribute_has_type(m, type, NLA_U16);
        if (r < 0)
                return r;

        r = rtnl_message_read_internal(m, type, &attr_data);
        if (r < 0)
                return r;
        else if ((size_t) r < sizeof(uint16_t))
                return -EIO;

        *data = *(uint16_t *) attr_data;

        return 0;
}

int sd_rtnl_message_read_u32(sd_rtnl_message *m, unsigned short type, uint32_t *data) {
        int r;
        void *attr_data;

        r = message_attribute_has_type(m, type, NLA_U32);
        if (r < 0)
                return r;

        r = rtnl_message_read_internal(m, type, &attr_data);
        if (r < 0)
                return r;
        else if ((size_t)r < sizeof(uint32_t))
                return -EIO;

        *data = *(uint32_t *) attr_data;

        return 0;
}

int sd_rtnl_message_read_ether_addr(sd_rtnl_message *m, unsigned short type, struct ether_addr *data) {
        int r;
        void *attr_data;

        r = message_attribute_has_type(m, type, NLA_ETHER_ADDR);
        if (r < 0)
                return r;

        r = rtnl_message_read_internal(m, type, &attr_data);
        if (r < 0)
                return r;
        else if ((size_t)r < sizeof(struct ether_addr))
                return -EIO;

        memcpy(data, attr_data, sizeof(struct ether_addr));

        return 0;
}

int sd_rtnl_message_read_cache_info(sd_rtnl_message *m, unsigned short type, struct ifa_cacheinfo *info) {
        int r;
        void *attr_data;

        r = message_attribute_has_type(m, type, NLA_CACHE_INFO);
        if (r < 0)
                return r;

        r = rtnl_message_read_internal(m, type, &attr_data);
        if (r < 0)
                return r;
        else if ((size_t)r < sizeof(struct ifa_cacheinfo))
                return -EIO;

        memcpy(info, attr_data, sizeof(struct ifa_cacheinfo));

        return 0;
}

int sd_rtnl_message_read_in_addr(sd_rtnl_message *m, unsigned short type, struct in_addr *data) {
        int r;
        void *attr_data;

        r = message_attribute_has_type(m, type, NLA_IN_ADDR);
        if (r < 0)
                return r;

        r = rtnl_message_read_internal(m, type, &attr_data);
        if (r < 0)
                return r;
        else if ((size_t)r < sizeof(struct in_addr))
                return -EIO;

        memcpy(data, attr_data, sizeof(struct in_addr));

        return 0;
}

int sd_rtnl_message_read_in6_addr(sd_rtnl_message *m, unsigned short type, struct in6_addr *data) {
        int r;
        void *attr_data;

        r = message_attribute_has_type(m, type, NLA_IN_ADDR);
        if (r < 0)
                return r;

        r = rtnl_message_read_internal(m, type, &attr_data);
        if (r < 0)
                return r;
        else if ((size_t)r < sizeof(struct in6_addr))
                return -EIO;

        memcpy(data, attr_data, sizeof(struct in6_addr));

        return 0;
}

int sd_rtnl_message_enter_container(sd_rtnl_message *m, unsigned short type) {
        const NLType *nl_type;
        const NLTypeSystem *type_system;
        void *container;
        size_t size;
        int r;

        assert_return(m, -EINVAL);
        assert_return(m->n_containers < RTNL_CONTAINER_DEPTH, -EINVAL);

        r = type_system_get_type(m->container_type_system[m->n_containers],
                                 &nl_type,
                                 type);
        if (r < 0)
                return r;

        if (nl_type->type == NLA_NESTED) {
                r = type_system_get_type_system(m->container_type_system[m->n_containers],
                                                &type_system,
                                                type);
                if (r < 0)
                        return r;
        } else if (nl_type->type == NLA_UNION) {
                const NLTypeSystemUnion *type_system_union;
                char *key;

                r = type_system_get_type_system_union(m->container_type_system[m->n_containers],
                                                      &type_system_union,
                                                      type);
                if (r < 0)
                        return r;

                r = sd_rtnl_message_read_string(m, type_system_union->match, &key);
                if (r < 0)
                        return r;

                r = type_system_union_get_type_system(type_system_union,
                                                      &type_system,
                                                      key);
                if (r < 0)
                        return r;
        } else
                return -EINVAL;

        r = rtnl_message_read_internal(m, type, &container);
        if (r < 0)
                return r;
        else
                size = (size_t)r;

        m->n_containers ++;

        r = rtnl_message_parse(m,
                               &m->rta_offset_tb[m->n_containers],
                               &m->rta_tb_size[m->n_containers],
                               type_system->max,
                               container,
                               size);
        if (r < 0) {
                m->n_containers --;
                return r;
        }

        m->container_type_system[m->n_containers] = type_system;

        return 0;
}

int sd_rtnl_message_exit_container(sd_rtnl_message *m) {
        assert_return(m, -EINVAL);
        assert_return(m->sealed, -EINVAL);
        assert_return(m->n_containers > 0, -EINVAL);

        free(m->rta_offset_tb[m->n_containers]);
        m->rta_offset_tb[m->n_containers] = NULL;
        m->container_type_system[m->n_containers] = NULL;

        m->n_containers --;

        return 0;
}

uint32_t rtnl_message_get_serial(sd_rtnl_message *m) {
        assert(m);
        assert(m->hdr);

        return m->hdr->nlmsg_seq;
}

int sd_rtnl_message_get_errno(sd_rtnl_message *m) {
        struct nlmsgerr *err;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);

        if (m->hdr->nlmsg_type != NLMSG_ERROR)
                return 0;

        err = NLMSG_DATA(m->hdr);

        return err->error;
}

int rtnl_message_parse(sd_rtnl_message *m,
                       size_t **rta_offset_tb,
                       unsigned short *rta_tb_size,
                       int max,
                       struct rtattr *rta,
                       unsigned int rt_len) {
        unsigned short type;
        size_t *tb;

        tb = new0(size_t, max + 1);
        if(!tb)
                return -ENOMEM;

        *rta_tb_size = max + 1;

        for (; RTA_OK(rta, rt_len); rta = RTA_NEXT(rta, rt_len)) {
                type = rta->rta_type;

                /* if the kernel is newer than the headers we used
                   when building, we ignore out-of-range attributes
                 */
                if (type > max)
                        continue;

                if (tb[type])
                        log_debug("rtnl: message parse - overwriting repeated attribute");

                tb[type] = (uint8_t *) rta - (uint8_t *) m->hdr;
        }

        *rta_offset_tb = tb;

        return 0;
}

/* returns the number of bytes sent, or a negative error code */
int socket_write_message(sd_rtnl *nl, sd_rtnl_message *m) {
        union {
                struct sockaddr sa;
                struct sockaddr_nl nl;
        } addr = {
                .nl.nl_family = AF_NETLINK,
        };
        ssize_t k;

        assert(nl);
        assert(m);
        assert(m->hdr);

        k = sendto(nl->fd, m->hdr, m->hdr->nlmsg_len,
                        0, &addr.sa, sizeof(addr));
        if (k < 0)
                return (errno == EAGAIN) ? 0 : -errno;

        return k;
}

static int socket_recv_message(int fd, struct iovec *iov, uint32_t *_group, bool peek) {
        uint8_t cred_buffer[CMSG_SPACE(sizeof(struct ucred)) +
                            CMSG_SPACE(sizeof(struct nl_pktinfo))];
        struct msghdr msg = {
                .msg_iov = iov,
                .msg_iovlen = 1,
                .msg_control = cred_buffer,
                .msg_controllen = sizeof(cred_buffer),
        };
        struct cmsghdr *cmsg;
        uint32_t group = 0;
        bool auth = false;
        int r;

        assert(fd >= 0);
        assert(iov);

        r = recvmsg(fd, &msg, MSG_TRUNC | (peek ? MSG_PEEK : 0));
        if (r < 0)
                /* no data */
                return (errno == EAGAIN) ? 0 : -errno;
        else if (r == 0)
                /* connection was closed by the kernel */
                return -ECONNRESET;

        for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
                if (cmsg->cmsg_level == SOL_SOCKET &&
                    cmsg->cmsg_type == SCM_CREDENTIALS &&
                    cmsg->cmsg_len == CMSG_LEN(sizeof(struct ucred))) {
                        struct ucred *ucred = (void *)CMSG_DATA(cmsg);

                        /* from the kernel */
                        if (ucred->uid == 0 && ucred->pid == 0)
                                auth = true;
                } else if (cmsg->cmsg_level == SOL_NETLINK &&
                           cmsg->cmsg_type == NETLINK_PKTINFO &&
                           cmsg->cmsg_len == CMSG_LEN(sizeof(struct nl_pktinfo))) {
                        struct nl_pktinfo *pktinfo = (void *)CMSG_DATA(cmsg);

                        /* multi-cast group */
                        group = pktinfo->group;
                }
        }

        if (!auth)
                /* not from the kernel, ignore */
                return 0;

        if (group)
                *_group = group;

        return r;
}

/* On success, the number of bytes received is returned and *ret points to the received message
 * which has a valid header and the correct size.
 * If nothing useful was received 0 is returned.
 * On failure, a negative error code is returned.
 */
int socket_read_message(sd_rtnl *rtnl) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *first = NULL;
        struct iovec iov = {};
        uint32_t group = 0;
        bool multi_part = false, done = false;
        struct nlmsghdr *new_msg;
        size_t len;
        int r;
        unsigned i = 0;

        assert(rtnl);
        assert(rtnl->rbuffer);
        assert(rtnl->rbuffer_allocated >= sizeof(struct nlmsghdr));

        /* read nothing, just get the pending message size */
        r = socket_recv_message(rtnl->fd, &iov, &group, true);
        if (r <= 0)
                return r;
        else
                len = (size_t)r;

        /* make room for the pending message */
        if (!greedy_realloc((void **)&rtnl->rbuffer,
                            &rtnl->rbuffer_allocated,
                            len, sizeof(uint8_t)))
                return -ENOMEM;

        iov.iov_base = rtnl->rbuffer;
        iov.iov_len = rtnl->rbuffer_allocated;

        /* read the pending message */
        r = socket_recv_message(rtnl->fd, &iov, &group, false);
        if (r <= 0)
                return r;
        else
                len = (size_t)r;

        if (len > rtnl->rbuffer_allocated)
                /* message did not fit in read buffer */
                return -EIO;

        if (NLMSG_OK(rtnl->rbuffer, len) && rtnl->rbuffer->nlmsg_flags & NLM_F_MULTI) {
                multi_part = true;

                for (i = 0; i < rtnl->rqueue_partial_size; i++) {
                        if (rtnl_message_get_serial(rtnl->rqueue_partial[i]) ==
                            rtnl->rbuffer->nlmsg_seq) {
                                first = rtnl->rqueue_partial[i];
                                break;
                        }
                }
        }

        for (new_msg = rtnl->rbuffer; NLMSG_OK(new_msg, len); new_msg = NLMSG_NEXT(new_msg, len)) {
                _cleanup_rtnl_message_unref_ sd_rtnl_message *m = NULL;
                const NLType *nl_type;

                if (!group && new_msg->nlmsg_pid != rtnl->sockaddr.nl.nl_pid)
                        /* not broadcast and not for us */
                        continue;

                if (new_msg->nlmsg_type == NLMSG_NOOP)
                        /* silently drop noop messages */
                        continue;

                if (new_msg->nlmsg_type == NLMSG_DONE) {
                        /* finished reading multi-part message */
                        done = true;
                        break;
                }

                /* check that we support this message type */
                r = type_system_get_type(NULL, &nl_type, new_msg->nlmsg_type);
                if (r < 0) {
                        if (r == -ENOTSUP)
                                log_debug("sd-rtnl: ignored message with unknown type: %u",
                                          new_msg->nlmsg_type);

                        continue;
                }

                /* check that the size matches the message type */
                if (new_msg->nlmsg_len < NLMSG_LENGTH(nl_type->size))
                        continue;

                r = message_new_empty(rtnl, &m);
                if (r < 0)
                        return r;

                m->hdr = memdup(new_msg, new_msg->nlmsg_len);
                if (!m->hdr)
                        return -ENOMEM;

                /* seal and parse the top-level message */
                r = sd_rtnl_message_rewind(m);
                if (r < 0)
                        return r;

                /* push the message onto the multi-part message stack */
                if (first)
                        m->next = first;
                first = m;
                m = NULL;
        }

        if (len)
                log_debug("sd-rtnl: discarding %zu bytes of incoming message", len);

        if (!first)
                return 0;

        if (!multi_part || done) {
                /* we got a complete message, push it on the read queue */
                r = rtnl_rqueue_make_room(rtnl);
                if (r < 0)
                        return r;

                rtnl->rqueue[rtnl->rqueue_size ++] = first;
                first = NULL;

                if (multi_part && (i < rtnl->rqueue_partial_size)) {
                        /* remove the message form the partial read queue */
                        memmove(rtnl->rqueue_partial + i,rtnl->rqueue_partial + i + 1,
                                sizeof(sd_rtnl_message*) * (rtnl->rqueue_partial_size - i - 1));
                        rtnl->rqueue_partial_size --;
                }

                return 1;
        } else {
                /* we only got a partial multi-part message, push it on the
                   partial read queue */
                if (i < rtnl->rqueue_partial_size) {
                        rtnl->rqueue_partial[i] = first;
                } else {
                        r = rtnl_rqueue_partial_make_room(rtnl);
                        if (r < 0)
                                return r;

                        rtnl->rqueue_partial[rtnl->rqueue_partial_size ++] = first;
                }
                first = NULL;

                return 0;
        }
}

int sd_rtnl_message_rewind(sd_rtnl_message *m) {
        const NLType *type;
        unsigned i;
        int r;

        assert_return(m, -EINVAL);

        /* don't allow appending to message once parsed */
        if (!m->sealed)
                rtnl_message_seal(m);

        for (i = 1; i <= m->n_containers; i++) {
                free(m->rta_offset_tb[i]);
                m->rta_offset_tb[i] = NULL;
                m->rta_tb_size[i] = 0;
                m->container_type_system[i] = NULL;
        }

        m->n_containers = 0;

        if (m->rta_offset_tb[0]) {
                /* top-level attributes have already been parsed */
                return 0;
        }

        assert(m->hdr);

        r = type_system_get_type(NULL, &type, m->hdr->nlmsg_type);
        if (r < 0)
                return r;

        if (type->type == NLA_NESTED) {
                const NLTypeSystem *type_system = type->type_system;

                assert(type_system);

                m->container_type_system[0] = type_system;

                r = rtnl_message_parse(m,
                                       &m->rta_offset_tb[m->n_containers],
                                       &m->rta_tb_size[m->n_containers],
                                       type_system->max,
                                       (struct rtattr*)((uint8_t*)NLMSG_DATA(m->hdr) +
                                                        NLMSG_ALIGN(type->size)),
                                       NLMSG_PAYLOAD(m->hdr, type->size));
                if (r < 0)
                        return r;
        }

        return 0;
}

void rtnl_message_seal(sd_rtnl_message *m) {
        assert(m);
        assert(!m->sealed);

        m->sealed = true;
}

sd_rtnl_message *sd_rtnl_message_next(sd_rtnl_message *m) {
        assert_return(m, NULL);

        return m->next;
}
