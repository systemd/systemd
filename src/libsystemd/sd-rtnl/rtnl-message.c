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
#include <linux/veth.h>

#include "util.h"
#include "refcnt.h"
#include "missing.h"

#include "sd-rtnl.h"
#include "rtnl-util.h"
#include "rtnl-internal.h"

#define GET_CONTAINER(m, i) ((i) < (m)->n_containers ? (struct rtattr*)((uint8_t*)(m)->hdr + (m)->container_offsets[i]) : NULL)
#define NEXT_RTA(m) ((struct rtattr*)((uint8_t*)(m)->hdr + (m)->next_rta_offset))
#define UPDATE_RTA(m, new) (m)->next_rta_offset = (uint8_t*)(new) - (uint8_t*)(m)->hdr;
#define PUSH_CONTAINER(m, new) (m)->container_offsets[(m)->n_containers ++] = (uint8_t*)(new) - (uint8_t*)(m)->hdr;

int message_new(sd_rtnl *rtnl, sd_rtnl_message **ret, size_t initial_size) {
        sd_rtnl_message *m;

        assert_return(ret, -EINVAL);
        assert_return(initial_size >= sizeof(struct nlmsghdr), -EINVAL);

        m = new0(sd_rtnl_message, 1);
        if (!m)
                return -ENOMEM;

        m->hdr = malloc0(initial_size);
        if (!m->hdr) {
                free(m);
                return -ENOMEM;
        }

        m->n_ref = REFCNT_INIT;

        m->hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
        m->sealed = false;

        if (rtnl)
                m->rtnl = sd_rtnl_ref(rtnl);

        *ret = m;

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

int sd_rtnl_message_new_route(sd_rtnl *rtnl, sd_rtnl_message **ret,
                              uint16_t nlmsg_type, unsigned char rtm_family) {
        struct rtmsg *rtm;
        int r;

        assert_return(rtnl_message_type_is_route(nlmsg_type), -EINVAL);
        assert_return(rtm_family == AF_INET || rtm_family == AF_INET6, -EINVAL);
        assert_return(ret, -EINVAL);

        r = message_new(rtnl, ret, NLMSG_SPACE(sizeof(struct rtmsg)));
        if (r < 0)
                return r;

        (*ret)->hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
        (*ret)->hdr->nlmsg_type = nlmsg_type;
        if (nlmsg_type == RTM_NEWROUTE)
                (*ret)->hdr->nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;

        rtm = NLMSG_DATA((*ret)->hdr);

        UPDATE_RTA(*ret, RTM_RTA(rtm));

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
        assert_return(nlmsg_type == RTM_NEWLINK ||
                      nlmsg_type == RTM_SETLINK || index > 0, -EINVAL);
        assert_return(ret, -EINVAL);

        r = message_new(rtnl, ret, NLMSG_SPACE(sizeof(struct ifinfomsg)));
        if (r < 0)
                return r;

        (*ret)->hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
        (*ret)->hdr->nlmsg_type = nlmsg_type;
        if (nlmsg_type == RTM_NEWLINK)
                (*ret)->hdr->nlmsg_flags |= NLM_F_CREATE;

        ifi = NLMSG_DATA((*ret)->hdr);

        ifi->ifi_family = AF_UNSPEC;
        ifi->ifi_index = index;

        UPDATE_RTA(*ret, IFLA_RTA(ifi));

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

int sd_rtnl_message_new_addr(sd_rtnl *rtnl, sd_rtnl_message **ret,
                             uint16_t nlmsg_type, int index,
                             unsigned char family) {
        struct ifaddrmsg *ifa;
        int r;

        assert_return(rtnl_message_type_is_addr(nlmsg_type), -EINVAL);
        assert_return(index > 0, -EINVAL);
        assert_return(family == AF_INET || family == AF_INET6, -EINVAL);
        assert_return(ret, -EINVAL);

        r = message_new(rtnl, ret, NLMSG_SPACE(sizeof(struct ifaddrmsg)));
        if (r < 0)
                return r;

        (*ret)->hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
        (*ret)->hdr->nlmsg_type = nlmsg_type;
        if (nlmsg_type == RTM_GETADDR && family == AF_INET)
                (*ret)->hdr->nlmsg_flags |= NLM_F_DUMP;

        ifa = NLMSG_DATA((*ret)->hdr);

        ifa->ifa_index = index;
        ifa->ifa_family = family;
        if (family == AF_INET)
                ifa->ifa_prefixlen = 32;
        else if (family == AF_INET6)
                ifa->ifa_prefixlen = 128;

        UPDATE_RTA(*ret, IFA_RTA(ifa));

        return 0;
}

sd_rtnl_message *sd_rtnl_message_ref(sd_rtnl_message *m) {
        if (m)
                assert_se(REFCNT_INC(m->n_ref) >= 2);

        return m;
}

sd_rtnl_message *sd_rtnl_message_unref(sd_rtnl_message *m) {
        if (m && REFCNT_DEC(m->n_ref) <= 0) {
                sd_rtnl_unref(m->rtnl);
                free(m->hdr);
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
        uint32_t rta_length, message_length;
        struct nlmsghdr *new_hdr;
        struct rtattr *rta;
        char *padding;
        unsigned i;

        assert(m);
        assert(m->hdr);
        assert(!m->sealed);
        assert(NLMSG_ALIGN(m->hdr->nlmsg_len) == m->hdr->nlmsg_len);
        assert(!data || data_length > 0);
        assert(data || m->n_containers < RTNL_CONTAINER_DEPTH);

        /* get the size of the new rta attribute (with padding at the end) */
        rta_length = RTA_LENGTH(data_length);

        /* get the new message size (with padding at the end) */
        message_length = m->hdr->nlmsg_len + RTA_ALIGN(rta_length);

        /* realloc to fit the new attribute */
        new_hdr = realloc(m->hdr, message_length);
        if (!new_hdr)
                return -ENOMEM;
        m->hdr = new_hdr;

        /* get pointer to the attribute we are about to add */
        rta = (struct rtattr *) ((uint8_t *) m->hdr + m->hdr->nlmsg_len);

        /* if we are inside containers, extend them */
        for (i = 0; i < m->n_containers; i++)
                GET_CONTAINER(m, i)->rta_len += message_length - m->hdr->nlmsg_len;

        /* fill in the attribute */
        rta->rta_type = type;
        rta->rta_len = rta_length;
        if (!data) {
                /* this is the start of a new container */
                m->container_offsets[m->n_containers ++] = m->hdr->nlmsg_len;
        } else {
                /* we don't deal with the case where the user lies about the type
                 * and gives us too little data (so don't do that)
                */
                padding = mempcpy(RTA_DATA(rta), data, data_length);
                /* make sure also the padding at the end of the message is initialized */
                memzero(padding,
                        (uint8_t *) m->hdr + message_length - (uint8_t *) padding);
        }

        /* update message size */
        m->hdr->nlmsg_len = message_length;

        return 0;
}

int sd_rtnl_message_append_string(sd_rtnl_message *m, unsigned short type, const char *data) {
        uint16_t rtm_type;
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(data, -EINVAL);

        r = sd_rtnl_message_get_type(m, &rtm_type);
        if (r < 0)
                return r;

        /* check that the type is correct */
        switch (rtm_type) {
                case RTM_NEWLINK:
                case RTM_SETLINK:
                case RTM_GETLINK:
                case RTM_DELLINK:
                        if (m->n_containers == 1) {
                                if (GET_CONTAINER(m, 0)->rta_type != IFLA_LINKINFO ||
                                    type != IFLA_INFO_KIND)
                                        return -ENOTSUP;
                        } else {
                                switch (type) {
                                        case IFLA_IFNAME:
                                        case IFLA_IFALIAS:
                                        case IFLA_QDISC:
                                                break;
                                        default:
                                                return -ENOTSUP;
                                }
                        }
                        break;
                case RTM_NEWADDR:
                case RTM_GETADDR:
                case RTM_DELADDR:
                        if (type != IFA_LABEL)
                                return -ENOTSUP;
                        break;
                default:
                        return -ENOTSUP;
        }

        r = add_rtattr(m, type, data, strlen(data) + 1);
        if (r < 0)
                return r;

        return 0;
}

int sd_rtnl_message_append_u8(sd_rtnl_message *m, unsigned short type, uint8_t data) {
        uint16_t rtm_type;
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);

        r = sd_rtnl_message_get_type(m, &rtm_type);
        if (r < 0)
                return r;

        switch (rtm_type) {
                case RTM_NEWLINK:
                case RTM_SETLINK:
                case RTM_GETLINK:
                case RTM_DELLINK:
                        switch (type) {
                                case IFLA_CARRIER:
                                case IFLA_OPERSTATE:
                                case IFLA_LINKMODE:
                                break;
                        default:
                                return -ENOTSUP;
                        }

                        break;
                default:
                        return -ENOTSUP;
        }

        r = add_rtattr(m, type, &data, sizeof(uint8_t));
        if (r < 0)
                return r;

        return 0;
}


int sd_rtnl_message_append_u16(sd_rtnl_message *m, unsigned short type, uint16_t data) {
        uint16_t rtm_type;
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);

        r = sd_rtnl_message_get_type(m, &rtm_type);
        if (r < 0)
                return r;

        /* check that the type is correct */
        switch (rtm_type) {
                case RTM_NEWLINK:
                case RTM_SETLINK:
                case RTM_GETLINK:
                case RTM_DELLINK:
                        if (m->n_containers == 2 &&
                            GET_CONTAINER(m, 0)->rta_type == IFLA_LINKINFO &&
                            GET_CONTAINER(m, 1)->rta_type == IFLA_INFO_DATA &&
                            type == IFLA_VLAN_ID)
                                break;
                        else
                                return -ENOTSUP;
                        break;
                default:
                        return -ENOTSUP;
        }

        r = add_rtattr(m, type, &data, sizeof(uint16_t));
        if (r < 0)
                return r;

        return 0;
}

int sd_rtnl_message_append_u32(sd_rtnl_message *m, unsigned short type, uint32_t data) {
        uint16_t rtm_type;
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);

        r = sd_rtnl_message_get_type(m, &rtm_type);
        if (r < 0)
                return r;

        /* check that the type is correct */
        switch (rtm_type) {
                case RTM_NEWLINK:
                case RTM_SETLINK:
                case RTM_GETLINK:
                case RTM_DELLINK:
                        switch (type) {
                                case IFLA_MASTER:
                                case IFLA_MTU:
                                case IFLA_LINK:
                                case IFLA_GROUP:
                                case IFLA_TXQLEN:
                                case IFLA_WEIGHT:
                                case IFLA_NET_NS_FD:
                                case IFLA_NET_NS_PID:
                                case IFLA_PROMISCUITY:
                                case IFLA_NUM_TX_QUEUES:
                                case IFLA_NUM_RX_QUEUES:
                                        break;
                                default:
                                        return -ENOTSUP;
                        }
                        break;
                case RTM_NEWROUTE:
                case RTM_GETROUTE:
                case RTM_DELROUTE:
                        switch (type) {
                                case RTA_TABLE:
                                case RTA_PRIORITY:
                                case RTA_IIF:
                                case RTA_OIF:
                                case RTA_MARK:
                                        break;
                                default:
                                        return -ENOTSUP;
                        }
                        break;
                default:
                        return -ENOTSUP;
        }

        r = add_rtattr(m, type, &data, sizeof(uint32_t));
        if (r < 0)
                return r;

        return 0;
}

int sd_rtnl_message_append_in_addr(sd_rtnl_message *m, unsigned short type, const struct in_addr *data) {
        struct ifaddrmsg *ifa;
        struct rtmsg *rtm;
        uint16_t rtm_type;
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(data, -EINVAL);

        r = sd_rtnl_message_get_type(m, &rtm_type);
        if (r < 0)
                return r;

        /* check that the type is correct */
        switch (rtm_type) {
                case RTM_NEWADDR:
                case RTM_GETADDR:
                case RTM_DELADDR:
                        switch (type) {
                                case IFA_ADDRESS:
                                case IFA_LOCAL:
                                case IFA_BROADCAST:
                                case IFA_ANYCAST:
                                        ifa = NLMSG_DATA(m->hdr);

                                        if (ifa->ifa_family != AF_INET)
                                                return -EINVAL;

                                        break;
                                default:
                                        return -ENOTSUP;
                        }
                        break;
                case RTM_NEWROUTE:
                case RTM_GETROUTE:
                case RTM_DELROUTE:
                        switch (type) {
                                case RTA_DST:
                                case RTA_SRC:
                                case RTA_GATEWAY:
                                        rtm = NLMSG_DATA(m->hdr);

                                        if (rtm->rtm_family != AF_INET)
                                                return -EINVAL;

                                        break;
                                default:
                                        return -ENOTSUP;
                        }
                        break;
                default:
                        return -ENOTSUP;
        }

        r = add_rtattr(m, type, data, sizeof(struct in_addr));
        if (r < 0)
                return r;

        return 0;
}

int sd_rtnl_message_append_in6_addr(sd_rtnl_message *m, unsigned short type, const struct in6_addr *data) {
        struct ifaddrmsg *ifa;
        struct rtmsg *rtm;
        uint16_t rtm_type;
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(data, -EINVAL);

        r = sd_rtnl_message_get_type(m, &rtm_type);
        if (r < 0)
                return r;

        /* check that the type is correct */
        switch (rtm_type) {
                case RTM_NEWADDR:
                case RTM_GETADDR:
                case RTM_DELADDR:
                        switch (type) {
                                case IFA_ADDRESS:
                                case IFA_LOCAL:
                                case IFA_BROADCAST:
                                case IFA_ANYCAST:
                                        ifa = NLMSG_DATA(m->hdr);

                                        if (ifa->ifa_family != AF_INET6)
                                                return -EINVAL;

                                        break;
                                default:
                                        return -ENOTSUP;
                        }
                        break;
                case RTM_NEWROUTE:
                case RTM_GETROUTE:
                case RTM_DELROUTE:
                        switch (type) {
                                case RTA_DST:
                                case RTA_SRC:
                                case RTA_GATEWAY:
                                        rtm = NLMSG_DATA(m->hdr);

                                        if (rtm->rtm_family != AF_INET6)
                                                return -EINVAL;

                                        break;
                                default:
                                        return -ENOTSUP;
                        }
                default:
                        return -ENOTSUP;
        }

        r = add_rtattr(m, type, data, sizeof(struct in6_addr));
        if (r < 0)
                return r;

        return 0;
}

int sd_rtnl_message_append_ether_addr(sd_rtnl_message *m, unsigned short type, const struct ether_addr *data) {
        uint16_t rtm_type;
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(data, -EINVAL);

        sd_rtnl_message_get_type(m, &rtm_type);

        switch (rtm_type) {
                case RTM_NEWLINK:
                case RTM_SETLINK:
                case RTM_DELLINK:
                case RTM_GETLINK:
                        switch (type) {
                                case IFLA_ADDRESS:
                                case IFLA_BROADCAST:
                                        break;
                                default:
                                        return -ENOTSUP;
                        }
                        break;
                default:
                        return -ENOTSUP;
        }

        r = add_rtattr(m, type, data, ETH_ALEN);
        if (r < 0)
                return r;

        return 0;
}

int sd_rtnl_message_open_container(sd_rtnl_message *m, unsigned short type) {
        uint16_t rtm_type;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);

        sd_rtnl_message_get_type(m, &rtm_type);

        if (rtnl_message_type_is_link(rtm_type)) {

                if ((type == IFLA_LINKINFO && m->n_containers == 0) ||
                    (type == IFLA_INFO_DATA && m->n_containers == 1 &&
                     GET_CONTAINER(m, 0)->rta_type == IFLA_LINKINFO))
                        return add_rtattr(m, type, NULL, 0);
                else if (type == VETH_INFO_PEER && m->n_containers == 2 &&
                         GET_CONTAINER(m, 1)->rta_type == IFLA_INFO_DATA &&
                         GET_CONTAINER(m, 0)->rta_type == IFLA_LINKINFO)
                        return add_rtattr(m, type, NULL, sizeof(struct ifinfomsg));
        }

        return -ENOTSUP;
}

int sd_rtnl_message_close_container(sd_rtnl_message *m) {
        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(m->n_containers > 0, -EINVAL);

        m->n_containers --;

        return 0;
}

int sd_rtnl_message_read(sd_rtnl_message *m, unsigned short *type, void **data) {
        size_t remaining_size;
        uint16_t rtm_type;
        int r;

        assert_return(m, -EINVAL);
        assert_return(m->sealed, -EPERM);
        assert_return(m->next_rta_offset, -EINVAL);
        assert_return(type, -EINVAL);
        assert_return(data, -EINVAL);

        /* only read until the end of the current container */
        if (m->n_containers)
                remaining_size = GET_CONTAINER(m, m->n_containers - 1)->rta_len -
                                 (m->next_rta_offset -
                                  m->container_offsets[m->n_containers - 1]);
        else
                remaining_size = m->hdr->nlmsg_len - m->next_rta_offset;

        if (!RTA_OK(NEXT_RTA(m), remaining_size))
                return 0;

        /* if we read a container, enter it and return its type */
        r = sd_rtnl_message_get_type(m, &rtm_type);
        if (r < 0)
                return r;

        *type = NEXT_RTA(m)->rta_type;

        if (rtnl_message_type_is_link(rtm_type) &&
            ((m->n_containers == 0 &&
              NEXT_RTA(m)->rta_type == IFLA_LINKINFO) ||
             (m->n_containers == 1 &&
              GET_CONTAINER(m, 0)->rta_type == IFLA_LINKINFO &&
              NEXT_RTA(m)->rta_type == IFLA_INFO_DATA))) {
                *data = NULL;
                PUSH_CONTAINER(m, NEXT_RTA(m));
                UPDATE_RTA(m, RTA_DATA(NEXT_RTA(m)));
        } else {
                *data = RTA_DATA(NEXT_RTA(m));
                UPDATE_RTA(m, RTA_NEXT(NEXT_RTA(m), remaining_size));
        }

        return 1;
}

int sd_rtnl_message_exit_container(sd_rtnl_message *m) {
        assert_return(m, -EINVAL);
        assert_return(m->sealed, -EINVAL);
        assert_return(m->n_containers > 0, -EINVAL);

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

int rtnl_message_seal(sd_rtnl *nl, sd_rtnl_message *m) {
        int r;

        assert(m);
        assert(m->hdr);

        if (m->sealed)
                return -EPERM;

        if (nl)
                m->hdr->nlmsg_seq = nl->serial++;

        m->sealed = true;

        r = sd_rtnl_message_rewind(m);
        if (r < 0)
                return r;

        return 0;
}

static int message_receive_need(sd_rtnl *rtnl, size_t *need) {
        assert(rtnl);
        assert(need);

        /* ioctl(rtnl->fd, FIONREAD, &need)
           Does not appear to work on netlink sockets. libnl uses
           MSG_PEEK instead. I don't know if that is worth the
           extra roundtrip.

           For now we simply use the maximum message size the kernel
           may use (NLMSG_GOODSIZE), and then realloc to the actual
           size after reading the message (hence avoiding huge memory
           usage in case many small messages are kept around) */
        *need = page_size();
        if (*need > 8192UL)
                *need = 8192UL;

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

/* On success, the number of bytes received is returned and *ret points to the received message
 * which has a valid header and the correct size.
 * If nothing useful was received 0 is returned.
 * On failure, a negative error code is returned.
 */
int socket_read_message(sd_rtnl *nl, sd_rtnl_message **ret) {
        sd_rtnl_message *m;
        union {
                struct sockaddr sa;
                struct sockaddr_nl nl;
        } addr;
        socklen_t addr_len;
        int r;
        ssize_t k;
        size_t need;

        assert(nl);
        assert(ret);

        r = message_receive_need(nl, &need);
        if (r < 0)
                return r;

        r = message_new(nl, &m, need);
        if (r < 0)
                return r;

        /* don't allow sealing/appending to received messages */
        m->sealed = true;

        addr_len = sizeof(addr);

        k = recvfrom(nl->fd, m->hdr, need,
                        0, &addr.sa, &addr_len);
        if (k < 0)
                k = (errno == EAGAIN) ? 0 : -errno; /* no data */
        else if (k == 0)
                k = -ECONNRESET; /* connection was closed by the kernel */
        else if (addr_len != sizeof(addr.nl) ||
                        addr.nl.nl_family != AF_NETLINK)
                k = -EIO; /* not a netlink message */
        else if (addr.nl.nl_pid != 0)
                k = 0; /* not from the kernel */
        else if ((size_t) k < sizeof(struct nlmsghdr) ||
                        (size_t) k < m->hdr->nlmsg_len)
                k = -EIO; /* too small (we do accept too big though) */
        else if (m->hdr->nlmsg_pid && m->hdr->nlmsg_pid != nl->sockaddr.nl.nl_pid)
                k = 0; /* not broadcast and not for us */

        if (k > 0)
                switch (m->hdr->nlmsg_type) {
                        struct ifinfomsg *ifi;
                        struct ifaddrmsg *ifa;
                        struct rtmsg *rtm;

                        /* check that the size matches the message type */
                        case NLMSG_ERROR:
                                if (m->hdr->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr)))
                                        k = -EIO;
                                break;
                        case RTM_NEWLINK:
                        case RTM_SETLINK:
                        case RTM_DELLINK:
                        case RTM_GETLINK:
                                if (m->hdr->nlmsg_len < NLMSG_LENGTH(sizeof(struct ifinfomsg)))
                                        k = -EIO;
                                else {
                                        ifi = NLMSG_DATA(m->hdr);
                                        UPDATE_RTA(m, IFLA_RTA(ifi));
                                }
                                break;
                        case RTM_NEWADDR:
                        case RTM_DELADDR:
                        case RTM_GETADDR:
                                if (m->hdr->nlmsg_len < NLMSG_LENGTH(sizeof(struct ifaddrmsg)))
                                        k = -EIO;
                                else {
                                        ifa = NLMSG_DATA(m->hdr);
                                        UPDATE_RTA(m, IFA_RTA(ifa));
                                }
                                break;
                        case RTM_NEWROUTE:
                        case RTM_DELROUTE:
                        case RTM_GETROUTE:
                                if (m->hdr->nlmsg_len < NLMSG_LENGTH(sizeof(struct rtmsg)))
                                        k = -EIO;
                                else {
                                        rtm = NLMSG_DATA(m->hdr);
                                        UPDATE_RTA(m, RTM_RTA(rtm));
                                }
                                break;
                        case NLMSG_NOOP:
                                k = 0;
                                break;
                        default:
                                k = 0; /* ignoring message of unknown type */
                }

        if (k <= 0)
                sd_rtnl_message_unref(m);
        else {
                /* we probably allocated way too much memory, give it back */
                m->hdr = realloc(m->hdr, m->hdr->nlmsg_len);
                *ret = m;
        }

        return k;
}

int sd_rtnl_message_rewind(sd_rtnl_message *m) {
        struct ifinfomsg *ifi;
        struct ifaddrmsg *ifa;
        struct rtmsg *rtm;

        assert_return(m, -EINVAL);
        assert_return(m->sealed, -EPERM);
        assert_return(m->hdr, -EINVAL);

        switch(m->hdr->nlmsg_type) {
                case RTM_NEWLINK:
                case RTM_SETLINK:
                case RTM_GETLINK:
                case RTM_DELLINK:
                        ifi = NLMSG_DATA(m->hdr);
                        UPDATE_RTA(m, IFLA_RTA(ifi));

                        break;
                case RTM_NEWADDR:
                case RTM_GETADDR:
                case RTM_DELADDR:
                        ifa = NLMSG_DATA(m->hdr);
                        UPDATE_RTA(m, IFA_RTA(ifa));

                        break;
                case RTM_NEWROUTE:
                case RTM_GETROUTE:
                case RTM_DELROUTE:
                        rtm = NLMSG_DATA(m->hdr);
                        UPDATE_RTA(m, RTM_RTA(rtm));

                        break;
                default:
                        return -ENOTSUP;
        }

        m->n_containers = 0;

        return 0;
}
