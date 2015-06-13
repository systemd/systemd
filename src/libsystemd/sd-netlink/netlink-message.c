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

#include "util.h"
#include "socket-util.h"
#include "formats-util.h"
#include "refcnt.h"
#include "missing.h"

#include "sd-netlink.h"
#include "netlink-util.h"
#include "netlink-internal.h"
#include "netlink-types.h"

#define GET_CONTAINER(m, i) ((i) < (m)->n_containers ? (struct rtattr*)((uint8_t*)(m)->hdr + (m)->container_offsets[i]) : NULL)
#define PUSH_CONTAINER(m, new) (m)->container_offsets[(m)->n_containers ++] = (uint8_t*)(new) - (uint8_t*)(m)->hdr;

#define RTA_TYPE(rta) ((rta)->rta_type & NLA_TYPE_MASK)

int message_new_empty(sd_netlink *rtnl, sd_netlink_message **ret) {
        sd_netlink_message *m;

        assert_return(ret, -EINVAL);

        /* Note that 'rtnl' is currently unused, if we start using it internally
           we must take care to avoid problems due to mutual references between
           buses and their queued messages. See sd-bus.
         */

        m = new0(sd_netlink_message, 1);
        if (!m)
                return -ENOMEM;

        m->n_ref = REFCNT_INIT;

        m->sealed = false;

        *ret = m;

        return 0;
}

int message_new(sd_netlink *rtnl, sd_netlink_message **ret, uint16_t type) {
        _cleanup_netlink_message_unref_ sd_netlink_message *m = NULL;
        const NLType *nl_type;
        size_t size;
        int r;

        r = type_system_get_type(NULL, &nl_type, type);
        if (r < 0)
                return r;

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

int sd_netlink_message_request_dump(sd_netlink_message *m, int dump) {
        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(m->hdr->nlmsg_type == RTM_GETLINK  ||
                      m->hdr->nlmsg_type == RTM_GETADDR  ||
                      m->hdr->nlmsg_type == RTM_GETROUTE ||
                      m->hdr->nlmsg_type == RTM_GETNEIGH,
                      -EINVAL);

        if (dump)
                m->hdr->nlmsg_flags |= NLM_F_DUMP;
        else
                m->hdr->nlmsg_flags &= ~NLM_F_DUMP;

        return 0;
}

sd_netlink_message *sd_netlink_message_ref(sd_netlink_message *m) {
        if (m)
                assert_se(REFCNT_INC(m->n_ref) >= 2);

        return m;
}

sd_netlink_message *sd_netlink_message_unref(sd_netlink_message *m) {
        if (m && REFCNT_DEC(m->n_ref) == 0) {
                unsigned i;

                free(m->hdr);

                for (i = 0; i <= m->n_containers; i++)
                        free(m->rta_offset_tb[i]);

                sd_netlink_message_unref(m->next);

                free(m);
        }

        return NULL;
}

int sd_netlink_message_get_type(sd_netlink_message *m, uint16_t *type) {
        assert_return(m, -EINVAL);
        assert_return(type, -EINVAL);

        *type = m->hdr->nlmsg_type;

        return 0;
}

int sd_netlink_message_is_broadcast(sd_netlink_message *m) {
        assert_return(m, -EINVAL);

        return m->broadcast;
}

/* If successful the updated message will be correctly aligned, if
   unsuccessful the old message is untouched. */
static int add_rtattr(sd_netlink_message *m, unsigned short type, const void *data, size_t data_length) {
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
        }

        /* make sure also the padding at the end of the message is initialized */
        padding_length = (uint8_t*)m->hdr + message_length - (uint8_t*)padding;
        memzero(padding, padding_length);

        /* update message size */
        m->hdr->nlmsg_len = message_length;

        return offset;
}

static int message_attribute_has_type(sd_netlink_message *m, uint16_t attribute_type, uint16_t data_type) {
        const NLType *type;
        int r;

        r = type_system_get_type(m->container_type_system[m->n_containers], &type, attribute_type);
        if (r < 0)
                return r;

        if (type->type != data_type)
                return -EINVAL;

        return type->size;
}

int sd_netlink_message_append_string(sd_netlink_message *m, unsigned short type, const char *data) {
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
                length = strnlen(data, size+1);
                if (length > size)
                        return -EINVAL;
        } else
                length = strlen(data);

        r = add_rtattr(m, type, data, length + 1);
        if (r < 0)
                return r;

        return 0;
}

int sd_netlink_message_append_u8(sd_netlink_message *m, unsigned short type, uint8_t data) {
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


int sd_netlink_message_append_u16(sd_netlink_message *m, unsigned short type, uint16_t data) {
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

int sd_netlink_message_append_u32(sd_netlink_message *m, unsigned short type, uint32_t data) {
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

int sd_netlink_message_append_in_addr(sd_netlink_message *m, unsigned short type, const struct in_addr *data) {
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

int sd_netlink_message_append_in6_addr(sd_netlink_message *m, unsigned short type, const struct in6_addr *data) {
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

int sd_netlink_message_append_ether_addr(sd_netlink_message *m, unsigned short type, const struct ether_addr *data) {
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

int sd_netlink_message_append_cache_info(sd_netlink_message *m, unsigned short type, const struct ifa_cacheinfo *info) {
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

int sd_netlink_message_open_container(sd_netlink_message *m, unsigned short type) {
        size_t size;
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(m->n_containers < RTNL_CONTAINER_DEPTH, -ERANGE);

        r = message_attribute_has_type(m, type, NLA_NESTED);
        if (r < 0) {
                const NLTypeSystemUnion *type_system_union;
                int family;

                r = message_attribute_has_type(m, type, NLA_UNION);
                if (r < 0)
                        return r;
                size = (size_t) r;

                r = sd_rtnl_message_get_family(m, &family);
                if (r < 0)
                        return r;

                r = type_system_get_type_system_union(m->container_type_system[m->n_containers], &type_system_union, type);
                if (r < 0)
                        return r;

                r = type_system_union_protocol_get_type_system(type_system_union,
                                                               &m->container_type_system[m->n_containers + 1],
                                                               family);
                if (r < 0)
                        return r;
        } else {
                size = (size_t)r;

                r = type_system_get_type_system(m->container_type_system[m->n_containers],
                                                &m->container_type_system[m->n_containers + 1],
                                                type);
                if (r < 0)
                        return r;
        }

        r = add_rtattr(m, type | NLA_F_NESTED, NULL, size);
        if (r < 0)
                return r;

        m->container_offsets[m->n_containers ++] = r;

        return 0;
}

int sd_netlink_message_open_container_union(sd_netlink_message *m, unsigned short type, const char *key) {
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

        r = sd_netlink_message_append_string(m, type_system_union->match, key);
        if (r < 0)
                return r;

        /* do we evere need non-null size */
        r = add_rtattr(m, type, NULL, 0);
        if (r < 0)
                return r;

        m->container_offsets[m->n_containers ++] = r;

        return 0;
}


int sd_netlink_message_close_container(sd_netlink_message *m) {
        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(m->n_containers > 0, -EINVAL);

        m->container_type_system[m->n_containers] = NULL;
        m->n_containers --;

        return 0;
}

int rtnl_message_read_internal(sd_netlink_message *m, unsigned short type, void **data) {
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

int sd_netlink_message_read_string(sd_netlink_message *m, unsigned short type, const char **data) {
        int r;
        void *attr_data;

        assert_return(m, -EINVAL);

        r = message_attribute_has_type(m, type, NLA_STRING);
        if (r < 0)
                return r;

        r = rtnl_message_read_internal(m, type, &attr_data);
        if (r < 0)
                return r;
        else if (strnlen(attr_data, r) >= (size_t) r)
                return -EIO;

        if (data)
                *data = (const char *) attr_data;

        return 0;
}

int sd_netlink_message_read_u8(sd_netlink_message *m, unsigned short type, uint8_t *data) {
        int r;
        void *attr_data;

        assert_return(m, -EINVAL);

        r = message_attribute_has_type(m, type, NLA_U8);
        if (r < 0)
                return r;

        r = rtnl_message_read_internal(m, type, &attr_data);
        if (r < 0)
                return r;
        else if ((size_t) r < sizeof(uint8_t))
                return -EIO;

        if (data)
                *data = *(uint8_t *) attr_data;

        return 0;
}

int sd_netlink_message_read_u16(sd_netlink_message *m, unsigned short type, uint16_t *data) {
        int r;
        void *attr_data;

        assert_return(m, -EINVAL);

        r = message_attribute_has_type(m, type, NLA_U16);
        if (r < 0)
                return r;

        r = rtnl_message_read_internal(m, type, &attr_data);
        if (r < 0)
                return r;
        else if ((size_t) r < sizeof(uint16_t))
                return -EIO;

        if (data)
                *data = *(uint16_t *) attr_data;

        return 0;
}

int sd_netlink_message_read_u32(sd_netlink_message *m, unsigned short type, uint32_t *data) {
        int r;
        void *attr_data;

        assert_return(m, -EINVAL);

        r = message_attribute_has_type(m, type, NLA_U32);
        if (r < 0)
                return r;

        r = rtnl_message_read_internal(m, type, &attr_data);
        if (r < 0)
                return r;
        else if ((size_t)r < sizeof(uint32_t))
                return -EIO;

        if (data)
                *data = *(uint32_t *) attr_data;

        return 0;
}

int sd_netlink_message_read_ether_addr(sd_netlink_message *m, unsigned short type, struct ether_addr *data) {
        int r;
        void *attr_data;

        assert_return(m, -EINVAL);

        r = message_attribute_has_type(m, type, NLA_ETHER_ADDR);
        if (r < 0)
                return r;

        r = rtnl_message_read_internal(m, type, &attr_data);
        if (r < 0)
                return r;
        else if ((size_t)r < sizeof(struct ether_addr))
                return -EIO;

        if (data)
                memcpy(data, attr_data, sizeof(struct ether_addr));

        return 0;
}

int sd_netlink_message_read_cache_info(sd_netlink_message *m, unsigned short type, struct ifa_cacheinfo *info) {
        int r;
        void *attr_data;

        assert_return(m, -EINVAL);

        r = message_attribute_has_type(m, type, NLA_CACHE_INFO);
        if (r < 0)
                return r;

        r = rtnl_message_read_internal(m, type, &attr_data);
        if (r < 0)
                return r;
        else if ((size_t)r < sizeof(struct ifa_cacheinfo))
                return -EIO;

        if (info)
                memcpy(info, attr_data, sizeof(struct ifa_cacheinfo));

        return 0;
}

int sd_netlink_message_read_in_addr(sd_netlink_message *m, unsigned short type, struct in_addr *data) {
        int r;
        void *attr_data;

        assert_return(m, -EINVAL);

        r = message_attribute_has_type(m, type, NLA_IN_ADDR);
        if (r < 0)
                return r;

        r = rtnl_message_read_internal(m, type, &attr_data);
        if (r < 0)
                return r;
        else if ((size_t)r < sizeof(struct in_addr))
                return -EIO;

        if (data)
                memcpy(data, attr_data, sizeof(struct in_addr));

        return 0;
}

int sd_netlink_message_read_in6_addr(sd_netlink_message *m, unsigned short type, struct in6_addr *data) {
        int r;
        void *attr_data;

        assert_return(m, -EINVAL);

        r = message_attribute_has_type(m, type, NLA_IN_ADDR);
        if (r < 0)
                return r;

        r = rtnl_message_read_internal(m, type, &attr_data);
        if (r < 0)
                return r;
        else if ((size_t)r < sizeof(struct in6_addr))
                return -EIO;

        if (data)
                memcpy(data, attr_data, sizeof(struct in6_addr));

        return 0;
}

int sd_netlink_message_enter_container(sd_netlink_message *m, unsigned short type) {
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

                r = type_system_get_type_system_union(m->container_type_system[m->n_containers],
                                                      &type_system_union,
                                                      type);
                if (r < 0)
                        return r;

                switch (type_system_union->match_type) {
                case NL_MATCH_SIBLING:
                {
                        const char *key;

                        r = sd_netlink_message_read_string(m, type_system_union->match, &key);
                        if (r < 0)
                                return r;

                        r = type_system_union_get_type_system(type_system_union,
                                                              &type_system,
                                                              key);
                        if (r < 0)
                                return r;

                        break;
                }
                case NL_MATCH_PROTOCOL:
                {
                        int family;

                        r = sd_rtnl_message_get_family(m, &family);
                        if (r < 0)
                                return r;

                        r = type_system_union_protocol_get_type_system(type_system_union,
                                                                       &type_system,
                                                                       family);
                        if (r < 0)
                                return r;

                        break;
                }
                default:
                        assert_not_reached("sd-netlink: invalid type system union type");
                }
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

int sd_netlink_message_exit_container(sd_netlink_message *m) {
        assert_return(m, -EINVAL);
        assert_return(m->sealed, -EINVAL);
        assert_return(m->n_containers > 0, -EINVAL);

        free(m->rta_offset_tb[m->n_containers]);
        m->rta_offset_tb[m->n_containers] = NULL;
        m->container_type_system[m->n_containers] = NULL;

        m->n_containers --;

        return 0;
}

uint32_t rtnl_message_get_serial(sd_netlink_message *m) {
        assert(m);
        assert(m->hdr);

        return m->hdr->nlmsg_seq;
}

int sd_netlink_message_is_error(sd_netlink_message *m) {
        assert_return(m, 0);
        assert_return(m->hdr, 0);

        return m->hdr->nlmsg_type == NLMSG_ERROR;
}

int sd_netlink_message_get_errno(sd_netlink_message *m) {
        struct nlmsgerr *err;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);

        if (!sd_netlink_message_is_error(m))
                return 0;

        err = NLMSG_DATA(m->hdr);

        return err->error;
}

int rtnl_message_parse(sd_netlink_message *m,
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
                type = RTA_TYPE(rta);

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

int sd_netlink_message_rewind(sd_netlink_message *m) {
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

void rtnl_message_seal(sd_netlink_message *m) {
        assert(m);
        assert(!m->sealed);

        m->sealed = true;
}

sd_netlink_message *sd_netlink_message_next(sd_netlink_message *m) {
        assert_return(m, NULL);

        return m->next;
}
