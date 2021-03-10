/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <stdbool.h>
#include <unistd.h>

#include "sd-netlink.h"

#include "alloc-util.h"
#include "format-util.h"
#include "memory-util.h"
#include "netlink-internal.h"
#include "netlink-types.h"
#include "netlink-util.h"
#include "socket-util.h"
#include "strv.h"

#define GET_CONTAINER(m, i) ((struct rtattr*)((uint8_t*)(m)->hdr + (m)->containers[i].offset))

#define RTA_TYPE(rta) ((rta)->rta_type & NLA_TYPE_MASK)
#define RTA_FLAGS(rta) ((rta)->rta_type & ~NLA_TYPE_MASK)

int message_new_empty(sd_netlink *rtnl, sd_netlink_message **ret) {
        sd_netlink_message *m;

        assert_return(ret, -EINVAL);

        /* Note that 'rtnl' is currently unused, if we start using it internally
           we must take care to avoid problems due to mutual references between
           buses and their queued messages. See sd-bus.
         */

        m = new(sd_netlink_message, 1);
        if (!m)
                return -ENOMEM;

        *m = (sd_netlink_message) {
                .n_ref = 1,
                .protocol = rtnl->protocol,
                .sealed = false,
        };

        *ret = m;

        return 0;
}

int message_new(sd_netlink *rtnl, sd_netlink_message **ret, uint16_t type) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        const NLType *nl_type;
        size_t size;
        int r;

        assert_return(rtnl, -EINVAL);

        r = type_system_root_get_type(rtnl, &nl_type, type);
        if (r < 0)
                return r;

        if (type_get_type(nl_type) != NETLINK_TYPE_NESTED)
                return -EINVAL;

        r = message_new_empty(rtnl, &m);
        if (r < 0)
                return r;

        size = NLMSG_SPACE(type_get_size(nl_type));

        assert(size >= sizeof(struct nlmsghdr));
        m->hdr = malloc0(size);
        if (!m->hdr)
                return -ENOMEM;

        m->hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

        type_get_type_system(nl_type, &m->containers[0].type_system);
        m->hdr->nlmsg_len = size;
        m->hdr->nlmsg_type = type;

        *ret = TAKE_PTR(m);

        return 0;
}

int sd_netlink_message_request_dump(sd_netlink_message *m, int dump) {
        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);

        assert_return(IN_SET(m->hdr->nlmsg_type,
                             RTM_GETLINK, RTM_GETLINKPROP, RTM_GETADDR, RTM_GETROUTE, RTM_GETNEIGH,
                             RTM_GETRULE, RTM_GETADDRLABEL, RTM_GETNEXTHOP), -EINVAL);

        SET_FLAG(m->hdr->nlmsg_flags, NLM_F_DUMP, dump);

        return 0;
}

DEFINE_TRIVIAL_REF_FUNC(sd_netlink_message, sd_netlink_message);

sd_netlink_message *sd_netlink_message_unref(sd_netlink_message *m) {
        while (m && --m->n_ref == 0) {
                unsigned i;

                free(m->hdr);

                for (i = 0; i <= m->n_containers; i++)
                        free(m->containers[i].attributes);

                sd_netlink_message *t = m;
                m = m->next;
                free(t);
        }

        return NULL;
}

int sd_netlink_message_get_type(const sd_netlink_message *m, uint16_t *type) {
        assert_return(m, -EINVAL);
        assert_return(type, -EINVAL);

        *type = m->hdr->nlmsg_type;

        return 0;
}

int sd_netlink_message_set_flags(sd_netlink_message *m, uint16_t flags) {
        assert_return(m, -EINVAL);
        assert_return(flags, -EINVAL);

        m->hdr->nlmsg_flags = flags;

        return 0;
}

int sd_netlink_message_is_broadcast(const sd_netlink_message *m) {
        assert_return(m, -EINVAL);

        return m->broadcast;
}

/* If successful the updated message will be correctly aligned, if
   unsuccessful the old message is untouched. */
static int add_rtattr(sd_netlink_message *m, unsigned short type, const void *data, size_t data_length) {
        size_t message_length;
        struct nlmsghdr *new_hdr;
        struct rtattr *rta;
        int offset;

        assert(m);
        assert(m->hdr);
        assert(!m->sealed);
        assert(NLMSG_ALIGN(m->hdr->nlmsg_len) == m->hdr->nlmsg_len);
        assert(!data || data_length > 0);

        /* get the new message size (with padding at the end) */
        message_length = m->hdr->nlmsg_len + RTA_SPACE(data_length);

        /* buffer should be smaller than both one page or 8K to be accepted by the kernel */
        if (message_length > MIN(page_size(), 8192UL))
                return -ENOBUFS;

        /* realloc to fit the new attribute */
        new_hdr = realloc(m->hdr, message_length);
        if (!new_hdr)
                return -ENOMEM;
        m->hdr = new_hdr;

        /* get pointer to the attribute we are about to add */
        rta = (struct rtattr *) ((uint8_t *) m->hdr + m->hdr->nlmsg_len);

        rtattr_append_attribute_internal(rta, type, data, data_length);

        /* if we are inside containers, extend them */
        for (unsigned i = 0; i < m->n_containers; i++)
                GET_CONTAINER(m, i)->rta_len += RTA_SPACE(data_length);

        /* update message size */
        offset = m->hdr->nlmsg_len;
        m->hdr->nlmsg_len = message_length;

        /* return old message size */
        return offset;
}

static int message_attribute_has_type(sd_netlink_message *m, size_t *out_size, uint16_t attribute_type, uint16_t data_type) {
        const NLType *type;
        int r;

        assert(m);

        r = type_system_get_type(m->containers[m->n_containers].type_system, &type, attribute_type);
        if (r < 0)
                return r;

        if (type_get_type(type) != data_type)
                return -EINVAL;

        if (out_size)
                *out_size = type_get_size(type);
        return 0;
}

int sd_netlink_message_append_string(sd_netlink_message *m, unsigned short type, const char *data) {
        size_t length, size;
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(data, -EINVAL);

        r = message_attribute_has_type(m, &size, type, NETLINK_TYPE_STRING);
        if (r < 0)
                return r;

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

int sd_netlink_message_append_strv(sd_netlink_message *m, unsigned short type, char * const *data) {
        size_t length, size;
        char * const *p;
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(data, -EINVAL);

        r = message_attribute_has_type(m, &size, type, NETLINK_TYPE_STRING);
        if (r < 0)
                return r;

        STRV_FOREACH(p, data) {
                if (size) {
                        length = strnlen(*p, size+1);
                        if (length > size)
                                return -EINVAL;
                } else
                        length = strlen(*p);

                r = add_rtattr(m, type, *p, length + 1);
                if (r < 0)
                        return r;
        }

        return 0;
}

int sd_netlink_message_append_flag(sd_netlink_message *m, unsigned short type) {
        size_t size;
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);

        r = message_attribute_has_type(m, &size, type, NETLINK_TYPE_FLAG);
        if (r < 0)
                return r;

        r = add_rtattr(m, type, NULL, 0);
        if (r < 0)
                return r;

        return 0;
}

int sd_netlink_message_append_u8(sd_netlink_message *m, unsigned short type, uint8_t data) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);

        r = message_attribute_has_type(m, NULL, type, NETLINK_TYPE_U8);
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

        r = message_attribute_has_type(m, NULL, type, NETLINK_TYPE_U16);
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

        r = message_attribute_has_type(m, NULL, type, NETLINK_TYPE_U32);
        if (r < 0)
                return r;

        r = add_rtattr(m, type, &data, sizeof(uint32_t));
        if (r < 0)
                return r;

        return 0;
}

int sd_netlink_message_append_u64(sd_netlink_message *m, unsigned short type, uint64_t data) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);

        r = message_attribute_has_type(m, NULL, type, NETLINK_TYPE_U64);
        if (r < 0)
                return r;

        r = add_rtattr(m, type, &data, sizeof(uint64_t));
        if (r < 0)
                return r;

        return 0;
}

int sd_netlink_message_append_s8(sd_netlink_message *m, unsigned short type, int8_t data) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);

        r = message_attribute_has_type(m, NULL, type, NETLINK_TYPE_S8);
        if (r < 0)
                return r;

        r = add_rtattr(m, type, &data, sizeof(int8_t));
        if (r < 0)
                return r;

        return 0;
}

int sd_netlink_message_append_s16(sd_netlink_message *m, unsigned short type, int16_t data) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);

        r = message_attribute_has_type(m, NULL, type, NETLINK_TYPE_S16);
        if (r < 0)
                return r;

        r = add_rtattr(m, type, &data, sizeof(int16_t));
        if (r < 0)
                return r;

        return 0;
}

int sd_netlink_message_append_s32(sd_netlink_message *m, unsigned short type, int32_t data) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);

        r = message_attribute_has_type(m, NULL, type, NETLINK_TYPE_S32);
        if (r < 0)
                return r;

        r = add_rtattr(m, type, &data, sizeof(int32_t));
        if (r < 0)
                return r;

        return 0;
}

int sd_netlink_message_append_s64(sd_netlink_message *m, unsigned short type, int64_t data) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);

        r = message_attribute_has_type(m, NULL, type, NETLINK_TYPE_S64);
        if (r < 0)
                return r;

        r = add_rtattr(m, type, &data, sizeof(int64_t));
        if (r < 0)
                return r;

        return 0;
}

int sd_netlink_message_append_data(sd_netlink_message *m, unsigned short type, const void *data, size_t len) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);

        r = add_rtattr(m, type, data, len);
        if (r < 0)
                return r;

        return 0;
}

int netlink_message_append_in_addr_union(sd_netlink_message *m, unsigned short type, int family, const union in_addr_union *data) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(data, -EINVAL);
        assert_return(IN_SET(family, AF_INET, AF_INET6), -EINVAL);

        r = message_attribute_has_type(m, NULL, type, NETLINK_TYPE_IN_ADDR);
        if (r < 0)
                return r;

        r = add_rtattr(m, type, data, FAMILY_ADDRESS_SIZE(family));
        if (r < 0)
                return r;

        return 0;
}

int sd_netlink_message_append_in_addr(sd_netlink_message *m, unsigned short type, const struct in_addr *data) {
        return netlink_message_append_in_addr_union(m, type, AF_INET, (const union in_addr_union *) data);
}

int sd_netlink_message_append_in6_addr(sd_netlink_message *m, unsigned short type, const struct in6_addr *data) {
        return netlink_message_append_in_addr_union(m, type, AF_INET6, (const union in_addr_union *) data);
}

int netlink_message_append_sockaddr_union(sd_netlink_message *m, unsigned short type, const union sockaddr_union *data) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(data, -EINVAL);
        assert_return(IN_SET(data->sa.sa_family, AF_INET, AF_INET6), -EINVAL);

        r = message_attribute_has_type(m, NULL, type, NETLINK_TYPE_SOCKADDR);
        if (r < 0)
                return r;

        r = add_rtattr(m, type, data, data->sa.sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
        if (r < 0)
                return r;

        return 0;
}

int sd_netlink_message_append_sockaddr_in(sd_netlink_message *m, unsigned short type, const struct sockaddr_in *data) {
        return netlink_message_append_sockaddr_union(m, type, (const union sockaddr_union *) data);
}

int sd_netlink_message_append_sockaddr_in6(sd_netlink_message *m, unsigned short type, const struct sockaddr_in6 *data) {
        return netlink_message_append_sockaddr_union(m, type, (const union sockaddr_union *) data);
}

int sd_netlink_message_append_ether_addr(sd_netlink_message *m, unsigned short type, const struct ether_addr *data) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(data, -EINVAL);

        r = message_attribute_has_type(m, NULL, type, NETLINK_TYPE_ETHER_ADDR);
        if (r < 0)
                return r;

        r = add_rtattr(m, type, data, ETH_ALEN);
        if (r < 0)
                return r;

        return 0;
}

int netlink_message_append_hw_addr(sd_netlink_message *m, unsigned short type, const hw_addr_data *data) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(data, -EINVAL);
        assert_return(data->length > 0, -EINVAL);

        r = message_attribute_has_type(m, NULL, type, NETLINK_TYPE_ETHER_ADDR);
        if (r < 0)
                return r;

        r = add_rtattr(m, type, data->addr.bytes, data->length);
        if (r < 0)
                return r;

        return 0;
}

int sd_netlink_message_append_cache_info(sd_netlink_message *m, unsigned short type, const struct ifa_cacheinfo *info) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(info, -EINVAL);

        r = message_attribute_has_type(m, NULL, type, NETLINK_TYPE_CACHE_INFO);
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
        /* m->containers[m->n_containers + 1] is accessed both in read and write. Prevent access out of bound */
        assert_return(m->n_containers < (RTNL_CONTAINER_DEPTH - 1), -ERANGE);

        r = message_attribute_has_type(m, &size, type, NETLINK_TYPE_NESTED);
        if (r < 0) {
                const NLTypeSystemUnion *type_system_union;
                int family;

                r = message_attribute_has_type(m, &size, type, NETLINK_TYPE_UNION);
                if (r < 0)
                        return r;

                r = sd_rtnl_message_get_family(m, &family);
                if (r < 0)
                        return r;

                r = type_system_get_type_system_union(m->containers[m->n_containers].type_system, &type_system_union, type);
                if (r < 0)
                        return r;

                r = type_system_union_protocol_get_type_system(type_system_union,
                                                               &m->containers[m->n_containers + 1].type_system,
                                                               family);
                if (r < 0)
                        return r;
        } else {
                r = type_system_get_type_system(m->containers[m->n_containers].type_system,
                                                &m->containers[m->n_containers + 1].type_system,
                                                type);
                if (r < 0)
                        return r;
        }

        r = add_rtattr(m, type | NLA_F_NESTED, NULL, size);
        if (r < 0)
                return r;

        m->containers[m->n_containers++].offset = r;

        return 0;
}

int sd_netlink_message_open_container_union(sd_netlink_message *m, unsigned short type, const char *key) {
        const NLTypeSystemUnion *type_system_union;
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(m->n_containers < (RTNL_CONTAINER_DEPTH - 1), -ERANGE);

        r = type_system_get_type_system_union(m->containers[m->n_containers].type_system, &type_system_union, type);
        if (r < 0)
                return r;

        r = type_system_union_get_type_system(type_system_union,
                                              &m->containers[m->n_containers + 1].type_system,
                                              key);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_string(m, type_system_union->match, key);
        if (r < 0)
                return r;

        /* do we ever need non-null size */
        r = add_rtattr(m, type | NLA_F_NESTED, NULL, 0);
        if (r < 0)
                return r;

        m->containers[m->n_containers++].offset = r;

        return 0;
}

int sd_netlink_message_close_container(sd_netlink_message *m) {
        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(m->n_containers > 0, -EINVAL);

        m->containers[m->n_containers].type_system = NULL;
        m->containers[m->n_containers].offset = 0;
        m->n_containers--;

        return 0;
}

int sd_netlink_message_open_array(sd_netlink_message *m, uint16_t type) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(m->n_containers < (RTNL_CONTAINER_DEPTH - 1), -ERANGE);

        r = add_rtattr(m, type | NLA_F_NESTED, NULL, 0);
        if (r < 0)
                return r;

        m->containers[m->n_containers].offset = r;
        m->n_containers++;
        m->containers[m->n_containers].type_system = m->containers[m->n_containers - 1].type_system;

        return 0;
}

int sd_netlink_message_cancel_array(sd_netlink_message *m) {
        uint32_t rta_len;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(m->n_containers > 1, -EINVAL);

        rta_len = GET_CONTAINER(m, (m->n_containers - 1))->rta_len;

        for (unsigned i = 0; i < m->n_containers; i++)
                GET_CONTAINER(m, i)->rta_len -= rta_len;

        m->hdr->nlmsg_len -= rta_len;

        m->n_containers--;
        m->containers[m->n_containers].type_system = NULL;

        return 0;
}

static int netlink_message_read_internal(
                sd_netlink_message *m,
                unsigned short type,
                void **ret_data,
                bool *ret_net_byteorder) {

        struct netlink_attribute *attribute;
        struct rtattr *rta;

        assert_return(m, -EINVAL);
        assert_return(m->sealed, -EPERM);

        assert(m->n_containers < RTNL_CONTAINER_DEPTH);

        if (!m->containers[m->n_containers].attributes)
                return -ENODATA;

        if (type >= m->containers[m->n_containers].n_attributes)
                return -ENODATA;

        attribute = &m->containers[m->n_containers].attributes[type];

        if (attribute->offset == 0)
                return -ENODATA;

        rta = (struct rtattr*)((uint8_t *) m->hdr + attribute->offset);

        if (ret_data)
                *ret_data = RTA_DATA(rta);

        if (ret_net_byteorder)
                *ret_net_byteorder = attribute->net_byteorder;

        return RTA_PAYLOAD(rta);
}

int sd_netlink_message_read(sd_netlink_message *m, unsigned short type, size_t size, void *data) {
        void *attr_data;
        int r;

        assert_return(m, -EINVAL);

        r = netlink_message_read_internal(m, type, &attr_data, NULL);
        if (r < 0)
                return r;

        if ((size_t) r < size)
                return -EIO;

        if (data)
                memcpy(data, attr_data, size);

        return r;
}

int sd_netlink_message_read_data(sd_netlink_message *m, unsigned short type, size_t *ret_size, void **ret_data) {
        void *attr_data, *data;
        int r;

        assert_return(m, -EINVAL);

        r = netlink_message_read_internal(m, type, &attr_data, NULL);
        if (r < 0)
                return r;

        if (ret_data) {
                data = memdup(attr_data, r);
                if (!data)
                        return -ENOMEM;

                *ret_data = data;
        }

        if (ret_size)
                *ret_size = r;

        return r;
}

int sd_netlink_message_read_string_strdup(sd_netlink_message *m, unsigned short type, char **data) {
        void *attr_data;
        char *str;
        int r;

        assert_return(m, -EINVAL);

        r = message_attribute_has_type(m, NULL, type, NETLINK_TYPE_STRING);
        if (r < 0)
                return r;

        r = netlink_message_read_internal(m, type, &attr_data, NULL);
        if (r < 0)
                return r;

        if (data) {
                str = strndup(attr_data, r);
                if (!str)
                        return -ENOMEM;

                *data = str;
        }

        return 0;
}

int sd_netlink_message_read_string(sd_netlink_message *m, unsigned short type, const char **data) {
        int r;
        void *attr_data;

        assert_return(m, -EINVAL);

        r = message_attribute_has_type(m, NULL, type, NETLINK_TYPE_STRING);
        if (r < 0)
                return r;

        r = netlink_message_read_internal(m, type, &attr_data, NULL);
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

        r = message_attribute_has_type(m, NULL, type, NETLINK_TYPE_U8);
        if (r < 0)
                return r;

        r = netlink_message_read_internal(m, type, &attr_data, NULL);
        if (r < 0)
                return r;
        else if ((size_t) r < sizeof(uint8_t))
                return -EIO;

        if (data)
                *data = *(uint8_t *) attr_data;

        return 0;
}

int sd_netlink_message_read_u16(sd_netlink_message *m, unsigned short type, uint16_t *data) {
        void *attr_data;
        bool net_byteorder;
        int r;

        assert_return(m, -EINVAL);

        r = message_attribute_has_type(m, NULL, type, NETLINK_TYPE_U16);
        if (r < 0)
                return r;

        r = netlink_message_read_internal(m, type, &attr_data, &net_byteorder);
        if (r < 0)
                return r;
        else if ((size_t) r < sizeof(uint16_t))
                return -EIO;

        if (data) {
                if (net_byteorder)
                        *data = be16toh(*(uint16_t *) attr_data);
                else
                        *data = *(uint16_t *) attr_data;
        }

        return 0;
}

int sd_netlink_message_read_u32(sd_netlink_message *m, unsigned short type, uint32_t *data) {
        void *attr_data;
        bool net_byteorder;
        int r;

        assert_return(m, -EINVAL);

        r = message_attribute_has_type(m, NULL, type, NETLINK_TYPE_U32);
        if (r < 0)
                return r;

        r = netlink_message_read_internal(m, type, &attr_data, &net_byteorder);
        if (r < 0)
                return r;
        else if ((size_t) r < sizeof(uint32_t))
                return -EIO;

        if (data) {
                if (net_byteorder)
                        *data = be32toh(*(uint32_t *) attr_data);
                else
                        *data = *(uint32_t *) attr_data;
        }

        return 0;
}

int sd_netlink_message_read_ether_addr(sd_netlink_message *m, unsigned short type, struct ether_addr *data) {
        int r;
        void *attr_data;

        assert_return(m, -EINVAL);

        r = message_attribute_has_type(m, NULL, type, NETLINK_TYPE_ETHER_ADDR);
        if (r < 0)
                return r;

        r = netlink_message_read_internal(m, type, &attr_data, NULL);
        if (r < 0)
                return r;
        else if ((size_t) r < sizeof(struct ether_addr))
                return -EIO;

        if (data)
                memcpy(data, attr_data, sizeof(struct ether_addr));

        return 0;
}

int netlink_message_read_hw_addr(sd_netlink_message *m, unsigned short type, hw_addr_data *data) {
        int r;
        void *attr_data;

        assert_return(m, -EINVAL);

        r = message_attribute_has_type(m, NULL, type, NETLINK_TYPE_ETHER_ADDR);
        if (r < 0)
                return r;

        r = netlink_message_read_internal(m, type, &attr_data, NULL);
        if (r < 0)
                return r;
        else if ((size_t) r > sizeof(union hw_addr_union))
                return -EIO;

        if (data) {
                memcpy(data->addr.bytes, attr_data, r);
                data->length = r;
        }

        return 0;
}

int sd_netlink_message_read_cache_info(sd_netlink_message *m, unsigned short type, struct ifa_cacheinfo *info) {
        int r;
        void *attr_data;

        assert_return(m, -EINVAL);

        r = message_attribute_has_type(m, NULL, type, NETLINK_TYPE_CACHE_INFO);
        if (r < 0)
                return r;

        r = netlink_message_read_internal(m, type, &attr_data, NULL);
        if (r < 0)
                return r;
        else if ((size_t) r < sizeof(struct ifa_cacheinfo))
                return -EIO;

        if (info)
                memcpy(info, attr_data, sizeof(struct ifa_cacheinfo));

        return 0;
}

int netlink_message_read_in_addr_union(sd_netlink_message *m, unsigned short type, int family, union in_addr_union *data) {
        void *attr_data;
        int r;

        assert_return(m, -EINVAL);
        assert_return(IN_SET(family, AF_INET, AF_INET6), -EINVAL);

        r = message_attribute_has_type(m, NULL, type, NETLINK_TYPE_IN_ADDR);
        if (r < 0)
                return r;

        r = netlink_message_read_internal(m, type, &attr_data, NULL);
        if (r < 0)
                return r;
        else if ((size_t) r < FAMILY_ADDRESS_SIZE(family))
                return -EIO;

        if (data)
                memcpy(data, attr_data, FAMILY_ADDRESS_SIZE(family));

        return 0;
}

int sd_netlink_message_read_in_addr(sd_netlink_message *m, unsigned short type, struct in_addr *data) {
        union in_addr_union u;
        int r;

        r = netlink_message_read_in_addr_union(m, type, AF_INET, &u);
        if (r >= 0 && data)
                *data = u.in;

        return r;
}

int sd_netlink_message_read_in6_addr(sd_netlink_message *m, unsigned short type, struct in6_addr *data) {
        union in_addr_union u;
        int r;

        r = netlink_message_read_in_addr_union(m, type, AF_INET6, &u);
        if (r >= 0 && data)
                *data = u.in6;

        return r;
}

int sd_netlink_message_has_flag(sd_netlink_message *m, unsigned short type) {
        void *attr_data;
        int r;

        assert_return(m, -EINVAL);

        /* This returns 1 when the flag is set, 0 when not set, negative errno on error. */

        r = message_attribute_has_type(m, NULL, type, NETLINK_TYPE_FLAG);
        if (r < 0)
                return r;

        r = netlink_message_read_internal(m, type, &attr_data, NULL);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return r;

        return 1;
}

int sd_netlink_message_read_strv(sd_netlink_message *m, unsigned short container_type, unsigned short type_id, char ***ret) {
        _cleanup_strv_free_ char **s = NULL;
        const NLTypeSystem *type_system;
        const NLType *nl_type;
        struct rtattr *rta;
        void *container;
        size_t rt_len;
        int r;

        assert_return(m, -EINVAL);
        assert_return(m->n_containers < RTNL_CONTAINER_DEPTH, -EINVAL);

        r = type_system_get_type(m->containers[m->n_containers].type_system,
                                 &nl_type,
                                 container_type);
        if (r < 0)
                return r;

        if (type_get_type(nl_type) != NETLINK_TYPE_NESTED)
                return -EINVAL;

        r = type_system_get_type_system(m->containers[m->n_containers].type_system,
                                        &type_system,
                                        container_type);
        if (r < 0)
                return r;

        r = type_system_get_type(type_system, &nl_type, type_id);
        if (r < 0)
                return r;

        if (type_get_type(nl_type) != NETLINK_TYPE_STRING)
                return -EINVAL;

        r = netlink_message_read_internal(m, container_type, &container, NULL);
        if (r < 0)
                return r;

        rt_len = (size_t) r;
        rta = container;

        /* RTA_OK() macro compares with rta->rt_len, which is unsigned short, and
         * LGTM.com analysis does not like the type difference. Hence, here we
         * introduce an unsigned short variable as a workaround. */
        unsigned short len = rt_len;
        for (; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
                unsigned short type;

                type = RTA_TYPE(rta);
                if (type != type_id)
                        continue;

                r = strv_extend(&s, RTA_DATA(rta));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(s);
        return 0;
}

static int netlink_container_parse(sd_netlink_message *m,
                                   struct netlink_container *container,
                                   struct rtattr *rta,
                                   size_t rt_len) {
        _cleanup_free_ struct netlink_attribute *attributes = NULL;
        size_t n_allocated = 0;

        /* RTA_OK() macro compares with rta->rt_len, which is unsigned short, and
         * LGTM.com analysis does not like the type difference. Hence, here we
         * introduce an unsigned short variable as a workaround. */
        unsigned short len = rt_len;
        for (; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
                unsigned short type;

                type = RTA_TYPE(rta);

                if (!GREEDY_REALLOC0(attributes, n_allocated, type + 1))
                        return -ENOMEM;

                if (attributes[type].offset != 0)
                        log_debug("rtnl: message parse - overwriting repeated attribute");

                attributes[type].offset = (uint8_t *) rta - (uint8_t *) m->hdr;
                attributes[type].nested = RTA_FLAGS(rta) & NLA_F_NESTED;
                attributes[type].net_byteorder = RTA_FLAGS(rta) & NLA_F_NET_BYTEORDER;
        }

        container->attributes = TAKE_PTR(attributes);
        container->n_attributes = n_allocated;

        return 0;
}

int sd_netlink_message_enter_container(sd_netlink_message *m, unsigned short type_id) {
        const NLType *nl_type;
        const NLTypeSystem *type_system;
        void *container;
        uint16_t type;
        size_t size;
        int r;

        assert_return(m, -EINVAL);
        assert_return(m->n_containers < (RTNL_CONTAINER_DEPTH - 1), -EINVAL);

        r = type_system_get_type(m->containers[m->n_containers].type_system,
                                 &nl_type,
                                 type_id);
        if (r < 0)
                return r;

        type = type_get_type(nl_type);

        if (type == NETLINK_TYPE_NESTED) {
                r = type_system_get_type_system(m->containers[m->n_containers].type_system,
                                                &type_system,
                                                type_id);
                if (r < 0)
                        return r;
        } else if (type == NETLINK_TYPE_UNION) {
                const NLTypeSystemUnion *type_system_union;

                r = type_system_get_type_system_union(m->containers[m->n_containers].type_system,
                                                      &type_system_union,
                                                      type_id);
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

        r = netlink_message_read_internal(m, type_id, &container, NULL);
        if (r < 0)
                return r;

        size = (size_t) r;
        m->n_containers++;

        r = netlink_container_parse(m,
                                    &m->containers[m->n_containers],
                                    container,
                                    size);
        if (r < 0) {
                m->n_containers--;
                return r;
        }

        m->containers[m->n_containers].type_system = type_system;

        return 0;
}

int sd_netlink_message_enter_array(sd_netlink_message *m, unsigned short type_id) {
        void *container;
        size_t size;
        int r;

        assert_return(m, -EINVAL);
        assert_return(m->n_containers < (RTNL_CONTAINER_DEPTH - 1), -EINVAL);

        r = netlink_message_read_internal(m, type_id, &container, NULL);
        if (r < 0)
                return r;

        size = (size_t) r;
        m->n_containers++;

        r = netlink_container_parse(m,
                                    &m->containers[m->n_containers],
                                    container,
                                    size);
        if (r < 0) {
                m->n_containers--;
                return r;
        }

        m->containers[m->n_containers].type_system = m->containers[m->n_containers - 1].type_system;

        return 0;
}

int sd_netlink_message_exit_container(sd_netlink_message *m) {
        assert_return(m, -EINVAL);
        assert_return(m->sealed, -EINVAL);
        assert_return(m->n_containers > 0, -EINVAL);

        m->containers[m->n_containers].attributes = mfree(m->containers[m->n_containers].attributes);
        m->containers[m->n_containers].type_system = NULL;

        m->n_containers--;

        return 0;
}

uint32_t rtnl_message_get_serial(sd_netlink_message *m) {
        assert(m);
        assert(m->hdr);

        return m->hdr->nlmsg_seq;
}

int sd_netlink_message_is_error(const sd_netlink_message *m) {
        assert_return(m, 0);
        assert_return(m->hdr, 0);

        return m->hdr->nlmsg_type == NLMSG_ERROR;
}

int sd_netlink_message_get_errno(const sd_netlink_message *m) {
        struct nlmsgerr *err;

        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);

        if (!sd_netlink_message_is_error(m))
                return 0;

        err = NLMSG_DATA(m->hdr);

        return err->error;
}

static int netlink_message_parse_error(sd_netlink_message *m) {
        struct nlmsgerr *err = NLMSG_DATA(m->hdr);
        size_t hlen = sizeof(struct nlmsgerr);

        /* no TLVs, nothing to do here */
        if (!(m->hdr->nlmsg_flags & NLM_F_ACK_TLVS))
                return 0;

        /* if NLM_F_CAPPED is set then the inner err msg was capped */
        if (!(m->hdr->nlmsg_flags & NLM_F_CAPPED))
                hlen += err->msg.nlmsg_len - sizeof(struct nlmsghdr);

        if (m->hdr->nlmsg_len <= NLMSG_SPACE(hlen))
                return 0;

        return netlink_container_parse(m,
                                       &m->containers[m->n_containers],
                                       (struct rtattr*)((uint8_t*) NLMSG_DATA(m->hdr) + hlen),
                                       NLMSG_PAYLOAD(m->hdr, hlen));
}

int sd_netlink_message_rewind(sd_netlink_message *m, sd_netlink *genl) {
        const NLType *nl_type;
        uint16_t type;
        size_t size;
        int r;

        assert_return(m, -EINVAL);
        assert_return(genl || m->protocol != NETLINK_GENERIC, -EINVAL);

        /* don't allow appending to message once parsed */
        if (!m->sealed)
                rtnl_message_seal(m);

        for (unsigned i = 1; i <= m->n_containers; i++)
                m->containers[i].attributes = mfree(m->containers[i].attributes);

        m->n_containers = 0;

        if (m->containers[0].attributes)
                /* top-level attributes have already been parsed */
                return 0;

        assert(m->hdr);

        r = type_system_root_get_type(genl, &nl_type, m->hdr->nlmsg_type);
        if (r < 0)
                return r;

        type = type_get_type(nl_type);
        size = type_get_size(nl_type);

        if (type == NETLINK_TYPE_NESTED) {
                const NLTypeSystem *type_system;

                type_get_type_system(nl_type, &type_system);

                m->containers[0].type_system = type_system;

                if (sd_netlink_message_is_error(m))
                        r = netlink_message_parse_error(m);
                else
                        r = netlink_container_parse(m,
                                                    &m->containers[m->n_containers],
                                                    (struct rtattr*)((uint8_t*) NLMSG_DATA(m->hdr) + NLMSG_ALIGN(size)),
                                                    NLMSG_PAYLOAD(m->hdr, size));
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
