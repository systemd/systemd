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

int message_new_empty(sd_netlink *nl, sd_netlink_message **ret) {
        sd_netlink_message *m;

        assert(nl);
        assert(ret);

        /* Note that 'nl' is currently unused, if we start using it internally we must take care to
         * avoid problems due to mutual references between buses and their queued messages. See sd-bus. */

        m = new(sd_netlink_message, 1);
        if (!m)
                return -ENOMEM;

        *m = (sd_netlink_message) {
                .n_ref = 1,
                .protocol = nl->protocol,
                .sealed = false,
        };

        *ret = m;
        return 0;
}

int message_new_full(
                sd_netlink *nl,
                uint16_t nlmsg_type,
                const NLAPolicySet *policy_set,
                size_t header_size,
                sd_netlink_message **ret) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        size_t size;
        int r;

        assert(nl);
        assert(policy_set);
        assert(ret);

        size = NLMSG_SPACE(header_size);
        assert(size >= sizeof(struct nlmsghdr));

        r = message_new_empty(nl, &m);
        if (r < 0)
                return r;

        m->containers[0].policy_set = policy_set;

        m->hdr = malloc0(size);
        if (!m->hdr)
                return -ENOMEM;

        m->hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
        m->hdr->nlmsg_len = size;
        m->hdr->nlmsg_type = nlmsg_type;

        *ret = TAKE_PTR(m);
        return 0;
}

int message_new(sd_netlink *nl, sd_netlink_message **ret, uint16_t nlmsg_type) {
        const NLAPolicySet *policy_set;
        size_t size;
        int r;

        assert_return(nl, -EINVAL);
        assert_return(ret, -EINVAL);

        r = netlink_get_policy_set_and_header_size(nl, nlmsg_type, &policy_set, &size);
        if (r < 0)
                return r;

        return message_new_full(nl, nlmsg_type, policy_set, size, ret);
}

int message_new_synthetic_error(sd_netlink *nl, int error, uint32_t serial, sd_netlink_message **ret) {
        struct nlmsgerr *err;
        int r;

        assert(error <= 0);

        r = message_new(nl, ret, NLMSG_ERROR);
        if (r < 0)
                return r;

        message_seal(*ret);
        (*ret)->hdr->nlmsg_seq = serial;

        err = NLMSG_DATA((*ret)->hdr);
        err->error = error;

        return 0;
}

int sd_netlink_message_set_request_dump(sd_netlink_message *m, int dump) {
        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(m->protocol != NETLINK_ROUTE ||
                      IN_SET(m->hdr->nlmsg_type,
                             RTM_GETLINK, RTM_GETLINKPROP, RTM_GETADDR, RTM_GETROUTE, RTM_GETNEIGH,
                             RTM_GETRULE, RTM_GETADDRLABEL, RTM_GETNEXTHOP, RTM_GETQDISC, RTM_GETTCLASS),
                      -EINVAL);

        SET_FLAG(m->hdr->nlmsg_flags, NLM_F_DUMP, dump);

        return 0;
}

DEFINE_TRIVIAL_REF_FUNC(sd_netlink_message, sd_netlink_message);

sd_netlink_message* sd_netlink_message_unref(sd_netlink_message *m) {
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

int sd_netlink_message_get_type(sd_netlink_message *m, uint16_t *ret) {
        assert_return(m, -EINVAL);
        assert_return(ret, -EINVAL);

        *ret = m->hdr->nlmsg_type;

        return 0;
}

int sd_netlink_message_set_flags(sd_netlink_message *m, uint16_t flags) {
        assert_return(m, -EINVAL);
        assert_return(flags != 0, -EINVAL);

        m->hdr->nlmsg_flags = flags;

        return 0;
}

int sd_netlink_message_is_broadcast(sd_netlink_message *m) {
        assert_return(m, -EINVAL);

        return m->multicast_group != 0;
}

/* If successful the updated message will be correctly aligned, if unsuccessful the old message is untouched. */
static int add_rtattr(sd_netlink_message *m, uint16_t attr_type, const void *data, size_t data_length) {
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

        rtattr_append_attribute_internal(rta, attr_type, data, data_length);

        /* if we are inside containers, extend them */
        for (unsigned i = 0; i < m->n_containers; i++)
                GET_CONTAINER(m, i)->rta_len += RTA_SPACE(data_length);

        /* update message size */
        offset = m->hdr->nlmsg_len;
        m->hdr->nlmsg_len = message_length;

        /* return old message size */
        return offset;
}

static int message_attribute_has_type(sd_netlink_message *m, size_t *ret_size, uint16_t attr_type, NLAType type) {
        const NLAPolicy *policy;

        assert(m);

        policy = policy_set_get_policy(m->containers[m->n_containers].policy_set, attr_type);
        if (!policy)
                return -EOPNOTSUPP;

        if (policy_get_type(policy) != type)
                return -EINVAL;

        if (ret_size)
                *ret_size = policy_get_size(policy);
        return 0;
}

int sd_netlink_message_append_string(sd_netlink_message *m, uint16_t attr_type, const char *data) {
        size_t length, size;
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(data, -EINVAL);

        r = message_attribute_has_type(m, &size, attr_type, NETLINK_TYPE_STRING);
        if (r < 0)
                return r;

        if (size) {
                length = strnlen(data, size+1);
                if (length > size)
                        return -EINVAL;
        } else
                length = strlen(data);

        r = add_rtattr(m, attr_type, data, length + 1);
        if (r < 0)
                return r;

        return 0;
}

int sd_netlink_message_append_strv(sd_netlink_message *m, uint16_t attr_type, const char* const *data) {
        size_t length, size;
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(data, -EINVAL);

        r = message_attribute_has_type(m, &size, attr_type, NETLINK_TYPE_STRING);
        if (r < 0)
                return r;

        STRV_FOREACH(p, data) {
                if (size) {
                        length = strnlen(*p, size+1);
                        if (length > size)
                                return -EINVAL;
                } else
                        length = strlen(*p);

                r = add_rtattr(m, attr_type, *p, length + 1);
                if (r < 0)
                        return r;
        }

        return 0;
}

int sd_netlink_message_append_flag(sd_netlink_message *m, uint16_t attr_type) {
        size_t size;
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);

        r = message_attribute_has_type(m, &size, attr_type, NETLINK_TYPE_FLAG);
        if (r < 0)
                return r;

        r = add_rtattr(m, attr_type, NULL, 0);
        if (r < 0)
                return r;

        return 0;
}

int sd_netlink_message_append_u8(sd_netlink_message *m, uint16_t attr_type, uint8_t data) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);

        r = message_attribute_has_type(m, NULL, attr_type, NETLINK_TYPE_U8);
        if (r < 0)
                return r;

        r = add_rtattr(m, attr_type, &data, sizeof(uint8_t));
        if (r < 0)
                return r;

        return 0;
}

int sd_netlink_message_append_u16(sd_netlink_message *m, uint16_t attr_type, uint16_t data) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);

        r = message_attribute_has_type(m, NULL, attr_type, NETLINK_TYPE_U16);
        if (r < 0)
                return r;

        r = add_rtattr(m, attr_type, &data, sizeof(uint16_t));
        if (r < 0)
                return r;

        return 0;
}

int sd_netlink_message_append_u32(sd_netlink_message *m, uint16_t attr_type, uint32_t data) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);

        r = message_attribute_has_type(m, NULL, attr_type, NETLINK_TYPE_U32);
        if (r < 0)
                return r;

        r = add_rtattr(m, attr_type, &data, sizeof(uint32_t));
        if (r < 0)
                return r;

        return 0;
}

int sd_netlink_message_append_u64(sd_netlink_message *m, uint16_t attr_type, uint64_t data) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);

        r = message_attribute_has_type(m, NULL, attr_type, NETLINK_TYPE_U64);
        if (r < 0)
                return r;

        r = add_rtattr(m, attr_type, &data, sizeof(uint64_t));
        if (r < 0)
                return r;

        return 0;
}

int sd_netlink_message_append_s8(sd_netlink_message *m, uint16_t attr_type, int8_t data) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);

        r = message_attribute_has_type(m, NULL, attr_type, NETLINK_TYPE_S8);
        if (r < 0)
                return r;

        r = add_rtattr(m, attr_type, &data, sizeof(int8_t));
        if (r < 0)
                return r;

        return 0;
}

int sd_netlink_message_append_s16(sd_netlink_message *m, uint16_t attr_type, int16_t data) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);

        r = message_attribute_has_type(m, NULL, attr_type, NETLINK_TYPE_S16);
        if (r < 0)
                return r;

        r = add_rtattr(m, attr_type, &data, sizeof(int16_t));
        if (r < 0)
                return r;

        return 0;
}

int sd_netlink_message_append_s32(sd_netlink_message *m, uint16_t attr_type, int32_t data) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);

        r = message_attribute_has_type(m, NULL, attr_type, NETLINK_TYPE_S32);
        if (r < 0)
                return r;

        r = add_rtattr(m, attr_type, &data, sizeof(int32_t));
        if (r < 0)
                return r;

        return 0;
}

int sd_netlink_message_append_s64(sd_netlink_message *m, uint16_t attr_type, int64_t data) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);

        r = message_attribute_has_type(m, NULL, attr_type, NETLINK_TYPE_S64);
        if (r < 0)
                return r;

        r = add_rtattr(m, attr_type, &data, sizeof(int64_t));
        if (r < 0)
                return r;

        return 0;
}

int sd_netlink_message_append_data(sd_netlink_message *m, uint16_t attr_type, const void *data, size_t len) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);

        r = add_rtattr(m, attr_type, data, len);
        if (r < 0)
                return r;

        return 0;
}

int sd_netlink_message_append_container_data(
                sd_netlink_message *m,
                uint16_t container_type,
                uint16_t attr_type,
                const void *data,
                size_t len) {

        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);

        r = sd_netlink_message_open_container(m, container_type);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_data(m, attr_type, data, len);
        if (r < 0)
                return r;

        return sd_netlink_message_close_container(m);
}

int netlink_message_append_in_addr_union(sd_netlink_message *m, uint16_t attr_type, int family, const union in_addr_union *data) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(data, -EINVAL);
        assert_return(IN_SET(family, AF_INET, AF_INET6), -EINVAL);

        r = message_attribute_has_type(m, NULL, attr_type, NETLINK_TYPE_IN_ADDR);
        if (r < 0)
                return r;

        r = add_rtattr(m, attr_type, data, FAMILY_ADDRESS_SIZE(family));
        if (r < 0)
                return r;

        return 0;
}

int sd_netlink_message_append_in_addr(sd_netlink_message *m, uint16_t attr_type, const struct in_addr *data) {
        return netlink_message_append_in_addr_union(m, attr_type, AF_INET, (const union in_addr_union *) data);
}

int sd_netlink_message_append_in6_addr(sd_netlink_message *m, uint16_t attr_type, const struct in6_addr *data) {
        return netlink_message_append_in_addr_union(m, attr_type, AF_INET6, (const union in_addr_union *) data);
}

int netlink_message_append_sockaddr_union(sd_netlink_message *m, uint16_t attr_type, const union sockaddr_union *data) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(data, -EINVAL);
        assert_return(IN_SET(data->sa.sa_family, AF_INET, AF_INET6), -EINVAL);

        r = message_attribute_has_type(m, NULL, attr_type, NETLINK_TYPE_SOCKADDR);
        if (r < 0)
                return r;

        r = add_rtattr(m, attr_type, data, data->sa.sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
        if (r < 0)
                return r;

        return 0;
}

int sd_netlink_message_append_sockaddr_in(sd_netlink_message *m, uint16_t attr_type, const struct sockaddr_in *data) {
        return netlink_message_append_sockaddr_union(m, attr_type, (const union sockaddr_union *) data);
}

int sd_netlink_message_append_sockaddr_in6(sd_netlink_message *m, uint16_t attr_type, const struct sockaddr_in6 *data) {
        return netlink_message_append_sockaddr_union(m, attr_type, (const union sockaddr_union *) data);
}

int sd_netlink_message_append_ether_addr(sd_netlink_message *m, uint16_t attr_type, const struct ether_addr *data) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(data, -EINVAL);

        r = message_attribute_has_type(m, NULL, attr_type, NETLINK_TYPE_ETHER_ADDR);
        if (r < 0)
                return r;

        r = add_rtattr(m, attr_type, data, ETH_ALEN);
        if (r < 0)
                return r;

        return 0;
}

int netlink_message_append_hw_addr(sd_netlink_message *m, uint16_t attr_type, const struct hw_addr_data *data) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(data, -EINVAL);
        assert_return(data->length > 0, -EINVAL);

        r = message_attribute_has_type(m, NULL, attr_type, NETLINK_TYPE_ETHER_ADDR);
        if (r < 0)
                return r;

        r = add_rtattr(m, attr_type, data->bytes, data->length);
        if (r < 0)
                return r;

        return 0;
}

int sd_netlink_message_append_cache_info(sd_netlink_message *m, uint16_t attr_type, const struct ifa_cacheinfo *info) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(info, -EINVAL);

        r = message_attribute_has_type(m, NULL, attr_type, NETLINK_TYPE_CACHE_INFO);
        if (r < 0)
                return r;

        r = add_rtattr(m, attr_type, info, sizeof(struct ifa_cacheinfo));
        if (r < 0)
                return r;

        return 0;
}

int sd_netlink_message_open_container(sd_netlink_message *m, uint16_t attr_type) {
        size_t size;
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        /* m->containers[m->n_containers + 1] is accessed both in read and write. Prevent access out of bound */
        assert_return(m->n_containers < (NETLINK_CONTAINER_DEPTH - 1), -ERANGE);

        r = message_attribute_has_type(m, &size, attr_type, NETLINK_TYPE_NESTED);
        if (r < 0) {
                const NLAPolicySetUnion *policy_set_union;
                int family;

                r = message_attribute_has_type(m, &size, attr_type, NETLINK_TYPE_NESTED_UNION_BY_FAMILY);
                if (r < 0)
                        return r;

                r = sd_rtnl_message_get_family(m, &family);
                if (r < 0)
                        return r;

                policy_set_union = policy_set_get_policy_set_union(
                                m->containers[m->n_containers].policy_set,
                                attr_type);
                if (!policy_set_union)
                        return -EOPNOTSUPP;

                m->containers[m->n_containers + 1].policy_set =
                        policy_set_union_get_policy_set_by_family(
                                policy_set_union,
                                family);
        } else
                m->containers[m->n_containers + 1].policy_set =
                        policy_set_get_policy_set(
                                m->containers[m->n_containers].policy_set,
                                attr_type);
        if (!m->containers[m->n_containers + 1].policy_set)
                return -EOPNOTSUPP;

        r = add_rtattr(m, attr_type | NLA_F_NESTED, NULL, size);
        if (r < 0)
                return r;

        m->containers[m->n_containers++].offset = r;

        return 0;
}

int sd_netlink_message_open_container_union(sd_netlink_message *m, uint16_t attr_type, const char *key) {
        const NLAPolicySetUnion *policy_set_union;
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(m->n_containers < (NETLINK_CONTAINER_DEPTH - 1), -ERANGE);

        r = message_attribute_has_type(m, NULL, attr_type, NETLINK_TYPE_NESTED_UNION_BY_STRING);
        if (r < 0)
                return r;

        policy_set_union = policy_set_get_policy_set_union(
                        m->containers[m->n_containers].policy_set,
                        attr_type);
        if (!policy_set_union)
                return -EOPNOTSUPP;

        m->containers[m->n_containers + 1].policy_set =
                policy_set_union_get_policy_set_by_string(
                        policy_set_union,
                        key);
        if (!m->containers[m->n_containers + 1].policy_set)
                return -EOPNOTSUPP;

        r = sd_netlink_message_append_string(m, policy_set_union_get_match_attribute(policy_set_union), key);
        if (r < 0)
                return r;

        /* do we ever need non-null size */
        r = add_rtattr(m, attr_type | NLA_F_NESTED, NULL, 0);
        if (r < 0)
                return r;

        m->containers[m->n_containers++].offset = r;

        return 0;
}

int sd_netlink_message_close_container(sd_netlink_message *m) {
        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(m->n_containers > 0, -EINVAL);

        m->containers[m->n_containers].policy_set = NULL;
        m->containers[m->n_containers].offset = 0;
        m->n_containers--;

        return 0;
}

int sd_netlink_message_open_array(sd_netlink_message *m, uint16_t attr_type) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(!m->sealed, -EPERM);
        assert_return(m->n_containers < (NETLINK_CONTAINER_DEPTH - 1), -ERANGE);

        r = add_rtattr(m, attr_type | NLA_F_NESTED, NULL, 0);
        if (r < 0)
                return r;

        m->containers[m->n_containers].offset = r;
        m->n_containers++;
        m->containers[m->n_containers].policy_set = m->containers[m->n_containers - 1].policy_set;

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
        m->containers[m->n_containers].policy_set = NULL;

        return 0;
}

static int netlink_message_read_internal(
                sd_netlink_message *m,
                uint16_t attr_type,
                void **ret_data,
                bool *ret_net_byteorder) {

        struct netlink_attribute *attribute;
        struct rtattr *rta;

        assert_return(m, -EINVAL);
        assert_return(m->sealed, -EPERM);

        assert(m->n_containers < NETLINK_CONTAINER_DEPTH);

        if (!m->containers[m->n_containers].attributes)
                return -ENODATA;

        if (attr_type > m->containers[m->n_containers].max_attribute)
                return -ENODATA;

        attribute = &m->containers[m->n_containers].attributes[attr_type];

        if (attribute->offset == 0)
                return -ENODATA;

        rta = (struct rtattr*)((uint8_t *) m->hdr + attribute->offset);

        if (ret_data)
                *ret_data = RTA_DATA(rta);

        if (ret_net_byteorder)
                *ret_net_byteorder = attribute->net_byteorder;

        return RTA_PAYLOAD(rta);
}

static int netlink_message_read_impl(
                sd_netlink_message *m,
                uint16_t attr_type,
                bool strict,
                NLAType type,
                size_t size,
                void *ret,
                bool *ret_net_byteorder) {

        bool net_byteorder;
        void *attr_data;
        int r;

        assert(m);

        if (type >= 0) {
                r = message_attribute_has_type(m, NULL, attr_type, type);
                if (r < 0)
                        return r;
        }

        r = netlink_message_read_internal(m, attr_type, &attr_data, &net_byteorder);
        if (r < 0)
                return r;

        if ((size_t) r > size)
                return -ENOBUFS;

        if (strict && (size_t) r != size)
                return -EIO;

        if (ret)
                memzero(mempcpy(ret, attr_data, r), size - (size_t) r);

        if (ret_net_byteorder)
                *ret_net_byteorder = net_byteorder;

        return r;
}

int sd_netlink_message_read(sd_netlink_message *m, uint16_t attr_type, size_t size, void *ret) {
        assert_return(m, -EINVAL);

        return netlink_message_read_impl(
                        m, attr_type, /* strict = */ false,
                        _NETLINK_TYPE_INVALID, size,
                        ret, /* ret_net_byteorder = */ NULL);
}

int sd_netlink_message_read_data(sd_netlink_message *m, uint16_t attr_type, size_t *ret_size, void **ret_data) {
        void *attr_data;
        int r;

        assert_return(m, -EINVAL);

        r = netlink_message_read_internal(m, attr_type, &attr_data, NULL);
        if (r < 0)
                return r;

        if (ret_data) {
                void *data;

                data = memdup_suffix0(attr_data, r);
                if (!data)
                        return -ENOMEM;

                *ret_data = data;
        }

        if (ret_size)
                *ret_size = r;

        return r;
}

int sd_netlink_message_read_string_strdup(sd_netlink_message *m, uint16_t attr_type, char **ret) {
        const char *s;
        int r;

        assert_return(m, -EINVAL);

        r = sd_netlink_message_read_string(m, attr_type, &s);
        if (r < 0)
                return r;

        return strdup_to(ret, s);
}

int sd_netlink_message_read_string(sd_netlink_message *m, uint16_t attr_type, const char **ret) {
        void *attr_data;
        int r;

        assert_return(m, -EINVAL);

        r = message_attribute_has_type(m, NULL, attr_type, NETLINK_TYPE_STRING);
        if (r < 0)
                return r;

        r = netlink_message_read_internal(m, attr_type, &attr_data, NULL);
        if (r < 0)
                return r;

        if (strnlen(attr_data, r) >= (size_t) r)
                return -EIO;

        if (ret)
                *ret = (const char *) attr_data;

        return 0;
}

int sd_netlink_message_read_u8(sd_netlink_message *m, uint16_t attr_type, uint8_t *ret) {
        assert_return(m, -EINVAL);

        return netlink_message_read_impl(
                        m, attr_type, /* strict = */ true,
                        NETLINK_TYPE_U8, sizeof(uint8_t),
                        ret, /* ret_net_byteorder = */ NULL);
}

int sd_netlink_message_read_u16(sd_netlink_message *m, uint16_t attr_type, uint16_t *ret) {
        bool net_byteorder;
        uint16_t u;
        int r;

        assert_return(m, -EINVAL);

        r = netlink_message_read_impl(
                        m, attr_type, /* strict = */ true,
                        NETLINK_TYPE_U16, sizeof(uint16_t),
                        ret ? &u : NULL, &net_byteorder);
        if (r < 0)
                return r;

        if (ret)
                *ret = net_byteorder ? be16toh(u) : u;

        return 0;
}

int sd_netlink_message_read_u32(sd_netlink_message *m, uint16_t attr_type, uint32_t *ret) {
        bool net_byteorder;
        uint32_t u;
        int r;

        assert_return(m, -EINVAL);

        r = netlink_message_read_impl(
                        m, attr_type, /* strict = */ true,
                        NETLINK_TYPE_U32, sizeof(uint32_t),
                        ret ? &u : NULL, &net_byteorder);
        if (r < 0)
                return r;

        if (ret)
                *ret = net_byteorder ? be32toh(u) : u;

        return 0;
}

int sd_netlink_message_read_u64(sd_netlink_message *m, uint16_t attr_type, uint64_t *ret) {
        bool net_byteorder;
        uint64_t u;
        int r;

        assert_return(m, -EINVAL);

        r = netlink_message_read_impl(
                        m, attr_type, /* strict = */ true,
                        NETLINK_TYPE_U64, sizeof(uint64_t),
                        ret ? &u : NULL, &net_byteorder);
        if (r < 0)
                return r;

        if (ret)
                *ret = net_byteorder ? be64toh(u) : u;

        return 0;
}

int sd_netlink_message_read_ether_addr(sd_netlink_message *m, uint16_t attr_type, struct ether_addr *ret) {
        assert_return(m, -EINVAL);

        return netlink_message_read_impl(
                        m, attr_type, /* strict = */ true,
                        NETLINK_TYPE_ETHER_ADDR, sizeof(struct ether_addr),
                        ret, /* ret_net_byteorder = */ NULL);
}

int netlink_message_read_hw_addr(sd_netlink_message *m, uint16_t attr_type, struct hw_addr_data *ret) {
        int r;

        assert_return(m, -EINVAL);

        r = netlink_message_read_impl(
                        m, attr_type, /* strict = */ false,
                        NETLINK_TYPE_ETHER_ADDR, HW_ADDR_MAX_SIZE,
                        ret ? ret->bytes : NULL, /* ret_net_byteorder = */ NULL);
        if (r < 0)
                return r;

        if (ret)
                ret->length = r;

        return r;
}

int sd_netlink_message_read_cache_info(sd_netlink_message *m, uint16_t attr_type, struct ifa_cacheinfo *ret) {
        assert_return(m, -EINVAL);

        return netlink_message_read_impl(
                        m, attr_type, /* strict = */ true,
                        NETLINK_TYPE_CACHE_INFO, sizeof(struct ifa_cacheinfo),
                        ret, /* ret_net_byteorder = */ NULL);
}

int netlink_message_read_in_addr_union(sd_netlink_message *m, uint16_t attr_type, int family, union in_addr_union *ret) {
        int r;

        assert_return(m, -EINVAL);
        assert_return(IN_SET(family, AF_INET, AF_INET6), -EINVAL);

        r = netlink_message_read_impl(
                        m, attr_type, /* strict = */ true,
                        NETLINK_TYPE_IN_ADDR, FAMILY_ADDRESS_SIZE(family),
                        ret, /* ret_net_byteorder = */ NULL);
        if (r < 0)
                return r;

        if (ret)
                memzero((uint8_t*) ret + FAMILY_ADDRESS_SIZE(family), sizeof(union in_addr_union) - FAMILY_ADDRESS_SIZE(family));

        return r;
}

int sd_netlink_message_read_in_addr(sd_netlink_message *m, uint16_t attr_type, struct in_addr *ret) {
        assert_return(m, -EINVAL);

        return netlink_message_read_impl(
                        m, attr_type, /* strict = */ true,
                        NETLINK_TYPE_IN_ADDR, sizeof(struct in_addr),
                        ret, /* ret_net_byteorder = */ NULL);
}

int sd_netlink_message_read_in6_addr(sd_netlink_message *m, uint16_t attr_type, struct in6_addr *ret) {
        assert_return(m, -EINVAL);

        return netlink_message_read_impl(
                        m, attr_type, /* strict = */ true,
                        NETLINK_TYPE_IN_ADDR, sizeof(struct in6_addr),
                        ret, /* ret_net_byteorder = */ NULL);
}

int sd_netlink_message_has_flag(sd_netlink_message *m, uint16_t attr_type) {
        void *attr_data;
        int r;

        assert_return(m, -EINVAL);

        /* This returns 1 when the flag is set, 0 when not set, negative errno on error. */

        r = message_attribute_has_type(m, NULL, attr_type, NETLINK_TYPE_FLAG);
        if (r < 0)
                return r;

        r = netlink_message_read_internal(m, attr_type, &attr_data, NULL);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return r;

        return 1;
}

int sd_netlink_message_read_strv(sd_netlink_message *m, uint16_t container_type, uint16_t attr_type, char ***ret) {
        _cleanup_strv_free_ char **s = NULL;
        const NLAPolicySet *policy_set;
        const NLAPolicy *policy;
        struct rtattr *rta;
        void *container;
        size_t rt_len;
        int r;

        assert_return(m, -EINVAL);
        assert_return(m->n_containers < NETLINK_CONTAINER_DEPTH, -EINVAL);

        policy = policy_set_get_policy(
                        m->containers[m->n_containers].policy_set,
                        container_type);
        if (!policy)
                return -EOPNOTSUPP;

        if (policy_get_type(policy) != NETLINK_TYPE_NESTED)
                return -EINVAL;

        policy_set = policy_set_get_policy_set(
                        m->containers[m->n_containers].policy_set,
                        container_type);
        if (!policy_set)
                return -EOPNOTSUPP;

        policy = policy_set_get_policy(policy_set, attr_type);
        if (!policy)
                return -EOPNOTSUPP;

        if (policy_get_type(policy) != NETLINK_TYPE_STRING)
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
                uint16_t type;

                type = RTA_TYPE(rta);
                if (type != attr_type)
                        continue;

                r = strv_extend(&s, RTA_DATA(rta));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(s);
        return 0;
}

static int netlink_container_parse(
                sd_netlink_message *m,
                struct netlink_container *container,
                struct rtattr *rta,
                size_t rt_len) {

        _cleanup_free_ struct netlink_attribute *attributes = NULL;
        uint16_t max_attr = 0;

        /* RTA_OK() macro compares with rta->rt_len, which is unsigned short, and
         * LGTM.com analysis does not like the type difference. Hence, here we
         * introduce an unsigned short variable as a workaround. */
        unsigned short len = rt_len;
        for (; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
                uint16_t attr;

                attr = RTA_TYPE(rta);
                max_attr = MAX(max_attr, attr);

                if (!GREEDY_REALLOC0(attributes, (size_t) max_attr + 1))
                        return -ENOMEM;

                if (attributes[attr].offset != 0)
                        log_debug("sd-netlink: message parse - overwriting repeated attribute");

                attributes[attr].offset = (uint8_t *) rta - (uint8_t *) m->hdr;
                attributes[attr].nested = RTA_FLAGS(rta) & NLA_F_NESTED;
                attributes[attr].net_byteorder = RTA_FLAGS(rta) & NLA_F_NET_BYTEORDER;
        }

        container->attributes = TAKE_PTR(attributes);
        container->max_attribute = max_attr;

        return 0;
}

int sd_netlink_message_enter_container(sd_netlink_message *m, uint16_t attr_type) {
        const NLAPolicy *policy;
        const NLAPolicySet *policy_set;
        void *container;
        size_t size;
        int r;

        assert_return(m, -EINVAL);
        assert_return(m->n_containers < (NETLINK_CONTAINER_DEPTH - 1), -EINVAL);

        policy = policy_set_get_policy(
                        m->containers[m->n_containers].policy_set,
                        attr_type);
        if (!policy)
                return -EOPNOTSUPP;

        switch (policy_get_type(policy)) {
        case NETLINK_TYPE_NESTED:
                policy_set = policy_set_get_policy_set(
                                m->containers[m->n_containers].policy_set,
                                attr_type);
                break;

        case NETLINK_TYPE_NESTED_UNION_BY_STRING: {
                const NLAPolicySetUnion *policy_set_union;
                const char *key;

                policy_set_union = policy_get_policy_set_union(policy);
                if (!policy_set_union)
                        return -EOPNOTSUPP;

                r = sd_netlink_message_read_string(
                                m,
                                policy_set_union_get_match_attribute(policy_set_union),
                                &key);
                if (r < 0)
                        return r;

                policy_set = policy_set_union_get_policy_set_by_string(
                                policy_set_union,
                                key);
                break;
        }
        case NETLINK_TYPE_NESTED_UNION_BY_FAMILY: {
                const NLAPolicySetUnion *policy_set_union;
                int family;

                policy_set_union = policy_get_policy_set_union(policy);
                if (!policy_set_union)
                        return -EOPNOTSUPP;

                r = sd_rtnl_message_get_family(m, &family);
                if (r < 0)
                        return r;

                policy_set = policy_set_union_get_policy_set_by_family(
                                policy_set_union,
                                family);
                break;
        }
        default:
                assert_not_reached();
        }
        if (!policy_set)
                return -EOPNOTSUPP;

        r = netlink_message_read_internal(m, attr_type, &container, NULL);
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

        m->containers[m->n_containers].policy_set = policy_set;

        return 0;
}

int sd_netlink_message_enter_array(sd_netlink_message *m, uint16_t attr_type) {
        void *container;
        size_t size;
        int r;

        assert_return(m, -EINVAL);
        assert_return(m->n_containers < (NETLINK_CONTAINER_DEPTH - 1), -EINVAL);

        r = netlink_message_read_internal(m, attr_type, &container, NULL);
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

        m->containers[m->n_containers].policy_set = m->containers[m->n_containers - 1].policy_set;

        return 0;
}

int sd_netlink_message_exit_container(sd_netlink_message *m) {
        assert_return(m, -EINVAL);
        assert_return(m->sealed, -EINVAL);
        assert_return(m->n_containers > 0, -EINVAL);

        m->containers[m->n_containers].attributes = mfree(m->containers[m->n_containers].attributes);
        m->containers[m->n_containers].max_attribute = 0;
        m->containers[m->n_containers].policy_set = NULL;

        m->n_containers--;

        return 0;
}

int sd_netlink_message_get_max_attribute(sd_netlink_message *m, uint16_t *ret) {
        assert_return(m, -EINVAL);
        assert_return(m->sealed, -EINVAL);
        assert_return(ret, -EINVAL);

        *ret = m->containers[m->n_containers].max_attribute;
        return 0;
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

int sd_netlink_message_rewind(sd_netlink_message *m, sd_netlink *nl) {
        size_t size;
        int r;

        assert_return(m, -EINVAL);
        assert_return(nl, -EINVAL);

        /* don't allow appending to message once parsed */
        message_seal(m);

        for (unsigned i = 1; i <= m->n_containers; i++)
                m->containers[i].attributes = mfree(m->containers[i].attributes);

        m->n_containers = 0;

        if (m->containers[0].attributes)
                /* top-level attributes have already been parsed */
                return 0;

        assert(m->hdr);

        r = netlink_get_policy_set_and_header_size(nl, m->hdr->nlmsg_type,
                                                   &m->containers[0].policy_set, &size);
        if (r < 0)
                return r;

        if (sd_netlink_message_is_error(m))
                return netlink_message_parse_error(m);

        return netlink_container_parse(m,
                                       &m->containers[0],
                                       (struct rtattr*)((uint8_t*) NLMSG_DATA(m->hdr) + NLMSG_ALIGN(size)),
                                       NLMSG_PAYLOAD(m->hdr, size));
}

void message_seal(sd_netlink_message *m) {
        assert(m);

        m->sealed = true;
}

sd_netlink_message* sd_netlink_message_next(sd_netlink_message *m) {
        assert_return(m, NULL);

        return m->next;
}
