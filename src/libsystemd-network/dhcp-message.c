/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if_arp.h>

#include "alloc-util.h"
#include "dhcp-client-id-internal.h"
#include "dhcp-message.h"
#include "dhcp-protocol.h"
#include "dhcp-route.h"
#include "dns-def.h"
#include "dns-domain.h"
#include "dns-resolver-internal.h"
#include "errno-util.h"
#include "ether-addr-util.h"
#include "hostname-util.h"
#include "in-addr-util.h"
#include "iovec-util.h"
#include "iovec-wrapper.h"
#include "ip-util.h"
#include "json-util.h"
#include "network-common.h"
#include "set.h"
#include "sort-util.h"
#include "string-util.h"
#include "unaligned.h"

static sd_dhcp_message* dhcp_message_free(sd_dhcp_message *message) {
        if (!message)
                return NULL;

        tlv_done(&message->options);
        return mfree(message);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_dhcp_message, sd_dhcp_message, dhcp_message_free);

int dhcp_message_new(sd_dhcp_message **ret) {
        assert(ret);

        sd_dhcp_message *message = new(sd_dhcp_message, 1);
        if (!message)
                return -ENOMEM;

        *message = (sd_dhcp_message) {
                .n_ref = 1,
                .options = TLV_INIT(TLV_DHCP4),
        };

        *ret = TAKE_PTR(message);
        return 0;
}

int dhcp_message_init_header(
                sd_dhcp_message *message,
                uint8_t op,
                uint32_t xid,
                uint16_t arp_type,
                const struct hw_addr_data *hw_addr) {

        assert(message);
        assert(IN_SET(op, BOOTREQUEST, BOOTREPLY));

        /* RFC 2131 section 4.1.1:
         * The client MUST include its hardware address in the ’chaddr’ field, if necessary for delivery of
         * DHCP reply messages.
         *
         * RFC 4390 section 2.1:
         * A DHCP client, when working over an IPoIB interface, MUST follow the following rules:
         * "htype" (hardware address type) MUST be 32 [ARPPARAM].
         * "hlen" (hardware address length) MUST be 0.
         * "chaddr" (client hardware address) field MUST be zeroed.
         *
         * Note, the maximum hardware address length (HW_ADDR_MAX_SIZE) is 32, but the size of the chaddr
         * field is 16.
         *
         * Also, ARP type is 2 bytes, but the htype field is 1 byte. */

        if (arp_type == ARPHRD_INFINIBAND)
                hw_addr = NULL;

        if (hw_addr && hw_addr->length > sizeof_field(DHCPMessageHeader, chaddr))
                return -EINVAL;

        message->header = (DHCPMessageHeader) {
                .op = op,
                .htype = arp_type <= UINT8_MAX ? arp_type : 0,
                .hlen = hw_addr ? hw_addr->length : 0,
                .xid = htobe32(xid),
                .magic = htobe32(DHCP_MAGIC_COOKIE),
        };

        if (hw_addr)
                memcpy_safe(message->header.chaddr, hw_addr->bytes, hw_addr->length);
        return 0;
}

void dhcp_message_set_broadcast_flag(sd_dhcp_message *message, bool b) {
        assert(message);

        SET_FLAG(message->header.flags, htobe16(0x8000), b);
}

bool dhcp_message_has_broadcast_flag(sd_dhcp_message *message) {
        assert(message);

        return FLAGS_SET(message->header.flags, htobe16(0x8000));
}

int dhcp_message_get_hw_addr(sd_dhcp_message *message, struct hw_addr_data *ret) {
        assert(message);
        assert(ret);

        if (message->header.hlen > sizeof_field(DHCPMessageHeader, chaddr))
                return -EBADMSG;

        ret->length = message->header.hlen;
        memcpy_safe(ret->bytes, message->header.chaddr, message->header.hlen);
        return 0;
}

bool dhcp_message_has_option(sd_dhcp_message *message, uint8_t code) {
        assert(message);
        return tlv_contains(&message->options, code);
}

void dhcp_message_remove_option(sd_dhcp_message *message, uint8_t code) {
        assert(message);
        tlv_remove(&message->options, code);
}

int dhcp_message_append_option(sd_dhcp_message *message, uint8_t code, size_t length, const void *data) {
        assert(message);
        return tlv_append(&message->options, code, length, data);
}

int dhcp_message_append_option_tlv(sd_dhcp_message *message, const TLV *tlv) {
        assert(message);
        return tlv_append_tlv(&message->options, tlv);
}

int dhcp_message_append_option_flag(sd_dhcp_message *message, uint8_t code) {
        assert(message);

        if (dhcp_message_has_option(message, code))
                return -EEXIST;

        return dhcp_message_append_option(message, code, /* length= */ 0, /* data= */ NULL);
}

int dhcp_message_append_option_u8(sd_dhcp_message *message, uint8_t code, uint8_t data) {
        assert(message);

        if (dhcp_message_has_option(message, code))
                return -EEXIST;

        return dhcp_message_append_option(message, code, sizeof(uint8_t), &data);
}

int dhcp_message_append_option_u16(sd_dhcp_message *message, uint8_t code, uint16_t data) {
        assert(message);

        if (dhcp_message_has_option(message, code))
                return -EEXIST;

        be16_t b = htobe16(data);
        return dhcp_message_append_option(message, code, sizeof(be16_t), &b);
}

int dhcp_message_append_option_be32(sd_dhcp_message *message, uint8_t code, be32_t data) {
        assert(message);

        if (dhcp_message_has_option(message, code))
                return -EEXIST;

        return dhcp_message_append_option(message, code, sizeof(be32_t), &data);
}

int dhcp_message_append_option_sec(sd_dhcp_message *message, uint8_t code, usec_t usec) {
        assert(message);
        return dhcp_message_append_option_be32(message, code, usec_to_be32_sec(usec));
}

int dhcp_message_append_option_address(sd_dhcp_message *message, uint8_t code, const struct in_addr *addr) {
        assert(message);
        assert(addr);
        return dhcp_message_append_option_be32(message, code, addr->s_addr);
}

int dhcp_message_append_option_addresses(sd_dhcp_message *message, uint8_t code, size_t n_addr, const struct in_addr *addr) {
        assert(message);
        assert(n_addr == 0 || addr);

        if (n_addr == 0)
                return 0;

        if (size_multiply_overflow(sizeof(struct in_addr), n_addr))
                return -ENOBUFS;

        if (code == SD_DHCP_OPTION_SIP_SERVER) {
                if (dhcp_message_has_option(message, SD_DHCP_OPTION_SIP_SERVER))
                        return -EEXIST;

                size_t len = size_add(1, sizeof(struct in_addr) * n_addr);
                if (len == SIZE_MAX)
                        return -ENOBUFS;

                _cleanup_free_ uint8_t *buf = new(uint8_t, len);
                if (!buf)
                        return -ENOMEM;

                buf[0] = 1; /* 'enc' field, 0: domains, 1: addresses */
                memcpy(buf + 1, addr, sizeof(struct in_addr) * n_addr);

                return dhcp_message_append_option(message, code, len, buf);
        }

        return dhcp_message_append_option(message, code, sizeof(struct in_addr) * n_addr, addr);
}

int dhcp_message_append_option_string(sd_dhcp_message *message, uint8_t code, const char *data) {
        assert(message);

        if (isempty(data))
                return 0;

        if (!string_is_safe(data, STRING_ALLOW_BACKSLASHES | STRING_ALLOW_QUOTES | STRING_ALLOW_GLOBS))
                return -EINVAL;

        if (dhcp_message_has_option(message, code))
                return -EEXIST;

        return dhcp_message_append_option(message, code, strlen(data), data);
}

static int dhcp_message_append_option_static_routes(sd_dhcp_message *message, size_t n_routes, const sd_dhcp_route *routes) {
        int r;

        assert(message);
        assert(routes || n_routes == 0);

        if (n_routes == 0)
                return 0;

        if (size_multiply_overflow(2 * sizeof(struct in_addr), n_routes))
                return -ENOBUFS;

        _cleanup_free_ struct in_addr *buf = new(struct in_addr, 2 * n_routes);
        if (!buf)
                return -ENOMEM;

        size_t count = 0;
        FOREACH_ARRAY(route, routes, n_routes) {
                uint8_t prefixlen;
                r = in4_addr_default_prefixlen(&route->dst_addr, &prefixlen);
                if (r < 0)
                        return r;

                if (prefixlen != route->dst_prefixlen)
                        return -EINVAL;

                struct in_addr dst = route->dst_addr;
                (void) in4_addr_mask(&dst, prefixlen);

                buf[count++] = dst;
                buf[count++] = route->gw_addr;
        }

        assert(count == 2 * n_routes);

        return dhcp_message_append_option_addresses(message, SD_DHCP_OPTION_STATIC_ROUTE, 2 * n_routes, buf);
}

static int dhcp_message_append_option_classless_static_routes(sd_dhcp_message *message, uint8_t code, size_t n_routes, const sd_dhcp_route *routes) {
        assert(message);
        assert(routes || n_routes == 0);
        assert(IN_SET(code,
                      SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE,
                      SD_DHCP_OPTION_PRIVATE_CLASSLESS_STATIC_ROUTE));

        if (n_routes == 0)
                return 0;

        if (size_multiply_overflow(1 + 2 * sizeof(struct in_addr), n_routes))
                return -ENOBUFS;

        _cleanup_free_ uint8_t *buf = new(uint8_t, (1 + 2 * sizeof(struct in_addr)) * n_routes);
        if (!buf)
                return -ENOMEM;

        uint8_t *p = buf;
        FOREACH_ARRAY(route, routes, n_routes) {
                if (route->dst_prefixlen > sizeof(struct in_addr) * 8)
                        return -EINVAL;

                *p++ = route->dst_prefixlen;
                struct in_addr dst = route->dst_addr;
                (void) in4_addr_mask(&dst, route->dst_prefixlen);
                p = mempcpy(p, &dst, DIV_ROUND_UP(route->dst_prefixlen, 8));
                p = mempcpy(p, &route->gw_addr, sizeof(struct in_addr));
        }

        return dhcp_message_append_option(message, code, p - buf, buf);
}

int dhcp_message_append_option_routes(sd_dhcp_message *message, uint8_t code, size_t n_routes, const sd_dhcp_route *routes) {
        switch (code) {
        case SD_DHCP_OPTION_STATIC_ROUTE:
                return dhcp_message_append_option_static_routes(message, n_routes, routes);
        case SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE:
        case SD_DHCP_OPTION_PRIVATE_CLASSLESS_STATIC_ROUTE:
                return dhcp_message_append_option_classless_static_routes(message, code, n_routes, routes);
        default:
                return -EINVAL;
        }
}

int dhcp_message_append_option_6rd(
                sd_dhcp_message *message,
                uint8_t ipv4masklen,
                uint8_t prefixlen,
                const struct in6_addr *prefix,
                size_t n_br_addresses,
                const struct in_addr *br_addresses) {

        assert(message);
        assert(prefix);
        assert(n_br_addresses == 0 || br_addresses);

        /* See RFC 5969 Section 7.1.1 and dhcp_message_get_option_6rd() below. */

        if (dhcp_message_has_option(message, SD_DHCP_OPTION_6RD))
                return -EEXIST;

        if (ipv4masklen > 32)
                return -EINVAL;

        if (32 - ipv4masklen + prefixlen > 128)
                return -EINVAL;

        if (n_br_addresses == 0)
                return -EINVAL;

        if (size_multiply_overflow(sizeof(struct in_addr), n_br_addresses))
                return -ENOBUFS;

        size_t buflen = size_add(2 + sizeof(struct in6_addr), sizeof(struct in_addr) * n_br_addresses);
        if (buflen == SIZE_MAX)
                return -ENOBUFS;

        _cleanup_free_ uint8_t *buf = new(uint8_t, buflen);
        if (!buf)
                return -ENOMEM;

        uint8_t *p = buf;
        *p++ = ipv4masklen;
        *p++ = prefixlen;

        struct in6_addr masked = *prefix;
        (void) in6_addr_mask(&masked, prefixlen);
        p = mempcpy(p, &masked, sizeof(struct in6_addr));

        memcpy(p, br_addresses, n_br_addresses * sizeof(struct in_addr));

        return dhcp_message_append_option(message, SD_DHCP_OPTION_6RD, buflen, buf);
}

int dhcp_message_append_option_client_id(sd_dhcp_message *message, const sd_dhcp_client_id *id) {
        assert(message);
        assert(id);

        if (!sd_dhcp_client_id_is_set(id))
                return -EINVAL;

        if (dhcp_message_has_option(message, SD_DHCP_OPTION_CLIENT_IDENTIFIER))
                return -EEXIST;

        return dhcp_message_append_option(message, SD_DHCP_OPTION_CLIENT_IDENTIFIER, id->size, id->raw);
}

static int cmp_uint8(const uint8_t *a, const uint8_t *b) {
        assert(a);
        assert(b);

        return CMP(*a, *b);
}

int dhcp_message_append_option_parameter_request_list(sd_dhcp_message *message, Set *prl) {
        assert(message);

        size_t len = set_size(prl);
        if (len == 0)
                return 0;

        _cleanup_free_ uint8_t *buf = new(uint8_t, len);
        if (!buf)
                return -ENOMEM;

        uint8_t *p = buf;
        void *q;
        SET_FOREACH(q, prl)
                *p++ = PTR_TO_UINT8(q);

        /* Sort the options to make the message reproducible. */
        typesafe_qsort(buf, len, cmp_uint8);

        return dhcp_message_append_option(message, SD_DHCP_OPTION_PARAMETER_REQUEST_LIST, len, buf);
}

static int dhcp_message_append_option_fqdn(sd_dhcp_message *message, uint8_t flags, bool is_client, const char *fqdn) {
        int r;

        assert(message);
        assert(fqdn);

        /* FIXME: Allow long fqdn, as now we support long option. */
        uint8_t buf[3 + DHCP_MAX_FQDN_LENGTH];

        /* RFC 4702 section 2.1
         * The "E" bit indicates the encoding of the Domain Name field. 1 indicates canonical wire format,
         * without compression. This encoding SHOULD be used by clients and MUST be supported by servers.
         * A server MUST use the same encoding as that used by the client. A server that does not support
         * the deprecated ASCII encoding MUST ignore Client FQDN options that use that encoding.
         *
         * Here, we unconditionally set the 'E' flag. Hence, sd_dhcp_server must ignore the option if a
         * client does not set the 'E' flag in the request. */
        buf[0] = flags | DHCP_FQDN_FLAG_E;

        /* RFC 4702 section 2.2
         * The two 1-octet RCODE1 and RCODE2 fields are deprecated. A client SHOULD set these to 0 when
         * sending the option and SHOULD ignore them on receipt. A server SHOULD set these to 255 when
         * sending the option and MUST ignore them on receipt. */
        buf[1] = is_client ? 0 : 255;
        buf[2] = is_client ? 0 : 255;

        r = dns_name_to_wire_format(fqdn, buf + 3, sizeof(buf) - 3, false);
        if (r <= 0)
                return r;

        return dhcp_message_append_option(message, SD_DHCP_OPTION_FQDN, 3 + r, buf);
}

int dhcp_message_append_option_hostname(sd_dhcp_message *message, uint8_t flags, bool is_client, const char *hostname) {
        assert(message);

        /* Hostname (12) or FQDN (81)
         *
         * RFC 4702 section 3.1
         * clients that send the Client FQDN option in their messages MUST NOT also send the Host Name option. */

        if (isempty(hostname))
                return 0;

        if (dhcp_message_has_option(message, SD_DHCP_OPTION_HOST_NAME))
                return -EEXIST;

        if (dhcp_message_has_option(message, SD_DHCP_OPTION_FQDN))
                return -EEXIST;

        if (dns_name_is_single_label(hostname))
                return dhcp_message_append_option_string(message, SD_DHCP_OPTION_HOST_NAME, hostname);

        return dhcp_message_append_option_fqdn(message, flags, is_client, hostname);
}

int dhcp_message_append_option_sub_tlv(sd_dhcp_message *message, uint8_t code, const TLV *tlv) {
        int r;

        assert(message);

        if (tlv_isempty(tlv))
                return 0;

        if (dhcp_message_has_option(message, code))
                return -EEXIST;

        _cleanup_(iovec_done) struct iovec iov = {};
        r = tlv_build(tlv, &iov);
        if (r < 0)
                return r;

        return dhcp_message_append_option(message, code, iov.iov_len, iov.iov_base);
}

int dhcp_message_append_option_length_prefixed_data(
                sd_dhcp_message *message,
                uint8_t code,
                size_t length_size,
                const struct iovec_wrapper *iovw) {

        int r;

        assert(message);

        _cleanup_(iovec_done) struct iovec iov = {};
        r = iovw_merge(iovw, length_size, &iov);
        if (r < 0)
                return r;

        if (!iovec_is_set(&iov))
                return 0;

        return dhcp_message_append_option(message, code, iov.iov_len, iov.iov_base);
}

int dhcp_message_get_option(sd_dhcp_message *message, uint8_t code, size_t length, void *ret) {
        int r;

        assert(message);

        struct iovec iov;
        r = tlv_get_full(&message->options, code, length, ret ? &iov : NULL);
        if (r < 0)
                return r;

        if (ret)
                memcpy_safe(ret, iov.iov_base, iov.iov_len);
        return 0;
}

int dhcp_message_get_option_alloc(sd_dhcp_message *message, uint8_t code, struct iovec *ret) {
        assert(message);
        return tlv_get_alloc(&message->options, code, ret);
}

int dhcp_message_get_option_flag(sd_dhcp_message *message, uint8_t code) {
        assert(message);
        return dhcp_message_get_option(message, code, /* length= */ 0, /* ret= */ NULL);
}

int dhcp_message_get_option_u8(sd_dhcp_message *message, uint8_t code, uint8_t *ret) {
        assert(message);
        return dhcp_message_get_option(message, code, sizeof(uint8_t), ret);
}

int dhcp_message_get_option_u16(sd_dhcp_message *message, uint8_t code, uint16_t *ret) {
        be16_t b;
        int r;

        assert(message);

        r = dhcp_message_get_option(message, code, sizeof(be16_t), ret ? &b : NULL);
        if (r < 0)
                return r;

        if (ret)
                *ret = be16toh(b);
        return 0;
}

int dhcp_message_get_option_be32(sd_dhcp_message *message, uint8_t code, be32_t *ret) {
        assert(message);
        return dhcp_message_get_option(message, code, sizeof(be32_t), ret);
}

int dhcp_message_get_option_sec(sd_dhcp_message *message, uint8_t code, bool max_as_infinity, usec_t *ret) {
        int r;

        assert(message);

        be32_t t;
        r = dhcp_message_get_option_be32(message, code, &t);
        if (r < 0)
                return r;

        if (ret)
                *ret = be32_sec_to_usec(t, max_as_infinity);
        return 0;
}

int dhcp_message_get_option_address(sd_dhcp_message *message, uint8_t code, struct in_addr *ret) {
        assert(message);
        return dhcp_message_get_option_be32(message, code, ret ? &ret->s_addr : NULL);
}

int dhcp_message_get_option_addresses(sd_dhcp_message *message, uint8_t code, size_t *ret_n_addr, struct in_addr **ret_addr) {
        int r;

        assert(message);
        assert(ret_n_addr || !ret_addr);

        _cleanup_(iovec_done) struct iovec iov_free = {};
        r = dhcp_message_get_option_alloc(message, code, &iov_free);
        if (r < 0)
                return r;

        struct iovec iov = iov_free;
        if (code == SD_DHCP_OPTION_SIP_SERVER) {
                if (!iovec_is_set(&iov))
                        return -EBADMSG;

                if (*(uint8_t*) iov.iov_base != 1) /* 'enc' field, 0: domains, 1: addresses */
                        return -ENODATA;

                iovec_inc(&iov, 1);
        }

        if (iov.iov_len % sizeof(struct in_addr) != 0)
                return -EBADMSG;

        size_t n = iov.iov_len / sizeof(struct in_addr);
        if (n == 0)
                return -ENODATA;

        if (ret_addr) {
                if (code == SD_DHCP_OPTION_SIP_SERVER) {
                        struct in_addr *addr = newdup(struct in_addr, iov.iov_base, n);
                        if (!addr)
                                return -ENOMEM;
                        *ret_addr = addr;
                } else {
                        *ret_addr = iov.iov_base;
                        TAKE_STRUCT(iov_free);
                }
        }
        if (ret_n_addr)
                *ret_n_addr = n;
        return 0;
}

int dhcp_message_get_option_string(sd_dhcp_message *message, uint8_t code, char **ret) {
        int r;

        assert(message);

        _cleanup_(iovec_done) struct iovec iov = {};
        r = dhcp_message_get_option_alloc(message, code, &iov);
        if (r < 0)
                return r;

        if (!iovec_is_set(&iov))
                return -ENODATA;

        /* Allow NUL at the end for buggy DHCP servers, but refuse intermediate NUL. */
        if (memchr(iov.iov_base, 0, iov.iov_len - 1))
                return -EBADMSG;

        /* Note, dhcp_message_get_option_alloc() -> tlv_get_alloc() allocates an extra byte to make
         * iov.iov_base can be handled as a NUL-terminated string. Hence, we can directly pass it to
         * isempty() and string_is_safe(). */

        if (isempty(iov.iov_base))
                return -ENODATA;

        if (!string_is_safe(iov.iov_base, STRING_ALLOW_BACKSLASHES | STRING_ALLOW_QUOTES | STRING_ALLOW_GLOBS))
                return -EBADMSG;

        if (ret)
                *ret = TAKE_PTR(iov.iov_base);
        return 0;
}

static int dhcp_message_get_option_static_routes(sd_dhcp_message *message, size_t *ret_n_routes, sd_dhcp_route **ret_routes) {
        int r;

        assert(message);

        size_t n;
        _cleanup_free_ struct in_addr *addrs = NULL;
        r = dhcp_message_get_option_addresses(message, SD_DHCP_OPTION_STATIC_ROUTE, &n, &addrs);
        if (r < 0)
                return r;

        if (n % 2 != 0)
                return -EBADMSG;

        _cleanup_free_ sd_dhcp_route *routes = NULL;
        size_t n_routes = 0;

        for (size_t i = 0; i < n; i += 2) {
                struct in_addr dst = addrs[i];

                uint8_t prefixlen;
                if (in4_addr_default_prefixlen(&dst, &prefixlen) < 0)
                        continue;

                (void) in4_addr_mask(&dst, prefixlen);

                /* RFC 2132 section 5.8:
                * The default route (0.0.0.0) is an illegal destination for a static route.*/
                if (in4_addr_is_null(&dst))
                        continue;

                if (!ret_routes) {
                        n_routes++;
                        continue;
                }

                if (!GREEDY_REALLOC(routes, n_routes + 1))
                        return -ENOMEM;

                routes[n_routes++] = (struct sd_dhcp_route) {
                        .dst_addr = dst,
                        .gw_addr = addrs[i + 1],
                        .dst_prefixlen = prefixlen,
                };
        }

        if (n_routes == 0)
                return -ENODATA;

        if (ret_routes)
                *ret_routes = TAKE_PTR(routes);
        if (ret_n_routes)
                *ret_n_routes = n_routes;
        return 0;
}

static int dhcp_message_get_option_classless_static_routes(sd_dhcp_message *message, uint8_t code, size_t *ret_n_routes, sd_dhcp_route **ret_routes) {
        int r;

        assert(message);
        assert(IN_SET(code,
                      SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE,
                      SD_DHCP_OPTION_PRIVATE_CLASSLESS_STATIC_ROUTE));

        _cleanup_(iovec_done) struct iovec iov = {};
        r = dhcp_message_get_option_alloc(message, code, &iov);
        if (r < 0)
                return r;

        _cleanup_free_ sd_dhcp_route *routes = NULL;
        size_t n_routes = 0;

        for (struct iovec i = iov; iovec_is_set(&i);) {
                uint8_t prefixlen = *(uint8_t*) i.iov_base;
                iovec_inc(&i, 1);

                if (prefixlen > 32)
                        return -EBADMSG;

                size_t n = DIV_ROUND_UP(prefixlen, 8);
                if (n > i.iov_len)
                        return -EBADMSG;

                struct in_addr dst = {};
                memcpy_safe(&dst, i.iov_base, n);
                (void) in4_addr_mask(&dst, prefixlen);
                iovec_inc(&i, n);

                if (i.iov_len < sizeof(struct in_addr))
                        return -EBADMSG;

                struct in_addr gw;
                memcpy(&gw, i.iov_base, sizeof(struct in_addr));
                iovec_inc(&i, sizeof(struct in_addr));

                if (!ret_routes) {
                        n_routes++;
                        continue;
                }

                if (!GREEDY_REALLOC(routes, n_routes + 1))
                        return -ENOMEM;

                routes[n_routes++] = (struct sd_dhcp_route) {
                        .dst_addr = dst,
                        .gw_addr = gw,
                        .dst_prefixlen = prefixlen,
                };
        }

        if (n_routes == 0)
                return -ENODATA;

        if (ret_routes)
                *ret_routes = TAKE_PTR(routes);
        if (ret_n_routes)
                *ret_n_routes = n_routes;
        return 0;
}

int dhcp_message_get_option_routes(sd_dhcp_message *message, uint8_t code, size_t *ret_n_routes, sd_dhcp_route **ret_routes) {
        switch (code) {
        case SD_DHCP_OPTION_STATIC_ROUTE:
                return dhcp_message_get_option_static_routes(message, ret_n_routes, ret_routes);
        case SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE:
        case SD_DHCP_OPTION_PRIVATE_CLASSLESS_STATIC_ROUTE:
                return dhcp_message_get_option_classless_static_routes(message, code, ret_n_routes, ret_routes);
        default:
                return -EINVAL;
        }
}

int dhcp_message_get_option_6rd(
                sd_dhcp_message *message,
                uint8_t *ret_ipv4masklen,
                uint8_t *ret_prefixlen,
                struct in6_addr *ret_prefix,
                size_t *ret_n_br_addresses,
                struct in_addr **ret_br_addresses) {

        int r;

        assert(message);
        assert(ret_n_br_addresses || !ret_br_addresses);

        /* See RFC 5969 Section 7.1.1 */

        _cleanup_(iovec_done) struct iovec iov = {};
        r = dhcp_message_get_option_alloc(message, SD_DHCP_OPTION_6RD, &iov);
        if (r < 0)
                return r;

        /* option-length: The length of the DHCP option in octets (22 octets with one BR IPv4 address). */
        if (iov.iov_len < 2 + sizeof(struct in6_addr) + sizeof(struct in_addr) ||
            (iov.iov_len - 2 - sizeof(struct in6_addr)) % sizeof(struct in_addr) != 0)
                return -EBADMSG;

        size_t n_br_addresses = (iov.iov_len - 2 - sizeof(struct in6_addr)) / sizeof(struct in_addr);
        assert(n_br_addresses > 0); /* We have already checked that in the above. */

        const uint8_t *p = iov.iov_base;

        /* IPv4MaskLen: The number of high-order bits that are identical across all CE IPv4 addresses
         *              within a given 6rd domain. This may be any value between 0 and 32. Any value
         *              greater than 32 is invalid. */
        uint8_t ipv4masklen = *p++;
        if (ipv4masklen > 32)
                return -EBADMSG;

        /* 6rdPrefixLen: The IPv6 prefix length of the SP's 6rd IPv6 prefix in number of bits. For the
         *               purpose of bounds checking by DHCP option processing, the sum of
         *               (32 - IPv4MaskLen) + 6rdPrefixLen MUST be less than or equal to 128. */
        uint8_t prefixlen = *p++;
        if (32 - ipv4masklen + prefixlen > 128)
                return -EBADMSG;

        /* 6rdPrefix: The service provider's 6rd IPv6 prefix represented as a 16-octet IPv6 address.
         *            The bits in the prefix after the 6rdPrefixlen number of bits are reserved and
         *            MUST be initialized to zero by the sender and ignored by the receiver. */
        struct in6_addr prefix;
        memcpy(&prefix, p, sizeof(struct in6_addr));
        (void) in6_addr_mask(&prefix, prefixlen);
        p += sizeof(struct in6_addr);

        /* 6rdBRIPv4Address: One or more IPv4 addresses of the 6rd Border Relays for a given 6rd domain. */
        if (ret_br_addresses) {
                struct in_addr *br_addresses = newdup(struct in_addr, p, n_br_addresses);
                if (!br_addresses)
                        return -ENOMEM;

                *ret_br_addresses = br_addresses;
        }

        if (ret_ipv4masklen)
                *ret_ipv4masklen = ipv4masklen;
        if (ret_prefixlen)
                *ret_prefixlen = prefixlen;
        if (ret_prefix)
                *ret_prefix = prefix;
        if (ret_n_br_addresses)
                *ret_n_br_addresses = n_br_addresses;
        return 0;
}

int dhcp_message_get_option_client_id(sd_dhcp_message *message, sd_dhcp_client_id *ret) {
        int r;

        assert(message);
        assert(ret);

        _cleanup_(iovec_done) struct iovec iov = {};
        r = dhcp_message_get_option_alloc(message, SD_DHCP_OPTION_CLIENT_IDENTIFIER, &iov);
        if (r < 0)
                return r;

        return sd_dhcp_client_id_set_raw(ret, iov.iov_base, iov.iov_len);
}

int dhcp_message_get_option_parameter_request_list(sd_dhcp_message *message, Set **ret) {
        int r;

        assert(message);

        _cleanup_(iovec_done) struct iovec iov = {};
        r = dhcp_message_get_option_alloc(message, SD_DHCP_OPTION_PARAMETER_REQUEST_LIST, &iov);
        if (r < 0)
                return r;

        if (!iovec_is_set(&iov))
                return -ENODATA;

        if (!ret)
                return 0;

        _cleanup_set_free_ Set *prl = NULL;
        for (struct iovec i = iov; iovec_is_set(&i); iovec_inc(&i, 1)) {
                r = set_ensure_put(&prl, /* hash_ops= */ NULL, UINT8_TO_PTR(*(uint8_t*) i.iov_base));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(prl);
        return 0;
}

static int normalize_dns_name(const char *name, char **ret) {
        int r;

        assert(name);

        _cleanup_free_ char *normalized = NULL;
        r = dns_name_normalize(name, /* flags= */ 0, &normalized);
        if (r < 0)
                return r;

        if (is_localhost(normalized))
                return -EINVAL;

        if (dns_name_is_root(normalized))
                return -EINVAL;

        if (ret)
                *ret = TAKE_PTR(normalized);
        return 0;
}

int dhcp_message_get_option_fqdn(sd_dhcp_message *message, uint8_t *ret_flags, char **ret_fqdn) {
        int r;

        assert(message);

        _cleanup_(iovec_done) struct iovec iov = {};
        r = dhcp_message_get_option_alloc(message, SD_DHCP_OPTION_FQDN, &iov);
        if (r < 0)
                return r;

        if (iov.iov_len <= 3)
                return -EBADMSG;

        uint8_t flags = *(uint8_t*) iov.iov_base;
        if (!FLAGS_SET(flags, DHCP_FQDN_FLAG_E))
                return -EOPNOTSUPP;

        struct iovec i;
        iovec_shift(&iov, 3, &i);

        _cleanup_free_ char *name = NULL;
        const uint8_t *p = i.iov_base;
        r = dns_name_from_wire_format(&p, &i.iov_len, &name);
        if (r < 0)
                return r;
        if (i.iov_len > 0) /* trailing garbage? */
                return -EBADMSG;

        if (isempty(name))
                return -ENODATA;

        if (!string_is_safe(name, /* flags= */ 0))
                return -EBADMSG;

        _cleanup_free_ char *normalized = NULL;
        r = normalize_dns_name(name, &normalized);
        if (r < 0)
                return r;

        if (ret_flags)
                *ret_flags = flags;
        if (ret_fqdn)
                *ret_fqdn = TAKE_PTR(normalized);
        return 0;
}

int dhcp_message_get_option_dns_name(sd_dhcp_message *message, uint8_t code, char **ret) {
        int r;

        assert(message);

        /* Mainly for Host Name or Domain Name options. */

        _cleanup_free_ char *name = NULL;
        r = dhcp_message_get_option_string(message, code, &name);
        if (r < 0)
                return r;

        _cleanup_free_ char *normalized = NULL;
        r = normalize_dns_name(name, &normalized);
        if (r < 0)
                return r;

        if (ret)
                *ret = TAKE_PTR(normalized);
        return 0;
}

int dhcp_message_get_option_hostname(sd_dhcp_message *message, char **ret) {
        int r;

        assert(message);

        /* FQDN option always takes precedence. */
        r = dhcp_message_get_option_fqdn(message, /* ret_flags= */ NULL, ret);
        if (ERRNO_IS_NEG_RESOURCE(r))
                return r;
        if (r >= 0)
                return 0;

        /* Then, fall back to Host Name option. */
        return dhcp_message_get_option_dns_name(message, SD_DHCP_OPTION_HOST_NAME, ret);
}

int dhcp_message_get_option_domains(sd_dhcp_message *message, uint8_t code, char ***ret) {
        int r;

        assert(message);

        /* This is mostly for SD_DHCP_OPTION_DOMAIN_SEARCH and SD_DHCP_OPTION_SIP_SERVER. */

        _cleanup_(iovec_done) struct iovec iov = {};
        r = dhcp_message_get_option_alloc(message, code, &iov);
        if (r < 0)
                return r;

        const uint8_t *buf = iov.iov_base;
        size_t len = iov.iov_len;

        if (code == SD_DHCP_OPTION_SIP_SERVER) {
                if (len == 0)
                        return -EBADMSG;

                if (buf[0] != 0) /* 'enc' field, 0: domains, 1: addresses */
                        return -ENODATA;

                len--;
                buf++;
        }

        _cleanup_strv_free_ char **names = NULL;
        size_t n_names = 0;

        _cleanup_free_ char *name = NULL;
        size_t n = 0;

        for (size_t pos = 0, jump_barrier = 0, next_chunk = 0; pos < len;) {
                uint8_t c = buf[pos++];

                if (c == 0) {
                        /* End of name */

                        if (!string_is_safe(name, /* flags= */ 0))
                                return -EBADMSG;

                        _cleanup_free_ char *normalized = NULL;
                        r = normalize_dns_name(name, &normalized);
                        if (r < 0)
                                return r;

                        r = strv_consume_with_size(&names, &n_names, TAKE_PTR(normalized));
                        if (r < 0)
                                return r;

                        if (next_chunk != 0)
                                pos = next_chunk;

                        next_chunk = 0;
                        jump_barrier = pos;

                        name = mfree(name);
                        n = 0;

                } else if (c <= 63) {
                        /* Literal label */

                        const char *label = (const char*) (buf + pos);
                        pos += c;

                        if (pos >= len)
                                return -EBADMSG;

                        if (!GREEDY_REALLOC(name, n + 1 + DNS_LABEL_ESCAPED_MAX))
                                return -ENOMEM;

                        if (n != 0)
                                name[n++] = '.';

                        r = dns_label_escape(label, c, name + n, DNS_LABEL_ESCAPED_MAX);
                        if (r < 0)
                                return r;

                        n += r;

                } else if (FLAGS_SET(c, 0xc0)) {
                        /* Pointer */

                        if (pos >= len) /* pointer is 2 bytes, hence we need to read at least one more byte. */
                                return -EBADMSG;

                        /* Save the current location so we don't end up re-parsing what's parsed so far. */
                        if (next_chunk == 0)
                                next_chunk = pos + 1;

                        pos = ((size_t) (c & ~0xc0) << 8) | ((size_t) buf[pos]);

                        /* Jumps are limited to a "prior occurrence" (RFC-1035 4.1.4) */
                        if (pos >= jump_barrier)
                                return -EBADMSG;

                        jump_barrier = pos;

                } else
                        return -EBADMSG;
        }

        if (!isempty(name)) /* trailing garbage?? Should not happen, but for safety. */
                return -EBADMSG;

        if (strv_isempty(names))
                return -EBADMSG;

        if (ret)
                *ret = TAKE_PTR(names);
        return 0;
}

int dhcp_message_get_option_sub_tlv(sd_dhcp_message *message, uint8_t code, TLVFlag flags, TLV **ret) {
        int r;

        assert(message);
        assert(!FLAGS_SET(flags, TLV_TEMPORARY));

        _cleanup_(iovec_done) struct iovec iov = {};
        r = dhcp_message_get_option_alloc(message, code, &iov);
        if (r < 0)
                return r;

        _cleanup_(tlv_unrefp) TLV *tlv = tlv_new(flags);
        if (!tlv)
                return -ENOMEM;

        r = tlv_parse(tlv, &iov);
        if (r < 0)
                return r;

        if (tlv_isempty(tlv))
                return -ENODATA;

        if (ret)
                *ret = TAKE_PTR(tlv);
        return 0;
}

int dhcp_message_get_option_length_prefixed_data(
                sd_dhcp_message *message,
                uint8_t code,
                size_t length_size,
                struct iovec_wrapper *ret) {

        int r;

        assert(message);

        _cleanup_(iovec_done) struct iovec iov = {};
        r = dhcp_message_get_option_alloc(message, code, &iov);
        if (r < 0)
                return r;

        _cleanup_(iovw_done_free) struct iovec_wrapper iovw = {};
        r = iovec_split(&iov, length_size, &iovw);
        if (r < 0)
                return r;

        if (iovw_isempty(&iovw))
                return -ENODATA;

        if (ret)
                *ret = TAKE_STRUCT(iovw);
        return 0;
}

static int parse_dnr_one(const struct iovec *iov, sd_dns_resolver *ret) {
        int r;

        assert(iovec_is_set(iov));
        assert(ret);

        _cleanup_(sd_dns_resolver_done) sd_dns_resolver resolver = {};
        struct iovec i = *iov;

        /* service priority */
        if (i.iov_len < sizeof(be16_t))
                return -EBADMSG;

        resolver.priority = unaligned_read_be16(i.iov_base);
        iovec_inc(&i, sizeof(be16_t));

        /* RFC 9460 section 2.4.1:
         * When SvcPriority is 0, the SVCB record is in AliasMode.
         *
         * We do not support the alias mode. But the entry itself is not invalid. */
        if (resolver.priority == 0) {
                *ret = (sd_dns_resolver) {};
                return 0;
        }

        /* authentication domain name */
        if (!iovec_is_set(&i))
                return -EBADMSG;

        size_t name_len = *(uint8_t*) i.iov_base;
        iovec_inc(&i, 1);
        if (i.iov_len < name_len)
                return -EBADMSG;

        const uint8_t *name_buf = i.iov_base;
        iovec_inc(&i, name_len);

        r = dns_name_from_wire_format(&name_buf, &name_len, &resolver.auth_name);
        if (r < 0)
                return r;
        if (r == 0 || name_len != 0)
                return -EBADMSG;

        r = dns_name_is_valid_ldh(resolver.auth_name);
        if (r < 0)
                return r;
        if (r == 0)
                return -EBADMSG;

        if (dns_name_is_root(resolver.auth_name))
                return -EBADMSG;

        /* RFC9463 section 3.1.6: In ADN-only mode, server omits everything after the ADN.
         *
         * We don't support these, but they are not invalid. */
        if (!iovec_is_set(&i)) {
                *ret = (sd_dns_resolver) {};
                return 0;
        }

        /* IPv4 addresses */
        size_t n = *(uint8_t*) i.iov_base;
        iovec_inc(&i, 1);

        if (n % sizeof(struct in_addr) != 0)
                return -EBADMSG;

        n /= sizeof(struct in_addr);

        /* RFC9463 section 3.1.8: option MUST include at least one valid IP addr */
        if (n == 0)
                return -EBADMSG;

        resolver.family = AF_INET;
        resolver.n_addrs = n;
        resolver.addrs = new(union in_addr_union, n);
        if (!resolver.addrs)
                return -ENOMEM;

        for (size_t j = 0; j < n; j++) {
                if (i.iov_len < sizeof(struct in_addr))
                        return -EBADMSG;

                struct in_addr a;
                memcpy(&a, i.iov_base, sizeof(struct in_addr));
                iovec_inc(&i, sizeof(struct in_addr));

                /* RFC9463 section 5.2: client MUST discard multicast and host loopback addresses */
                if (in4_addr_is_multicast(&a) || in4_addr_is_localhost(&a))
                        return -EBADMSG;

                resolver.addrs[j] = (union in_addr_union) { .in = a };
        }

        /* service params */
        r = dnr_parse_svc_params(i.iov_base, i.iov_len, &resolver);
        if (r < 0)
                return r;
        if (r == 0) {
                /* We can't use this record, but it is not invalid. */
                *ret = (sd_dns_resolver) {};
                return 0;
        }

        *ret = TAKE_STRUCT(resolver);
        return 1;
}

int dhcp_message_get_option_dnr(sd_dhcp_message *message, size_t *ret_n_resolvers, sd_dns_resolver **ret_resolvers) {
        int r;

        assert(message);
        assert(ret_n_resolvers || !ret_resolvers);

        /* See RFC 9463 section 5.1 */

        _cleanup_(iovw_done_free) struct iovec_wrapper iovw = {};
        r = dhcp_message_get_option_length_prefixed_data(message, SD_DHCP_OPTION_V4_DNR, /* length_size= */ 2, &iovw);
        if (r < 0)
                return r;

        sd_dns_resolver *resolvers = NULL;
        size_t n_resolvers = 0;
        CLEANUP_ARRAY(resolvers, n_resolvers, dns_resolver_free_array);
        FOREACH_ARRAY(i, iovw.iovec, iovw.count) {
                _cleanup_(sd_dns_resolver_done) sd_dns_resolver dnr = {};
                r = parse_dnr_one(i, &dnr);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                if (!ret_resolvers) {
                        n_resolvers++;
                        continue;
                }

                if (!GREEDY_REALLOC(resolvers, n_resolvers + 1))
                        return -ENOMEM;

                resolvers[n_resolvers++] = TAKE_STRUCT(dnr);
        }

        if (n_resolvers == 0) /* no supported resolver */
                return -ENODATA;

        if (ret_resolvers) {
                /* Sort the resolvers with their priorities. */
                typesafe_qsort(resolvers, n_resolvers, dns_resolver_prio_compare);
                *ret_resolvers = TAKE_PTR(resolvers);
        }
        if (ret_n_resolvers)
                *ret_n_resolvers = n_resolvers;

        return 0;
}

static int dhcp_message_verify_header(
                const struct iovec *iov,
                uint8_t op,
                const uint32_t *xid,
                uint16_t arp_type,
                const struct hw_addr_data *hw_addr) {

        assert(iov);
        assert(iovec_is_valid(iov));
        assert(IN_SET(op, 0, BOOTREQUEST, BOOTREPLY)); /* when 0, both BOOTREQUEST and BOOTREPLY are accepted */

        POINTER_MAY_BE_NULL(xid);
        POINTER_MAY_BE_NULL(hw_addr);

        if (iov->iov_len < sizeof(DHCPMessageHeader))
                return -EBADMSG;

        const DHCPMessageHeader *header = iov->iov_base;

        if (!IN_SET(header->op, BOOTREQUEST, BOOTREPLY))
                return -EBADMSG;
        if (op != 0 && header->op != op)
                return -EBADMSG;

        if (xid && be32toh(header->xid) != *xid)
                return -EBADMSG;

        if (arp_type <= UINT8_MAX && header->htype != arp_type)
                return -EBADMSG;

        if (header->hlen > sizeof_field(DHCPMessageHeader, chaddr))
                return -EBADMSG;

        if (hw_addr && memcmp_nn(header->chaddr, header->hlen, hw_addr->bytes, hw_addr->length) != 0)
                return -EBADMSG;

        return 0;
}

int dhcp_message_parse(
                const struct iovec *iov,
                uint8_t op,
                const uint32_t *xid,
                uint16_t arp_type,
                const struct hw_addr_data *hw_addr,
                sd_dhcp_message **ret) {

        int r;

        assert(iov);
        assert(ret);

        r = dhcp_message_verify_header(iov, op, xid, arp_type, hw_addr);
        if (r < 0)
                return r;

        _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *message = NULL;
        r = dhcp_message_new(&message);
        if (r < 0)
                return r;

        memcpy(&message->header, iov->iov_base, sizeof(DHCPMessageHeader));

        if (be32toh(message->header.magic) != DHCP_MAGIC_COOKIE) {
                /* Should be BOOTP, and no options. */
                *ret = TAKE_PTR(message);
                return 0;
        }

        /* In the BOOTP protocol (RFC 951), the vendor field (magic + options) is 64 bytes, but here we do
         * not check the length, and support all DHCP options even if we are running as BOOTP client. */

        r = tlv_parse(&message->options, &IOVEC_SHIFT(iov, sizeof(DHCPMessageHeader)));
        if (r < 0)
                return r;

        /* Parse SD_DHCP_OPTION_OVERLOAD (52) to determine if we should parse sname and/or file. */
        uint8_t overload = DHCP_OVERLOAD_NONE;
        (void) dhcp_message_get_option_u8(message, SD_DHCP_OPTION_OVERLOAD, &overload);

        if (FLAGS_SET(overload, DHCP_OVERLOAD_FILE)) {
                r = tlv_parse(&message->options, &IOVEC_MAKE(message->header.file, sizeof(message->header.file)));
                if (r < 0)
                        return r;
        }

        if (FLAGS_SET(overload, DHCP_OVERLOAD_SNAME)) {
                r = tlv_parse(&message->options, &IOVEC_MAKE(message->header.sname, sizeof(message->header.sname)));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(message);
        return 0;
}

int dhcp_message_build(sd_dhcp_message *message, struct iovec_wrapper *ret) {
        int r;

        assert(message);
        assert(ret);

        size_t size = size_add(sizeof(DHCPMessageHeader), tlv_size(&message->options));
        if (size > UDP_PAYLOAD_MAX_SIZE)
                return -E2BIG;

        _cleanup_(iovw_done_free) struct iovec_wrapper iovw = {};
        r = iovw_extend(&iovw, &message->header, sizeof(DHCPMessageHeader));
        if (r < 0)
                return r;

        struct iovec options;
        r = tlv_build(&message->options, &options);
        if (r < 0)
                return r;

        r = iovw_consume_iov(&iovw, &options);
        if (r < 0)
                return r;

        /* For compatibility with other implementations and network appliances, the message size should be at
         * least 300 bytes, which is the size of BOOTP message. */
        size_t padding_size = LESS_BY(BOOTP_MESSAGE_SIZE, size);
        if (padding_size > 0) {
                uint8_t *padding = new0(uint8_t, padding_size);
                if (!padding)
                        return -ENOMEM;

                r = iovw_consume(&iovw, padding, padding_size);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_STRUCT(iovw);
        return 0;
}

int dhcp_message_build_json(sd_dhcp_message *message, sd_json_variant **ret) {
        int r;

        assert(message);
        assert(message->header.hlen <= sizeof(message->header.chaddr));
        assert(ret);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        r = sd_json_buildo(
                        &v,
                        SD_JSON_BUILD_PAIR_UNSIGNED("op", message->header.op),
                        SD_JSON_BUILD_PAIR_UNSIGNED("htype", message->header.htype),
                        SD_JSON_BUILD_PAIR_UNSIGNED("hops", message->header.hops),
                        SD_JSON_BUILD_PAIR_UNSIGNED("xid", be32toh(message->header.xid)),
                        SD_JSON_BUILD_PAIR_UNSIGNED("secs", be16toh(message->header.secs)),
                        SD_JSON_BUILD_PAIR_UNSIGNED("flags", be16toh(message->header.flags)),
                        JSON_BUILD_PAIR_HEX_NON_EMPTY("ciaddr", &message->header.ciaddr, sizeof(message->header.ciaddr)),
                        JSON_BUILD_PAIR_HEX_NON_EMPTY("yiaddr", &message->header.yiaddr, sizeof(message->header.yiaddr)),
                        JSON_BUILD_PAIR_HEX_NON_EMPTY("siaddr", &message->header.siaddr, sizeof(message->header.siaddr)),
                        JSON_BUILD_PAIR_HEX_NON_EMPTY("giaddr", &message->header.giaddr, sizeof(message->header.giaddr)),
                        JSON_BUILD_PAIR_HEX_NON_EMPTY("chaddr", message->header.chaddr, message->header.hlen));
        if (r < 0)
                return r;

        uint8_t overload = DHCP_OVERLOAD_NONE;
        (void) dhcp_message_get_option_u8(message, SD_DHCP_OPTION_OVERLOAD, &overload);

        if (!FLAGS_SET(overload, DHCP_OVERLOAD_SNAME) && !eqzero(message->header.sname)) {
                r = sd_json_variant_merge_objectbo(
                                &v,
                                JSON_BUILD_PAIR_HEX_NON_EMPTY("sname", message->header.sname, sizeof(message->header.sname)));
                if (r < 0)
                        return r;
        }

        if (!FLAGS_SET(overload, DHCP_OVERLOAD_FILE) && !eqzero(message->header.file)) {
                r = sd_json_variant_merge_objectbo(
                                &v,
                                JSON_BUILD_PAIR_HEX_NON_EMPTY("file", message->header.file, sizeof(message->header.file)));
                if (r < 0)
                        return r;
        }

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;
        r = tlv_build_json(&message->options, &w);
        if (r < 0)
                return r;

        r = sd_json_variant_merge_objectbo(
                        &v,
                        JSON_BUILD_PAIR_VARIANT_NON_NULL("options", w));
        if (r < 0)
                return r;

        *ret = TAKE_PTR(v);
        return 0;
}

typedef struct MessageParam {
        uint8_t op;
        uint8_t htype;
        uint8_t hops;
        uint32_t xid;
        uint16_t secs;
        uint16_t flags;
        struct iovec ciaddr;
        struct iovec yiaddr;
        struct iovec siaddr;
        struct iovec giaddr;
        struct iovec chaddr;
        struct iovec sname;
        struct iovec file;
        TLV *options;
} MessageParam;

static void message_param_done(MessageParam *p) {
        assert(p);

        iovec_done(&p->ciaddr);
        iovec_done(&p->yiaddr);
        iovec_done(&p->siaddr);
        iovec_done(&p->giaddr);
        iovec_done(&p->chaddr);
        iovec_done(&p->sname);
        iovec_done(&p->file);
        tlv_unref(p->options);
}

static int dispatch_options(const char *name, sd_json_variant *v, sd_json_dispatch_flags_t flags, void *userdata) {
        TLV **options = ASSERT_PTR(userdata);
        int r;

        if (*options)
                return -EINVAL; /* multiple options field? */

        _cleanup_(tlv_unrefp) TLV *tlv = tlv_new(TLV_DHCP4);
        if (!tlv)
                return -ENOMEM;

        r = tlv_parse_json(tlv, v);
        if (r < 0)
                return r;

        *options = TAKE_PTR(tlv);
        return 0;
}

int dhcp_message_parse_json(sd_json_variant *v, sd_dhcp_message **ret) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "op",      _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint8,    offsetof(MessageParam, op),      SD_JSON_MANDATORY },
                { "htype",   _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint8,    offsetof(MessageParam, htype),   0                 },
                { "hops",    _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint8,    offsetof(MessageParam, hops),    0                 },
                { "xid",     _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint32,   offsetof(MessageParam, xid),     0                 },
                { "secs",    _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint16,   offsetof(MessageParam, secs),    0                 },
                { "flags",   _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint16,   offsetof(MessageParam, flags),   0                 },
                { "ciaddr",  SD_JSON_VARIANT_STRING,        json_dispatch_unhex_iovec, offsetof(MessageParam, ciaddr),  0                 },
                { "yiaddr",  SD_JSON_VARIANT_STRING,        json_dispatch_unhex_iovec, offsetof(MessageParam, yiaddr),  0                 },
                { "siaddr",  SD_JSON_VARIANT_STRING,        json_dispatch_unhex_iovec, offsetof(MessageParam, siaddr),  0                 },
                { "giaddr",  SD_JSON_VARIANT_STRING,        json_dispatch_unhex_iovec, offsetof(MessageParam, giaddr),  0                 },
                { "chaddr",  SD_JSON_VARIANT_STRING,        json_dispatch_unhex_iovec, offsetof(MessageParam, chaddr),  0                 },
                { "sname",   SD_JSON_VARIANT_STRING,        json_dispatch_unhex_iovec, offsetof(MessageParam, sname),   0                 },
                { "file",    SD_JSON_VARIANT_STRING,        json_dispatch_unhex_iovec, offsetof(MessageParam, file),    0                 },
                { "options", SD_JSON_VARIANT_ARRAY,         dispatch_options,          offsetof(MessageParam, options), 0                 },
                {},
        };

        int r;

        assert(v);
        assert(ret);

        _cleanup_(message_param_done) MessageParam p = {};
        r = sd_json_dispatch(v, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &p);
        if (r < 0)
                return r;

        if (!IN_SET(p.op, BOOTREQUEST, BOOTREPLY))
                return -EINVAL;
        if (!iovec_is_valid(&p.ciaddr) || !IN_SET(p.ciaddr.iov_len, 0, sizeof_field(sd_dhcp_message, header.ciaddr)))
                return -EINVAL;
        if (!iovec_is_valid(&p.yiaddr) || !IN_SET(p.yiaddr.iov_len, 0, sizeof_field(sd_dhcp_message, header.yiaddr)))
                return -EINVAL;
        if (!iovec_is_valid(&p.siaddr) || !IN_SET(p.siaddr.iov_len, 0, sizeof_field(sd_dhcp_message, header.siaddr)))
                return -EINVAL;
        if (!iovec_is_valid(&p.giaddr) || !IN_SET(p.giaddr.iov_len, 0, sizeof_field(sd_dhcp_message, header.giaddr)))
                return -EINVAL;
        if (!iovec_is_valid(&p.chaddr) || p.chaddr.iov_len > sizeof_field(sd_dhcp_message, header.chaddr))
                return -EINVAL;
        if (!iovec_is_valid(&p.sname) || p.sname.iov_len > sizeof_field(sd_dhcp_message, header.sname))
                return -EINVAL;
        if (!iovec_is_valid(&p.file) || p.file.iov_len > sizeof_field(sd_dhcp_message, header.file))
                return -EINVAL;

        _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *message = NULL;
        r = dhcp_message_new(&message);
        if (r < 0)
                return r;

        message->header = (DHCPMessageHeader) {
                .op = p.op,
                .htype = p.htype,
                .hlen = p.chaddr.iov_len,
                .hops = p.hops,
                .xid = htobe32(p.xid),
                .secs = htobe16(p.secs),
                .flags = htobe16(p.flags),
                .magic = htobe32(DHCP_MAGIC_COOKIE),
        };

        memcpy_safe(&message->header.ciaddr, p.ciaddr.iov_base, p.ciaddr.iov_len);
        memcpy_safe(&message->header.yiaddr, p.yiaddr.iov_base, p.yiaddr.iov_len);
        memcpy_safe(&message->header.siaddr, p.siaddr.iov_base, p.siaddr.iov_len);
        memcpy_safe(&message->header.giaddr, p.giaddr.iov_base, p.giaddr.iov_len);
        memcpy_safe(message->header.chaddr, p.chaddr.iov_base, p.chaddr.iov_len);
        memcpy_safe(message->header.sname, p.sname.iov_base, p.sname.iov_len);
        memcpy_safe(message->header.file, p.file.iov_base, p.file.iov_len);
        if (p.options) {
                message->options = TAKE_STRUCT(*p.options);
                p.options = mfree(p.options);
        }

        *ret = TAKE_PTR(message);
        return 0;
}
