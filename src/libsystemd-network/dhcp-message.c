/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if_arp.h>

#include "alloc-util.h"
#include "dhcp-message.h"
#include "dhcp-option.h"
#include "ether-addr-util.h"
#include "hashmap.h"
#include "iovec-util.h"
#include "iovec-wrapper.h"
#include "ip-util.h"
#include "network-common.h"
#include "string-util.h"
#include "utf8.h"

static sd_dhcp_message* dhcp_message_free(sd_dhcp_message *message) {
        if (!message)
                return NULL;

        hashmap_free(message->options);
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

int dhcp_message_get_hw_addr(sd_dhcp_message *message, struct hw_addr_data *ret) {
        assert(message);
        assert(ret);

        if (message->header.hlen > sizeof_field(DHCPMessageHeader, chaddr))
                return -EBADMSG;

        ret->length = message->header.hlen;
        memcpy_safe(ret->bytes, message->header.chaddr, message->header.hlen);
        return 0;
}

static bool message_has_option(sd_dhcp_message *message, uint8_t code) {
        assert(message);
        return hashmap_contains(message->options, UINT_TO_PTR(code));
}

void dhcp_message_remove_option(sd_dhcp_message *message, uint8_t code) {
        assert(message);
        sd_dhcp_option_unref(hashmap_remove(message->options, UINT_TO_PTR(code)));
}

int dhcp_message_append_option(sd_dhcp_message *message, uint8_t code, size_t length, const void *data) {
        assert(message);
        return dhcp_options_append(&message->options, code, length, data);
}

int dhcp_message_append_options(sd_dhcp_message *message, Hashmap *options) {
        assert(message);
        return dhcp_options_append_many(&message->options, options);
}

int dhcp_message_append_option_string(sd_dhcp_message *message, uint8_t code, const char *data) {
        assert(message);

        if (isempty(data))
                return 0;

        if (message_has_option(message, code))
                return -EEXIST;

        return dhcp_message_append_option(message, code, strlen(data), data);
}

int dhcp_message_append_option_flag(sd_dhcp_message *message, uint8_t code) {
        assert(message);

        if (message_has_option(message, code))
                return -EEXIST;

        return dhcp_message_append_option(message, code, /* length= */ 0, /* data= */ NULL);
}

int dhcp_message_append_option_u8(sd_dhcp_message *message, uint8_t code, uint8_t data) {
        assert(message);

        if (message_has_option(message, code))
                return -EEXIST;

        return dhcp_message_append_option(message, code, sizeof(uint8_t), &data);
}

int dhcp_message_append_option_u16(sd_dhcp_message *message, uint8_t code, uint16_t data) {
        assert(message);

        if (message_has_option(message, code))
                return -EEXIST;

        be16_t b = htobe16(data);
        return dhcp_message_append_option(message, code, sizeof(be16_t), &b);
}

int dhcp_message_append_option_be32(sd_dhcp_message *message, uint8_t code, be32_t data) {
        assert(message);

        if (message_has_option(message, code))
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

        if (n_addr > SIZE_MAX / sizeof(struct in_addr))
                return -ENOBUFS;

        return dhcp_message_append_option(message, code, sizeof(struct in_addr) * n_addr, addr);
}

int dhcp_message_get_option(sd_dhcp_message *message, uint8_t code, size_t length, void *ret) {
        assert(message);

        /* Mainly for reading options with fixed length. */

        sd_dhcp_option *o = hashmap_get(message->options, UINT_TO_PTR(code));
        if (!o)
                return -ENODATA;

        /* If we found an option with expected data length, then ignore all other options with the same code.
         * RFC 3396 states that a long option may be stored in multiple TLVs with same option code. So, if an
         * option is specified as a fixed length less than 255 bytes, then it is not necessary to store the
         * option in multiple TLVs. If a message has multiple options with the same option that should have
         * fixed length data, then that should mean the message is mostly broken, hence in that case the
         * first option with the valid length wins and let's drop other options. If there is no option with
         * the valid length, try to concatenate all options to support the case that an implementation of the
         * server side may read more into the RFC than intended. */
        size_t len = 0;
        LIST_FOREACH(option, i, o) {
                if (i->length == length) {
                        if (ret)
                                memcpy_safe(ret, i->data, i->length);
                        return 0;
                }
                len += i->length;
        }

        /* Even if the concatenated data still do not have the expected length, then the message is broken
         * (or our expectation is wrong). */
        if (len != length)
                return -EBADMSG;

        if (!ret)
                return 0;

        void *p = ret;
        LIST_FOREACH(option, i, o)
                p = mempcpy_safe(p, i->data, i->length);

        return 0;
}

int dhcp_message_get_option_alloc(sd_dhcp_message *message, uint8_t code, size_t *ret_size, void **ret_data) {
        assert(message);

        /* Mainly for reading options with variable length. */

        sd_dhcp_option *o = hashmap_get(message->options, UINT_TO_PTR(code));
        if (!o)
                return -ENODATA;

        size_t len = 0;
        LIST_FOREACH(option, i, o)
                len += i->length;

        if (ret_data) {
                /* Here, we allocate one extra byte, to make the result usable as a string. Of course, the
                 * returned count does not include it. */
                _cleanup_free_ uint8_t *data = malloc(len + 1);
                if (!data)
                        return -ENOMEM;

                uint8_t *p = data;
                LIST_FOREACH(option, i, o)
                        p = mempcpy_safe(p, i->data, i->length);

                *p = 0;

                /* Safety check: if the caller doesn't want to know the size of what we just read it will
                 * rely on the trailing NUL byte. But if there's an embedded NUL byte, then we should refuse
                 * operation as otherwise there'd be ambiguity about what we just read. */
                if (!ret_size && memchr(data, 0, len))
                        return -EBADMSG;

                *ret_data = TAKE_PTR(data);
        }
        if (ret_size)
                *ret_size = len; /* Here, we may set 0, the caller may need to check it. */
        return 0;
}

int dhcp_message_get_option_alloc_iovec(sd_dhcp_message *message, uint8_t code, struct iovec *ret) {
        assert(message);
        assert(ret);
        return dhcp_message_get_option_alloc(message, code, &ret->iov_len, &ret->iov_base);
}

int dhcp_message_get_option_string(sd_dhcp_message *message, uint8_t code, char **ret) {
        int r;

        assert(message);

        _cleanup_free_ char *s = NULL;
        r = dhcp_message_get_option_alloc(message, code, /* ret_size= */ NULL, (void**) &s);
        if (r < 0)
                return r;

        if (isempty(s))
                return -ENODATA;

        if (!utf8_is_valid(s) || string_has_cc(s, /* ok= */ NULL))
                return -EBADMSG;

        if (ret)
                *ret = TAKE_PTR(s);
        return 0;
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

        _cleanup_free_ uint8_t *buf = NULL;
        size_t len;
        r = dhcp_message_get_option_alloc(message, code, &len, (void**) &buf);
        if (r < 0)
                return r;

        if (len % sizeof(struct in_addr) != 0)
                return -EBADMSG;

        size_t n = len / sizeof(struct in_addr);
        if (n == 0)
                return -ENODATA;

        if (ret_addr)
                *ret_addr = (struct in_addr*) TAKE_PTR(buf);
        if (ret_n_addr)
                *ret_n_addr = n;
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

        r = dhcp_options_parse(&message->options, &IOVEC_SHIFT(iov, sizeof(DHCPMessageHeader)));
        if (r < 0)
                return r;

        /* Parse SD_DHCP_OPTION_OVERLOAD (52) to determine if we should parse sname and/or file. */
        uint8_t overload = DHCP_OVERLOAD_NONE;
        (void) dhcp_message_get_option_u8(message, SD_DHCP_OPTION_OVERLOAD, &overload);

        if (FLAGS_SET(overload, DHCP_OVERLOAD_FILE)) {
                r = dhcp_options_parse(&message->options, &IOVEC_MAKE(message->header.file, sizeof(message->header.file)));
                if (r < 0)
                        return r;
        }

        if (FLAGS_SET(overload, DHCP_OVERLOAD_SNAME)) {
                r = dhcp_options_parse(&message->options, &IOVEC_MAKE(message->header.sname, sizeof(message->header.sname)));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(message);
        return 0;
}

int dhcp_message_build(const sd_dhcp_message *message, struct iovec_wrapper *ret) {
        int r;

        assert(message);
        assert(ret);

        size_t size = size_add(sizeof(DHCPMessageHeader), dhcp_options_size(message->options));
        if (size > UDP_PAYLOAD_MAX_SIZE)
                return -E2BIG;

        _cleanup_(iovw_done_free) struct iovec_wrapper iovw = {};
        r = iovw_extend(&iovw, &message->header, sizeof(DHCPMessageHeader));
        if (r < 0)
                return r;

        _cleanup_(iovec_done) struct iovec options = {};
        r = dhcp_options_build(message->options, &options);
        if (r < 0)
                return r;

        r = iovw_put_iov(&iovw, &options);
        if (r < 0)
                return r;
        TAKE_STRUCT(options);

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
