/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if_arp.h>

#include "alloc-util.h"
#include "dhcp-message.h"
#include "dhcp-protocol.h"
#include "ether-addr-util.h"
#include "iovec-util.h"
#include "iovec-wrapper.h"
#include "ip-util.h"
#include "network-common.h"

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
