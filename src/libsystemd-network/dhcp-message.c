/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if_arp.h>

#include "alloc-util.h"
#include "dhcp-client-id-internal.h"
#include "dhcp-message.h"
#include "dhcp-protocol.h"
#include "dns-domain.h"
#include "errno-util.h"
#include "ether-addr-util.h"
#include "hostname-util.h"
#include "iovec-util.h"
#include "iovec-wrapper.h"
#include "ip-util.h"
#include "network-common.h"
#include "set.h"
#include "sort-util.h"
#include "string-util.h"

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

        _cleanup_(iovec_done) struct iovec iov = {};
        r = dhcp_message_get_option_alloc(message, code, &iov);
        if (r < 0)
                return r;

        if (iov.iov_len % sizeof(struct in_addr) != 0)
                return -EBADMSG;

        size_t n = iov.iov_len / sizeof(struct in_addr);
        if (n == 0)
                return -ENODATA;

        if (ret_addr)
                *ret_addr = (struct in_addr*) TAKE_PTR(iov.iov_base);
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
