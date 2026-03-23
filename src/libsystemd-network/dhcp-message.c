/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "dhcp-message.h"
#include "dhcp-option.h"
#include "dns-domain.h"
#include "ether-addr-util.h"
#include "hashmap.h"
#include "hostname-util.h"
#include "iovec-util.h"
#include "iovec-wrapper.h"
#include "ip-util.h"
#include "set.h"
#include "sort-util.h"
#include "string-util.h"
#include "strv.h"
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
        assert(hw_addr);
        assert(hw_addr->length <= sizeof_field(DHCPMessageHeader, chaddr));

        /* RFC 2131 section 4.1.1:
         * The client MUST include its hardware address in the ’chaddr’ field, if necessary for delivery of
         * DHCP reply messages.
         *
         * RFC 4390 section 2.1:
         * A DHCP client, when working over an IPoIB interface, MUST follow the following rules:
         * "htype" (hardware address type) MUST be 32 [ARPPARAM].
         * "hlen" (hardware address length) MUST be 0.
         * "chaddr" (client hardware address) field MUST be zeroed. */

        message->header = (DHCPMessageHeader) {
                .op = op,
                .htype = arp_type <= UINT8_MAX ? arp_type : 0,
                .hlen = hw_addr->length,
                .xid = htobe32(xid),
                .magic = htobe32(DHCP_MAGIC_COOKIE),
        };

        memcpy_safe(message->header.chaddr, hw_addr->bytes, hw_addr->length);
        return 0;
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
        if (isempty(data))
                return 0;

        return dhcp_message_append_option(message, code, strlen(data), data);
}

int dhcp_message_append_option_flag(sd_dhcp_message *message, uint8_t code) {
        return dhcp_message_append_option(message, code, /* length= */ 0, /* data= */ NULL);
}

int dhcp_message_append_option_u8(sd_dhcp_message *message, uint8_t code, uint8_t data) {
        return dhcp_message_append_option(message, code, sizeof(uint8_t), &data);
}

int dhcp_message_append_option_u16(sd_dhcp_message *message, uint8_t code, uint16_t data) {
        be16_t b = htobe16(data);
        return dhcp_message_append_option(message, code, sizeof(be16_t), &b);
}

int dhcp_message_append_option_be32(sd_dhcp_message *message, uint8_t code, be32_t data) {
        return dhcp_message_append_option(message, code, sizeof(be32_t), &data);
}

int dhcp_message_append_option_address(sd_dhcp_message *message, uint8_t code, const struct in_addr *addr) {
        return dhcp_message_append_option(message, code, sizeof(struct in_addr), addr);
}

int dhcp_message_append_option_addresses(sd_dhcp_message *message, uint8_t code, size_t n_addr, const struct in_addr *addr) {
        return dhcp_message_append_option(message, code, sizeof(struct in_addr) * n_addr, addr);
}

int dhcp_message_append_option_sip_addresses(sd_dhcp_message *message, size_t n_addr, const struct in_addr *addr) {
        assert(message);
        assert(n_addr == 0 || addr);

        if (n_addr == 0)
                return 0;

        size_t len = 1 + sizeof(struct in_addr) * n_addr;
        _cleanup_free_ uint8_t *buf = new(uint8_t, len);
        if (!buf)
                return -ENOMEM;

        buf[0] = 1; /* 'enc' field, 0: domains, 1: addresses */
        memcpy(buf + 1, addr, sizeof(struct in_addr) * n_addr);

        return dhcp_message_append_option(message, SD_DHCP_OPTION_SIP_SERVER, len, buf);
}

static int cmp_uint8(const uint8_t *a, const uint8_t *b) {
        return CMP(*a, *b);
}

int dhcp_message_append_option_parameter_request_list(sd_dhcp_message *message, Set *prl) {
        assert(message);

        size_t len = set_size(prl);
        if (len <= 0)
                return 0;

        _cleanup_free_ uint8_t *buf = new(uint8_t, len);
        if (!buf)
                return -ENOMEM;

        uint8_t *p = buf;
        void *q;
        SET_FOREACH(q, prl)
                *p++ = PTR_TO_UINT8(q);

        /* Sort the option to make the message reproducible. */
        typesafe_qsort(buf, len, cmp_uint8);

        return dhcp_message_append_option(message, SD_DHCP_OPTION_PARAMETER_REQUEST_LIST, len, buf);
}

int dhcp_message_append_option_hostname(sd_dhcp_message *message, uint8_t flags, bool is_client, const char *hostname) {
        int r;

        assert(message);

        if (isempty(hostname))
                return 0;

        /* RFC 4702 section 3.1
         * clients that send the Client FQDN option in their messages MUST NOT also send the Host Name
         * option.
         *
         * Here, we also do the same for servers. */

        if (dns_name_is_single_label(hostname))
                return dhcp_message_append_option_string(message, SD_DHCP_OPTION_HOST_NAME, hostname);

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

        r = dns_name_to_wire_format(hostname, buf + 3, sizeof(buf) - 3, false);
        if (r <= 0)
                return r;

        return dhcp_message_append_option(message, SD_DHCP_OPTION_FQDN, 3 + r, buf);
}

int dhcp_message_append_option_vendor_specific(sd_dhcp_message *message, Hashmap *options) {
        int r;

        assert(message);

        if (hashmap_isempty(options))
                return 0; /* No data to append. */

        _cleanup_(iovec_done) struct iovec iov = {};
        r = dhcp_options_build(options, &iov);
        if (r < 0)
                return r;

        return dhcp_message_append_option(message, SD_DHCP_OPTION_VENDOR_SPECIFIC, iov.iov_len, iov.iov_base);
}

int dhcp_message_append_option_user_class(sd_dhcp_message *message, char * const *classes) {
        assert(message);

        /* FIXME: RFC 3004 does NOT states that each user class data is a string. */
        size_t len = 0;
        STRV_FOREACH(s, classes) {
                /* The minimum data length is 1. */
                if (isempty(*s))
                        continue;

                /* The length field of each data is 1 byte, hence the maximum data length is 255. */
                size_t n = strlen(*s);
                if (n > UINT8_MAX)
                        continue;

                len += 1 + strlen(*s);
        }

        if (len <= 0)
                return 0; /* No valid data to append. */

        _cleanup_free_ uint8_t *buf = new(uint8_t, len);
        if (!buf)
                return -ENOMEM;

        uint8_t *p = buf;
        STRV_FOREACH(s, classes) {
                if (isempty(*s))
                        continue;

                size_t n = strlen(*s);
                if (n > UINT8_MAX)
                        continue;

                *p++ = n;
                p = mempcpy(p, *s, n);
        }

        return dhcp_message_append_option(message, SD_DHCP_OPTION_USER_CLASS, len, buf);
}

int dhcp_message_get_option(sd_dhcp_message *message, uint8_t code, size_t length, void *ret) {
        assert(message);

        /* Mainly for reading options with fixed length. */

        sd_dhcp_option *o = hashmap_get(message->options, UINT_TO_PTR(code));
        if (!o)
                return -ENOENT;

        /* If we found a option with expected data length, then ignore all other options with the same code.
         * RFC 3396 states that a long option may be stored in multiple TLVs with same option code. So, if an
         * option is specified as a fix length less than 255 bytes, then it is not necessary to store the
         * option in multiple TLVs. If a message has multiple options with the same option that should have
         * fixed length data, then that should means the message is mostly broken, hence in that case the
         * first option with the valid length wins and let's drop other options. If there is no option with
         * the valid length, try to concatenate all options to support the case that an implementation of the
         * server side may read more into the RFC than intended.*/
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

int dhcp_message_get_option_alloc(sd_dhcp_message *message, uint8_t code, size_t chunk, size_t *ret_n_chunk, void **ret_data) {
        assert(message);

        /* Mainly for reading options with variable length. */

        if (chunk == 0)
                chunk = 1;

        sd_dhcp_option *o = hashmap_get(message->options, UINT_TO_PTR(code));
        if (!o)
                return -ENOENT;

        size_t len = 0;
        LIST_FOREACH(option, i, o)
                len += i->length;

        if (len % chunk != 0)
                return -EBADMSG;

        if (ret_data) {
                /* Here, we allocate one extra byte, to make the result can be used as a string. Of course,
                 * the returned count does not include it. */
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
                if (!ret_n_chunk && memchr(data, 0, len))
                        return -EBADMSG;

                *ret_data = TAKE_PTR(data);
        }
        if (ret_n_chunk)
                *ret_n_chunk = len / chunk;
        return 0;
}

int dhcp_message_get_option_alloc_iovec(sd_dhcp_message *message, uint8_t code, struct iovec *ret) {
        assert(ret);
        return dhcp_message_get_option_alloc(message, code, /* chunk= */ 1, &ret->iov_len, &ret->iov_base);
}

int dhcp_message_get_option_string(sd_dhcp_message *message, uint8_t code, char **ret) {
        int r;

        _cleanup_free_ char *s = NULL;
        r = dhcp_message_get_option_alloc(message, code, /* chunk= */ 1, /* ret_n_chunk= */ NULL, (void**) &s);
        if (r < 0)
                return r;

        if (!utf8_is_valid(s) || string_has_cc(s, /* ok= */ NULL))
                return -EBADMSG;

        if (ret)
                *ret = TAKE_PTR(s);
        return 0;
}

int dhcp_message_get_option_flag(sd_dhcp_message *message, uint8_t code) {
        return dhcp_message_get_option(message, code, /* length= */ 0, /* ret= */ NULL);
}

int dhcp_message_get_option_u8(sd_dhcp_message *message, uint8_t code, uint8_t *ret) {
        return dhcp_message_get_option(message, code, sizeof(uint8_t), ret);
}

int dhcp_message_get_option_u16(sd_dhcp_message *message, uint8_t code, uint16_t *ret) {
        be16_t b;
        int r;

        r = dhcp_message_get_option(message, code, sizeof(be16_t), ret ? &b : NULL);
        if (r < 0)
                return r;

        if (ret)
                *ret = be16toh(b);
        return 0;
}

int dhcp_message_get_option_be32(sd_dhcp_message *message, uint8_t code, be32_t *ret) {
        return dhcp_message_get_option(message, code, sizeof(be32_t), ret);
}

int dhcp_message_get_option_address(sd_dhcp_message *message, uint8_t code, struct in_addr *ret) {
        return dhcp_message_get_option(message, code, sizeof(struct in_addr), ret);
}

int dhcp_message_get_option_addresses(sd_dhcp_message *message, uint8_t code, size_t *ret_n_addr, struct in_addr **ret_addr) {
        return dhcp_message_get_option_alloc(message, code, sizeof(struct in_addr), ret_n_addr, (void**) ret_addr);
}

int dhcp_message_get_option_sip_addresses(sd_dhcp_message *message, size_t *ret_n_addr, struct in_addr **ret_addr) {
        int r;

        _cleanup_free_ uint8_t *buf = NULL;
        size_t len;
        r = dhcp_message_get_option_alloc(message, SD_DHCP_OPTION_SIP_SERVER, /* chunk= */ 1, &len, (void**) &buf);
        if (r < 0)
                return r;

        if (len < 1)
                return -EBADMSG;

        if (buf[0] != 1) /* 'enc' field, 0: domains, 1: addresses */
                return -ENOENT;

        if ((len - 1) % sizeof(struct in_addr) != 0)
                return -EBADMSG;

        size_t n_addr = (len - 1) / sizeof(struct in_addr);
        if (n_addr <= 0)
                return -ENOENT;

        if (ret_addr) {
                struct in_addr *addr = newdup(struct in_addr, buf + 1, n_addr);
                if (!addr)
                        return -ENOMEM;

                *ret_addr = addr;
        }
        if (ret_n_addr)
                *ret_n_addr = n_addr;
        return 0;
}

int dhcp_message_get_option_parameter_request_list(sd_dhcp_message *message, Set **ret) {
        int r;

        _cleanup_free_ uint8_t *buf = NULL;
        size_t len;
        r = dhcp_message_get_option_alloc(message, SD_DHCP_OPTION_PARAMETER_REQUEST_LIST, /* chunk= */ 1, &len, (void**) &buf);
        if (r < 0)
                return r;

        if (!ret)
                return 0;

        _cleanup_set_free_ Set *prl = NULL;
        FOREACH_ARRAY(i, buf, len) {
                r = set_ensure_put(&prl, /* hash_ops= */ NULL, UINT8_TO_PTR(*i));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(prl);
        return 0;
}

static int normalize_hostname(const char *name, char **ret) {
        int r;

        assert(name);
        assert(ret);

        _cleanup_free_ char *normalized = NULL;
        r = dns_name_normalize(name, /* flags= */ 0, &normalized);
        if (r < 0)
                return r;

        if (is_localhost(normalized))
                return -EINVAL;

        if (dns_name_is_root(normalized))
                return -EINVAL;

        *ret = TAKE_PTR(normalized);
        return 0;
}

static int dhcp_message_get_option_hostname_impl(sd_dhcp_message *message, char **ret) {
        int r;

        _cleanup_free_ char *name = NULL;
        r = dhcp_message_get_option_string(message, SD_DHCP_OPTION_HOST_NAME, &name);
        if (r < 0)
                return r;

        _cleanup_free_ char *normalized = NULL;
        r = normalize_hostname(name, &normalized);
        if (r < 0)
                return r;

        if (!dns_name_is_single_label(normalized))
                return -EBADMSG;

        if (ret)
                *ret = TAKE_PTR(normalized);
        return 0;
}

static int dhcp_message_get_option_fqdn(sd_dhcp_message *message, uint8_t *ret_flags, char **ret) {
        int r;

        _cleanup_free_ uint8_t *buf = NULL;
        size_t len;
        r = dhcp_message_get_option_alloc(message, SD_DHCP_OPTION_FQDN, /* chunk= */ 1, &len, (void**) &buf);
        if (r < 0)
                return r;

        if (len <= 3)
                return -EBADMSG;

        if (!FLAGS_SET(buf[0], DHCP_FQDN_FLAG_E))
                return -EOPNOTSUPP;

        const uint8_t *p = buf + 3;
        len -= 3;

        _cleanup_free_ char *name = NULL;
        r = dns_name_from_wire_format(&p, &len, &name);
        if (r < 0)
                return r;

        _cleanup_free_ char *normalized = NULL;
        r = normalize_hostname(name, &normalized);
        if (r < 0)
                return r;

        if (ret_flags)
                *ret_flags = buf[0];
        if (ret)
                *ret = TAKE_PTR(normalized);
        return 0;
}

int dhcp_message_get_option_hostname(sd_dhcp_message *message, uint8_t *ret_flags, char **ret) {
        int r;

        /* FQDN option takes precedence. */
        if (dhcp_message_get_option_fqdn(message, ret_flags, ret) >= 0)
                return 0;

        r = dhcp_message_get_option_hostname_impl(message, ret);
        if (r < 0)
                return r;

        if (ret_flags)
                *ret_flags = 0;
        return 0;
}

int dhcp_message_get_option_vendor_specific(sd_dhcp_message *message, Hashmap **ret) {
        int r;

        _cleanup_(iovec_done) struct iovec iov = {};
        r = dhcp_message_get_option_alloc_iovec(message, SD_DHCP_OPTION_VENDOR_SPECIFIC, &iov);
        if (r < 0)
                return r;

        _cleanup_hashmap_free_ Hashmap *options = NULL;
        r = dhcp_options_parse_iovec(&options, &iov);
        if (r < 0)
                return r;

        if (ret)
                *ret = TAKE_PTR(options);
        return 0;
}

int dhcp_message_get_option_user_class(sd_dhcp_message *message, char ***ret) {
        int r;

        _cleanup_free_ uint8_t *buf = NULL;
        size_t len;
        r = dhcp_message_get_option_alloc(message, SD_DHCP_OPTION_USER_CLASS, /* chunk= */ 1, &len, (void**) &buf);
        if (r < 0)
                return r;

        _cleanup_strv_free_ char **classes = NULL;
        size_t n_classes = 0;
        for (uint8_t *p = buf; len > 0;) {
                uint8_t l = *p++;
                len--;
                if (l <= 0) /* huh? */
                        continue;
                if (l > len)
                        return -EBADMSG;

                _cleanup_free_ char *s = memdup_suffix0(p, l);
                if (!s)
                        return -ENOMEM;

                p += l;
                len -= l;

                if (!utf8_is_valid(s) || string_has_cc(s, /* ok= */ NULL))
                        continue;

                if (!ret)
                        continue;

                r = strv_consume_with_size(&classes, &n_classes, TAKE_PTR(s));
                if (r < 0)
                        return r;
        }

        if (ret)
                *ret = TAKE_PTR(classes);
        return 0;
}

static int dhcp_message_verify_header(
                const struct iovec *iov,
                uint8_t op,
                const uint32_t *xid,
                uint16_t arp_type,
                const struct hw_addr_data *hw_addr) {

        assert(iov);
        assert(IN_SET(op, BOOTREQUEST, BOOTREPLY));

        /* The magic field (called vendor field in RFC 951) is optional in the BOOTP protocol. */
        if (iov->iov_len < offsetof(DHCPMessageHeader, magic))
                return -EBADMSG;

        const DHCPMessageHeader *header = iov->iov_base;

        if (header->op != op)
                return -EBADMSG;

        if (xid && be32toh(header->xid) != *xid)
                return -EBADMSG;

        if (arp_type <= UINT8_MAX && header->htype != arp_type)
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

        memcpy(&message->header, iov->iov_base, MIN(iov->iov_len, sizeof(DHCPMessageHeader)));

        if (be32toh(message->header.magic) != DHCP_MAGIC_COOKIE ||
            iov->iov_len <= sizeof(DHCPMessageHeader)) {
                /* Should be BOOTP, and no options. */
                *ret = TAKE_PTR(message);
                return 0;
        }

        /* In the BOOTP protocol (RFC 951), the vendor field (magic + options) is 64 bytes, but here we do
         * not check the length, and support all DHCP options even if we are running as BOOTP client. */

        r = dhcp_options_parse_iovec(&message->options, &IOVEC_SHIFT(iov, sizeof(DHCPMessageHeader)));
        if (r < 0)
                return r;

        /* Parse SD_DHCP_OPTION_OVERLOAD (52) to determine if we should parse sname and/or file. */
        uint8_t overload = DHCP_OVERLOAD_NONE;
        (void) dhcp_message_get_option_u8(message, SD_DHCP_OPTION_OVERLOAD, &overload);

        if (FLAGS_SET(overload, DHCP_OVERLOAD_FILE)) {
                r = dhcp_options_parse(&message->options, message->header.file, sizeof(message->header.file));
                if (r < 0)
                        return r;
        }

        if (FLAGS_SET(overload, DHCP_OVERLOAD_SNAME)) {
                r = dhcp_options_parse(&message->options, message->header.sname, sizeof(message->header.sname));
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

        size_t size = sizeof(DHCPMessageHeader) + dhcp_options_size(message->options);

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
         * least 300 bytes, which is the maximal size of BOOTP message. */
        size_t padding_size = LESS_BY(BOOTP_MAX_MESSAGE_SIZE, size);
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
