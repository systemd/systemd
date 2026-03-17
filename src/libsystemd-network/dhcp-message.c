/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if_arp.h>

#include "alloc-util.h"
#include "dhcp-message.h"
#include "dhcp-option.h"
#include "dns-domain.h"
#include "ether-addr-util.h"
#include "hashmap.h"
#include "iovec-util.h"
#include "ip-util.h"
#include "set.h"
#include "sort-util.h"
#include "string-util.h"
#include "strv.h"
#include "utf8.h"

#define DHCP_MESSAGE_MAX_OPTIONS 4096u

static sd_dhcp_message* dhcp_message_free(sd_dhcp_message *message) {
        if (!message)
                return NULL;

        hashmap_free(message->options);
        return mfree(message);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_dhcp_message, sd_dhcp_message, dhcp_message_free);

int dhcp_message_new_empty(sd_dhcp_message **ret) {
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
                .htype = arp_type,
                .hlen = arp_type == ARPHRD_INFINIBAND ? 0 : hw_addr->length,
                .xid = htobe32(xid),
                .magic = htobe32(DHCP_MAGIC_COOKIE),
        };

        memcpy_safe(message->header.chaddr, hw_addr->bytes, message->header.hlen);
        return 0;
}

void dhcp_message_remove_option(sd_dhcp_message *message, uint8_t code) {
        assert(message);
        sd_dhcp_option_unref(hashmap_remove(message->options, UINT_TO_PTR(code)));
}

static int dhcp_message_append_option_impl(sd_dhcp_message *message, uint8_t code, uint8_t length, const void *data) {
        int r;

        assert(message);

        if (IN_SET(code, SD_DHCP_OPTION_PAD, SD_DHCP_OPTION_END))
                return -EINVAL;

        _cleanup_(sd_dhcp_option_unrefp) sd_dhcp_option *o = NULL;
        r = sd_dhcp_option_new(code, data, length, &o);
        if (r < 0)
                return r;

        sd_dhcp_option *e = hashmap_get(message->options, UINT_TO_PTR(o->option));
        if (e) {
                LIST_APPEND(option, e->option_next, TAKE_PTR(o));
                return 0;
        }

        r = hashmap_ensure_put(&message->options, &dhcp_option_hash_ops, UINT_TO_PTR(o->option), o);
        if (r < 0)
                return r;

        TAKE_PTR(o);
        return 0;
}

int dhcp_message_append_option(sd_dhcp_message *message, uint8_t code, size_t length, const void *data) {
        int r;

        assert(message);
        assert(data || length == 0);

        /* Safety check. Assume not so many options. */
        if (hashmap_size(message->options) + DIV_ROUND_UP(length, UINT8_MAX) >= DHCP_MESSAGE_MAX_OPTIONS)
                return -E2BIG;

        const uint8_t *p = data;
        while (length > UINT8_MAX) {
                /* If the data is too long, then split it into small pieces. See RFC 3396. */
                r = dhcp_message_append_option_impl(message, code, UINT8_MAX, p);
                if (r < 0)
                        return r;

                p += UINT8_MAX;
                length -= UINT8_MAX;
        }

        return dhcp_message_append_option_impl(message, code, length, p);
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

int dhcp_message_append_option_vendor_specific(sd_dhcp_message *message, OrderedHashmap *data) {
        assert(message);

        /* TODO: Use Hashmap, allow multiple options with the same option code, and sort by option code,
         * like we do in dhcp_message_build(). */

        size_t len = 0;
        sd_dhcp_option *i;
        ORDERED_HASHMAP_FOREACH(i, data)
                len += 2 + i->length;

        if (len <= 0)
                return 0; /* No data to append. */

        /* Additional 1 byte for the end marker (255). */
        len++;

        _cleanup_free_ uint8_t *buf = new(uint8_t, len);
        if (!buf)
                return -ENOMEM;

        uint8_t *p = buf;
        ORDERED_HASHMAP_FOREACH(i, data)
                p = mempcpy(p, i->tlv, 2 + i->length);

        *p = 255;

        return dhcp_message_append_option(message, SD_DHCP_OPTION_VENDOR_SPECIFIC, len, buf);
}

int dhcp_message_append_option_user_class(sd_dhcp_message *message, char * const *data) {
        assert(message);

        /* FIXME: RFC 3004 does NOT states that each user class data is a string. */
        size_t len = 0;
        STRV_FOREACH(s, data) {
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
        STRV_FOREACH(s, data) {
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

        /* If the first option has data with expected length, then ignore all subsequent options.
         * RFC 3396 states that a long option may be stored in multiple TLVs with same option code. So, if an
         * option is specified as a fix length less than 255 bytes, then it is not necessary to store the
         * option in multiple TLVs. In that case, multiple options with the same option code should be mostly
         * broken message, hence in that case first win and drop any later ones. */
        if (o->length == length) {
                if (ret)
                        memcpy_safe(ret, o->data, o->length);
                return 0;
        }

        /* Otherwise, concatenate all options. */
        size_t len = 0;
        LIST_FOREACH(option, i, o)
                len += i->length;

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
                /* Here, we allocate one extra byte, to make the result can be used as a string. */
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

int dhcp_message_get_option_string(sd_dhcp_message *message, uint8_t code, char **ret) {
        int r;

        assert(message);

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

static int dhcp_message_extract_options(sd_dhcp_message *message, const uint8_t *buf, size_t len) {
        int r;

        assert(message);
        assert(buf || len == 0);

        for (;;) {
                /* option code */
                if (len <= 0)
                        break;
                uint8_t c = *buf++;
                len--;

                /* PAD and END do not have the length field. */
                if (c == SD_DHCP_OPTION_PAD)
                        continue;
                if (c == SD_DHCP_OPTION_END)
                        break;

                if (len <= 0)
                        return -EBADMSG;

                /* option length */
                uint8_t l = *buf++;
                len--;
                if (l > len)
                        return -EBADMSG;

                r = dhcp_message_append_option(message, c, l, buf);
                if (r < 0)
                        return r;

                buf += l;
                len -= l;
        }

        return 0;
}

int dhcp_message_new(const uint8_t *buf, size_t len, sd_dhcp_message **ret) {
        int r;

        assert(buf || len == 0);
        assert(ret);

        /* The magic field (called vendor field in RFC 951) is optional in the BOOTP protocol. */
        if (len < offsetof(DHCPMessageHeader, magic))
                return -EBADMSG;

        _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *message = NULL;
        r = dhcp_message_new_empty(&message);
        if (r < 0)
                return r;

        memcpy(&message->header, buf, MIN(len, sizeof(DHCPMessageHeader)));

        if (be32toh(message->header.magic) != DHCP_MAGIC_COOKIE ||
            len <= sizeof(DHCPMessageHeader)) {
                /* Should be BOOTP, and no options. */
                *ret = TAKE_PTR(message);
                return 0;
        }

        /* In the BOOTP protocol (RFC 951), the vendor field (magic + options) is 64 bytes, but here we do
         * not check the length, and support all DHCP options even if we are running as BOOTP client. */

        r = dhcp_message_extract_options(message, buf + sizeof(DHCPMessageHeader), len - sizeof(DHCPMessageHeader));
        if (r < 0)
                return r;

        /* Parse SD_DHCP_OPTION_OVERLOAD (52) to determine if we should parse sname and/or file. */
        uint8_t overload = DHCP_OVERLOAD_NONE;
        (void) dhcp_message_get_option_u8(message, SD_DHCP_OPTION_OVERLOAD, &overload);

        if (FLAGS_SET(overload, DHCP_OVERLOAD_FILE)) {
                r = dhcp_message_extract_options(message, message->header.file, sizeof(message->header.file));
                if (r < 0)
                        return r;
        }

        if (FLAGS_SET(overload, DHCP_OVERLOAD_SNAME)) {
                r = dhcp_message_extract_options(message, message->header.sname, sizeof(message->header.sname));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(message);
        return 0;
}


int dhcp_message_build(const sd_dhcp_message *message, struct iovec *ret) {
        int r;

        assert(message);
        assert(ret);

        _cleanup_free_ sd_dhcp_option **sorted = NULL;
        size_t n;
        r = hashmap_dump_sorted(message->options, (void***) &sorted, &n);
        if (r < 0)
                return r;

        size_t size = sizeof(DHCPMessageHeader) + 1; /* 1 is for SD_DHCP_OPTION_END */
        FOREACH_ARRAY(o, sorted, n)
                LIST_FOREACH(option, i, *o)
                        size += i->length + 2;

        if (size > UDP_PAYLOAD_MAX_SIZE)
                return -E2BIG;

        /* For compatibility with other implementations and network appliances, the message size should be at
         * least 300 bytes, which is the maximal size of BOOTP message. */
        _cleanup_free_ uint8_t *buf = new(uint8_t, MAX(size, BOOTP_MAX_MESSAGE_SIZE));
        if (!buf)
                return -ENOMEM;

        uint8_t *p = mempcpy(buf, &message->header, sizeof(DHCPMessageHeader));
        FOREACH_ARRAY(o, sorted, n)
                LIST_FOREACH(option, i, *o)
                        p = mempcpy(p, i->tlv, i->length + 2);

        *p++ = SD_DHCP_OPTION_END;
        memzero(p, LESS_BY(BOOTP_MAX_MESSAGE_SIZE, size));

        *ret = IOVEC_MAKE(TAKE_PTR(buf), size);
        return 0;
}
