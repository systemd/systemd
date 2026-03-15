/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if_arp.h>

#include "alloc-util.h"
#include "dhcp-message.h"
#include "dhcp-option.h"
#include "dhcp-packet.h"
#include "hashmap.h"
#include "in-addr-util.h"
#include "iovec-util.h"
#include "iovec-wrapper.h"
#include "ip-util.h"
#include "socket-util.h"
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
                uint8_t hlen,
                const uint8_t *chaddr) {

        assert(message);
        assert(IN_SET(op, BOOTREQUEST, BOOTREPLY));
        assert(chaddr || hlen == 0);

        message->header.op = op;
        message->header.htype = arp_type;

        /* RFC 2131 section 4.1.1:
         * The client MUST include its hardware address in the ’chaddr’ field, if necessary for delivery of
         * DHCP reply messages.
         *
         * RFC 4390 section 2.1:
         * A DHCP client, when working over an IPoIB interface, MUST follow the following rules:
         * "htype" (hardware address type) MUST be 32 [ARPPARAM].
         * "hlen" (hardware address length) MUST be 0.
         * "chaddr" (client hardware address) field MUST be zeroed.
         */
        message->header.hlen = arp_type == ARPHRD_INFINIBAND ? 0 : hlen;
        memcpy_safe(message->header.chaddr, chaddr, message->header.hlen);

        message->header.xid = htobe32(xid);
        message->header.magic = htobe32(DHCP_MAGIC_COOKIE);
        return 0;
}

int dhcp_message_append_option(sd_dhcp_message *message, uint8_t code, uint8_t length, const void *data) {
        int r;

        assert(message);

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

int dhcp_message_append_option_string(sd_dhcp_message *message, uint8_t code, const char *data) {
        return dhcp_message_append_option(message, code, strlen_ptr(data), data);
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

int dhcp_message_append_option_addresses(sd_dhcp_message *message, uint8_t code, size_t n_addr, const struct in_addr *addr) {
        return dhcp_message_append_option(message, code, sizeof(struct in_addr) * n_addr, addr);
}

int dhcp_message_get_option(sd_dhcp_message *message, uint8_t code, size_t length, void *ret) {
        assert(message);
        assert(length == 0 || ret);

        /* Mainly for reading options with fixed length. */

        sd_dhcp_option *o = hashmap_get(message->options, UINT_TO_PTR(code));
        if (!o)
                return -ENOENT;

        /* If the first option has data with valid length, then ignore all subsequent options. */
        if (o->length == length) {
                memcpy_safe(ret, o->data, o->length);
                return 0;
        }

        /* Otherwise, concatenate all options. */
        size_t len = 0;
        LIST_FOREACH(option, i, o)
                len += i->length;

        if (len != length)
                return -EBADMSG;

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
        r = dhcp_message_get_option_alloc(message, code, /* chunk= */ 1, /* ret_length= */ NULL, (void**) &s);
        if (r < 0)
                return r;

        if (!utf8_is_valid(s) || string_has_cc(s, /* ok= */ NULL))
                return -EBADMSG;

        if (ret)
                *ret = TAKE_PTR(s);
        return 0;
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

                /* END and PAD do not have length field. */
                if (c == SD_DHCP_OPTION_END)
                        break;
                if (c == SD_DHCP_OPTION_PAD)
                        continue;

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

int dhcp_message_new_from_payload(const uint8_t *buf, size_t len, sd_dhcp_message **ret) {
        int r;

        assert(buf || len == 0);
        assert(ret);

        /* The magic field (called vendor field in RFC 951) is optional in the BOOTP protocol. */
        if (len < offsetof(DHCPMessageHeader, magic))
                return -EBADMSG;

        _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *message = NULL;
        r = dhcp_message_new(&message);
        if (r < 0)
                return r;

        memcpy(&message->header, buf, MIN(len, sizeof(DHCPMessageHeader)));

        if (be32toh(message->header.magic) != DHCP_MAGIC_COOKIE) {
                /* Should be BOOTP, and no options. */
                *ret = TAKE_PTR(message);
                return 0;
        }

        assert(len >= sizeof(DHCPMessageHeader));

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


int dhcp_message_build_payload(const sd_dhcp_message *message, struct iovec *ret) {
        int r;

        assert(message);
        assert(ret);

        _cleanup_free_ sd_dhcp_option **sorted = NULL;
        size_t n;
        r = hashmap_dump_sorted(message->options, (void***) &sorted, &n);
        if (r < 0)
                return r;

        size_t size = sizeof(DHCPMessageHeader);
        FOREACH_ARRAY(i, sorted, n)
                LIST_FOREACH(option, o, *i)
                        size += o->length + 2;

        _cleanup_free_ void *buf = malloc(size);
        if (!buf)
                return -ENOMEM;

        void *p = mempcpy(buf, &message->header, sizeof(DHCPMessageHeader));
        FOREACH_ARRAY(i, sorted, n)
                LIST_FOREACH(option, o, *i)
                        p = mempcpy(p, o->tlv, o->length + 2);

        *ret = IOVEC_MAKE(TAKE_PTR(buf), size);
        return 0;
}

int dhcp_message_build_packet(
                const sd_dhcp_message *message,
                be32_t source_addr,
                uint16_t source_port,
                be32_t destination_addr,
                uint16_t destination_port,
                int ip_service_type,
                struct iovec_wrapper *ret) {

        int r;

        assert(message);
        assert(ret);

        _cleanup_(iovec_done) struct iovec payload = {};
        r = dhcp_message_build_payload(message, &payload);
        if (r < 0)
                return r;

        _cleanup_(iovw_done_free) struct iovec_wrapper iovw = {};
        r = udp_packet_build(
                        source_addr,
                        source_port,
                        destination_addr,
                        destination_port,
                        ip_service_type,
                        &payload,
                        &iovw);
        if (r < 0)
                return r;

        TAKE_STRUCT(payload);

        *ret = TAKE_STRUCT(iovw);
        return 0;
}

int dhcp_message_send_udp(const sd_dhcp_message *message, int fd, be32_t dest, uint16_t port) {
        int r;

        assert(message);
        assert(fd >= 0);

        _cleanup_(iovec_done) struct iovec payload = {};
        r = dhcp_message_build_payload(message, &payload);
        if (r < 0)
                return r;

        union sockaddr_union sa = {
                .in.sin_family = AF_INET,
                .in.sin_port = htobe16(port),
                .in.sin_addr.s_addr = dest,
        };

        struct msghdr mh = {
                .msg_name = &sa.sa,
                .msg_namelen = sizeof(sa.in),
                .msg_iov = &payload,
                .msg_iovlen = 1,
        };

        ssize_t n = sendmsg(fd, &mh, MSG_NOSIGNAL);
        if (n < 0)
                return -errno;

        return 0;
}

int dhcp_message_send_raw(
                const sd_dhcp_message *message,
                int fd,
                be32_t source_addr,
                uint16_t source_port,
                be32_t destination_addr,
                uint16_t destination_port,
                int ip_service_type) {

        int r;

        assert(message);
        assert(fd >= 0);

        _cleanup_(iovw_done_free) struct iovec_wrapper packet = {};
        r = dhcp_message_build_packet(
                        message,
                        source_addr,
                        source_port,
                        destination_addr,
                        destination_port,
                        ip_service_type,
                        &packet);
        if (r < 0)
                return r;

        union sockaddr_union sa;
        socklen_t salen = sizeof(sa);
        if (getsockname(fd, &sa.sa, &salen) < 0)
                return -errno;

        struct msghdr mh = {
                .msg_name = &sa.sa,
                .msg_namelen = salen,
                .msg_iov = packet.iovec,
                .msg_iovlen = packet.count,
        };

        ssize_t n = sendmsg(fd, &mh, MSG_NOSIGNAL);
        if (n < 0)
                return -errno;

        return 0;
}

int dhcp_message_recv_udp(int fd, sd_dhcp_message **ret) {
        int r;

        assert(fd >= 0);
        assert(ret);

        ssize_t buflen = next_datagram_size_fd(fd);
        if (buflen < 0)
                return buflen;

        _cleanup_free_ void *buf = malloc(buflen);
        if (!buf)
                return -ENOMEM;

        /* This needs to be initialized with zero. See #20741.
         * The issue is fixed on glibc-2.35 (8fba672472ae0055387e9315fc2eddfa6775ca79). */
        CMSG_BUFFER_TYPE(CMSG_SPACE_TIMEVAL) control = {};
        struct iovec iov = IOVEC_MAKE(buf, buflen);
        struct msghdr msg = {
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };

        ssize_t n = recvmsg_safe(fd, &msg, MSG_DONTWAIT);
        if (n < 0)
                return n;

        _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *message = NULL;
        r = dhcp_message_new_from_payload(buf, n, &message);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(message);
        return 0;
}

int dhcp_message_recv_raw(int fd, uint16_t port, sd_dhcp_message **ret) {
        int r;

        assert(fd >= 0);
        assert(ret);

        ssize_t buflen = next_datagram_size_fd(fd);
        if (buflen < 0)
                return buflen;

        _cleanup_free_ void *buf = malloc(buflen);
        if (!buf)
                return -ENOMEM;

        /* This needs to be initialized with zero. See #20741.
         * The issue is fixed on glibc-2.35 (8fba672472ae0055387e9315fc2eddfa6775ca79). */
        CMSG_BUFFER_TYPE(CMSG_SPACE_TIMEVAL +
                         CMSG_SPACE(sizeof(struct tpacket_auxdata))) control = {};
        struct iovec iov = IOVEC_MAKE(buf, buflen);
        struct msghdr msg = {
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };

        ssize_t n = recvmsg_safe(fd, &msg, MSG_DONTWAIT);
        if (n < 0)
                return n;

        struct tpacket_auxdata *aux = CMSG_FIND_DATA(&msg, SOL_PACKET, PACKET_AUXDATA, struct tpacket_auxdata);
        bool checksum = aux && !FLAGS_SET(aux->tp_status, TP_STATUS_CSUMNOTREADY);

        r = udp_packet_verify(buf, n, port, checksum, &iov);
        if (r < 0)
                return r;

        _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *message = NULL;
        r = dhcp_message_new_from_payload(iov.iov_base, iov.iov_len, &message);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(message);
        return 0;
}
