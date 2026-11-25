/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include "clat.h"
#include "in-addr-util.h"
#include "networkd-xlat-packet.h"
#include "random-util.h"
#include "tests.h"
#include "unaligned.h"

#define LOCAL4  "192.0.0.1"
#define REMOTE4 "198.41.0.4"
#define ROUTER6 "2001:db8:ffff::1"
#define CLAT6   "2001:db8:1::c1a7"
#define PREF64  "64:ff9b::"
#define REMOTE6 "64:ff9b::c629:4"

static struct in6_addr in6(const char *s) {
        union in_addr_union u;

        ASSERT_OK(in_addr_from_string(AF_INET6, s, &u));
        return u.in6;
}

static struct in_addr in4(const char *s) {
        union in_addr_union u;

        ASSERT_OK(in_addr_from_string(AF_INET, s, &u));
        return u.in;
}

static XlatPacketParams params(void) {
        return (XlatPacketParams) {
                .address = in6(CLAT6),
                .pref64 = in6(PREF64),
                .pref64_len = 96,
                .mtu = 1500,
                .ipv4_id = 0x1234,
        };
}

/* A checksum implementation independent of the one being tested: sum of big endian words */
static uint32_t sum_be(uint32_t sum, const void *buf, size_t len) {
        const uint8_t *p = buf;

        for (size_t i = 0; i < len; i++)
                sum += i % 2 == 0 ? (uint32_t) p[i] << 8 : p[i];

        return sum;
}

static uint16_t fold_be(uint32_t sum) {
        while (sum >> 16)
                sum = (sum & 0xffff) + (sum >> 16);

        return (uint16_t) ~sum;
}

static uint32_t pseudo4(const uint8_t *ip, size_t len, uint8_t protocol) {
        return sum_be(len + protocol, ip + 12, 8);
}

static uint32_t pseudo6(const uint8_t *ip, size_t len, uint8_t protocol) {
        return sum_be(len + protocol, ip + 8, 32);
}

static size_t l4_checksum_offset(uint8_t protocol) {
        switch (protocol) {
        case IPPROTO_TCP:
                return 16;
        case IPPROTO_UDP:
                return 6;
        default:
                return 2;
        }
}

static void fill_l4_checksum(uint8_t *l4, size_t len, uint8_t protocol, uint32_t pseudo) {
        uint16_t c;

        unaligned_write_be16(l4 + l4_checksum_offset(protocol), 0);
        c = fold_be(sum_be(pseudo, l4, len));
        if (c == 0 && protocol == IPPROTO_UDP)
                c = 0xffff;
        unaligned_write_be16(l4 + l4_checksum_offset(protocol), c);
}

static size_t make4(uint8_t *buf, uint8_t protocol, const char *src, const char *dst, const uint8_t *l4, size_t len) {
        struct in_addr s = in4(src), d = in4(dst);

        memzero(buf, 20);
        buf[0] = 0x45;
        buf[1] = 0x2a; /* TOS */
        unaligned_write_be16(buf + 2, 20 + len);
        buf[8] = 63;
        buf[9] = protocol;
        memcpy(buf + 12, &s, 4);
        memcpy(buf + 16, &d, 4);
        unaligned_write_be16(buf + 10, fold_be(sum_be(/* sum= */ 0, buf, 20)));

        memcpy_safe(buf + 20, l4, len);
        fill_l4_checksum(buf + 20, len, protocol, protocol == IPPROTO_ICMP ? 0 : pseudo4(buf, len, protocol));
        return 20 + len;
}

static size_t make6(uint8_t *buf, uint8_t protocol, const char *src, const char *dst, const uint8_t *l4, size_t len) {
        struct in6_addr s = in6(src), d = in6(dst);

        memzero(buf, 40);
        buf[0] = 0x62; /* traffic class 0x2a */
        buf[1] = 0xa0;
        unaligned_write_be16(buf + 4, len);
        buf[6] = protocol;
        buf[7] = 61;
        memcpy(buf + 8, &s, 16);
        memcpy(buf + 24, &d, 16);

        memcpy_safe(buf + 40, l4, len);
        fill_l4_checksum(buf + 40, len, protocol, pseudo6(buf, len, protocol));
        return 40 + len;
}

static void verify4(const uint8_t *p, size_t size) {
        size_t len;

        ASSERT_GE(size, 20u);
        ASSERT_EQ(p[0], 0x45);
        len = unaligned_read_be16(p + 2);
        ASSERT_EQ(len, size);
        ASSERT_EQ(fold_be(sum_be(/* sum= */ 0, p, 20)), 0);
        ASSERT_EQ(fold_be(sum_be(p[9] == IPPROTO_ICMP ? 0 : pseudo4(p, len - 20, p[9]), p + 20, len - 20)), 0);
}

static void verify6(const uint8_t *p, size_t size) {
        size_t len;

        ASSERT_GE(size, 40u);
        ASSERT_EQ(p[0] >> 4, 6);
        len = unaligned_read_be16(p + 4);
        ASSERT_EQ(len + 40, size);
        ASSERT_EQ(fold_be(sum_be(pseudo6(p, len, p[6]), p + 40, len)), 0);
}

static void make_l4(uint8_t *l4, size_t len, uint8_t protocol) {
        for (size_t i = 0; i < len; i++)
                l4[i] = i * 7 + 3;

        unaligned_write_be16(l4, 40000);        /* source port, or ICMP type and code */
        unaligned_write_be16(l4 + 2, 53);       /* destination port, or ICMP checksum */

        if (protocol == IPPROTO_UDP)
                unaligned_write_be16(l4 + 4, len);
        if (protocol == IPPROTO_TCP)
                l4[12] = 0x50;
}

static uint8_t in_buf[XLAT_PACKET_SIZE_MAX], out_buf[XLAT_PACKET_SIZE_MAX], l4_buf[XLAT_PACKET_SIZE_MAX];

/* Translate the packet in in_buf, which carries a complete checksum, to out_buf */
static int translate_6to4(XlatPacketParams *p, size_t n, size_t *ret_size) {
        return xlat_packet_6to4(p, in_buf, n, /* checksum_partial= */ false, out_buf, sizeof(out_buf), ret_size);
}

TEST(pref64) {
        /* The examples of RFC 6052 section 2.4 */
        static const struct {
                const char *prefix;
                unsigned len;
                const char *result;
        } table[] = {
                { "2001:db8::",         32, "2001:db8:c000:221::"                },
                { "2001:db8:100::",     40, "2001:db8:1c0:2:21::"                },
                { "2001:db8:122::",     48, "2001:db8:122:c000:2:2100::"         },
                { "2001:db8:122:300::", 56, "2001:db8:122:3c0:0:221::"           },
                { "2001:db8:122:344::", 64, "2001:db8:122:344:c0:2:2100::"       },
                { "2001:db8:122:344::", 96, "2001:db8:122:344::192.0.2.33"       },
        };

        struct in_addr a = in4("192.0.2.33");

        FOREACH_ELEMENT(t, table) {
                struct in6_addr prefix = in6(t->prefix), expected = in6(t->result), result;
                struct in_addr extracted;

                clat_ipv4_embed(prefix.s6_addr, t->len, (const uint8_t*) &a, result.s6_addr);
                ASSERT_TRUE(in6_addr_equal(&result, &expected));

                clat_ipv4_extract(result.s6_addr, t->len, (uint8_t*) &extracted);
                ASSERT_EQ(extracted.s_addr, a.s_addr);
        }
}

TEST(ipv4_is_global) {
        FOREACH_STRING(s, "0.1.2.3", "10.0.0.1", "100.64.0.1", "100.127.255.255", "127.0.0.1", "169.254.1.1",
                       "172.16.0.1", "172.31.255.255", "192.0.0.1", "192.0.2.1", "192.168.1.1", "198.18.0.1",
                       "198.19.255.255", "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "255.255.255.255") {
                struct in_addr a = in4(s);
                ASSERT_FALSE(clat_ipv4_is_global((const uint8_t*) &a));
        }

        FOREACH_STRING(s, "1.1.1.1", "100.63.255.255", "100.128.0.1", "172.15.0.1", "172.32.0.1", "192.0.1.1",
                       "192.88.99.1", "198.17.0.1", "198.20.0.1", "198.41.0.4", "223.255.255.254") {
                struct in_addr a = in4(s);
                ASSERT_TRUE(clat_ipv4_is_global((const uint8_t*) &a));
        }
}

TEST(icmp_mapping) {
        uint8_t in[8] = {}, out[8];

        static const int table4[][4] = { /* type4, code4, type6, code6 */
                { 3, 0, 1, 0 }, { 3, 1, 1, 0 }, { 3, 2, 4, 1 }, { 3, 3, 1, 4 }, { 3, 4, 2, 0 }, { 3, 5, 1, 0 },
                { 3, 6, 1, 0 }, { 3, 7, 1, 0 }, { 3, 8, 1, 0 }, { 3, 9, 1, 1 }, { 3, 10, 1, 1 }, { 3, 11, 1, 0 },
                { 3, 12, 1, 0 }, { 3, 13, 1, 1 }, { 3, 15, 1, 1 }, { 11, 0, 3, 0 }, { 11, 1, 3, 1 },
        };
        FOREACH_ELEMENT(t, table4) {
                in[0] = (*t)[0];
                in[1] = (*t)[1];
                ASSERT_EQ((int) clat_icmp_4to6(in, 100, 1500, out), (int) CLAT_ICMP_ERROR);
                ASSERT_EQ(out[0], (*t)[2]);
                ASSERT_EQ(out[1], (*t)[3]);
        }

        static const int table6[][4] = { /* type6, code6, type4, code4 */
                { 1, 0, 3, 1 }, { 1, 1, 3, 10 }, { 1, 2, 3, 1 }, { 1, 3, 3, 1 }, { 1, 4, 3, 3 },
                { 2, 0, 3, 4 }, { 3, 0, 11, 0 }, { 3, 1, 11, 1 }, { 4, 1, 3, 2 },
        };
        FOREACH_ELEMENT(t, table6) {
                memzero(in, sizeof(in));
                in[0] = (*t)[0];
                in[1] = (*t)[1];
                ASSERT_EQ((int) clat_icmp_6to4(in, 1500, out), (int) CLAT_ICMP_ERROR);
                ASSERT_EQ(out[0], (*t)[2]);
                ASSERT_EQ(out[1], (*t)[3]);
        }

        /* Silently dropped */
        in[0] = 3;
        in[1] = 14;
        ASSERT_EQ((int) clat_icmp_4to6(in, 100, 1500, out), (int) CLAT_ICMP_DROP);
        int type;
        FOREACH_ARGUMENT(type, 4, 5, 9, 10, 13, 15, 17) {
                in[0] = type;
                in[1] = 0;
                ASSERT_EQ((int) clat_icmp_4to6(in, 100, 1500, out), (int) CLAT_ICMP_DROP);
        }
        FOREACH_ARGUMENT(type, 130, 133, 135, 136, 137) {
                in[0] = type;
                ASSERT_EQ((int) clat_icmp_6to4(in, 1500, out), (int) CLAT_ICMP_DROP);
        }

        /* Parameter problem pointers, RFC 7915 figures 3 and 6 */
        memzero(in, sizeof(in));
        in[0] = 12;
        in[4] = 9;
        ASSERT_EQ((int) clat_icmp_4to6(in, 100, 1500, out), (int) CLAT_ICMP_ERROR);
        ASSERT_EQ(unaligned_read_be32(out + 4), 6u);
        in[4] = 4; /* identification: not applicable */
        ASSERT_EQ((int) clat_icmp_4to6(in, 100, 1500, out), (int) CLAT_ICMP_DROP);

        memzero(in, sizeof(in));
        in[0] = 4;
        in[7] = 6;
        ASSERT_EQ((int) clat_icmp_6to4(in, 1500, out), (int) CLAT_ICMP_ERROR);
        ASSERT_EQ(out[4], 9);
        in[7] = 30;
        ASSERT_EQ((int) clat_icmp_6to4(in, 1500, out), (int) CLAT_ICMP_ERROR);
        ASSERT_EQ(out[4], 16);
        in[7] = 2; /* flow label: not applicable */
        ASSERT_EQ((int) clat_icmp_6to4(in, 1500, out), (int) CLAT_ICMP_DROP);

        /* Packet too big and fragmentation needed */
        static const unsigned mtus6[][3] = { /* mtu in the message, link MTU, result */
                { 1400, 1500, 1372 }, { 1280, 1500, 1252 }, { 576, 1500, 1252 }, { 9000, 1500, 1472 },
                { 9000, 9000, 8972 },
        };
        FOREACH_ELEMENT(t, mtus6) {
                memzero(in, sizeof(in));
                in[0] = 2;
                unaligned_write_be32(in + 4, (*t)[0]);
                ASSERT_EQ((int) clat_icmp_6to4(in, (*t)[1], out), (int) CLAT_ICMP_ERROR);
                ASSERT_EQ(unaligned_read_be16(out + 6), (*t)[2]);
        }

        static const unsigned mtus4[][4] = { /* mtu in the message, quoted length, link MTU, result */
                { 1400, 1500, 1500, 1420 }, { 576, 1500, 1500, 1280 }, { 1500, 1500, 1500, 1500 },
                { 0, 1500, 9000, 1492 }, { 0, 9000, 9000, 8166 }, { 0, 600, 1500, 1280 },
        };
        FOREACH_ELEMENT(t, mtus4) {
                memzero(in, sizeof(in));
                in[0] = 3;
                in[1] = 4;
                unaligned_write_be16(in + 6, (*t)[0]);
                ASSERT_EQ((int) clat_icmp_4to6(in, (*t)[1], (*t)[2], out), (int) CLAT_ICMP_ERROR);
                ASSERT_EQ(unaligned_read_be32(out + 4), (*t)[3]);
        }
}

TEST(transport_4to6_and_6to4) {
        int protocol, len;

        FOREACH_ARGUMENT(protocol, IPPROTO_TCP, IPPROTO_UDP)
                FOREACH_ARGUMENT(len, 20, 21, 512, 1439, 1440, 8000) {
                        XlatPacketParams p = params();
                        struct in6_addr dst, expected = in6(REMOTE6);
                        size_t n, size;

                        make_l4(l4_buf, len, protocol);

                        n = make4(in_buf, protocol, LOCAL4, REMOTE4, l4_buf, len);
                        ASSERT_OK(xlat_packet_4to6(&p, in_buf, n, out_buf, sizeof(out_buf), &size, &dst));
                        ASSERT_EQ(size, (size_t) len + 40);
                        ASSERT_TRUE(in6_addr_equal(&dst, &expected));
                        ASSERT_EQ(out_buf[6], protocol);
                        ASSERT_EQ(out_buf[7], 63);
                        ASSERT_EQ(out_buf[0], 0x62);
                        ASSERT_EQ(out_buf[1], 0xa0);
                        verify6(out_buf, size);

                        n = make6(in_buf, protocol, REMOTE6, CLAT6, l4_buf, len);
                        ASSERT_OK(translate_6to4(&p, n, &size));
                        ASSERT_EQ(size, (size_t) len + 20);
                        ASSERT_EQ(out_buf[1], 0x2a);
                        ASSERT_EQ(out_buf[8], 61);
                        verify4(out_buf, size);

                        /* RFC 7915 section 5.1 and RFC 6864: DF only above 1260 bytes, and an
                         * identification when DF is clear */
                        if (size <= 1260) {
                                ASSERT_EQ(unaligned_read_be16(out_buf + 6), 0);
                                ASSERT_EQ(unaligned_read_be16(out_buf + 4), 0x1234);
                                ASSERT_EQ(p.ipv4_id, 0x1235);
                        } else {
                                ASSERT_EQ(unaligned_read_be16(out_buf + 6), IP_DF);
                                ASSERT_EQ(p.ipv4_id, 0x1234);
                        }

                        /* A corrupted packet stays corrupted */
                        in_buf[n - 1] ^= 1;
                        ASSERT_OK(translate_6to4(&p, n, &size));
                        ASSERT_NE(fold_be(sum_be(pseudo4(out_buf, size - 20, protocol), out_buf + 20, size - 20)), 0);

                        /* A packet whose checksum only covers the pseudo-header so far */
                        n = make6(in_buf, protocol, REMOTE6, CLAT6, l4_buf, len);
                        unaligned_write_be16(in_buf + 40 + l4_checksum_offset(protocol),
                                             (uint16_t) ~fold_be(pseudo6(in_buf, len, protocol)));
                        ASSERT_OK(xlat_packet_6to4(&p, in_buf, n, /* checksum_partial= */ true,
                                                   out_buf, sizeof(out_buf), &size));
                        verify4(out_buf, size);
                }
}

TEST(df_boundary) {
        int len;

        FOREACH_ARGUMENT(len, 1240, 1241) {
                XlatPacketParams p = params();
                size_t n, size;

                make_l4(l4_buf, len, IPPROTO_UDP);
                n = make6(in_buf, IPPROTO_UDP, REMOTE6, CLAT6, l4_buf, len);
                ASSERT_OK(translate_6to4(&p, n, &size));
                ASSERT_EQ(unaligned_read_be16(out_buf + 6), len == 1240 ? 0 : IP_DF);
        }
}

TEST(udp_zero_checksum) {
        XlatPacketParams p = params();
        struct in6_addr dst;
        size_t n, size;
        int len;

        FOREACH_ARGUMENT(len, 8, 9, 3001) {
                make_l4(l4_buf, len, IPPROTO_UDP);
                n = make4(in_buf, IPPROTO_UDP, LOCAL4, REMOTE4, l4_buf, len);
                unaligned_write_be16(in_buf + 26, 0);

                /* RFC 7915 section 4.5: compute it, or drop the datagram */
                p.drop_udp_zero_checksum = false;
                ASSERT_OK(xlat_packet_4to6(&p, in_buf, n, out_buf, sizeof(out_buf), &size, &dst));
                ASSERT_NE(unaligned_read_be16(out_buf + 46), 0);
                verify6(out_buf, size);

                p.drop_udp_zero_checksum = true;
                ASSERT_ERROR(xlat_packet_4to6(&p, in_buf, n, out_buf, sizeof(out_buf), &size, &dst), ENODATA);
        }

        /* Not valid in IPv6 */
        make_l4(l4_buf, 100, IPPROTO_UDP);
        n = make6(in_buf, IPPROTO_UDP, REMOTE6, CLAT6, l4_buf, 100);
        unaligned_write_be16(in_buf + 46, 0);
        ASSERT_ERROR(translate_6to4(&p, n, &size), EBADMSG);
}

TEST(echo) {
        XlatPacketParams p = params();
        struct in6_addr dst;
        size_t n, size;
        int type;

        FOREACH_ARGUMENT(type, ICMP_ECHO, ICMP_ECHOREPLY) {
                make_l4(l4_buf, 64, IPPROTO_ICMP);
                l4_buf[0] = type;
                l4_buf[1] = 0;
                n = make4(in_buf, IPPROTO_ICMP, LOCAL4, REMOTE4, l4_buf, 64);
                ASSERT_OK(xlat_packet_4to6(&p, in_buf, n, out_buf, sizeof(out_buf), &size, &dst));
                ASSERT_EQ(out_buf[6], IPPROTO_ICMPV6);
                ASSERT_EQ(out_buf[40], type == ICMP_ECHO ? ICMP6_ECHO_REQUEST : ICMP6_ECHO_REPLY);
                verify6(out_buf, size);

                l4_buf[0] = type == ICMP_ECHO ? ICMP6_ECHO_REQUEST : ICMP6_ECHO_REPLY;
                n = make6(in_buf, IPPROTO_ICMPV6, REMOTE6, CLAT6, l4_buf, 64);
                ASSERT_OK(translate_6to4(&p, n, &size));
                ASSERT_EQ(out_buf[9], IPPROTO_ICMP);
                ASSERT_EQ(out_buf[20], type);
                verify4(out_buf, size);
        }

        /* Neighbor discovery is not translated */
        l4_buf[0] = 135;
        n = make6(in_buf, IPPROTO_ICMPV6, REMOTE6, CLAT6, l4_buf, 64);
        ASSERT_ERROR(translate_6to4(&p, n, &size), EOPNOTSUPP);
}

TEST(rejected) {
        XlatPacketParams p = params();
        struct in6_addr dst;
        size_t n, size;

        make_l4(l4_buf, 40, IPPROTO_UDP);

        /* Source other than the CLAT address */
        n = make4(in_buf, IPPROTO_UDP, "192.168.1.1", REMOTE4, l4_buf, 40);
        ASSERT_ERROR(xlat_packet_4to6(&p, in_buf, n, out_buf, sizeof(out_buf), &size, &dst), EPERM);

        /* RFC 6052 section 3.1: no private addresses in the Well-Known Prefix, in either direction */
        n = make4(in_buf, IPPROTO_UDP, LOCAL4, "192.168.1.1", l4_buf, 40);
        ASSERT_ERROR(xlat_packet_4to6(&p, in_buf, n, out_buf, sizeof(out_buf), &size, &dst), EPERM);
        n = make6(in_buf, IPPROTO_UDP, "64:ff9b::c0a8:101", CLAT6, l4_buf, 40);
        ASSERT_ERROR(translate_6to4(&p, n, &size), EPERM);

        /* But in a network specific prefix */
        p.pref64 = in6("2001:db8:64::");
        n = make4(in_buf, IPPROTO_UDP, LOCAL4, "192.168.1.1", l4_buf, 40);
        ASSERT_OK(xlat_packet_4to6(&p, in_buf, n, out_buf, sizeof(out_buf), &size, &dst));
        n = make4(in_buf, IPPROTO_UDP, LOCAL4, "224.0.0.251", l4_buf, 40);
        ASSERT_ERROR(xlat_packet_4to6(&p, in_buf, n, out_buf, sizeof(out_buf), &size, &dst), EPERM);
        p = params();

        /* Outside the prefix, or not for the CLAT address */
        n = make6(in_buf, IPPROTO_UDP, ROUTER6, CLAT6, l4_buf, 40);
        ASSERT_ERROR(translate_6to4(&p, n, &size), EPERM);
        n = make6(in_buf, IPPROTO_UDP, REMOTE6, "2001:db8:1::1", l4_buf, 40);
        ASSERT_ERROR(translate_6to4(&p, n, &size), EPERM);

        /* Fragmented ICMP messages */
        n = make4(in_buf, IPPROTO_ICMP, LOCAL4, REMOTE4, l4_buf, 40);
        unaligned_write_be16(in_buf + 6, IP_MF);
        ASSERT_ERROR(xlat_packet_4to6(&p, in_buf, n, out_buf, sizeof(out_buf), &size, &dst), EOPNOTSUPP);

        /* Truncated */
        n = make4(in_buf, IPPROTO_UDP, LOCAL4, REMOTE4, l4_buf, 40);
        ASSERT_ERROR(xlat_packet_4to6(&p, in_buf, n - 1, out_buf, sizeof(out_buf), &size, &dst), EBADMSG);
        n = make6(in_buf, IPPROTO_UDP, REMOTE6, CLAT6, l4_buf, 40);
        ASSERT_ERROR(translate_6to4(&p, n - 1, &size), EBADMSG);

        /* Other protocols */
        n = make4(in_buf, 132, LOCAL4, REMOTE4, l4_buf, 40);
        ASSERT_ERROR(xlat_packet_4to6(&p, in_buf, n, out_buf, sizeof(out_buf), &size, &dst), EOPNOTSUPP);
}

TEST(ipv4_options) {
        XlatPacketParams p = params();
        struct in6_addr dst;
        size_t n, size;

        make_l4(l4_buf, 40, IPPROTO_UDP);
        n = make4(in_buf, IPPROTO_UDP, LOCAL4, REMOTE4, l4_buf, 40);

        /* Insert 4 bytes of options: RFC 7915 section 4.1 ignores them… */
        memmove(in_buf + 24, in_buf + 20, 40);
        in_buf[0] = 0x46;
        unaligned_write_be16(in_buf + 2, n + 4);
        memcpy(in_buf + 20, (const uint8_t[]) { IPOPT_NOP, IPOPT_NOP, IPOPT_NOP, IPOPT_EOL }, 4);
        ASSERT_OK(xlat_packet_4to6(&p, in_buf, n + 4, out_buf, sizeof(out_buf), &size, &dst));
        ASSERT_EQ(size, 80u);
        verify6(out_buf, size);

        /* …but discards source routed packets */
        memcpy(in_buf + 20, (const uint8_t[]) { IPOPT_LSRR, 3, 4, IPOPT_EOL }, 4);
        ASSERT_ERROR(xlat_packet_4to6(&p, in_buf, n + 4, out_buf, sizeof(out_buf), &size, &dst), EPERM);
}

/* An ICMPv6 error about a packet of ours, as sent by a router */
static size_t make_error6(uint8_t *buf, uint8_t type, uint8_t code, uint32_t value, const char *src,
                          uint8_t protocol, size_t quoted_l4_len, size_t quoted_len) {

        static uint8_t quoted[2048], msg[2048];

        make_l4(l4_buf, quoted_l4_len, protocol);
        if (protocol == IPPROTO_ICMPV6)
                l4_buf[0] = ICMP6_ECHO_REQUEST, l4_buf[1] = 0;
        make6(quoted, protocol, CLAT6, REMOTE6, l4_buf, quoted_l4_len);

        memzero(msg, 8);
        msg[0] = type;
        msg[1] = code;
        unaligned_write_be32(msg + 4, value);
        memcpy(msg + 8, quoted, quoted_len);

        return make6(buf, IPPROTO_ICMPV6, src, CLAT6, msg, 8 + quoted_len);
}

TEST(icmp_error_6to4) {
        int protocol;

        FOREACH_ARGUMENT(protocol, IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMPV6) {
                uint8_t protocol4 = protocol == IPPROTO_ICMPV6 ? IPPROTO_ICMP : protocol;
                XlatPacketParams p = params();
                size_t n, size;

                /* Packet too big from a router that is not within the prefix, with the complete quoted
                 * packet, so that all checksums can be verified */
                n = make_error6(in_buf, ICMP6_PACKET_TOO_BIG, /* code= */ 0, 1400, ROUTER6, protocol, 64, 104);
                ASSERT_OK(translate_6to4(&p, n, &size));
                verify4(out_buf, size);
                ASSERT_EQ(size, 20u + 8u + 20u + 64u);
                struct in_addr src = in4("192.0.0.8");
                ASSERT_EQ(memcmp(out_buf + 12, &src, 4), 0);
                ASSERT_EQ(out_buf[20], ICMP_DEST_UNREACH);
                ASSERT_EQ(out_buf[21], ICMP_FRAG_NEEDED);
                ASSERT_EQ(unaligned_read_be16(out_buf + 26), 1372);
                /* The quoted packet */
                verify4(out_buf + 28, 20 + 64);
                ASSERT_EQ(out_buf[28 + 9], protocol4);
                struct in_addr local = in4(LOCAL4), remote = in4(REMOTE4);
                ASSERT_EQ(memcmp(out_buf + 28 + 12, &local, 4), 0);
                ASSERT_EQ(memcmp(out_buf + 28 + 16, &remote, 4), 0);

                /* Port unreachable from the NAT64 side, quoting only 8 bytes of the transport header */
                n = make_error6(in_buf, ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_NOPORT, /* value= */ 0,
                                REMOTE6, protocol, 64, 48);
                ASSERT_OK(translate_6to4(&p, n, &size));
                ASSERT_EQ(size, 20u + 8u + 20u + 8u);
                ASSERT_EQ(fold_be(sum_be(/* sum= */ 0, out_buf, 20)), 0);
                ASSERT_EQ(fold_be(sum_be(/* sum= */ 0, out_buf + 20, size - 20)), 0);
                ASSERT_EQ(memcmp(out_buf + 12, &remote, 4), 0);
                ASSERT_EQ(out_buf[20], ICMP_DEST_UNREACH);
                ASSERT_EQ(out_buf[21], ICMP_PORT_UNREACH);
                ASSERT_EQ(unaligned_read_be16(out_buf + 28 + 2), 64 + 20);

                /* A bad checksum */
                in_buf[n - 1] ^= 1;
                ASSERT_ERROR(translate_6to4(&p, n, &size), EBADMSG);

                /* About a packet we did not send */
                p.address = in6("2001:db8:1::2");
                n = make_error6(in_buf, ICMP6_TIME_EXCEEDED, /* code= */ 0, /* value= */ 0,
                                ROUTER6, protocol, 64, 104);
                memcpy(in_buf + 24, &p.address, 16);
                fill_l4_checksum(in_buf + 40, n - 40, IPPROTO_ICMPV6, pseudo6(in_buf, n - 40, IPPROTO_ICMPV6));
                ASSERT_ERROR(translate_6to4(&p, n, &size), EPERM);
        }
}

TEST(icmp_error_4to6) {
        int protocol, code;

        FOREACH_ARGUMENT(protocol, IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP)
                FOREACH_ARGUMENT(code, ICMP_PORT_UNREACH, ICMP_PROT_UNREACH) {
                        static uint8_t quoted[2048], msg[2048];
                        XlatPacketParams p = params();
                        struct in6_addr dst, expected = in6(REMOTE6), clat = in6(CLAT6);
                        size_t n, size;

                        make_l4(l4_buf, 64, protocol);
                        if (protocol == IPPROTO_ICMP)
                                l4_buf[0] = ICMP_ECHOREPLY, l4_buf[1] = 0;
                        make4(quoted, protocol, REMOTE4, LOCAL4, l4_buf, 64);

                        memzero(msg, 8);
                        msg[0] = ICMP_DEST_UNREACH;
                        msg[1] = code;
                        memcpy(msg + 8, quoted, 84);
                        n = make4(in_buf, IPPROTO_ICMP, LOCAL4, REMOTE4, msg, 8 + 84);

                        ASSERT_OK(xlat_packet_4to6(&p, in_buf, n, out_buf, sizeof(out_buf), &size, &dst));
                        ASSERT_TRUE(in6_addr_equal(&dst, &expected));
                        ASSERT_EQ(size, 40u + 8u + 40u + 64u);
                        verify6(out_buf, size);
                        ASSERT_EQ(out_buf[40], code == ICMP_PORT_UNREACH ? ICMP6_DST_UNREACH : ICMP6_PARAM_PROB);
                        ASSERT_EQ(out_buf[41], code == ICMP_PORT_UNREACH ? 4 : 1);
                        verify6(out_buf + 48, 40 + 64);
                        ASSERT_EQ(memcmp(out_buf + 48 + 8, &expected, 16), 0);
                        ASSERT_EQ(memcmp(out_buf + 48 + 24, &clat, 16), 0);
                }
}

TEST(icmp_error_truncated_to_minimum_mtu) {
        static uint8_t quoted[2048], msg[2048];
        XlatPacketParams p = params();
        struct in6_addr dst;
        size_t n, size;

        make_l4(l4_buf, 1400, IPPROTO_UDP);
        make4(quoted, IPPROTO_UDP, REMOTE4, LOCAL4, l4_buf, 1400);
        memzero(msg, 8);
        msg[0] = ICMP_DEST_UNREACH;
        msg[1] = ICMP_PORT_UNREACH;
        memcpy(msg + 8, quoted, 1420);
        n = make4(in_buf, IPPROTO_ICMP, LOCAL4, REMOTE4, msg, 1428);

        ASSERT_OK(xlat_packet_4to6(&p, in_buf, n, out_buf, sizeof(out_buf), &size, &dst));
        ASSERT_EQ(size, 1280u);
        verify6(out_buf, size);
}

/* A datagram split into fragments is translated fragment by fragment, in both directions, and the checksum of
 * the reassembled result has to be right */
TEST(fragments) {
        static uint8_t datagram[3000], reassembled[3000];
        XlatPacketParams p = params();
        struct in6_addr dst;
        size_t n, size;
        int protocol;

        FOREACH_ARGUMENT(protocol, IPPROTO_TCP, IPPROTO_UDP) {
                /* IPv4 → IPv6 */
                make_l4(datagram, sizeof(datagram), protocol);
                make4(in_buf, protocol, LOCAL4, REMOTE4, datagram, sizeof(datagram));
                memcpy(datagram, in_buf + 20, sizeof(datagram)); /* with the checksum */

                for (size_t offset = 0; offset < sizeof(datagram); offset += 1448) {
                        size_t len = MIN(sizeof(datagram) - offset, 1448u);
                        bool more = offset + len < sizeof(datagram);

                        n = make4(in_buf, protocol, LOCAL4, REMOTE4, datagram, /* len= */ 0);
                        memcpy(in_buf + 20, datagram + offset, len);
                        n += len;
                        unaligned_write_be16(in_buf + 2, n);
                        unaligned_write_be16(in_buf + 4, 0xbeef);
                        unaligned_write_be16(in_buf + 6, (more ? IP_MF : 0) | offset / 8);

                        ASSERT_OK(xlat_packet_4to6(&p, in_buf, n, out_buf, sizeof(out_buf), &size, &dst));
                        ASSERT_EQ(size, 40 + 8 + len);
                        ASSERT_EQ(out_buf[6], IPPROTO_FRAGMENT);
                        ASSERT_EQ(unaligned_read_be16(out_buf + 4), 8 + len);
                        ASSERT_EQ(out_buf[40], protocol);
                        ASSERT_EQ(unaligned_read_be16(out_buf + 42), offset | more);
                        ASSERT_EQ(unaligned_read_be32(out_buf + 44), 0xbeefu);
                        memcpy(reassembled + offset, out_buf + 48, len);
                }

                n = make6(in_buf, protocol, CLAT6, REMOTE6, datagram, /* len= */ 0);
                ASSERT_EQ(fold_be(sum_be(pseudo6(in_buf, sizeof(reassembled), protocol),
                                         reassembled, sizeof(reassembled))), 0);

                /* IPv6 → IPv4 */
                make6(in_buf, protocol, REMOTE6, CLAT6, datagram, sizeof(datagram));
                memcpy(datagram, in_buf + 40, sizeof(datagram));

                for (size_t offset = 0; offset < sizeof(datagram); offset += 1232) {
                        size_t len = MIN(sizeof(datagram) - offset, 1232u);
                        bool more = offset + len < sizeof(datagram);

                        make6(in_buf, protocol, REMOTE6, CLAT6, datagram, /* len= */ 0);
                        in_buf[6] = IPPROTO_FRAGMENT;
                        unaligned_write_be16(in_buf + 4, 8 + len);
                        in_buf[40] = protocol;
                        in_buf[41] = 0;
                        unaligned_write_be16(in_buf + 42, offset | more);
                        unaligned_write_be32(in_buf + 44, 0x1234beef);
                        memcpy(in_buf + 48, datagram + offset, len);

                        ASSERT_OK(translate_6to4(&p, 48 + len, &size));
                        ASSERT_EQ(size, 20 + len);
                        ASSERT_EQ(fold_be(sum_be(/* sum= */ 0, out_buf, 20)), 0);
                        ASSERT_EQ(unaligned_read_be16(out_buf + 4), 0xbeef);
                        ASSERT_EQ(unaligned_read_be16(out_buf + 6), (more ? IP_MF : 0) | offset / 8);
                        ASSERT_EQ(out_buf[9], protocol);
                        memcpy(reassembled + offset, out_buf + 20, len);
                }

                n = make4(in_buf, protocol, REMOTE4, LOCAL4, datagram, /* len= */ 0);
                ASSERT_EQ(fold_be(sum_be(pseudo4(in_buf, sizeof(reassembled), protocol),
                                         reassembled, sizeof(reassembled))), 0);
        }

        /* A first fragment of a UDP datagram without checksum cannot be translated */
        make_l4(l4_buf, 64, IPPROTO_UDP);
        n = make4(in_buf, IPPROTO_UDP, LOCAL4, REMOTE4, l4_buf, 64);
        unaligned_write_be16(in_buf + 6, IP_MF);
        unaligned_write_be16(in_buf + 26, 0);
        ASSERT_ERROR(xlat_packet_4to6(&p, in_buf, n, out_buf, sizeof(out_buf), &size, &dst), ENODATA);
}

TEST(icmp_error_6to4_quoted_fragment) {
        static uint8_t msg[256];
        XlatPacketParams p = params();
        size_t n, size;
        int offset;

        FOREACH_ARGUMENT(offset, 0, 1232) {
                make_l4(l4_buf, 64, IPPROTO_UDP);
                memzero(msg, sizeof(msg));
                msg[0] = ICMP6_PACKET_TOO_BIG;
                unaligned_write_be32(msg + 4, 1400);
                make6(msg + 8, IPPROTO_UDP, CLAT6, REMOTE6, l4_buf, 64);
                /* Insert a fragment header */
                memmove(msg + 56, msg + 48, 64);
                msg[8 + 6] = IPPROTO_FRAGMENT;
                unaligned_write_be16(msg + 8 + 4, 8 + 64);
                msg[48] = IPPROTO_UDP;
                msg[49] = 0;
                unaligned_write_be16(msg + 50, offset | 1);
                unaligned_write_be32(msg + 52, 0xbeef);
                n = make6(in_buf, IPPROTO_ICMPV6, ROUTER6, CLAT6, msg, 120);

                ASSERT_OK(translate_6to4(&p, n, &size));
                ASSERT_EQ(size, 20u + 8u + 20u + 64u);
                ASSERT_EQ(fold_be(sum_be(/* sum= */ 0, out_buf, 20)), 0);
                ASSERT_EQ(fold_be(sum_be(/* sum= */ 0, out_buf + 20, size - 20)), 0);
                ASSERT_EQ(unaligned_read_be16(out_buf + 26), 1372);
                ASSERT_EQ(unaligned_read_be16(out_buf + 28 + 2), 20 + 64);
                ASSERT_EQ(unaligned_read_be16(out_buf + 28 + 4), 0xbeef);
                ASSERT_EQ(unaligned_read_be16(out_buf + 28 + 6), IP_MF | offset / 8);
                if (offset == 0)
                        /* The quoted datagram is complete here, hence its checksum can be verified */
                        verify4(out_buf + 28, 20 + 64);
                else
                        ASSERT_EQ(memcmp(out_buf + 48, msg + 56, 64), 0);
        }
}

/* The translators parse packets received from the network: they must not crash or overrun on garbage */
TEST(mutated_packets) {
        XlatPacketParams p = params();
        struct in6_addr dst;
        size_t size;

        for (unsigned i = 0; i < 100000; i++) {
                _cleanup_free_ uint8_t *packet = NULL, *out = NULL;
                size_t n;

                if (i % 2 == 0)
                        n = make_error6(in_buf, random_u32() % 5, random_u32() % 6, random_u32(),
                                        i % 4 == 0 ? ROUTER6 : REMOTE6,
                                        i % 3 == 0 ? IPPROTO_TCP : IPPROTO_UDP, 64, 104);
                else {
                        static uint8_t msg[256];

                        make_l4(l4_buf, 64, IPPROTO_UDP);
                        make4(msg + 8, IPPROTO_UDP, REMOTE4, LOCAL4, l4_buf, 64);
                        msg[0] = ICMP_DEST_UNREACH;
                        msg[1] = ICMP_PORT_UNREACH;
                        n = make4(in_buf, IPPROTO_ICMP, LOCAL4, REMOTE4, msg, 92);
                }

                for (unsigned j = random_u32() % 4; j > 0; j--)
                        in_buf[random_u32() % n] = random_u32();

                n = random_u32() % 8 == 0 ? random_u32() % (n + 1) : n;

                /* Exactly sized buffers, so that overruns are caught by sanitizers */
                ASSERT_NOT_NULL(packet = memdup(in_buf, MAX(n, 1u)));
                size_t out_max = random_u32() % 8 == 0 ? random_u32() % 256 : 2048;
                ASSERT_NOT_NULL(out = malloc(MAX(out_max, 1u)));

                if (i % 2 == 0)
                        (void) xlat_packet_6to4(&p, packet, n, random_u32() % 2, out, out_max, &size);
                else {
                        /* The ICMP checksum is verified first, hence repair it to reach further */
                        if (n >= 28 && random_u32() % 2 == 0 &&
                            (packet[0] & 0x0f) == 5 && unaligned_read_be16(packet + 2) == n)
                                fill_l4_checksum(packet + 20, n - 20, IPPROTO_ICMP, /* pseudo= */ 0);
                        (void) xlat_packet_4to6(&p, packet, n, out, out_max, &size, &dst);
                }
        }
}

DEFINE_TEST_MAIN(LOG_INFO);
