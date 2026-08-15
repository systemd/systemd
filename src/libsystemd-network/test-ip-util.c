/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "iovec-util.h"
#include "iovec-wrapper.h"
#include "ip-util.h"
#include "random-util.h"
#include "tests.h"

TEST(ip_checksum) {
        uint8_t buf[20] = {
                0x45, 0x00, 0x02, 0x40, 0x00, 0x00, 0x00, 0x00,
                0x40, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xff, 0xff, 0xff, 0xff
        };

        ASSERT_EQ(ip_checksum(buf, 20), be16toh(0x78ae));
}

static void create_packet(struct iphdr *ip, struct udphdr *udp, struct iovec_wrapper *payload, struct iovec *ret) {
        _cleanup_(iovw_done) struct iovec_wrapper iovw = {};
        ASSERT_OK(iovw_put(&iovw, ip, sizeof(struct iphdr)));
        ASSERT_OK(iovw_put(&iovw, udp, sizeof(struct udphdr)));
        ASSERT_OK(iovw_put_iovw(&iovw, payload));
        ASSERT_OK(iovw_concat(&iovw, ret));
}

TEST(udp_packet_build_and_verify) {
        size_t n = random_u64_range(20) + 20;

        _cleanup_(iovw_done_free) struct iovec_wrapper payload = {};
        size_t i;
        FOREACH_ARGUMENT(i, 1, 0, 1, 1, 3, 1, 2, 1, n, n, n + 1, n + 1, n + 2, n + 3, n + 4, n + 5, n + 6) {
                struct iovec tmp = {};
                ASSERT_OK(random_bytes_allocate_iovec(i, &tmp));
                ASSERT_OK(iovw_consume_iov(&payload, &tmp));
        }

        struct iphdr ip;
        struct udphdr udp;
        ASSERT_OK(udp_packet_build(
                                  /* source_addr= */ htobe32(0xC0020001),
                                  /* source_port= */ 42,
                                  /* destination_addr= */ htobe32(0xC0020002),
                                  /* destination_port= */ 43,
                                  /* ip_service_type= */ 7,
                                  &payload,
                                  &ip,
                                  &udp));

        _cleanup_(iovec_done) struct iovec joined = {};
        ASSERT_OK(iovw_concat(&payload, &joined));

        struct iphdr ip2;
        struct udphdr udp2;
        ASSERT_OK(udp_packet_build(
                                  /* source_addr= */ htobe32(0xC0020001),
                                  /* source_port= */ 42,
                                  /* destination_addr= */ htobe32(0xC0020002),
                                  /* destination_port= */ 43,
                                  /* ip_service_type= */ 7,
                                  &(struct iovec_wrapper) {
                                          .iovec = &joined,
                                          .count = 1,
                                  },
                                  &ip2,
                                  &udp2));

        ASSERT_EQ(memcmp(&ip, &ip2, sizeof(struct iphdr)), 0);
        ASSERT_EQ(memcmp(&udp, &udp2, sizeof(struct udphdr)), 0);

        _cleanup_(iovec_done) struct iovec packet = {};
        create_packet(&ip, &udp, &payload, &packet);

        struct iovec iov;
        ASSERT_OK(udp_packet_verify(&packet, /* port= */ 43, /* checksum= */ false, &iov));
        ASSERT_TRUE(iovec_equal(&iov, &joined));
        ASSERT_OK(udp_packet_verify(&packet, /* port= */ 43, /* checksum= */ true, &iov));
        ASSERT_TRUE(iovec_equal(&iov, &joined));

        /* UDP port mismatch */
        ASSERT_ERROR(udp_packet_verify(&packet, /* port= */ 42, /* checksum= */ false, /* ret_payload= */ NULL), EBADMSG);

        /* truncated packet */
        ASSERT_ERROR(udp_packet_verify(&IOVEC_MAKE(packet.iov_base, packet.iov_len - 1),
                                       /* port= */ 43, /* checksum= */ false, /* ret_payload= */ NULL), EBADMSG);

        /* bad IP version */
        struct iphdr badip = ip;
        badip.version = 6;
        iovec_done(&packet);
        create_packet(&badip, &udp, &payload, &packet);
        ASSERT_ERROR(udp_packet_verify(&packet, /* port= */ 43, /* checksum= */ false, /* ret_payload= */ NULL), EBADMSG);

        /* bad IP header size */
        badip = ip;
        badip.ihl = 1;
        iovec_done(&packet);
        create_packet(&badip, &udp, &payload, &packet);
        ASSERT_ERROR(udp_packet_verify(&packet, /* port= */ 43, /* checksum= */ false, /* ret_payload= */ NULL), EBADMSG);

        /* packet size in IP header is smaller than IP header size */
        badip = ip;
        badip.tot_len = htobe16(1);
        iovec_done(&packet);
        create_packet(&badip, &udp, &payload, &packet);
        ASSERT_ERROR(udp_packet_verify(&packet, /* port= */ 43, /* checksum= */ false, /* ret_payload= */ NULL), EBADMSG);

        /* packet size in IP header is larger than the packet size */
        badip = ip;
        badip.tot_len = htobe16(be16toh(ip.tot_len) + 1);
        iovec_done(&packet);
        create_packet(&badip, &udp, &payload, &packet);
        ASSERT_ERROR(udp_packet_verify(&packet, /* port= */ 43, /* checksum= */ false, /* ret_payload= */ NULL), EBADMSG);

        /* IP protocol mismatch */
        badip = ip;
        badip.protocol = IPPROTO_TCP;
        iovec_done(&packet);
        create_packet(&badip, &udp, &payload, &packet);
        ASSERT_ERROR(udp_packet_verify(&packet, /* port= */ 43, /* checksum= */ false, /* ret_payload= */ NULL), EBADMSG);

        /* bad IP header checksum */
        badip = ip;
        badip.check = ~ip.check;
        iovec_done(&packet);
        create_packet(&badip, &udp, &payload, &packet);
        ASSERT_ERROR(udp_packet_verify(&packet, /* port= */ 43, /* checksum= */ false, /* ret_payload= */ NULL), EBADMSG);

        /* UDP length is smaller than the UDP header size */
        struct udphdr badudp = udp;
        badudp.len = htobe16(1);
        iovec_done(&packet);
        create_packet(&ip, &badudp, &payload, &packet);
        ASSERT_ERROR(udp_packet_verify(&packet, /* port= */ 43, /* checksum= */ false, /* ret_payload= */ NULL), EBADMSG);

        /* UDP length is smaller than the packet size */
        badudp = udp;
        badudp.len = htobe16(be16toh(udp.len) - 1);
        iovec_done(&packet);
        create_packet(&ip, &badudp, &payload, &packet);
        ASSERT_ERROR(udp_packet_verify(&packet, /* port= */ 43, /* checksum= */ false, /* ret_payload= */ NULL), EBADMSG);

        /* UDP length is larger than the packet size */
        badudp = udp;
        badudp.len = htobe16(be16toh(udp.len) + 1);
        iovec_done(&packet);
        create_packet(&ip, &badudp, &payload, &packet);
        ASSERT_ERROR(udp_packet_verify(&packet, /* port= */ 43, /* checksum= */ false, /* ret_payload= */ NULL), EBADMSG);

        /* bad UDP checksum */
        badudp = udp;
        if (udp.check != UINT16_MAX)
                badudp.check = ~udp.check;
        else
                badudp.check = 0xdeadu;
        iovec_done(&packet);
        create_packet(&ip, &badudp, &payload, &packet);
        ASSERT_OK(udp_packet_verify(&packet, /* port= */ 43, /* checksum= */ false, &iov));
        ASSERT_TRUE(iovec_equal(&iov, &joined));
        ASSERT_ERROR(udp_packet_verify(&packet, /* port= */ 43, /* checksum= */ true, /* ret_payload= */ NULL), EBADMSG);

        /* missing UDP checksum */
        badudp = udp;
        badudp.check = 0;
        iovec_done(&packet);
        create_packet(&ip, &badudp, &payload, &packet);
        ASSERT_OK(udp_packet_verify(&packet, /* port= */ 43, /* checksum= */ false, &iov));
        ASSERT_TRUE(iovec_equal(&iov, &joined));
        ASSERT_OK(udp_packet_verify(&packet, /* port= */ 43, /* checksum= */ true, &iov));
        ASSERT_TRUE(iovec_equal(&iov, &joined));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
