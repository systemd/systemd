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

        _cleanup_(iovw_done) struct iovec_wrapper iovw = {};
        ASSERT_OK(iovw_put(&iovw, &ip, sizeof(struct iphdr)));
        ASSERT_OK(iovw_put(&iovw, &udp, sizeof(struct udphdr)));
        ASSERT_OK(iovw_put_iovw(&iovw, &payload));

        _cleanup_(iovec_done) struct iovec packet = {};
        ASSERT_OK(iovw_concat(&iovw, &packet));

        struct iovec iov;
        ASSERT_OK(udp_packet_verify(&packet, /* port= */ 43, /* checksum= */ true, &iov));

        _cleanup_(iovec_done) struct iovec joined = {};
        ASSERT_OK(iovw_concat(&payload, &joined));
        ASSERT_TRUE(iovec_equal(&iov, &joined));

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

}

DEFINE_TEST_MAIN(LOG_DEBUG);
