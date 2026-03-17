/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
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

TEST(udp_packet_verify) {
        size_t n = random_u64_range(100) + 100;
        _cleanup_free_ void *buf = malloc(n);
        random_bytes(buf, n);
        struct iovec payload = IOVEC_MAKE(buf, n);

        _cleanup_(iovw_done_free) struct iovec_wrapper iovw = {};
        ASSERT_OK(udp_packet_build(
                                  /* source_addr= */ 0xC0020001,
                                  /* source_pprt= */ 42,
                                  /* destination_addr= */ 0xC0020002,
                                  /* destination_port= */ 43,
                                  /* ip_service_type= */ 7,
                                  &payload,
                                  &iovw));
        TAKE_PTR(buf);

        _cleanup_(iovec_done) struct iovec packet = {};
        ASSERT_OK(iovw_concat(&iovw, &packet));

        struct iovec iov;
        ASSERT_OK(udp_packet_verify(packet.iov_base, packet.iov_len, /* port= */ 43, /* checksum= */ true, &iov));
        ASSERT_EQ(iovec_memcmp(&iov, &payload), 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
