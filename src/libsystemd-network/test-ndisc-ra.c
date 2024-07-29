/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2017 Intel Corporation. All rights reserved.
***/

#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "sd-radv.h"

#include "alloc-util.h"
#include "hexdecoct.h"
#include "icmp6-test-util.h"
#include "socket-util.h"
#include "strv.h"
#include "tests.h"

static struct ether_addr mac_addr = {
        .ether_addr_octet = { 0x78, 0x2b, 0xcb, 0xb3, 0x6d, 0x53 }
};

static bool test_stopped;
static struct {
        struct in6_addr address;
        unsigned char prefixlen;
        uint32_t valid;
        uint32_t preferred;
        bool successful;
} prefix[] = {
        { { { { 0x20, 0x01, 0x0d, 0xb8, 0xde, 0xad, 0xbe, 0xef,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } }, 64,
          500, 440, true },
        { { { { 0x20, 0x01, 0x0d, 0xb8, 0x0b, 0x16, 0xd0, 0x0d,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } }, 64,
          /* indicate default valid and preferred lifetimes for the test code */
          0, 0, true },
        { { { { 0x20, 0x01, 0x0d, 0xb8, 0x0b, 0x16, 0xd0, 0x0d,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } }, 58,
          0, 0,
          /* indicate that this prefix already exists */
          false },
        { { { { 0x20, 0x01, 0x0d, 0xb8, 0x0b, 0x16, 0xd0, 0x0d,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } }, 120,
          0, 0,
          /* indicate that this prefix already exists */
          false },
        { { { { 0x20, 0x01, 0x0d, 0xb8, 0x0b, 0x16, 0xd0, 0x0d,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } }, 12,
          0, 0,
          /* indicate that this prefix already exists */
          false },
        { { { { 0x20, 0x01, 0x0d, 0xb8, 0xc0, 0x01, 0x0d, 0xad,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } }, 48,
          0, 0, true },
        { { { { 0x20, 0x01, 0x0d, 0xb8, 0xc0, 0x01, 0x0d, 0xad,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } }, 60,
          0, 0,
          /* indicate that this prefix already exists */
          false },
};

static const struct in6_addr test_rdnss = { { { 0x20, 0x01, 0x0d, 0xb8,
                                                0xde, 0xad, 0xbe, 0xef,
                                                0x00, 0x00, 0x00, 0x00,
                                                0x00, 0x00, 0x00, 0x01 } } };
static const char *test_dnssl[] = { "lab.intra",
                                    NULL };

TEST(radv_prefix) {
        sd_radv_prefix *p;

        assert_se(sd_radv_prefix_new(&p) >= 0);

        ASSERT_RETURN_EXPECTED_SE(sd_radv_prefix_set_onlink(NULL, true) < 0);
        assert_se(sd_radv_prefix_set_onlink(p, true) >= 0);
        assert_se(sd_radv_prefix_set_onlink(p, false) >= 0);

        ASSERT_RETURN_EXPECTED_SE(sd_radv_prefix_set_address_autoconfiguration(NULL, true) < 0);
        assert_se(sd_radv_prefix_set_address_autoconfiguration(p, true) >= 0);
        assert_se(sd_radv_prefix_set_address_autoconfiguration(p, false) >= 0);

        ASSERT_RETURN_EXPECTED_SE(sd_radv_prefix_set_valid_lifetime(NULL, 1, 1) < 0);
        assert_se(sd_radv_prefix_set_valid_lifetime(p, 0, 0) >= 0);
        assert_se(sd_radv_prefix_set_valid_lifetime(p, 300 * USEC_PER_SEC, USEC_INFINITY) >= 0);
        assert_se(sd_radv_prefix_set_valid_lifetime(p, 300 * USEC_PER_SEC, USEC_PER_YEAR) >= 0);

        ASSERT_RETURN_EXPECTED_SE(sd_radv_prefix_set_preferred_lifetime(NULL, 1, 1) < 0);
        assert_se(sd_radv_prefix_set_preferred_lifetime(p, 0, 0) >= 0);
        assert_se(sd_radv_prefix_set_preferred_lifetime(p, 300 * USEC_PER_SEC, USEC_INFINITY) >= 0);
        assert_se(sd_radv_prefix_set_preferred_lifetime(p, 300 * USEC_PER_SEC, USEC_PER_YEAR) >= 0);

        ASSERT_RETURN_EXPECTED_SE(sd_radv_prefix_set_prefix(NULL, NULL, 0) < 0);
        ASSERT_RETURN_EXPECTED_SE(sd_radv_prefix_set_prefix(p, NULL, 0) < 0);

        assert_se(sd_radv_prefix_set_prefix(p, &prefix[0].address, 64) >= 0);
        assert_se(sd_radv_prefix_set_prefix(p, &prefix[0].address, 0) < 0);
        assert_se(sd_radv_prefix_set_prefix(p, &prefix[0].address, 1) < 0);
        assert_se(sd_radv_prefix_set_prefix(p, &prefix[0].address, 2) < 0);
        assert_se(sd_radv_prefix_set_prefix(p, &prefix[0].address, 3) >= 0);
        assert_se(sd_radv_prefix_set_prefix(p, &prefix[0].address, 125) >= 0);
        assert_se(sd_radv_prefix_set_prefix(p, &prefix[0].address, 128) >= 0);
        ASSERT_RETURN_EXPECTED_SE(sd_radv_prefix_set_prefix(p, &prefix[0].address, 129) < 0);
        ASSERT_RETURN_EXPECTED_SE(sd_radv_prefix_set_prefix(p, &prefix[0].address, 255) < 0);

        assert_se(!sd_radv_prefix_unref(p));
}

TEST(radv_route_prefix) {
        sd_radv_route_prefix *p;

        assert_se(sd_radv_route_prefix_new(&p) >= 0);

        ASSERT_RETURN_EXPECTED_SE(sd_radv_route_prefix_set_lifetime(NULL, 1, 1) < 0);
        assert_se(sd_radv_route_prefix_set_lifetime(p, 0, 0) >= 0);
        assert_se(sd_radv_route_prefix_set_lifetime(p, 300 * USEC_PER_SEC, USEC_INFINITY) >= 0);
        assert_se(sd_radv_route_prefix_set_lifetime(p, 300 * USEC_PER_SEC, USEC_PER_YEAR) >= 0);

        ASSERT_RETURN_EXPECTED_SE(sd_radv_route_prefix_set_prefix(NULL, NULL, 0) < 0);
        ASSERT_RETURN_EXPECTED_SE(sd_radv_route_prefix_set_prefix(p, NULL, 0) < 0);

        assert_se(sd_radv_route_prefix_set_prefix(p, &prefix[0].address, 64) >= 0);
        assert_se(sd_radv_route_prefix_set_prefix(p, &prefix[0].address, 0) >= 0);
        assert_se(sd_radv_route_prefix_set_prefix(p, &prefix[0].address, 1) >= 0);
        assert_se(sd_radv_route_prefix_set_prefix(p, &prefix[0].address, 2) >= 0);
        assert_se(sd_radv_route_prefix_set_prefix(p, &prefix[0].address, 3) >= 0);
        assert_se(sd_radv_route_prefix_set_prefix(p, &prefix[0].address, 125) >= 0);
        assert_se(sd_radv_route_prefix_set_prefix(p, &prefix[0].address, 128) >= 0);
        ASSERT_RETURN_EXPECTED_SE(sd_radv_route_prefix_set_prefix(p, &prefix[0].address, 129) < 0);
        ASSERT_RETURN_EXPECTED_SE(sd_radv_route_prefix_set_prefix(p, &prefix[0].address, 255) < 0);

        assert_se(!sd_radv_route_prefix_unref(p));
}

TEST(radv_pref64_prefix) {
        sd_radv_pref64_prefix *p;

        assert_se(sd_radv_pref64_prefix_new(&p) >= 0);

        ASSERT_RETURN_EXPECTED_SE(sd_radv_pref64_prefix_set_prefix(NULL, NULL, 0, 0) < 0);
        ASSERT_RETURN_EXPECTED_SE(sd_radv_pref64_prefix_set_prefix(p, NULL, 0, 0) < 0);

        assert_se(sd_radv_pref64_prefix_set_prefix(p, &prefix[0].address, 32, 300 * USEC_PER_SEC) >= 0);
        assert_se(sd_radv_pref64_prefix_set_prefix(p, &prefix[0].address, 40, 300 * USEC_PER_SEC) >= 0);
        assert_se(sd_radv_pref64_prefix_set_prefix(p, &prefix[0].address, 48, 300 * USEC_PER_SEC) >= 0);
        assert_se(sd_radv_pref64_prefix_set_prefix(p, &prefix[0].address, 56, 300 * USEC_PER_SEC) >= 0);
        assert_se(sd_radv_pref64_prefix_set_prefix(p, &prefix[0].address, 64, 300 * USEC_PER_SEC) >= 0);
        assert_se(sd_radv_pref64_prefix_set_prefix(p, &prefix[0].address, 96, 300 * USEC_PER_SEC) >= 0);

        assert_se(sd_radv_pref64_prefix_set_prefix(p, &prefix[0].address, 80, 300 * USEC_PER_SEC) < 0);
        assert_se(sd_radv_pref64_prefix_set_prefix(p, &prefix[0].address, 80, USEC_PER_DAY) < 0);

        assert_se(!sd_radv_pref64_prefix_unref(p));
}

TEST(radv) {
        sd_radv *ra;

        assert_se(sd_radv_new(&ra) >= 0);
        assert_se(ra);

        ASSERT_RETURN_EXPECTED_SE(sd_radv_set_ifindex(NULL, 0) < 0);
        ASSERT_RETURN_EXPECTED_SE(sd_radv_set_ifindex(ra, 0) < 0);
        ASSERT_RETURN_EXPECTED_SE(sd_radv_set_ifindex(ra, -1) < 0);
        ASSERT_RETURN_EXPECTED_SE(sd_radv_set_ifindex(ra, -2) < 0);
        assert_se(sd_radv_set_ifindex(ra, 42) >= 0);

        ASSERT_RETURN_EXPECTED_SE(sd_radv_set_mac(NULL, NULL) < 0);
        ASSERT_RETURN_EXPECTED_SE(sd_radv_set_mac(ra, NULL) >= 0);
        assert_se(sd_radv_set_mac(ra, &mac_addr) >= 0);

        ASSERT_RETURN_EXPECTED_SE(sd_radv_set_mtu(NULL, 0) < 0);
        ASSERT_RETURN_EXPECTED_SE(sd_radv_set_mtu(ra, 0) < 0);
        ASSERT_RETURN_EXPECTED_SE(sd_radv_set_mtu(ra, 1279) < 0);
        assert_se(sd_radv_set_mtu(ra, 1280) >= 0);
        assert_se(sd_radv_set_mtu(ra, ~0) >= 0);

        ASSERT_RETURN_EXPECTED_SE(sd_radv_set_hop_limit(NULL, 0) < 0);
        assert_se(sd_radv_set_hop_limit(ra, 0) >= 0);
        assert_se(sd_radv_set_hop_limit(ra, ~0) >= 0);

        ASSERT_RETURN_EXPECTED_SE(sd_radv_set_router_lifetime(NULL, 0) < 0);
        assert_se(sd_radv_set_router_lifetime(ra, 0) >= 0);
        assert_se(sd_radv_set_router_lifetime(ra, USEC_INFINITY) < 0);
        assert_se(sd_radv_set_router_lifetime(ra, USEC_PER_YEAR) < 0);
        assert_se(sd_radv_set_router_lifetime(ra, 300 * USEC_PER_SEC) >= 0);

        ASSERT_RETURN_EXPECTED_SE(sd_radv_set_preference(NULL, 0) < 0);
        assert_se(sd_radv_set_preference(ra, SD_NDISC_PREFERENCE_LOW) >= 0);
        assert_se(sd_radv_set_preference(ra, SD_NDISC_PREFERENCE_MEDIUM) >= 0);
        assert_se(sd_radv_set_preference(ra, SD_NDISC_PREFERENCE_HIGH) >= 0);
        ASSERT_RETURN_EXPECTED_SE(sd_radv_set_preference(ra, ~0) < 0);

        ASSERT_RETURN_EXPECTED_SE(sd_radv_set_managed_information(NULL, true) < 0);
        assert_se(sd_radv_set_managed_information(ra, true) >= 0);
        assert_se(sd_radv_set_managed_information(ra, false) >= 0);

        ASSERT_RETURN_EXPECTED_SE(sd_radv_set_other_information(NULL, true) < 0);
        assert_se(sd_radv_set_other_information(ra, true) >= 0);
        assert_se(sd_radv_set_other_information(ra, false) >= 0);

        ASSERT_RETURN_EXPECTED_SE(sd_radv_set_reachable_time(NULL, 10 * USEC_PER_MSEC) < 0);
        assert_se(sd_radv_set_reachable_time(ra, 10 * USEC_PER_MSEC) >= 0);
        assert_se(sd_radv_set_reachable_time(ra, 0) >= 0);
        assert_se(sd_radv_set_reachable_time(ra, USEC_INFINITY) >= 0);

        ASSERT_RETURN_EXPECTED_SE(sd_radv_set_retransmit(NULL, 10 * USEC_PER_MSEC) < 0);
        assert_se(sd_radv_set_retransmit(ra, 10 * USEC_PER_MSEC) >= 0);
        assert_se(sd_radv_set_retransmit(ra, 0) >= 0);
        assert_se(sd_radv_set_retransmit(ra, USEC_INFINITY) >= 0);

        ASSERT_RETURN_EXPECTED_SE(sd_radv_set_rdnss(NULL, 0, NULL, 0) < 0);
        assert_se(sd_radv_set_rdnss(ra, 0, NULL, 0) >= 0);
        ASSERT_RETURN_EXPECTED_SE(sd_radv_set_rdnss(ra, 0, NULL, 128) < 0);
        assert_se(sd_radv_set_rdnss(ra, 600 * USEC_PER_SEC, &test_rdnss, 0) >= 0);
        assert_se(sd_radv_set_rdnss(ra, 600 * USEC_PER_SEC, &test_rdnss, 1) >= 0);
        assert_se(sd_radv_set_rdnss(ra, 0, &test_rdnss, 1) >= 0);
        assert_se(sd_radv_set_rdnss(ra, 0, NULL, 0) >= 0);

        assert_se(sd_radv_set_dnssl(ra, 0, NULL) >= 0);
        assert_se(sd_radv_set_dnssl(ra, 600 * USEC_PER_SEC, NULL) >= 0);
        assert_se(sd_radv_set_dnssl(ra, 0, (char **)test_dnssl) >= 0);
        assert_se(sd_radv_set_dnssl(ra, 600 * USEC_PER_SEC, (char **)test_dnssl) >= 0);

        ASSERT_RETURN_EXPECTED_SE(sd_radv_set_home_agent_information(NULL, true) < 0);
        assert_se(sd_radv_set_home_agent_information(ra, true) >= 0);
        assert_se(sd_radv_set_home_agent_information(ra, false) >= 0);

        ASSERT_RETURN_EXPECTED_SE(sd_radv_set_home_agent_preference(NULL, 10) < 0);
        assert_se(sd_radv_set_home_agent_preference(ra, 10) >= 0);
        assert_se(sd_radv_set_home_agent_preference(ra, 0) >= 0);

        ASSERT_RETURN_EXPECTED_SE(sd_radv_set_home_agent_lifetime(NULL, 300 * USEC_PER_SEC) < 0);
        assert_se(sd_radv_set_home_agent_lifetime(ra, 300 * USEC_PER_SEC) >= 0);
        assert_se(sd_radv_set_home_agent_lifetime(ra, 0) >= 0);
        assert_se(sd_radv_set_home_agent_lifetime(ra, USEC_PER_DAY) < 0);

        ra = sd_radv_unref(ra);
        assert_se(!ra);
}

static void dump_message(const uint8_t *buf, size_t len) {
        assert(len >= sizeof(struct nd_router_advert));

        printf("Received Router Advertisement with lifetime %i sec\n",
               (buf[6] << 8) + buf[7]);

        for (size_t i = 0; i < len; i++) {
                if (!(i % 8))
                        printf("%3zu: ", i);

                printf("0x%02x", buf[i]);

                if ((i + 1) % 8)
                        printf(", ");
                else
                        printf("\n");
        }
}

static void verify_message(const uint8_t *buf, size_t len) {
        static const uint8_t advertisement[] = {
                /* ICMPv6 Router Advertisement, no checksum */
                0x86, 0x00, 0x00, 0x00, 0x40, 0xc0, 0x00, 0xb4,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                /* Source Link Layer Address Option */
                0x01, 0x01, 0x78, 0x2b, 0xcb, 0xb3, 0x6d, 0x53,
                /* Prefix Information Option */
                0x03, 0x04, 0x40, 0xc0, 0x00, 0x00, 0x01, 0xf4,
                0x00, 0x00, 0x01, 0xb8, 0x00, 0x00, 0x00, 0x00,
                0x20, 0x01, 0x0d, 0xb8, 0xde, 0xad, 0xbe, 0xef,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                /* Prefix Information Option */
                0x03, 0x04, 0x40, 0xc0, 0x00, 0x00, 0x0e, 0x10,
                0x00, 0x00, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00,
                0x20, 0x01, 0x0d, 0xb8, 0x0b, 0x16, 0xd0, 0x0d,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                /* Prefix Information Option */
                0x03, 0x04, 0x30, 0xc0, 0x00, 0x00, 0x0e, 0x10,
                0x00, 0x00, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00,
                0x20, 0x01, 0x0d, 0xb8, 0xc0, 0x01, 0x0d, 0xad,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                /* Recursive DNS Server Option */
                0x19, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c,
                0x20, 0x01, 0x0d, 0xb8, 0xde, 0xad, 0xbe, 0xef,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                /* DNS Search List Option */
                0x1f, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c,
                0x03, 0x6c, 0x61, 0x62, 0x05, 0x69, 0x6e, 0x74,
                0x72, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        };

        /* verify only up to known options, rest is not yet implemented */
        for (size_t i = 0, m = MIN(len, sizeof(advertisement)); i < m; i++) {
                if (test_stopped)
                        /* on stop, many header fields are zero */
                        switch (i) {
                        case 4: /* hop limit */
                        case 5: /* flags */
                        case 6 ... 7: /* router lifetime */
                        case 8 ... 11: /* reachable time */
                        case 12 ... 15: /* retrans timer */
                                assert_se(buf[i] == 0);
                                continue;
                        }

                assert_se(buf[i] == advertisement[i]);
        }
}

static int radv_recv(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        sd_radv *ra = ASSERT_PTR(userdata);
        _cleanup_free_ uint8_t *buf = NULL;
        ssize_t buflen;

        buflen = next_datagram_size_fd(fd);
        assert_se(buflen >= 0);
        assert_se(buf = new0(uint8_t, buflen));

        assert_se(read(fd, buf, buflen) == buflen);

        dump_message(buf, buflen);
        verify_message(buf, buflen);

        if (test_stopped) {
                assert_se(sd_event_exit(sd_radv_get_event(ra), 0) >= 0);
                return 0;
        }

        assert_se(sd_radv_stop(ra) >= 0);
        test_stopped = true;
        return 0;
}

TEST(ra) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *recv_router_advertisement = NULL;
        _cleanup_(sd_radv_unrefp) sd_radv *ra = NULL;

        assert_se(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, test_fd) >= 0);

        assert_se(sd_event_new(&e) >= 0);

        assert_se(sd_radv_new(&ra) >= 0);
        assert_se(ra);

        assert_se(sd_radv_attach_event(ra, e, 0) >= 0);

        assert_se(sd_radv_set_ifindex(ra, 42) >= 0);
        assert_se(sd_radv_set_mac(ra, &mac_addr) >= 0);
        assert_se(sd_radv_set_router_lifetime(ra, 180 * USEC_PER_SEC) >= 0);
        assert_se(sd_radv_set_hop_limit(ra, 64) >= 0);
        assert_se(sd_radv_set_managed_information(ra, true) >= 0);
        assert_se(sd_radv_set_other_information(ra, true) >= 0);
        assert_se(sd_radv_set_rdnss(ra, 60 * USEC_PER_SEC, &test_rdnss, 1) >= 0);
        assert_se(sd_radv_set_dnssl(ra, 60 * USEC_PER_SEC, (char **)test_dnssl) >= 0);

        for (unsigned i = 0; i < ELEMENTSOF(prefix); i++) {
                sd_radv_prefix *p;

                printf("Test prefix %u\n", i);
                assert_se(sd_radv_prefix_new(&p) >= 0);

                assert_se(sd_radv_prefix_set_prefix(p, &prefix[i].address,
                                                    prefix[i].prefixlen) >= 0);
                if (prefix[i].valid > 0)
                        assert_se(sd_radv_prefix_set_valid_lifetime(p, prefix[i].valid * USEC_PER_SEC, USEC_INFINITY) >= 0);
                if (prefix[i].preferred > 0)
                        assert_se(sd_radv_prefix_set_preferred_lifetime(p, prefix[i].preferred * USEC_PER_SEC, USEC_INFINITY) >= 0);

                assert_se((sd_radv_add_prefix(ra, p) >= 0) == prefix[i].successful);
                /* If the previous sd_radv_add_prefix() succeeds, then also the second call should also succeed. */
                assert_se((sd_radv_add_prefix(ra, p) >= 0) == prefix[i].successful);

                p = sd_radv_prefix_unref(p);
                assert_se(!p);
        }

        assert_se(sd_event_add_io(e, &recv_router_advertisement, test_fd[0], EPOLLIN, radv_recv, ra) >= 0);
        assert_se(sd_event_source_set_io_fd_own(recv_router_advertisement, true) >= 0);

        assert_se(sd_event_add_time_relative(e, NULL, CLOCK_BOOTTIME,
                                             30 * USEC_PER_SEC, 0,
                                             NULL, INT_TO_PTR(-ETIMEDOUT)) >= 0);

        assert_se(sd_radv_start(ra) >= 0);

        assert_se(sd_event_loop(e) >= 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
