/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  Copyright © 2017 Intel Corporation. All rights reserved.
***/

#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "sd-radv.h"

#include "alloc-util.h"
#include "hexdecoct.h"
#include "icmp6-util.h"
#include "socket-util.h"
#include "strv.h"
#include "tests.h"

static struct ether_addr mac_addr = {
        .ether_addr_octet = { 0x78, 0x2b, 0xcb, 0xb3, 0x6d, 0x53 }
};

static uint8_t advertisement[] = {
        /* ICMPv6 Router Advertisement, no checksum */
        0x86, 0x00, 0x00, 0x00,  0x40, 0xc0, 0x00, 0xb4,
        0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
        /* Source Link Layer Address Option */
        0x01, 0x01, 0x78, 0x2b,  0xcb, 0xb3, 0x6d, 0x53,
        /* Prefix Information Option */
        0x03, 0x04, 0x40, 0xc0,  0x00, 0x00, 0x01, 0xf4,
        0x00, 0x00, 0x01, 0xb8,  0x00, 0x00, 0x00, 0x00,
        0x20, 0x01, 0x0d, 0xb8,  0xde, 0xad, 0xbe, 0xef,
        0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
        /* Prefix Information Option */
        0x03, 0x04, 0x40, 0xc0,  0x00, 0x27, 0x8d, 0x00,
        0x00, 0x09, 0x3a, 0x80,  0x00, 0x00, 0x00, 0x00,
        0x20, 0x01, 0x0d, 0xb8,  0x0b, 0x16, 0xd0, 0x0d,
        0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
        /* Prefix Information Option */
        0x03, 0x04, 0x30, 0xc0,  0x00, 0x27, 0x8d, 0x00,
        0x00, 0x09, 0x3a, 0x80,  0x00, 0x00, 0x00, 0x00,
        0x20, 0x01, 0x0d, 0xb8,  0xc0, 0x01, 0x0d, 0xad,
        0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
        /* Recursive DNS Server Option */
        0x19, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c,
        0x20, 0x01, 0x0d, 0xb8, 0xde, 0xad, 0xbe, 0xef,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        /* DNS Search List Option */
        0x1f, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c,
        0x03, 0x6c, 0x61, 0x62, 0x05, 0x69, 0x6e, 0x74,
        0x72, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static sd_event_source *test_hangcheck;
static bool test_stopped;
static int test_fd[2];
static sd_event_source *recv_router_advertisement;
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

static int test_rs_hangcheck(sd_event_source *s, uint64_t usec,
                             void *userdata) {
        assert_se(false);

        return 0;
}

static void test_radv_prefix(void) {
        sd_radv_prefix *p;

        printf("* %s\n", __FUNCTION__);

        assert_se(sd_radv_prefix_new(&p) >= 0);

        assert_se(sd_radv_prefix_set_onlink(NULL, true) < 0);
        assert_se(sd_radv_prefix_set_onlink(p, true) >= 0);
        assert_se(sd_radv_prefix_set_onlink(p, false) >= 0);

        assert_se(sd_radv_prefix_set_address_autoconfiguration(NULL, true) < 0);
        assert_se(sd_radv_prefix_set_address_autoconfiguration(p, true) >= 0);
        assert_se(sd_radv_prefix_set_address_autoconfiguration(p, false) >= 0);

        assert_se(sd_radv_prefix_set_valid_lifetime(NULL, true) < 0);
        assert_se(sd_radv_prefix_set_valid_lifetime(p, ~0) >= 0);
        assert_se(sd_radv_prefix_set_valid_lifetime(p, 42) >= 0);
        assert_se(sd_radv_prefix_set_valid_lifetime(p, 0) >= 0);

        assert_se(sd_radv_prefix_set_preferred_lifetime(NULL, true) < 0);
        assert_se(sd_radv_prefix_set_preferred_lifetime(p, ~0) >= 0);
        assert_se(sd_radv_prefix_set_preferred_lifetime(p, 42) >= 0);
        assert_se(sd_radv_prefix_set_preferred_lifetime(p, 0) >= 0);

        assert_se(sd_radv_prefix_set_prefix(NULL, NULL, 0) < 0);
        assert_se(sd_radv_prefix_set_prefix(p, NULL, 0) < 0);

        assert_se(sd_radv_prefix_set_prefix(p, &prefix[0].address, 64) >= 0);
        assert_se(sd_radv_prefix_set_prefix(p, &prefix[0].address, 0) < 0);
        assert_se(sd_radv_prefix_set_prefix(p, &prefix[0].address, 1) < 0);
        assert_se(sd_radv_prefix_set_prefix(p, &prefix[0].address, 2) < 0);
        assert_se(sd_radv_prefix_set_prefix(p, &prefix[0].address, 3) >= 0);
        assert_se(sd_radv_prefix_set_prefix(p, &prefix[0].address, 125) >= 0);
        assert_se(sd_radv_prefix_set_prefix(p, &prefix[0].address, 128) >= 0);
        assert_se(sd_radv_prefix_set_prefix(p, &prefix[0].address, 129) < 0);
        assert_se(sd_radv_prefix_set_prefix(p, &prefix[0].address, 255) < 0);

        p = sd_radv_prefix_unref(p);
        assert_se(!p);
}

static void test_radv(void) {
        sd_radv *ra;

        printf("* %s\n", __FUNCTION__);

        assert_se(sd_radv_new(&ra) >= 0);
        assert_se(ra);

        assert_se(sd_radv_set_ifindex(NULL, 0) < 0);
        assert_se(sd_radv_set_ifindex(ra, 0) >= 0);
        assert_se(sd_radv_set_ifindex(ra, -1) >= 0);
        assert_se(sd_radv_set_ifindex(ra, -2) < 0);
        assert_se(sd_radv_set_ifindex(ra, 42) >= 0);

        assert_se(sd_radv_set_mac(NULL, NULL) < 0);
        assert_se(sd_radv_set_mac(ra, NULL) >= 0);
        assert_se(sd_radv_set_mac(ra, &mac_addr) >= 0);

        assert_se(sd_radv_set_mtu(NULL, 0) < 0);
        assert_se(sd_radv_set_mtu(ra, 0) < 0);
        assert_se(sd_radv_set_mtu(ra, 1279) < 0);
        assert_se(sd_radv_set_mtu(ra, 1280) >= 0);
        assert_se(sd_radv_set_mtu(ra, ~0) >= 0);

        assert_se(sd_radv_set_hop_limit(NULL, 0) < 0);
        assert_se(sd_radv_set_hop_limit(ra, 0) >= 0);
        assert_se(sd_radv_set_hop_limit(ra, ~0) >= 0);

        assert_se(sd_radv_set_router_lifetime(NULL, 0) < 0);
        assert_se(sd_radv_set_router_lifetime(ra, 0) >= 0);
        assert_se(sd_radv_set_router_lifetime(ra, ~0) >= 0);

        assert_se(sd_radv_set_preference(NULL, 0) < 0);
        assert_se(sd_radv_set_preference(ra, SD_NDISC_PREFERENCE_LOW) >= 0);
        assert_se(sd_radv_set_preference(ra, SD_NDISC_PREFERENCE_MEDIUM) >= 0);
        assert_se(sd_radv_set_preference(ra, SD_NDISC_PREFERENCE_HIGH) >= 0);
        assert_se(sd_radv_set_preference(ra, ~0) < 0);

        assert_se(sd_radv_set_preference(ra, SD_NDISC_PREFERENCE_HIGH) >= 0);
        assert_se(sd_radv_set_router_lifetime(ra, 42000) >= 0);
        assert_se(sd_radv_set_router_lifetime(ra, 0) < 0);
        assert_se(sd_radv_set_preference(ra, SD_NDISC_PREFERENCE_MEDIUM) >= 0);
        assert_se(sd_radv_set_router_lifetime(ra, 0) >= 0);

        assert_se(sd_radv_set_managed_information(NULL, true) < 0);
        assert_se(sd_radv_set_managed_information(ra, true) >= 0);
        assert_se(sd_radv_set_managed_information(ra, false) >= 0);

        assert_se(sd_radv_set_other_information(NULL, true) < 0);
        assert_se(sd_radv_set_other_information(ra, true) >= 0);
        assert_se(sd_radv_set_other_information(ra, false) >= 0);

        assert_se(sd_radv_set_rdnss(NULL, 0, NULL, 0) < 0);
        assert_se(sd_radv_set_rdnss(ra, 0, NULL, 0) >= 0);
        assert_se(sd_radv_set_rdnss(ra, 0, NULL, 128) < 0);
        assert_se(sd_radv_set_rdnss(ra, 600, &test_rdnss, 0) >= 0);
        assert_se(sd_radv_set_rdnss(ra, 600, &test_rdnss, 1) >= 0);
        assert_se(sd_radv_set_rdnss(ra, 0, &test_rdnss, 1) >= 0);
        assert_se(sd_radv_set_rdnss(ra, 0, NULL, 0) >= 0);

        assert_se(sd_radv_set_dnssl(ra, 0, NULL) >= 0);
        assert_se(sd_radv_set_dnssl(ra, 600, NULL) >= 0);
        assert_se(sd_radv_set_dnssl(ra, 0, (char **)test_dnssl) >= 0);
        assert_se(sd_radv_set_dnssl(ra, 600, (char **)test_dnssl) >= 0);

        ra = sd_radv_unref(ra);
        assert_se(!ra);
}

int icmp6_bind_router_solicitation(int index) {
        return -ENOSYS;
}

int icmp6_bind_router_advertisement(int index) {
        assert_se(index == 42);

        return test_fd[1];
}

int icmp6_send_router_solicitation(int s, const struct ether_addr *ether_addr) {

        return 0;
}

int icmp6_receive(int fd, void *iov_base, size_t iov_len,
                  struct in6_addr *dst, triple_timestamp *timestamp) {
        assert_se(read (fd, iov_base, iov_len) == (ssize_t)iov_len);

        if (timestamp)
                triple_timestamp_get(timestamp);

        return 0;
}

static int radv_recv(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        sd_radv *ra = userdata;
        unsigned char buf[168];
        size_t i;

        assert_se(read(test_fd[0], &buf, sizeof(buf)) == sizeof(buf));

        /* router lifetime must be zero when test is stopped */
        if (test_stopped) {
                advertisement[6] = 0x00;
                advertisement[7] = 0x00;
        }

        printf ("Received Router Advertisement with lifetime %u\n",
                (advertisement[6] << 8) + advertisement[7]);

        /* test only up to buf size, rest is not yet implemented */
        for (i = 0; i < sizeof(buf); i++) {
                if (!(i % 8))
                        printf("%3zd: ", i);

                printf("0x%02x", buf[i]);

                assert_se(buf[i] == advertisement[i]);

                if ((i + 1) % 8)
                        printf(", ");
                else
                        printf("\n");
        }

        if (test_stopped) {
                sd_event *e;

                e = sd_radv_get_event(ra);
                sd_event_exit(e, 0);

                return 0;
        }

        assert_se(sd_radv_stop(ra) >= 0);
        test_stopped = true;

        return 0;
}

static void test_ra(void) {
        sd_event *e;
        sd_radv *ra;
        usec_t time_now = now(clock_boottime_or_monotonic());
        unsigned i;

        printf("* %s\n", __FUNCTION__);

        assert_se(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, test_fd) >= 0);

        assert_se(sd_event_new(&e) >= 0);

        assert_se(sd_radv_new(&ra) >= 0);
        assert_se(ra);

        assert_se(sd_radv_attach_event(ra, e, 0) >= 0);

        assert_se(sd_radv_set_ifindex(ra, 42) >= 0);
        assert_se(sd_radv_set_mac(ra, &mac_addr) >= 0);
        assert_se(sd_radv_set_router_lifetime(ra, 180) >= 0);
        assert_se(sd_radv_set_hop_limit(ra, 64) >= 0);
        assert_se(sd_radv_set_managed_information(ra, true) >= 0);
        assert_se(sd_radv_set_other_information(ra, true) >= 0);
        assert_se(sd_radv_set_rdnss(ra, 60, &test_rdnss, 1) >= 0);
        assert_se(sd_radv_set_dnssl(ra, 60, (char **)test_dnssl) >= 0);

        for (i = 0; i < ELEMENTSOF(prefix); i++) {
                sd_radv_prefix *p;

                printf("Test prefix %u\n", i);
                assert_se(sd_radv_prefix_new(&p) >= 0);

                assert_se(sd_radv_prefix_set_prefix(p, &prefix[i].address,
                                                    prefix[i].prefixlen) >= 0);
                if (prefix[i].valid)
                        assert_se(sd_radv_prefix_set_valid_lifetime(p, prefix[i].valid) >= 0);
                if (prefix[i].preferred)
                        assert_se(sd_radv_prefix_set_preferred_lifetime(p, prefix[i].preferred) >= 0);

                assert_se((sd_radv_add_prefix(ra, p, false) >= 0) == prefix[i].successful);
                assert_se(sd_radv_add_prefix(ra, p, false) < 0);

                p = sd_radv_prefix_unref(p);
                assert_se(!p);
        }

        assert_se(sd_event_add_io(e, &recv_router_advertisement, test_fd[0],
                                  EPOLLIN, radv_recv, ra) >= 0);

        assert_se(sd_event_add_time(e, &test_hangcheck, clock_boottime_or_monotonic(),
                                 time_now + 2 *USEC_PER_SEC, 0,
                                 test_rs_hangcheck, NULL) >= 0);

        assert_se(sd_radv_start(ra) >= 0);

        sd_event_loop(e);

        test_hangcheck = sd_event_source_unref(test_hangcheck);

        ra = sd_radv_unref(ra);
        assert_se(!ra);

        close(test_fd[0]);

        sd_event_unref(e);
}

int main(int argc, char *argv[]) {

        test_setup_logging(LOG_DEBUG);

        test_radv_prefix();
        test_radv();
        test_ra();

        printf("* done\n");
        return 0;
}
