/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2014 Intel Corporation. All rights reserved.
***/

#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "sd-ndisc.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "hexdecoct.h"
#include "icmp6-packet.h"
#include "icmp6-test-util.h"
#include "socket-util.h"
#include "strv.h"
#include "ndisc-internal.h"
#include "tests.h"

static struct ether_addr mac_addr = {
        .ether_addr_octet = {'A', 'B', 'C', '1', '2', '3'}
};

static bool verbose = false;

static void router_dump(sd_ndisc_router *rt) {
        struct in6_addr addr;
        uint8_t hop_limit;
        usec_t t, lifetime, retrans_time;
        uint64_t flags;
        uint32_t mtu;
        uint8_t preference;
        int r;

        assert_se(rt);

        log_info("--");
        assert_se(sd_ndisc_router_get_sender_address(rt, &addr) >= 0);
        log_info("Sender: %s", IN6_ADDR_TO_STRING(&addr));

        assert_se(sd_ndisc_router_get_timestamp(rt, CLOCK_REALTIME, &t) >= 0);
        log_info("Timestamp: %s", FORMAT_TIMESTAMP(t));

        assert_se(sd_ndisc_router_get_timestamp(rt, CLOCK_MONOTONIC, &t) >= 0);
        log_info("Monotonic: %" PRIu64, t);

        if (sd_ndisc_router_get_hop_limit(rt, &hop_limit) < 0)
                log_info("No hop limit set");
        else
                log_info("Hop limit: %u", hop_limit);

        assert_se(sd_ndisc_router_get_flags(rt, &flags) >= 0);
        log_info("Flags: <%s|%s>",
                 flags & ND_RA_FLAG_OTHER ? "OTHER" : "",
                 flags & ND_RA_FLAG_MANAGED ? "MANAGED" : "");

        assert_se(sd_ndisc_router_get_preference(rt, &preference) >= 0);
        log_info("Preference: %s",
                 preference == SD_NDISC_PREFERENCE_LOW ? "low" :
                 preference == SD_NDISC_PREFERENCE_HIGH ? "high" : "medium");

        assert_se(sd_ndisc_router_get_lifetime(rt, &lifetime) >= 0);
        assert_se(sd_ndisc_router_get_lifetime_timestamp(rt, CLOCK_REALTIME, &t) >= 0);
        log_info("Lifetime: %s (%s)", FORMAT_TIMESPAN(lifetime, USEC_PER_SEC), FORMAT_TIMESTAMP(t));

        assert_se(sd_ndisc_router_get_retransmission_time(rt, &retrans_time) >= 0);
        log_info("Retransmission Time: %s", FORMAT_TIMESPAN(retrans_time, USEC_PER_SEC));

        if (sd_ndisc_router_get_mtu(rt, &mtu) < 0)
                log_info("No MTU set");
        else
                log_info("MTU: %" PRIu32, mtu);

        r = sd_ndisc_router_option_rewind(rt);
        for (;;) {
                uint8_t type;

                assert_se(r >= 0);

                if (r == 0)
                        break;

                assert_se(sd_ndisc_router_option_get_type(rt, &type) >= 0);

                log_info(">> Option %u", type);

                switch (type) {

                case SD_NDISC_OPTION_SOURCE_LL_ADDRESS:
                case SD_NDISC_OPTION_TARGET_LL_ADDRESS: {
                        _cleanup_free_ char *c = NULL;
                        const uint8_t *p;
                        size_t n;

                        assert_se(sd_ndisc_router_option_get_raw(rt, &p, &n) >= 0);
                        assert_se(n > 2);
                        assert_se(c = hexmem(p + 2, n - 2));

                        log_info("Address: %s", c);
                        break;
                }

                case SD_NDISC_OPTION_PREFIX_INFORMATION: {
                        uint8_t prefix_len, pfl;
                        struct in6_addr a;

                        assert_se(sd_ndisc_router_prefix_get_valid_lifetime(rt, &lifetime) >= 0);
                        assert_se(sd_ndisc_router_prefix_get_valid_lifetime_timestamp(rt, CLOCK_REALTIME, &t) >= 0);
                        log_info("Valid Lifetime: %s (%s)", FORMAT_TIMESPAN(lifetime, USEC_PER_SEC), FORMAT_TIMESTAMP(t));

                        assert_se(sd_ndisc_router_prefix_get_preferred_lifetime(rt, &lifetime) >= 0);
                        assert_se(sd_ndisc_router_prefix_get_preferred_lifetime_timestamp(rt, CLOCK_REALTIME, &t) >= 0);
                        log_info("Preferred Lifetime: %s (%s)", FORMAT_TIMESPAN(lifetime, USEC_PER_SEC), FORMAT_TIMESTAMP(t));

                        assert_se(sd_ndisc_router_prefix_get_flags(rt, &pfl) >= 0);
                        log_info("Flags: <%s|%s>",
                                 pfl & ND_OPT_PI_FLAG_ONLINK ? "ONLINK" : "",
                                 pfl & ND_OPT_PI_FLAG_AUTO ? "AUTO" : "");

                        assert_se(sd_ndisc_router_prefix_get_prefixlen(rt, &prefix_len) >= 0);
                        log_info("Prefix Length: %u", prefix_len);

                        assert_se(sd_ndisc_router_prefix_get_address(rt, &a) >= 0);
                        log_info("Prefix: %s", IN6_ADDR_TO_STRING(&a));

                        break;
                }

                case SD_NDISC_OPTION_RDNSS: {
                        const struct in6_addr *a;
                        int n, i;

                        n = sd_ndisc_router_rdnss_get_addresses(rt, &a);
                        assert_se(n > 0);

                        for (i = 0; i < n; i++)
                                log_info("DNS: %s", IN6_ADDR_TO_STRING(a + i));

                        assert_se(sd_ndisc_router_rdnss_get_lifetime(rt, &lifetime) >= 0);
                        assert_se(sd_ndisc_router_rdnss_get_lifetime_timestamp(rt, CLOCK_REALTIME, &t) >= 0);
                        log_info("Lifetime: %s (%s)", FORMAT_TIMESPAN(lifetime, USEC_PER_SEC), FORMAT_TIMESTAMP(t));
                        break;
                }

                case SD_NDISC_OPTION_DNSSL: {
                        char **l;

                        assert_se(sd_ndisc_router_dnssl_get_domains(rt, &l) >= 0);

                        STRV_FOREACH(s, l)
                                log_info("Domain: %s", *s);

                        assert_se(sd_ndisc_router_dnssl_get_lifetime(rt, &lifetime) >= 0);
                        assert_se(sd_ndisc_router_dnssl_get_lifetime_timestamp(rt, CLOCK_REALTIME, &t) >= 0);
                        log_info("Lifetime: %s (%s)", FORMAT_TIMESPAN(lifetime, USEC_PER_SEC), FORMAT_TIMESTAMP(t));
                        break;
                }}

                r = sd_ndisc_router_option_next(rt);
        }
}

static int send_ra(uint8_t flags) {
        uint8_t advertisement[] = {
                /* struct nd_router_advert */
                0x86, 0x00, 0xde, 0x83, 0x40, 0xc0, 0x00, 0xb4,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                /* type = 0x03 (SD_NDISC_OPTION_PREFIX_INFORMATION), length = 32 */
                0x03, 0x04, 0x40, 0xc0, 0x00, 0x00, 0x01, 0xf4,
                0x00, 0x00, 0x01, 0xb8, 0x00, 0x00, 0x00, 0x00,
                0x20, 0x01, 0x0d, 0xb8, 0xde, 0xad, 0xbe, 0xef,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                /* type = 0x19 (SD_NDISC_OPTION_RDNSS), length = 24 */
                0x19, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c,
                0x20, 0x01, 0x0d, 0xb8, 0xde, 0xad, 0xbe, 0xef,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                /* type = 0x1f (SD_NDISC_OPTION_DNSSL), length = 24 */
                0x1f, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c,
                0x03, 0x6c, 0x61, 0x62, 0x05, 0x69, 0x6e, 0x74,
                0x72, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                /* type = 0x01 (SD_NDISC_OPTION_SOURCE_LL_ADDRESS), length = 8 */
                0x01, 0x01, 0x78, 0x2b, 0xcb, 0xb3, 0x6d, 0x53,
        };

        advertisement[5] = flags;

        assert_se(write(test_fd[1], advertisement, sizeof(advertisement)) ==
                  sizeof(advertisement));

        if (verbose)
                printf("  sent RA with flag 0x%02x\n", flags);

        return 0;
}

static void test_callback_ra(sd_ndisc *nd, sd_ndisc_event_t event, void *message, void *userdata) {
        sd_event *e = userdata;
        static unsigned idx = 0;
        uint64_t flags_array[] = {
                0,
                0,
                0,
                ND_RA_FLAG_OTHER,
                ND_RA_FLAG_MANAGED
        };
        uint64_t flags;

        assert_se(nd);

        if (event != SD_NDISC_EVENT_ROUTER)
                return;

        sd_ndisc_router *rt = ASSERT_PTR(message);

        router_dump(rt);

        assert_se(sd_ndisc_router_get_flags(rt, &flags) >= 0);
        assert_se(flags == flags_array[idx]);
        idx++;

        if (verbose)
                printf("  got event 0x%02" PRIx64 "\n", flags);

        if (idx < ELEMENTSOF(flags_array)) {
                send_ra(flags_array[idx]);
                return;
        }

        idx = 0;
        sd_event_exit(e, 0);
}

static int on_recv_rs(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        _cleanup_(icmp6_packet_unrefp) ICMP6Packet *packet = NULL;
        assert_se(icmp6_packet_receive(fd, &packet) >= 0);

        return send_ra(0);
}

TEST(rs) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        _cleanup_(sd_ndisc_unrefp) sd_ndisc *nd = NULL;

        assert_se(sd_event_new(&e) >= 0);

        assert_se(sd_ndisc_new(&nd) >= 0);
        assert_se(nd);

        assert_se(sd_ndisc_attach_event(nd, e, 0) >= 0);

        assert_se(sd_ndisc_set_ifindex(nd, 42) >= 0);
        assert_se(sd_ndisc_set_mac(nd, &mac_addr) >= 0);
        assert_se(sd_ndisc_set_callback(nd, test_callback_ra, e) >= 0);

        assert_se(sd_event_add_time_relative(e, NULL, CLOCK_BOOTTIME,
                                             30 * USEC_PER_SEC, 0,
                                             NULL, INT_TO_PTR(-ETIMEDOUT)) >= 0);

        assert_se(sd_ndisc_stop(nd) >= 0);
        assert_se(sd_ndisc_start(nd) >= 0);
        assert_se(sd_ndisc_start(nd) >= 0);
        assert_se(sd_ndisc_stop(nd) >= 0);
        test_fd[1] = safe_close(test_fd[1]);

        assert_se(sd_ndisc_start(nd) >= 0);

        assert_se(sd_event_add_io(e, &s, test_fd[1], EPOLLIN, on_recv_rs, nd) >= 0);
        assert_se(sd_event_source_set_io_fd_own(s, true) >= 0);

        assert_se(sd_event_loop(e) >= 0);

        test_fd[1] = -EBADF;
}

static int send_ra_invalid_domain(uint8_t flags) {
        uint8_t advertisement[] = {
                /* struct nd_router_advert */
                0x86, 0x00, 0xde, 0x83, 0x40, 0xc0, 0x00, 0xb4,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                /* type = 0x03 (SD_NDISC_OPTION_PREFIX_INFORMATION), length = 32 */
                0x03, 0x04, 0x40, 0xc0, 0x00, 0x00, 0x01, 0xf4,
                0x00, 0x00, 0x01, 0xb8, 0x00, 0x00, 0x00, 0x00,
                0x20, 0x01, 0x0d, 0xb8, 0xde, 0xad, 0xbe, 0xef,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                /* type = 0x19 (SD_NDISC_OPTION_RDNSS), length = 24 */
                0x19, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c,
                0x20, 0x01, 0x0d, 0xb8, 0xde, 0xad, 0xbe, 0xef,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                /* type = 0x1f (SD_NDISC_OPTION_DNSSL), length = 112 */
                0x1f, 0x0e, 0xee, 0x68, 0xb0, 0xf4, 0x36, 0x39,
                0x2c, 0xbc, 0x0b, 0xbc, 0xa9, 0x97, 0x71, 0x37,
                0xad, 0x86, 0x80, 0x14, 0x2e, 0x58, 0xaa, 0x8a,
                0xb7, 0xa1, 0xbe, 0x91, 0x59, 0x00, 0xc4, 0xe8,
                0xdd, 0xd8, 0x6d, 0xe5, 0x4a, 0x7a, 0x71, 0x42,
                0x74, 0x45, 0x9e, 0x2e, 0xfd, 0x9d, 0x71, 0x1d,
                0xd0, 0xc0, 0x54, 0x0c, 0x4d, 0x1f, 0xbf, 0x90,
                0xd9, 0x79, 0x58, 0xc0, 0x1d, 0xa3, 0x39, 0xcf,
                0xb8, 0xec, 0xd2, 0xe4, 0xcd, 0xb6, 0x13, 0x2f,
                0xc0, 0x46, 0xe8, 0x07, 0x3f, 0xaa, 0x28, 0xa5,
                0x23, 0xf1, 0xf0, 0xca, 0xd3, 0x19, 0x3f, 0xfa,
                0x6c, 0x7c, 0xec, 0x1b, 0xcf, 0x71, 0xeb, 0xba,
                0x68, 0x1b, 0x8e, 0x7d, 0x93, 0x7e, 0x0b, 0x9f,
                0xdb, 0x12, 0x9c, 0x75, 0x22, 0x5f, 0x12, 0x00,
                /* type = 0x01 (SD_NDISC_OPTION_SOURCE_LL_ADDRESS), length = 8 */
                0x01, 0x01, 0x78, 0x2b, 0xcb, 0xb3, 0x6d, 0x53,
        };

        advertisement[5] = flags;

        printf("sizeof(nd_router_advert)=%zu\n", sizeof(struct nd_router_advert));

        assert_se(write(test_fd[1], advertisement, sizeof(advertisement)) ==
                  sizeof(advertisement));

        if (verbose)
                printf("  sent RA with flag 0x%02x\n", flags);

        return 0;
}

static int on_recv_rs_invalid_domain(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        _cleanup_(icmp6_packet_unrefp) ICMP6Packet *packet = NULL;
        assert_se(icmp6_packet_receive(fd, &packet) >= 0);

        return send_ra_invalid_domain(0);
}

TEST(invalid_domain) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        _cleanup_(sd_ndisc_unrefp) sd_ndisc *nd = NULL;

        assert_se(sd_event_new(&e) >= 0);

        assert_se(sd_ndisc_new(&nd) >= 0);
        assert_se(nd);

        assert_se(sd_ndisc_attach_event(nd, e, 0) >= 0);

        assert_se(sd_ndisc_set_ifindex(nd, 42) >= 0);
        assert_se(sd_ndisc_set_mac(nd, &mac_addr) >= 0);
        assert_se(sd_ndisc_set_callback(nd, test_callback_ra, e) >= 0);

        assert_se(sd_event_add_time_relative(e, NULL, CLOCK_BOOTTIME,
                                             30 * USEC_PER_SEC, 0,
                                             NULL, INT_TO_PTR(-ETIMEDOUT)) >= 0);

        assert_se(sd_ndisc_start(nd) >= 0);

        assert_se(sd_event_add_io(e, &s, test_fd[1], EPOLLIN, on_recv_rs_invalid_domain, nd) >= 0);
        assert_se(sd_event_source_set_io_fd_own(s, true) >= 0);

        assert_se(sd_event_loop(e) >= 0);

        test_fd[1] = -EBADF;
}

static void neighbor_dump(sd_ndisc_neighbor *na) {
        struct in6_addr addr;
        uint32_t flags;

        assert_se(na);

        log_info("--");
        assert_se(sd_ndisc_neighbor_get_sender_address(na, &addr) >= 0);
        log_info("Sender: %s", IN6_ADDR_TO_STRING(&addr));

        assert_se(sd_ndisc_neighbor_get_flags(na, &flags) >= 0);
        log_info("Flags: Router:%s, Solicited:%s, Override: %s",
                 yes_no(flags & ND_NA_FLAG_ROUTER),
                 yes_no(flags & ND_NA_FLAG_SOLICITED),
                 yes_no(flags & ND_NA_FLAG_OVERRIDE));

        assert_se(sd_ndisc_neighbor_is_router(na) == FLAGS_SET(flags, ND_NA_FLAG_ROUTER));
        assert_se(sd_ndisc_neighbor_is_solicited(na) == FLAGS_SET(flags, ND_NA_FLAG_SOLICITED));
        assert_se(sd_ndisc_neighbor_is_override(na) == FLAGS_SET(flags, ND_NA_FLAG_OVERRIDE));
}

static int send_na(uint32_t flags) {
        uint8_t advertisement[] = {
                /* struct nd_neighbor_advert */
                0x88, 0x00, 0xde, 0x83, 0x00, 0x00, 0x00, 0x00,
                0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                /* type = 0x02 (SD_NDISC_OPTION_TARGET_LL_ADDRESS), length = 8 */
                0x01, 0x01, 'A', 'B', 'C', '1', '2', '3',
        };

        ((struct nd_neighbor_advert*) advertisement)->nd_na_flags_reserved = flags;

        assert_se(write(test_fd[1], advertisement, sizeof(advertisement)) == sizeof(advertisement));
        if (verbose)
                printf("  sent NA with flag 0x%02x\n", flags);

        return 0;
}

static void test_callback_na(sd_ndisc *nd, sd_ndisc_event_t event, void *message, void *userdata) {
        sd_event *e = userdata;
        static unsigned idx = 0;
        uint32_t flags_array[] = {
                0,
                0,
                ND_NA_FLAG_ROUTER,
                ND_NA_FLAG_SOLICITED,
                ND_NA_FLAG_SOLICITED | ND_NA_FLAG_OVERRIDE,
        };
        uint32_t flags;

        assert_se(nd);

        if (event != SD_NDISC_EVENT_NEIGHBOR)
                return;

        sd_ndisc_neighbor *rt = ASSERT_PTR(message);

        neighbor_dump(rt);

        assert_se(sd_ndisc_neighbor_get_flags(rt, &flags) >= 0);
        assert_se(flags == flags_array[idx]);
        idx++;

        if (verbose)
                printf("  got event 0x%02" PRIx32 "\n", flags);

        if (idx < ELEMENTSOF(flags_array)) {
                send_na(flags_array[idx]);
                return;
        }

        idx = 0;
        sd_event_exit(e, 0);
}

static int on_recv_rs_na(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        _cleanup_(icmp6_packet_unrefp) ICMP6Packet *packet = NULL;
        assert_se(icmp6_packet_receive(fd, &packet) >= 0);

        return send_na(0);
}

TEST(na) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        _cleanup_(sd_ndisc_unrefp) sd_ndisc *nd = NULL;

        assert_se(sd_event_new(&e) >= 0);

        assert_se(sd_ndisc_new(&nd) >= 0);
        assert_se(nd);

        assert_se(sd_ndisc_attach_event(nd, e, 0) >= 0);

        assert_se(sd_ndisc_set_ifindex(nd, 42) >= 0);
        assert_se(sd_ndisc_set_mac(nd, &mac_addr) >= 0);
        assert_se(sd_ndisc_set_callback(nd, test_callback_na, e) >= 0);

        assert_se(sd_event_add_time_relative(e, NULL, CLOCK_BOOTTIME,
                                             30 * USEC_PER_SEC, 0,
                                             NULL, INT_TO_PTR(-ETIMEDOUT)) >= 0);

        assert_se(sd_ndisc_start(nd) >= 0);

        assert_se(sd_event_add_io(e, &s, test_fd[1], EPOLLIN, on_recv_rs_na, nd) >= 0);
        assert_se(sd_event_source_set_io_fd_own(s, true) >= 0);

        assert_se(sd_event_loop(e) >= 0);

        test_fd[1] = -EBADF;
}

static int on_recv_rs_timeout(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        _cleanup_(icmp6_packet_unrefp) ICMP6Packet *packet = NULL;
        sd_ndisc *nd = ASSERT_PTR(userdata);
        static int count = 0;
        static usec_t last = 0;
        usec_t min, max;

        assert_se(icmp6_packet_receive(fd, &packet) >= 0);

        if (++count >= 20)
                sd_event_exit(nd->event, 0);

        if (last == 0) {
                /* initial RT = IRT + RAND*IRT  */
                min = NDISC_ROUTER_SOLICITATION_INTERVAL -
                        NDISC_ROUTER_SOLICITATION_INTERVAL / 10;
                max = NDISC_ROUTER_SOLICITATION_INTERVAL +
                        NDISC_ROUTER_SOLICITATION_INTERVAL / 10;
        } else {
                /* next RT = 2*RTprev + RAND*RTprev */
                min = 2 * last - last / 10;
                max = 2 * last + last / 10;
        }

        /* final RT > MRT */
        if (last * 2 > NDISC_MAX_ROUTER_SOLICITATION_INTERVAL) {
                min = NDISC_MAX_ROUTER_SOLICITATION_INTERVAL -
                        NDISC_MAX_ROUTER_SOLICITATION_INTERVAL / 10;
                max = NDISC_MAX_ROUTER_SOLICITATION_INTERVAL +
                        NDISC_MAX_ROUTER_SOLICITATION_INTERVAL / 10;
        }

        log_info("backoff timeout interval %2d %s%s <= %s <= %s",
                 count,
                 last * 2 > NDISC_MAX_ROUTER_SOLICITATION_INTERVAL ? "(max) ": "",
                 FORMAT_TIMESPAN(min, USEC_PER_MSEC),
                 FORMAT_TIMESPAN(nd->retransmit_time, USEC_PER_MSEC),
                 FORMAT_TIMESPAN(max, USEC_PER_MSEC));

        assert_se(min <= nd->retransmit_time);
        assert_se(max >= nd->retransmit_time);

        last = nd->retransmit_time;

        assert_se(sd_event_source_set_time(nd->timeout_event_source, 0) >= 0);

        return 0;
}

TEST(timeout) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        _cleanup_(sd_ndisc_unrefp) sd_ndisc *nd = NULL;

        assert_se(sd_event_new(&e) >= 0);

        assert_se(sd_ndisc_new(&nd) >= 0);
        assert_se(nd);

        assert_se(sd_ndisc_attach_event(nd, e, 0) >= 0);

        assert_se(sd_ndisc_set_ifindex(nd, 42) >= 0);
        assert_se(sd_ndisc_set_mac(nd, &mac_addr) >= 0);

        assert_se(sd_event_add_time_relative(e, NULL, CLOCK_BOOTTIME,
                                             30 * USEC_PER_SEC, 0,
                                             NULL, INT_TO_PTR(-ETIMEDOUT)) >= 0);

        assert_se(sd_ndisc_start(nd) >= 0);

        assert_se(sd_event_add_io(e, &s, test_fd[1], EPOLLIN, on_recv_rs_timeout, nd) >= 0);
        assert_se(sd_event_source_set_io_fd_own(s, true) >= 0);

        assert_se(sd_event_loop(e) >= 0);

        test_fd[1] = -EBADF;
}

DEFINE_TEST_MAIN(LOG_DEBUG);
