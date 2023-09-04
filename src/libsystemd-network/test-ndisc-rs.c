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
#include "icmp6-util.h"
#include "socket-util.h"
#include "strv.h"
#include "ndisc-internal.h"
#include "tests.h"

static struct ether_addr mac_addr = {
        .ether_addr_octet = {'A', 'B', 'C', '1', '2', '3'}
};

static bool verbose = false;
static int test_fd[2];
static sd_ndisc *test_timeout_nd;

typedef int (*send_ra_t)(uint8_t flags);
static send_ra_t send_ra_function;

static void router_dump(sd_ndisc_router *rt) {
        struct in6_addr addr;
        uint8_t hop_limit;
        uint64_t t, flags;
        uint32_t mtu;
        uint16_t lifetime;
        unsigned preference;
        int r;

        assert_se(rt);

        log_info("--");
        assert_se(sd_ndisc_router_get_address(rt, &addr) >= 0);
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
        log_info("Lifetime: %" PRIu16, lifetime);

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
                        const void *p;
                        size_t n;

                        assert_se(sd_ndisc_router_option_get_raw(rt, &p, &n) >= 0);
                        assert_se(n > 2);
                        assert_se(c = hexmem((uint8_t*) p + 2, n - 2));

                        log_info("Address: %s", c);
                        break;
                }

                case SD_NDISC_OPTION_PREFIX_INFORMATION: {
                        uint32_t lifetime_valid, lifetime_preferred;
                        unsigned prefix_len;
                        uint8_t pfl;
                        struct in6_addr a;

                        assert_se(sd_ndisc_router_prefix_get_valid_lifetime(rt, &lifetime_valid) >= 0);
                        log_info("Valid Lifetime: %" PRIu32, lifetime_valid);

                        assert_se(sd_ndisc_router_prefix_get_preferred_lifetime(rt, &lifetime_preferred) >= 0);
                        log_info("Preferred Lifetime: %" PRIu32, lifetime_preferred);

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
                        uint32_t lt;
                        int n, i;

                        n = sd_ndisc_router_rdnss_get_addresses(rt, &a);
                        assert_se(n > 0);

                        for (i = 0; i < n; i++)
                                log_info("DNS: %s", IN6_ADDR_TO_STRING(a + i));

                        assert_se(sd_ndisc_router_rdnss_get_lifetime(rt, &lt) >= 0);
                        log_info("Lifetime: %" PRIu32, lt);
                        break;
                }

                case SD_NDISC_OPTION_DNSSL: {
                        _cleanup_strv_free_ char **l = NULL;
                        uint32_t lt;
                        int n, i;

                        n = sd_ndisc_router_dnssl_get_domains(rt, &l);
                        assert_se(n > 0);

                        for (i = 0; i < n; i++)
                                log_info("Domain: %s", l[i]);

                        assert_se(sd_ndisc_router_dnssl_get_lifetime(rt, &lt) >= 0);
                        log_info("Lifetime: %" PRIu32, lt);
                        break;
                }}

                r = sd_ndisc_router_option_next(rt);
        }
}

int icmp6_bind_router_solicitation(int ifindex) {
        assert_se(ifindex == 42);

        if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, test_fd) < 0)
                return -errno;

        return test_fd[0];
}

int icmp6_bind_router_advertisement(int ifindex) {
        return -ENOSYS;
}

static struct in6_addr dummy_link_local = {
        .s6_addr = {
                0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x12, 0x34, 0x56, 0xff, 0xfe, 0x78, 0x9a, 0xbc,
        },
};

int icmp6_receive(
                int fd,
                void *iov_base,
                size_t iov_len,
                struct in6_addr *ret_sender,
                triple_timestamp *ret_timestamp) {

        assert_se(read (fd, iov_base, iov_len) == (ssize_t)iov_len);

        if (ret_timestamp)
                triple_timestamp_get(ret_timestamp);

        if (ret_sender)
                *ret_sender = dummy_link_local;

        return 0;
}

static int send_ra(uint8_t flags) {
        uint8_t advertisement[] = {
                0x86, 0x00, 0xde, 0x83, 0x40, 0xc0, 0x00, 0xb4,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x03, 0x04, 0x40, 0xc0, 0x00, 0x00, 0x01, 0xf4,
                0x00, 0x00, 0x01, 0xb8, 0x00, 0x00, 0x00, 0x00,
                0x20, 0x01, 0x0d, 0xb8, 0xde, 0xad, 0xbe, 0xef,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x19, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c,
                0x20, 0x01, 0x0d, 0xb8, 0xde, 0xad, 0xbe, 0xef,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                0x1f, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c,
                0x03, 0x6c, 0x61, 0x62, 0x05, 0x69, 0x6e, 0x74,
                0x72, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x01, 0x01, 0x78, 0x2b, 0xcb, 0xb3, 0x6d, 0x53,
        };

        advertisement[5] = flags;

        assert_se(write(test_fd[1], advertisement, sizeof(advertisement)) ==
                  sizeof(advertisement));

        if (verbose)
                printf("  sent RA with flag 0x%02x\n", flags);

        return 0;
}

int icmp6_send_router_solicitation(int s, const struct ether_addr *ether_addr) {
        if (!send_ra_function)
                return 0;

        return send_ra_function(0);
}

static void test_callback(sd_ndisc *nd, sd_ndisc_event_t event, sd_ndisc_router *rt, void *userdata) {
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

        sd_event_exit(e, 0);
}

TEST(rs) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_ndisc_unrefp) sd_ndisc *nd = NULL;

        send_ra_function = send_ra;

        assert_se(sd_event_new(&e) >= 0);

        assert_se(sd_ndisc_new(&nd) >= 0);
        assert_se(nd);

        assert_se(sd_ndisc_attach_event(nd, e, 0) >= 0);

        assert_se(sd_ndisc_set_ifindex(nd, 42) >= 0);
        assert_se(sd_ndisc_set_mac(nd, &mac_addr) >= 0);
        assert_se(sd_ndisc_set_callback(nd, test_callback, e) >= 0);

        assert_se(sd_event_add_time_relative(e, NULL, CLOCK_BOOTTIME,
                                             30 * USEC_PER_SEC, 0,
                                             NULL, INT_TO_PTR(-ETIMEDOUT)) >= 0);

        assert_se(sd_ndisc_stop(nd) >= 0);
        assert_se(sd_ndisc_start(nd) >= 0);
        assert_se(sd_ndisc_start(nd) >= 0);
        assert_se(sd_ndisc_stop(nd) >= 0);
        test_fd[1] = safe_close(test_fd[1]);

        assert_se(sd_ndisc_start(nd) >= 0);

        assert_se(sd_event_loop(e) >= 0);

        test_fd[1] = safe_close(test_fd[1]);
}

static int test_timeout_value(uint8_t flags) {
        static int count = 0;
        static usec_t last = 0;
        sd_ndisc *nd = test_timeout_nd;
        usec_t min, max;

        assert_se(nd);
        assert_se(nd->event);

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
        _cleanup_(sd_ndisc_unrefp) sd_ndisc *nd = NULL;

        send_ra_function = test_timeout_value;

        assert_se(sd_event_new(&e) >= 0);

        assert_se(sd_ndisc_new(&nd) >= 0);
        assert_se(nd);

        test_timeout_nd = nd;

        assert_se(sd_ndisc_attach_event(nd, e, 0) >= 0);

        assert_se(sd_ndisc_set_ifindex(nd, 42) >= 0);
        assert_se(sd_ndisc_set_mac(nd, &mac_addr) >= 0);

        assert_se(sd_event_add_time_relative(e, NULL, CLOCK_BOOTTIME,
                                             30 * USEC_PER_SEC, 0,
                                             NULL, INT_TO_PTR(-ETIMEDOUT)) >= 0);

        assert_se(sd_ndisc_start(nd) >= 0);

        assert_se(sd_event_loop(e) >= 0);

        test_fd[1] = safe_close(test_fd[1]);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
