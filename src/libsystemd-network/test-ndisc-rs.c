/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  Copyright © 2014 Intel Corporation. All rights reserved.
***/

#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "sd-ndisc.h"

#include "alloc-util.h"
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
static sd_event_source *test_hangcheck;
static int test_fd[2];
static sd_ndisc *test_timeout_nd;

typedef int (*send_ra_t)(uint8_t flags);
static send_ra_t send_ra_function;

static void router_dump(sd_ndisc_router *rt) {
        struct in6_addr addr;
        char buf[FORMAT_TIMESTAMP_MAX];
        uint8_t hop_limit;
        uint64_t t, flags;
        uint32_t mtu;
        uint16_t lifetime;
        unsigned preference;
        int r;

        assert_se(rt);

        log_info("--");
        assert_se(sd_ndisc_router_get_address(rt, &addr) == -ENODATA);

        assert_se(sd_ndisc_router_get_timestamp(rt, CLOCK_REALTIME, &t) >= 0);
        log_info("Timestamp: %s", format_timestamp(buf, sizeof(buf), t));

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
                        char buff[INET6_ADDRSTRLEN];

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
                        log_info("Prefix: %s", inet_ntop(AF_INET6, &a, buff, sizeof(buff)));

                        break;
                }

                case SD_NDISC_OPTION_RDNSS: {
                        const struct in6_addr *a;
                        uint32_t lt;
                        int n, i;

                        n = sd_ndisc_router_rdnss_get_addresses(rt, &a);
                        assert_se(n > 0);

                        for (i = 0; i < n; i++) {
                                char buff[INET6_ADDRSTRLEN];
                                log_info("DNS: %s", inet_ntop(AF_INET6, a + i, buff, sizeof(buff)));
                        }

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

static int test_rs_hangcheck(sd_event_source *s, uint64_t usec,
                             void *userdata) {
        assert_se(false);

        return 0;
}

int icmp6_bind_router_solicitation(int index) {
        assert_se(index == 42);

        if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, test_fd) < 0)
                return -errno;

        return test_fd[0];
}

int icmp6_bind_router_advertisement(int index) {

        return -ENOSYS;
}

int icmp6_receive(int fd, void *iov_base, size_t iov_len,
                  struct in6_addr *dst, triple_timestamp *timestamp) {
        assert_se(read (fd, iov_base, iov_len) == (ssize_t)iov_len);

        if (timestamp)
                triple_timestamp_get(timestamp);

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

static void test_callback(sd_ndisc *nd, sd_ndisc_event event, sd_ndisc_router *rt, void *userdata) {
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
        uint32_t mtu;

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

        assert_se(sd_ndisc_get_mtu(nd, &mtu) == -ENODATA);

        sd_event_exit(e, 0);
}

static void test_rs(void) {
        sd_event *e;
        sd_ndisc *nd;
        usec_t time_now = now(clock_boottime_or_monotonic());

        if (verbose)
                printf("* %s\n", __FUNCTION__);

        send_ra_function = send_ra;

        assert_se(sd_event_new(&e) >= 0);

        assert_se(sd_ndisc_new(&nd) >= 0);
        assert_se(nd);

        assert_se(sd_ndisc_attach_event(nd, e, 0) >= 0);

        assert_se(sd_ndisc_set_ifindex(nd, 42) >= 0);
        assert_se(sd_ndisc_set_mac(nd, &mac_addr) >= 0);
        assert_se(sd_ndisc_set_callback(nd, test_callback, e) >= 0);

        assert_se(sd_event_add_time(e, &test_hangcheck, clock_boottime_or_monotonic(),
                                 time_now + 2 *USEC_PER_SEC, 0,
                                 test_rs_hangcheck, NULL) >= 0);

        assert_se(sd_ndisc_stop(nd) >= 0);
        assert_se(sd_ndisc_start(nd) >= 0);
        assert_se(sd_ndisc_stop(nd) >= 0);

        assert_se(sd_ndisc_start(nd) >= 0);

        sd_event_loop(e);

        test_hangcheck = sd_event_source_unref(test_hangcheck);

        nd = sd_ndisc_unref(nd);
        assert_se(!nd);

        close(test_fd[1]);

        sd_event_unref(e);
}

static int test_timeout_value(uint8_t flags) {
        static int count = 0;
        static usec_t last = 0;
        sd_ndisc *nd = test_timeout_nd;
        usec_t min, max;
        char time_string_min[FORMAT_TIMESPAN_MAX];
        char time_string_nd[FORMAT_TIMESPAN_MAX];
        char time_string_max[FORMAT_TIMESPAN_MAX];

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

        format_timespan(time_string_min, FORMAT_TIMESPAN_MAX,
                        min, USEC_PER_MSEC);
        format_timespan(time_string_nd, FORMAT_TIMESPAN_MAX,
                        nd->retransmit_time, USEC_PER_MSEC);
        format_timespan(time_string_max, FORMAT_TIMESPAN_MAX,
                        max, USEC_PER_MSEC);

        log_info("backoff timeout interval %2d %s%s <= %s <= %s",
                 count,
                 (last * 2 > NDISC_MAX_ROUTER_SOLICITATION_INTERVAL)? "(max) ": "",
                 time_string_min, time_string_nd, time_string_max);

        assert_se(min <= nd->retransmit_time);
        assert_se(max >= nd->retransmit_time);

        last = nd->retransmit_time;

        assert_se(sd_event_source_set_time(nd->timeout_event_source, 0) >= 0);

        return 0;
}

static void test_timeout(void) {
        sd_event *e;
        sd_ndisc *nd;
        usec_t time_now = now(clock_boottime_or_monotonic());

        if (verbose)
                printf("* %s\n", __FUNCTION__);

        send_ra_function = test_timeout_value;

        assert_se(sd_event_new(&e) >= 0);

        assert_se(sd_ndisc_new(&nd) >= 0);
        assert_se(nd);

        test_timeout_nd = nd;

        assert_se(sd_ndisc_attach_event(nd, e, 0) >= 0);

        assert_se(sd_ndisc_set_ifindex(nd, 42) >= 0);
        assert_se(sd_ndisc_set_mac(nd, &mac_addr) >= 0);

        assert_se(sd_event_add_time(e, &test_hangcheck, clock_boottime_or_monotonic(),
                                 time_now + 2U * USEC_PER_SEC, 0,
                                 test_rs_hangcheck, NULL) >= 0);

        assert_se(sd_ndisc_start(nd) >= 0);

        sd_event_loop(e);

        test_hangcheck = sd_event_source_unref(test_hangcheck);

        nd = sd_ndisc_unref(nd);

        sd_event_unref(e);
}

int main(int argc, char *argv[]) {

        test_setup_logging(LOG_DEBUG);

        test_rs();
        test_timeout();

        return 0;
}
