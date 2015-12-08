/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright (C) 2014 Intel Corporation. All rights reserved.

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <netinet/icmp6.h>

#include "sd-ndisc.h"

#include "icmp6-util.h"
#include "socket-util.h"

static struct ether_addr mac_addr = {
        .ether_addr_octet = {'A', 'B', 'C', '1', '2', '3'}
};

static bool verbose = false;
static sd_event_source *test_hangcheck;
static int test_fd[2];

typedef int (*send_ra_t)(uint8_t flags);
static send_ra_t send_ra_function;

static int test_rs_hangcheck(sd_event_source *s, uint64_t usec,
                             void *userdata) {
        assert_se(false);

        return 0;
}

int icmp6_bind_router_solicitation(int index) {
        assert_se(index == 42);

        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, test_fd) < 0)
                return -errno;

        return test_fd[0];
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
        return send_ra_function(0);
}

static void test_rs_done(sd_ndisc *nd, uint8_t flags, const struct in6_addr *gateway, unsigned lifetime, int pref, void *userdata) {
        sd_event *e = userdata;
        static unsigned idx = 0;
        uint8_t flags_array[] = {
                0,
                0,
                0,
                ND_RA_FLAG_OTHER,
                ND_RA_FLAG_MANAGED
        };
        uint32_t mtu;

        assert_se(nd);

        assert_se(flags == flags_array[idx]);
        idx++;

        if (verbose)
                printf("  got event 0x%02x\n", flags);

        if (idx < ELEMENTSOF(flags_array)) {
                send_ra(flags_array[idx]);
                return;
        }

        assert_se(sd_ndisc_get_mtu(nd, &mtu) == -ENOMSG);

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

        assert_se(sd_ndisc_set_index(nd, 42) >= 0);
        assert_se(sd_ndisc_set_mac(nd, &mac_addr) >= 0);
        assert_se(sd_ndisc_set_callback(nd, test_rs_done, NULL, NULL, NULL, e) >= 0);

        assert_se(sd_event_add_time(e, &test_hangcheck, clock_boottime_or_monotonic(),
                                 time_now + 2 *USEC_PER_SEC, 0,
                                 test_rs_hangcheck, NULL) >= 0);

        assert_se(sd_ndisc_stop(nd) >= 0);
        assert_se(sd_ndisc_router_discovery_start(nd) >= 0);
        assert_se(sd_ndisc_stop(nd) >= 0);

        assert_se(sd_ndisc_router_discovery_start(nd) >= 0);

        sd_event_loop(e);

        test_hangcheck = sd_event_source_unref(test_hangcheck);

        nd = sd_ndisc_unref(nd);
        assert_se(!nd);

        close(test_fd[1]);

        sd_event_unref(e);
}

int main(int argc, char *argv[]) {

        log_set_max_level(LOG_DEBUG);
        log_parse_environment();
        log_open();

        test_rs();

        return 0;
}
