/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Some unit tests for the helper functions in timesyncd. */

#include <linux/ptp_clock.h>

#include "tests.h"
#include "timesyncd-conf.h"
#include "timesyncd-manager.h"
#include "timesyncd-phc.h"
#include "timesyncd-server.h"

TEST(manager_parse_string) {
        /* Make sure that NTP_SERVERS is configured to something
         * that we can actually parse successfully. */

        _cleanup_(manager_freep) Manager *m = NULL;

        ASSERT_OK_ZERO(manager_new(&m));

        ASSERT_FALSE(m->fallback_set);
        ASSERT_OK_ZERO(manager_parse_server_string(m, SERVER_FALLBACK, NTP_SERVERS));
        ASSERT_TRUE(m->fallback_set);
        ASSERT_OK_ZERO(manager_parse_fallback_string(m, NTP_SERVERS));

        ASSERT_OK_ZERO(manager_parse_server_string(m, SERVER_SYSTEM, "time1.foobar.com time2.foobar.com axrfav.,avf..ra 12345..123"));
        ASSERT_OK_ZERO(manager_parse_server_string(m, SERVER_FALLBACK, "time1.foobar.com time2.foobar.com axrfav.,avf..ra 12345..123"));
        ASSERT_OK_ZERO(manager_parse_server_string(m, SERVER_LINK, "time1.foobar.com time2.foobar.com axrfav.,avf..ra 12345..123"));
}

static int parse_phc(Manager *m, const char *rvalue) {
        return config_parse_phc(
                        /* unit= */ NULL,
                        "test.conf",
                        /* line= */ 1,
                        "Time",
                        /* section_line= */ 1,
                        "PHC",
                        /* ltype= */ 0,
                        rvalue,
                        /* data= */ NULL,
                        m);
}

TEST(phc_config) {
        _cleanup_(manager_freep) Manager *m = NULL;

        ASSERT_OK_ZERO(manager_new(&m));

        /* Default: use tagged devices */
        ASSERT_TRUE(m->phc_enabled);
        ASSERT_NULL(m->phc_device_match);

        ASSERT_OK_ZERO(parse_phc(m, "no"));
        ASSERT_FALSE(m->phc_enabled);
        ASSERT_NULL(m->phc_device_match);

        ASSERT_OK_ZERO(parse_phc(m, "/dev/ptp_kvm"));
        ASSERT_TRUE(m->phc_enabled);
        ASSERT_STREQ(m->phc_device_match, "/dev/ptp_kvm");

        /* Invalid paths are ignored, and leave the previous setting in place */
        ASSERT_OK_ZERO(parse_phc(m, "ptp0"));
        ASSERT_OK_ZERO(parse_phc(m, "/etc/passwd"));
        ASSERT_OK_ZERO(parse_phc(m, "/dev/../etc/passwd"));
        ASSERT_OK_ZERO(parse_phc(m, "/dev//ptp0"));
        ASSERT_OK_ZERO(parse_phc(m, "/dev"));
        ASSERT_OK_ZERO(parse_phc(m, "/dev/"));
        ASSERT_TRUE(m->phc_enabled);
        ASSERT_STREQ(m->phc_device_match, "/dev/ptp_kvm");

        ASSERT_OK_ZERO(parse_phc(m, "yes"));
        ASSERT_TRUE(m->phc_enabled);
        ASSERT_NULL(m->phc_device_match);

        ASSERT_OK_ZERO(parse_phc(m, "/dev/ptp1"));
        ASSERT_STREQ(m->phc_device_match, "/dev/ptp1");

        /* Empty string resets to the default */
        ASSERT_OK_ZERO(parse_phc(m, ""));
        ASSERT_TRUE(m->phc_enabled);
        ASSERT_NULL(m->phc_device_match);
}

static void set_ts(struct ptp_clock_time *t, int64_t sec, uint32_t nsec) {
        *t = (struct ptp_clock_time) {
                .sec = sec,
                .nsec = nsec,
        };
}

TEST(phc_pick_sample) {
        struct ptp_sys_offset s = {};
        int64_t offset, delay, device;

        /* No samples */
        ASSERT_ERROR(phc_pick_sample(&s, &offset, &delay, &device), EINVAL);

        s.n_samples = PTP_MAX_SAMPLES + 1;
        ASSERT_ERROR(phc_pick_sample(&s, &offset, &delay, &device), EINVAL);

        /* sys₀=1000.000000000, phc₀=1005.000001000, sys₁=1000.000004000 (delay 4µs)
         *                      phc₁=1005.000010500, sys₂=1000.000011000 (delay 7µs)
         *                      phc₂=1005.000013000, sys₃=1000.000014000 (delay 3µs, the best one) */
        s.n_samples = 3;
        set_ts(s.ts + 0, 1000, /* nsec= */ 0);
        set_ts(s.ts + 1, 1005,  1000);
        set_ts(s.ts + 2, 1000,  4000);
        set_ts(s.ts + 3, 1005, 10500);
        set_ts(s.ts + 4, 1000, 11000);
        set_ts(s.ts + 5, 1005, 13000);
        set_ts(s.ts + 6, 1000, 14000);

        ASSERT_OK_ZERO(phc_pick_sample(&s, &offset, &delay, &device));
        ASSERT_EQ(delay, 3000);
        ASSERT_EQ(offset, 5 * (int64_t) NSEC_PER_SEC + 13000 - 12500);
        ASSERT_EQ(device, 1005 * (int64_t) NSEC_PER_SEC + 13000);

        /* Negative offset, and system clock stepped backwards during the last sandwich, which must be
         * ignored even though it appears to have the smallest width */
        s.n_samples = 2;
        set_ts(s.ts + 0, 2000, 999999000);
        set_ts(s.ts + 1, 1999, 999999500);
        set_ts(s.ts + 2, 2001,      1000);
        set_ts(s.ts + 3, 1999, 999999900);
        set_ts(s.ts + 4, 1990, /* nsec= */ 0);

        ASSERT_OK_ZERO(phc_pick_sample(&s, &offset, &delay, /* ret_device_nsec= */ NULL));
        ASSERT_EQ(delay, 2000);
        ASSERT_EQ(offset, -(int64_t) NSEC_PER_SEC + 500 - 1000);

        /* Only stepped samples */
        s.n_samples = 1;
        set_ts(s.ts + 0, 2000, /* nsec= */ 0);
        set_ts(s.ts + 1, 2000, /* nsec= */ 0);
        set_ts(s.ts + 2, 1999, /* nsec= */ 0);
        ASSERT_ERROR(phc_pick_sample(&s, &offset, &delay, &device), ERANGE);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
