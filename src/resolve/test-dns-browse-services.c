/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "random-util.h"
#include "resolved-dns-browse-services.h"
#include "tests.h"
#include "time-util.h"

TEST(calculate_next_query_delay) {
        for (int i = 0; i < 100; i++) {
                usec_t delay = (1 + random_u64_range(3600)) * USEC_PER_SEC;
                usec_t expected = (delay < 2048 * USEC_PER_SEC) ? delay * 2 : 3600 * USEC_PER_SEC;
                ASSERT_EQ(mdns_calculate_next_query_delay(delay), expected);
        }
}

TEST(mdns_maintenance_next_time) {
        usec_t until = 1000000; /* Example until time */
        uint32_t ttl = 100;     /* Example TTL */

        /* Test for each TTL state */
        for (DnsRecordTTLState state = DNS_RECORD_TTL_STATE_80_PERCENT; state <= _DNS_RECORD_TTL_STATE_MAX; state++) {
                usec_t expected = usec_sub_unsigned(until, (20 - state * 5) * ttl * USEC_PER_SEC / 100);
                usec_t result = mdns_maintenance_next_time(until, ttl, state);
                ASSERT_EQ(result, expected);
        }
}

TEST(mdns_maintenance_jitter) {
        uint32_t ttl = 100; /* Example TTL */

        for (int i = 0; i < 100; i++) {
                usec_t jitter = mdns_maintenance_jitter(ttl);
                ASSERT_LE(jitter, (2 * ttl * USEC_PER_SEC / 100));
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
