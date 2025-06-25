/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "battery-capacity.h"
#include "errno-util.h"
#include "hashmap.h"
#include "log.h"
#include "tests.h"
#include "time-util.h"

TEST(fetch_batteries_capacity_by_name) {
        _cleanup_hashmap_free_ Hashmap *capacity = NULL;
        int r;

        assert_se(fetch_batteries_capacity_by_name(&capacity) >= 0);
        log_debug("fetch_batteries_capacity_by_name: %u entries", hashmap_size(capacity));

        const char *name;
        void *cap;
        HASHMAP_FOREACH_KEY(cap, name, capacity) {
                assert(cap);  /* Anything non-null is fine. */
                log_info("Battery %s: capacity = %i", name, get_capacity_by_name(capacity, name));
        }

        for (int i = 0; i < 2; i++) {
                usec_t interval;

                if (i > 0)
                        sleep(1);

                r = get_total_suspend_interval(capacity, &interval);
                assert_se(r >= 0 || r == -ENOENT);
                log_info("%d: get_total_suspend_interval: %s", i,
                         r < 0 ? STRERROR(r) : FORMAT_TIMESPAN(interval, USEC_PER_SEC));
        }
}

static int intro(void) {
        if (getuid() != 0)
                log_warning("This program is unlikely to work for unprivileged users");

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
