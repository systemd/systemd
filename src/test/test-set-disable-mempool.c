/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <pthread.h>

#include "process-util.h"
#include "set.h"
#include "tests.h"

#define NUM 100

static void* thread(void *p) {
        Set **s = p;

        assert_se(s);
        assert_se(*s);

        assert_se(!is_main_thread());
        assert_se(set_size(*s) == NUM);
        *s = set_free(*s);

        return NULL;
}

static void test_one(const char *val) {
        pthread_t t;
        int x[NUM] = {};
        unsigned i;
        Set *s;

        log_info("Testing with SYSTEMD_MEMPOOL=%s", val);
        assert_se(setenv("SYSTEMD_MEMPOOL", val, true) == 0);
        assert_se(is_main_thread());

        assert_se(s = set_new(NULL));
        for (i = 0; i < NUM; i++)
                assert_se(set_put(s, &x[i]));

        assert_se(pthread_create(&t, NULL, thread, &s) == 0);
        assert_se(pthread_join(t, NULL) == 0);

        assert_se(!s);
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_one("0");
        /* The value $SYSTEMD_MEMPOOL= is cached. So the following
         * test should also succeed. */
        test_one("1");

        return 0;
}
