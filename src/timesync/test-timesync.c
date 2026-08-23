/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Some unit tests for the helper functions in timesyncd. */

#include "tests.h"
#include "timesyncd-conf.h"
#include "timesyncd-manager.h"
#include "timesyncd-server.h"

TEST(manager_parse_string) {
        /* Make sure that NTP_SERVERS is configured to something
         * that we can actually parse successfully. */

        _cleanup_(manager_freep) Manager *m = NULL;

        assert_se(manager_new(&m) == 0);

        assert_se(!m->fallback_set);
        assert_se(manager_parse_server_string(m, SERVER_FALLBACK, NTP_SERVERS) == 0);
        assert_se(m->fallback_set);
        assert_se(manager_parse_fallback_string(m, NTP_SERVERS) == 0);

        assert_se(manager_parse_server_string(m, SERVER_SYSTEM, "time1.foobar.com time2.foobar.com axrfav.,avf..ra 12345..123") == 0);
        assert_se(manager_parse_server_string(m, SERVER_FALLBACK, "time1.foobar.com time2.foobar.com axrfav.,avf..ra 12345..123") == 0);
        assert_se(manager_parse_server_string(m, SERVER_LINK, "time1.foobar.com time2.foobar.com axrfav.,avf..ra 12345..123") == 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
