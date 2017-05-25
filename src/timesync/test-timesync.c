/***
  This file is part of systemd.

  Copyright 2017 Zbigniew Jędrzejewski-Szmek

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

/* Some unit tests for the helper functions in timesyncd. */

#include "log.h"
#include "macro.h"
#include "timesyncd-conf.h"

static void test_manager_parse_string(void) {
        /* Make sure that NTP_SERVERS is configured to something
         * that we can actually parse successfully. */

        _cleanup_(manager_freep) Manager *m = NULL;

        assert_se(manager_new(&m) == 0);

        assert_se(!m->have_fallbacks);
        assert_se(manager_parse_server_string(m, SERVER_FALLBACK, NTP_SERVERS) == 0);
        assert_se(m->have_fallbacks);
        assert_se(manager_parse_fallback_string(m, NTP_SERVERS) == 0);

        assert_se(manager_parse_server_string(m, SERVER_SYSTEM, "time1.foobar.com time2.foobar.com") == 0);
        assert_se(manager_parse_server_string(m, SERVER_FALLBACK, "time1.foobar.com time2.foobar.com") == 0);
        assert_se(manager_parse_server_string(m, SERVER_LINK, "time1.foobar.com time2.foobar.com") == 0);
}

int main(int argc, char **argv) {
        log_set_max_level(LOG_DEBUG);
        log_parse_environment();

        test_manager_parse_string();

        return 0;
}
