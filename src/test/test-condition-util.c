/***
  This file is part of systemd

  Copyright 2014 Ronny Chevalier

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

#include "condition-util.h"
#include "macro.h"
#include "util.h"
#include "log.h"
#include "architecture.h"
#include "systemd/sd-id128.h"

static void test_condition_test_ac_power(void) {
        Condition *condition;

        condition = condition_new(CONDITION_AC_POWER, "true", false, false);
        assert_se(condition_test_ac_power(condition) == on_ac_power());
        condition_free(condition);

        condition = condition_new(CONDITION_AC_POWER, "false", false, false);
        assert_se(condition_test_ac_power(condition) != on_ac_power());
        condition_free(condition);

        condition = condition_new(CONDITION_AC_POWER, "false", false, true);
        assert_se(condition_test_ac_power(condition) == on_ac_power());
        condition_free(condition);
}

static void test_condition_test_host(void) {
        Condition *condition;
        sd_id128_t id;
        int r;
        char sid[SD_ID128_STRING_MAX];
        _cleanup_free_ char *hostname = NULL;

        r = sd_id128_get_machine(&id);
        assert_se(r >= 0);
        assert_se(sd_id128_to_string(id, sid));

        condition = condition_new(CONDITION_HOST, sid, false, false);
        assert_se(condition_test_host(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_HOST, "garbage value jjjjjjjjjjjjjj", false, false);
        assert_se(!condition_test_host(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_HOST, sid, false, true);
        assert_se(!condition_test_host(condition));
        condition_free(condition);

        hostname = gethostname_malloc();
        assert_se(hostname);

        condition = condition_new(CONDITION_HOST, hostname, false, false);
        assert_se(condition_test_host(condition));
        condition_free(condition);
}

static void test_condition_test_architecture(void) {
        Condition *condition;
        Architecture a;
        const char *sa;

        a = uname_architecture();
        assert_se(a >= 0);

        sa = architecture_to_string(a);
        assert_se(sa);

        condition = condition_new(CONDITION_ARCHITECTURE, sa, false, false);
        assert_se(condition_test_architecture(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_ARCHITECTURE, "garbage value", false, false);
        assert_se(!condition_test_architecture(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_ARCHITECTURE, sa, false, true);
        assert_se(!condition_test_architecture(condition));
        condition_free(condition);
}

int main(int argc, char *argv[]) {
        log_parse_environment();
        log_open();

        test_condition_test_ac_power();
        test_condition_test_host();
        test_condition_test_architecture();

        return 0;
}
