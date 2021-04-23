/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "service.h"
#include "tests.h"

#define EXEC_START_ABSOLUTE \
        "ExecStart 0 /bin/sh \"sh\" \"-e\" \"-x\" \"-c\" \"systemctl --state=failed --no-legend --no-pager >/failed ; systemctl daemon-reload ; echo OK >/testok\""
#define EXEC_START_RELATIVE \
        "ExecStart 0 sh \"sh\" \"-e\" \"-x\" \"-c\" \"systemctl --state=failed --no-legend --no-pager >/failed ; systemctl daemon-reload ; echo OK >/testok\""

static void test_deserialize_exec_command_one(const char *key, const char *line, int expected) {
        int r;

        /* Only vestigial state is created here that is sufficient for log_unit_*() not to crash. */
        Manager m = {};
        Service s = {
                .meta.id = (char*) "test",
                .meta.manager = &m,
        };

        r = service_deserialize_exec_command(UNIT(&s), key, line);
        log_debug("[%s] → %d (expected: %d)", line, r, expected);
        assert(r == expected);

        /* Note that the command doesn't match any command in the empty list of commands in 's', so it is
         * always rejected with "Current command vanished from the unit file", and we don't leak anything. */
}

static void test_deserialize_exec_command(void) {
        log_info("/* %s */", __func__);

        test_deserialize_exec_command_one("main-command", EXEC_START_ABSOLUTE, 0);
        test_deserialize_exec_command_one("main-command", EXEC_START_RELATIVE, 0);
        test_deserialize_exec_command_one("control-command", EXEC_START_ABSOLUTE, 0);
        test_deserialize_exec_command_one("control-command", EXEC_START_RELATIVE, 0);

        test_deserialize_exec_command_one("control-command", "ExecStart 0 /bin/sh \"sh\"", 0);
        test_deserialize_exec_command_one("control-command", "ExecStart 0 /no/command ", -EINVAL);
        test_deserialize_exec_command_one("control-command", "ExecStart 0 /bad/quote \"", -EINVAL);
        test_deserialize_exec_command_one("control-command", "ExecStart s /bad/id x y z", -EINVAL);
        test_deserialize_exec_command_one("control-command", "ExecStart 11", -EINVAL);
        test_deserialize_exec_command_one("control-command", "ExecWhat 11 /a/b c d e", -EINVAL);
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_deserialize_exec_command();

        return EXIT_SUCCESS;
}
