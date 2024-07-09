/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "logind-action.h"
#include "logind-session.h"
#include "sleep-config.h"
#include "test-tables.h"
#include "tests.h"

static void test_sleep_handle_action(void) {
        for (HandleAction action = _HANDLE_ACTION_SLEEP_FIRST; action < _HANDLE_ACTION_SLEEP_LAST; action++) {
                const HandleActionData *data;
                const char *sleep_operation_str, *handle_action_str;

                assert_se(data = handle_action_lookup(action));

                assert_se(handle_action_str = handle_action_to_string(action));
                assert_se(sleep_operation_str = sleep_operation_to_string(data->sleep_operation));

                assert_se(streq(handle_action_str, sleep_operation_str));
        }
}

int main(int argc, char **argv) {
        test_setup_logging(LOG_DEBUG);

        test_table(handle_action, HANDLE_ACTION);
        test_table(inhibit_mode, INHIBIT_MODE);
        test_table(kill_whom, KILL_WHOM);
        test_table(session_class, SESSION_CLASS);
        test_table(session_state, SESSION_STATE);
        test_table(session_type, SESSION_TYPE);
        test_table(user_state, USER_STATE);

        test_sleep_handle_action();

        return EXIT_SUCCESS;
}
