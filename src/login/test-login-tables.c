/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "logind-action.h"
#include "logind-session.h"
#include "test-tables.h"

int main(int argc, char **argv) {
        test_table(handle_action, HANDLE_ACTION);
        test_table(inhibit_mode, INHIBIT_MODE);
        test_table(kill_who, KILL_WHO);
        test_table(session_class, SESSION_CLASS);
        test_table(session_state, SESSION_STATE);
        test_table(session_type, SESSION_TYPE);
        test_table(user_state, USER_STATE);

        return EXIT_SUCCESS;
}
