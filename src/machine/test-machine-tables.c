/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "machine.h"
#include "test-tables.h"
#include "tests.h"

int main(int argc, char **argv) {
        test_setup_logging(LOG_DEBUG);

        test_table(kill_whom, KILL_WHOM);
        test_table(machine_class, MACHINE_CLASS);
        test_table(machine_state, MACHINE_STATE);

        return EXIT_SUCCESS;
}
