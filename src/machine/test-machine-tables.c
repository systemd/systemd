/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "machine.h"
#include "test-tables.h"

int main(int argc, char **argv) {
        test_table(kill_who, KILL_WHO);
        test_table(machine_class, MACHINE_CLASS);
        test_table(machine_state, MACHINE_STATE);

        return EXIT_SUCCESS;
}
