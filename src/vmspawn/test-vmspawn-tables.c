/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "test-tables.h"
#include "tests.h"
#include "vmspawn-settings.h"

int main(int argc, char **argv) {
        test_setup_logging(LOG_DEBUG);

        test_table(ConsoleMode, console_mode, CONSOLE_MODE);

        return 0;
}
