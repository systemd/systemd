/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "nspawn-settings.h"
#include "test-tables.h"
#include "tests.h"

int main(int argc, char **argv) {
        test_setup_logging(LOG_DEBUG);

        test_table(ResolvConfMode, resolv_conf_mode, RESOLV_CONF_MODE);
        test_table(TimezoneMode, timezone_mode, TIMEZONE_MODE);

        return 0;
}
