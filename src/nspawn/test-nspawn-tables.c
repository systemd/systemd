/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "nspawn-settings.h"
#include "test-tables.h"

int main(int argc, char **argv) {
        test_table(resolv_conf_mode, RESOLV_CONF_MODE);
        test_table(timezone_mode, TIMEZONE_MODE);

        return 0;
}
