/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "link-config.h"
#include "test-tables.h"
#include "tests.h"

int main(int argc, char **argv) {
        test_setup_logging(LOG_DEBUG);

        test_table(MACAddressPolicy, mac_address_policy, MAC_ADDRESS_POLICY);

        return EXIT_SUCCESS;
}
