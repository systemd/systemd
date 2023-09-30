/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "link-config.h"
#include "test-tables.h"

int main(int argc, char **argv) {
        test_table(mac_address_policy, MAC_ADDRESS_POLICY);

        return EXIT_SUCCESS;
}
