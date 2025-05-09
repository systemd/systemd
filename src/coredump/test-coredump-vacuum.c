/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "coredump-vacuum.h"
#include "tests.h"

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        if (coredump_vacuum(-1, UINT64_MAX, 70 * 1024) < 0)
                return EXIT_FAILURE;

        return EXIT_SUCCESS;
}
