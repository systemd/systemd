/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "coredump-vacuum.h"

int main(int argc, char *argv[]) {

        if (coredump_vacuum(-1, UINT64_MAX, 70 * 1024) < 0)
                return EXIT_FAILURE;

        return EXIT_SUCCESS;
}
