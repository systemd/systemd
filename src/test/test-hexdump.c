/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "hexdump.h"
#include "tests.h"

TEST(hexdump) {
        uint8_t data[146];
        unsigned i;

        hexdump(stdout, NULL, 0);
        hexdump(stdout, "", 0);
        hexdump(stdout, "", SIZE_MAX);
        hexdump(stdout, "", 1);
        hexdump(stdout, "x", 1);
        hexdump(stdout, "x", SIZE_MAX);
        hexdump(stdout, "x", 2);
        hexdump(stdout, "foobar", 7);
        hexdump(stdout, "foobar", SIZE_MAX);
        hexdump(stdout, "f\nobar", 7);
        hexdump(stdout, "f\nobar", SIZE_MAX);
        hexdump(stdout, "xxxxxxxxxxxxxxxxxxxxyz", 23);

        for (i = 0; i < ELEMENTSOF(data); i++)
                data[i] = i*2;

        hexdump(stdout, data, sizeof(data));
}

DEFINE_TEST_MAIN(LOG_INFO);
