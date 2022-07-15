/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "static-destruct.h"
#include "tests.h"

static int foo = 0;
static int bar = 0;
static int baz = 0;
static char* memory = NULL;

static void test_destroy(int *b) {
        (*b)++;
}

STATIC_DESTRUCTOR_REGISTER(foo, test_destroy);
STATIC_DESTRUCTOR_REGISTER(bar, test_destroy);
STATIC_DESTRUCTOR_REGISTER(bar, test_destroy);
STATIC_DESTRUCTOR_REGISTER(baz, test_destroy);
STATIC_DESTRUCTOR_REGISTER(baz, test_destroy);
STATIC_DESTRUCTOR_REGISTER(baz, test_destroy);
STATIC_DESTRUCTOR_REGISTER(memory, freep);

TEST(static_destruct) {
        assert_se(memory = strdup("hallo"));

        assert_se(foo == 0 && bar == 0 && baz == 0);
        static_destruct();
        assert_se(foo == 1 && bar == 2 && baz == 3);

        assert_se(memory == NULL);
}

DEFINE_TEST_MAIN(LOG_INFO);
