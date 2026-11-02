/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "static-destruct.h"
#include "strv.h"
#include "tests.h"

static int foo = 0;
static int bar = 0;
static int baz = 0;
static char *memory = NULL;
static char **strings = NULL;
static size_t n_strings = 0;
static int *integers = NULL;
static size_t n_integers = 0;

static void test_destroy(int *b) {
        (*b)++;
}

static void test_strings_destroy(char **array, size_t n) {
        ASSERT_EQ(n, 3U);
        ASSERT_STRV_EQ(array, STRV_MAKE("a", "bbb", "ccc"));

        strv_free(array);
}

static void test_integers_destroy(int *array, size_t n) {
        ASSERT_EQ(n, 10U);

        for (size_t i = 0; i < n; i++)
                ASSERT_EQ(array[i], (int) (i * i));

        free(array);
}

STATIC_DESTRUCTOR_REGISTER(foo, test_destroy);
STATIC_DESTRUCTOR_REGISTER(bar, test_destroy);
STATIC_DESTRUCTOR_REGISTER(bar, test_destroy);
STATIC_DESTRUCTOR_REGISTER(baz, test_destroy);
STATIC_DESTRUCTOR_REGISTER(baz, test_destroy);
STATIC_DESTRUCTOR_REGISTER(baz, test_destroy);
STATIC_DESTRUCTOR_REGISTER(memory, freep);
STATIC_ARRAY_DESTRUCTOR_REGISTER(strings, n_strings, test_strings_destroy);
STATIC_ARRAY_DESTRUCTOR_REGISTER(integers, n_integers, test_integers_destroy);

TEST(static_destruct) {
        ASSERT_EQ(foo, 0);
        ASSERT_EQ(bar, 0);
        ASSERT_EQ(baz, 0);
        ASSERT_NOT_NULL(memory = strdup("hallo"));
        ASSERT_NOT_NULL(strings = strv_new("a", "bbb", "ccc"));
        n_strings = strv_length(strings);
        n_integers = 10;
        ASSERT_NOT_NULL(integers = new(int, n_integers));
        for (size_t i = 0; i < n_integers; i++)
                integers[i] = i * i;

        static_destruct();

        ASSERT_EQ(foo, 1);
        ASSERT_EQ(bar, 2);
        ASSERT_EQ(baz, 3);
        ASSERT_NULL(memory);
        ASSERT_NULL(strings);
        ASSERT_EQ(n_strings, 0U);
        ASSERT_NULL(integers);
        ASSERT_EQ(n_integers, 0U);
}

DEFINE_TEST_MAIN(LOG_INFO);
