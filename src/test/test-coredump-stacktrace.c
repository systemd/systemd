/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* This is a test program that intentionally segfaults so we can generate a
 * predictable-ish stack trace in tests. */

#include <stdlib.h>

static void baz(void) {
        int *x = NULL;

        *x = 42;
}

static void bar(void) {
        baz();
}

static void foo(void) {
        bar();
}

int main(void) {
        foo();

        return 0;
}
