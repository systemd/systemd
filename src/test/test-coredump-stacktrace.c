/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* This is a test program that intentionally segfaults so we can generate a
 * predictable-ish stack trace in tests. */

#include <stdlib.h>

__attribute__((noinline))
static void baz(int *x) {
        *x = rand();
}

__attribute__((noinline))
static void bar(void) {
        int * volatile x = NULL;

        baz(x);
}

__attribute__((noinline))
static void foo(void) {
        bar();
}

int main(void) {
        foo();

        return 0;
}
