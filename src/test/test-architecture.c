/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "architecture.h"
#include "errno-util.h"
#include "log.h"
#include "path-util.h"
#include "tests.h"
#include "virt.h"

TEST(architecture_from_string) {
        ASSERT_LT(architecture_from_string(""), 0);
        ASSERT_LT(architecture_from_string(NULL), 0);
        ASSERT_LT(architecture_from_string("hoge"), 0);
        ASSERT_NULL(architecture_to_string(-1));
        ASSERT_EQ(architecture_from_string(architecture_to_string(0)), 0);
        ASSERT_EQ(architecture_from_string(architecture_to_string(1)), 1);
}

TEST(detect_virtualization) {
        Virtualization v = detect_virtualization();
        if (ERRNO_IS_NEG_PRIVILEGE(v))
                return (void) log_tests_skipped("Cannot detect virtualization");
        ASSERT_OK(v);

        log_info("virtualization=%s id=%s",
                 VIRTUALIZATION_IS_CONTAINER(v) ? "container" :
                 VIRTUALIZATION_IS_VM(v)        ? "vm" : "n/a",
                 virtualization_to_string(v));
}

TEST(uname_architecture) {
        Architecture a = ASSERT_OK(uname_architecture());
        const char *p = ASSERT_NOT_NULL(architecture_to_string(a));
        log_info("uname architecture=%s", p);
        ASSERT_EQ(architecture_from_string(p), a);
}

TEST(native_architecture) {
        Architecture a = ASSERT_OK(native_architecture());
        const char *p = ASSERT_NOT_NULL(architecture_to_string(a));
        log_info("native architecture=%s", p);
        ASSERT_EQ(architecture_from_string(p), a);

        log_info("primary library architecture=" LIB_ARCH_TUPLE);
}

TEST(filename_part) {
        for (Architecture i = 0; i < _ARCHITECTURE_MAX; i++) {
                const char *n = ASSERT_PTR(architecture_to_string(i));

                /* Let's validate that all architecture names we define are good for inclusion in .v/
                 * filename patterns which use "." and "_" as field separators in the filenames. */
                ASSERT_TRUE(filename_part_is_valid(n));
                ASSERT_NULL(strchr(n, '_'));
                ASSERT_NULL(strchr(n, '.'));

                log_info("Good for inclusion in .v/ filenames: %s", n);
        }
}

DEFINE_TEST_MAIN(LOG_INFO);
