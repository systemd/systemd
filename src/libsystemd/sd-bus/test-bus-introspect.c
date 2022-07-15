/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-introspect.h"
#include "log.h"
#include "tests.h"

#include "test-vtable-data.h"

static void test_manual_introspection_one(const sd_bus_vtable vtable[]) {
        struct introspect intro = {};
        _cleanup_free_ char *s = NULL;

        log_info("/* %s */", __func__);

        assert_se(introspect_begin(&intro, false) >= 0);

        assert_se(introspect_write_interface(&intro, "org.foo", vtable) >= 0);
        /* write again to check if output looks OK for a different interface */
        assert_se(introspect_write_interface(&intro, "org.foo.bar", vtable) >= 0);
        assert_se(introspect_finish(&intro, &s) == 0);

        fputs(s, stdout);
        fputs("\n", stdout);
}

TEST(manual_introspection) {
        test_manual_introspection_one(test_vtable_1);
        test_manual_introspection_one(test_vtable_2);
        test_manual_introspection_one(test_vtable_deprecated);
        test_manual_introspection_one((const sd_bus_vtable *) vtable_format_221);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
