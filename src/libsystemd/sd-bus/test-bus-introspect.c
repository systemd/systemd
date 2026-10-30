/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-introspect.h"
#include "log.h"
#include "test-vtable-data.h"
#include "tests.h"

static void test_manual_introspection_one(const sd_bus_vtable vtable[]) {
        BusIntrospect intro = {};
        _cleanup_free_ char *s = NULL;

        log_info("/* %s */", __func__);

        ASSERT_OK(introspect_begin(&intro, /* trusted= */ false));

        ASSERT_OK(introspect_write_interface(&intro, "org.foo", vtable));
        /* write again to check if output looks OK for a different interface */
        ASSERT_OK(introspect_write_interface(&intro, "org.foo.bar", vtable));
        ASSERT_OK_ZERO(introspect_finish(&intro, &s));

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
