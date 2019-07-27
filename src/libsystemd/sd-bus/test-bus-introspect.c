/* SPDX-License-Identifier: LGPL-2.1+ */

#include "bus-introspect.h"
#include "log.h"
#include "tests.h"

#include "test-vtable-data.h"

static void test_manual_introspection(const sd_bus_vtable vtable[]) {
        struct introspect intro = {};
        _cleanup_free_ char *s = NULL;

        log_info("/* %s */", __func__);

        assert_se(introspect_begin(&intro, false) >= 0);

        fprintf(intro.f, " <interface name=\"org.foo\">\n");
        assert_se(introspect_write_interface(&intro, vtable) >= 0);
        fputs(" </interface>\n", intro.f);

        assert_se(introspect_finish(&intro, &s) == 0);
        fputs(s, stdout);
        fputs("\n", stdout);
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_manual_introspection(test_vtable_1);
        test_manual_introspection(test_vtable_2);
        test_manual_introspection(test_vtable_deprecated);
        test_manual_introspection((const sd_bus_vtable *) vtable_format_221);

        return 0;
}
