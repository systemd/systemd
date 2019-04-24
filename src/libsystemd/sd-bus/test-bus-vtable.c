/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stdbool.h>
#include <stddef.h>

/* We use system assert.h here, because we don't want to keep macro.h and log.h C++ compatible */
#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <stdio.h>

#include "sd-bus-vtable.h"

#ifndef __cplusplus
#  include "bus-objects.h"
#endif

#include "test-vtable-data.h"

#define DEFAULT_BUS_PATH "unix:path=/run/dbus/system_bus_socket"

static void test_vtable(void) {
        sd_bus *bus = NULL;
        struct context c = {};
        int r;

        assert(sd_bus_new(&bus) >= 0);

        assert(sd_bus_add_object_vtable(bus, NULL, "/foo", "org.freedesktop.systemd.testVtable", test_vtable_2, &c) >= 0);
        assert(sd_bus_add_object_vtable(bus, NULL, "/foo", "org.freedesktop.systemd.testVtable2", test_vtable_2, &c) >= 0);
        /* the cast on the line below is needed to test with the old version of the table */
        assert(sd_bus_add_object_vtable(bus, NULL, "/foo", "org.freedesktop.systemd.testVtable221",
                                        (const sd_bus_vtable *)vtable_format_221, &c) >= 0);

        assert(sd_bus_set_address(bus, DEFAULT_BUS_PATH) >= 0);
        r = sd_bus_start(bus);
        assert(r == 0 ||     /* success */
               r == -ENOENT  /* dbus is inactive */ );

#ifndef __cplusplus
        _cleanup_free_ char *s = NULL;

        assert_se(introspect_path(bus, "/foo", NULL, false, true, NULL, &s, NULL) == 1);
        fputs(s, stdout);
#endif

        sd_bus_unref(bus);
}

int main(int argc, char **argv) {
        test_vtable();

        return 0;
}
