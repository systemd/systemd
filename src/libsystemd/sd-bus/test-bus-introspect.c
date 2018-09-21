/* SPDX-License-Identifier: LGPL-2.1+ */

#include "bus-introspect.h"
#include "log.h"

static int prop_get(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *error) {
        return -EINVAL;
}

static int prop_set(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *error) {
        return -EINVAL;
}

static const sd_bus_vtable vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD("Hello", "ssas", "a(uu)", NULL, 0),
        SD_BUS_METHOD("DeprecatedHello", "", "", NULL, SD_BUS_VTABLE_DEPRECATED),
        SD_BUS_METHOD("DeprecatedHelloNoReply", "", "", NULL, SD_BUS_VTABLE_DEPRECATED|SD_BUS_VTABLE_METHOD_NO_REPLY),
        SD_BUS_SIGNAL("Wowza", "sss", 0),
        SD_BUS_SIGNAL("DeprecatedWowza", "ut", SD_BUS_VTABLE_DEPRECATED),
        SD_BUS_WRITABLE_PROPERTY("AProperty", "s", prop_get, prop_set, 0, 0),
        SD_BUS_PROPERTY("AReadOnlyDeprecatedProperty", "(ut)", prop_get, 0, SD_BUS_VTABLE_DEPRECATED),
        SD_BUS_PROPERTY("ChangingProperty", "t", prop_get, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Invalidating", "t", prop_get, 0, SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        SD_BUS_PROPERTY("Constant", "t", prop_get, 0, SD_BUS_VTABLE_PROPERTY_CONST|SD_BUS_VTABLE_PROPERTY_EXPLICIT),
        SD_BUS_VTABLE_END
};

int main(int argc, char *argv[]) {
        struct introspect intro;

        log_set_max_level(LOG_DEBUG);

        assert_se(introspect_begin(&intro, false) >= 0);

        fprintf(intro.f, " <interface name=\"org.foo\">\n");
        assert_se(introspect_write_interface(&intro, vtable) >= 0);
        fputs(" </interface>\n", intro.f);

        fflush(intro.f);
        fputs(intro.introspection, stdout);

        introspect_free(&intro);

        return 0;
}
