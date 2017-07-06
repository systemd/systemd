#include <stdbool.h>
#include <stddef.h>

/* We use system assert.h here, because we don't want to keep macro.h and log.h C++ compatible */
#undef NDEBUG
#include <assert.h>
#include <errno.h>

#include "sd-bus-vtable.h"

#define DEFAULT_BUS_PATH "unix:path=/run/dbus/system_bus_socket"

struct context {
        bool quit;
        char *something;
        char *automatic_string_property;
        uint32_t automatic_integer_property;
};

static int handler(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        return 1;
}

static int value_handler(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *error) {
        return 1;
}

static int get_handler(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *error) {
        return 1;
}

static int set_handler(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *value, void *userdata, sd_bus_error *error) {
        return 1;
}

static const sd_bus_vtable vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD("AlterSomething", "s", "s", handler, 0),
        SD_BUS_METHOD("Exit", "", "", handler, 0),
        SD_BUS_METHOD_WITH_OFFSET("AlterSomething2", "s", "s", handler, 200, 0),
        SD_BUS_METHOD_WITH_OFFSET("Exit2", "", "", handler, 200, 0),
        SD_BUS_PROPERTY("Value", "s", value_handler, 10, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Value2", "s", value_handler, 10, SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        SD_BUS_PROPERTY("Value3", "s", value_handler, 10, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Value4", "s", value_handler, 10, 0),
        SD_BUS_PROPERTY("AnExplicitProperty", "s", NULL, offsetof(struct context, something),
                        SD_BUS_VTABLE_PROPERTY_EXPLICIT|SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        SD_BUS_WRITABLE_PROPERTY("Something", "s", get_handler, set_handler, 0, 0),
        SD_BUS_WRITABLE_PROPERTY("AutomaticStringProperty", "s", NULL, NULL,
                                 offsetof(struct context, automatic_string_property), 0),
        SD_BUS_WRITABLE_PROPERTY("AutomaticIntegerProperty", "u", NULL, NULL,
                                 offsetof(struct context, automatic_integer_property), 0),
        SD_BUS_METHOD("NoOperation", NULL, NULL, NULL, 0),
        SD_BUS_SIGNAL("DummySignal", "b", 0),
        SD_BUS_SIGNAL("DummySignal2", "so", 0),
        SD_BUS_VTABLE_END
};

static void test_vtable(void) {
        sd_bus *bus = NULL;
        struct context c = {};
        int r;

        assert(sd_bus_new(&bus) >= 0);

        assert(sd_bus_add_object_vtable(bus, NULL, "/foo", "org.freedesktop.systemd.testVtable", vtable, &c) >= 0);
        assert(sd_bus_add_object_vtable(bus, NULL, "/foo", "org.freedesktop.systemd.testVtable2", vtable, &c) >= 0);

        assert(sd_bus_set_address(bus, DEFAULT_BUS_PATH) >= 0);
        r = sd_bus_start(bus);
        assert(r == 0 ||     /* success */
               r == -ENOENT  /* dbus is inactive */ );

        sd_bus_unref(bus);
}

int main(int argc, char **argv) {
        test_vtable();

        return 0;
}
