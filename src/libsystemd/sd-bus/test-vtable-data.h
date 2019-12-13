/* SPDX-License-Identifier: LGPL-2.1+ */

/* This is meant to be included in other files, hence no headers */

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

static const sd_bus_vtable test_vtable_1[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD("Hello", "ssas", "a(uu)", NULL, 0),
        SD_BUS_METHOD("DeprecatedHello", "", "", NULL, SD_BUS_VTABLE_DEPRECATED),
        SD_BUS_METHOD("DeprecatedHelloNoReply", "", "", NULL, SD_BUS_VTABLE_DEPRECATED|SD_BUS_VTABLE_METHOD_NO_REPLY),
        SD_BUS_SIGNAL("Wowza", "sss", 0),
        SD_BUS_SIGNAL("DeprecatedWowza", "ut", SD_BUS_VTABLE_DEPRECATED),
        SD_BUS_WRITABLE_PROPERTY("AProperty", "s", get_handler, set_handler, 0, 0),
        SD_BUS_PROPERTY("AReadOnlyDeprecatedProperty", "(ut)", get_handler, 0, SD_BUS_VTABLE_DEPRECATED),
        SD_BUS_PROPERTY("ChangingProperty", "t", get_handler, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Invalidating", "t", get_handler, 0, SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        SD_BUS_PROPERTY("Constant", "t", get_handler, 0, SD_BUS_VTABLE_PROPERTY_CONST|SD_BUS_VTABLE_PROPERTY_EXPLICIT),
        SD_BUS_VTABLE_END
};

static const sd_bus_vtable test_vtable_2[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD("AlterSomething", "s", "s", handler, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Exit", "", "", handler, 0),
        SD_BUS_METHOD_WITH_OFFSET("AlterSomething2", "s", "s", handler, 200, 0),
        SD_BUS_METHOD_WITH_OFFSET("Exit2", "", "", handler, 200, 0),
        SD_BUS_METHOD_WITH_NAMES_OFFSET("AlterSomething3", "so", SD_BUS_PARAM(string) SD_BUS_PARAM(path),
                        "s", SD_BUS_PARAM(returnstring), handler, 200, 0),
        SD_BUS_METHOD_WITH_NAMES("Exit3", "bx", SD_BUS_PARAM(with_confirmation) SD_BUS_PARAM(after_msec),
                        "bb", SD_BUS_PARAM(accepted) SD_BUS_PARAM(scheduled), handler, 0),
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
        SD_BUS_SIGNAL_WITH_NAMES("DummySignal3", "so", SD_BUS_PARAM(string) SD_BUS_PARAM(path), 0),
        SD_BUS_VTABLE_END
};

static const sd_bus_vtable test_vtable_deprecated[] = {
        SD_BUS_VTABLE_START(SD_BUS_VTABLE_DEPRECATED),
        SD_BUS_VTABLE_END
};

struct sd_bus_vtable_221 {
        uint8_t type:8;
        uint64_t flags:56;
        union {
                struct {
                        size_t element_size;
                } start;
                struct {
                        const char *member;
                        const char *signature;
                        const char *result;
                        sd_bus_message_handler_t handler;
                        size_t offset;
                } method;
                struct {
                        const char *member;
                        const char *signature;
                } signal;
                struct {
                        const char *member;
                        const char *signature;
                        sd_bus_property_get_t get;
                        sd_bus_property_set_t set;
                        size_t offset;
                } property;
        } x;
};

static const struct sd_bus_vtable_221 vtable_format_221[] = {
        {
                .type = _SD_BUS_VTABLE_START,
                .flags = 0,
                .x = {
                        .start = {
                                .element_size = sizeof(struct sd_bus_vtable_221)
                        },
                },
        },
        {
                .type = _SD_BUS_VTABLE_METHOD,
                .flags = 0,
                .x = {
                        .method = {
                                .member = "Exit",
                                .signature = "",
                                .result = "",
                                .handler = handler,
                                .offset = 0,
                        },
                },
        },
        {
                .type = _SD_BUS_VTABLE_END,
                .flags = 0,
                .x = { { 0 } },
        }
};
