/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "bus-internal.h"
#include "bus-map-properties.h"
#include "bus-util.h"
#include "log.h"
#include "tests.h"

static int callback(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        return 1;
}

static void destroy_callback(void *userdata) {
        int *n_called = userdata;

        (*n_called)++;
}

TEST(destroy_callback) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        sd_bus_slot *slot = NULL;
        sd_bus_destroy_t t;

        int r, n_called = 0;

        r = bus_open_system_watch_bind_with_description(&bus, "test-bus");
        if (r < 0)
                return (void) log_error_errno(r, "Failed to connect to bus: %m");

        ASSERT_OK_EQ(sd_bus_request_name_async(bus, &slot, "org.freedesktop.systemd.test-bus-util", 0, callback, &n_called),
                     1);

        ASSERT_EQ(sd_bus_slot_get_destroy_callback(slot, NULL), 0);
        ASSERT_EQ(sd_bus_slot_get_destroy_callback(slot, &t), 0);

        ASSERT_EQ(sd_bus_slot_set_destroy_callback(slot, destroy_callback), 0);
        ASSERT_EQ(sd_bus_slot_get_destroy_callback(slot, NULL), 1);
        ASSERT_EQ(sd_bus_slot_get_destroy_callback(slot, &t), 1);
        assert_se(t == destroy_callback);

        /* Force cleanup so we can look at n_called */
        ASSERT_EQ(n_called, 0);
        sd_bus_slot_unref(slot);
        ASSERT_EQ(n_called, 1);
}

/* Adjacent guard field lets us observe whether an over-wide write spilled past the declared slot. */
struct numeric_target {
        uint32_t value;
        uint32_t guard;
};

struct strv_target {
        char **list;
};

#define GUARD_PATTERN UINT32_C(0x5A5A5A5A)

/* Build an unconnected bus object usable only for constructing messages locally */
static void map_properties_fake_bus(sd_bus **ret) {
        sd_bus *bus = NULL;

        ASSERT_OK(sd_bus_new(&bus));
        bus->state = BUS_RUNNING; /* Fake state to allow message creation */
        *ret = bus;
}

static void map_properties_seal_for_read(sd_bus_message *m) {
        ASSERT_OK(sd_bus_message_seal(m, 1, 0));
        ASSERT_OK(sd_bus_message_rewind(m, true));
}

/* A peer that sends a property variant whose wire type is wider than the declared map signature */
TEST(map_all_properties_numeric_type_confusion) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

        struct numeric_target data = { .value = 0, .guard = GUARD_PATTERN };

        static const struct bus_properties_map map[] = {
                { "Value", "u", NULL, offsetof(struct numeric_target, value) },
                {},
        };

        map_properties_fake_bus(&bus);

        ASSERT_OK(sd_bus_message_new_method_call(bus, &m, "foo.bar", "/", "foo.bar", "Get"));
        ASSERT_OK(sd_bus_message_append(m, "a{sv}", 1, "Value", "t", (uint64_t) 0xAABBCCDD11223344ULL));
        map_properties_seal_for_read(m);

        ASSERT_OK(bus_message_map_all_properties(m, map, /* flags= */ 0, /* reterr_error= */ NULL, &data));

        /* The over-wide variant must be rejected, leaving the adjacent field intact. */
        ASSERT_EQ(data.guard, GUARD_PATTERN);
}

/* A property declared as a string array ("as") mapped into a char** slot receiving a "t" */
TEST(map_all_properties_pointer_type_confusion) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

        struct strv_target data = {};

        static const struct bus_properties_map map[] = {
                { "List", "as", NULL, offsetof(struct strv_target, list) },
                {},
        };

        map_properties_fake_bus(&bus);

        ASSERT_OK(sd_bus_message_new_method_call(bus, &m, "foo.bar", "/", "foo.bar", "Get"));
        ASSERT_OK(sd_bus_message_append(m, "a{sv}", 1, "List", "t", (uint64_t) 0xDEADBEEFCAFEBABEULL));
        map_properties_seal_for_read(m);

        ASSERT_OK(bus_message_map_all_properties(m, map, /* flags= */ 0, /* reterr_error= */ NULL, &data));

        /* The mismatched variant must be skipped, leaving no peer-controlled pointer behind. */
        ASSERT_NULL(data.list);
}

/* The matching-type path must keep working: a correctly typed "u" variant is read into the slot. */
TEST(map_all_properties_correct_type) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

        struct numeric_target data = { .value = 0, .guard = GUARD_PATTERN };

        static const struct bus_properties_map map[] = {
                { "Value", "u", NULL, offsetof(struct numeric_target, value) },
                {},
        };

        map_properties_fake_bus(&bus);

        ASSERT_OK(sd_bus_message_new_method_call(bus, &m, "foo.bar", "/", "foo.bar", "Get"));
        ASSERT_OK(sd_bus_message_append(m, "a{sv}", 1, "Value", "u", (uint32_t) 42));
        map_properties_seal_for_read(m);

        ASSERT_OK(bus_message_map_all_properties(m, map, /* flags= */ 0, /* reterr_error= */ NULL, &data));

        ASSERT_EQ(data.value, UINT32_C(42));
        ASSERT_EQ(data.guard, GUARD_PATTERN);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
