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

/* Guard field detects an over-wide write spilling past the declared slot. */
struct numeric_target {
        uint32_t value;
        uint32_t guard;
};

struct strv_target {
        char **list;
        char **guard;
};

#define GUARD_PATTERN UINT32_C(0x5A5A5A5A)

/* Unconnected bus, only good for constructing messages locally. */
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

/* Over-wide scalar wire type must not write past the declared slot. */
TEST(map_all_properties_numeric_type_confusion) {
        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
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

        /* Skipped, adjacent field intact. */
        ASSERT_EQ(data.guard, GUARD_PATTERN);
}

/* Scalar "t" against a declared "as" char** slot must be skipped, not planted+freed. */
TEST(map_all_properties_pointer_type_confusion) {
        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

        char *guard_marker = NULL;
        struct strv_target data = { .guard = &guard_marker };

        static const struct bus_properties_map map[] = {
                { "List", "as", NULL, offsetof(struct strv_target, list) },
                {},
        };

        map_properties_fake_bus(&bus);

        ASSERT_OK(sd_bus_message_new_method_call(bus, &m, "foo.bar", "/", "foo.bar", "Get"));
        ASSERT_OK(sd_bus_message_append(m, "a{sv}", 1, "List", "t", (uint64_t) 0xDEADBEEFCAFEBABEULL));
        map_properties_seal_for_read(m);

        ASSERT_OK(bus_message_map_all_properties(m, map, /* flags= */ 0, /* reterr_error= */ NULL, &data));

        ASSERT_NULL(data.list);
        ASSERT_TRUE(data.guard == &guard_marker);
}

/* Mismatched array type ("ai" vs "as") must be skipped before map_basic()'s strv branch. */
TEST(map_all_properties_array_type_confusion) {
        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

        char *guard_marker = NULL;
        struct strv_target data = { .guard = &guard_marker };

        static const struct bus_properties_map map[] = {
                { "List", "as", NULL, offsetof(struct strv_target, list) },
                {},
        };

        map_properties_fake_bus(&bus);

        ASSERT_OK(sd_bus_message_new_method_call(bus, &m, "foo.bar", "/", "foo.bar", "Get"));
        ASSERT_OK(sd_bus_message_append(m, "a{sv}", 1, "List", "ai", 1, (int32_t) 7));
        map_properties_seal_for_read(m);

        ASSERT_OK(bus_message_map_all_properties(m, map, /* flags= */ 0, /* reterr_error= */ NULL, &data));

        /* Skipped before map_basic()'s strv branch runs. */
        ASSERT_NULL(data.list);
        ASSERT_TRUE(data.guard == &guard_marker);
}

/* Correctly typed "u" variant is still read into the slot. */
TEST(map_all_properties_correct_type) {
        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
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

static int record_set_called(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *reterr_error, void *userdata) {
        bool *called = ASSERT_PTR(userdata);
        int r;

        /* Consume the value, like a real set callback would. */
        r = sd_bus_message_skip(m, NULL);
        if (r < 0)
                return r;

        *called = true;
        return 0;
}

/* Wrong-type variant must be skipped before a property-set callback runs. */
TEST(map_all_properties_set_callback_type_confusion) {
        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

        bool called = false;

        static const struct bus_properties_map map[] = {
                { "List", "as", record_set_called, 0 },
                {},
        };

        map_properties_fake_bus(&bus);

        /* Wrong type: the set callback must not run. */
        ASSERT_OK(sd_bus_message_new_method_call(bus, &m, "foo.bar", "/", "foo.bar", "Get"));
        ASSERT_OK(sd_bus_message_append(m, "a{sv}", 1, "List", "t", (uint64_t) 0xDEADBEEFCAFEBABEULL));
        map_properties_seal_for_read(m);

        ASSERT_OK(bus_message_map_all_properties(m, map, /* flags= */ 0, /* reterr_error= */ NULL, &called));
        ASSERT_FALSE(called);

        /* Matching type: the set callback runs as before. */
        m = sd_bus_message_unref(m);
        ASSERT_OK(sd_bus_message_new_method_call(bus, &m, "foo.bar", "/", "foo.bar", "Get"));
        ASSERT_OK(sd_bus_message_append(m, "a{sv}", 1, "List", "as", 1, "item"));
        map_properties_seal_for_read(m);

        ASSERT_OK(bus_message_map_all_properties(m, map, /* flags= */ 0, /* reterr_error= */ NULL, &called));
        ASSERT_TRUE(called);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
