/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <pthread.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-internal.h"
#include "bus-message.h"
#include "log.h"
#include "strv.h"
#include "tests.h"

struct context {
        int fds[2];
        bool quit;
        char *something;
        char *automatic_string_property;
        uint32_t automatic_integer_property;
};

static int something_handler(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        struct context *c = userdata;
        const char *s;
        char *n = NULL;

        ASSERT_OK_POSITIVE(sd_bus_message_read(m, "s", &s));

        ASSERT_NOT_NULL(n = strjoin("<<<", s, ">>>"));

        free(c->something);
        c->something = n;

        log_info("AlterSomething() called, got %s, returning %s", s, n);

        /* This should fail, since the return type doesn't match */
        ASSERT_ERROR(sd_bus_reply_method_return(m, "u", 4711), ENOMSG);

        ASSERT_OK(sd_bus_reply_method_return(m, "s", n));

        return 1;
}

static int exit_handler(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        struct context *c = userdata;

        c->quit = true;

        log_info("Exit called");

        ASSERT_OK(sd_bus_reply_method_return(m, ""));

        return 1;
}

static int get_handler(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *reterr_error) {
        struct context *c = userdata;

        log_info("property get for %s called, returning \"%s\".", property, c->something);

        ASSERT_OK(sd_bus_message_append(reply, "s", c->something));

        return 1;
}

static int set_handler(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *value, void *userdata, sd_bus_error *reterr_error) {
        struct context *c = userdata;
        const char *s;
        char *n;

        log_info("property set for %s called", property);

        ASSERT_OK(sd_bus_message_read(value, "s", &s));

        ASSERT_NOT_NULL(n = strdup(s));

        free(c->something);
        c->something = n;

        return 1;
}

static int value_handler(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *reterr_error) {
        _cleanup_free_ char *s = NULL;
        const char *x;

        ASSERT_OK(asprintf(&s, "object %p, path %s", userdata, path));
        ASSERT_OK(sd_bus_message_append(reply, "s", s));

        ASSERT_NOT_NULL(x = startswith(path, "/value/"));

        ASSERT_EQ(PTR_TO_UINT(userdata), 30U);

        return 1;
}

static int notify_test(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        ASSERT_OK(sd_bus_emit_properties_changed(sd_bus_message_get_bus(m), m->path, "org.freedesktop.systemd.ValueTest", "Value", NULL));

        ASSERT_OK(sd_bus_reply_method_return(m, NULL));

        return 1;
}

static int notify_test2(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        ASSERT_OK(sd_bus_emit_properties_changed_strv(sd_bus_message_get_bus(m), m->path, "org.freedesktop.systemd.ValueTest", NULL));

        ASSERT_OK(sd_bus_reply_method_return(m, NULL));

        return 1;
}

static int emit_interfaces_added(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        ASSERT_OK(sd_bus_emit_interfaces_added(sd_bus_message_get_bus(m), "/value/a/x", "org.freedesktop.systemd.ValueTest", NULL));

        ASSERT_OK(sd_bus_reply_method_return(m, NULL));

        return 1;
}

static int emit_interfaces_removed(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        ASSERT_OK(sd_bus_emit_interfaces_removed(sd_bus_message_get_bus(m), "/value/a/x", "org.freedesktop.systemd.ValueTest", NULL));

        ASSERT_OK(sd_bus_reply_method_return(m, NULL));

        return 1;
}

static int emit_object_added(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        ASSERT_OK(sd_bus_emit_object_added(sd_bus_message_get_bus(m), "/value/a/x"));

        ASSERT_OK(sd_bus_reply_method_return(m, NULL));

        return 1;
}

static int emit_object_with_manager_added(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        ASSERT_OK(sd_bus_emit_object_added(sd_bus_message_get_bus(m), "/value/a"));

        return ASSERT_OK(sd_bus_reply_method_return(m, NULL));
}

static int emit_object_removed(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        ASSERT_OK(sd_bus_emit_object_removed(sd_bus_message_get_bus(m), "/value/a/x"));

        ASSERT_OK(sd_bus_reply_method_return(m, NULL));

        return 1;
}

static const sd_bus_vtable vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD("AlterSomething", "s", "s", something_handler, 0),
        SD_BUS_METHOD("Exit", "", "", exit_handler, 0),
        SD_BUS_WRITABLE_PROPERTY("Something", "s", get_handler, set_handler, 0, 0),
        SD_BUS_WRITABLE_PROPERTY("AutomaticStringProperty", "s", NULL, NULL, offsetof(struct context, automatic_string_property), 0),
        SD_BUS_WRITABLE_PROPERTY("AutomaticIntegerProperty", "u", NULL, NULL, offsetof(struct context, automatic_integer_property), 0),
        SD_BUS_METHOD("NoOperation", NULL, NULL, NULL, 0),
        SD_BUS_METHOD("EmitInterfacesAdded", NULL, NULL, emit_interfaces_added, 0),
        SD_BUS_METHOD("EmitInterfacesRemoved", NULL, NULL, emit_interfaces_removed, 0),
        SD_BUS_METHOD("EmitObjectAdded", NULL, NULL, emit_object_added, 0),
        SD_BUS_METHOD("EmitObjectWithManagerAdded", NULL, NULL, emit_object_with_manager_added, 0),
        SD_BUS_METHOD("EmitObjectRemoved", NULL, NULL, emit_object_removed, 0),
        SD_BUS_VTABLE_END
};

static const sd_bus_vtable vtable2[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD("NotifyTest", "", "", notify_test, 0),
        SD_BUS_METHOD("NotifyTest2", "", "", notify_test2, 0),
        SD_BUS_PROPERTY("Value", "s", value_handler, 10, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Value2", "s", value_handler, 10, SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        SD_BUS_PROPERTY("Value3", "s", value_handler, 10, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Value4", "s", value_handler, 10, 0),
        SD_BUS_PROPERTY("AnExplicitProperty", "s", NULL, offsetof(struct context, something), SD_BUS_VTABLE_PROPERTY_EXPLICIT|SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        SD_BUS_VTABLE_END
};

static int enumerator_callback(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *reterr_error) {

        if (object_path_startswith("/value", path))
                ASSERT_NOT_NULL(*nodes = strv_new("/value/c", "/value/b", "/value/a"));

        return 1;
}

static int enumerator2_callback(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *reterr_error) {

        if (object_path_startswith("/value/a", path))
                ASSERT_NOT_NULL(*nodes = strv_new("/value/a/z", "/value/a/x", "/value/a/y"));

        return 1;
}

static int enumerator3_callback(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *reterr_error) {
        _cleanup_strv_free_ char **v = NULL;

        if (!object_path_startswith("/value/b", path))
                return 1;

        for (unsigned i = 10; i < 20; i++)
                ASSERT_OK(strv_extendf(&v, "/value/b/%u", i));
        for (unsigned i = 29; i >= 20; i--)
                ASSERT_OK(strv_extendf(&v, "/value/b/%u", i));

        *nodes = TAKE_PTR(v);
        return 1;
}

static void* server(void *p) {
        struct context *c = p;
        sd_bus *bus = NULL;
        sd_id128_t id;
        int r;

        c->quit = false;

        ASSERT_OK(sd_id128_randomize(&id));

        ASSERT_OK(sd_bus_new(&bus));
        ASSERT_OK(sd_bus_set_fd(bus, c->fds[0], c->fds[0]));
        ASSERT_OK(sd_bus_set_server(bus, 1, id));

        ASSERT_OK(sd_bus_add_object_vtable(bus, NULL, "/foo", "org.freedesktop.systemd.test", vtable, c));
        ASSERT_OK(sd_bus_add_object_vtable(bus, NULL, "/foo", "org.freedesktop.systemd.test2", vtable, c));
        ASSERT_OK(sd_bus_add_fallback_vtable(bus, NULL, "/value", "org.freedesktop.systemd.ValueTest", vtable2, NULL, UINT_TO_PTR(20)));
        ASSERT_OK(sd_bus_add_node_enumerator(bus, NULL, "/value", enumerator_callback, NULL));
        ASSERT_OK(sd_bus_add_node_enumerator(bus, NULL, "/value/a", enumerator2_callback, NULL));
        ASSERT_OK(sd_bus_add_node_enumerator(bus, NULL, "/value/b", enumerator3_callback, NULL));
        ASSERT_OK(sd_bus_add_object_manager(bus, NULL, "/value"));
        ASSERT_OK(sd_bus_add_object_manager(bus, NULL, "/value/a"));

        ASSERT_OK(sd_bus_start(bus));

        log_error("Entering event loop on server");

        while (!c->quit) {
                log_error("Loop!");

                r = sd_bus_process(bus, NULL);
                if (r < 0) {
                        log_error_errno(r, "Failed to process requests: %m");
                        goto fail;
                }

                if (r == 0) {
                        r = sd_bus_wait(bus, UINT64_MAX);
                        if (r < 0) {
                                log_error_errno(r, "Failed to wait: %m");
                                goto fail;
                        }

                        continue;
                }
        }

        r = 0;

fail:
        if (bus) {
                sd_bus_flush(bus);
                sd_bus_unref(bus);
        }

        return INT_TO_PTR(r);
}

static int client(struct context *c) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_strv_free_ char **lines = NULL;
        const char *s;
        int r;

        ASSERT_OK(sd_bus_new(&bus));
        ASSERT_OK(sd_bus_set_fd(bus, c->fds[1], c->fds[1]));
        ASSERT_OK(sd_bus_start(bus));

        ASSERT_OK(sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.systemd.test", "NoOperation", &error, NULL, NULL));

        ASSERT_OK(sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.systemd.test", "AlterSomething", &error, &reply, "s", "hallo"));

        ASSERT_OK(sd_bus_message_read(reply, "s", &s));
        ASSERT_STREQ(s, "<<<hallo>>>");

        reply = sd_bus_message_unref(reply);

        ASSERT_FAIL(sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.systemd.test", "Doesntexist", &error, &reply, ""));
        ASSERT_TRUE(sd_bus_error_has_name(&error, SD_BUS_ERROR_UNKNOWN_METHOD));

        sd_bus_error_free(&error);

        ASSERT_FAIL(sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.systemd.test", "Doesntexist", &error, &reply, NULL)); /* NULL and "" are equivalent */
        ASSERT_TRUE(sd_bus_error_has_name(&error, SD_BUS_ERROR_UNKNOWN_METHOD));

        sd_bus_error_free(&error);

        ASSERT_FAIL(sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.systemd.test", "AlterSomething", &error, &reply, "as", 1, "hallo"));
        ASSERT_TRUE(sd_bus_error_has_name(&error, SD_BUS_ERROR_INVALID_ARGS));

        sd_bus_error_free(&error);

        ASSERT_OK(sd_bus_get_property(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.systemd.test", "Something", &error, &reply, "s"));

        ASSERT_OK(sd_bus_message_read(reply, "s", &s));
        ASSERT_STREQ(s, "<<<hallo>>>");

        reply = sd_bus_message_unref(reply);

        ASSERT_OK(sd_bus_set_property(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.systemd.test", "Something", &error, "s", "test"));

        ASSERT_OK(sd_bus_get_property(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.systemd.test", "Something", &error, &reply, "s"));

        ASSERT_OK(sd_bus_message_read(reply, "s", &s));
        ASSERT_STREQ(s, "test");

        reply = sd_bus_message_unref(reply);

        ASSERT_OK(sd_bus_set_property(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.systemd.test", "AutomaticIntegerProperty", &error, "u", 815));

        ASSERT_EQ(c->automatic_integer_property, 815U);

        ASSERT_OK(sd_bus_set_property(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.systemd.test", "AutomaticStringProperty", &error, "s", "Du Dödel, Du!"));

        ASSERT_STREQ(c->automatic_string_property, "Du Dödel, Du!");

        ASSERT_OK(sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.DBus.Introspectable", "Introspect", &error, &reply, ""));

        ASSERT_OK(sd_bus_message_read(reply, "s", &s));
        fputs(s, stdout);

        reply = sd_bus_message_unref(reply);

        ASSERT_OK(sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.DBus.Introspectable", "Introspect", &error, &reply, NULL)); /* NULL and "" are equivalent */

        ASSERT_OK(sd_bus_message_read(reply, "s", &s));
        fputs(s, stdout);

        reply = sd_bus_message_unref(reply);

        ASSERT_OK(sd_bus_get_property(bus, "org.freedesktop.systemd.test", "/value/xuzz", "org.freedesktop.systemd.ValueTest", "Value", &error, &reply, "s"));

        ASSERT_OK(sd_bus_message_read(reply, "s", &s));
        log_info("read %s", s);

        reply = sd_bus_message_unref(reply);

        ASSERT_OK(sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/", "org.freedesktop.DBus.Introspectable", "Introspect", &error, &reply, NULL));

        ASSERT_OK(sd_bus_message_read(reply, "s", &s));
        fputs(s, stdout);

        reply = sd_bus_message_unref(reply);

        ASSERT_OK(sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/value", "org.freedesktop.DBus.Introspectable", "Introspect", &error, &reply, NULL));

        ASSERT_OK(sd_bus_message_read(reply, "s", &s));
        fputs(s, stdout);

        reply = sd_bus_message_unref(reply);

        ASSERT_OK(sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/value/a", "org.freedesktop.DBus.Introspectable", "Introspect", &error, &reply, NULL));

        ASSERT_OK(sd_bus_message_read(reply, "s", &s));
        fputs(s, stdout);

        ASSERT_NOT_NULL(lines = strv_split_newlines(s));
        ASSERT_TRUE(strv_contains(lines, " <node name=\"x\"/>"));
        ASSERT_TRUE(strv_contains(lines, " <node name=\"y\"/>"));
        ASSERT_TRUE(strv_contains(lines, " <node name=\"z\"/>"));
        lines = strv_free(lines);

        reply = sd_bus_message_unref(reply);

        ASSERT_OK(sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/value/b", "org.freedesktop.DBus.Introspectable", "Introspect", &error, &reply, NULL));

        ASSERT_OK(sd_bus_message_read(reply, "s", &s));
        fputs(s, stdout);

        ASSERT_NOT_NULL(lines = strv_split_newlines(s));
        for (unsigned i = 10; i < 30; i++) {
                _cleanup_free_ char *n = NULL;

                ASSERT_OK(asprintf(&n, " <node name=\"%u\"/>", i));
                ASSERT_TRUE(strv_contains(lines, n));
        }
        lines = strv_free(lines);

        reply = sd_bus_message_unref(reply);

        ASSERT_OK(sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.DBus.Properties", "GetAll", &error, &reply, "s", NULL));

        sd_bus_message_dump(reply, stdout, SD_BUS_MESSAGE_DUMP_WITH_HEADER);

        reply = sd_bus_message_unref(reply);

        ASSERT_FAIL(sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/value/a", "org.freedesktop.DBus.Properties", "GetAll", &error, &reply, "s", "org.freedesktop.systemd.ValueTest2"));
        ASSERT_TRUE(sd_bus_error_has_name(&error, SD_BUS_ERROR_UNKNOWN_INTERFACE));
        sd_bus_error_free(&error);

        ASSERT_FAIL(sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.DBus.ObjectManager", "GetManagedObjects", &error, &reply, NULL));
        ASSERT_TRUE(sd_bus_error_has_name(&error, SD_BUS_ERROR_UNKNOWN_METHOD));
        sd_bus_error_free(&error);

        ASSERT_OK(sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/value", "org.freedesktop.DBus.ObjectManager", "GetManagedObjects", &error, &reply, NULL));

        sd_bus_message_dump(reply, stdout, SD_BUS_MESSAGE_DUMP_WITH_HEADER);

        /* Check that /value/b does not have ObjectManager interface but /value/a does */
        ASSERT_OK_POSITIVE(sd_bus_message_rewind(reply, 1));
        ASSERT_OK_POSITIVE(sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "{oa{sa{sv}}}"));
        unsigned path_count = 0;
        while (ASSERT_OK(sd_bus_message_enter_container(reply, SD_BUS_TYPE_DICT_ENTRY, "oa{sa{sv}}")) > 0) {
                const char *path = NULL;
                ASSERT_OK_POSITIVE(sd_bus_message_read_basic(reply, 'o', &path));

                /* Check if the enumerated path is sorted. */
                switch (path_count) {
                case 0:
                        ASSERT_STREQ(path, "/value/a");
                        break;
                case 1:
                        ASSERT_STREQ(path, "/value/b");
                        break;
                case 2:
                        ASSERT_STREQ(path, "/value/c");
                        break;
                default: {
                        unsigned u = path_count - 3 + 10;
                        _cleanup_free_ char *path_expected = NULL;
                        ASSERT_OK(asprintf(&path_expected, "/value/b/%u", u));
                        ASSERT_STREQ(path, path_expected);
                }}
                path_count++;

                /* Check that there is no object manager interface here */
                bool found_object_manager_interface = false;
                ASSERT_OK_POSITIVE(sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "{sa{sv}}"));
                while (ASSERT_OK(sd_bus_message_enter_container(reply, SD_BUS_TYPE_DICT_ENTRY, "sa{sv}")) > 0) {
                        const char *interface_name = NULL;
                        ASSERT_OK_POSITIVE(sd_bus_message_read_basic(reply, 's', &interface_name));

                        if (streq(interface_name, "org.freedesktop.DBus.ObjectManager"))
                                found_object_manager_interface = true;

                        ASSERT_OK(sd_bus_message_skip(reply, "a{sv}"));
                        ASSERT_OK(sd_bus_message_exit_container(reply));
                }
                ASSERT_OK(sd_bus_message_exit_container(reply));

                ASSERT_EQ(found_object_manager_interface, streq(path, "/value/a"));

                ASSERT_OK(sd_bus_message_exit_container(reply));
        }

        reply = sd_bus_message_unref(reply);

        ASSERT_OK(sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/value/a", "org.freedesktop.systemd.ValueTest", "NotifyTest", &error, NULL, NULL));

        ASSERT_OK_POSITIVE(r = sd_bus_process(bus, &reply));

        ASSERT_OK_POSITIVE(sd_bus_message_is_signal(reply, "org.freedesktop.DBus.Properties", "PropertiesChanged"));
        sd_bus_message_dump(reply, stdout, SD_BUS_MESSAGE_DUMP_WITH_HEADER);

        reply = sd_bus_message_unref(reply);

        ASSERT_OK(sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/value/a", "org.freedesktop.systemd.ValueTest", "NotifyTest2", &error, NULL, NULL));

        ASSERT_OK_POSITIVE(r = sd_bus_process(bus, &reply));

        ASSERT_OK_POSITIVE(sd_bus_message_is_signal(reply, "org.freedesktop.DBus.Properties", "PropertiesChanged"));
        sd_bus_message_dump(reply, stdout, SD_BUS_MESSAGE_DUMP_WITH_HEADER);

        reply = sd_bus_message_unref(reply);

        ASSERT_OK(sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.systemd.test", "EmitInterfacesAdded", &error, NULL, NULL));

        ASSERT_OK_POSITIVE(r = sd_bus_process(bus, &reply));

        ASSERT_OK_POSITIVE(sd_bus_message_is_signal(reply, "org.freedesktop.DBus.ObjectManager", "InterfacesAdded"));
        sd_bus_message_dump(reply, stdout, SD_BUS_MESSAGE_DUMP_WITH_HEADER);

        reply = sd_bus_message_unref(reply);

        ASSERT_OK(sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.systemd.test", "EmitInterfacesRemoved", &error, NULL, NULL));

        ASSERT_OK_POSITIVE(r = sd_bus_process(bus, &reply));

        ASSERT_OK_POSITIVE(sd_bus_message_is_signal(reply, "org.freedesktop.DBus.ObjectManager", "InterfacesRemoved"));
        sd_bus_message_dump(reply, stdout, SD_BUS_MESSAGE_DUMP_WITH_HEADER);

        reply = sd_bus_message_unref(reply);

        ASSERT_OK(sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.systemd.test", "EmitObjectAdded", &error, NULL, NULL));

        ASSERT_OK_POSITIVE(r = sd_bus_process(bus, &reply));

        ASSERT_OK_POSITIVE(sd_bus_message_is_signal(reply, "org.freedesktop.DBus.ObjectManager", "InterfacesAdded"));
        sd_bus_message_dump(reply, stdout, SD_BUS_MESSAGE_DUMP_WITH_HEADER);

        /* Check if /value/a/x does not have org.freedesktop.DBus.ObjectManager */
        ASSERT_OK(sd_bus_message_rewind(reply, 1));
        const char* should_be_value_a_x = NULL;
        ASSERT_OK_POSITIVE(sd_bus_message_read_basic(reply, 'o', &should_be_value_a_x));
        ASSERT_STREQ(should_be_value_a_x, "/value/a/x");
        ASSERT_OK_POSITIVE(sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "{sa{sv}}"));
        while (ASSERT_OK(sd_bus_message_enter_container(reply, SD_BUS_TYPE_DICT_ENTRY, "sa{sv}")) > 0) {
                const char* interface_name = NULL;
                ASSERT_OK_POSITIVE(sd_bus_message_read_basic(reply, 's', &interface_name));

                ASSERT_FALSE(streq(interface_name, "org.freedesktop.DBus.ObjectManager"));

                ASSERT_OK(sd_bus_message_skip(reply, "a{sv}"));

                ASSERT_OK(sd_bus_message_exit_container(reply));
        }

        reply = sd_bus_message_unref(reply);

        ASSERT_OK(sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.systemd.test", "EmitObjectWithManagerAdded", &error, NULL, NULL));

        ASSERT_OK_POSITIVE(sd_bus_process(bus, &reply));

        ASSERT_OK_POSITIVE(sd_bus_message_is_signal(reply, "org.freedesktop.DBus.ObjectManager", "InterfacesAdded"));
        sd_bus_message_dump(reply, stdout, SD_BUS_MESSAGE_DUMP_WITH_HEADER);

        /* Check if /value/a has org.freedesktop.DBus.ObjectManager */
        ASSERT_OK(sd_bus_message_rewind(reply, 1));
        const char* should_be_value_a = NULL;
        bool found_object_manager = false;
        ASSERT_OK_POSITIVE(sd_bus_message_read_basic(reply, 'o', &should_be_value_a));
        ASSERT_STREQ(should_be_value_a, "/value/a");
        ASSERT_OK_POSITIVE(sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "{sa{sv}}"));
        while (ASSERT_OK(sd_bus_message_enter_container(reply, SD_BUS_TYPE_DICT_ENTRY, "sa{sv}")) > 0) {
                const char* interface_name = NULL;
                ASSERT_OK_POSITIVE(sd_bus_message_read_basic(reply, 's', &interface_name));

                if (streq(interface_name, "org.freedesktop.DBus.ObjectManager")) {
                        found_object_manager = true;
                        break;
                }

                ASSERT_OK(sd_bus_message_skip(reply, "a{sv}"));

                ASSERT_OK(sd_bus_message_exit_container(reply));
        }
        ASSERT_TRUE(found_object_manager);

        reply = sd_bus_message_unref(reply);

        ASSERT_OK(sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.systemd.test", "EmitObjectRemoved", &error, NULL, NULL));

        ASSERT_OK_POSITIVE(r = sd_bus_process(bus, &reply));

        ASSERT_OK_POSITIVE(sd_bus_message_is_signal(reply, "org.freedesktop.DBus.ObjectManager", "InterfacesRemoved"));
        sd_bus_message_dump(reply, stdout, SD_BUS_MESSAGE_DUMP_WITH_HEADER);

        /* Check if /value/a/x does not have org.freedesktop.DBus.ObjectManager */
        ASSERT_OK(sd_bus_message_rewind(reply, 1));
        should_be_value_a_x = NULL;
        ASSERT_OK_POSITIVE(sd_bus_message_read_basic(reply, 'o', &should_be_value_a_x));
        ASSERT_STREQ(should_be_value_a_x, "/value/a/x");
        ASSERT_OK_POSITIVE(sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "s"));
        const char* deleted_interface_name = NULL;
        while (ASSERT_OK(sd_bus_message_read_basic(reply, 's', &deleted_interface_name)))
                ASSERT_FALSE(streq(deleted_interface_name, "org.freedesktop.DBus.ObjectManager"));
        ASSERT_OK(sd_bus_message_exit_container(reply));

        reply = sd_bus_message_unref(reply);

        ASSERT_OK(sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.systemd.test", "Exit", &error, NULL, NULL));

        sd_bus_flush(bus);

        return 0;
}

int main(int argc, char *argv[]) {
        struct context c = {};
        pthread_t s;
        void *p;
        int r, q;

        test_setup_logging(LOG_DEBUG);

        c.automatic_integer_property = 4711;
        ASSERT_NOT_NULL(c.automatic_string_property = strdup("dudeldu"));

        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM, 0, c.fds));

        r = pthread_create(&s, NULL, server, &c);
        if (r != 0)
                return -r;

        r = client(&c);

        q = pthread_join(s, &p);
        if (q != 0)
                return -q;

        if (r < 0)
                return r;

        if (PTR_TO_INT(p) < 0)
                return PTR_TO_INT(p);

        free(c.something);
        free(c.automatic_string_property);

        return EXIT_SUCCESS;
}
