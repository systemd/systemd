/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <pthread.h>
#include <stdlib.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-dump.h"
#include "bus-internal.h"
#include "bus-message.h"
#include "log.h"
#include "macro.h"
#include "strv.h"
#include "tests.h"

struct context {
        int fds[2];
        bool quit;
        char *something;
        char *automatic_string_property;
        uint32_t automatic_integer_property;
};

static int something_handler(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        struct context *c = userdata;
        const char *s;
        char *n = NULL;
        int r;

        r = sd_bus_message_read(m, "s", &s);
        assert_se(r > 0);

        n = strjoin("<<<", s, ">>>");
        assert_se(n);

        free(c->something);
        c->something = n;

        log_info("AlterSomething() called, got %s, returning %s", s, n);

        /* This should fail, since the return type doesn't match */
        assert_se(sd_bus_reply_method_return(m, "u", 4711) == -ENOMSG);

        r = sd_bus_reply_method_return(m, "s", n);
        assert_se(r >= 0);

        return 1;
}

static int exit_handler(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        struct context *c = userdata;
        int r;

        c->quit = true;

        log_info("Exit called");

        r = sd_bus_reply_method_return(m, "");
        assert_se(r >= 0);

        return 1;
}

static int get_handler(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *error) {
        struct context *c = userdata;
        int r;

        log_info("property get for %s called, returning \"%s\".", property, c->something);

        r = sd_bus_message_append(reply, "s", c->something);
        assert_se(r >= 0);

        return 1;
}

static int set_handler(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *value, void *userdata, sd_bus_error *error) {
        struct context *c = userdata;
        const char *s;
        char *n;
        int r;

        log_info("property set for %s called", property);

        r = sd_bus_message_read(value, "s", &s);
        assert_se(r >= 0);

        n = strdup(s);
        assert_se(n);

        free(c->something);
        c->something = n;

        return 1;
}

static int value_handler(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *s = NULL;
        const char *x;
        int r;

        assert_se(asprintf(&s, "object %p, path %s", userdata, path) >= 0);
        r = sd_bus_message_append(reply, "s", s);
        assert_se(r >= 0);

        assert_se(x = startswith(path, "/value/"));

        assert_se(PTR_TO_UINT(userdata) == 30);

        return 1;
}

static int notify_test(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        int r;

        assert_se(sd_bus_emit_properties_changed(sd_bus_message_get_bus(m), m->path, "org.freedesktop.systemd.ValueTest", "Value", NULL) >= 0);

        r = sd_bus_reply_method_return(m, NULL);
        assert_se(r >= 0);

        return 1;
}

static int notify_test2(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        int r;

        assert_se(sd_bus_emit_properties_changed_strv(sd_bus_message_get_bus(m), m->path, "org.freedesktop.systemd.ValueTest", NULL) >= 0);

        r = sd_bus_reply_method_return(m, NULL);
        assert_se(r >= 0);

        return 1;
}

static int emit_interfaces_added(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        int r;

        assert_se(sd_bus_emit_interfaces_added(sd_bus_message_get_bus(m), "/value/a/x", "org.freedesktop.systemd.ValueTest", NULL) >= 0);

        r = sd_bus_reply_method_return(m, NULL);
        assert_se(r >= 0);

        return 1;
}

static int emit_interfaces_removed(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        int r;

        assert_se(sd_bus_emit_interfaces_removed(sd_bus_message_get_bus(m), "/value/a/x", "org.freedesktop.systemd.ValueTest", NULL) >= 0);

        r = sd_bus_reply_method_return(m, NULL);
        assert_se(r >= 0);

        return 1;
}

static int emit_object_added(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        int r;

        assert_se(sd_bus_emit_object_added(sd_bus_message_get_bus(m), "/value/a/x") >= 0);

        r = sd_bus_reply_method_return(m, NULL);
        assert_se(r >= 0);

        return 1;
}

static int emit_object_with_manager_added(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        assert_se(sd_bus_emit_object_added(sd_bus_message_get_bus(m), "/value/a") >= 0);

        return ASSERT_SE_NONNEG(sd_bus_reply_method_return(m, NULL));
}

static int emit_object_removed(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        int r;

        assert_se(sd_bus_emit_object_removed(sd_bus_message_get_bus(m), "/value/a/x") >= 0);

        r = sd_bus_reply_method_return(m, NULL);
        assert_se(r >= 0);

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

static int enumerator_callback(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error) {

        if (object_path_startswith("/value", path))
                assert_se(*nodes = strv_new("/value/a", "/value/b", "/value/c"));

        return 1;
}

static int enumerator2_callback(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error) {

        if (object_path_startswith("/value/a", path))
                assert_se(*nodes = strv_new("/value/a/x", "/value/a/y", "/value/a/z"));

        return 1;
}

static int enumerator3_callback(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error) {
        _cleanup_strv_free_ char **v = NULL;

        if (!object_path_startswith("/value/b", path))
                return 1;

        for (unsigned i = 0; i < 30; i++)
                assert_se(strv_extendf(&v, "/value/b/%u", i) >= 0);

        *nodes = TAKE_PTR(v);
        return 1;
}

static void *server(void *p) {
        struct context *c = p;
        sd_bus *bus = NULL;
        sd_id128_t id;
        int r;

        c->quit = false;

        assert_se(sd_id128_randomize(&id) >= 0);

        assert_se(sd_bus_new(&bus) >= 0);
        assert_se(sd_bus_set_fd(bus, c->fds[0], c->fds[0]) >= 0);
        assert_se(sd_bus_set_server(bus, 1, id) >= 0);

        assert_se(sd_bus_add_object_vtable(bus, NULL, "/foo", "org.freedesktop.systemd.test", vtable, c) >= 0);
        assert_se(sd_bus_add_object_vtable(bus, NULL, "/foo", "org.freedesktop.systemd.test2", vtable, c) >= 0);
        assert_se(sd_bus_add_fallback_vtable(bus, NULL, "/value", "org.freedesktop.systemd.ValueTest", vtable2, NULL, UINT_TO_PTR(20)) >= 0);
        assert_se(sd_bus_add_node_enumerator(bus, NULL, "/value", enumerator_callback, NULL) >= 0);
        assert_se(sd_bus_add_node_enumerator(bus, NULL, "/value/a", enumerator2_callback, NULL) >= 0);
        assert_se(sd_bus_add_node_enumerator(bus, NULL, "/value/b", enumerator3_callback, NULL) >= 0);
        assert_se(sd_bus_add_object_manager(bus, NULL, "/value") >= 0);
        assert_se(sd_bus_add_object_manager(bus, NULL, "/value/a") >= 0);

        assert_se(sd_bus_start(bus) >= 0);

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

        assert_se(sd_bus_new(&bus) >= 0);
        assert_se(sd_bus_set_fd(bus, c->fds[1], c->fds[1]) >= 0);
        assert_se(sd_bus_start(bus) >= 0);

        r = sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.systemd.test", "NoOperation", &error, NULL, NULL);
        assert_se(r >= 0);

        r = sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.systemd.test", "AlterSomething", &error, &reply, "s", "hallo");
        assert_se(r >= 0);

        r = sd_bus_message_read(reply, "s", &s);
        assert_se(r >= 0);
        assert_se(streq(s, "<<<hallo>>>"));

        reply = sd_bus_message_unref(reply);

        r = sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.systemd.test", "Doesntexist", &error, &reply, "");
        assert_se(r < 0);
        assert_se(sd_bus_error_has_name(&error, SD_BUS_ERROR_UNKNOWN_METHOD));

        sd_bus_error_free(&error);

        r = sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.systemd.test", "Doesntexist", &error, &reply, NULL); /* NULL and "" are equivalent */
        assert_se(r < 0);
        assert_se(sd_bus_error_has_name(&error, SD_BUS_ERROR_UNKNOWN_METHOD));

        sd_bus_error_free(&error);

        r = sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.systemd.test", "AlterSomething", &error, &reply, "as", 1, "hallo");
        assert_se(r < 0);
        assert_se(sd_bus_error_has_name(&error, SD_BUS_ERROR_INVALID_ARGS));

        sd_bus_error_free(&error);

        r = sd_bus_get_property(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.systemd.test", "Something", &error, &reply, "s");
        assert_se(r >= 0);

        r = sd_bus_message_read(reply, "s", &s);
        assert_se(r >= 0);
        assert_se(streq(s, "<<<hallo>>>"));

        reply = sd_bus_message_unref(reply);

        r = sd_bus_set_property(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.systemd.test", "Something", &error, "s", "test");
        assert_se(r >= 0);

        r = sd_bus_get_property(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.systemd.test", "Something", &error, &reply, "s");
        assert_se(r >= 0);

        r = sd_bus_message_read(reply, "s", &s);
        assert_se(r >= 0);
        assert_se(streq(s, "test"));

        reply = sd_bus_message_unref(reply);

        r = sd_bus_set_property(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.systemd.test", "AutomaticIntegerProperty", &error, "u", 815);
        assert_se(r >= 0);

        assert_se(c->automatic_integer_property == 815);

        r = sd_bus_set_property(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.systemd.test", "AutomaticStringProperty", &error, "s", "Du Dödel, Du!");
        assert_se(r >= 0);

        assert_se(streq(c->automatic_string_property, "Du Dödel, Du!"));

        r = sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.DBus.Introspectable", "Introspect", &error, &reply, "");
        assert_se(r >= 0);

        r = sd_bus_message_read(reply, "s", &s);
        assert_se(r >= 0);
        fputs(s, stdout);

        reply = sd_bus_message_unref(reply);

        r = sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.DBus.Introspectable", "Introspect", &error, &reply, NULL); /* NULL and "" are equivalent */
        assert_se(r >= 0);

        r = sd_bus_message_read(reply, "s", &s);
        assert_se(r >= 0);
        fputs(s, stdout);

        reply = sd_bus_message_unref(reply);

        r = sd_bus_get_property(bus, "org.freedesktop.systemd.test", "/value/xuzz", "org.freedesktop.systemd.ValueTest", "Value", &error, &reply, "s");
        assert_se(r >= 0);

        r = sd_bus_message_read(reply, "s", &s);
        assert_se(r >= 0);
        log_info("read %s", s);

        reply = sd_bus_message_unref(reply);

        r = sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/", "org.freedesktop.DBus.Introspectable", "Introspect", &error, &reply, NULL);
        assert_se(r >= 0);

        r = sd_bus_message_read(reply, "s", &s);
        assert_se(r >= 0);
        fputs(s, stdout);

        reply = sd_bus_message_unref(reply);

        r = sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/value", "org.freedesktop.DBus.Introspectable", "Introspect", &error, &reply, NULL);
        assert_se(r >= 0);

        r = sd_bus_message_read(reply, "s", &s);
        assert_se(r >= 0);
        fputs(s, stdout);

        reply = sd_bus_message_unref(reply);

        r = sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/value/a", "org.freedesktop.DBus.Introspectable", "Introspect", &error, &reply, NULL);
        assert_se(r >= 0);

        r = sd_bus_message_read(reply, "s", &s);
        assert_se(r >= 0);
        fputs(s, stdout);

        assert_se(lines = strv_split_newlines(s));
        assert_se(strv_contains(lines, " <node name=\"x\"/>"));
        assert_se(strv_contains(lines, " <node name=\"y\"/>"));
        assert_se(strv_contains(lines, " <node name=\"z\"/>"));
        lines = strv_free(lines);

        reply = sd_bus_message_unref(reply);

        r = sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/value/b", "org.freedesktop.DBus.Introspectable", "Introspect", &error, &reply, NULL);
        assert_se(r >= 0);

        r = sd_bus_message_read(reply, "s", &s);
        assert_se(r >= 0);
        fputs(s, stdout);

        assert_se(lines = strv_split_newlines(s));
        for (unsigned i = 0; i < 30; i++) {
                _cleanup_free_ char *n = NULL;

                assert_se(asprintf(&n, " <node name=\"%u\"/>", i) >= 0);
                assert_se(strv_contains(lines, n));
        }
        lines = strv_free(lines);

        reply = sd_bus_message_unref(reply);

        r = sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.DBus.Properties", "GetAll", &error, &reply, "s", NULL);
        assert_se(r >= 0);

        sd_bus_message_dump(reply, stdout, SD_BUS_MESSAGE_DUMP_WITH_HEADER);

        reply = sd_bus_message_unref(reply);

        r = sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/value/a", "org.freedesktop.DBus.Properties", "GetAll", &error, &reply, "s", "org.freedesktop.systemd.ValueTest2");
        assert_se(r < 0);
        assert_se(sd_bus_error_has_name(&error, SD_BUS_ERROR_UNKNOWN_INTERFACE));
        sd_bus_error_free(&error);

        r = sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.DBus.ObjectManager", "GetManagedObjects", &error, &reply, NULL);
        assert_se(r < 0);
        assert_se(sd_bus_error_has_name(&error, SD_BUS_ERROR_UNKNOWN_METHOD));
        sd_bus_error_free(&error);

        r = sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/value", "org.freedesktop.DBus.ObjectManager", "GetManagedObjects", &error, &reply, NULL);
        assert_se(r >= 0);

        sd_bus_message_dump(reply, stdout, SD_BUS_MESSAGE_DUMP_WITH_HEADER);

        /* Check that /value/b does not have ObjectManager interface but /value/a does */
        assert_se(sd_bus_message_rewind(reply, 1) > 0);
        assert_se(sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "{oa{sa{sv}}}") > 0);
        while (ASSERT_SE_NONNEG(sd_bus_message_enter_container(reply, SD_BUS_TYPE_DICT_ENTRY, "oa{sa{sv}}")) > 0) {
                const char *path = NULL;
                assert_se(sd_bus_message_read_basic(reply, 'o', &path) > 0);
                if (STR_IN_SET(path, "/value/b", "/value/a")) {
                        /* Check that there is no object manager interface here */
                        bool found_object_manager_interface = false;
                        assert_se(sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "{sa{sv}}") > 0);
                        while (ASSERT_SE_NONNEG(sd_bus_message_enter_container(reply, SD_BUS_TYPE_DICT_ENTRY, "sa{sv}")) > 0) {
                                const char *interface_name = NULL;
                                assert_se(sd_bus_message_read_basic(reply, 's', &interface_name) > 0);

                                if (streq(interface_name, "org.freedesktop.DBus.ObjectManager")) {
                                        assert_se(!streq(path, "/value/b"));
                                        found_object_manager_interface = true;
                                }

                                assert_se(sd_bus_message_skip(reply, "a{sv}") >= 0);
                                assert_se(sd_bus_message_exit_container(reply) >= 0);
                        }
                        assert_se(sd_bus_message_exit_container(reply) >= 0);

                        if (streq(path, "/value/a"))
                                /* ObjectManager must be here */
                                assert_se(found_object_manager_interface);

                } else
                        assert_se(sd_bus_message_skip(reply, "a{sa{sv}}") >= 0);

                assert_se(sd_bus_message_exit_container(reply) >= 0);
        }

        reply = sd_bus_message_unref(reply);

        r = sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/value/a", "org.freedesktop.systemd.ValueTest", "NotifyTest", &error, NULL, NULL);
        assert_se(r >= 0);

        r = sd_bus_process(bus, &reply);
        assert_se(r > 0);

        assert_se(sd_bus_message_is_signal(reply, "org.freedesktop.DBus.Properties", "PropertiesChanged"));
        sd_bus_message_dump(reply, stdout, SD_BUS_MESSAGE_DUMP_WITH_HEADER);

        reply = sd_bus_message_unref(reply);

        r = sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/value/a", "org.freedesktop.systemd.ValueTest", "NotifyTest2", &error, NULL, NULL);
        assert_se(r >= 0);

        r = sd_bus_process(bus, &reply);
        assert_se(r > 0);

        assert_se(sd_bus_message_is_signal(reply, "org.freedesktop.DBus.Properties", "PropertiesChanged"));
        sd_bus_message_dump(reply, stdout, SD_BUS_MESSAGE_DUMP_WITH_HEADER);

        reply = sd_bus_message_unref(reply);

        r = sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.systemd.test", "EmitInterfacesAdded", &error, NULL, NULL);
        assert_se(r >= 0);

        r = sd_bus_process(bus, &reply);
        assert_se(r > 0);

        assert_se(sd_bus_message_is_signal(reply, "org.freedesktop.DBus.ObjectManager", "InterfacesAdded"));
        sd_bus_message_dump(reply, stdout, SD_BUS_MESSAGE_DUMP_WITH_HEADER);

        reply = sd_bus_message_unref(reply);

        r = sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.systemd.test", "EmitInterfacesRemoved", &error, NULL, NULL);
        assert_se(r >= 0);

        r = sd_bus_process(bus, &reply);
        assert_se(r > 0);

        assert_se(sd_bus_message_is_signal(reply, "org.freedesktop.DBus.ObjectManager", "InterfacesRemoved"));
        sd_bus_message_dump(reply, stdout, SD_BUS_MESSAGE_DUMP_WITH_HEADER);

        reply = sd_bus_message_unref(reply);

        r = sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.systemd.test", "EmitObjectAdded", &error, NULL, NULL);
        assert_se(r >= 0);

        r = sd_bus_process(bus, &reply);
        assert_se(r > 0);

        assert_se(sd_bus_message_is_signal(reply, "org.freedesktop.DBus.ObjectManager", "InterfacesAdded"));
        sd_bus_message_dump(reply, stdout, SD_BUS_MESSAGE_DUMP_WITH_HEADER);

        /* Check if /value/a/x does not have org.freedesktop.DBus.ObjectManager */
        assert_se(sd_bus_message_rewind(reply, 1) >= 0);
        const char* should_be_value_a_x = NULL;
        assert_se(sd_bus_message_read_basic(reply, 'o', &should_be_value_a_x) > 0);
        assert_se(streq(should_be_value_a_x, "/value/a/x"));
        assert_se(sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "{sa{sv}}") > 0);
        while (ASSERT_SE_NONNEG(sd_bus_message_enter_container(reply, SD_BUS_TYPE_DICT_ENTRY, "sa{sv}")) > 0) {
                const char* interface_name = NULL;
                assert_se(sd_bus_message_read_basic(reply, 's', &interface_name) > 0);

                assert(!streq(interface_name, "org.freedesktop.DBus.ObjectManager"));

                assert_se(sd_bus_message_skip(reply, "a{sv}") >= 0);

                assert_se(sd_bus_message_exit_container(reply) >= 0);
        }

        reply = sd_bus_message_unref(reply);

        assert_se(sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.systemd.test", "EmitObjectWithManagerAdded", &error, NULL, NULL) >= 0);

        assert_se(sd_bus_process(bus, &reply) > 0);

        assert_se(sd_bus_message_is_signal(reply, "org.freedesktop.DBus.ObjectManager", "InterfacesAdded"));
        sd_bus_message_dump(reply, stdout, SD_BUS_MESSAGE_DUMP_WITH_HEADER);

        /* Check if /value/a has org.freedesktop.DBus.ObjectManager */
        assert_se(sd_bus_message_rewind(reply, 1) >= 0);
        const char* should_be_value_a = NULL;
        bool found_object_manager = false;
        assert_se(sd_bus_message_read_basic(reply, 'o', &should_be_value_a) > 0);
        assert_se(streq(should_be_value_a, "/value/a"));
        assert_se(sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "{sa{sv}}") > 0);
        while (ASSERT_SE_NONNEG(sd_bus_message_enter_container(reply, SD_BUS_TYPE_DICT_ENTRY, "sa{sv}")) > 0) {
                const char* interface_name = NULL;
                assert_se(sd_bus_message_read_basic(reply, 's', &interface_name));

                if (streq(interface_name, "org.freedesktop.DBus.ObjectManager")) {
                        found_object_manager = true;
                        break;
                }

                assert_se(sd_bus_message_skip(reply, "a{sv}") >= 0);

                assert_se(sd_bus_message_exit_container(reply) >= 0);
        }
        assert_se(found_object_manager);

        reply = sd_bus_message_unref(reply);

        r = sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.systemd.test", "EmitObjectRemoved", &error, NULL, NULL);
        assert_se(r >= 0);

        r = sd_bus_process(bus, &reply);
        assert_se(r > 0);

        assert_se(sd_bus_message_is_signal(reply, "org.freedesktop.DBus.ObjectManager", "InterfacesRemoved"));
        sd_bus_message_dump(reply, stdout, SD_BUS_MESSAGE_DUMP_WITH_HEADER);

        /* Check if /value/a/x does not have org.freedesktop.DBus.ObjectManager */
        assert_se(sd_bus_message_rewind(reply, 1) >= 0);
        should_be_value_a_x = NULL;
        assert_se(sd_bus_message_read_basic(reply, 'o', &should_be_value_a_x) > 0);
        assert_se(streq(should_be_value_a_x, "/value/a/x"));
        assert_se(sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "s") > 0);
        const char* deleted_interface_name = NULL;
        while (ASSERT_SE_NONNEG(sd_bus_message_read_basic(reply, 's', &deleted_interface_name)) > 0) {
                assert(!streq(deleted_interface_name, "org.freedesktop.DBus.ObjectManager"));
        }
        assert_se(sd_bus_message_exit_container(reply) >= 0);

        reply = sd_bus_message_unref(reply);

        r = sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.systemd.test", "Exit", &error, NULL, NULL);
        assert_se(r >= 0);

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
        assert_se(c.automatic_string_property = strdup("dudeldu"));

        assert_se(socketpair(AF_UNIX, SOCK_STREAM, 0, c.fds) >= 0);

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
