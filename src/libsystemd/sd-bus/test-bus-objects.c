/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <assert.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>

#include "log.h"
#include "util.h"
#include "macro.h"
#include "strv.h"

#include "sd-bus.h"
#include "bus-internal.h"
#include "bus-message.h"
#include "bus-util.h"
#include "bus-dump.h"

struct context {
        int fds[2];
        bool quit;
        char *something;
        char *automatic_string_property;
        uint32_t automatic_integer_property;
};

static int something_handler(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {
        struct context *c = userdata;
        const char *s;
        char *n = NULL;
        int r;

        r = sd_bus_message_read(m, "s", &s);
        assert_se(r > 0);

        n = strjoin("<<<", s, ">>>", NULL);
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

static int exit_handler(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {
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

static int notify_test(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {
        int r;

        assert_se(sd_bus_emit_properties_changed(bus, m->path, "org.freedesktop.systemd.ValueTest", "Value", NULL) >= 0);

        r = sd_bus_reply_method_return(m, NULL);
        assert_se(r >= 0);

        return 1;
}

static int notify_test2(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {
        int r;

        assert_se(sd_bus_emit_properties_changed_strv(bus, m->path, "org.freedesktop.systemd.ValueTest", NULL) >= 0);

        r = sd_bus_reply_method_return(m, NULL);
        assert_se(r >= 0);

        return 1;
}

static int emit_interfaces_added(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {
        int r;

        assert_se(sd_bus_emit_interfaces_added(bus, m->path, "org.freedesktop.systemd.test", NULL) >= 0);

        r = sd_bus_reply_method_return(m, NULL);
        assert_se(r >= 0);

        return 1;
}

static int emit_interfaces_removed(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {
        int r;

        assert_se(sd_bus_emit_interfaces_removed(bus, m->path, "org.freedesktop.systemd.test", NULL) >= 0);

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
        SD_BUS_VTABLE_END
};

static int enumerator_callback(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error) {

        if (object_path_startswith("/value", path))
                assert_se(*nodes = strv_new("/value/a", "/value/b", "/value/c", NULL));

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
        assert_se(sd_bus_add_object_manager(bus, NULL, "/value") >= 0);

        assert_se(sd_bus_start(bus) >= 0);

        log_error("Entering event loop on server");

        while (!c->quit) {
                log_error("Loop!");

                r = sd_bus_process(bus, NULL);
                if (r < 0) {
                        log_error("Failed to process requests: %s", strerror(-r));
                        goto fail;
                }

                if (r == 0) {
                        r = sd_bus_wait(bus, (uint64_t) -1);
                        if (r < 0) {
                                log_error("Failed to wait: %s", strerror(-r));
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
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_bus_unref_ sd_bus *bus = NULL;
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
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

        sd_bus_message_unref(reply);
        reply = NULL;

        r = sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.systemd.test", "Doesntexist", &error, &reply, "");
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

        sd_bus_message_unref(reply);
        reply = NULL;

        r = sd_bus_set_property(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.systemd.test", "Something", &error, "s", "test");
        assert_se(r >= 0);

        r = sd_bus_get_property(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.systemd.test", "Something", &error, &reply, "s");
        assert_se(r >= 0);

        r = sd_bus_message_read(reply, "s", &s);
        assert_se(r >= 0);
        assert_se(streq(s, "test"));

        sd_bus_message_unref(reply);
        reply = NULL;

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

        sd_bus_message_unref(reply);
        reply = NULL;

        r = sd_bus_get_property(bus, "org.freedesktop.systemd.test", "/value/xuzz", "org.freedesktop.systemd.ValueTest", "Value", &error, &reply, "s");
        assert_se(r >= 0);

        r = sd_bus_message_read(reply, "s", &s);
        assert_se(r >= 0);
        log_info("read %s", s);

        sd_bus_message_unref(reply);
        reply = NULL;

        r = sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/", "org.freedesktop.DBus.Introspectable", "Introspect", &error, &reply, "");
        assert_se(r >= 0);

        r = sd_bus_message_read(reply, "s", &s);
        assert_se(r >= 0);
        fputs(s, stdout);

        sd_bus_message_unref(reply);
        reply = NULL;

        r = sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/value", "org.freedesktop.DBus.Introspectable", "Introspect", &error, &reply, "");
        assert_se(r >= 0);

        r = sd_bus_message_read(reply, "s", &s);
        assert_se(r >= 0);
        fputs(s, stdout);

        sd_bus_message_unref(reply);
        reply = NULL;

        r = sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/value/a", "org.freedesktop.DBus.Introspectable", "Introspect", &error, &reply, "");
        assert_se(r >= 0);

        r = sd_bus_message_read(reply, "s", &s);
        assert_se(r >= 0);
        fputs(s, stdout);

        sd_bus_message_unref(reply);
        reply = NULL;

        r = sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.DBus.Properties", "GetAll", &error, &reply, "s", "");
        assert_se(r >= 0);

        bus_message_dump(reply, stdout, true);

        sd_bus_message_unref(reply);
        reply = NULL;

        r = sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/value/a", "org.freedesktop.DBus.Properties", "GetAll", &error, &reply, "s", "org.freedesktop.systemd.ValueTest2");
        assert_se(r < 0);
        assert_se(sd_bus_error_has_name(&error, SD_BUS_ERROR_UNKNOWN_INTERFACE));
        sd_bus_error_free(&error);

        r = sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.DBus.ObjectManager", "GetManagedObjects", &error, &reply, "");
        assert_se(r < 0);
        assert_se(sd_bus_error_has_name(&error, SD_BUS_ERROR_UNKNOWN_METHOD));
        sd_bus_error_free(&error);

        r = sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/value", "org.freedesktop.DBus.ObjectManager", "GetManagedObjects", &error, &reply, "");
        assert_se(r >= 0);

        bus_message_dump(reply, stdout, true);

        sd_bus_message_unref(reply);
        reply = NULL;

        r = sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/value/a", "org.freedesktop.systemd.ValueTest", "NotifyTest", &error, NULL, "");
        assert_se(r >= 0);

        r = sd_bus_process(bus, &reply);
        assert_se(r > 0);

        assert_se(sd_bus_message_is_signal(reply, "org.freedesktop.DBus.Properties", "PropertiesChanged"));
        bus_message_dump(reply, stdout, true);

        sd_bus_message_unref(reply);
        reply = NULL;

        r = sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/value/a", "org.freedesktop.systemd.ValueTest", "NotifyTest2", &error, NULL, "");
        assert_se(r >= 0);

        r = sd_bus_process(bus, &reply);
        assert_se(r > 0);

        assert_se(sd_bus_message_is_signal(reply, "org.freedesktop.DBus.Properties", "PropertiesChanged"));
        bus_message_dump(reply, stdout, true);

        sd_bus_message_unref(reply);
        reply = NULL;

        r = sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.systemd.test", "EmitInterfacesAdded", &error, NULL, "");
        assert_se(r >= 0);

        r = sd_bus_process(bus, &reply);
        assert_se(r > 0);

        assert_se(sd_bus_message_is_signal(reply, "org.freedesktop.DBus.ObjectManager", "InterfacesAdded"));
        bus_message_dump(reply, stdout, true);

        sd_bus_message_unref(reply);
        reply = NULL;

        r = sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.systemd.test", "EmitInterfacesRemoved", &error, NULL, "");
        assert_se(r >= 0);

        r = sd_bus_process(bus, &reply);
        assert_se(r > 0);

        assert_se(sd_bus_message_is_signal(reply, "org.freedesktop.DBus.ObjectManager", "InterfacesRemoved"));
        bus_message_dump(reply, stdout, true);

        sd_bus_message_unref(reply);
        reply = NULL;

        r = sd_bus_call_method(bus, "org.freedesktop.systemd.test", "/foo", "org.freedesktop.systemd.test", "Exit", &error, NULL, "");
        assert_se(r >= 0);

        sd_bus_flush(bus);

        return 0;
}

int main(int argc, char *argv[]) {
        struct context c = {};
        pthread_t s;
        void *p;
        int r, q;

        zero(c);

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
