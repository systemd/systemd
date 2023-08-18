#include <getopt.h>
#include <stdio.h>

#include "sd-bus.h"
#include "sd-event.h"

#include "build.h"
#include "bus-object.h"
#include "bus-polkit.h"
#include "hashmap.h"
#include "parse-argument.h"
#include "main-func.h"
#include "missing_capability.h"
#include "user-util.h"

static bool arg_mock_polkit = false;

static int setup_bus(
                const char *name,
                const BusObjectImplementation *impl,
                void *context,
                sd_event *event,
                sd_bus **ret) {

        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        assert(name);
        assert(impl);
        assert(event);
        assert(ret);

        r = sd_bus_default_system(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to get system bus connection: %m");

        r = bus_add_implementation(bus, impl, context);
        if (r < 0)
                return r;

        r = sd_bus_request_name_async(bus, NULL, name, 0, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to request name: %m");

        r = sd_bus_attach_event(bus, event, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to attach bus to event loop: %m");

        *ret = TAKE_PTR(bus);

        return 0;
}

static int run_dbus_service(const char *name, const BusObjectImplementation *impl, void *context) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        assert(name);
        assert(impl);

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        r = sd_event_set_signal_exit(event, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable signal exit: %m");

        r = setup_bus(name, impl, context, event, &bus);
        if (r < 0)
                return r;

        r = bus_event_loop_with_idle(event, bus, name, (uint64_t) -1, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        return 0;
}

static int mock_polkit_method_check_authorization(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        const struct {
                const char *action;
                bool is_authorized;
                bool is_challenge;
        } actions[] = {
                { "io.systemd.test.TestBusPolkit-allowed",      true,   false },
                { "io.systemd.test.TestBusPolkit-denied",       false,  false },
                { "io.systemd.test.TestBusPolkit-interactive",  false,  true  },
        };

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        char *action;
        int r;

        assert(m);
        assert(error);

        r = sd_bus_message_skip(m, "(sa{sv})");
        if (r < 0)
                return r;

        r = sd_bus_message_read_basic(m, 's', &action);
        if (r < 0)
                return r;

        FOREACH_ARRAY(i, actions, ELEMENTSOF(actions))
                if (streq(action, i->action))
                        return sd_bus_reply_method_return(m, "(bba{ss})", i->is_authorized, i->is_challenge, NULL);

        return sd_bus_reply_method_errorf(m, SD_BUS_ERROR_INVALID_ARGS, "Unknown action %s", action);
}

static const sd_bus_vtable mock_polkit_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_METHOD_WITH_ARGS("CheckAuthorization",
                                SD_BUS_ARGS("(sa{sv})", subject, "s", action_id, "a{ss}", details, "u", flags, "s", cancellation_id),
                                SD_BUS_ARGS("(bba{ss})", result),
                                mock_polkit_method_check_authorization,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_VTABLE_END,
};

const BusObjectImplementation mock_polkit_object = {
        "/org/freedesktop/PolicyKit1/Authority",
        "org.freedesktop.PolicyKit1.Authority",
        .vtables = BUS_VTABLES(mock_polkit_vtable),
};

typedef struct TestServiceContext {
        Hashmap *registry;
} TestServiceContext;

static void test_service_context_done(TestServiceContext *c) {
        c->registry = bus_verify_polkit_async_registry_free(c->registry);
}

static int verify_polkit(sd_bus_message *m, const char *action, TestServiceContext *c, sd_bus_error *e) {
        assert(m);
        assert(action);
        assert(c);
        assert(e);

        return bus_verify_polkit_async(m, CAP_SYS_ADMIN, action, NULL, false, UID_INVALID, &c->registry, e);
}

static int test_service_method_test_no_polkit(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        int r;

        assert(m);
        assert(userdata);
        assert(error);

        r = verify_polkit(m, "io.systemd.test.TestBusPolkit-allowed", userdata, error);
        if (r < 0 && r != -EACCES)
                return r;
        if (r == 0)
                return 1; /* Will call us back */
        if (r > 0)
                return -EBADE;

        assert(r == -EACCES);
        return sd_bus_reply_method_return(m, NULL);
}

static int test_service_method_test_allowed(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        int r;

        assert(m);
        assert(userdata);
        assert(error);

        r = verify_polkit(m, "io.systemd.test.TestBusPolkit-allowed", userdata, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        assert(r > 0);
        return sd_bus_reply_method_return(m, NULL);
}

static int test_service_method_test_denied(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        int r;

        assert(m);
        assert(userdata);
        assert(error);

        r = verify_polkit(m, "io.systemd.test.TestBusPolkit-denied", userdata, error);
        if (r < 0 && r != -EACCES)
                return r;
        if (r == 0)
                return 1; /* Will call us back */
        if (r > 0)
                return -EBADE;

        assert(r == -EACCES);
        return sd_bus_reply_method_return(m, NULL);
}

static int test_service_method_test_interactive(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        int r;

        assert(m);
        assert(userdata);
        assert(error);

        r = verify_polkit(m, "io.systemd.test.TestBusPolkit-interactive", userdata, error);
        if (r < 0 && r != -EACCES)
                return r;
        if (r == 0)
                return 1; /* Will call us back */
        if (r > 0)
                return -EBADE;

        assert(r == -EACCES);
        return sd_bus_reply_method_return(m, NULL);
}

static int test_service_method_test_unknown(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        int r;

        assert(m);
        assert(userdata);
        assert(error);

        r = verify_polkit(m, "io.systemd.test.TestBusPolkit-unknown", userdata, error);
        if (r > 0 || r == -EACCES)
                return -EBADE;
        if (r == 0)
                return 1; /* Will call us back */
        if (!sd_bus_error_is_set(error))
                return -EBADE;

        assert(r < 0);
        return sd_bus_reply_method_return(m, NULL);
}

static const sd_bus_vtable test_service_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_METHOD_WITH_ARGS("TestNoPolkit",
                                SD_BUS_NO_ARGS,
                                SD_BUS_NO_ARGS,
                                test_service_method_test_no_polkit,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_METHOD_WITH_ARGS("TestAllowed",
                                SD_BUS_NO_ARGS,
                                SD_BUS_NO_ARGS,
                                test_service_method_test_allowed,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_METHOD_WITH_ARGS("TestDenied",
                                SD_BUS_NO_ARGS,
                                SD_BUS_NO_ARGS,
                                test_service_method_test_denied,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_METHOD_WITH_ARGS("TestInteractive",
                                SD_BUS_NO_ARGS,
                                SD_BUS_NO_ARGS,
                                test_service_method_test_interactive,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_METHOD_WITH_ARGS("TestUnknown",
                                SD_BUS_NO_ARGS,
                                SD_BUS_NO_ARGS,
                                test_service_method_test_unknown,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_VTABLE_END,
};

const BusObjectImplementation test_service_object = {
        "/io/systemd/test/TestBusPolkit",
        "io.systemd.test.TestBusPolkit",
        .vtables = BUS_VTABLES(test_service_vtable),
};

static int run_mock_polkit(void) {
        return run_dbus_service("org.freedesktop.PolicyKit1", &mock_polkit_object, NULL);
}

static int run_test_service(void) {
        _cleanup_(test_service_context_done) TestServiceContext context = {};

        return run_dbus_service("io.systemd.test.TestBusPolkit", &test_service_object, &context);
}

static int help(void) {
        printf("%s [OPTIONS...]\n\n"
               "Creates system user accounts.\n\n"
               "  -h --help                 Show this help\n"
               "     --version              Show package version\n"
               "     --mock-polkit          Show configuration files\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_MOCK_POLKIT,
        };

        static const struct option options[] = {
                { "help",         no_argument,       NULL, 'h'              },
                { "version",      no_argument,       NULL, ARG_VERSION      },
                { "mock-polkit",  no_argument,       NULL, ARG_MOCK_POLKIT  },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_MOCK_POLKIT:
                        arg_mock_polkit = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        return 1;
}

static int run(int argc, char *argv[]) {
        int r;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (arg_mock_polkit)
                return run_mock_polkit();

        return run_test_service();
}

DEFINE_MAIN_FUNCTION(run);
