/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdbool.h>

#include "sd-bus.h"
#include "sd-event.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "build.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-util.h"
#include "daemon-util.h"
#include "errno-util.h"
#include "log.h"
#include "main-func.h"
#include "parse-argument.h"
#include "printk-util.h"
#include "varlink-io.systemd.MuteConsole.h"
#include "varlink-util.h"
#include "verbs.h"
#include "virt.h"

static bool arg_mute_pid1 = true;
static bool arg_mute_kernel = true;
static bool arg_varlink = false;

COMMAND(
        "systemd-mute-console\0",
        "Mute status output to the console.",
        .man_pages = "systemd-mute-console(1)\0",
);

static int parse_argv(int argc, char *argv[]) {
        assert(argc >= 0);
        assert(argv);

        OptionParser opts = { argc, argv };
        int r;

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return command_print_help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_LONG("kernel", "BOOL", "Mute kernel log output"):
                        r = parse_boolean_argument("--kernel=", opts.arg, &arg_mute_kernel);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("pid1", "BOOL", "Mute PID 1 status output"):
                        r = parse_boolean_argument("--pid1=", opts.arg, &arg_mute_pid1);
                        if (r < 0)
                                return r;
                        break;

                OPTION_COMMON_INTROSPECT_CLI:
                        return introspect_cli(SD_JSON_FORMAT_OFF);
                }

        r = sd_varlink_invocation(SD_VARLINK_ALLOW_ACCEPT);
        if (r < 0)
                return log_error_errno(r, "Failed to check if invoked in Varlink mode: %m");
        if (r > 0)
                arg_varlink = true;

        return 1;
}

static int set_show_status(const char *value) {
        int r;
        assert(value);

        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        r = bus_connect_system_systemd(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to systemd: %m");

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        r = bus_call_method(bus, bus_systemd_mgr, "SetShowStatus", &error, /* ret_reply= */ NULL, "s", value);
        if (r < 0)
                return log_error_errno(r, "Failed to issue SetShowStatus() method call: %s", bus_error_message(&error, r));

        return 0;
}

/* Muting is refcounted, so that several clients can hold it at the same time: the outputs are muted when
 * the first client asks for it, and restored when the last one goes away. */
typedef struct Context {
        unsigned n_muted_pid1;
        unsigned n_muted_kernel;

        int saved_kernel;
} Context;

/* Per Varlink connection: what this client holds a reference on. */
typedef struct Request {
        bool muted_pid1;
        bool muted_kernel;

        /* sd-varlink fails a method call which neither got a final reply nor had its connection referenced
         * by the callback. This keeps the call open until the client disconnects. */
        sd_varlink *link;
} Request;

/* Returns > 0 if a reference was taken, 0 if muting is disabled. */
static int mute_pid1(Context *c, bool enable) {
        int r;

        assert(c);

        if (!enable) {
                log_debug("Muting of PID 1 status console output disabled.");
                return 0;
        }

        if (c->n_muted_pid1 == 0) {
                r = set_show_status("no");
                if (r < 0)
                        return r;

                log_debug("Successfully muted PID 1 status console output.");
        }

        c->n_muted_pid1++;
        return 1;
}

static int unmute_pid1(Context *c) {
        int r;

        assert(c);
        assert(c->n_muted_pid1 > 0);

        if (--c->n_muted_pid1 > 0)
                return 0;

        r = set_show_status("");
        if (r < 0)
                return r;

        log_debug("Successfully unmuted PID 1 status console output.");
        return 0;
}

static int mute_kernel_now(Context *c) {
        int r;

        assert(c);

        if (detect_container() > 0) {
                log_debug("Skipping muting of printk() console output, because running in a container.");
                return 0;
        }

        int level = sysctl_printk_read();
        if (level < 0)
                return log_error_errno(level, "Failed to read kernel printk() console output level: %m");

        if (level == 0) {
                log_info("Not muting kernel printk() console output, since it is already disabled.");
                c->saved_kernel = -1; /* don't bother with restoring */
        } else {
                r = sysctl_printk_write(0);
                if (r < 0)
                        return log_error_errno(r, "Failed to change kernel printk() console output level: %m");

                log_debug("Successfully muted kernel printk() console output.");
                c->saved_kernel = level;
        }

        return 0;
}

static int unmute_kernel_now(Context *c) {
        int r;

        assert(c);

        if (c->saved_kernel < 0) {
                log_debug("Not restoring kernel printk() console output level.");
                return 0;
        }

        int level = sysctl_printk_read();
        if (level < 0)
                return log_error_errno(level, "Failed to read kernel printk() console output level: %m");

        if (level != 0) {
                log_info("Not unmuting kernel printk() console output, since it has been changed externally in the meantime.");
                return 0;
        }

        r = sysctl_printk_write(c->saved_kernel);
        if (r < 0)
                return log_error_errno(r, "Failed to unmute kernel printk() console output level: %m");

        log_debug("Successfully unmuted kernel printk() console output.");
        c->saved_kernel = -1;
        return 0;
}

/* Returns > 0 if a reference was taken, 0 if muting is disabled. */
static int mute_kernel(Context *c, bool enable) {
        int r;

        assert(c);

        if (!enable) {
                log_debug("Muting of kernel printk() console output disabled.");
                return 0;
        }

        if (c->n_muted_kernel == 0) {
                r = mute_kernel_now(c);
                if (r < 0)
                        return r;
        }

        c->n_muted_kernel++;
        return 1;
}

static int unmute_kernel(Context *c) {
        assert(c);
        assert(c->n_muted_kernel > 0);

        if (--c->n_muted_kernel > 0)
                return 0;

        return unmute_kernel_now(c);
}

static void vl_on_disconnect(sd_varlink_server *server, sd_varlink *link, void *userdata) {
        Context *c = ASSERT_PTR(userdata);

        assert(link);

        _cleanup_free_ Request *req = sd_varlink_set_userdata(link, NULL);
        if (!req)
                return;

        if (req->muted_pid1)
                (void) unmute_pid1(c);
        if (req->muted_kernel)
                (void) unmute_kernel(c);

        sd_varlink_flush_close_unref(req->link);
}

static int vl_method_mute(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        struct {
                bool pid1;
                bool kernel;
        } p = {
                .pid1 = true,
                .kernel = true,
        };
        int r;

        assert(link);
        assert(FLAGS_SET(flags, SD_VARLINK_METHOD_MORE));

        Context *c = ASSERT_PTR(sd_varlink_server_get_userdata(sd_varlink_get_server(link)));

        /* Refuse multiple requests per connection. */
        if (sd_varlink_get_userdata(link))
                return -EBUSY;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "kernel", SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, voffsetof(p, kernel), 0 },
                { "pid1",   SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, voffsetof(p, pid1),   0 },
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        Request *req = new(Request, 1);
        if (!req)
                return -ENOMEM;

        *req = (Request) {
                .link = sd_varlink_ref(link),
        };

        /* The Request object is now owned by the link, and released by the disconnect handler */
        (void) sd_varlink_set_userdata(link, req);

        r = mute_pid1(c, p.pid1);
        if (r < 0)
                return r;
        req->muted_pid1 = r > 0;

        r = mute_kernel(c, p.kernel);
        if (r < 0) {
                /* Don't keep a failed request's PID 1 mute around until the client disconnects. */
                if (req->muted_pid1) {
                        (void) unmute_pid1(c);
                        req->muted_pid1 = false;
                }
                return r;
        }
        req->muted_kernel = r > 0;

        /* Let client know we are muted now. We use sd_varlink_notify() here (rather than sd_varlink_reply())
         * because we want to keep the method call open, as we want that the lifetime of the
         * connection/method call to determine how long we keep the console muted. */
        r = sd_varlink_notify(link, /* parameters= */ NULL);
        if (r < 0)
                return r;

        return 0;
}

static int vl_server(void) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *varlink_server = NULL;
        Context c = {
                .saved_kernel = -1,
        };
        int r;

        /* Invocation as Varlink service */

        r = varlink_server_new(
                        &varlink_server,
                        SD_VARLINK_SERVER_ROOT_ONLY |
                        SD_VARLINK_SERVER_MYSELF_ONLY |
                        SD_VARLINK_SERVER_HANDLE_SIGINT |
                        SD_VARLINK_SERVER_HANDLE_SIGTERM,
                        &c);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface(varlink_server, &vl_interface_io_systemd_MuteConsole);
        if (r < 0)
                return log_error_errno(r, "Failed to add Varlink interface: %m");

        r = sd_varlink_server_bind_method_many(
                        varlink_server,
                        "io.systemd.MuteConsole.Mute", vl_method_mute);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink methods: %m");

        r = sd_varlink_server_bind_disconnect(varlink_server, vl_on_disconnect);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink disconnect handler: %m");

        r = sd_varlink_server_loop_auto(varlink_server);
        if (r < 0)
                return log_error_errno(r, "Failed to run Varlink event loop: %m");

        return 0;
}

static int run(int argc, char* argv[]) {
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (arg_varlink)
                return vl_server();

        if (!arg_mute_pid1 && !arg_mute_kernel)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Not asked to mute anything, refusing.");

        Context c = {
                .saved_kernel = -1,
        };

        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        r = sd_event_new(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to get default event source: %m");

        (void) sd_event_set_watchdog(event, true);
        (void) sd_event_set_signal_exit(event, true);

        int ret = 0;
        RET_GATHER(ret, mute_pid1(&c, arg_mute_pid1));
        RET_GATHER(ret, mute_kernel(&c, arg_mute_kernel));

        /* Now tell service manager we are ready to go */
        _unused_ _cleanup_(notify_on_cleanup) const char *notify_message =
                notify_start("READY=1\n"
                             "STATUS=Console status output muted temporarily.",
                             "STOPPING=1\n"
                             "STATUS=Console status output unmuted.");

        /* Now wait for SIGINT/SIGTERM */
        r = sd_event_loop(event);
        if (r < 0)
                RET_GATHER(ret, log_error_errno(r, "Failed to run event loop: %m"));

        if (c.n_muted_pid1 > 0)
                RET_GATHER(ret, unmute_pid1(&c));
        if (c.n_muted_kernel > 0)
                RET_GATHER(ret, unmute_kernel(&c));

        return ret;
}

DEFINE_MAIN_FUNCTION(run);
