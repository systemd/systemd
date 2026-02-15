/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <stdbool.h>

#include "sd-bus.h"
#include "sd-event.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "ansi-color.h"
#include "build.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-util.h"
#include "daemon-util.h"
#include "errno-util.h"
#include "log.h"
#include "main-func.h"
#include "parse-argument.h"
#include "pretty-print.h"
#include "printk-util.h"
#include "varlink-io.systemd.MuteConsole.h"
#include "varlink-util.h"
#include "virt.h"

static bool arg_mute_pid1 = true;
static bool arg_mute_kernel = true;
static bool arg_varlink = false;

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-mute-console", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...]\n"
               "\n%sMute status output to the console.%s\n\n"
               "  -h --help            Show this help\n"
               "     --version         Show package version\n"
               "     --kernel=BOOL     Mute kernel log output\n"
               "     --pid1=BOOL       Mute PID 1 status output\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_KERNEL,
                ARG_PID1,
        };

        static const struct option options[] = {
                { "help",    no_argument,       NULL, 'h'           },
                { "version", no_argument,       NULL, ARG_VERSION   },
                { "kernel",  required_argument, NULL, ARG_KERNEL    },
                { "pid1",    required_argument, NULL, ARG_PID1      },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_PID1:
                        r = parse_boolean_argument("--pid1=", optarg, &arg_mute_pid1);
                        if (r < 0)
                                return r;

                        break;

                case ARG_KERNEL:
                        r = parse_boolean_argument("--kernel=", optarg, &arg_mute_kernel);
                        if (r < 0)
                                return r;

                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }
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

typedef struct Context {
        bool mute_pid1;
        bool mute_kernel;

        bool muted_pid1;
        int saved_kernel;

        sd_varlink *link;
} Context;

static int mute_pid1(Context *c) {
        int r;

        assert(c);

        if (!c->mute_pid1) {
                log_debug("Muting of PID 1 status console output disabled.");
                c->muted_pid1 = false;
                return 0;
        }

        r = set_show_status("no");
        if (r < 0)
                return r;

        log_debug("Successfully muted PID 1 status console output.");

        c->muted_pid1 = true;
        return 0;
}

static int unmute_pid1(Context *c) {
        int r;

        assert(c);

        if (!c->muted_pid1) {
                if (c->mute_pid1)
                        log_debug("Not restoring PID 1 status console output level.");
                return 0;
        }

        r = set_show_status("");
        if (r < 0)
                return r;

        log_debug("Successfully unmuted PID 1 status console output.");
        c->muted_pid1 = false;
        return 0;
}

static int mute_kernel(Context *c) {
        int r;

        assert(c);

        if (!c->mute_kernel) {
                log_debug("Muting of kernel printk() console output disabled.");
                c->saved_kernel = -1;
                return 0;
        }

        if (detect_container() > 0) {
                log_debug("Skipping muting of printk() console output, because running in a container.");

                c->mute_kernel = false;
                c->saved_kernel = -1;
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

static int unmute_kernel(Context *c) {
        int r;

        assert(c);

        if (c->saved_kernel < 0) {
                if (c->mute_kernel)
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

static void vl_on_disconnect(sd_varlink_server *server, sd_varlink *link, void *userdata) {
        assert(link);

        Context *c = sd_varlink_get_userdata(link);
        if (!c)
                return;

        (void) unmute_pid1(c);
        (void) unmute_kernel(c);

        (void) sd_varlink_set_userdata(c->link, NULL);
        sd_varlink_flush_close_unref(c->link);

        free(c);
}

static int vl_method_mute(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        int r;

        assert(link);
        assert(FLAGS_SET(flags, SD_VARLINK_METHOD_MORE));

        _cleanup_free_ Context *nc = new(Context, 1);
        if (!nc)
                return -ENOMEM;

        *nc = (Context) {
                .mute_pid1 = true,
                .mute_kernel = true,
                .saved_kernel = -1,
        };

        static const sd_json_dispatch_field dispatch_table[] = {
                { "kernel", SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(Context, mute_kernel), 0 },
                { "pid1",   SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(Context, mute_pid1),   0 },
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, nc);
        if (r != 0)
                return r;

        r = sd_varlink_server_bind_disconnect(sd_varlink_get_server(link), vl_on_disconnect);
        if (r < 0)
                return r;

        (void) sd_varlink_set_userdata(link, nc);
        nc->link = sd_varlink_ref(link);
        Context *c = TAKE_PTR(nc); /* the Context object is now managed by the disconnect handler, not us anymore */

        r = 0;
        RET_GATHER(r, mute_pid1(c));
        RET_GATHER(r, mute_kernel(c));
        if (r < 0)
                return r;

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
        int r;

        /* Invocation as Varlink service */

        r = varlink_server_new(
                        &varlink_server,
                        SD_VARLINK_SERVER_ROOT_ONLY|
                        SD_VARLINK_SERVER_HANDLE_SIGINT|
                        SD_VARLINK_SERVER_HANDLE_SIGTERM,
                        /* userdata= */ NULL);
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
                .mute_pid1 = arg_mute_pid1,
                .mute_kernel = arg_mute_kernel,
                .saved_kernel = -1,
        };

        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        r = sd_event_new(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to get default event source: %m");

        (void) sd_event_set_watchdog(event, true);
        (void) sd_event_set_signal_exit(event, true);

        int ret = 0;
        RET_GATHER(ret, mute_pid1(&c));
        RET_GATHER(ret, mute_kernel(&c));

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

        RET_GATHER(ret, unmute_pid1(&c));
        RET_GATHER(ret, unmute_kernel(&c));

        return ret;
}

DEFINE_MAIN_FUNCTION(run);
