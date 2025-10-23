/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "alloc-util.h"
#include "build.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "log.h"
#include "main-func.h"
#include "sd-varlink.h"
#include "string-util.h"

static int metrics_on_query_reply(
                sd_varlink *link,
                sd_json_variant *parameters,
                const char *error_id,
                sd_varlink_reply_flags_t flags,
                void *userdata) {
        assert(link);

        if (error_id) {
                bool disconnect;

                disconnect = streq(error_id, SD_VARLINK_ERROR_DISCONNECTED);
                if (disconnect)
                        log_info("Disconnected.");
                else
                        log_error("Varlink error: %s", error_id);

                (void) sd_event_exit(ASSERT_PTR(sd_varlink_get_event(link)), disconnect ? EXIT_SUCCESS : EXIT_FAILURE);
                return 0;
        }

        sd_json_variant_dump(parameters, SD_JSON_FORMAT_PRETTY_AUTO|SD_JSON_FORMAT_COLOR_AUTO, stdout, NULL);

        if (sd_varlink_is_idle(link) > 0) // This was never true
                sd_event_exit(ASSERT_PTR(sd_varlink_get_event(link)), EXIT_SUCCESS);

        return 0;
}

static int metrics_call(const char *path, sd_event *event, sd_varlink *vl) {
        int r;

        assert(path);
        assert(event);

        r = sd_event_set_signal_exit(event, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable exit on SIGINT/SIGTERM: %m");

        r = sd_varlink_connect_address(&vl, path);
        if (r < 0)
                return log_debug_errno(r, "Unable to connect to %s: %m", path);

        r = sd_varlink_attach_event(vl, event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_debug_errno(r, "Failed to attach varlink connection to event loop: %m");

        r = sd_varlink_bind_reply(vl, metrics_on_query_reply);
        if (r < 0)
                return log_debug_errno(r, "Failed to bind reply callback: %m");

        r = sd_varlink_observe(vl, "io.systemd.Metrics.Describe", /* parameter */ NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to issue Describe() call: %m");

        return 0;
}

static int metrics_start_query(void) {
        _cleanup_closedir_ DIR *d = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        int r;

        d = opendir("/run/systemd/metrics/");
        if (!d) {
                if (errno == ENOENT)
                        return -ESRCH;

                return -errno;
        }

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to get event loop: %m");


        FOREACH_DIRENT(de, d, return -errno) {
                _cleanup_free_ char *p = NULL;
                _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;

                p = path_join("/run/systemd/metrics/", de->d_name);
                if (!p)
                        return -ENOMEM;

                if (de->d_type != DT_SOCK && de->d_type != DT_UNKNOWN)
                        continue;

                r = metrics_call(p, event, vl);
                if (r < 0)
                        return r;
        }

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        // r = sd_event_get_exit_code(event, &c);
        // if (r < 0)
        //         return log_error_errno(r, "Failed to get exit code: %m");

        return 0;
}

static int help(void) {
        printf("%s [OPTIONS...]\n\n"
               "Print metrics for all systemd components.\n\n"
               "  -h --help             Show this help\n"
               "     --version          Show package version\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100
        };

        static const struct option options[] = {
                { "help",          no_argument,       NULL, 'h'               },
                { "version",       no_argument,       NULL, ARG_VERSION       },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hp", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (optind < argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s takes no arguments.",
                                       program_invocation_short_name);

        return 1;
}

static int run(int argc, char *argv[]) {
        int r;

        /* This is mostly intended to be used for scripts which want
         * to detect whether we are being run in a virtualized
         * environment or not */

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = metrics_start_query();
        if (r < 0)
                return r;

        return 0;
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
