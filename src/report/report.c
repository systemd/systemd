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
#include "sd-event.h"
#include "time-util.h"

#define RUN_SYSTEMD_METRICS_PATH "/run/systemd/metrics/"
#define MAX_CONCURRENT_METRICS_SOCKETS 20
#define TIMEOUT_USEC (30*USEC_PER_SEC) /* 30 seconds */

typedef struct Context {
        int n_ref;
} Context;

static int metrics_on_query_reply(
                sd_varlink *link,
                sd_json_variant *parameters,
                const char *error_id,
                sd_varlink_reply_flags_t flags,
                void *userdata) {
        assert(link);

        Context* context = ASSERT_PTR(userdata);

        if (error_id) {
                if (streq(error_id, SD_VARLINK_ERROR_DISCONNECTED))
                        log_info("Varlink disconnected");
                else if (streq(error_id, SD_VARLINK_ERROR_TIMEOUT))
                        log_info("Varlink timed out");
                else
                        log_error("Varlink error: %s", error_id);

                goto finish;
        }

        sd_json_variant_dump(parameters, SD_JSON_FORMAT_PRETTY_AUTO|SD_JSON_FORMAT_COLOR_AUTO, stdout, NULL);

        fflush(stdout);

finish:
        if (!FLAGS_SET(flags, SD_VARLINK_REPLY_CONTINUES) && (--context->n_ref == 0))
                (void) sd_event_exit(ASSERT_PTR(sd_varlink_get_event(link)), EXIT_SUCCESS);

        return 0;
}

static int metrics_call(const char *path, sd_event *event, sd_varlink **ret, Context *context) {
        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        int r;

        assert(path);
        assert(event);
        assert(ret);
        assert(context);

        r = sd_varlink_connect_address(&vl, path);
        if (r < 0)
                return log_debug_errno(r, "Unable to connect to %s: %m", path);

        (void) sd_varlink_set_userdata(vl, context);

        r = sd_varlink_set_relative_timeout(vl, TIMEOUT_USEC);
        if (r < 0)
                return log_error_errno(r, "Failed to set varlink timeout: %m");

        r = sd_varlink_attach_event(vl, event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_debug_errno(r, "Failed to attach varlink connection to event loop: %m");

        r = sd_varlink_bind_reply(vl, metrics_on_query_reply);
        if (r < 0)
                return log_debug_errno(r, "Failed to bind reply callback: %m");

        r = sd_varlink_observe(vl, "io.systemd.Metrics.List", /* parameters= */ NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to issue io.systemd.Metrics.List call: %m");

        *ret = TAKE_PTR(vl);

        return 0;
}

static void sd_varlink_unref_many(sd_varlink **array, size_t n) {
        assert(array);

        FOREACH_ARRAY(v, array, n)
                sd_varlink_unref(*v);

        free(array);
}

static int metrics_start_query(void) {
        _cleanup_closedir_ DIR *d = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        int r;

        d = opendir(RUN_SYSTEMD_METRICS_PATH);
        if (!d) {
                if (errno == ENOENT)
                        return log_error_errno(ENOENT, "No metrics sockets found: %m");

                return log_error_errno(errno, "Failed to open directory %s: %m", RUN_SYSTEMD_METRICS_PATH);
        }

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to get event loop: %m");

        r = sd_event_set_signal_exit(event, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable exit on SIGINT/SIGTERM: %m");

        size_t n_varlinks = MAX_CONCURRENT_METRICS_SOCKETS;
        sd_varlink **varlinks = new0(sd_varlink *, n_varlinks);
        if (!varlinks)
                return log_error_errno(ENOMEM, "Failed to allocate varlinks array: %m");

        CLEANUP_ARRAY(varlinks, n_varlinks, sd_varlink_unref_many);

        Context context = {};
        int i = 0;

        FOREACH_DIRENT(de, d, return -errno) {
                _cleanup_free_ char *p = NULL;

                if (de->d_type != DT_SOCK && de->d_type != DT_UNKNOWN)
                        continue;

                p = path_join(RUN_SYSTEMD_METRICS_PATH, de->d_name);
                if (!p)
                        return log_error_errno(ENOMEM, "Failed to allocate path: %m");

                r = metrics_call(p, event, &varlinks[i], &context);
                if (r < 0) {
                        log_error_errno(r, "Failed to connect to %s: %m", p);
                        continue;
                }

                context.n_ref++;

                if (++i >= MAX_CONCURRENT_METRICS_SOCKETS) {
                        log_warning("Too many concurrent metrics sockets, stop iterating");
                        break;
                }
        }

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

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
