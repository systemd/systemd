/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "sd-event.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "ansi-color.h"
#include "build.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "log.h"
#include "main-func.h"
#include "path-lookup.h"
#include "pretty-print.h"
#include "runtime-scope.h"
#include "sort-util.h"
#include "string-util.h"
#include "time-util.h"

#define MAX_CONCURRENT_METRICS_SOCKETS 20
#define TIMEOUT_USEC (30 * USEC_PER_SEC) /* 30 seconds */

static RuntimeScope arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;

typedef struct Context {
        unsigned n_open_connections;
        sd_json_variant **metrics;  /* Collected metrics for sorting */
        size_t n_metrics;
} Context;

static int metric_compare(sd_json_variant *const *a, sd_json_variant *const *b) {
        const char *name_a, *name_b, *object_a, *object_b;
        sd_json_variant *fields_a, *fields_b;
        _cleanup_free_ char *fields_str_a = NULL, *fields_str_b = NULL;
        int r;

        assert(a && *a);
        assert(b && *b);

        name_a = sd_json_variant_string(sd_json_variant_by_key(*a, "name"));
        name_b = sd_json_variant_string(sd_json_variant_by_key(*b, "name"));
        r = strcmp_ptr(name_a, name_b);
        if (r != 0)
                return r;

        object_a = sd_json_variant_string(sd_json_variant_by_key(*a, "object"));
        object_b = sd_json_variant_string(sd_json_variant_by_key(*b, "object"));
        r = strcmp_ptr(object_a, object_b);
        if (r != 0)
                return r;

        fields_a = sd_json_variant_by_key(*a, "fields");
        fields_b = sd_json_variant_by_key(*b, "fields");
        if (fields_a)
                (void) sd_json_variant_format(fields_a, 0, &fields_str_a);
        if (fields_b)
                (void) sd_json_variant_format(fields_b, 0, &fields_str_b);

        return strcmp_ptr(fields_str_a, fields_str_b);
}

static int metrics_on_query_reply(
                sd_varlink *link,
                sd_json_variant *parameters,
                const char *error_id,
                sd_varlink_reply_flags_t flags,
                void *userdata) {

        assert(link);

        Context *context = ASSERT_PTR(userdata);

        if (error_id) {
                if (streq(error_id, SD_VARLINK_ERROR_DISCONNECTED))
                        log_info("Varlink disconnected");
                else if (streq(error_id, SD_VARLINK_ERROR_TIMEOUT))
                        log_info("Varlink timed out");
                else
                        log_error("Varlink error: %s", error_id);

                goto finish;
        }

        /* Collect metrics for later sorting */
        if (!GREEDY_REALLOC(context->metrics, context->n_metrics + 1))
                return log_oom();
        context->metrics[context->n_metrics++] = sd_json_variant_ref(parameters);

finish:
        if (!FLAGS_SET(flags, SD_VARLINK_REPLY_CONTINUES)) {
                assert(context->n_open_connections > 0);
                context->n_open_connections--;

                if (context->n_open_connections == 0)
                        (void) sd_event_exit(ASSERT_PTR(sd_varlink_get_event(link)), EXIT_SUCCESS);
        }

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

static void context_done(Context *context) {
        assert(context);

        for (size_t i = 0; i < context->n_metrics; i++)
                sd_json_variant_unref(context->metrics[i]);
        free(context->metrics);
}

static void metrics_output_sorted(Context *context) {
        assert(context);

        if (context->n_metrics == 0)
                return;

        typesafe_qsort(context->metrics, context->n_metrics, metric_compare);

        FOREACH_ARRAY(m, context->metrics, context->n_metrics)
                sd_json_variant_dump(
                                *m,
                                SD_JSON_FORMAT_PRETTY_AUTO | SD_JSON_FORMAT_COLOR_AUTO | SD_JSON_FORMAT_FLUSH,
                                stdout,
                                NULL);
}

static int metrics_query(void) {
        _cleanup_closedir_ DIR *d = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_free_ char *metrics_path = NULL;
        int r;

        r = runtime_directory_generic(arg_runtime_scope, "systemd/report", &metrics_path);
        if (r < 0)
                return log_error_errno(r, "Failed to determine metrics directory path: %m");

        d = opendir(metrics_path);
        if (!d) {
                if (errno == ENOENT)
                        return 0;

                return log_error_errno(errno, "Failed to open directory %s: %m", metrics_path);
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

        FOREACH_DIRENT(de, d, return -errno) {
                _cleanup_free_ char *p = NULL;

                if (!IN_SET(de->d_type, DT_SOCK, DT_UNKNOWN))
                        continue;

                p = path_join(metrics_path, de->d_name);
                if (!p)
                        return log_oom();

                r = metrics_call(p, event, &varlinks[context.n_open_connections], &context);
                if (r < 0) {
                        log_error_errno(r, "Failed to connect to %s: %m", p);
                        continue;
                }

                if (++context.n_open_connections >= MAX_CONCURRENT_METRICS_SOCKETS) {
                        log_warning("Too many concurrent metrics sockets, stop iterating");
                        break;
                }
        }

        r = sd_event_loop(event);
        if (r < 0) {
                context_done(&context);
                return log_error_errno(r, "Failed to run event loop: %m");
        }

        metrics_output_sorted(&context);

        context_done(&context);

        return 0;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-report", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] \n\n"
               "%sPrint metrics for all system components.%s\n\n"
               "  -h --help             Show this help\n"
               "     --version          Show package version\n"
               "     --user             Connect to user service manager\n"
               "     --system           Connect to system service manager (default)\n"
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
                ARG_USER,
                ARG_SYSTEM,
        };

        static const struct option options[] = {
                { "help",    no_argument, NULL, 'h'         },
                { "version", no_argument, NULL, ARG_VERSION },
                { "user",    no_argument, NULL, ARG_USER    },
                { "system",  no_argument, NULL, ARG_SYSTEM  },
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
                case ARG_USER:
                        arg_runtime_scope = RUNTIME_SCOPE_USER;
                        break;
                case ARG_SYSTEM:
                        arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
                        break;
                case '?':
                        return -EINVAL;
                default:
                        assert_not_reached();
                }

        if (optind < argc)
                return log_error_errno(
                                SYNTHETIC_ERRNO(EINVAL),
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

        r = metrics_query();
        if (r < 0)
                return r;

        return 0;
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
