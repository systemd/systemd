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
#include "parse-argument.h"
#include "path-lookup.h"
#include "pretty-print.h"
#include "runtime-scope.h"
#include "set.h"
#include "sort-util.h"
#include "string-util.h"
#include "time-util.h"
#include "varlink-util.h"

#define METRICS_MAX 1024U
#define METRICS_LINKS_MAX 128U
#define TIMEOUT_USEC (30 * USEC_PER_SEC) /* 30 seconds */

static RuntimeScope arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
static sd_json_format_flags_t arg_json_format_flags = SD_JSON_FORMAT_PRETTY_AUTO|SD_JSON_FORMAT_COLOR_AUTO;

typedef struct Context {
        sd_event *event;
        Set *links;
        sd_json_variant **metrics;  /* Collected metrics for sorting */
        size_t n_metrics, n_skipped_metrics;
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
        } else if (context->n_metrics >= METRICS_MAX)
                context->n_skipped_metrics++;
        else {
                /* Collect metrics for later sorting */
                if (!GREEDY_REALLOC(context->metrics, context->n_metrics + 1))
                        return log_oom();
                context->metrics[context->n_metrics++] = sd_json_variant_ref(parameters);
        }

        if (!FLAGS_SET(flags, SD_VARLINK_REPLY_CONTINUES)) {
                assert_se(set_remove(context->links, link) == link);
                link = sd_varlink_close_unref(link);

                if (set_isempty(context->links))
                        (void) sd_event_exit(context->event, EXIT_SUCCESS);
        }

        return 0;
}

static int metrics_call(Context *context, const char *path) {
        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        int r;

        assert(context);
        assert(path);

        r = sd_varlink_connect_address(&vl, path);
        if (r < 0)
                return log_error_errno(r, "Unable to connect to %s: %m", path);

        (void) sd_varlink_set_userdata(vl, context);

        r = sd_varlink_set_relative_timeout(vl, TIMEOUT_USEC);
        if (r < 0)
                return log_error_errno(r, "Failed to set varlink timeout: %m");

        r = sd_varlink_attach_event(vl, context->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach varlink connection to event loop: %m");

        r = sd_varlink_bind_reply(vl, metrics_on_query_reply);
        if (r < 0)
                return log_error_errno(r, "Failed to bind reply callback: %m");

        r = sd_varlink_observe(vl, "io.systemd.Metrics.List", /* parameters= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to issue io.systemd.Metrics.List call: %m");

        if (set_ensure_put(&context->links, &varlink_hash_ops, vl) < 0)
                return log_oom();

        TAKE_PTR(vl);
        return 0;
}

static void context_done(Context *context) {
        assert(context);

        set_free(context->links);
        sd_json_variant_unref_many(context->metrics, context->n_metrics);
        sd_event_unref(context->event);
}

static int metrics_output_sorted(Context *context) {
        int r;

        assert(context);

        typesafe_qsort(context->metrics, context->n_metrics, metric_compare);

        FOREACH_ARRAY(m, context->metrics, context->n_metrics) {
                r = sd_json_variant_dump(
                                *m,
                                arg_json_format_flags | SD_JSON_FORMAT_FLUSH,
                                stdout,
                                /* prefix= */ NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to write JSON: %m");
        }

        if (context->n_metrics == 0)
                log_info("No metrics collected.");

        return 0;
}

static int metrics_query(void) {
        int r;

        _cleanup_free_ char *metrics_path = NULL;
        r = runtime_directory_generic(arg_runtime_scope, "systemd/report", &metrics_path);
        if (r < 0)
                return log_error_errno(r, "Failed to determine metrics directory path: %m");

        log_debug("Looking for reports in %s/", metrics_path);

        _cleanup_(context_done) Context context = {};

        r = sd_event_default(&context.event);
        if (r < 0)
                return log_error_errno(r, "Failed to get event loop: %m");

        r = sd_event_set_signal_exit(context.event, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable exit on SIGINT/SIGTERM: %m");

        size_t n_skipped_sources = 0;
        _cleanup_closedir_ DIR *d = opendir(metrics_path);
        if (!d) {
                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to open metrics directory %s: %m", metrics_path);
        } else {
                FOREACH_DIRENT(de, d,
                               return log_warning_errno(errno, "Failed to read %s: %m", metrics_path)) {

                        if (!IN_SET(de->d_type, DT_SOCK, DT_UNKNOWN))
                                continue;

                        if (set_size(context.links) >= METRICS_LINKS_MAX) {
                                n_skipped_sources++;
                                break;
                        }

                        _cleanup_free_ char *p = path_join(metrics_path, de->d_name);
                        if (!p)
                                return log_oom();

                        (void) metrics_call(&context, p);
                }
        }

        if (set_isempty(context.links))
                log_info("No metrics sources found.");
        else {
                r = sd_event_loop(context.event);
                if (r < 0)
                        return log_error_errno(r, "Failed to run event loop: %m");

                r = metrics_output_sorted(&context);
                if (r < 0)
                        return r;

                if (n_skipped_sources > 0)
                        log_warning("Too many metrics sources, only %u sources contacted, %zu sources skipped.", set_size(context.links), n_skipped_sources);
                if (context.n_skipped_metrics > 0)
                        log_warning("Too many metrics, only %zu metrics collected, %zu metrics skipped.", context.n_metrics, context.n_skipped_metrics);

                if (n_skipped_sources > 0 ||
                    context.n_skipped_metrics > 0)
                        return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
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
               "     --json=pretty|short\n"
               "                        Configure JSON output\n"
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
                ARG_JSON,
        };

        static const struct option options[] = {
                { "help",    no_argument,       NULL, 'h'         },
                { "version", no_argument,       NULL, ARG_VERSION },
                { "user",    no_argument,       NULL, ARG_USER    },
                { "system",  no_argument,       NULL, ARG_SYSTEM  },
                { "json",    required_argument, NULL, ARG_JSON    },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)
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

                case ARG_JSON:
                        r = parse_json_argument(optarg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;

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

        return metrics_query();
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
