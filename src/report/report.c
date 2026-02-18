/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "sd-event.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "ansi-color.h"
#include "build.h"
#include "chase.h"
#include "dirent-util.h"
#include "format-table.h"
#include "log.h"
#include "main-func.h"
#include "parse-argument.h"
#include "path-lookup.h"
#include "pretty-print.h"
#include "recurse-dir.h"
#include "runtime-scope.h"
#include "set.h"
#include "sort-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "verbs.h"

#define METRICS_MAX 1024U
#define METRICS_LINKS_MAX 128U
#define TIMEOUT_USEC (30 * USEC_PER_SEC) /* 30 seconds */

static PagerFlags arg_pager_flags = 0;
static RuntimeScope arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
static sd_json_format_flags_t arg_json_format_flags = SD_JSON_FORMAT_OFF|SD_JSON_FORMAT_PRETTY_AUTO|SD_JSON_FORMAT_COLOR_AUTO;

typedef enum Action {
        ACTION_LIST,
        ACTION_DESCRIBE,
        _ACTION_MAX,
        _ACTION_INVALID = -EINVAL,
} Action;

typedef struct Context {
        Action action;
        sd_event *event;
        Set *link_infos;
        sd_json_variant **metrics;  /* Collected metrics for sorting */
        size_t n_metrics, n_skipped_metrics, n_invalid_metrics;
} Context;

typedef struct LinkInfo {
        Context *context;
        sd_varlink *link;
        char *metric_prefix;
} LinkInfo;

static LinkInfo* link_info_free(LinkInfo *li) {
        if (!li)
                return NULL;

        sd_varlink_close_unref(li->link);
        free(li->metric_prefix);
        return mfree(li);
}

static void context_done(Context *context) {
        if (!context)
                return;

        set_free(context->link_infos);
        sd_json_variant_unref_many(context->metrics, context->n_metrics);
        sd_event_unref(context->event);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(LinkInfo*, link_info_free);
DEFINE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                link_info_hash_ops,
                void,
                trivial_hash_func,
                trivial_compare_func,
                LinkInfo,
                link_info_free);

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

static bool metric_startswith_prefix(const char *metric_name, const char *prefix) {
        if (isempty(metric_name) || isempty(prefix))
                return false;

        /* NB: this checks for a *true* prefix, i.e. insists on the dot separator after the prefix. Or in
         * other words, "foo" is not going to be considered a prefix of "foo", but of "foo.bar" it will. */

        const char *m = startswith(metric_name, prefix);
        return !isempty(m) && m[0] == '.';
}

static bool metrics_validate_one(LinkInfo *li, sd_json_variant *metric) {
        int r;

        assert(li);
        assert(metric);

        static const sd_json_dispatch_field dispatch_table[] = {
                { "name", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, 0, SD_JSON_MANDATORY },
                {}
        };

        const char *metric_name = NULL;
        r = sd_json_dispatch(metric, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &metric_name);
        if (r < 0) {
                log_debug_errno(r, "Failed to get metric name, assuming name is not valid: %m");
                return false;
        }

        return metric_startswith_prefix(metric_name, li->metric_prefix);
}

static int metrics_on_query_reply(
                sd_varlink *link,
                sd_json_variant *parameters,
                const char *error_id,
                sd_varlink_reply_flags_t flags,
                void *userdata) {

        assert(link);

        LinkInfo *li = ASSERT_PTR(userdata);
        Context *context = ASSERT_PTR(li->context);

        if (error_id) {
                if (streq(error_id, SD_VARLINK_ERROR_DISCONNECTED))
                        log_info("Varlink disconnected");
                else if (streq(error_id, SD_VARLINK_ERROR_TIMEOUT))
                        log_info("Varlink timed out");
                else
                        log_error("Varlink error: %s", error_id);

                goto finish;
        }

        if (context->n_metrics >= METRICS_MAX) {
                context->n_skipped_metrics++;
                goto finish;
        }

        if (!metrics_validate_one(li, parameters)) {
                context->n_invalid_metrics++;
                goto finish;
        }

        /* Collect metrics for later sorting */
        if (!GREEDY_REALLOC(context->metrics, context->n_metrics + 1))
                return log_oom();

        context->metrics[context->n_metrics++] = sd_json_variant_ref(parameters);

finish:
        if (!FLAGS_SET(flags, SD_VARLINK_REPLY_CONTINUES)) {
                assert_se(set_remove(context->link_infos, li) == li);
                link_info_free(li);
                if (set_isempty(context->link_infos))
                        (void) sd_event_exit(context->event, EXIT_SUCCESS);
        }

        return 0;
}

static int metrics_call(Context *context, const char *name, const char *path) {
        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        int r;

        assert(context);
        assert(path);

        r = sd_varlink_connect_address(&vl, path);
        if (r < 0)
                return log_error_errno(r, "Unable to connect to %s: %m", path);

        r = sd_varlink_set_relative_timeout(vl, TIMEOUT_USEC);
        if (r < 0)
                return log_error_errno(r, "Failed to set varlink timeout: %m");

        r = sd_varlink_attach_event(vl, context->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach varlink connection to event loop: %m");

        r = sd_varlink_bind_reply(vl, metrics_on_query_reply);
        if (r < 0)
                return log_error_errno(r, "Failed to bind reply callback: %m");

        const char *method = context->action == ACTION_LIST ? "io.systemd.Metrics.List" : "io.systemd.Metrics.Describe";
        r = sd_varlink_observe(vl,
                               method,
                               /* parameters= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to issue %s() call: %m", method);

        _cleanup_(link_info_freep) LinkInfo *li = new(LinkInfo, 1);
        if (!li)
                return log_oom();

        *li = (LinkInfo) {
                .context = context,
                .link = sd_varlink_ref(vl),
                .metric_prefix = strdup(name),
        };

        if (!li->metric_prefix)
                return log_oom();

        if (set_ensure_put(&context->link_infos, &link_info_hash_ops, li) < 0)
                return log_oom();

        (void) sd_varlink_set_userdata(vl, li);

        TAKE_PTR(li);
        return 0;
}

static int metrics_output_list(Context *context, Table **ret) {
        int r;

        assert(context);

        _cleanup_(table_unrefp) Table *table = table_new("family", "object", "fields", "value");
        if (!table)
                return log_oom();

        table_set_ersatz_string(table, TABLE_ERSATZ_DASH);
        table_set_sort(table, (size_t) 0, (size_t) 1, (size_t) 2, (size_t) 3);

        FOREACH_ARRAY(m, context->metrics, context->n_metrics) {
                struct {
                        const char *name;
                        const char *object;
                        sd_json_variant *fields, *value;
                } d = {};

                static const sd_json_dispatch_field dispatch_table[] = {
                        { "name",   SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string,  voffsetof(d, name),   SD_JSON_MANDATORY },
                        { "object", SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string,  voffsetof(d, object), 0                 },
                        { "fields", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_variant_noref, voffsetof(d, fields), 0                 },
                        { "value",  _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_variant_noref, voffsetof(d, value),  SD_JSON_MANDATORY },
                        {}
                };

                r = sd_json_dispatch(*m, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &d);
                if (r < 0) {
                        _cleanup_free_ char *t = NULL;
                        int k = sd_json_variant_format(*m, /* flags= */ 0, &t);
                        if (k < 0)
                                return log_error_errno(k, "Failed to format JSON: %m");

                        log_warning_errno(r, "Cannot parse metric, skipping: %s", t);
                        continue;
                }

                r = table_add_many(
                                table,
                                TABLE_STRING,     d.name,
                                TABLE_STRING,     d.object,
                                TABLE_JSON,       d.fields,
                                TABLE_SET_WEIGHT, 50U,
                                TABLE_JSON,       d.value,
                                TABLE_SET_WEIGHT, 50U);
                if (r < 0)
                        return table_log_add_error(r);
        }

        *ret = TAKE_PTR(table);
        return 0;
}

static int metrics_output_describe(Context *context, Table **ret) {
        int r;

        assert(context);

        _cleanup_(table_unrefp) Table *table = table_new("family", "type", "description");
        if (!table)
                return log_oom();

        table_set_ersatz_string(table, TABLE_ERSATZ_DASH);
        table_set_sort(table, (size_t) 0, (size_t) 1, (size_t) 2);

        FOREACH_ARRAY(m, context->metrics, context->n_metrics) {
                struct {
                        const char *name;
                        const char *type;
                        const char *description;
                } d = {};

                static const sd_json_dispatch_field dispatch_table[] = {
                        { "name",        SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(d, name),        SD_JSON_MANDATORY },
                        { "type",        SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(d, type),        SD_JSON_MANDATORY },
                        { "description", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(d, description), 0                 },
                        {}
                };

                r = sd_json_dispatch(*m, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &d);
                if (r < 0) {
                        _cleanup_free_ char *t = NULL;
                        int k = sd_json_variant_format(*m, /* flags= */ 0, &t);
                        if (k < 0)
                                return log_error_errno(k, "Failed to format JSON: %m");

                        log_warning_errno(r, "Cannot parse metric description, skipping: %s", t);
                        continue;
                }

                r = table_add_many(
                                table,
                                TABLE_STRING,     d.name,
                                TABLE_STRING,     d.type,
                                TABLE_STRING,     d.description,
                                TABLE_SET_WEIGHT, 50U);
                if (r < 0)
                        return table_log_add_error(r);
        }

        *ret = TAKE_PTR(table);
        return 0;
}

static int metrics_output(Context *context) {
        int r;

        assert(context);

        typesafe_qsort(context->metrics, context->n_metrics, metric_compare);

        if (sd_json_format_enabled(arg_json_format_flags)) {
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

        _cleanup_(table_unrefp) Table *table = NULL;
        switch(context->action) {

        case ACTION_LIST:
                r = metrics_output_list(context, &table);
                break;

        case ACTION_DESCRIBE:
                r = metrics_output_describe(context, &table);
                break;

        default:
                assert_not_reached();
        }
        if (r < 0)
                return r;

        if (!table_isempty(table) || sd_json_format_enabled(arg_json_format_flags)) {
                r = table_print_with_pager(table, arg_json_format_flags, arg_pager_flags, /* show_header= */ true);
                if (r < 0)
                        return r;
        }

        if (!sd_json_format_enabled(arg_json_format_flags)) {
                if (table_isempty(table))
                        printf("No metrics available.\n");
                else
                        printf("\n%zu metrics listed.\n", table_get_rows(table) - 1);
        }

        return 0;
}

static int readdir_sources(char **ret_directory, DirectoryEntries **ret) {
        int r;

        assert(ret_directory);
        assert(ret);

        _cleanup_free_ char *sources_path = NULL;
        r = runtime_directory_generic(arg_runtime_scope, "systemd/report", &sources_path);
        if (r < 0)
                return log_error_errno(r, "Failed to determine sources directory path: %m");

        log_debug("Looking for metrics in '%s'.", sources_path);

        size_t m = 0;

        _cleanup_free_ DirectoryEntries *de = NULL;
        r = readdir_all_at(
                        AT_FDCWD,
                        sources_path,
                        RECURSE_DIR_IGNORE_DOT|RECURSE_DIR_ENSURE_TYPE,
                        &de);
        if (r == -ENOENT)
                *ret = NULL;
        else if (r < 0)
                return log_error_errno(r, "Failed to enumerate '%s': %m", sources_path);
        else {
                /* Filter out non-sockets/non-symlinks entries */
                FOREACH_ARRAY(i, de->entries, de->n_entries) {
                        struct dirent *d = *i;

                        if (!IN_SET(d->d_type, DT_SOCK, DT_LNK))
                                continue;

                        de->entries[m++] = *i;
                }

                de->n_entries = m;
                *ret = TAKE_PTR(de);
        }

        *ret_directory = TAKE_PTR(sources_path);
        return m > 0;
}

static int verb_metrics(int argc, char *argv[], void *userdata) {
        Action action;
        int r;

        assert(argc == 1);
        assert(argv);

        if (streq_ptr(argv[0], "metrics"))
                action = ACTION_LIST;
        else {
                assert(streq_ptr(argv[0], "describe-metrics"));
                action = ACTION_DESCRIBE;
        }

        _cleanup_(context_done) Context context = {
                .action = action,
        };
        size_t n_skipped_sources = 0;

        _cleanup_free_ DirectoryEntries *de = NULL;
        _cleanup_free_ char *sources_path = NULL;
        r = readdir_sources(&sources_path, &de);
        if (r < 0)
                return r;
        if (r > 0) {
                r = sd_event_default(&context.event);
                if (r < 0)
                        return log_error_errno(r, "Failed to get event loop: %m");

                r = sd_event_set_signal_exit(context.event, true);
                if (r < 0)
                        return log_error_errno(r, "Failed to enable exit on SIGINT/SIGTERM: %m");

                FOREACH_ARRAY(i, de->entries, de->n_entries) {
                        struct dirent *d = *i;

                        if (set_size(context.link_infos) >= METRICS_LINKS_MAX) {
                                n_skipped_sources++;
                                break;
                        }

                        _cleanup_free_ char *p = path_join(sources_path, d->d_name);
                        if (!p)
                                return log_oom();

                        (void) metrics_call(&context, d->d_name, p);
                }
        }

        if (set_isempty(context.link_infos))
                log_info("No metrics sources found.");
        else {
                assert(context.event);

                r = sd_event_loop(context.event);
                if (r < 0)
                        return log_error_errno(r, "Failed to run event loop: %m");

                r = metrics_output(&context);
                if (r < 0)
                        return r;
        }

        if (n_skipped_sources > 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EUCLEAN),
                                         "Too many metrics sources, only %u sources contacted, %zu sources skipped.",
                                         set_size(context.link_infos), n_skipped_sources);
        if (context.n_invalid_metrics > 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EUCLEAN),
                                         "%zu metrics are not valid.",
                                         context.n_invalid_metrics);
        if (context.n_skipped_metrics > 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EUCLEAN),
                                         "Too many metrics, only %zu metrics collected, %zu metrics skipped.",
                                         context.n_metrics, context.n_skipped_metrics);
        return 0;
}

static int verb_list_sources(int argc, char *argv[], void *userdata) {
        int r;

        _cleanup_(table_unrefp) Table *table = table_new("source", "address");
        if (!table)
                return log_oom();

        _cleanup_free_ char *sources_path = NULL;
        _cleanup_free_ DirectoryEntries *de = NULL;
        r = readdir_sources(&sources_path, &de);
        if (r < 0)
                return r;
        if (r > 0)
                FOREACH_ARRAY(i, de->entries, de->n_entries) {
                        struct dirent *d = *i;

                        _cleanup_free_ char *k = path_join(sources_path, d->d_name);
                        if (!k)
                                return log_oom();

                        _cleanup_free_ char *resolved = NULL;
                        r = chase(k, /* root= */ NULL, CHASE_MUST_BE_SOCKET, &resolved, /* ret_fd= */ NULL);
                        if (r < 0) {
                                log_warning_errno(r, "Failed to resolve '%s', skipping: %m", k);
                                continue;
                        }

                        _cleanup_free_ char *j = strjoin("unix:", resolved);
                        if (!j)
                                return log_oom();

                        r = table_add_many(
                                        table,
                                        TABLE_STRING, d->d_name,
                                        TABLE_STRING, j);
                        if (r < 0)
                                return table_log_add_error(r);
                }

        if (!table_isempty(table) || sd_json_format_enabled(arg_json_format_flags)) {
                r = table_print_with_pager(table, arg_json_format_flags, arg_pager_flags, /* show_header= */ true);
                if (r < 0)
                        return r;
        }

        if (!sd_json_format_enabled(arg_json_format_flags)) {
                if (table_isempty(table))
                        printf("No sources available.\n");
                else
                        printf("\n%zu sources listed.\n", table_get_rows(table) - 1);
        }

        return 0;
}

static int verb_help(int argc, char *argv[], void *userdata) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-report", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] COMMAND ...\n"
               "\n%5$sAcquire metrics from local sources.%6$s\n"
               "\n%3$sCommands:%4$s\n"
               "  metrics               Acquire list of metrics and their values\n"
               "  describe-metrics      Describe available metrics\n"
               "  list-sources          Show list of known metrics sources\n"
               "\n%3$sOptions:%4$s\n"
               "  -h --help             Show this help\n"
               "     --version          Show package version\n"
               "     --no-pager         Do not pipe output into a pager\n"
               "     --user             Connect to user service manager\n"
               "     --system           Connect to system service manager (default)\n"
               "     --json=pretty|short\n"
               "                        Configure JSON output\n"
               "  -j                    Equivalent to --json=pretty (on TTY) or --json=short\n"
               "                        (otherwise)\n"
               "\nSee the %2$s for details.\n",
               program_invocation_short_name,
               link,
               ansi_underline(),
               ansi_normal(),
               ansi_highlight(),
               ansi_normal());

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
                ARG_USER,
                ARG_SYSTEM,
                ARG_JSON,
        };

        static const struct option options[] = {
                { "help",     no_argument,       NULL, 'h'          },
                { "version",  no_argument,       NULL, ARG_VERSION  },
                { "no-pager", no_argument,       NULL, ARG_NO_PAGER },
                { "user",     no_argument,       NULL, ARG_USER     },
                { "system",   no_argument,       NULL, ARG_SYSTEM   },
                { "json",     required_argument, NULL, ARG_JSON     },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hj", options, NULL)) >= 0)
                switch (c) {
                case 'h':
                        return verb_help(/* argc= */ 0, /* argv= */ NULL, /* userdata= */ NULL);

                case ARG_VERSION:
                        return version();

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

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

                case 'j':
                        arg_json_format_flags = SD_JSON_FORMAT_PRETTY_AUTO|SD_JSON_FORMAT_COLOR_AUTO;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        return 1;
}

static int report_main(int argc, char *argv[]) {

        static const Verb verbs[] = {
                { "help",             VERB_ANY, 1, 0, verb_help         },
                { "metrics",          VERB_ANY, 1, 0, verb_metrics      },
                { "describe-metrics", VERB_ANY, 1, 0, verb_metrics      },
                { "list-sources",     VERB_ANY, 1, 0, verb_list_sources },
                {}
        };

        return dispatch_verb(argc, argv, verbs, NULL);
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        return report_main(argc, argv);
}

DEFINE_MAIN_FUNCTION(run);
