/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "build.h"
#include "chase.h"
#include "dirent-util.h"
#include "format-table.h"
#include "help-util.h"
#include "log.h"
#include "main-func.h"
#include "options.h"
#include "parse-argument.h"
#include "path-lookup.h"
#include "recurse-dir.h"
#include "report.h"
#include "report-generate.h"
#include "report-sign.h"
#include "report-upload.h"
#include "runtime-scope.h"
#include "set.h"
#include "sort-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "varlink-idl-util.h"
#include "varlink-io.systemd.Report.h"
#include "varlink-util.h"
#include "verbs.h"
#include "web-util.h"

#define METRICS_MAX 4096U
#define METRICS_LINKS_MAX 128U
#define TIMEOUT_USEC (30 * USEC_PER_SEC) /* 30 seconds */

static PagerFlags arg_pager_flags = 0;
static bool arg_legend = true;
static RuntimeScope arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
sd_json_format_flags_t arg_json_format_flags = SD_JSON_FORMAT_OFF|SD_JSON_FORMAT_PRETTY_AUTO|SD_JSON_FORMAT_COLOR_AUTO;
char *arg_url = NULL;
char *arg_key = NULL;
char *arg_cert = NULL;
char *arg_trust = NULL;
char **arg_extra_headers = NULL;
usec_t arg_network_timeout_usec = TIMEOUT_USEC;
bool arg_sign = false;

STATIC_DESTRUCTOR_REGISTER(arg_url, freep);
STATIC_DESTRUCTOR_REGISTER(arg_key, freep);
STATIC_DESTRUCTOR_REGISTER(arg_cert, freep);
STATIC_DESTRUCTOR_REGISTER(arg_trust, freep);
STATIC_DESTRUCTOR_REGISTER(arg_extra_headers, strv_freep);

typedef struct LinkInfo {
        Context *context;
        sd_varlink *link;
        char *name;
} LinkInfo;

static LinkInfo* link_info_free(LinkInfo *li) {
        if (!li)
                return NULL;

        sd_varlink_close_unref(li->link);
        free(li->name);
        return mfree(li);
}

static void context_done(Context *context) {
        if (!context)
                return;

        context->event = sd_event_unref(context->event);
        context->link_infos = set_free(context->link_infos);
        context->matches = strv_free(context->matches);
        sd_json_variant_unref_many(context->metrics, context->n_metrics);
        context->metrics = NULL;
        context->n_metrics = 0;
        iovw_done_free(&context->upload_answer);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(LinkInfo*, link_info_free);
DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                link_info_hash_ops,
                void, trivial_hash_func, trivial_compare_func,
                LinkInfo, link_info_free);

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

static int metrics_name_valid(const char *metric_name) {

        /* Validates a metrics family name. Since the prefix shall match the Varlink service name, we'll
         * enforce Varlink interface naming rules on it. Given how close we are to Varlink let's also enforce
         * rules on metrics names similar to those of Varlink field names. */

        const char *e = strrchr(metric_name, '.');
        if (!e)
                return false;

        _cleanup_free_ char *j = strndup(metric_name, e - metric_name);
        if (!j)
                return -ENOMEM;

        if (!varlink_idl_interface_name_is_valid(j))
                return false;

        if (!varlink_idl_field_name_is_valid(e+1))
                return false;

        return true;
}

static bool metric_startswith_prefix(const char *metric_name, const char *prefix) {
        if (isempty(metric_name) || isempty(prefix))
                return false;

        /* NB: this checks for a *true* prefix, i.e. insists on the dot separator after the prefix. Or in
         * other words, "foo" is not going to be considered a prefix of "foo", but of "foo.bar" it will. */

        const char *m = startswith(metric_name, prefix);
        return !isempty(m) && m[0] == '.';
}

typedef enum {
        VERDICT_INVALID,
        VERDICT_MATCH,
        VERDICT_MISMATCH,
} Verdict;

static Verdict metrics_verdict(LinkInfo *li, sd_json_variant *metric) {
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
                return VERDICT_INVALID;
        }

        /* Validate metric name is generally valid */
        r = metrics_name_valid(metric_name);
        if (r < 0) {
                log_debug_errno(r, "Failed to determine if '%s' is a valid metric name: %m", metric_name);
                return VERDICT_INVALID;
        }
        if (!r) {
                log_debug("Metric name '%s' is not valid, skipping.", metric_name);
                return VERDICT_INVALID;
        }

        /* Validate metric name matches the Varlink service it was found on */
        if (!metric_startswith_prefix(metric_name, li->name)) {
                log_debug("Metric name '%s' does not match service name '%s', skipping.", metric_name, li->name);
                return VERDICT_INVALID;
        }

        /* Check it against any specified matches */
        bool matches;
        if (strv_isempty(li->context->matches))
                matches = true;
        else {
                matches = false;

                /* Allow exact matches or prefix matches */
                STRV_FOREACH(i, li->context->matches)
                        if (streq(metric_name, *i) ||
                            metric_startswith_prefix(metric_name, *i)) {
                                matches = true;
                                break;
                        }
        }

        if (!matches) {
                log_debug("Metric '%s' does not match search, ignoring.", metric_name);
                return VERDICT_MISMATCH;
        }

        return VERDICT_MATCH;
}

static int on_query_reply(
                sd_varlink *link,
                sd_json_variant *parameters,
                const char *error_id,
                sd_varlink_reply_flags_t flags,
                void *userdata) {

        assert(link);

        LinkInfo *li = ASSERT_PTR(userdata);
        Context *context = ASSERT_PTR(li->context);

        if (error_id) {
                if (STR_IN_SET(error_id, SD_VARLINK_ERROR_METHOD_NOT_FOUND,
                                         SD_VARLINK_ERROR_METHOD_NOT_IMPLEMENTED))
                        log_debug("Ignoring Varlink endpoint '%s': %s", li->name, error_id);
                else if (streq(error_id, SD_VARLINK_ERROR_DISCONNECTED))
                        log_warning("Varlink connection to '%s' disconnected prematurely, ignoring.", li->name);
                else if (streq(error_id, SD_VARLINK_ERROR_TIMEOUT))
                        log_warning("Varlink connection to '%s' timed out, ignoring.", li->name);
                else if (streq(error_id, "io.systemd.Metrics.NoSuchMetric"))
                        log_debug("Varlink connection to '%s' reported no more metrics, ignoring.", li->name);
                else
                        log_warning("Varlink error from '%s', ignoring: %s", li->name, error_id);

                goto finish;
        }

        if (context->n_metrics >= METRICS_MAX) {
                context->n_skipped_metrics++;
                goto finish;
        }

        Verdict v = metrics_verdict(li, parameters);
        if (v == VERDICT_INVALID) {
                context->n_invalid_metrics++;
                goto finish;
        }
        if (v == VERDICT_MISMATCH)
                goto finish;

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

static int call_collect(Context *context, const char *name, const char *path) {
        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        int r;

        assert(context);
        assert(path);

        r = sd_varlink_connect_address(&vl, path);
        if (r < 0)
                return log_error_errno(r, "Unable to connect to %s: %m", path);

        r = sd_varlink_set_description(vl, name);
        if (r < 0)
                return log_error_errno(r, "Failed to set varlink description: %m");

        r = sd_varlink_set_relative_timeout(vl, TIMEOUT_USEC);
        if (r < 0)
                return log_error_errno(r, "Failed to set varlink timeout: %m");

        r = sd_varlink_attach_event(vl, context->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach varlink connection to event loop: %m");

        r = sd_varlink_bind_reply(vl, on_query_reply);
        if (r < 0)
                return log_error_errno(r, "Failed to bind reply callback: %m");

        const char *method = context->action == ACTION_DESCRIBE_METRICS ?
                "io.systemd.Metrics.Describe" :
                "io.systemd.Metrics.List"; /* This is the method for all other actions. */

        r = sd_varlink_observe(vl, method, /* parameters= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to issue %s() call: %m", method);

        _cleanup_(link_info_freep) LinkInfo *li = new(LinkInfo, 1);
        if (!li)
                return log_oom();

        *li = (LinkInfo) {
                .context = context,
                .link = sd_varlink_ref(vl),
                .name = strdup(name),
        };
        if (!li->name)
                return log_oom();

        if (set_ensure_put(&context->link_infos, &link_info_hash_ops, li) < 0)
                return log_oom();

        (void) sd_varlink_set_userdata(vl, li);

        TAKE_PTR(li);
        return 0;
}

static int output_collected_list(Context *context, Table **ret) {
        int r;

        assert(context);
        assert(ret);

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

static int output_collected_describe(Context *context, Table **ret) {
        int r;

        assert(context);
        assert(ret);

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

static int output_collected(Context *context) {
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

                if (context->n_metrics == 0 && arg_legend)
                        log_info("No metrics collected.");
                return 0;
        }

        _cleanup_(table_unrefp) Table *table = NULL;

        switch(context->action) {

        case ACTION_LIST_METRICS:
                r = output_collected_list(context, &table);
                break;

        case ACTION_DESCRIBE_METRICS:
                r = output_collected_describe(context, &table);
                break;

        default:
                assert_not_reached();
        }
        if (r < 0)
                return r;

        if (!table_isempty(table) || sd_json_format_enabled(arg_json_format_flags)) {
                r = table_print_with_pager(table, arg_json_format_flags, arg_pager_flags, arg_legend);
                if (r < 0)
                        return r;
        }

        if (arg_legend && !sd_json_format_enabled(arg_json_format_flags)) {
                if (table_isempty(table))
                        printf("No metrics available.\n");
                else
                        printf("\n%zu metrics listed.\n", table_get_rows(table) - 1);
        }

        return 0;
}

static int parse_metrics_matches(char **input, char ***ret) {
        int r;

        assert(ret);

        _cleanup_strv_free_ char **matches = NULL;
        STRV_FOREACH(i, input) {
                r = metrics_name_valid(*i);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine if '%s' is a valid metric name: %m", *i);
                if (!r && !varlink_idl_interface_name_is_valid(*i))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Match is not a valid family name or prefix: %s", *i);

                if (strv_extend(&matches, *i) < 0)
                        return log_oom();
        }

        strv_sort_uniq(matches);

        *ret = TAKE_PTR(matches);
        return 0;
}

static bool test_service_matches(const char *service, char **matches) {
        assert(service);

        if (strv_isempty(matches))
                return true;

        /* Only contact services whose name is either a prefix of any of the specified metrics families, or
         * if the specified metric families are a prefix of the service.
         *
         * Example: if user specifies "foo" we want to match sockets "foo" and "foo.bar".
         *          if user specifies "foo.waldo" we want to match sockets "foo" and "foo.waldo" as well as "foo.waldo.quux".
         *
         *          in other words: it should be fine to specify any prefix of a service name to get all metrics from all matching services.
         *                          it should also be fine to specify a full metric name, and then go directly to the relevant services, and ask for matching metrics.
         */

        STRV_FOREACH(i, matches) {
                if (streq(service, *i))
                        return true;

                if (metric_startswith_prefix(*i, service) ||
                    metric_startswith_prefix(service, *i))
                        return true;
        }

        return false;
}

static int readdir_sources(char **matches, char **ret_directory, DirectoryEntries **ret) {
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
                /* Filter out non-sockets/non-symlinks and badly named entries */
                FOREACH_ARRAY(i, de->entries, de->n_entries) {
                        struct dirent *d = *i;

                        if (!IN_SET(d->d_type, DT_SOCK, DT_LNK))
                                continue;

                        if (!varlink_idl_interface_name_is_valid(d->d_name))
                                continue;

                        if (!test_service_matches(d->d_name, matches))
                                continue;

                        de->entries[m++] = *i;
                }

                de->n_entries = m;
                *ret = TAKE_PTR(de);
        }

        *ret_directory = TAKE_PTR(sources_path);
        return m > 0;
}

static int context_collect_metrics(Context *context) {
        int r;

        /* Contacts all known metrics sources, issues the appropriate Varlink call on each and runs the
         * event loop until all replies came in. Expects the caller to have set up context->event
         * beforehand. The collected metrics end up in context->metrics. */

        assert(context);
        assert(context->event);

        _cleanup_free_ DirectoryEntries *de = NULL;
        _cleanup_free_ char *sources_path = NULL;
        r = readdir_sources(context->matches, &sources_path, &de);
        if (r < 0)
                return r;
        if (r == 0)
                return 0;

        FOREACH_ARRAY(i, de->entries, de->n_entries) {
                struct dirent *d = *i;

                if (set_size(context->link_infos) >= METRICS_LINKS_MAX) {
                        context->n_skipped_sources++;
                        break;
                }

                _cleanup_free_ char *p = path_join(sources_path, d->d_name);
                if (!p)
                        return log_oom();

                (void) call_collect(context, d->d_name, p);
        }

        context->n_contacted_sources = set_size(context->link_infos);

        if (context->n_contacted_sources == 0)
                return 0;

        r = sd_event_loop(context->event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        return 1;
}

VERB_FULL(verb_metrics, "metrics", "[MATCH…]", VERB_ANY, VERB_ANY, 0, ACTION_LIST_METRICS,
          "Acquire list of metrics and their values");
VERB_FULL(verb_metrics, "describe", "[MATCH…]", VERB_ANY, VERB_ANY, 0, ACTION_DESCRIBE_METRICS,
          "Describe available metrics");
VERB_FULL(verb_metrics, "generate", "[MATCH…]", VERB_ANY, VERB_ANY, 0, ACTION_GENERATE,
          "Build a report with metrics");
VERB_FULL(verb_metrics, "upload", "[MATCH…]", VERB_ANY, VERB_ANY, 0, ACTION_UPLOAD,
          "Upload a report with metrics");
static int verb_metrics(int argc, char *argv[], uintptr_t data, void *userdata) {
        Action action = data;
        int r;

        assert(argc >= 1);
        assert(argv);
        assert(IN_SET(action, ACTION_LIST_METRICS, ACTION_DESCRIBE_METRICS, ACTION_GENERATE, ACTION_UPLOAD));

        if (IN_SET(action, ACTION_LIST_METRICS, ACTION_DESCRIBE_METRICS))
                /* Enable JSON-SEQ mode for the first two verbs, since we'll dump a large series of JSON
                 * objects. In the report format, we return a single JSON object, so don't do this. */
                arg_json_format_flags |= SD_JSON_FORMAT_SEQ;

        _cleanup_(context_done) Context context = {
                .action = action,
        };

        r = parse_metrics_matches(argv + 1, &context.matches);
        if (r < 0)
                return r;

        r = sd_event_default(&context.event);
        if (r < 0)
                return log_error_errno(r, "Failed to get event loop: %m");

        r = sd_event_set_signal_exit(context.event, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable exit on SIGINT/SIGTERM: %m");

        r = context_collect_metrics(&context);
        if (r < 0)
                return r;
        if (r == 0) {
                if (arg_legend)
                        log_info("No metrics sources found.");
        } else {
                switch (action) {

                case ACTION_LIST_METRICS:
                case ACTION_DESCRIBE_METRICS:
                        r = output_collected(&context);
                        break;

                case ACTION_GENERATE:
                        r = context_generate_report(&context);
                        break;

                case ACTION_UPLOAD:
                        r = context_upload_report(&context);
                        break;

                default:
                        assert_not_reached();
                }
                if (r < 0)
                        return r;
        }

        if (context.n_skipped_sources > 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EUCLEAN),
                                         "Too many metrics sources, only %zu sources contacted, %zu sources skipped.",
                                         context.n_contacted_sources, context.n_skipped_sources);
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

VERB_NOARG(verb_list_sources, "list-sources", "Show list of known metrics sources");
static int verb_list_sources(int argc, char *argv[], uintptr_t _data, void *userdata) {
        int r;

        _cleanup_(table_unrefp) Table *table = table_new("source", "address");
        if (!table)
                return log_oom();

        _cleanup_free_ char *sources_path = NULL;
        _cleanup_free_ DirectoryEntries *de = NULL;
        r = readdir_sources(/* matches= */ NULL, &sources_path, &de);
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
                r = table_print_with_pager(table, arg_json_format_flags, arg_pager_flags, arg_legend);
                if (r < 0)
                        return r;
        }

        if (arg_legend && !sd_json_format_enabled(arg_json_format_flags)) {
                if (table_isempty(table))
                        printf("No sources available.\n");
                else
                        printf("\n%zu sources listed.\n", table_get_rows(table) - 1);
        }

        return 0;
}

static int vl_method_generate_internal(
                sd_varlink *link,
                sd_json_variant *parameters,
                bool sign) {

        int r;

        assert(link);
        assert(parameters);

        _cleanup_strv_free_ char **input_matches = NULL;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "matches", SD_JSON_VARIANT_ARRAY, sd_json_dispatch_strv, 0, 0 },
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &input_matches);
        if (r != 0)
                return r;

        _cleanup_(context_done) Context context = {
                .action = ACTION_GENERATE,
        };

        r = parse_metrics_matches(input_matches, &context.matches);
        if (r < 0)
                return sd_varlink_error_invalid_parameter_name(link, "matches");

        r = sd_event_new(&context.event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        r = context_collect_metrics(&context);
        if (r < 0)
                return r;

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *report = NULL;
        r = context_build_report(&context, &report);
        if (r < 0)
                return r;

        if (sign) {
                /* Use compact JSON formatting (no pretty/color/seq flags), matching the on-the-wire format
                 * used for uploads. context_sign_report() adds the JSON-SEQ record separators itself. */
                _cleanup_free_ char *s = NULL;
                r = context_sign_report_as_string(&context, report, /* format_flags= */ 0, &s);
                if (r < 0)
                        return r;

                return sd_varlink_replybo(
                                link,
                                SD_JSON_BUILD_PAIR_BASE64("reportData", s, strlen(s)));
        }

        return sd_varlink_replybo(
                        link,
                        SD_JSON_BUILD_PAIR_VARIANT("report", report));
}

static int vl_method_generate(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        return vl_method_generate_internal(link, parameters, /* sign= */ false);
}

static int vl_method_generate_signed(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        return vl_method_generate_internal(link, parameters, /* sign= */ true);
}

static int vl_server(void) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *vs = NULL;
        int r;

        r = varlink_server_new(&vs, SD_VARLINK_SERVER_MYSELF_ONLY|SD_VARLINK_SERVER_ROOT_ONLY, /* userdata= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface(vs, &vl_interface_io_systemd_Report);
        if (r < 0)
                return log_error_errno(r, "Failed to add Varlink interface: %m");

        r = sd_varlink_server_bind_method_many(
                        vs,
                        "io.systemd.Report.Generate",       vl_method_generate,
                        "io.systemd.Report.GenerateSigned", vl_method_generate_signed);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink methods: %m");

        r = sd_varlink_server_loop_auto(vs);
        if (r < 0)
                return log_error_errno(r, "Failed to run Varlink event loop: %m");

        return 0;
}

static int help(void) {
        int r;

        _cleanup_(table_unrefp) Table *verbs = NULL, *options = NULL;
        r = verbs_get_help_table(&verbs);
        if (r < 0)
                return r;

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        (void) table_sync_column_widths(0, options, verbs);

        help_cmdline("[OPTIONS...] COMMAND ...");
        help_abstract("Acquire metrics from local sources.");
        help_section("Commands");

        r = table_print_or_warn(verbs);
        if (r < 0)
                return r;

        help_section("Options");

        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        help_man_page_reference("systemd-report", "1");
        return 0;
}

VERB_COMMON_HELP_HIDDEN(help);

static int parse_argv(int argc, char *argv[], char ***ret_args) {
        int r;

        assert(argc >= 0);
        assert(argv);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {
                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_COMMON_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                OPTION_COMMON_NO_LEGEND:
                        arg_legend = false;
                        break;

                OPTION_LONG("user", NULL, "Connect to user service manager"):
                        arg_runtime_scope = RUNTIME_SCOPE_USER;
                        break;

                OPTION_LONG("system", NULL, "Connect to system service manager (default)"):
                        arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
                        break;

                OPTION_COMMON_JSON:
                        r = parse_json_argument(opts.arg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;
                        break;

                OPTION_COMMON_LOWERCASE_J:
                        arg_json_format_flags = SD_JSON_FORMAT_PRETTY_AUTO|SD_JSON_FORMAT_COLOR_AUTO;
                        break;

                OPTION_LONG("url", "URL",
                            "Upload to this address"):
                        r = free_and_strdup_warn(&arg_url, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("key", "FILENAME",
                            "Specify key in PEM format (default: \"" REPORT_PRIV_KEY_FILE "\")"):
                        r = free_and_strdup_warn(&arg_key, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("cert", "FILENAME",
                            "Specify certificate in PEM format (default: \"" REPORT_CERT_FILE "\")"):
                        r = free_and_strdup_warn(&arg_cert, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("trust", "FILENAME|all",
                            "Specify CA certificate or disable checking (default: \"" REPORT_TRUST_FILE "\")"):
                        r = free_and_strdup_warn(&arg_trust, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("network-timeout", "SEC", "Specify timeout for network upload operation"):
                        r = parse_sec(opts.arg, &arg_network_timeout_usec);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --network-timeout value: %s", opts.arg);
                        break;

                OPTION_LONG("extra-header", "NAME: VALUE",
                            "Inject additional header into the upload request"):
                        if (isempty(opts.arg)) {
                                arg_extra_headers = strv_free(arg_extra_headers);
                                break;
                        }

                        if (!http_header_valid(opts.arg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid HTTP header: %s", opts.arg);

                        if (strv_extend(&arg_extra_headers, opts.arg) < 0)
                                return log_oom();
                        break;

                OPTION_LONG("sign", "BOOL", "Sign the generated report."):
                        r = parse_boolean_argument("--sign", opts.arg, &arg_sign);
                        if (r < 0)
                                return r;

                        break;
                }

        if ((arg_url || arg_key || arg_cert || arg_trust || arg_extra_headers) && !HAVE_LIBCURL)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Compiled without libcurl.");

        *ret_args = option_parser_get_args(&opts);
        return 1;
}

static int run(int argc, char *argv[]) {
        char **args = NULL;
        int r;

        log_setup();

        /* If invoked as a socket-activated Varlink service (Accept=yes), act as the io.systemd.Report
         * server instead of running the command line interface. */
        r = sd_varlink_invocation(SD_VARLINK_ALLOW_ACCEPT);
        if (r < 0)
                return log_error_errno(r, "Failed to check if invoked in Varlink mode: %m");
        if (r > 0)
                return vl_server();

        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        return dispatch_verb(args, NULL);
}

DEFINE_MAIN_FUNCTION(run);
