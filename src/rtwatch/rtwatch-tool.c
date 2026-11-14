/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <locale.h>

#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "build.h"
#include "bus-util.h"
#include "escape.h"
#include "format-table.h"
#include "json-util.h"
#include "log.h"
#include "main-func.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "pidref.h"
#include "polkit-agent.h"
#include "strv.h"
#include "threadref.h"
#include "varlink-util.h"
#include "verbs.h"

#define RTWATCH_VARLINK_ADDRESS "/run/systemd/io.systemd.RTWatch"

static bool arg_ask_password = true;
static sd_json_format_flags_t arg_json_format_flags = SD_JSON_FORMAT_OFF;
static pid_t arg_thread = 0;

COMMAND(
        "systemd-rtwatch\0",
        "Query or control the realtime scheduling policy service.",
        .man_pages = "systemd-rtwatch(1)\0",
);

static int connect_rtwatch(sd_varlink **ret) {
        int r;

        assert(ret);

        r = sd_varlink_connect_address(ret, RTWATCH_VARLINK_ADDRESS);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to " RTWATCH_VARLINK_ADDRESS ": %m");

        return 0;
}

static int call(const char *method, sd_json_variant *parameters, sd_json_variant **ret) {
        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *vl = NULL;
        sd_json_variant *reply = NULL;
        int r;

        assert(method);

        r = connect_rtwatch(&vl);
        if (r < 0)
                return r;

        r = varlink_call_and_log(vl, method, parameters, &reply);
        if (r < 0)
                return r;

        /* The reply is owned by the connection, which we close when returning, hence take a reference */
        if (ret)
                *ret = sd_json_variant_ref(reply);

        return 0;
}

VERB_DEFAULT_NOARG(verb_status, "status", "Show current policy and state");
static int verb_status(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *reply = NULL;
        int r;

        r = call("io.systemd.RTWatch.Describe", /* parameters= */ NULL, &reply);
        if (r < 0)
                return r;

        if (sd_json_format_enabled(arg_json_format_flags))
                return sd_json_variant_dump(reply, arg_json_format_flags, /* f= */ NULL, /* prefix= */ NULL);

        struct {
                const char *scheduling_policy;
                int max_realtime_priority;
                int min_nice_level;
                uint64_t max_realtime_time_usec;
                bool suspended;
                uint64_t refuse_until_usec;
                unsigned users, processes, threads;
        } d = {};

        static const sd_json_dispatch_field dispatch_table[] = {
                { "schedulingPolicy",    SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, voffsetof(d, scheduling_policy),      SD_JSON_MANDATORY },
                { "maxRealtimePriority", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int,          voffsetof(d, max_realtime_priority),  SD_JSON_MANDATORY },
                { "minNiceLevel",        _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int,          voffsetof(d, min_nice_level),         SD_JSON_MANDATORY },
                { "maxRealtimeTimeUSec", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,       voffsetof(d, max_realtime_time_usec), SD_JSON_MANDATORY },
                { "suspended",           SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool,      voffsetof(d, suspended),              SD_JSON_MANDATORY },
                { "refuseUntilUSec",     _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,       voffsetof(d, refuse_until_usec),      SD_JSON_NULLABLE  },
                { "users",               _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,         voffsetof(d, users),                  SD_JSON_MANDATORY },
                { "processes",           _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,         voffsetof(d, processes),              SD_JSON_MANDATORY },
                { "threads",             _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,         voffsetof(d, threads),                SD_JSON_MANDATORY },
                {}
        };

        r = sd_json_dispatch(reply, dispatch_table, SD_JSON_LOG|SD_JSON_ALLOW_EXTENSIONS, &d);
        if (r < 0)
                return r;

        _cleanup_(table_unrefp) Table *table = table_new_vertical();
        if (!table)
                return log_oom();

        r = table_add_many(table,
                           TABLE_FIELD, "Scheduling policy",
                           TABLE_STRING, d.scheduling_policy,
                           TABLE_FIELD, "Max realtime priority",
                           TABLE_INT, d.max_realtime_priority,
                           TABLE_FIELD, "Min nice level",
                           TABLE_INT, d.min_nice_level,
                           TABLE_FIELD, "Max RLIMIT_RTTIME",
                           TABLE_TIMESPAN, (usec_t) d.max_realtime_time_usec,
                           TABLE_FIELD, "Suspended",
                           TABLE_BOOLEAN, d.suspended,
                           TABLE_FIELD, "Refusing requests",
                           TABLE_BOOLEAN, d.refuse_until_usec > 0,
                           TABLE_FIELD, "Supervised users",
                           TABLE_UINT, d.users,
                           TABLE_FIELD, "Supervised processes",
                           TABLE_UINT, d.processes,
                           TABLE_FIELD, "Supervised threads",
                           TABLE_UINT, d.threads);
        if (r < 0)
                return table_log_add_error(r);

        return table_print_or_warn(table);
}

typedef struct ThreadInfo {
        uid_t user_id;
        ThreadRef thread;
        int priority;
        int nice_level;
        const char *unit;
        const char *user_unit;
        char **command_line;
        const char *thread_name;
} ThreadInfo;

static void thread_info_done(ThreadInfo *i) {
        assert(i);

        threadref_done(&i->thread);
        i->command_line = strv_free(i->command_line);
}

static int json_dispatch_thread_id(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "process", SD_JSON_VARIANT_OBJECT,        json_dispatch_pidref,    offsetof(ThreadRef, process),         SD_JSON_MANDATORY },
                { "tid",     _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int32,  offsetof(ThreadRef, thread_id),       SD_JSON_MANDATORY },
                { "pidfdId", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, offsetof(ThreadRef, thread_pidfd_id), SD_JSON_NULLABLE  },
                {}
        };

        return sd_json_dispatch(variant, dispatch_table, flags|SD_JSON_ALLOW_EXTENSIONS, ASSERT_PTR(userdata));
}

VERB_NOARG(verb_list, "list", "List threads currently made realtime or high priority");
static int verb_list(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *vl = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *list = NULL;
        sd_json_variant *reply = NULL, *e;
        const char *error_id = NULL;
        int r;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "userId",      _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uid_gid,      offsetof(ThreadInfo, user_id),      SD_JSON_MANDATORY },
                { "thread",      SD_JSON_VARIANT_OBJECT,        json_dispatch_thread_id,       offsetof(ThreadInfo, thread),       SD_JSON_MANDATORY },
                { "priority",    _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int,          offsetof(ThreadInfo, priority),     SD_JSON_NULLABLE  },
                { "niceLevel",   _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int,          offsetof(ThreadInfo, nice_level),   SD_JSON_NULLABLE  },
                { "unit",        SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(ThreadInfo, unit),         SD_JSON_NULLABLE  },
                { "userUnit",    SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(ThreadInfo, user_unit),    SD_JSON_NULLABLE  },
                { "commandLine", SD_JSON_VARIANT_ARRAY,         sd_json_dispatch_strv,         offsetof(ThreadInfo, command_line), SD_JSON_NULLABLE  },
                { "threadName",  SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(ThreadInfo, thread_name),  SD_JSON_NULLABLE  },
                {}
        };

        r = connect_rtwatch(&vl);
        if (r < 0)
                return r;

        r = sd_varlink_collect(vl, "io.systemd.RTWatch.List", /* parameters= */ NULL, &reply, &error_id);
        if (r < 0)
                return log_error_errno(r, "Failed to issue List() varlink call: %m");
        if (error_id) {
                r = sd_varlink_error_to_errno(error_id, reply); /* If this is a system errno style error, output it with %m */
                if (r != -EBADR)
                        return log_error_errno(r, "Failed to issue List() varlink call: %m");

                return log_error_errno(r, "Failed to issue List() varlink call: %s", error_id);
        }

        /* If there are no threads the service sends a single empty reply, skip that */
        JSON_VARIANT_ARRAY_FOREACH(e, reply) {
                if (sd_json_variant_is_null(e) || sd_json_variant_is_blank_object(e))
                        continue;

                r = sd_json_variant_append_array(&list, e);
                if (r < 0)
                        return log_oom();
        }

        if (sd_json_format_enabled(arg_json_format_flags)) {
                if (!list) {
                        r = sd_json_variant_new_array(&list, /* array= */ NULL, /* n= */ 0);
                        if (r < 0)
                                return log_oom();
                }

                return sd_json_variant_dump(list, arg_json_format_flags, /* f= */ NULL, /* prefix= */ NULL);
        }

        _cleanup_(table_unrefp) Table *table = table_new("uid", "pid", "tid", "thread", "priority", "nice", "unit", "user unit", "command line");
        if (!table)
                return log_oom();

        table_set_ersatz_string(table, TABLE_ERSATZ_DASH);
        (void) table_set_sort(table, (size_t) 0, (size_t) 1, (size_t) 2);

        JSON_VARIANT_ARRAY_FOREACH(e, list) {
                _cleanup_(thread_info_done) ThreadInfo i = {
                        .thread = THREADREF_NULL,
                        .priority = -1,
                        .nice_level = INT_MAX,
                };

                r = sd_json_dispatch(e, dispatch_table, SD_JSON_LOG|SD_JSON_ALLOW_EXTENSIONS, &i);
                if (r < 0)
                        return r;

                r = table_add_many(table,
                                   TABLE_UID, i.user_id,
                                   TABLE_PID, i.thread.process.pid,
                                   TABLE_PID, i.thread.thread_id,
                                   TABLE_STRING, i.thread_name);
                if (r < 0)
                        return table_log_add_error(r);

                if (i.priority >= 0)
                        r = table_add_many(table, TABLE_INT, i.priority, TABLE_EMPTY);
                else if (i.nice_level != INT_MAX)
                        r = table_add_many(table, TABLE_EMPTY, TABLE_INT, i.nice_level);
                else
                        r = table_add_many(table, TABLE_EMPTY, TABLE_EMPTY);
                if (r < 0)
                        return table_log_add_error(r);

                _cleanup_free_ char *command_line = NULL;
                if (i.command_line) {
                        command_line = quote_command_line(i.command_line, SHELL_ESCAPE_EMPTY);
                        if (!command_line)
                                return log_oom();
                }

                r = table_add_many(table,
                                   TABLE_STRING, i.unit,
                                   TABLE_STRING, i.user_unit,
                                   TABLE_STRING, command_line);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (table_isempty(table)) {
                log_info("No realtime or high priority threads.");
                return 0;
        }

        return table_print_or_warn(table);
}

static int make_thread(const char *method, const char *field, const char *pid_string, int value) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *parameters = NULL;
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        int r;

        assert(method);
        assert(field);
        assert(pid_string);

        r = pidref_set_pidstr(&pidref, pid_string);
        if (r < 0)
                return log_error_errno(r, "Failed to pin process '%s': %m", pid_string);

        (void) polkit_agent_open_if_enabled(BUS_TRANSPORT_LOCAL, arg_ask_password);

        r = sd_json_buildo(
                        &parameters,
                        SD_JSON_BUILD_PAIR_OBJECT(
                                        "thread",
                                        JSON_BUILD_PAIR_PIDREF("process", &pidref),
                                        SD_JSON_BUILD_PAIR_CONDITION(arg_thread > 0, "tid", SD_JSON_BUILD_INTEGER(arg_thread))),
                        SD_JSON_BUILD_PAIR_INTEGER(field, value),
                        SD_JSON_BUILD_PAIR_BOOLEAN("allowInteractiveAuthentication", arg_ask_password));
        if (r < 0)
                return log_error_errno(r, "Failed to build JSON parameters: %m");

        return call(method, parameters, /* ret= */ NULL);
}

VERB(verb_make_realtime, "make-realtime", "PID PRIORITY\0", 3, 3, 0,
     "Make a process' main thread (or the thread specified with --thread=) realtime");
static int verb_make_realtime(int argc, char *argv[], uintptr_t _data, void *userdata) {
        int priority, r;

        r = safe_atoi(argv[2], &priority);
        if (r < 0)
                return log_error_errno(r, "Failed to parse priority '%s': %m", argv[2]);

        return make_thread("io.systemd.RTWatch.MakeThreadRealtime", "priority", argv[1], priority);
}

VERB(verb_make_high_priority, "make-high-priority", "PID NICE\0", 3, 3, 0,
     "Make a process' main thread (or the thread specified with --thread=) high priority");
static int verb_make_high_priority(int argc, char *argv[], uintptr_t _data, void *userdata) {
        int nice_level, r;

        r = parse_nice(argv[2], &nice_level);
        if (r < 0)
                return log_error_errno(r, "Failed to parse nice level '%s': %m", argv[2]);

        return make_thread("io.systemd.RTWatch.MakeThreadHighPriority", "niceLevel", argv[1], nice_level);
}

static int call_manage(const char *method) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *parameters = NULL;
        int r;

        assert(method);

        (void) polkit_agent_open_if_enabled(BUS_TRANSPORT_LOCAL, arg_ask_password);

        r = sd_json_buildo(
                        &parameters,
                        SD_JSON_BUILD_PAIR_BOOLEAN("allowInteractiveAuthentication", arg_ask_password));
        if (r < 0)
                return log_error_errno(r, "Failed to build JSON parameters: %m");

        return call(method, parameters, /* ret= */ NULL);
}

VERB_NOARG(verb_reset_known, "reset-known", "Demote all known realtime and high priority threads");
static int verb_reset_known(int argc, char *argv[], uintptr_t _data, void *userdata) {
        return call_manage("io.systemd.RTWatch.ResetKnown");
}

VERB_NOARG(verb_reset_all, "reset-all", "Demote all realtime threads of the system");
static int verb_reset_all(int argc, char *argv[], uintptr_t _data, void *userdata) {
        return call_manage("io.systemd.RTWatch.ResetAll");
}

VERB_NOARG(verb_suspend, "suspend", "Temporarily demote all known threads");
static int verb_suspend(int argc, char *argv[], uintptr_t _data, void *userdata) {
        return call_manage("io.systemd.RTWatch.Suspend");
}

VERB_NOARG(verb_resume, "resume", "Promote again threads demoted by 'suspend'");
static int verb_resume(int argc, char *argv[], uintptr_t _data, void *userdata) {
        return call_manage("io.systemd.RTWatch.Resume");
}

static int parse_argv(int argc, char *argv[], char ***ret_args) {
        int r;

        assert(argc >= 0);
        assert(argv);
        assert(ret_args);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return command_print_help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_COMMON_NO_ASK_PASSWORD:
                        arg_ask_password = false;
                        break;

                OPTION_COMMON_JSON:
                        r = parse_json_argument(opts.arg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;
                        break;

                OPTION_COMMON_LOWERCASE_J:
                        arg_json_format_flags = SD_JSON_FORMAT_PRETTY_AUTO|SD_JSON_FORMAT_COLOR_AUTO;
                        break;

                OPTION_LONG("thread", "TID", "Operate on the specified thread of the process"):
                        r = parse_pid(opts.arg, &arg_thread);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse thread ID '%s': %m", opts.arg);
                        break;

                OPTION_COMMON_INTROSPECT_CLI:
                        return introspect_cli(arg_json_format_flags);
                }

        *ret_args = option_parser_get_args(&opts);
        return 1;
}

static int run(int argc, char *argv[]) {
        char **args = NULL;
        int r;

        setlocale(LC_ALL, "");
        log_setup();

        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        return dispatch_verb(args, /* userdata= */ NULL);
}

DEFINE_MAIN_FUNCTION(run);
