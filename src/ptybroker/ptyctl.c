/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "build.h"
#include "fd-util.h"
#include "format-table.h"
#include "help-util.h"
#include "json-util.h"
#include "log.h"
#include "main-func.h"
#include "options.h"
#include "parse-argument.h"
#include "ptybroker-client.h"
#include "ptyfwd.h"
#include "runtime-scope.h"
#include "set.h"
#include "string-util.h"
#include "strv.h"
#include "varlink-util.h"
#include "verbs.h"

static bool arg_quiet = false;
static RuntimeScope arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
static char *arg_background = NULL;
static char *arg_title = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_background, freep);
STATIC_DESTRUCTOR_REGISTER(arg_title, freep);

static int help(void) {
        int r;

        help_cmdline("[OPTIONS...] COMMAND ...");
        help_abstract("Interact with the pseudo TTY broker.");

        _cleanup_(table_unrefp) Table *verbs = NULL;
        r = verbs_get_help_table(&verbs);
        if (r < 0)
                return r;

        _cleanup_(table_unrefp) Table *options = NULL;
        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        (void) table_sync_column_widths(0, verbs, options);

        help_section("Commands");
        r = table_print_or_warn(verbs);
        if (r < 0)
                return r;

        help_section("Options");
        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        help_man_page_reference("ptyctl", "1");
        return 0;
}

VERB_COMMON_HELP_HIDDEN(help);

VERB_DEFAULT_NOARG(verb_list, "list", "List the PTYs registered with the broker");
static int verb_list(int argc, char *argv[], uintptr_t data, void *userdata) {
        int r;

        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        r = pty_broker_connect(arg_runtime_scope, &vl);
        if (r < 0)
                return r;

        sd_json_variant *reply = NULL;
        const char *error_id = NULL;
        r = sd_varlink_collect(vl, "io.systemd.PTYBroker.ListPty", /* parameters= */ NULL, &reply, &error_id);
        if (r < 0)
                return log_error_errno(r, "Failed to call ListPty(): %m");
        if (error_id && !streq(error_id, "io.systemd.PTYBroker.NoSuchPty"))
                return log_error_errno(sd_varlink_error_to_errno(error_id, reply),
                                       "Failed to list PTYs: %s", error_id);

        _cleanup_(table_unrefp) Table *table = table_new("name", "description", "tag", "frontend", "backend", "backend path");
        if (!table)
                return log_oom();

        table_set_ersatz_string(table, TABLE_ERSATZ_DASH);
        (void) table_set_sort(table, (size_t) 0);

        sd_json_variant *i;
        JSON_VARIANT_ARRAY_FOREACH(i, reply) {
                struct {
                        const char *name;
                        const char *description;
                        const char *tag;
                        const char *frontend_type;
                        const char *backend_type;
                        const char *backend_path;
                } e = {};

                static const sd_json_dispatch_field dispatch_table[] = {
                        { "name",         SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(e, name),          0 },
                        { "description",  SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(e, description),   0 },
                        { "tag",          SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(e, tag),           0 },
                        { "frontendType", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(e, frontend_type), 0 },
                        { "backendType",  SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(e, backend_type),  0 },
                        { "backendPath",  SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(e, backend_path),  0 },
                        {}
                };

                r = sd_json_dispatch(i, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &e);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse ListPty() reply: %m");

                r = table_add_many(
                                table,
                                TABLE_STRING, e.name,
                                TABLE_STRING, e.description,
                                TABLE_STRING, e.tag,
                                TABLE_STRING, e.frontend_type,
                                TABLE_STRING, e.backend_type,
                                TABLE_STRING, e.backend_path);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (table_isempty(table)) {
                if (!arg_quiet)
                        log_info("No PTYs.");
                return 0;
        }

        return table_print_or_warn(table);
}

static int monitor_broker_pty(const char *name, int *ret_monitor_fd) {
        int r;

        assert(name);
        assert(ret_monitor_fd);

        /* Attach to an *existing* pseudo TTY allocation via ptybrokerd's MonitorPty(). We neither allocate a
         * new PTY nor spawn a child: MonitorPty() upgrades the connection to a bidirectional socket that
         * carries the monitored frontend's output to us and forwards our input back to it. We use it as the
         * PTY forwarder "master". */

        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        r = pty_broker_connect(arg_runtime_scope, &vl);
        if (r < 0)
                return r;

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *ts = NULL;
        r = pty_broker_terminal_settings_to_json(&ts);
        if (r < 0)
                return log_error_errno(r, "Failed to build terminal settings: %m");

        _cleanup_close_ int input_fd = -EBADF, output_fd = -EBADF;
        sd_json_variant *reply = NULL;
        const char *error_id = NULL;
        r = sd_varlink_call_and_upgradebo(
                        vl,
                        "io.systemd.PTYBroker.MonitorPty",
                        &reply,
                        &error_id,
                        &input_fd,
                        &output_fd,
                        SD_JSON_BUILD_PAIR_STRING("name", name),
                        SD_JSON_BUILD_PAIR_VARIANT("terminalSettings", ts));
        if (r < 0)
                return log_error_errno(r, "Failed to call MonitorPty(): %m");
        if (error_id)
                return log_error_errno(sd_varlink_error_to_errno(error_id, reply),
                                       "Failed to monitor PTY via ptybrokerd: %s", error_id);

        r = same_fd(input_fd, output_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to check if input/output file descriptors match: %m");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EPROTO), "Input/output file descriptor of monitor connection do not match.");

        /* The upgraded monitor connection is a single bidirectional socket, handed to us as two dup'ed fds.
         * The PTY forwarder reads and writes a single "master" fd, so we keep the input side for that and
         * drop the redundant output side. */
        *ret_monitor_fd = TAKE_FD(input_fd);

        return 0;
}

static int pty_forward_handler(PTYForward *f, int rcode, void *userdata) {
        sd_event *e = ASSERT_PTR(userdata);

        assert(f);

        if (rcode == -ECANCELED) {
                log_debug_errno(rcode, "PTY forwarder disconnected.");
                return sd_event_exit(e, EXIT_SUCCESS);
        } else if (rcode < 0) {
                (void) sd_event_exit(e, EXIT_FAILURE);
                return log_error_errno(rcode, "Error on PTY forwarding logic: %m");
        }

        return 0;
}

VERB(verb_monitor, "monitor", "NAME", 2, 2, 0, "Monitor the specified PTY");
static int verb_monitor(int argc, char *argv[], uintptr_t data, void *userdata) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_close_ int monitor_fd = -EBADF;
        _cleanup_(pty_forward_freep) PTYForward *forward = NULL;
        int r;

        r = monitor_broker_pty(argv[1], &monitor_fd);
        if (r < 0)
                return r;

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to get event loop: %m");

        if (!arg_quiet)
                log_info("Press ^] three times within 1s to disconnect TTY.");

        r = pty_forward_new(event, monitor_fd, /* flags= */ 0, &forward);
        if (r < 0)
                return log_error_errno(r, "Failed to create PTY forwarder: %m");

        if (!isempty(arg_background)) {
                r = pty_forward_set_background_color(forward, arg_background);
                if (r < 0)
                        return log_error_errno(r, "Failed to set background color: %m");
        }

        if (shall_set_terminal_title() && !isempty(arg_title)) {
                r = pty_forward_set_title(forward, arg_title);
                if (r < 0)
                        return log_error_errno(r, "Failed to set title: %m");
        }

        pty_forward_set_hangup_handler(forward, pty_forward_handler, event);

        return sd_event_loop(event);
}

typedef struct HangUpContext {
        sd_event *event;
        Set *connections;
        int error;
} HangUpContext;

static void hangup_context_done(HangUpContext *c) {
        assert(c);

        /* Free the connections before the event loop, as they hold event sources attached to it. */
        set_free(c->connections);
        sd_event_unref(c->event);
}

static int on_hangup_reply(
                sd_varlink *link,
                sd_json_variant *parameters,
                const char *error_id,
                sd_varlink_reply_flags_t flags,
                void *userdata) {

        HangUpContext *context = ASSERT_PTR(userdata);

        assert(link);

        /* The name of the PTY this connection hangs up is stashed in the connection's description. */
        const char *name = sd_varlink_get_description(link);

        if (error_id) {
                int e = sd_varlink_error_to_errno(error_id, parameters);
                log_error_errno(e, "Failed to hang up PTY '%s': %s", strna(name), error_id);
                if (context->error == 0)
                        context->error = e;
        }

        /* Drop the completed connection from the set. sd_varlink_process() holds a reference for the duration
         * of this callback, so unreffing here is safe. Once the set has drained we are done. */
        assert_se(set_remove(context->connections, link) == link);
        sd_varlink_unref(link);

        if (set_isempty(context->connections))
                (void) sd_event_exit(context->event, context->error < 0 ? EXIT_FAILURE : EXIT_SUCCESS);

        return 0;
}

VERB(verb_hangup, "hangup", "NAME…", 2, VERB_ANY, 0, "Hang up the specified PTY(s)");
static int verb_hangup(int argc, char *argv[], uintptr_t data, void *userdata) {
        _cleanup_(hangup_context_done) HangUpContext context = {};
        int r;

        r = sd_event_default(&context.event);
        if (r < 0)
                return log_error_errno(r, "Failed to get event loop: %m");

        /* Establish a separate connection to the broker for each PTY to hang up, keep all of them alive in a
         * Set, and enqueue the HangUpPty() calls in parallel. Each reply drops its connection from the set;
         * we only return once the set has drained. */

        STRV_FOREACH(name, strv_skip(argv, 1)) {
                _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
                r = pty_broker_connect(arg_runtime_scope, &vl);
                if (r < 0)
                        return r;

                r = sd_varlink_set_description(vl, *name);
                if (r < 0)
                        return log_error_errno(r, "Failed to set Varlink connection description: %m");

                r = sd_varlink_attach_event(vl, context.event, SD_EVENT_PRIORITY_NORMAL);
                if (r < 0)
                        return log_error_errno(r, "Failed to attach Varlink connection to event loop: %m");

                sd_varlink_set_userdata(vl, &context);

                r = sd_varlink_bind_reply(vl, on_hangup_reply);
                if (r < 0)
                        return log_error_errno(r, "Failed to bind reply callback: %m");

                r = sd_varlink_invokebo(
                                vl,
                                "io.systemd.PTYBroker.HangUpPty",
                                SD_JSON_BUILD_PAIR_STRING("name", *name));
                if (r < 0)
                        return log_error_errno(r, "Failed to enqueue HangUpPty() call: %m");

                r = set_ensure_put(&context.connections, &varlink_hash_ops, vl);
                if (r < 0)
                        return log_oom();

                TAKE_PTR(vl); /* The set owns the connection now. */
        }

        r = sd_event_loop(context.event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        return context.error;
}

static int parse_argv(int argc, char *argv[], char ***ret_args) {
        assert(argc >= 0);
        assert(argv);
        assert(ret_args);

        OptionParser opts = { argc, argv };
        int r;

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION('q', "quiet", NULL, "Suppress information messages during runtime"):
                        arg_quiet = true;
                        break;

                OPTION_LONG("system", NULL, "Talk to system PTY broker"):
                        arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
                        break;

                OPTION_LONG("user", NULL, "Talk to per-user PTY broker"):
                        arg_runtime_scope = RUNTIME_SCOPE_USER;
                        break;

                OPTION_LONG("background", "COLOR", "Set ANSI color for background (when monitoring)"):
                        r = parse_background_argument(opts.arg, &arg_background);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("title", "TITLE", "Set terminal title (when monitoring)"):
                        r = free_and_strdup_warn(&arg_title, opts.arg);
                        if (r < 0)
                                return r;
                        break;
                }

        *ret_args = option_parser_get_args(&opts);
        return 1;
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        char **args = NULL;
        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        return dispatch_verb(args, NULL);
}

DEFINE_MAIN_FUNCTION(run);
