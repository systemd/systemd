/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "build.h"
#include "event-util.h"
#include "fd-util.h"
#include "format-table.h"
#include "log.h"
#include "main-func.h"
#include "options.h"
#include "parse-argument.h"
#include "pidref.h"
#include "pretty-print.h"
#include "process-util.h"
#include "ptyfwd.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"

static bool arg_quiet = false;
static bool arg_read_only = false;
static char *arg_background = NULL;
static char *arg_title = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_background, freep);
STATIC_DESTRUCTOR_REGISTER(arg_title, freep);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        _cleanup_(table_unrefp) Table *options = NULL;
        int r;

        r = terminal_urlify_man("systemd-pty-forward", "1", &link);
        if (r < 0)
                return log_oom();

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        printf("%s [OPTIONS...] COMMAND ...\n"
               "\n%sRun command with a custom terminal background color or title.%s\n"
               "\n%sOptions:%s\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               ansi_underline(),
               ansi_normal());

        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        printf("\nSee the %s for details.\n", link);
        return 0;
}

static int parse_argv(int argc, char *argv[], char ***remaining_args) {
        assert(argc >= 0);
        assert(argv);
        assert(remaining_args);

        OptionParser state = { argc, argv, OPTION_PARSER_STOP_AT_FIRST_NONOPTION };
        const char *arg;
        int r;

        FOREACH_OPTION(&state, c, &arg, /* on_error= */ return c)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION('q', "quiet", NULL, "Suppress information messages during runtime"):
                        arg_quiet = true;
                        break;

                OPTION_LONG("read-only", NULL, "Do not accept any user input on stdin"):
                        arg_read_only = true;
                        break;

                OPTION_LONG("background", "COLOR", "Set ANSI color for background"):
                        r = parse_background_argument(arg, &arg_background);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("title", "TITLE", "Set terminal title"):
                        r = free_and_strdup_warn(&arg_title, arg);
                        if (r < 0)
                                return r;
                        break;
                }

        if (option_parser_get_n_args(&state) == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Expected command line, refusing.");

        *remaining_args = option_parser_get_args(&state);
        return 1;
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

static int helper_on_exit(sd_event_source *s, const siginfo_t *si, void *userdata) {
        /* Add 128 to signal exit statuses to mimic shells. */
        return sd_event_exit(sd_event_source_get_event(s), si->si_status + (si->si_code == CLD_EXITED ? 0 : 128));
}

static int run(int argc, char *argv[]) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_close_ int pty_fd = -EBADF, peer_fd = -EBADF;
        _cleanup_(pty_forward_freep) PTYForward *forward = NULL;
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *child = NULL;
        sd_event_source **forward_signal_sources = NULL;
        size_t n_forward_signal_sources = 0;
        int r;

        CLEANUP_ARRAY(forward_signal_sources, n_forward_signal_sources, event_source_unref_many);

        log_setup();

        char **args = NULL;
        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        _cleanup_strv_free_ char **l = strv_copy(args);
        if (!l)
                return log_oom();

        assert_se(!strv_isempty(l));

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to get event loop: %m");

        pty_fd = openpt_allocate(O_RDWR|O_NOCTTY|O_NONBLOCK|O_CLOEXEC, /* ret_peer_path= */ NULL);
        if (pty_fd < 0)
                return log_error_errno(pty_fd, "Failed to acquire pseudo tty: %m");

        peer_fd = pty_open_peer(pty_fd, O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (peer_fd < 0)
                return log_error_errno(peer_fd, "Failed to open pty peer: %m");

        if (!arg_quiet)
                log_info("Press ^] three times within 1s to disconnect TTY.");

        r = pty_forward_new(event, pty_fd, arg_read_only ? PTY_FORWARD_READ_ONLY : 0, &forward);
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

        r = pidref_safe_fork_full(
                        "(sd-ptyfwd)",
                        (int[]) { peer_fd, peer_fd, peer_fd },
                        /* except_fds= */ NULL,
                        /* n_except_fds= */ 0,
                        /* flags= */ FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_REARRANGE_STDIO,
                        &pidref);
        if (r < 0)
                return log_error_errno(r, "Failed to fork child: %m");
        if (r == 0) {
                r = terminal_new_session();
                if (r < 0)
                        return log_error_errno(r, "Failed to create new session: %m");

                (void) execvp(l[0], l);
                log_error_errno(errno, "Failed to execute %s: %m", l[0]);
                _exit(EXIT_FAILURE);
        }

        peer_fd = safe_close(peer_fd);

        r = event_add_child_pidref(event, &child, &pidref, WEXITED, helper_on_exit, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to add child event source: %m");

        r = sd_event_source_set_child_process_own(child, true);
        if (r < 0)
                return log_error_errno(r, "Failed to take ownership of child process: %m");

        /* Make sure we don't forward signals to a dead child process by increasing the priority of the child
         * process event source. */
        r = sd_event_source_set_priority(child, SD_EVENT_PRIORITY_IMPORTANT);
        if (r < 0)
                return log_error_errno(r, "Failed to set child event source priority: %m");

        r = event_forward_signals(
                        event,
                        child,
                        pty_forward_signals, ELEMENTSOF(pty_forward_signals),
                        &forward_signal_sources, &n_forward_signal_sources);
        if (r < 0)
                return log_error_errno(r, "Failed to set up signal forwarding: %m");

        return sd_event_loop(event);
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
