/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <unistd.h>

#include "alloc-util.h"
#include "build.h"
#include "event-util.h"
#include "fd-util.h"
#include "main-func.h"
#include "pretty-print.h"
#include "ptyfwd.h"
#include "strv.h"

static bool arg_quiet = false;
static bool arg_read_only = false;
static char *arg_background = NULL;
static char *arg_title = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_background, freep);
STATIC_DESTRUCTOR_REGISTER(arg_title, freep);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-pty-forward", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s  [OPTIONS...] COMMAND ...\n"
               "\n%5$sRun command with a custom terminal background color or title.%6$s\n"
               "\n%3$sOptions:%4$s\n"
               "  -h --help              Show this help\n"
               "     --version           Print version\n"
               "  -q --quiet             Suppress information messages during runtime\n"
               "     --read-only         Do not accept any user input on stdin\n"
               "     --background=COLOR  Set ANSI color for background\n"
               "     --title=TITLE       Set terminal title\n"
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
                ARG_READ_ONLY,
                ARG_BACKGROUND,
                ARG_TITLE,
        };

        static const struct option options[] = {
                { "help",               no_argument,       NULL, 'h'                    },
                { "version",            no_argument,       NULL, ARG_VERSION            },
                { "quiet",              no_argument,       NULL, 'q'                    },
                { "read-only",          no_argument,       NULL, ARG_READ_ONLY          },
                { "background",         required_argument, NULL, ARG_BACKGROUND         },
                { "title",              required_argument, NULL, ARG_TITLE              },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        optind = 0;
        while ((c = getopt_long(argc, argv, "+hq", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case 'q':
                        arg_quiet = true;
                        break;

                case ARG_READ_ONLY:
                        arg_read_only = true;
                        break;

                case ARG_BACKGROUND:
                        r = free_and_strdup_warn(&arg_background, optarg);
                        if (r < 0)
                                return r;
                        break;

                case ARG_TITLE:
                        r = free_and_strdup_warn(&arg_title, optarg);
                        if (r < 0)
                                return r;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

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
        _cleanup_(sd_event_source_unrefp) sd_event_source *exit_source = NULL;
        int r;

        log_setup();

        assert_se(sigprocmask_many(SIG_BLOCK, /*ret_old_mask=*/ NULL, SIGCHLD) >= 0);

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        _cleanup_strv_free_ char **l = strv_copy(argv + optind);
        if (!l)
                return log_oom();

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to get event loop: %m");

        (void) sd_event_set_signal_exit(event, true);

        pty_fd = openpt_allocate(O_RDWR|O_NOCTTY|O_NONBLOCK|O_CLOEXEC, /*ret_peer=*/ NULL);
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

        pty_forward_set_handler(forward, pty_forward_handler, event);

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

        r = event_add_child_pidref(event, &exit_source, &pidref, WEXITED, helper_on_exit, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to add child event source: %m");

        r = sd_event_source_set_child_process_own(exit_source, true);
        if (r < 0)
                return log_error_errno(r, "Failed to take ownership of child process: %m");

        return sd_event_loop(event);
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
