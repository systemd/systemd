/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "sd-daemon.h"
#include "sd-event.h"

#include "alloc-util.h"
#include "build.h"
#include "env-util.h"
#include "escape.h"
#include "event-util.h"
#include "exit-status.h"
#include "fd-util.h"
#include "fdset.h"
#include "format-util.h"
#include "log.h"
#include "main-func.h"
#include "notify-recv.h"
#include "parse-util.h"
#include "pidref.h"
#include "pretty-print.h"
#include "process-util.h"
#include "signal-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "user-util.h"

static enum {
        ACTION_NOTIFY,
        ACTION_BOOTED,
        ACTION_FORK,
} arg_action = ACTION_NOTIFY;
static bool arg_ready = false;
static bool arg_reloading = false;
static bool arg_stopping = false;
static PidRef arg_pid = PIDREF_NULL;
static const char *arg_status = NULL;
static uid_t arg_uid = UID_INVALID;
static gid_t arg_gid = GID_INVALID;
static bool arg_no_block = false;
static char **arg_env = NULL;
static char **arg_exec = NULL;
static FDSet *arg_fds = NULL;
static char *arg_fdname = NULL;
static bool arg_quiet = false;

STATIC_DESTRUCTOR_REGISTER(arg_pid, pidref_done);
STATIC_DESTRUCTOR_REGISTER(arg_env, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_exec, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_fds, fdset_freep);
STATIC_DESTRUCTOR_REGISTER(arg_fdname, freep);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-notify", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] [VARIABLE=VALUE...]\n"
               "%s [OPTIONS...] --exec [VARIABLE=VALUE...] ; -- CMDLINE...\n"
               "%s [OPTIONS...] --fork -- CMDLINE...\n"
               "\n%sNotify the init system about service status updates.%s\n\n"
               "  -h --help            Show this help\n"
               "     --version         Show package version\n"
               "     --ready           Inform the service manager about service start-up/reload\n"
               "                       completion\n"
               "     --reloading       Inform the service manager about configuration reloading\n"
               "     --stopping        Inform the service manager about service shutdown\n"
               "     --pid[=PID]       Set main PID of daemon\n"
               "     --uid=USER        Set user to send from\n"
               "     --status=TEXT     Set status text\n"
               "     --booted          Check if the system was booted up with systemd\n"
               "     --no-block        Do not wait until operation finished\n"
               "     --exec            Execute command line separated by ';' once done\n"
               "     --fd=FD           Pass specified file descriptor with along with message\n"
               "     --fdname=NAME     Name to assign to passed file descriptor(s)\n"
               "     --fork            Receive notifications from child rather than sending them\n"
               "  -q --quiet           Do not show PID of child when forking\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               program_invocation_short_name,
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
}

static int get_manager_pid(PidRef *ret) {
        int r;

        assert(ret);

        /* If we run as a service managed by systemd --user the $MANAGERPID environment variable points to
         * the service manager's PID. */
        const char *e = getenv("MANAGERPID");
        if (!e) {
                *ret = PIDREF_NULL;
                return 0;
        }

        _cleanup_(pidref_done) PidRef manager = PIDREF_NULL;
        r = pidref_set_pidstr(&manager, e);
        if (r < 0)
                return log_warning_errno(r, "$MANAGERPID is set to an invalid PID, ignoring: %s", e);

        e = getenv("MANAGERPIDFDID");
        if (e) {
                uint64_t manager_pidfd_id;

                r = safe_atou64(e, &manager_pidfd_id);
                if (r < 0)
                        return log_warning_errno(r, "$MANAGERPIDFDID is not set to a valid inode number, ignoring: %s", e);

                r = pidref_acquire_pidfd_id(&manager);
                if (r < 0)
                        return log_warning_errno(r, "Unable to acquire pidfd ID for manager: %m");

                if (manager_pidfd_id != manager.fd_id) {
                        log_debug("$MANAGERPIDFDID doesn't match process currently referenced by $MANAGERPID, suppressing.");
                        *ret = PIDREF_NULL;
                        return 0;
                }
        }

        *ret = TAKE_PIDREF(manager);
        return 1;
}

static int pidref_parent_if_applicable(PidRef *ret) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL, manager = PIDREF_NULL;
        int r;

        assert(ret);

        r = pidref_set_parent(&pidref);
        if (r < 0)
                return log_debug_errno(r, "Failed to create reference to our parent process: %m");

        /* Don't send from PID 1 or the service manager's PID (which might be distinct from 1, if we are a
         * --user service). That'd just be confusing for the service manager. */
        if (pidref.pid == 1)
                goto from_self;

        r = get_manager_pid(&manager);
        if (r > 0 && pidref_equal(&pidref, &manager))
                goto from_self;

        *ret = TAKE_PIDREF(pidref);
        return 0;

from_self:
        return pidref_set_self(ret);
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_READY = 0x100,
                ARG_RELOADING,
                ARG_STOPPING,
                ARG_VERSION,
                ARG_PID,
                ARG_STATUS,
                ARG_BOOTED,
                ARG_UID,
                ARG_NO_BLOCK,
                ARG_EXEC,
                ARG_FD,
                ARG_FDNAME,
                ARG_FORK,
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'           },
                { "version",   no_argument,       NULL, ARG_VERSION   },
                { "ready",     no_argument,       NULL, ARG_READY     },
                { "reloading", no_argument,       NULL, ARG_RELOADING },
                { "stopping",  no_argument,       NULL, ARG_STOPPING  },
                { "pid",       optional_argument, NULL, ARG_PID       },
                { "status",    required_argument, NULL, ARG_STATUS    },
                { "booted",    no_argument,       NULL, ARG_BOOTED    },
                { "uid",       required_argument, NULL, ARG_UID       },
                { "no-block",  no_argument,       NULL, ARG_NO_BLOCK  },
                { "exec",      no_argument,       NULL, ARG_EXEC      },
                { "fd",        required_argument, NULL, ARG_FD        },
                { "fdname",    required_argument, NULL, ARG_FDNAME    },
                { "fork",      no_argument,       NULL, ARG_FORK      },
                { "quiet",     no_argument,       NULL, 'q'           },
                {}
        };

        _cleanup_fdset_free_ FDSet *passed = NULL;
        bool do_exec = false;
        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hq", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_READY:
                        arg_ready = true;
                        break;

                case ARG_RELOADING:
                        arg_reloading = true;
                        break;

                case ARG_STOPPING:
                        arg_stopping = true;
                        break;

                case ARG_PID:
                        pidref_done(&arg_pid);

                        if (isempty(optarg) || streq(optarg, "auto"))
                                r = pidref_parent_if_applicable(&arg_pid);
                        else if (streq(optarg, "parent"))
                                r = pidref_set_parent(&arg_pid);
                        else if (streq(optarg, "self"))
                                r = pidref_set_self(&arg_pid);
                        else
                                r = pidref_set_pidstr(&arg_pid, optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to refer to --pid='%s': %m", optarg);

                        break;

                case ARG_STATUS:
                        arg_status = optarg;
                        break;

                case ARG_BOOTED:
                        arg_action = ACTION_BOOTED;
                        break;

                case ARG_UID: {
                        const char *u = optarg;

                        r = get_user_creds(&u, &arg_uid, &arg_gid, NULL, NULL, 0);
                        if (r == -ESRCH) /* If the user doesn't exist, then accept it anyway as numeric */
                                r = parse_uid(u, &arg_uid);
                        if (r < 0)
                                return log_error_errno(r, "Can't resolve user %s: %m", optarg);

                        break;
                }

                case ARG_NO_BLOCK:
                        arg_no_block = true;
                        break;

                case ARG_EXEC:
                        do_exec = true;
                        break;

                case ARG_FD: {
                        _cleanup_close_ int owned_fd = -EBADF;
                        int fdnr;

                        fdnr = parse_fd(optarg);
                        if (fdnr < 0)
                                return log_error_errno(fdnr, "Failed to parse file descriptor: %s", optarg);

                        if (!passed) {
                                /* Take possession of all passed fds */
                                r = fdset_new_fill(/* filter_cloexec= */ 0, &passed);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to take possession of passed file descriptors: %m");
                        }

                        if (fdnr < 3) {
                                /* For stdin/stdout/stderr we want to keep the fd, too, hence make a copy */
                                owned_fd = fcntl(fdnr, F_DUPFD_CLOEXEC, 3);
                                if (owned_fd < 0)
                                        return log_error_errno(errno, "Failed to duplicate file descriptor: %m");
                        } else {
                                /* Otherwise, move the fd over */
                                owned_fd = fdset_remove(passed, fdnr);
                                if (owned_fd < 0)
                                        return log_error_errno(owned_fd, "Specified file descriptor '%i' not passed or specified more than once: %m", fdnr);
                        }

                        if (!arg_fds) {
                                arg_fds = fdset_new();
                                if (!arg_fds)
                                        return log_oom();
                        }

                        r = fdset_consume(arg_fds, TAKE_FD(owned_fd));
                        if (r < 0)
                                return log_error_errno(r, "Failed to add file descriptor to set: %m");
                        break;
                }

                case ARG_FDNAME:
                        if (!fdname_is_valid(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "File descriptor name invalid: %s", optarg);

                        if (free_and_strdup(&arg_fdname, optarg) < 0)
                                return log_oom();

                        break;

                case ARG_FORK:
                        arg_action = ACTION_FORK;
                        break;

                case 'q':
                        arg_quiet = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }
        }

        bool have_env = arg_ready || arg_stopping || arg_reloading || arg_status || pidref_is_set(&arg_pid) || !fdset_isempty(arg_fds);

        switch (arg_action) {

        case ACTION_NOTIFY: {
                if (arg_fdname && fdset_isempty(arg_fds))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No file descriptors passed, but --fdname= set, refusing.");

                size_t n_arg_env;

                if (do_exec) {
                        int i;

                        for (i = optind; i < argc; i++)
                                if (streq(argv[i], ";"))
                                        break;

                        if (i >= argc)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "If --exec is used argument list must contain ';' separator, refusing.");
                        if (i+1 == argc)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Empty command line specified after ';' separator, refusing.");

                        arg_exec = strv_copy_n(argv + i + 1, argc - i - 1);
                        if (!arg_exec)
                                return log_oom();

                        n_arg_env = i - optind;
                } else
                        n_arg_env = argc - optind;

                have_env = have_env || n_arg_env > 0;
                if (!have_env) {
                        if (do_exec)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No notify message specified while --exec, refusing.");

                        /* No argument at all? */
                        help();
                        return -EINVAL;
                }

                if (n_arg_env > 0) {
                        arg_env = strv_copy_n(argv + optind, n_arg_env);
                        if (!arg_env)
                                return log_oom();
                }

                if (!fdset_isempty(passed))
                        log_warning("Warning: %u more file descriptors passed than referenced with --fd=.", fdset_size(passed));

                break;
        }

        case ACTION_BOOTED:
                if (argc > optind)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--booted takes no parameters, refusing.");

                break;

        case ACTION_FORK:
                if (optind >= argc)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--fork requires a command to be specified, refusing.");

                break;

        default:
                assert_not_reached();
        }

        if (have_env && arg_action != ACTION_NOTIFY)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--ready, --reloading, --stopping, --pid=, --status=, --fd= may not be combined with --fork or --booted, refusing.");

        return 1;
}

static int on_notify_socket(sd_event_source *s, int fd, unsigned event, void *userdata) {
        PidRef *child = ASSERT_PTR(userdata);
        int r;

        assert(s);
        assert(fd >= 0);

        _cleanup_free_ char *text = NULL;
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        r = notify_recv(fd, &text, /* ret_ucred= */ NULL, &pidref);
        if (r == -EAGAIN)
                return 0;
        if (r < 0)
                return r;

        if (!pidref_equal(child, &pidref)) {
                log_warning("Received notification message from unexpected process " PID_FMT " (expected " PID_FMT "), ignoring.",
                            pidref.pid, child->pid);
                return 0;
        }

        const char *p = find_line_startswith(text, "READY=1");
        if (!p || !IN_SET(*p, '\n', 0)) {
                if (!DEBUG_LOGGING)
                        return 0;

                _cleanup_free_ char *escaped = cescape(text);
                log_debug("Received notification message without READY=1, ignoring: %s", strna(escaped));
                return 0;
        }

        log_debug("Received READY=1, exiting.");
        return sd_event_exit(sd_event_source_get_event(s), EXIT_SUCCESS);
}

static int on_child(sd_event_source *s, const siginfo_t *si, void *userdata) {
        assert(s);
        assert(si);

        int ret;
        if (si->si_code == CLD_EXITED) {
                if (si->si_status != EXIT_SUCCESS)
                        log_debug("Child failed with exit status %i.", si->si_status);
                else
                        log_debug("Child exited successfully. (But no READY=1 message was sent!)");

                /* NB: we propagate success here if the child exited cleanly but never sent us READY=1. We
                 * are not a service manager after all, where this would be a protocol violation. We are just
                 * a shell tool to fork off stuff in the background, where I think it makes sense to allow
                 * clean early exit of forked off processes. */
                ret = si->si_status;

        } else if (IN_SET(si->si_code, CLD_KILLED, CLD_DUMPED))
                ret = log_debug_errno(SYNTHETIC_ERRNO(EPROTO),
                                      "Child terminated by signal %s.", signal_to_string(si->si_status));
        else
                ret = log_debug_errno(SYNTHETIC_ERRNO(EPROTO),
                                      "Child terminated due to unknown reason.");

        return sd_event_exit(sd_event_source_get_event(s), ret);
}

static int action_fork(char *const *_command) {

        static const int forward_signals[] = {
                SIGHUP,
                SIGTERM,
                SIGINT,
                SIGQUIT,
                SIGTSTP,
                SIGCONT,
                SIGUSR1,
                SIGUSR2,
        };

        int r;

        assert(!strv_isempty(_command));

        /* Make a copy, since pidref_safe_fork_full() will change argv[] further down. */
        _cleanup_strv_free_ char **command = strv_copy(_command);
        if (!command)
                return log_oom();

        _cleanup_free_ char *c = strv_join(command, " ");
        if (!c)
                return log_oom();

        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        r = sd_event_new(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        _cleanup_(pidref_done) PidRef child = PIDREF_NULL;
        _cleanup_free_ char *addr_string = NULL;
        r = notify_socket_prepare(
                        event,
                        SD_EVENT_PRIORITY_NORMAL - 10, /* If we receive both the sd_notify() message and a
                                                        * SIGCHLD always process sd_notify() first, it's the
                                                        * more interesting, "positive" information. */
                        on_notify_socket,
                        &child,
                        &addr_string);
        if (r < 0)
                return log_error_errno(r, "Failed to prepare notify socket: %m");

        r = pidref_safe_fork_full(
                        "(notify)",
                        /* stdio_fds= */ (const int[]) { -EBADF, -EBADF, STDERR_FILENO },
                        /* except_fds= */ NULL,
                        /* n_except_fds= */ 0,
                        /* flags= */ FORK_REARRANGE_STDIO,
                        &child);
        if (r < 0)
                return log_error_errno(r, "Failed to fork child in order to execute '%s': %m", c);
        if (r == 0) {
                if (setenv("NOTIFY_SOCKET", addr_string, /* overwrite= */ true) < 0) {
                        log_error_errno(errno, "Failed to set $NOTIFY_SOCKET: %m");
                        _exit(EXIT_MEMORY);
                }

                log_debug("Executing: %s", c);
                execvp(command[0], command);
                log_error_errno(errno, "Failed to execute '%s': %m", c);
                _exit(EXIT_EXEC);
        }

        if (!arg_quiet) {
                printf(PID_FMT "\n", child.pid);
                fflush(stdout);
        }

        BLOCK_SIGNALS(SIGCHLD);

        _cleanup_(sd_event_source_disable_unrefp) sd_event_source *child_event_source = NULL;
        r = event_add_child_pidref(event, &child_event_source, &child, WEXITED, on_child, /* userdata= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate child source: %m");

        /* Handle SIGCHLD before propagating the other signals below */
        r = sd_event_source_set_priority(child_event_source, SD_EVENT_PRIORITY_NORMAL - 5);
        if (r < 0)
                return log_error_errno(r, "Failed to change child event source priority: %m");

        sd_event_source **forward_signal_sources = NULL;
        size_t n_forward_signal_sources = 0;
        CLEANUP_ARRAY(forward_signal_sources, n_forward_signal_sources, event_source_unref_many);

        r = event_forward_signals(
                        event,
                        child_event_source,
                        forward_signals, ELEMENTSOF(forward_signals),
                        &forward_signal_sources, &n_forward_signal_sources);
        if (r < 0)
                return log_error_errno(r, "Failed to set up signal forwarding: %m");

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        return r;
}

static int run(int argc, char* argv[]) {
        _cleanup_free_ char *status = NULL, *main_pid = NULL, *main_pidfd_id = NULL, *msg = NULL,
                       *monotonic_usec = NULL, *fdn = NULL;
        _cleanup_strv_free_ char **final_env = NULL;
        const char *our_env[10];
        size_t i = 0;
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (arg_action == ACTION_FORK)
                return action_fork(argv + optind);

        if (arg_action == ACTION_BOOTED) {
                r = sd_booted();
                if (r < 0)
                        log_debug_errno(r, "Failed to determine whether we are booted with systemd, assuming we aren't: %m");
                else
                        log_debug("The system %s booted with systemd.", r ? "was" : "was not");

                return r <= 0;
        }

        if (arg_reloading) {
                our_env[i++] = "RELOADING=1";

                if (asprintf(&monotonic_usec, "MONOTONIC_USEC=" USEC_FMT, now(CLOCK_MONOTONIC)) < 0)
                        return log_oom();

                our_env[i++] = monotonic_usec;
        }

        if (arg_ready)
                our_env[i++] = "READY=1";

        if (arg_stopping)
                our_env[i++] = "STOPPING=1";

        if (arg_status) {
                status = strjoin("STATUS=", arg_status);
                if (!status)
                        return log_oom();

                our_env[i++] = status;
        }

        if (pidref_is_set(&arg_pid)) {
                if (asprintf(&main_pid, "MAINPID="PID_FMT, arg_pid.pid) < 0)
                        return log_oom();

                our_env[i++] = main_pid;

                r = pidref_acquire_pidfd_id(&arg_pid);
                if (r < 0)
                        log_debug_errno(r, "Unable to acquire pidfd id of new main pid " PID_FMT ", ignoring: %m",
                                        arg_pid.pid);
                else {
                        if (asprintf(&main_pidfd_id, "MAINPIDFDID=%" PRIu64, arg_pid.fd_id) < 0)
                                return log_oom();

                        our_env[i++] = main_pidfd_id;
                }
        }

        if (!fdset_isempty(arg_fds)) {
                our_env[i++] = "FDSTORE=1";

                if (arg_fdname) {
                        fdn = strjoin("FDNAME=", arg_fdname);
                        if (!fdn)
                                return log_oom();

                        our_env[i++] = fdn;
                }
        }

        our_env[i++] = NULL;

        final_env = strv_env_merge((char**) our_env, arg_env);
        if (!final_env)
                return log_oom();
        assert(!strv_isempty(final_env));

        msg = strv_join(final_env, "\n");
        if (!msg)
                return log_oom();

        /* If this is requested change to the requested UID/GID. Note that we only change the real UID here, and leave
           the effective UID in effect (which is 0 for this to work). That's because we want the privileges to fake the
           ucred data, and sd_pid_notify() uses the real UID for filling in ucred. */

        if (arg_gid != GID_INVALID &&
            setregid(arg_gid, GID_INVALID) < 0)
                return log_error_errno(errno, "Failed to change GID: %m");

        if (arg_uid != UID_INVALID &&
            setreuid(arg_uid, UID_INVALID) < 0)
                return log_error_errno(errno, "Failed to change UID: %m");

        /* If --pid= is explicitly specified, use it as source pid. Otherwise, pretend the message originates
         * from our parent, i.e. --pid=auto */
        if (!pidref_is_set(&arg_pid))
                (void) pidref_parent_if_applicable(&arg_pid);

        if (fdset_isempty(arg_fds))
                r = sd_pid_notify(arg_pid.pid, /* unset_environment= */ false, msg);
        else {
                _cleanup_free_ int *a = NULL;
                int k;

                k = fdset_to_array(arg_fds, &a);
                if (k < 0)
                        return log_error_errno(k, "Failed to convert file descriptor set to array: %m");

                r = sd_pid_notify_with_fds(arg_pid.pid, /* unset_environment= */ false, msg, a, k);

        }
        if (r == -E2BIG)
                return log_error_errno(r, "Too many file descriptors passed.");
        if (r < 0)
                return log_error_errno(r, "Failed to notify init system: %m");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "No status data could be sent: $NOTIFY_SOCKET was not set");

        arg_fds = fdset_free(arg_fds); /* Close before we execute anything */

        if (!arg_no_block) {
                r = sd_pid_notify_barrier(arg_pid.pid, /* unset_environment= */ false, 5 * USEC_PER_SEC);
                if (r < 0)
                        return log_error_errno(r, "Failed to invoke barrier: %m");
                if (r == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "No status data could be sent: $NOTIFY_SOCKET was not set");
        }

        if (arg_exec) {
                execvp(arg_exec[0], arg_exec);

                _cleanup_free_ char *cmdline = strv_join(arg_exec, " ");
                return log_error_errno(errno, "Failed to execute command line: %s", strnull(cmdline));
        }

        /* The DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE() boilerplate will send the exit status via
         * sd_notify(). Which is normally fine, but very confusing in systemd-notify, whose purpose is to
         * send user-controllable notification messages, and not implicit ones. Let's turn if off, by
         * unsetting the $NOTIFY_SOCKET environment variable. */
        (void) unsetenv("NOTIFY_SOCKET");
        return 0;
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
