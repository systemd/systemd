/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "sd-daemon.h"

#include "alloc-util.h"
#include "build.h"
#include "env-util.h"
#include "fd-util.h"
#include "fdset.h"
#include "format-util.h"
#include "log.h"
#include "main-func.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "process-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "time-util.h"
#include "user-util.h"

static bool arg_ready = false;
static bool arg_reloading = false;
static bool arg_stopping = false;
static pid_t arg_pid = 0;
static const char *arg_status = NULL;
static bool arg_booted = false;
static uid_t arg_uid = UID_INVALID;
static gid_t arg_gid = GID_INVALID;
static bool arg_no_block = false;
static char **arg_env = NULL;
static char **arg_exec = NULL;
static FDSet *arg_fds = NULL;
static char *arg_fdname = NULL;

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
               "%s [OPTIONS...] --exec [VARIABLE=VALUE...] ; CMDLINE...\n"
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
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
}

static pid_t manager_pid(void) {
        const char *e;
        pid_t pid;
        int r;

        /* If we run as a service managed by systemd --user the $MANAGERPID environment variable points to
         * the service manager's PID. */
        e = getenv("MANAGERPID");
        if (!e)
                return 0;

        r = parse_pid(e, &pid);
        if (r < 0) {
                log_warning_errno(r, "$MANAGERPID is set to an invalid PID, ignoring: %s", e);
                return 0;
        }

        return pid;
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
                {}
        };

        _cleanup_fdset_free_ FDSet *passed = NULL;
        bool do_exec = false;
        int c, r, n_env;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0) {

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
                        if (isempty(optarg) || streq(optarg, "auto")) {
                                arg_pid = getppid();

                                if (arg_pid <= 1 ||
                                    arg_pid == manager_pid()) /* Don't send from PID 1 or the service
                                                               * manager's PID (which might be distinct from
                                                               * 1, if we are a --user instance), that'd just
                                                               * be confusing for the service manager */
                                        arg_pid = getpid_cached();
                        } else if (streq(optarg, "parent"))
                                arg_pid = getppid();
                        else if (streq(optarg, "self"))
                                arg_pid = getpid_cached();
                        else {
                                r = parse_pid(optarg, &arg_pid);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse PID %s.", optarg);
                        }

                        break;

                case ARG_STATUS:
                        arg_status = optarg;
                        break;

                case ARG_BOOTED:
                        arg_booted = true;
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

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }
        }

        if (optind >= argc &&
            !arg_ready &&
            !arg_stopping &&
            !arg_reloading &&
            !arg_status &&
            !arg_pid &&
            !arg_booted &&
            fdset_isempty(arg_fds)) {
                help();
                return -EINVAL;
        }

        if (arg_fdname && fdset_isempty(arg_fds))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No file descriptors passed, but --fdname= set, refusing.");

        if (do_exec) {
                int i;

                for (i = optind; i < argc; i++)
                        if (streq(argv[i], ";"))
                                break;

                if (i >= argc)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "If --exec is used argument list must contain ';' separator, refusing.");
                if (i+1 == argc)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Empty command line specified after ';' separator, refusing");

                arg_exec = strv_copy_n(argv + i + 1, argc - i - 1);
                if (!arg_exec)
                        return log_oom();

                n_env = i - optind;
        } else
                n_env = argc - optind;

        if (n_env > 0) {
                arg_env = strv_copy_n(argv + optind, n_env);
                if (!arg_env)
                        return log_oom();
        }

        if (!fdset_isempty(passed))
                log_warning("Warning: %u more file descriptors passed than referenced with --fd=.", fdset_size(passed));

        return 1;
}

static int run(int argc, char* argv[]) {
        _cleanup_free_ char *status = NULL, *cpid = NULL, *n = NULL, *monotonic_usec = NULL, *fdn = NULL;
        _cleanup_strv_free_ char **final_env = NULL;
        char* our_env[9];
        size_t i = 0;
        pid_t source_pid;
        int r;

        log_show_color(true);
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (arg_booted) {
                r = sd_booted();
                if (r < 0)
                        log_debug_errno(r, "Failed to determine whether we are booted with systemd, assuming we aren't: %m");
                else
                        log_debug("The system %s booted with systemd.", r ? "was" : "was not");

                return r <= 0;
        }

        if (arg_reloading) {
                our_env[i++] = (char*) "RELOADING=1";

                if (asprintf(&monotonic_usec, "MONOTONIC_USEC=" USEC_FMT, now(CLOCK_MONOTONIC)) < 0)
                        return log_oom();

                our_env[i++] = monotonic_usec;
        }

        if (arg_ready)
                our_env[i++] = (char*) "READY=1";

        if (arg_stopping)
                our_env[i++] = (char*) "STOPPING=1";

        if (arg_status) {
                status = strjoin("STATUS=", arg_status);
                if (!status)
                        return log_oom();

                our_env[i++] = status;
        }

        if (arg_pid > 0) {
                if (asprintf(&cpid, "MAINPID="PID_FMT, arg_pid) < 0)
                        return log_oom();

                our_env[i++] = cpid;
        }

        if (!fdset_isempty(arg_fds)) {
                our_env[i++] = (char*) "FDSTORE=1";

                if (arg_fdname) {
                        fdn = strjoin("FDNAME=", arg_fdname);
                        if (!fdn)
                                return log_oom();

                        our_env[i++] = fdn;
                }
        }

        our_env[i++] = NULL;

        final_env = strv_env_merge(our_env, arg_env);
        if (!final_env)
                return log_oom();

        if (strv_isempty(final_env))
                return 0;

        n = strv_join(final_env, "\n");
        if (!n)
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

        if (arg_pid > 0)
                source_pid = arg_pid;
        else {
                /* Pretend the message originates from our parent, given that we are typically called from a
                 * shell script, i.e. we are not the main process of a service but only a child of it. */
                source_pid = getppid();
                if (source_pid <= 1 ||
                    source_pid == manager_pid()) /* safety check: don't claim we'd send anything from PID 1
                                                  * or the service manager itself */
                        source_pid = 0;
        }

        if (fdset_isempty(arg_fds))
                r = sd_pid_notify(source_pid, /* unset_environment= */ false, n);
        else {
                _cleanup_free_ int *a = NULL;
                int k;

                k = fdset_to_array(arg_fds, &a);
                if (k < 0)
                        return log_error_errno(k, "Failed to convert file descriptor set to array: %m");

                r = sd_pid_notify_with_fds(source_pid, /* unset_environment= */ false, n, a, k);

        }
        if (r < 0)
                return log_error_errno(r, "Failed to notify init system: %m");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "No status data could be sent: $NOTIFY_SOCKET was not set");

        arg_fds = fdset_free(arg_fds); /* Close before we execute anything */

        if (!arg_no_block) {
                r = sd_pid_notify_barrier(source_pid, /* unset_environment= */ false, 5 * USEC_PER_SEC);
                if (r < 0)
                        return log_error_errno(r, "Failed to invoke barrier: %m");
                if (r == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "No status data could be sent: $NOTIFY_SOCKET was not set");
        }

        if (arg_exec) {
                _cleanup_free_ char *cmdline = NULL;

                execvp(arg_exec[0], arg_exec);

                cmdline = strv_join(arg_exec, " ");
                if (!cmdline)
                        return log_oom();

                return log_error_errno(errno, "Failed to execute command line: %s", cmdline);
        }

        /* The DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE() boilerplate will send the exit status via
         * sd_notify(). Which is normally fine, but very confusing in systemd-notify, whose purpose is to
         * send user-controllable notification messages, and not implicit ones. Let's turn if off, by
         * unsetting the $NOTIFY_SOCKET environment variable. */
        (void) unsetenv("NOTIFY_SOCKET");
        return 0;
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
