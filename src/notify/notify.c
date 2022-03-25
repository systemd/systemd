/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "sd-daemon.h"

#include "alloc-util.h"
#include "env-util.h"
#include "format-util.h"
#include "log.h"
#include "main-func.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "time-util.h"
#include "user-util.h"
#include "util.h"

static bool arg_ready = false;
static pid_t arg_pid = 0;
static const char *arg_status = NULL;
static bool arg_booted = false;
static uid_t arg_uid = UID_INVALID;
static gid_t arg_gid = GID_INVALID;
static bool arg_no_block = false;

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-notify", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] [VARIABLE=VALUE...]\n"
               "\n%sNotify the init system about service status updates.%s\n\n"
               "  -h --help            Show this help\n"
               "     --version         Show package version\n"
               "     --ready           Inform the init system about service start-up completion\n"
               "     --pid[=PID]       Set main PID of daemon\n"
               "     --uid=USER        Set user to send from\n"
               "     --status=TEXT     Set status text\n"
               "     --booted          Check if the system was booted up with systemd\n"
               "     --no-block        Do not wait until operation finished\n"
               "\nSee the %s for details.\n",
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
                ARG_VERSION,
                ARG_PID,
                ARG_STATUS,
                ARG_BOOTED,
                ARG_UID,
                ARG_NO_BLOCK
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'           },
                { "version",   no_argument,       NULL, ARG_VERSION   },
                { "ready",     no_argument,       NULL, ARG_READY     },
                { "pid",       optional_argument, NULL, ARG_PID       },
                { "status",    required_argument, NULL, ARG_STATUS    },
                { "booted",    no_argument,       NULL, ARG_BOOTED    },
                { "uid",       required_argument, NULL, ARG_UID       },
                { "no-block",  no_argument,       NULL, ARG_NO_BLOCK  },
                {}
        };

        int c, r;

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

                case ARG_PID:
                        if (isempty(optarg) || streq(optarg, "auto")) {
                                arg_pid = getppid();

                                if (arg_pid <= 1 ||
                                    arg_pid == manager_pid()) /* Don't send from PID 1 or the service
                                                               * manager's PID (which might be distinct from
                                                               * 1, if we are a --user instance), that'd just
                                                               * be confusing for the service manager */
                                        arg_pid = getpid();
                        } else if (streq(optarg, "parent"))
                                arg_pid = getppid();
                        else if (streq(optarg, "self"))
                                arg_pid = getpid();
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

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }
        }

        if (optind >= argc &&
            !arg_ready &&
            !arg_status &&
            !arg_pid &&
            !arg_booted) {
                help();
                return -EINVAL;
        }

        return 1;
}

static int run(int argc, char* argv[]) {
        _cleanup_free_ char *status = NULL, *cpid = NULL, *n = NULL;
        _cleanup_strv_free_ char **final_env = NULL;
        char* our_env[4];
        unsigned i = 0;
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

        if (arg_ready)
                our_env[i++] = (char*) "READY=1";

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

        our_env[i++] = NULL;

        final_env = strv_env_merge(our_env, argv + optind);
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
        r = sd_pid_notify(source_pid, false, n);
        if (r < 0)
                return log_error_errno(r, "Failed to notify init system: %m");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "No status data could be sent: $NOTIFY_SOCKET was not set");

        if (!arg_no_block) {
                r = sd_notify_barrier(0, 5 * USEC_PER_SEC);
                if (r < 0)
                        return log_error_errno(r, "Failed to invoke barrier: %m");
                if (r == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "No status data could be sent: $NOTIFY_SOCKET was not set");
        }

        return 0;
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
