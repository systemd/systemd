/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <sys/file.h>

#include "blockdev-util.h"
#include "btrfs-util.h"
#include "fd-util.h"
#include "main-func.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "process-util.h"
#include "signal-util.h"
#include "stat-util.h"
#include "strv.h"
#include "time-util.h"

static usec_t arg_timeout_usec = USEC_INFINITY;
static char *arg_device = NULL;
static char **arg_cmdline = NULL;
static bool arg_print = false;
static bool arg_find = false;

STATIC_DESTRUCTOR_REGISTER(arg_cmdline, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_device, freep);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-lockdev", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] [DEVICE] [COMMAND]\n"
               "%s [OPTIONS...] --print [DEVICE]\n"
               "\n%sLock a block device and run a comand.%s\n\n"
               "  -h --help            Show this help\n"
               "     --version         Show package version\n"
               "  -t --timeout=SECS    Block at most the specified time waiting for lock\n"
               "  -p --print           Only show which block device the lock will be taken on\n"
               "     --find=BOOL       Find backing device of file or directory\n"
               "  -f                   Short for --find=yes\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_FIND,
        };

        static const struct option options[] = {
                { "help",    no_argument,       NULL, 'h'         },
                { "version", no_argument,       NULL, ARG_VERSION },
                { "timeout", required_argument, NULL, 't'         },
                { "print",   no_argument,       NULL, 'p'         },
                { "find",    no_argument,       NULL, ARG_FIND    },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, arg_print ? "ht:pf" : "+ht:pf", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case 't':
                        r = parse_sec(optarg, &arg_timeout_usec);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --timeout= parameter: %s", optarg);
                        break;

                case 'p':
                        arg_print = true;
                        break;

                case ARG_FIND:
                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --find= parameter: %s", optarg);

                        arg_find = r;
                        break;

                case 'f':
                        arg_find = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (arg_print) {
                if (optind + 1 != argc)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unexpected number of arguments. Expected block device path.");
        } else {
                if (optind + 2 > argc)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Too few arguments, expected block device path and command to execute.");

                arg_cmdline = strv_copy(argv + optind + 1);
                if (!arg_cmdline)
                        return log_oom();
        }

        arg_device = strdup(argv[optind]);
        if (!arg_device)
                return log_oom();

        return 1;
}

static int run(int argc, char* argv[]) {
        _cleanup_free_ char *whole_node = NULL;
        _cleanup_close_ int fd = -1;
        dev_t devt, whole_devt;
        struct stat st;
        pid_t pid;
        int r;

        log_show_color(true);
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (stat(arg_device, &st) < 0)
                return log_error_errno(errno, "Failed to stat '%s': %m", arg_device);

        if (S_ISBLK(st.st_mode))
                devt = st.st_rdev;
        else if (!arg_find)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTBLK), "Not a block device: %s", arg_device);
        else if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode))
                return log_error_errno(SYNTHETIC_ERRNO(ENOTBLK), "Not a block device, regular file or directory: %s", arg_device);
        else if (major(st.st_dev) != 0)
                devt = st.st_dev;
        else {
                _cleanup_close_ int regfd = -1;

                /* If major(st.st_dev) is zero, this might mean we are backed by btrfs, which needs special
                 * handing, to get the backing device node. */

                regfd = open(arg_device, O_RDONLY|O_CLOEXEC|O_NONBLOCK);
                if (regfd < 0)
                        return log_error_errno(errno, "Failed to open '%s': %m", arg_device);

                r = btrfs_get_block_device_fd(regfd, &devt);
                if (r == -ENOTTY)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTBLK), "Path '%s' not backed by block device.", arg_device);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire btrfs backing device of '%s': %m", arg_device);
        }

        r = block_get_whole_disk(devt, &whole_devt);
        if (r < 0)
                return log_error_errno(r, "Failed to find whole block device for '%s': %m", arg_device);

        r = device_path_make_canonical(S_IFBLK, whole_devt, &whole_node);
        if (r < 0)
                return log_error_errno(r, "Failed to format block device path: %m");

        if (arg_print) {
                printf("%s\n", whole_node);
                return EXIT_SUCCESS;
        }

        fd = open(whole_node, O_RDONLY|O_CLOEXEC|O_NONBLOCK);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open '%s': %m", whole_node);

        if (flock(fd, LOCK_EX|LOCK_NB) < 0) {

                if (errno != EAGAIN)
                        return log_error_errno(errno, "Failed to lock device '%s': %m", whole_node);

                if (arg_timeout_usec == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EBUSY), "Device '%s' is currently locked.", whole_node);

                if (arg_timeout_usec == USEC_INFINITY)  {

                        log_info("Device '%s' is currently locked, waiting…", whole_node);

                        if (flock(fd, LOCK_EX) < 0)
                                return log_error_errno(errno, "Failed to lock device '%s': %m", whole_node);

                } else {
                        _cleanup_(sigkill_waitp) pid_t flock_pid = 0;
                        usec_t end;

                        /* flock() doesn't support a time-out. Let's fake one then. The traditional way to do
                         * this is via alarm()/setitimer()/timer_create(), but that's racy, given that the
                         * SIGALRM might aleady fire between the alarm() and the flock() in which case the
                         * flock() is never cancelled and we lock up (this is a short time window, but with
                         * short timeouts on a loaded machine we might run into it, who knows?). Let's
                         * instead do the lock out-of-process: fork off a child that does the locking, and
                         * that we'll wait on and kill if it takes too long. */

                        log_info("Device '%s' is currently locked, waiting %s…", whole_node, FORMAT_TIMESPAN(arg_timeout_usec, 0));

                        BLOCK_SIGNALS(SIGCHLD);

                        end = usec_add(now(CLOCK_MONOTONIC), arg_timeout_usec);

                        r = safe_fork("(timed-flock)", FORK_DEATHSIG|FORK_LOG, &flock_pid);
                        if (r < 0)
                                return r;
                        if (r == 0) {
                                /* Child */

                                if (flock(fd, LOCK_EX) < 0) {
                                        log_error_errno(errno, "Failed to lock device '%s': %m", whole_node);
                                        _exit(EXIT_FAILURE);
                                }

                                _exit(EXIT_SUCCESS);
                        }

                        for (;;) {
                                siginfo_t si;
                                sigset_t ss;
                                usec_t n;

                                assert(sigemptyset(&ss) >= 0);
                                assert(sigaddset(&ss, SIGCHLD) >= 0);

                                n = now(CLOCK_MONOTONIC);
                                if (n >= end)
                                        return log_error_errno(SYNTHETIC_ERRNO(ETIMEDOUT), "Timeout reached.");

                                r = sigtimedwait(&ss, NULL, TIMESPEC_STORE(end - n));
                                if (r < 0) {
                                        if (errno != EAGAIN)
                                                return log_error_errno(errno, "Failed to wait for SIGCHLD: %m");

                                        return log_error_errno(SYNTHETIC_ERRNO(ETIMEDOUT), "Timeout reached.");
                                }

                                assert(r == SIGCHLD);

                                zero(si);

                                if (waitid(P_PID, flock_pid, &si, WEXITED|WNOHANG|WNOWAIT) < 0)
                                        return log_error_errno(errno, "Failed to wait for child: %m");

                                if (si.si_pid != 0) {
                                        assert(si.si_pid == flock_pid);

                                        if (si.si_code != CLD_EXITED || si.si_status != EXIT_SUCCESS)
                                                return log_error_errno(SYNTHETIC_ERRNO(EPROTO), "Unexpected exit status of file lock child.");

                                        break;
                                }

                                log_debug("Got SIGCHLD for other child, continuing.");
                        }
                }
        }

        /* Ignore SIGINT and allow the forked process to receive it */
        (void) ignore_signals(SIGINT);

        r = safe_fork("(devlock)", FORK_RESET_SIGNALS|FORK_DEATHSIG|FORK_CLOSE_ALL_FDS|FORK_RLIMIT_NOFILE_SAFE|FORK_LOG, &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Child */

                execvp(arg_cmdline[0], arg_cmdline);
                log_open();
                log_error_errno(errno, "Failed to execute %s: %m", argv[optind]);
                _exit(EXIT_FAILURE);
        }

        return wait_for_terminate_and_check(argv[optind], pid, 0);
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
