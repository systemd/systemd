/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <getopt.h>
#include <stdlib.h>
#include <sys/file.h>
#include <unistd.h>

#include "blockdev-util.h"
#include "btrfs-util.h"
#include "fd-util.h"
#include "fdset.h"
#include "main-func.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "process-util.h"
#include "signal-util.h"
#include "sort-util.h"
#include "stat-util.h"
#include "strv.h"
#include "time-util.h"
#include "udevadm.h"

static usec_t arg_timeout_usec = USEC_INFINITY;
static char **arg_devices = NULL;
static char **arg_backing = NULL;
static char **arg_cmdline = NULL;
static bool arg_print = false;

STATIC_DESTRUCTOR_REGISTER(arg_devices, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_backing, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_cmdline, strv_freep);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("udevadm", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] COMMAND\n"
               "%s [OPTIONS...] --print\n"
               "\n%sLock a block device and run a comand.%s\n\n"
               "  -h --help            Print this message\n"
               "  -V --version         Print version of the program\n"
               "  -d --device=DEVICE   Block device to lock\n"
               "  -b --backing=FILE    File whose backing block device to lock\n"
               "  -t --timeout=SECS    Block at most the specified time waiting for lock\n"
               "  -p --print           Only show which block device the lock would be taken on\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        static const struct option options[] = {
                { "help",    no_argument,       NULL, 'h'      },
                { "version", no_argument,       NULL, 'V'      },
                { "device",  required_argument, NULL, 'd'      },
                { "backing", required_argument, NULL, 'b'      },
                { "timeout", required_argument, NULL, 't'      },
                { "print",   no_argument,       NULL, 'p'      },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, arg_print ? "hVd:b:t:p" : "+hVd:b:t:p", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case 'V':
                        return print_version();

                case 'd':
                case 'b': {
                        _cleanup_free_ char *s = NULL;
                        char ***l = c == 'd' ? &arg_devices : &arg_backing;

                        r = path_make_absolute_cwd(optarg, &s);
                        if (r < 0)
                                return log_error_errno(r, "Failed to make path '%s' absolute: %m", optarg);

                        path_simplify(s);

                        if (strv_consume(l, TAKE_PTR(s)) < 0)
                                return log_oom();

                        strv_uniq(*l);
                        break;
                }

                case 't':
                        r = parse_sec(optarg, &arg_timeout_usec);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --timeout= parameter: %s", optarg);
                        break;

                case 'p':
                        arg_print = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (arg_print) {
                if (optind != argc)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No arguments expected");
        } else {
                if (optind + 1 > argc)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Too few arguments, command to execute.");

                arg_cmdline = strv_copy(argv + optind);
                if (!arg_cmdline)
                        return log_oom();
        }

        if (strv_isempty(arg_devices) && strv_isempty(arg_backing))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No devices to lock specified, refusing.");

        return 1;
}

static int find_devno(
                dev_t **devnos,
                size_t *n_devnos,
                const char *device,
                bool backing) {

        dev_t devt, whole_devt;
        struct stat st;
        int r;

        assert(devnos);
        assert(n_devnos);
        assert(*devnos || *n_devnos == 0);
        assert(device);

        if (stat(device, &st) < 0)
                return log_error_errno(errno, "Failed to stat '%s': %m", device);

        if (S_ISBLK(st.st_mode))
                devt = st.st_rdev;
        else if (!backing)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTBLK), "Not a block device: %s", device);
        else if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode))
                return log_error_errno(SYNTHETIC_ERRNO(ENOTBLK), "Not a block device, regular file or directory: %s", device);
        else if (major(st.st_dev) != 0)
                devt = st.st_dev;
        else {
                _cleanup_close_ int regfd = -1;
                struct stat st2;

                /* If major(st.st_dev) is zero, this might mean we are backed by btrfs, which needs special
                 * handing, to get the backing device node. */

                regfd = open(device, O_RDONLY|O_CLOEXEC|O_NONBLOCK);
                if (regfd < 0)
                        return log_error_errno(errno, "Failed to open '%s': %m", device);

                /* Extra safety: let's check we are still looking at the same file */
                if (fstat(regfd, &st2) < 0)
                        return log_error_errno(errno, "Failed to stat '%s': %m", device);
                if (!stat_inode_same(&st, &st2))
                        return log_error_errno(SYNTHETIC_ERRNO(ENXIO), "File '%s' was replaced while we were looking at it.", device);

                r = btrfs_get_block_device_fd(regfd, &devt);
                if (r == -ENOTTY)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTBLK), "Path '%s' not backed by block device.", device);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire btrfs backing device of '%s': %m", device);
        }

        r = block_get_whole_disk(devt, &whole_devt);
        if (r < 0)
                return log_error_errno(r, "Failed to find whole block device for '%s': %m", device);

        if (typesafe_bsearch(&whole_devt, *devnos, *n_devnos, devt_compare_func)) {
                log_debug("Device %u:%u already listed for locking, ignoring.", major(whole_devt), minor(whole_devt));
                return 0;
        }

        if (!GREEDY_REALLOC(*devnos, *n_devnos + 1))
                return log_oom();

        (*devnos)[(*n_devnos)++] = whole_devt;

        /* Immediately sort again, to ensure the binary search above will work for the next device we add */
        typesafe_qsort(*devnos, *n_devnos, devt_compare_func);
        return 1;
}

static int lock_device(
                const char *path,
                dev_t devno,
                usec_t deadline) {

        _cleanup_close_ int fd = -1;
        struct stat st;
        int r;

        fd = open(path, O_RDONLY|O_CLOEXEC|O_NONBLOCK);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open '%s': %m", path);

        if (fstat(fd, &st) < 0)
                return log_error_errno(errno, "Failed to stat '%s': %m", path);

        /* Extra safety: check that the device still refers to what we think it refers to */
        if (!S_ISBLK(st.st_mode) || st.st_rdev != devno)
                return log_error_errno(SYNTHETIC_ERRNO(ENXIO), "Path '%s' no longer refers to specified block device %u:%u: %m", path, major(devno), minor(devno));

        if (flock(fd, LOCK_EX|LOCK_NB) < 0) {

                if (errno != EAGAIN)
                        return log_error_errno(errno, "Failed to lock device '%s': %m", path);

                if (deadline == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EBUSY), "Device '%s' is currently locked.", path);

                if (deadline == USEC_INFINITY)  {

                        log_info("Device '%s' is currently locked, waiting…", path);

                        if (flock(fd, LOCK_EX) < 0)
                                return log_error_errno(errno, "Failed to lock device '%s': %m", path);

                } else {
                        _cleanup_(sigkill_waitp) pid_t flock_pid = 0;

                        /* flock() doesn't support a time-out. Let's fake one then. The traditional way to do
                         * this is via alarm()/setitimer()/timer_create(), but that's racy, given that the
                         * SIGALRM might aleady fire between the alarm() and the flock() in which case the
                         * flock() is never cancelled and we lock up (this is a short time window, but with
                         * short timeouts on a loaded machine we might run into it, who knows?). Let's
                         * instead do the lock out-of-process: fork off a child that does the locking, and
                         * that we'll wait on and kill if it takes too long. */

                        log_info("Device '%s' is currently locked, waiting %s…",
                                 path, FORMAT_TIMESPAN(usec_sub_unsigned(deadline, now(CLOCK_MONOTONIC)), 0));

                        BLOCK_SIGNALS(SIGCHLD);

                        r = safe_fork("(timed-flock)", FORK_DEATHSIG|FORK_LOG, &flock_pid);
                        if (r < 0)
                                return r;
                        if (r == 0) {
                                /* Child */

                                if (flock(fd, LOCK_EX) < 0) {
                                        log_error_errno(errno, "Failed to lock device '%s': %m", path);
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
                                if (n >= deadline)
                                        return log_error_errno(SYNTHETIC_ERRNO(ETIMEDOUT), "Timeout reached.");

                                r = sigtimedwait(&ss, NULL, TIMESPEC_STORE(deadline - n));
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

        log_debug("Successfully locked %s (%u:%u)…", path, major(devno), minor(devno));

        return TAKE_FD(fd);
}

int lock_main(int argc, char *argv[], void *userdata) {
        _cleanup_(fdset_freep) FDSet *fds = NULL;
        _cleanup_free_ dev_t *devnos = NULL;
        size_t n_devnos = 0;
        usec_t deadline;
        pid_t pid;
        int r;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        STRV_FOREACH(i, arg_devices) {
                r = find_devno(&devnos, &n_devnos, *i, /* backing= */ false);
                if (r < 0)
                        return r;
        }

        STRV_FOREACH(i, arg_backing) {
                r = find_devno(&devnos, &n_devnos, *i, /* backing= */ true);
                if (r < 0)
                        return r;
        }

        assert(n_devnos > 0);

        fds = fdset_new();
        if (!fds)
                return log_oom();

        if (IN_SET(arg_timeout_usec, 0, USEC_INFINITY))
                deadline = arg_timeout_usec;
        else
                deadline = usec_add(now(CLOCK_MONOTONIC), arg_timeout_usec);

        for (size_t i = 0; i < n_devnos; i++) {
                _cleanup_free_ char *node = NULL;

                r = device_path_make_canonical(S_IFBLK, devnos[i], &node);
                if (r < 0)
                        return log_error_errno(r, "Failed to format block device path: %m");

                if (arg_print)
                        printf("%s\n", node);
                else {
                        _cleanup_close_ int fd = -1;

                        fd = lock_device(node, devnos[i], deadline);
                        if (fd < 0)
                                return fd;

                        r = fdset_put(fds, fd);
                        if (r < 0)
                                return log_oom();

                        TAKE_FD(fd);
                }
        }

        if (arg_print)
                return EXIT_SUCCESS;

        /* Ignore SIGINT and allow the forked process to receive it */
        (void) ignore_signals(SIGINT);

        r = safe_fork("(lock)", FORK_RESET_SIGNALS|FORK_DEATHSIG|FORK_CLOSE_ALL_FDS|FORK_RLIMIT_NOFILE_SAFE|FORK_LOG, &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Child */

                execvp(arg_cmdline[0], arg_cmdline);
                log_open();
                log_error_errno(errno, "Failed to execute %s: %m", arg_cmdline[0]);
                _exit(EXIT_FAILURE);
        }

        return wait_for_terminate_and_check(arg_cmdline[0], pid, 0);
}
