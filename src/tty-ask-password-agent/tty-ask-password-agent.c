/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2015 Werner Fink
***/

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "alloc-util.h"
#include "ask-password-api.h"
#include "conf-parser.h"
#include "def.h"
#include "dirent-util.h"
#include "exit-status.h"
#include "fd-util.h"
#include "fileio.h"
#include "hashmap.h"
#include "inotify-util.h"
#include "io-util.h"
#include "macro.h"
#include "main-func.h"
#include "memory-util.h"
#include "mkdir-label.h"
#include "path-util.h"
#include "pretty-print.h"
#include "process-util.h"
#include "set.h"
#include "signal-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "utmp-wtmp.h"

static enum {
        ACTION_LIST,
        ACTION_QUERY,
        ACTION_WATCH,
        ACTION_WALL,
} arg_action = ACTION_QUERY;

static bool arg_plymouth = false;
static bool arg_console = false;
static const char *arg_device = NULL;

static int send_passwords(const char *socket_name, char **passwords) {
        _cleanup_(erase_and_freep) char *packet = NULL;
        _cleanup_close_ int socket_fd = -1;
        union sockaddr_union sa;
        socklen_t sa_len;
        size_t packet_length = 1;
        char *d;
        ssize_t n;
        int r;

        assert(socket_name);

        r = sockaddr_un_set_path(&sa.un, socket_name);
        if (r < 0)
                return r;
        sa_len = r;

        STRV_FOREACH(p, passwords)
                packet_length += strlen(*p) + 1;

        packet = new(char, packet_length);
        if (!packet)
                return -ENOMEM;

        packet[0] = '+';

        d = packet + 1;
        STRV_FOREACH(p, passwords)
                d = stpcpy(d, *p) + 1;

        socket_fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0);
        if (socket_fd < 0)
                return log_debug_errno(errno, "socket(): %m");

        n = sendto(socket_fd, packet, packet_length, MSG_NOSIGNAL, &sa.sa, sa_len);
        if (n < 0)
                return log_debug_errno(errno, "sendto(): %m");

        return (int) n;
}

static bool wall_tty_match(const char *path, bool is_local, void *userdata) {
        _cleanup_free_ char *p = NULL;
        _cleanup_close_ int fd = -1;
        struct stat st;

        assert(path_is_absolute(path));

        if (lstat(path, &st) < 0) {
                log_debug_errno(errno, "Failed to stat %s: %m", path);
                return true;
        }

        if (!S_ISCHR(st.st_mode)) {
                log_debug("%s is not a character device.", path);
                return true;
        }

        /* We use named pipes to ensure that wall messages suggesting
         * password entry are not printed over password prompts
         * already shown. We use the fact here that opening a pipe in
         * non-blocking mode for write-only will succeed only if
         * there's some writer behind it. Using pipes has the
         * advantage that the block will automatically go away if the
         * process dies. */

        if (asprintf(&p, "/run/systemd/ask-password-block/%u:%u", major(st.st_rdev), minor(st.st_rdev)) < 0) {
                log_oom();
                return true;
        }

        fd = open(p, O_WRONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (fd < 0) {
                log_debug_errno(errno, "Failed to open the wall pipe: %m");
                return 1;
        }

        /* What, we managed to open the pipe? Then this tty is filtered. */
        return 0;
}

static int agent_ask_password_tty(
                const char *message,
                usec_t until,
                AskPasswordFlags flags,
                const char *flag_file,
                char ***ret) {

        int tty_fd = -1, r;
        const char *con = arg_device ?: "/dev/console";

        if (arg_console) {
                tty_fd = acquire_terminal(con, ACQUIRE_TERMINAL_WAIT, USEC_INFINITY);
                if (tty_fd < 0)
                        return log_error_errno(tty_fd, "Failed to acquire %s: %m", con);

                r = reset_terminal_fd(tty_fd, true);
                if (r < 0)
                        log_warning_errno(r, "Failed to reset terminal, ignoring: %m");

                log_info("Starting password query on %s.", con);
        }

        r = ask_password_tty(tty_fd, message, NULL, until, flags, flag_file, ret);

        if (arg_console) {
                tty_fd = safe_close(tty_fd);
                release_terminal();

                if (r >= 0)
                        log_info("Password query on %s finished successfully.", con);
        }

        return r;
}

static int process_one_password_file(const char *filename) {
        _cleanup_free_ char *socket_name = NULL, *message = NULL;
        bool accept_cached = false, echo = false, silent = false;
        uint64_t not_after = 0;
        pid_t pid = 0;

        const ConfigTableItem items[] = {
                { "Ask", "Socket",       config_parse_string, CONFIG_PARSE_STRING_SAFE, &socket_name   },
                { "Ask", "NotAfter",     config_parse_uint64, 0,                        &not_after     },
                { "Ask", "Message",      config_parse_string, 0,                        &message       },
                { "Ask", "PID",          config_parse_pid,    0,                        &pid           },
                { "Ask", "AcceptCached", config_parse_bool,   0,                        &accept_cached },
                { "Ask", "Echo",         config_parse_bool,   0,                        &echo          },
                { "Ask", "Silent",       config_parse_bool,   0,                        &silent        },
                {}
        };

        int r;

        assert(filename);

        r = config_parse(NULL, filename, NULL,
                         NULL,
                         config_item_table_lookup, items,
                         CONFIG_PARSE_RELAXED|CONFIG_PARSE_WARN,
                         NULL,
                         NULL);
        if (r < 0)
                return r;

        if (!socket_name)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Invalid password file %s", filename);

        if (not_after > 0 && now(CLOCK_MONOTONIC) > not_after)
                return 0;

        if (pid > 0 && !pid_is_alive(pid))
                return 0;

        switch (arg_action) {
        case ACTION_LIST:
                printf("'%s' (PID " PID_FMT ")\n", strna(message), pid);
                return 0;

        case ACTION_WALL: {
                 _cleanup_free_ char *wall = NULL;

                 if (asprintf(&wall,
                              "Password entry required for \'%s\' (PID " PID_FMT ").\r\n"
                              "Please enter password with the systemd-tty-ask-password-agent tool.",
                              strna(message),
                              pid) < 0)
                         return log_oom();

                 (void) utmp_wall(wall, NULL, NULL, wall_tty_match, NULL);
                 return 0;
        }
        case ACTION_QUERY:
        case ACTION_WATCH: {
                _cleanup_strv_free_erase_ char **passwords = NULL;
                AskPasswordFlags flags = 0;

                if (access(socket_name, W_OK) < 0) {
                        if (arg_action == ACTION_QUERY)
                                log_info("Not querying '%s' (PID " PID_FMT "), lacking privileges.", strna(message), pid);

                        return 0;
                }

                SET_FLAG(flags, ASK_PASSWORD_ACCEPT_CACHED, accept_cached);
                SET_FLAG(flags, ASK_PASSWORD_CONSOLE_COLOR, arg_console);
                SET_FLAG(flags, ASK_PASSWORD_ECHO, echo);
                SET_FLAG(flags, ASK_PASSWORD_SILENT, silent);

                if (arg_plymouth)
                        r = ask_password_plymouth(message, not_after, flags, filename, &passwords);
                else
                        r = agent_ask_password_tty(message, not_after, flags, filename, &passwords);
                if (r < 0) {
                        /* If the query went away, that's OK */
                        if (IN_SET(r, -ETIME, -ENOENT))
                                return 0;

                        return log_error_errno(r, "Failed to query password: %m");
                }

                if (strv_isempty(passwords))
                        return -ECANCELED;

                r = send_passwords(socket_name, passwords);
                if (r < 0)
                        return log_error_errno(r, "Failed to send: %m");
                break;
        }}

        return 0;
}

static int wall_tty_block(void) {
        _cleanup_free_ char *p = NULL;
        dev_t devnr;
        int fd, r;

        r = get_ctty_devnr(0, &devnr);
        if (r == -ENXIO) /* We have no controlling tty */
                return -ENOTTY;
        if (r < 0)
                return log_error_errno(r, "Failed to get controlling TTY: %m");

        if (asprintf(&p, "/run/systemd/ask-password-block/%u:%u", major(devnr), minor(devnr)) < 0)
                return log_oom();

        (void) mkdir_parents_label(p, 0700);
        (void) mkfifo(p, 0600);

        fd = open(p, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (fd < 0)
                return log_debug_errno(errno, "Failed to open %s: %m", p);

        return fd;
}

static int process_password_files(void) {
        _cleanup_closedir_ DIR *d = NULL;
        int r = 0;

        d = opendir("/run/systemd/ask-password");
        if (!d) {
                if (errno == ENOENT)
                        return 0;

                return log_error_errno(errno, "Failed to open /run/systemd/ask-password: %m");
        }

        FOREACH_DIRENT(de, d, return log_error_errno(errno, "Failed to read directory: %m")) {
                _cleanup_free_ char *p = NULL;
                int q;

                /* We only support /run on tmpfs, hence we can rely on
                 * d_type to be reliable */

                if (de->d_type != DT_REG)
                        continue;

                if (!startswith(de->d_name, "ask."))
                        continue;

                p = path_join("/run/systemd/ask-password", de->d_name);
                if (!p)
                        return log_oom();

                q = process_one_password_file(p);
                if (q < 0 && r == 0)
                        r = q;
        }

        return r;
}

static int process_and_watch_password_files(bool watch) {
        enum {
                FD_SIGNAL,
                FD_INOTIFY,
                _FD_MAX
        };

        _unused_ _cleanup_close_ int tty_block_fd = -1;
        _cleanup_close_ int notify = -1, signal_fd = -1;
        struct pollfd pollfd[_FD_MAX];
        sigset_t mask;
        int r;

        tty_block_fd = wall_tty_block();

        (void) mkdir_p_label("/run/systemd/ask-password", 0755);

        assert_se(sigemptyset(&mask) >= 0);
        assert_se(sigset_add_many(&mask, SIGTERM, -1) >= 0);
        assert_se(sigprocmask(SIG_SETMASK, &mask, NULL) >= 0);

        if (watch) {
                signal_fd = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC);
                if (signal_fd < 0)
                        return log_error_errno(errno, "Failed to allocate signal file descriptor: %m");

                pollfd[FD_SIGNAL] = (struct pollfd) { .fd = signal_fd, .events = POLLIN };

                notify = inotify_init1(IN_CLOEXEC);
                if (notify < 0)
                        return log_error_errno(errno, "Failed to allocate directory watch: %m");

                r = inotify_add_watch_and_warn(notify, "/run/systemd/ask-password", IN_CLOSE_WRITE|IN_MOVED_TO);
                if (r < 0)
                        return r;

                pollfd[FD_INOTIFY] = (struct pollfd) { .fd = notify, .events = POLLIN };
        }

        for (;;) {
                usec_t timeout = USEC_INFINITY;

                r = process_password_files();
                if (r < 0) {
                        if (r == -ECANCELED)
                                /* Disable poll() timeout since at least one password has
                                 * been skipped and therefore one file remains and is
                                 * unlikely to trigger any events. */
                                timeout = 0;
                        else
                                /* FIXME: we should do something here since otherwise the service
                                 * requesting the password won't notice the error and will wait
                                 * indefinitely. */
                                log_error_errno(r, "Failed to process password: %m");
                }

                if (!watch)
                        break;

                r = ppoll_usec(pollfd, _FD_MAX, timeout);
                if (r == -EINTR)
                        continue;
                if (r < 0)
                        return r;

                if (pollfd[FD_INOTIFY].revents != 0)
                        (void) flush_fd(notify);

                if (pollfd[FD_SIGNAL].revents != 0)
                        break;
        }

        return 0;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-tty-ask-password-agent", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...]\n\n"
               "%sProcess system password requests.%s\n\n"
               "  -h --help              Show this help\n"
               "     --version           Show package version\n"
               "     --list              Show pending password requests\n"
               "     --query             Process pending password requests\n"
               "     --watch             Continuously process password requests\n"
               "     --wall              Continuously forward password requests to wall\n"
               "     --plymouth          Ask question with Plymouth instead of on TTY\n"
               "     --console[=DEVICE]  Ask question on /dev/console (or DEVICE if specified)\n"
               "                         instead of the current TTY\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_LIST = 0x100,
                ARG_QUERY,
                ARG_WATCH,
                ARG_WALL,
                ARG_PLYMOUTH,
                ARG_CONSOLE,
                ARG_VERSION
        };

        static const struct option options[] = {
                { "help",     no_argument,       NULL, 'h'          },
                { "version",  no_argument,       NULL, ARG_VERSION  },
                { "list",     no_argument,       NULL, ARG_LIST     },
                { "query",    no_argument,       NULL, ARG_QUERY    },
                { "watch",    no_argument,       NULL, ARG_WATCH    },
                { "wall",     no_argument,       NULL, ARG_WALL     },
                { "plymouth", no_argument,       NULL, ARG_PLYMOUTH },
                { "console",  optional_argument, NULL, ARG_CONSOLE  },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_LIST:
                        arg_action = ACTION_LIST;
                        break;

                case ARG_QUERY:
                        arg_action = ACTION_QUERY;
                        break;

                case ARG_WATCH:
                        arg_action = ACTION_WATCH;
                        break;

                case ARG_WALL:
                        arg_action = ACTION_WALL;
                        break;

                case ARG_PLYMOUTH:
                        arg_plymouth = true;
                        break;

                case ARG_CONSOLE:
                        arg_console = true;
                        if (optarg) {

                                if (isempty(optarg))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                               "Empty console device path is not allowed.");

                                arg_device = optarg;
                        }
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (optind != argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s takes no arguments.", program_invocation_short_name);

        if (arg_plymouth || arg_console) {

                if (!IN_SET(arg_action, ACTION_QUERY, ACTION_WATCH))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Options --query and --watch conflict.");

                if (arg_plymouth && arg_console)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Options --plymouth and --console conflict.");
        }

        return 1;
}

/*
 * To be able to ask on all terminal devices of /dev/console the devices are collected. If more than one
 * device is found, then on each of the terminals an inquiring task is forked.  Every task has its own session
 * and its own controlling terminal.  If one of the tasks does handle a password, the remaining tasks will be
 * terminated.
 */
static int ask_on_this_console(const char *tty, pid_t *ret_pid, char **arguments) {
        static const struct sigaction sigchld = {
                .sa_handler = nop_signal_handler,
                .sa_flags = SA_NOCLDSTOP | SA_RESTART,
        };
        static const struct sigaction sighup = {
                .sa_handler = SIG_DFL,
                .sa_flags = SA_RESTART,
        };
        int r;

        assert_se(sigaction(SIGCHLD, &sigchld, NULL) >= 0);
        assert_se(sigaction(SIGHUP, &sighup, NULL) >= 0);
        assert_se(sigprocmask_many(SIG_UNBLOCK, NULL, SIGHUP, SIGCHLD, -1) >= 0);

        r = safe_fork("(sd-passwd)", FORK_RESET_SIGNALS|FORK_LOG, ret_pid);
        if (r < 0)
                return r;
        if (r == 0) {
                assert_se(prctl(PR_SET_PDEATHSIG, SIGHUP) >= 0);

                STRV_FOREACH(i, arguments) {
                        char *k;

                        if (!streq(*i, "--console"))
                                continue;

                        k = strjoin("--console=", tty);
                        if (!k) {
                                log_oom();
                                _exit(EXIT_FAILURE);
                        }

                        free_and_replace(*i, k);
                }

                execv(SYSTEMD_TTY_ASK_PASSWORD_AGENT_BINARY_PATH, arguments);
                _exit(EXIT_FAILURE);
        }

        return 0;
}

static void terminate_agents(Set *pids) {
        sigset_t set;
        void *p;
        int r, signum;

        /*
         * Request termination of the remaining processes as those
         * are not required anymore.
         */
        SET_FOREACH(p, pids)
                (void) kill(PTR_TO_PID(p), SIGTERM);

        /*
         * Collect the processes which have go away.
         */
        assert_se(sigemptyset(&set) >= 0);
        assert_se(sigaddset(&set, SIGCHLD) >= 0);

        while (!set_isempty(pids)) {
                siginfo_t status = {};

                r = waitid(P_ALL, 0, &status, WEXITED|WNOHANG);
                if (r < 0 && errno == EINTR)
                        continue;

                if (r == 0 && status.si_pid > 0) {
                        set_remove(pids, PID_TO_PTR(status.si_pid));
                        continue;
                }

                signum = sigtimedwait(&set, NULL, TIMESPEC_STORE(50 * USEC_PER_MSEC));
                if (signum < 0) {
                        if (errno != EAGAIN)
                                log_error_errno(errno, "sigtimedwait() failed: %m");
                        break;
                }
                assert(signum == SIGCHLD);
        }

        /*
         * Kill hanging processes.
         */
        SET_FOREACH(p, pids) {
                log_warning("Failed to terminate child %d, killing it", PTR_TO_PID(p));
                (void) kill(PTR_TO_PID(p), SIGKILL);
        }
}

static int ask_on_consoles(char *argv[]) {
        _cleanup_set_free_ Set *pids = NULL;
        _cleanup_strv_free_ char **consoles = NULL, **arguments = NULL;
        siginfo_t status = {};
        pid_t pid;
        int r;

        r = get_kernel_consoles(&consoles);
        if (r < 0)
                return log_error_errno(r, "Failed to determine devices of /dev/console: %m");

        pids = set_new(NULL);
        if (!pids)
                return log_oom();

        arguments = strv_copy(argv);
        if (!arguments)
                return log_oom();

        /* Start an agent on each console. */
        STRV_FOREACH(tty, consoles) {
                r = ask_on_this_console(*tty, &pid, arguments);
                if (r < 0)
                        return r;

                if (set_put(pids, PID_TO_PTR(pid)) < 0)
                        return log_oom();
        }

        /* Wait for an agent to exit. */
        for (;;) {
                zero(status);

                if (waitid(P_ALL, 0, &status, WEXITED) < 0) {
                        if (errno == EINTR)
                                continue;

                        return log_error_errno(errno, "waitid() failed: %m");
                }

                set_remove(pids, PID_TO_PTR(status.si_pid));
                break;
        }

        if (!is_clean_exit(status.si_code, status.si_status, EXIT_CLEAN_DAEMON, NULL))
                log_error("Password agent failed with: %d", status.si_status);

        terminate_agents(pids);
        return 0;
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        umask(0022);

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (arg_console && !arg_device)
                /*
                 * Spawn a separate process for each console device.
                 */
                return ask_on_consoles(argv);

        if (arg_device) {
                /*
                 * Later on, a controlling terminal will be acquired,
                 * therefore the current process has to become a session
                 * leader and should not have a controlling terminal already.
                 */
                (void) setsid();
                (void) release_terminal();
        }

        return process_and_watch_password_files(!IN_SET(arg_action, ACTION_QUERY, ACTION_LIST));
}

DEFINE_MAIN_FUNCTION(run);
