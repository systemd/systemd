/*-*- Mode: C; c-basic-offset: 8 -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <dbus/dbus.h>

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <getopt.h>
#include <signal.h>
#include <sys/wait.h>
#include <fcntl.h>

#include "manager.h"
#include "log.h"
#include "mount-setup.h"
#include "hostname-setup.h"
#include "loopback-setup.h"
#include "load-fragment.h"
#include "fdset.h"

static enum {
        ACTION_RUN,
        ACTION_HELP,
        ACTION_TEST,
        ACTION_DUMP_CONFIGURATION_ITEMS
} action = ACTION_RUN;

static char *default_unit = NULL;
static ManagerRunningAs running_as = _MANAGER_RUNNING_AS_INVALID;

static bool dump_core = true;
static bool crash_shell = false;
static int crash_chvt = -1;
static bool confirm_spawn = false;
static FILE* serialization = NULL;

_noreturn static void freeze(void) {
        for (;;)
                pause();
}

static void nop_handler(int sig) {
}

_noreturn static void crash(int sig) {

        if (!dump_core)
                log_error("Caught <%s>, not dumping core.", strsignal(sig));
        else {
                struct sigaction sa;
                pid_t pid;

                /* We want to wait for the core process, hence let's enable SIGCHLD */
                zero(sa);
                sa.sa_handler = nop_handler;
                sa.sa_flags = SA_NOCLDSTOP|SA_RESTART;
                assert_se(sigaction(SIGCHLD, &sa, NULL) == 0);

                if ((pid = fork()) < 0)
                        log_error("Caught <%s>, cannot fork for core dump: %s", strsignal(sig), strerror(errno));

                else if (pid == 0) {
                        struct rlimit rl;

                        /* Enable default signal handler for core dump */
                        zero(sa);
                        sa.sa_handler = SIG_DFL;
                        assert_se(sigaction(sig, &sa, NULL) == 0);

                        /* Don't limit the core dump size */
                        zero(rl);
                        rl.rlim_cur = RLIM_INFINITY;
                        rl.rlim_max = RLIM_INFINITY;
                        setrlimit(RLIMIT_CORE, &rl);

                        /* Just to be sure... */
                        assert_se(chdir("/") == 0);

                        /* Raise the signal again */
                        raise(sig);

                        assert_not_reached("We shouldn't be here...");
                        _exit(1);

                } else {
                        int status, r;

                        /* Order things nicely. */
                        if ((r = waitpid(pid, &status, 0)) < 0)
                                log_error("Caught <%s>, waitpid() failed: %s", strsignal(sig), strerror(errno));
                        else if (!WCOREDUMP(status))
                                log_error("Caught <%s>, core dump failed.", strsignal(sig));
                        else
                                log_error("Caught <%s>, dumped core as pid %llu.", strsignal(sig), (unsigned long long) pid);
                }
        }

        if (crash_chvt)
                chvt(crash_chvt);

        if (crash_shell) {
                struct sigaction sa;
                pid_t pid;

                log_info("Executing crash shell in 10s...");
                sleep(10);

                /* Let the kernel reap children for us */
                zero(sa);
                sa.sa_handler = SIG_IGN;
                sa.sa_flags = SA_NOCLDSTOP|SA_NOCLDWAIT|SA_RESTART;
                assert_se(sigaction(SIGCHLD, &sa, NULL) == 0);

                if ((pid = fork()) < 0)
                        log_error("Failed to fork off crash shell: %s", strerror(errno));
                else if (pid == 0) {
                        int fd, r;

                        if ((fd = acquire_terminal("/dev/console", false, true)) < 0)
                                log_error("Failed to acquire terminal: %s", strerror(-fd));
                        else if ((r = make_stdio(fd)) < 0)
                                log_error("Failed to duplicate terminal fd: %s", strerror(-r));

                        execl("/bin/sh", "/bin/sh", NULL);

                        log_error("execl() failed: %s", strerror(errno));
                        _exit(1);
                }

                log_info("Successfully spawned crash shall as pid %llu.", (unsigned long long) pid);
        }

        log_info("Freezing execution.");
        freeze();
}

static void install_crash_handler(void) {
        struct sigaction sa;

        zero(sa);

        sa.sa_handler = crash;
        sa.sa_flags = SA_NODEFER;

        assert_se(sigaction(SIGSEGV, &sa, NULL) == 0);
        assert_se(sigaction(SIGILL, &sa, NULL) == 0);
        assert_se(sigaction(SIGFPE, &sa, NULL) == 0);
        assert_se(sigaction(SIGBUS, &sa, NULL) == 0);
        assert_se(sigaction(SIGQUIT, &sa, NULL) == 0);
        assert_se(sigaction(SIGABRT, &sa, NULL) == 0);
}

static int make_null_stdio(void) {
        int null_fd, r;

        if ((null_fd = open("/dev/null", O_RDWR)) < 0) {
                log_error("Failed to open /dev/null: %m");
                return -errno;
        }

        if ((r = make_stdio(null_fd)) < 0)
                log_warning("Failed to dup2() device: %s", strerror(-r));

        return r;
}

static int console_setup(bool do_reset) {
        int tty_fd, r;

        /* If we are init, we connect stdin/stdout/stderr to /dev/null
         * and make sure we don't have a controlling tty. */

        release_terminal();

        if (!do_reset)
                return 0;

        if ((tty_fd = open_terminal("/dev/console", O_WRONLY|O_NOCTTY|O_CLOEXEC)) < 0) {
                log_error("Failed to open /dev/console: %s", strerror(-tty_fd));
                return -tty_fd;
        }

        if ((r = reset_terminal(tty_fd)) < 0)
                log_error("Failed to reset /dev/console: %s", strerror(-r));

        close_nointr_nofail(tty_fd);
        return r;
}

static int set_default_unit(const char *u) {
        char *c;

        assert(u);

        if (!(c = strdup(u)))
                return -ENOMEM;

        free(default_unit);
        default_unit = c;
        return 0;
}

static int parse_proc_cmdline_word(const char *word) {

        static const char * const rlmap[] = {
                "single", SPECIAL_RUNLEVEL1_TARGET,
                "-s",     SPECIAL_RUNLEVEL1_TARGET,
                "s",      SPECIAL_RUNLEVEL1_TARGET,
                "S",      SPECIAL_RUNLEVEL1_TARGET,
                "1",      SPECIAL_RUNLEVEL1_TARGET,
                "2",      SPECIAL_RUNLEVEL2_TARGET,
                "3",      SPECIAL_RUNLEVEL3_TARGET,
                "4",      SPECIAL_RUNLEVEL4_TARGET,
                "5",      SPECIAL_RUNLEVEL5_TARGET
        };

        if (startswith(word, "systemd.default="))
                return set_default_unit(word + 16);

        else if (startswith(word, "systemd.log_target=")) {

                if (log_set_target_from_string(word + 19) < 0)
                        log_warning("Failed to parse log target %s. Ignoring.", word + 19);

        } else if (startswith(word, "systemd.log_level=")) {

                if (log_set_max_level_from_string(word + 18) < 0)
                        log_warning("Failed to parse log level %s. Ignoring.", word + 18);

        } else if (startswith(word, "systemd.dump_core=")) {
                int r;

                if ((r = parse_boolean(word + 18)) < 0)
                        log_warning("Failed to parse dump core switch %s, Ignoring.", word + 18);
                else
                        dump_core = r;

        } else if (startswith(word, "systemd.crash_shell=")) {
                int r;

                if ((r = parse_boolean(word + 20)) < 0)
                        log_warning("Failed to parse crash shell switch %s, Ignoring.", word + 20);
                else
                        crash_shell = r;


        } else if (startswith(word, "systemd.confirm_spawn=")) {
                int r;

                if ((r = parse_boolean(word + 22)) < 0)
                        log_warning("Failed to parse confirm spawn switch %s, Ignoring.", word + 22);
                else
                        confirm_spawn = r;

        } else if (startswith(word, "systemd.crash_chvt=")) {
                int k;

                if (safe_atoi(word + 19, &k) < 0)
                        log_warning("Failed to parse crash chvt switch %s, Ignoring.", word + 19);
                else
                        crash_chvt = k;

        } else if (startswith(word, "systemd.")) {

                log_warning("Unknown kernel switch %s. Ignoring.", word);

                log_info("Supported kernel switches:");
                log_info("systemd.default=UNIT                     Default unit to start");
                log_info("systemd.log_target=console|kmsg|syslog   Log target");
                log_info("systemd.log_level=LEVEL                  Log level");
                log_info("systemd.dump_core=0|1                    Dump core on crash");
                log_info("systemd.crash_shell=0|1                  On crash run shell");
                log_info("systemd.crash_chvt=N                     Change to VT #N on crash");
                log_info("systemd.confirm_spawn=0|1                Confirm every process spawn");

        } else {
                unsigned i;

                /* SysV compatibility */
                for (i = 0; i < ELEMENTSOF(rlmap); i += 2)
                        if (streq(word, rlmap[i]))
                                return set_default_unit(rlmap[i+1]);
        }

        return 0;
}

static int parse_proc_cmdline(void) {
        char *line;
        int r;
        char *w;
        size_t l;
        char *state;

        if ((r = read_one_line_file("/proc/cmdline", &line)) < 0) {
                log_warning("Failed to read /proc/cmdline, ignoring: %s", strerror(errno));
                return 0;
        }

        FOREACH_WORD_QUOTED(w, l, line, state) {
                char *word;

                if (!(word = strndup(w, l))) {
                        r = -ENOMEM;
                        goto finish;
                }

                r = parse_proc_cmdline_word(word);
                free(word);

                if (r < 0)
                        goto finish;
        }

        r = 0;

finish:
        free(line);
        return r;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_LOG_LEVEL = 0x100,
                ARG_LOG_TARGET,
                ARG_DEFAULT,
                ARG_RUNNING_AS,
                ARG_TEST,
                ARG_DUMP_CONFIGURATION_ITEMS,
                ARG_CONFIRM_SPAWN,
                ARG_DESERIALIZE
        };

        static const struct option options[] = {
                { "log-level",                required_argument, NULL, ARG_LOG_LEVEL                },
                { "log-target",               required_argument, NULL, ARG_LOG_TARGET               },
                { "default",                  required_argument, NULL, ARG_DEFAULT                  },
                { "running-as",               required_argument, NULL, ARG_RUNNING_AS               },
                { "test",                     no_argument,       NULL, ARG_TEST                     },
                { "help",                     no_argument,       NULL, 'h'                          },
                { "dump-configuration-items", no_argument,       NULL, ARG_DUMP_CONFIGURATION_ITEMS },
                { "confirm-spawn",            no_argument,       NULL, ARG_CONFIRM_SPAWN            },
                { "deserialize",              required_argument, NULL, ARG_DESERIALIZE              },
                { NULL,                       0,                 NULL, 0                            }
        };

        int c, r;

        assert(argc >= 1);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)

                switch (c) {

                case ARG_LOG_LEVEL:
                        if ((r = log_set_max_level_from_string(optarg)) < 0) {
                                log_error("Failed to parse log level %s.", optarg);
                                return r;
                        }

                        break;

                case ARG_LOG_TARGET:

                        if ((r = log_set_target_from_string(optarg)) < 0) {
                                log_error("Failed to parse log target %s.", optarg);
                                return r;
                        }

                        break;

                case ARG_DEFAULT:

                        if ((r = set_default_unit(optarg)) < 0) {
                                log_error("Failed to set default unit %s: %s", optarg, strerror(-r));
                                return r;
                        }

                        break;

                case ARG_RUNNING_AS: {
                        ManagerRunningAs as;

                        if ((as = manager_running_as_from_string(optarg)) < 0) {
                                log_error("Failed to parse running as value %s", optarg);
                                return -EINVAL;
                        }

                        running_as = as;
                        break;
                }

                case ARG_TEST:
                        action = ACTION_TEST;
                        break;

                case ARG_DUMP_CONFIGURATION_ITEMS:
                        action = ACTION_DUMP_CONFIGURATION_ITEMS;
                        break;

                case ARG_CONFIRM_SPAWN:
                        confirm_spawn = true;
                        break;

                case ARG_DESERIALIZE: {
                        int fd;
                        FILE *f;

                        if ((r = safe_atoi(optarg, &fd)) < 0 || fd < 0) {
                                log_error("Failed to parse deserialize option %s.", optarg);
                                return r;
                        }

                        if (!(f = fdopen(fd, "r"))) {
                                log_error("Failed to open serialization fd: %m");
                                return r;
                        }

                        if (serialization)
                                fclose(serialization);

                        serialization = f;

                        break;
                }

                case 'h':
                        action = ACTION_HELP;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        log_error("Unknown option code %c", c);
                        return -EINVAL;
                }

        /* PID 1 will get the kernel arguments as parameters, which we
         * ignore and unconditionally read from
         * /proc/cmdline. However, we need to ignore those arguments
         * here. */
        if (running_as != MANAGER_INIT && optind < argc) {
                log_error("Excess arguments.");
                return -EINVAL;
        }

        return 0;
}

static int help(void) {

        printf("%s [options]\n\n"
               "  -h --help                      Show this help\n"
               "     --default=UNIT              Set default unit\n"
               "     --log-level=LEVEL           Set log level\n"
               "     --log-target=TARGET         Set log target (console, syslog, kmsg, syslog-or-kmsg)\n"
               "     --running-as=AS             Set running as (init, system, session)\n"
               "     --test                      Determine startup sequence, dump it and exit\n"
               "     --dump-configuration-items  Dump understood unit configuration items\n"
               "     --confirm-spawn             Ask for confirmation when spawning processes\n",
               __progname);

        return 0;
}

static int prepare_reexecute(Manager *m, FILE **_f, FDSet **_fds) {
        FILE *f = NULL;
        FDSet *fds = NULL;
        int r;

        assert(m);
        assert(_f);
        assert(_fds);

        if ((r = manager_open_serialization(&f)) < 0) {
                log_error("Failed to create serialization faile: %s", strerror(-r));
                goto fail;
        }

        if (!(fds = fdset_new())) {
                r = -ENOMEM;
                log_error("Failed to allocate fd set: %s", strerror(-r));
                goto fail;
        }

        if ((r = manager_serialize(m, f, fds)) < 0) {
                log_error("Failed to serialize state: %s", strerror(-r));
                goto fail;
        }

        if (fseeko(f, 0, SEEK_SET) < 0) {
                log_error("Failed to rewind serialization fd: %m");
                goto fail;
        }

        if ((r = fd_cloexec(fileno(f), false)) < 0) {
                log_error("Failed to disable O_CLOEXEC for serialization: %s", strerror(-r));
                goto fail;
        }

        if ((r = fdset_cloexec(fds, false)) < 0) {
                log_error("Failed to disable O_CLOEXEC for serialization fds: %s", strerror(-r));
                goto fail;
        }

        *_f = f;
        *_fds = fds;

        return 0;

fail:
        fdset_free(fds);

        if (f)
                fclose(f);

        return r;
}

int main(int argc, char *argv[]) {
        Manager *m = NULL;
        Unit *target = NULL;
        Job *job = NULL;
        int r, retval = 1;
        FDSet *fds = NULL;
        bool reexecute = false;

        if (getpid() == 1) {
                running_as = MANAGER_INIT;
                log_set_target(LOG_TARGET_SYSLOG_OR_KMSG);
        } else
                running_as = MANAGER_SESSION;

        if (set_default_unit(SPECIAL_DEFAULT_TARGET) < 0)
                goto finish;

        /* Mount /proc, /sys and friends, so that /proc/cmdline and
         * /proc/$PID/fd is available. */
        if (mount_setup() < 0)
                goto finish;

        /* Reset all signal handlers. */
        assert_se(reset_all_signal_handlers() == 0);

        /* If we are init, we can block sigkill. Yay. */
        ignore_signal(SIGKILL);
        ignore_signal(SIGPIPE);

        if (running_as != MANAGER_SESSION)
                if (parse_proc_cmdline() < 0)
                        goto finish;

        log_parse_environment();

        if (parse_argv(argc, argv) < 0)
                goto finish;

        if (action == ACTION_HELP) {
                retval = help();
                goto finish;
        } else if (action == ACTION_DUMP_CONFIGURATION_ITEMS) {
                unit_dump_config_items(stdout);
                retval = 0;
                goto finish;
        }

        assert_se(action == ACTION_RUN || action == ACTION_TEST);

        /* Remember open file descriptors for later deserialization */
        if (serialization) {
                if ((r = fdset_new_fill(&fds)) < 0) {
                        log_error("Failed to allocate fd set: %s", strerror(-r));
                        goto finish;
                }

                assert_se(fdset_remove(fds, fileno(serialization)) >= 0);
        } else
                close_all_fds(NULL, 0);

        /* Set up PATH unless it is already set */
        setenv("PATH",
               "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
               running_as == MANAGER_INIT);

        /* Move out of the way, so that we won't block unmounts */
        assert_se(chdir("/")  == 0);

        if (running_as != MANAGER_SESSION) {
                /* Become a session leader if we aren't one yet. */
                setsid();

                /* Disable the umask logic */
                umask(0);
        }

        /* Make sure D-Bus doesn't fiddle with the SIGPIPE handlers */
        dbus_connection_set_change_sigpipe(FALSE);

        /* Reset the console, but only if this is really init and we
         * are freshly booted */
        if (running_as != MANAGER_SESSION && action == ACTION_RUN) {
                console_setup(getpid() == 1 && !serialization);
                make_null_stdio();
        }

        /* Open the logging devices, if possible and necessary */
        log_open();

        /* Make sure we leave a core dump without panicing the
         * kernel. */
        if (getpid() == 1)
                install_crash_handler();

        log_debug("systemd running in %s mode.", manager_running_as_to_string(running_as));

        if (running_as == MANAGER_INIT) {
                hostname_setup();
                loopback_setup();
        }

        if ((r = manager_new(running_as, confirm_spawn, &m)) < 0) {
                log_error("Failed to allocate manager object: %s", strerror(-r));
                goto finish;
        }

        if ((r = manager_startup(m, serialization, fds)) < 0)
                log_error("Failed to fully start up daemon: %s", strerror(-r));

        if (fds) {
                /* This will close all file descriptors that were opened, but
                 * not claimed by any unit. */

                fdset_free(fds);
                fds = NULL;
        }

        if (serialization) {
                fclose(serialization);
                serialization = NULL;
        } else {
                log_debug("Activating default unit: %s", default_unit);

                if ((r = manager_load_unit(m, default_unit, NULL, &target)) < 0) {
                        log_error("Failed to load default target: %s", strerror(-r));

                        log_info("Trying to load rescue target...");
                        if ((r = manager_load_unit(m, SPECIAL_RESCUE_TARGET, NULL, &target)) < 0) {
                                log_error("Failed to load rescue target: %s", strerror(-r));
                                goto finish;
                        }
                }

                if (action == ACTION_TEST) {
                        printf("-> By units:\n");
                        manager_dump_units(m, stdout, "\t");
                }

                if ((r = manager_add_job(m, JOB_START, target, JOB_REPLACE, false, &job)) < 0) {
                        log_error("Failed to start default target: %s", strerror(-r));
                        goto finish;
                }

                if (action == ACTION_TEST) {
                        printf("-> By jobs:\n");
                        manager_dump_jobs(m, stdout, "\t");
                        retval = 0;
                        goto finish;
                }
        }

        for (;;) {
                if ((r = manager_loop(m)) < 0) {
                        log_error("Failed to run mainloop: %s", strerror(-r));
                        goto finish;
                }

                switch (m->exit_code) {

                case MANAGER_EXIT:
                        retval = 0;
                        log_debug("Exit.");
                        goto finish;

                case MANAGER_RELOAD:
                        if ((r = manager_reload(m)) < 0)
                                log_error("Failed to reload: %s", strerror(-r));
                        break;

                case MANAGER_REEXECUTE:
                        if (prepare_reexecute(m, &serialization, &fds) < 0)
                                goto finish;

                        reexecute = true;
                        log_debug("Reexecuting.");
                        goto finish;

                default:
                        assert_not_reached("Unknown exit code.");
                }
        }

finish:
        if (m)
                manager_free(m);

        free(default_unit);

        dbus_shutdown();

        if (reexecute) {
                const char *args[11];
                unsigned i = 0;
                char sfd[16];

                assert(serialization);
                assert(fds);

                args[i++] = SYSTEMD_BINARY_PATH;

                args[i++] = "--log-level";
                args[i++] = log_level_to_string(log_get_max_level());

                args[i++] = "--log-target";
                args[i++] = log_target_to_string(log_get_target());

                args[i++] = "--running-as";
                args[i++] = manager_running_as_to_string(running_as);

                snprintf(sfd, sizeof(sfd), "%i", fileno(serialization));
                char_array_0(sfd);

                args[i++] = "--deserialize";
                args[i++] = sfd;

                if (confirm_spawn)
                        args[i++] = "--confirm-spawn";

                args[i++] = NULL;

                assert(i <= ELEMENTSOF(args));

                execv(args[0], (char* const*) args);

                log_error("Failed to reexecute: %m");
        }

        if (serialization)
                fclose(serialization);

        if (fds)
                fdset_free(fds);

        if (getpid() == 1)
                freeze();

        return retval;
}
