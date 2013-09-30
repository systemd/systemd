/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
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
#include <sys/prctl.h>
#include <sys/mount.h>

#include "manager.h"
#include "log.h"
#include "load-fragment.h"
#include "fdset.h"
#include "special.h"
#include "conf-parser.h"
#include "dbus-common.h"
#include "missing.h"
#include "label.h"
#include "build.h"
#include "strv.h"
#include "def.h"
#include "virt.h"
#include "watchdog.h"
#include "path-util.h"
#include "switch-root.h"
#include "capability.h"
#include "killall.h"
#include "env-util.h"
#include "hwclock.h"
#include "sd-daemon.h"
#include "sd-messages.h"

#include "mount-setup.h"
#include "loopback-setup.h"
#ifdef HAVE_KMOD
#include "kmod-setup.h"
#endif
#include "hostname-setup.h"
#include "machine-id-setup.h"
#include "selinux-setup.h"
#include "ima-setup.h"
#include "fileio.h"
#include "smack-setup.h"

static enum {
        ACTION_RUN,
        ACTION_HELP,
        ACTION_VERSION,
        ACTION_TEST,
        ACTION_DUMP_CONFIGURATION_ITEMS,
        ACTION_DONE
} arg_action = ACTION_RUN;

static char *arg_default_unit = NULL;
static SystemdRunningAs arg_running_as = _SYSTEMD_RUNNING_AS_INVALID;

static bool arg_dump_core = true;
static bool arg_crash_shell = false;
static int arg_crash_chvt = -1;
static bool arg_confirm_spawn = false;
static bool arg_show_status = true;
static bool arg_switched_root = false;
static char ***arg_join_controllers = NULL;
static ExecOutput arg_default_std_output = EXEC_OUTPUT_JOURNAL;
static ExecOutput arg_default_std_error = EXEC_OUTPUT_INHERIT;
static usec_t arg_runtime_watchdog = 0;
static usec_t arg_shutdown_watchdog = 10 * USEC_PER_MINUTE;
static char **arg_default_environment = NULL;
static struct rlimit *arg_default_rlimit[RLIMIT_NLIMITS] = {};
static uint64_t arg_capability_bounding_set_drop = 0;
static nsec_t arg_timer_slack_nsec = (nsec_t) -1;

static FILE* serialization = NULL;

static void nop_handler(int sig) {
}

_noreturn_ static void crash(int sig) {

        if (getpid() != 1)
                /* Pass this on immediately, if this is not PID 1 */
                raise(sig);
        else if (!arg_dump_core)
                log_error("Caught <%s>, not dumping core.", signal_to_string(sig));
        else {
                struct sigaction sa = {
                        .sa_handler = nop_handler,
                        .sa_flags = SA_NOCLDSTOP|SA_RESTART,
                };
                pid_t pid;

                /* We want to wait for the core process, hence let's enable SIGCHLD */
                sigaction(SIGCHLD, &sa, NULL);

                pid = fork();
                if (pid < 0)
                        log_error("Caught <%s>, cannot fork for core dump: %s", signal_to_string(sig), strerror(errno));

                else if (pid == 0) {
                        struct rlimit rl = {};

                        /* Enable default signal handler for core dump */
                        zero(sa);
                        sa.sa_handler = SIG_DFL;
                        sigaction(sig, &sa, NULL);

                        /* Don't limit the core dump size */
                        rl.rlim_cur = RLIM_INFINITY;
                        rl.rlim_max = RLIM_INFINITY;
                        setrlimit(RLIMIT_CORE, &rl);

                        /* Just to be sure... */
                        chdir("/");

                        /* Raise the signal again */
                        raise(sig);

                        assert_not_reached("We shouldn't be here...");
                        _exit(1);

                } else {
                        siginfo_t status;
                        int r;

                        /* Order things nicely. */
                        r = wait_for_terminate(pid, &status);
                        if (r < 0)
                                log_error("Caught <%s>, waitpid() failed: %s", signal_to_string(sig), strerror(-r));
                        else if (status.si_code != CLD_DUMPED)
                                log_error("Caught <%s>, core dump failed.", signal_to_string(sig));
                        else
                                log_error("Caught <%s>, dumped core as pid %lu.", signal_to_string(sig), (unsigned long) pid);
                }
        }

        if (arg_crash_chvt)
                chvt(arg_crash_chvt);

        if (arg_crash_shell) {
                struct sigaction sa = {
                        .sa_handler = SIG_IGN,
                        .sa_flags = SA_NOCLDSTOP|SA_NOCLDWAIT|SA_RESTART,
                };
                pid_t pid;

                log_info("Executing crash shell in 10s...");
                sleep(10);

                /* Let the kernel reap children for us */
                assert_se(sigaction(SIGCHLD, &sa, NULL) == 0);

                pid = fork();
                if (pid < 0)
                        log_error("Failed to fork off crash shell: %m");
                else if (pid == 0) {
                        make_console_stdio();
                        execl("/bin/sh", "/bin/sh", NULL);

                        log_error("execl() failed: %m");
                        _exit(1);
                }

                log_info("Successfully spawned crash shell as pid %lu.", (unsigned long) pid);
        }

        log_info("Freezing execution.");
        freeze();
}

static void install_crash_handler(void) {
        struct sigaction sa = {
                .sa_handler = crash,
                .sa_flags = SA_NODEFER,
        };

        sigaction_many(&sa, SIGNALS_CRASH_HANDLER, -1);
}

static int console_setup(bool do_reset) {
        int tty_fd, r;

        /* If we are init, we connect stdin/stdout/stderr to /dev/null
         * and make sure we don't have a controlling tty. */

        release_terminal();

        if (!do_reset)
                return 0;

        tty_fd = open_terminal("/dev/console", O_WRONLY|O_NOCTTY|O_CLOEXEC);
        if (tty_fd < 0) {
                log_error("Failed to open /dev/console: %s", strerror(-tty_fd));
                return -tty_fd;
        }

        /* We don't want to force text mode.
         * plymouth may be showing pictures already from initrd. */
        r = reset_terminal_fd(tty_fd, false);
        if (r < 0)
                log_error("Failed to reset /dev/console: %s", strerror(-r));

        close_nointr_nofail(tty_fd);
        return r;
}

static int set_default_unit(const char *u) {
        char *c;

        assert(u);

        c = strdup(u);
        if (!c)
                return -ENOMEM;

        free(arg_default_unit);
        arg_default_unit = c;

        return 0;
}

static int parse_proc_cmdline_word(const char *word) {

        static const char * const rlmap[] = {
                "emergency", SPECIAL_EMERGENCY_TARGET,
                "-b",        SPECIAL_EMERGENCY_TARGET,
                "single",    SPECIAL_RESCUE_TARGET,
                "-s",        SPECIAL_RESCUE_TARGET,
                "s",         SPECIAL_RESCUE_TARGET,
                "S",         SPECIAL_RESCUE_TARGET,
                "1",         SPECIAL_RESCUE_TARGET,
                "2",         SPECIAL_RUNLEVEL2_TARGET,
                "3",         SPECIAL_RUNLEVEL3_TARGET,
                "4",         SPECIAL_RUNLEVEL4_TARGET,
                "5",         SPECIAL_RUNLEVEL5_TARGET,
        };

        assert(word);

        if (startswith(word, "systemd.unit=")) {

                if (!in_initrd())
                        return set_default_unit(word + 13);

        } else if (startswith(word, "rd.systemd.unit=")) {

                if (in_initrd())
                        return set_default_unit(word + 16);

        } else if (startswith(word, "systemd.log_target=")) {

                if (log_set_target_from_string(word + 19) < 0)
                        log_warning("Failed to parse log target %s. Ignoring.", word + 19);

        } else if (startswith(word, "systemd.log_level=")) {

                if (log_set_max_level_from_string(word + 18) < 0)
                        log_warning("Failed to parse log level %s. Ignoring.", word + 18);

        } else if (startswith(word, "systemd.log_color=")) {

                if (log_show_color_from_string(word + 18) < 0)
                        log_warning("Failed to parse log color setting %s. Ignoring.", word + 18);

        } else if (startswith(word, "systemd.log_location=")) {

                if (log_show_location_from_string(word + 21) < 0)
                        log_warning("Failed to parse log location setting %s. Ignoring.", word + 21);

        } else if (startswith(word, "systemd.dump_core=")) {
                int r;

                if ((r = parse_boolean(word + 18)) < 0)
                        log_warning("Failed to parse dump core switch %s. Ignoring.", word + 18);
                else
                        arg_dump_core = r;

        } else if (startswith(word, "systemd.crash_shell=")) {
                int r;

                if ((r = parse_boolean(word + 20)) < 0)
                        log_warning("Failed to parse crash shell switch %s. Ignoring.", word + 20);
                else
                        arg_crash_shell = r;

        } else if (startswith(word, "systemd.confirm_spawn=")) {
                int r;

                if ((r = parse_boolean(word + 22)) < 0)
                        log_warning("Failed to parse confirm spawn switch %s. Ignoring.", word + 22);
                else
                        arg_confirm_spawn = r;

        } else if (startswith(word, "systemd.crash_chvt=")) {
                int k;

                if (safe_atoi(word + 19, &k) < 0)
                        log_warning("Failed to parse crash chvt switch %s. Ignoring.", word + 19);
                else
                        arg_crash_chvt = k;

        } else if (startswith(word, "systemd.show_status=")) {
                int r;

                if ((r = parse_boolean(word + 20)) < 0)
                        log_warning("Failed to parse show status switch %s. Ignoring.", word + 20);
                else
                        arg_show_status = r;
        } else if (startswith(word, "systemd.default_standard_output=")) {
                int r;

                if ((r = exec_output_from_string(word + 32)) < 0)
                        log_warning("Failed to parse default standard output switch %s. Ignoring.", word + 32);
                else
                        arg_default_std_output = r;
        } else if (startswith(word, "systemd.default_standard_error=")) {
                int r;

                if ((r = exec_output_from_string(word + 31)) < 0)
                        log_warning("Failed to parse default standard error switch %s. Ignoring.", word + 31);
                else
                        arg_default_std_error = r;
        } else if (startswith(word, "systemd.setenv=")) {
                _cleanup_free_ char *cenv = NULL;

                cenv = strdup(word + 15);
                if (!cenv)
                        return -ENOMEM;

                if (env_assignment_is_valid(cenv)) {
                        char **env;

                        env = strv_env_set(arg_default_environment, cenv);
                        if (env)
                                arg_default_environment = env;
                        else
                                log_warning("Setting environment variable '%s' failed, ignoring: %m", cenv);
                } else
                        log_warning("Environment variable name '%s' is not valid. Ignoring.", cenv);

        } else if (startswith(word, "systemd.") ||
                   (in_initrd() && startswith(word, "rd.systemd."))) {

                const char *c;

                /* Ignore systemd.journald.xyz and friends */
                c = word;
                if (startswith(c, "rd."))
                        c += 3;
                if (startswith(c, "systemd."))
                        c += 8;
                if (c[strcspn(c, ".=")] != '.')  {

                        log_warning("Unknown kernel switch %s. Ignoring.", word);

                        log_info("Supported kernel switches:\n"
                                 "systemd.unit=UNIT                        Default unit to start\n"
                                 "rd.systemd.unit=UNIT                     Default unit to start when run in initrd\n"
                                 "systemd.dump_core=0|1                    Dump core on crash\n"
                                 "systemd.crash_shell=0|1                  Run shell on crash\n"
                                 "systemd.crash_chvt=N                     Change to VT #N on crash\n"
                                 "systemd.confirm_spawn=0|1                Confirm every process spawn\n"
                                 "systemd.show_status=0|1                  Show status updates on the console during bootup\n"
                                 "systemd.log_target=console|kmsg|journal|journal-or-kmsg|syslog|syslog-or-kmsg|null\n"
                                 "                                         Log target\n"
                                 "systemd.log_level=LEVEL                  Log level\n"
                                 "systemd.log_color=0|1                    Highlight important log messages\n"
                                 "systemd.log_location=0|1                 Include code location in log messages\n"
                                 "systemd.default_standard_output=null|tty|syslog|syslog+console|kmsg|kmsg+console|journal|journal+console\n"
                                 "                                         Set default log output for services\n"
                                 "systemd.default_standard_error=null|tty|syslog|syslog+console|kmsg|kmsg+console|journal|journal+console\n"
                                 "                                         Set default log error output for services\n"
                                 "systemd.setenv=ASSIGNMENT                Set an environment variable for all spawned processes\n");
                }

        } else if (streq(word, "quiet"))
                arg_show_status = false;
        else if (streq(word, "debug")) {
                /* Log to kmsg, the journal socket will fill up before the
                 * journal is started and tools running during that time
                 * will block with every log message for for 60 seconds,
                 * before they give up. */
                log_set_max_level(LOG_DEBUG);
                log_set_target(LOG_TARGET_KMSG);
        } else if (!in_initrd()) {
                unsigned i;

                /* SysV compatibility */
                for (i = 0; i < ELEMENTSOF(rlmap); i += 2)
                        if (streq(word, rlmap[i]))
                                return set_default_unit(rlmap[i+1]);
        }

        return 0;
}

#define DEFINE_SETTER(name, func, descr)                              \
        static int name(const char *unit,                             \
                        const char *filename,                         \
                        unsigned line,                                \
                        const char *section,                          \
                        const char *lvalue,                           \
                        int ltype,                                    \
                        const char *rvalue,                           \
                        void *data,                                   \
                        void *userdata) {                             \
                                                                      \
                int r;                                                \
                                                                      \
                assert(filename);                                     \
                assert(lvalue);                                       \
                assert(rvalue);                                       \
                                                                      \
                r = func(rvalue);                                     \
                if (r < 0)                                            \
                        log_syntax(unit, LOG_ERR, filename, line, -r, \
                                   "Invalid " descr "'%s': %s",       \
                                   rvalue, strerror(-r));             \
                                                                      \
                return 0;                                             \
        }

DEFINE_SETTER(config_parse_level2, log_set_max_level_from_string, "log level")
DEFINE_SETTER(config_parse_target, log_set_target_from_string, "target")
DEFINE_SETTER(config_parse_color, log_show_color_from_string, "color" )
DEFINE_SETTER(config_parse_location, log_show_location_from_string, "location")


static int config_parse_cpu_affinity2(const char *unit,
                                      const char *filename,
                                      unsigned line,
                                      const char *section,
                                      const char *lvalue,
                                      int ltype,
                                      const char *rvalue,
                                      void *data,
                                      void *userdata) {

        char *w;
        size_t l;
        char *state;
        cpu_set_t *c = NULL;
        unsigned ncpus = 0;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        FOREACH_WORD_QUOTED(w, l, rvalue, state) {
                char *t;
                int r;
                unsigned cpu;

                if (!(t = strndup(w, l)))
                        return log_oom();

                r = safe_atou(t, &cpu);
                free(t);

                if (!c)
                        if (!(c = cpu_set_malloc(&ncpus)))
                                return log_oom();

                if (r < 0 || cpu >= ncpus) {
                        log_syntax(unit, LOG_ERR, filename, line, -r,
                                   "Failed to parse CPU affinity '%s'", rvalue);
                        CPU_FREE(c);
                        return -EBADMSG;
                }

                CPU_SET_S(cpu, CPU_ALLOC_SIZE(ncpus), c);
        }

        if (c) {
                if (sched_setaffinity(0, CPU_ALLOC_SIZE(ncpus), c) < 0)
                        log_warning_unit(unit, "Failed to set CPU affinity: %m");

                CPU_FREE(c);
        }

        return 0;
}

static void strv_free_free(char ***l) {
        char ***i;

        if (!l)
                return;

        for (i = l; *i; i++)
                strv_free(*i);

        free(l);
}

static void free_join_controllers(void) {
        strv_free_free(arg_join_controllers);
        arg_join_controllers = NULL;
}

static int config_parse_join_controllers(const char *unit,
                                         const char *filename,
                                         unsigned line,
                                         const char *section,
                                         const char *lvalue,
                                         int ltype,
                                         const char *rvalue,
                                         void *data,
                                         void *userdata) {

        unsigned n = 0;
        char *state, *w;
        size_t length;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        free_join_controllers();

        FOREACH_WORD_QUOTED(w, length, rvalue, state) {
                char *s, **l;

                s = strndup(w, length);
                if (!s)
                        return log_oom();

                l = strv_split(s, ",");
                free(s);

                strv_uniq(l);

                if (strv_length(l) <= 1) {
                        strv_free(l);
                        continue;
                }

                if (!arg_join_controllers) {
                        arg_join_controllers = new(char**, 2);
                        if (!arg_join_controllers) {
                                strv_free(l);
                                return log_oom();
                        }

                        arg_join_controllers[0] = l;
                        arg_join_controllers[1] = NULL;

                        n = 1;
                } else {
                        char ***a;
                        char ***t;

                        t = new0(char**, n+2);
                        if (!t) {
                                strv_free(l);
                                return log_oom();
                        }

                        n = 0;

                        for (a = arg_join_controllers; *a; a++) {

                                if (strv_overlap(*a, l)) {
                                        char **c;

                                        c = strv_merge(*a, l);
                                        if (!c) {
                                                strv_free(l);
                                                strv_free_free(t);
                                                return log_oom();
                                        }

                                        strv_free(l);
                                        l = c;
                                } else {
                                        char **c;

                                        c = strv_copy(*a);
                                        if (!c) {
                                                strv_free(l);
                                                strv_free_free(t);
                                                return log_oom();
                                        }

                                        t[n++] = c;
                                }
                        }

                        t[n++] = strv_uniq(l);

                        strv_free_free(arg_join_controllers);
                        arg_join_controllers = t;
                }
        }

        return 0;
}

static int parse_config_file(void) {

        const ConfigTableItem items[] = {
                { "Manager", "LogLevel",              config_parse_level2,       0, NULL                     },
                { "Manager", "LogTarget",             config_parse_target,       0, NULL                     },
                { "Manager", "LogColor",              config_parse_color,        0, NULL                     },
                { "Manager", "LogLocation",           config_parse_location,     0, NULL                     },
                { "Manager", "DumpCore",              config_parse_bool,         0, &arg_dump_core           },
                { "Manager", "CrashShell",            config_parse_bool,         0, &arg_crash_shell         },
                { "Manager", "ShowStatus",            config_parse_bool,         0, &arg_show_status         },
                { "Manager", "CrashChVT",             config_parse_int,          0, &arg_crash_chvt          },
                { "Manager", "CPUAffinity",           config_parse_cpu_affinity2, 0, NULL                    },
                { "Manager", "DefaultStandardOutput", config_parse_output,       0, &arg_default_std_output  },
                { "Manager", "DefaultStandardError",  config_parse_output,       0, &arg_default_std_error   },
                { "Manager", "JoinControllers",       config_parse_join_controllers, 0, &arg_join_controllers },
                { "Manager", "RuntimeWatchdogSec",    config_parse_sec,          0, &arg_runtime_watchdog    },
                { "Manager", "ShutdownWatchdogSec",   config_parse_sec,          0, &arg_shutdown_watchdog   },
                { "Manager", "CapabilityBoundingSet", config_parse_bounding_set, 0, &arg_capability_bounding_set_drop },
                { "Manager", "TimerSlackNSec",        config_parse_nsec,         0, &arg_timer_slack_nsec    },
                { "Manager", "DefaultEnvironment",    config_parse_environ,      0, &arg_default_environment },
                { "Manager", "DefaultLimitCPU",       config_parse_limit,        0, &arg_default_rlimit[RLIMIT_CPU]},
                { "Manager", "DefaultLimitFSIZE",     config_parse_limit,        0, &arg_default_rlimit[RLIMIT_FSIZE]},
                { "Manager", "DefaultLimitDATA",      config_parse_limit,        0, &arg_default_rlimit[RLIMIT_DATA]},
                { "Manager", "DefaultLimitSTACK",     config_parse_limit,        0, &arg_default_rlimit[RLIMIT_STACK]},
                { "Manager", "DefaultLimitCORE",      config_parse_limit,        0, &arg_default_rlimit[RLIMIT_CORE]},
                { "Manager", "DefaultLimitRSS",       config_parse_limit,        0, &arg_default_rlimit[RLIMIT_RSS]},
                { "Manager", "DefaultLimitNOFILE",    config_parse_limit,        0, &arg_default_rlimit[RLIMIT_NOFILE]},
                { "Manager", "DefaultLimitAS",        config_parse_limit,        0, &arg_default_rlimit[RLIMIT_AS]},
                { "Manager", "DefaultLimitNPROC",     config_parse_limit,        0, &arg_default_rlimit[RLIMIT_NPROC]},
                { "Manager", "DefaultLimitMEMLOCK",   config_parse_limit,        0, &arg_default_rlimit[RLIMIT_MEMLOCK]},
                { "Manager", "DefaultLimitLOCKS",     config_parse_limit,        0, &arg_default_rlimit[RLIMIT_LOCKS]},
                { "Manager", "DefaultLimitSIGPENDING",config_parse_limit,        0, &arg_default_rlimit[RLIMIT_SIGPENDING]},
                { "Manager", "DefaultLimitMSGQUEUE",  config_parse_limit,        0, &arg_default_rlimit[RLIMIT_MSGQUEUE]},
                { "Manager", "DefaultLimitNICE",      config_parse_limit,        0, &arg_default_rlimit[RLIMIT_NICE]},
                { "Manager", "DefaultLimitRTPRIO",    config_parse_limit,        0, &arg_default_rlimit[RLIMIT_RTPRIO]},
                { "Manager", "DefaultLimitRTTIME",    config_parse_limit,        0, &arg_default_rlimit[RLIMIT_RTTIME]},
                { NULL, NULL, NULL, 0, NULL }
        };

        _cleanup_fclose_ FILE *f;
        const char *fn;
        int r;

        fn = arg_running_as == SYSTEMD_SYSTEM ? PKGSYSCONFDIR "/system.conf" : PKGSYSCONFDIR "/user.conf";
        f = fopen(fn, "re");
        if (!f) {
                if (errno == ENOENT)
                        return 0;

                log_warning("Failed to open configuration file '%s': %m", fn);
                return 0;
        }

        r = config_parse(NULL, fn, f, "Manager\0", config_item_table_lookup, (void*) items, false, false, NULL);
        if (r < 0)
                log_warning("Failed to parse configuration file: %s", strerror(-r));

        return 0;
}

static int parse_proc_cmdline(void) {
        _cleanup_free_ char *line = NULL;
        char *w, *state;
        int r;
        size_t l;

        /* Don't read /proc/cmdline if we are in a container, since
         * that is only relevant for the host system */
        if (detect_container(NULL) > 0)
                return 0;

        r = read_one_line_file("/proc/cmdline", &line);
        if (r < 0) {
                log_warning("Failed to read /proc/cmdline, ignoring: %s", strerror(-r));
                return 0;
        }

        FOREACH_WORD_QUOTED(w, l, line, state) {
                _cleanup_free_ char *word;

                word = strndup(w, l);
                if (!word)
                        return log_oom();

                r = parse_proc_cmdline_word(word);
                if (r < 0) {
                        log_error("Failed on cmdline argument %s: %s", word, strerror(-r));
                        return r;
                }
        }

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_LOG_LEVEL = 0x100,
                ARG_LOG_TARGET,
                ARG_LOG_COLOR,
                ARG_LOG_LOCATION,
                ARG_UNIT,
                ARG_SYSTEM,
                ARG_USER,
                ARG_TEST,
                ARG_VERSION,
                ARG_DUMP_CONFIGURATION_ITEMS,
                ARG_DUMP_CORE,
                ARG_CRASH_SHELL,
                ARG_CONFIRM_SPAWN,
                ARG_SHOW_STATUS,
                ARG_DESERIALIZE,
                ARG_SWITCHED_ROOT,
                ARG_INTROSPECT,
                ARG_DEFAULT_STD_OUTPUT,
                ARG_DEFAULT_STD_ERROR
        };

        static const struct option options[] = {
                { "log-level",                required_argument, NULL, ARG_LOG_LEVEL                },
                { "log-target",               required_argument, NULL, ARG_LOG_TARGET               },
                { "log-color",                optional_argument, NULL, ARG_LOG_COLOR                },
                { "log-location",             optional_argument, NULL, ARG_LOG_LOCATION             },
                { "unit",                     required_argument, NULL, ARG_UNIT                     },
                { "system",                   no_argument,       NULL, ARG_SYSTEM                   },
                { "user",                     no_argument,       NULL, ARG_USER                     },
                { "test",                     no_argument,       NULL, ARG_TEST                     },
                { "help",                     no_argument,       NULL, 'h'                          },
                { "version",                  no_argument,       NULL, ARG_VERSION                  },
                { "dump-configuration-items", no_argument,       NULL, ARG_DUMP_CONFIGURATION_ITEMS },
                { "dump-core",                optional_argument, NULL, ARG_DUMP_CORE                },
                { "crash-shell",              optional_argument, NULL, ARG_CRASH_SHELL              },
                { "confirm-spawn",            optional_argument, NULL, ARG_CONFIRM_SPAWN            },
                { "show-status",              optional_argument, NULL, ARG_SHOW_STATUS              },
                { "deserialize",              required_argument, NULL, ARG_DESERIALIZE              },
                { "switched-root",            no_argument,       NULL, ARG_SWITCHED_ROOT            },
                { "introspect",               optional_argument, NULL, ARG_INTROSPECT               },
                { "default-standard-output",  required_argument, NULL, ARG_DEFAULT_STD_OUTPUT,      },
                { "default-standard-error",   required_argument, NULL, ARG_DEFAULT_STD_ERROR,       },
                { NULL,                       0,                 NULL, 0                            }
        };

        int c, r;

        assert(argc >= 1);
        assert(argv);

        if (getpid() == 1)
                opterr = 0;

        while ((c = getopt_long(argc, argv, "hDbsz:", options, NULL)) >= 0)

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

                case ARG_LOG_COLOR:

                        if (optarg) {
                                if ((r = log_show_color_from_string(optarg)) < 0) {
                                        log_error("Failed to parse log color setting %s.", optarg);
                                        return r;
                                }
                        } else
                                log_show_color(true);

                        break;

                case ARG_LOG_LOCATION:

                        if (optarg) {
                                if ((r = log_show_location_from_string(optarg)) < 0) {
                                        log_error("Failed to parse log location setting %s.", optarg);
                                        return r;
                                }
                        } else
                                log_show_location(true);

                        break;

                case ARG_DEFAULT_STD_OUTPUT:

                        if ((r = exec_output_from_string(optarg)) < 0) {
                                log_error("Failed to parse default standard output setting %s.", optarg);
                                return r;
                        } else
                                arg_default_std_output = r;
                        break;

                case ARG_DEFAULT_STD_ERROR:

                        if ((r = exec_output_from_string(optarg)) < 0) {
                                log_error("Failed to parse default standard error output setting %s.", optarg);
                                return r;
                        } else
                                arg_default_std_error = r;
                        break;

                case ARG_UNIT:

                        if ((r = set_default_unit(optarg)) < 0) {
                                log_error("Failed to set default unit %s: %s", optarg, strerror(-r));
                                return r;
                        }

                        break;

                case ARG_SYSTEM:
                        arg_running_as = SYSTEMD_SYSTEM;
                        break;

                case ARG_USER:
                        arg_running_as = SYSTEMD_USER;
                        break;

                case ARG_TEST:
                        arg_action = ACTION_TEST;
                        break;

                case ARG_VERSION:
                        arg_action = ACTION_VERSION;
                        break;

                case ARG_DUMP_CONFIGURATION_ITEMS:
                        arg_action = ACTION_DUMP_CONFIGURATION_ITEMS;
                        break;

                case ARG_DUMP_CORE:
                        r = optarg ? parse_boolean(optarg) : 1;
                        if (r < 0) {
                                log_error("Failed to parse dump core boolean %s.", optarg);
                                return r;
                        }
                        arg_dump_core = r;
                        break;

                case ARG_CRASH_SHELL:
                        r = optarg ? parse_boolean(optarg) : 1;
                        if (r < 0) {
                                log_error("Failed to parse crash shell boolean %s.", optarg);
                                return r;
                        }
                        arg_crash_shell = r;
                        break;

                case ARG_CONFIRM_SPAWN:
                        r = optarg ? parse_boolean(optarg) : 1;
                        if (r < 0) {
                                log_error("Failed to parse confirm spawn boolean %s.", optarg);
                                return r;
                        }
                        arg_confirm_spawn = r;
                        break;

                case ARG_SHOW_STATUS:
                        r = optarg ? parse_boolean(optarg) : 1;
                        if (r < 0) {
                                log_error("Failed to parse show status boolean %s.", optarg);
                                return r;
                        }
                        arg_show_status = r;
                        break;

                case ARG_DESERIALIZE: {
                        int fd;
                        FILE *f;

                        r = safe_atoi(optarg, &fd);
                        if (r < 0 || fd < 0) {
                                log_error("Failed to parse deserialize option %s.", optarg);
                                return r < 0 ? r : -EINVAL;
                        }

                        fd_cloexec(fd, true);

                        f = fdopen(fd, "r");
                        if (!f) {
                                log_error("Failed to open serialization fd: %m");
                                return -errno;
                        }

                        if (serialization)
                                fclose(serialization);

                        serialization = f;

                        break;
                }

                case ARG_SWITCHED_ROOT:
                        arg_switched_root = true;
                        break;

                case ARG_INTROSPECT: {
                        const char * const * i = NULL;

                        for (i = bus_interface_table; *i; i += 2)
                                if (!optarg || streq(i[0], optarg)) {
                                        fputs(DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE
                                              "<node>\n", stdout);
                                        fputs(i[1], stdout);
                                        fputs("</node>\n", stdout);

                                        if (optarg)
                                                break;
                                }

                        if (!i[0] && optarg)
                                log_error("Unknown interface %s.", optarg);

                        arg_action = ACTION_DONE;
                        break;
                }

                case 'h':
                        arg_action = ACTION_HELP;
                        break;

                case 'D':
                        log_set_max_level(LOG_DEBUG);
                        break;

                case 'b':
                case 's':
                case 'z':
                        /* Just to eat away the sysvinit kernel
                         * cmdline args without getopt() error
                         * messages that we'll parse in
                         * parse_proc_cmdline_word() or ignore. */

                case '?':
                default:
                        if (getpid() != 1) {
                                log_error("Unknown option code %c", c);
                                return -EINVAL;
                        }

                        break;
                }

        if (optind < argc && getpid() != 1) {
                /* Hmm, when we aren't run as init system
                 * let's complain about excess arguments */

                log_error("Excess arguments.");
                return -EINVAL;
        }

        if (detect_container(NULL) > 0) {
                char **a;

                /* All /proc/cmdline arguments the kernel didn't
                 * understand it passed to us. We're not really
                 * interested in that usually since /proc/cmdline is
                 * more interesting and complete. With one exception:
                 * if we are run in a container /proc/cmdline is not
                 * relevant for the container, hence we rely on argv[]
                 * instead. */

                for (a = argv; a < argv + argc; a++)
                        if ((r = parse_proc_cmdline_word(*a)) < 0) {
                                log_error("Failed on cmdline argument %s: %s", *a, strerror(-r));
                                return r;
                        }
        }

        return 0;
}

static int help(void) {

        printf("%s [OPTIONS...]\n\n"
               "Starts up and maintains the system or user services.\n\n"
               "  -h --help                      Show this help\n"
               "     --test                      Determine startup sequence, dump it and exit\n"
               "     --dump-configuration-items  Dump understood unit configuration items\n"
               "     --introspect[=INTERFACE]    Extract D-Bus interface data\n"
               "     --unit=UNIT                 Set default unit\n"
               "     --system                    Run a system instance, even if PID != 1\n"
               "     --user                      Run a user instance\n"
               "     --dump-core[=0|1]           Dump core on crash\n"
               "     --crash-shell[=0|1]         Run shell on crash\n"
               "     --confirm-spawn[=0|1]       Ask for confirmation when spawning processes\n"
               "     --show-status[=0|1]         Show status updates on the console during bootup\n"
               "     --log-target=TARGET         Set log target (console, journal, syslog, kmsg, journal-or-kmsg, syslog-or-kmsg, null)\n"
               "     --log-level=LEVEL           Set log level (debug, info, notice, warning, err, crit, alert, emerg)\n"
               "     --log-color[=0|1]           Highlight important log messages\n"
               "     --log-location[=0|1]        Include code location in log messages\n"
               "     --default-standard-output=  Set default standard output for services\n"
               "     --default-standard-error=   Set default standard error output for services\n",
               program_invocation_short_name);

        return 0;
}

static int version(void) {
        puts(PACKAGE_STRING);
        puts(SYSTEMD_FEATURES);

        return 0;
}

static int prepare_reexecute(Manager *m, FILE **_f, FDSet **_fds, bool switching_root) {
        FILE *f = NULL;
        FDSet *fds = NULL;
        int r;

        assert(m);
        assert(_f);
        assert(_fds);

        r = manager_open_serialization(m, &f);
        if (r < 0) {
                log_error("Failed to create serialization file: %s", strerror(-r));
                goto fail;
        }

        /* Make sure nothing is really destructed when we shut down */
        m->n_reloading ++;
        bus_broadcast_reloading(m, true);

        fds = fdset_new();
        if (!fds) {
                r = -ENOMEM;
                log_error("Failed to allocate fd set: %s", strerror(-r));
                goto fail;
        }

        r = manager_serialize(m, f, fds, switching_root);
        if (r < 0) {
                log_error("Failed to serialize state: %s", strerror(-r));
                goto fail;
        }

        if (fseeko(f, 0, SEEK_SET) < 0) {
                log_error("Failed to rewind serialization fd: %m");
                goto fail;
        }

        r = fd_cloexec(fileno(f), false);
        if (r < 0) {
                log_error("Failed to disable O_CLOEXEC for serialization: %s", strerror(-r));
                goto fail;
        }

        r = fdset_cloexec(fds, false);
        if (r < 0) {
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

static int bump_rlimit_nofile(struct rlimit *saved_rlimit) {
        struct rlimit nl;
        int r;

        assert(saved_rlimit);

        /* Save the original RLIMIT_NOFILE so that we can reset it
         * later when transitioning from the initrd to the main
         * systemd or suchlike. */
        if (getrlimit(RLIMIT_NOFILE, saved_rlimit) < 0) {
                log_error("Reading RLIMIT_NOFILE failed: %m");
                return -errno;
        }

        /* Make sure forked processes get the default kernel setting */
        if (!arg_default_rlimit[RLIMIT_NOFILE]) {
                struct rlimit *rl;

                rl = newdup(struct rlimit, saved_rlimit, 1);
                if (!rl)
                        return log_oom();

                arg_default_rlimit[RLIMIT_NOFILE] = rl;
        }

        /* Bump up the resource limit for ourselves substantially */
        nl.rlim_cur = nl.rlim_max = 64*1024;
        r = setrlimit_closest(RLIMIT_NOFILE, &nl);
        if (r < 0) {
                log_error("Setting RLIMIT_NOFILE failed: %s", strerror(-r));
                return r;
        }

        return 0;
}

static void test_mtab(void) {
        char *p;

        /* Check that /etc/mtab is a symlink */

        if (readlink_malloc("/etc/mtab", &p) >= 0) {
                bool b;

                b = streq(p, "/proc/self/mounts") || streq(p, "/proc/mounts");
                free(p);

                if (b)
                        return;
        }

        log_warning("/etc/mtab is not a symlink or not pointing to /proc/self/mounts. "
                    "This is not supported anymore. "
                    "Please make sure to replace this file by a symlink to avoid incorrect or misleading mount(8) output.");
}

static void test_usr(void) {

        /* Check that /usr is not a separate fs */

        if (dir_is_empty("/usr") <= 0)
                return;

        log_warning("/usr appears to be on its own filesytem and is not already mounted. This is not a supported setup. "
                    "Some things will probably break (sometimes even silently) in mysterious ways. "
                    "Consult http://freedesktop.org/wiki/Software/systemd/separate-usr-is-broken for more information.");
}

static void test_cgroups(void) {

        if (access("/proc/cgroups", F_OK) >= 0)
                return;

        log_warning("CONFIG_CGROUPS was not set when your kernel was compiled. "
                    "Systems without control groups are not supported. "
                    "We will now sleep for 10s, and then continue boot-up. "
                    "Expect breakage and please do not file bugs. "
                    "Instead fix your kernel and enable CONFIG_CGROUPS. "
                    "Consult http://0pointer.de/blog/projects/cgroups-vs-cgroups.html for more information.");

        sleep(10);
}

static int initialize_join_controllers(void) {
        /* By default, mount "cpu" + "cpuacct" together, and "net_cls"
         * + "net_prio". We'd like to add "cpuset" to the mix, but
         * "cpuset" does't really work for groups with no initialized
         * attributes. */

        arg_join_controllers = new(char**, 3);
        if (!arg_join_controllers)
                return -ENOMEM;

        arg_join_controllers[0] = strv_new("cpu", "cpuacct", NULL);
        arg_join_controllers[1] = strv_new("net_cls", "net_prio", NULL);
        arg_join_controllers[2] = NULL;

        if (!arg_join_controllers[0] || !arg_join_controllers[1]) {
                free_join_controllers();
                return -ENOMEM;
        }

        return 0;
}

int main(int argc, char *argv[]) {
        Manager *m = NULL;
        int r, retval = EXIT_FAILURE;
        usec_t before_startup, after_startup;
        char timespan[FORMAT_TIMESPAN_MAX];
        FDSet *fds = NULL;
        bool reexecute = false;
        const char *shutdown_verb = NULL;
        dual_timestamp initrd_timestamp = { 0ULL, 0ULL };
        dual_timestamp userspace_timestamp = { 0ULL, 0ULL };
        dual_timestamp kernel_timestamp = { 0ULL, 0ULL };
        static char systemd[] = "systemd";
        bool skip_setup = false;
        int j;
        bool loaded_policy = false;
        bool arm_reboot_watchdog = false;
        bool queue_default_job = false;
        char *switch_root_dir = NULL, *switch_root_init = NULL;
        static struct rlimit saved_rlimit_nofile = { 0, 0 };

#ifdef HAVE_SYSV_COMPAT
        if (getpid() != 1 && strstr(program_invocation_short_name, "init")) {
                /* This is compatibility support for SysV, where
                 * calling init as a user is identical to telinit. */

                errno = -ENOENT;
                execv(SYSTEMCTL_BINARY_PATH, argv);
                log_error("Failed to exec " SYSTEMCTL_BINARY_PATH ": %m");
                return 1;
        }
#endif

        dual_timestamp_from_monotonic(&kernel_timestamp, 0);
        dual_timestamp_get(&userspace_timestamp);

        /* Determine if this is a reexecution or normal bootup. We do
         * the full command line parsing much later, so let's just
         * have a quick peek here. */
        if (strv_find(argv+1, "--deserialize"))
                skip_setup = true;

        /* If we have switched root, do all the special setup
         * things */
        if (strv_find(argv+1, "--switched-root"))
                skip_setup = false;

        /* If we get started via the /sbin/init symlink then we are
           called 'init'. After a subsequent reexecution we are then
           called 'systemd'. That is confusing, hence let's call us
           systemd right-away. */
        program_invocation_short_name = systemd;
        prctl(PR_SET_NAME, systemd);

        saved_argv = argv;
        saved_argc = argc;

        log_show_color(isatty(STDERR_FILENO) > 0);

        /* Disable the umask logic */
        if (getpid() == 1)
                umask(0);

        if (getpid() == 1 && detect_container(NULL) <= 0) {

                /* Running outside of a container as PID 1 */
                arg_running_as = SYSTEMD_SYSTEM;
                make_null_stdio();
                log_set_target(LOG_TARGET_KMSG);
                log_open();

                if (in_initrd())
                        initrd_timestamp = userspace_timestamp;

                if (!skip_setup) {
                        mount_setup_early();
                        if (selinux_setup(&loaded_policy) < 0)
                                goto finish;
                        if (ima_setup() < 0)
                                goto finish;
                        if (smack_setup() < 0)
                                goto finish;
                }

                if (label_init(NULL) < 0)
                        goto finish;

                if (!skip_setup) {
                        if (hwclock_is_localtime() > 0) {
                                int min;

                                /* The first-time call to settimeofday() does a time warp in the kernel */
                                r = hwclock_set_timezone(&min);
                                if (r < 0)
                                        log_error("Failed to apply local time delta, ignoring: %s", strerror(-r));
                                else
                                        log_info("RTC configured in localtime, applying delta of %i minutes to system time.", min);
                        } else if (!in_initrd()) {
                                /*
                                 * Do dummy first-time call to seal the kernel's time warp magic
                                 *
                                 * Do not call this this from inside the initrd. The initrd might not
                                 * carry /etc/adjtime with LOCAL, but the real system could be set up
                                 * that way. In such case, we need to delay the time-warp or the sealing
                                 * until we reach the real system.
                                 */
                                hwclock_reset_timezone();

                                /* Tell the kernel our timezone */
                                r = hwclock_set_timezone(NULL);
                                if (r < 0)
                                        log_error("Failed to set the kernel's timezone, ignoring: %s", strerror(-r));
                        }
                }

                /* Set the default for later on, but don't actually
                 * open the logs like this for now. Note that if we
                 * are transitioning from the initrd there might still
                 * be journal fd open, and we shouldn't attempt
                 * opening that before we parsed /proc/cmdline which
                 * might redirect output elsewhere. */
                log_set_target(LOG_TARGET_JOURNAL_OR_KMSG);

        } else if (getpid() == 1) {
                /* Running inside a container, as PID 1 */
                arg_running_as = SYSTEMD_SYSTEM;
                log_set_target(LOG_TARGET_CONSOLE);
                log_open();

                /* For the later on, see above... */
                log_set_target(LOG_TARGET_JOURNAL);

                /* clear the kernel timestamp,
                 * because we are in a container */
                kernel_timestamp.monotonic = 0ULL;
                kernel_timestamp.realtime = 0ULL;

        } else {
                /* Running as user instance */
                arg_running_as = SYSTEMD_USER;
                log_set_target(LOG_TARGET_AUTO);
                log_open();

                /* clear the kernel timestamp,
                 * because we are not PID 1 */
                kernel_timestamp.monotonic = 0ULL;
                kernel_timestamp.realtime = 0ULL;
        }

        /* Initialize default unit */
        r = set_default_unit(SPECIAL_DEFAULT_TARGET);
        if (r < 0) {
                log_error("Failed to set default unit %s: %s", SPECIAL_DEFAULT_TARGET, strerror(-r));
                goto finish;
        }

        r = initialize_join_controllers();
        if (r < 0)
                goto finish;

        /* Mount /proc, /sys and friends, so that /proc/cmdline and
         * /proc/$PID/fd is available. */
        if (getpid() == 1) {
                r = mount_setup(loaded_policy);
                if (r < 0)
                        goto finish;
        }

        /* Reset all signal handlers. */
        assert_se(reset_all_signal_handlers() == 0);

        ignore_signals(SIGNALS_IGNORE, -1);

        if (parse_config_file() < 0)
                goto finish;

        if (arg_running_as == SYSTEMD_SYSTEM)
                if (parse_proc_cmdline() < 0)
                        goto finish;

        log_parse_environment();

        if (parse_argv(argc, argv) < 0)
                goto finish;

        if (arg_action == ACTION_TEST &&
            geteuid() == 0) {
                log_error("Don't run test mode as root.");
                goto finish;
        }

        if (arg_running_as == SYSTEMD_USER &&
            arg_action == ACTION_RUN &&
            sd_booted() <= 0) {
                log_error("Trying to run as user instance, but the system has not been booted with systemd.");
                goto finish;
        }

        if (arg_running_as == SYSTEMD_SYSTEM &&
            arg_action == ACTION_RUN &&
            running_in_chroot() > 0) {
                log_error("Cannot be run in a chroot() environment.");
                goto finish;
        }

        if (arg_action == ACTION_HELP) {
                retval = help();
                goto finish;
        } else if (arg_action == ACTION_VERSION) {
                retval = version();
                goto finish;
        } else if (arg_action == ACTION_DUMP_CONFIGURATION_ITEMS) {
                unit_dump_config_items(stdout);
                retval = EXIT_SUCCESS;
                goto finish;
        } else if (arg_action == ACTION_DONE) {
                retval = EXIT_SUCCESS;
                goto finish;
        }

        assert_se(arg_action == ACTION_RUN || arg_action == ACTION_TEST);

        /* Close logging fds, in order not to confuse fdset below */
        log_close();

        /* Remember open file descriptors for later deserialization */
        r = fdset_new_fill(&fds);
        if (r < 0) {
                log_error("Failed to allocate fd set: %s", strerror(-r));
                goto finish;
        } else
                fdset_cloexec(fds, true);

        if (serialization)
                assert_se(fdset_remove(fds, fileno(serialization)) >= 0);

        if (arg_running_as == SYSTEMD_SYSTEM)
                /* Become a session leader if we aren't one yet. */
                setsid();

        /* Move out of the way, so that we won't block unmounts */
        assert_se(chdir("/")  == 0);

        /* Make sure D-Bus doesn't fiddle with the SIGPIPE handlers */
        dbus_connection_set_change_sigpipe(FALSE);

        /* Reset the console, but only if this is really init and we
         * are freshly booted */
        if (arg_running_as == SYSTEMD_SYSTEM && arg_action == ACTION_RUN)
                console_setup(getpid() == 1 && !skip_setup);

        /* Open the logging devices, if possible and necessary */
        log_open();

        /* Make sure we leave a core dump without panicing the
         * kernel. */
        if (getpid() == 1) {
                install_crash_handler();

                r = mount_cgroup_controllers(arg_join_controllers);
                if (r < 0)
                        goto finish;
        }

        if (arg_running_as == SYSTEMD_SYSTEM) {
                const char *virtualization = NULL;

                log_info(PACKAGE_STRING " running in system mode. (" SYSTEMD_FEATURES ")");

                detect_virtualization(&virtualization);
                if (virtualization)
                        log_info("Detected virtualization '%s'.", virtualization);

                if (in_initrd())
                        log_info("Running in initial RAM disk.");

        } else
                log_debug(PACKAGE_STRING " running in user mode. (" SYSTEMD_FEATURES ")");

        if (arg_running_as == SYSTEMD_SYSTEM && !skip_setup) {
                if (arg_show_status || plymouth_running())
                        status_welcome();

#ifdef HAVE_KMOD
                kmod_setup();
#endif
                hostname_setup();
                machine_id_setup();
                loopback_setup();

                test_mtab();
                test_usr();
                test_cgroups();
        }

        if (arg_running_as == SYSTEMD_SYSTEM && arg_runtime_watchdog > 0)
                watchdog_set_timeout(&arg_runtime_watchdog);

        if (arg_timer_slack_nsec != (nsec_t) -1)
                if (prctl(PR_SET_TIMERSLACK, arg_timer_slack_nsec) < 0)
                        log_error("Failed to adjust timer slack: %m");

        if (arg_capability_bounding_set_drop) {
                r = capability_bounding_set_drop_usermode(arg_capability_bounding_set_drop);
                if (r < 0) {
                        log_error("Failed to drop capability bounding set of usermode helpers: %s", strerror(-r));
                        goto finish;
                }
                r = capability_bounding_set_drop(arg_capability_bounding_set_drop, true);
                if (r < 0) {
                        log_error("Failed to drop capability bounding set: %s", strerror(-r));
                        goto finish;
                }
        }

        if (arg_running_as == SYSTEMD_USER) {
                /* Become reaper of our children */
                if (prctl(PR_SET_CHILD_SUBREAPER, 1) < 0) {
                        log_warning("Failed to make us a subreaper: %m");
                        if (errno == EINVAL)
                                log_info("Perhaps the kernel version is too old (< 3.4?)");
                }
        }

        if (arg_running_as == SYSTEMD_SYSTEM)
                bump_rlimit_nofile(&saved_rlimit_nofile);

        r = manager_new(arg_running_as, !!serialization, &m);
        if (r < 0) {
                log_error("Failed to allocate manager object: %s", strerror(-r));
                goto finish;
        }

        m->confirm_spawn = arg_confirm_spawn;
        m->default_std_output = arg_default_std_output;
        m->default_std_error = arg_default_std_error;
        m->runtime_watchdog = arg_runtime_watchdog;
        m->shutdown_watchdog = arg_shutdown_watchdog;
        m->userspace_timestamp = userspace_timestamp;
        m->kernel_timestamp = kernel_timestamp;
        m->initrd_timestamp = initrd_timestamp;

        manager_set_default_rlimits(m, arg_default_rlimit);

        if (arg_default_environment)
                manager_environment_add(m, arg_default_environment);

        manager_set_show_status(m, arg_show_status);

        /* Remember whether we should queue the default job */
        queue_default_job = !serialization || arg_switched_root;

        before_startup = now(CLOCK_MONOTONIC);

        r = manager_startup(m, serialization, fds);
        if (r < 0)
                log_error("Failed to fully start up daemon: %s", strerror(-r));

        /* This will close all file descriptors that were opened, but
         * not claimed by any unit. */
        fdset_free(fds);
        fds = NULL;

        if (serialization) {
                fclose(serialization);
                serialization = NULL;
        }

        if (queue_default_job) {
                DBusError error;
                Unit *target = NULL;
                Job *default_unit_job;

                dbus_error_init(&error);

                log_debug("Activating default unit: %s", arg_default_unit);

                r = manager_load_unit(m, arg_default_unit, NULL, &error, &target);
                if (r < 0) {
                        log_error("Failed to load default target: %s", bus_error(&error, r));
                        dbus_error_free(&error);
                } else if (target->load_state == UNIT_ERROR || target->load_state == UNIT_NOT_FOUND)
                        log_error("Failed to load default target: %s", strerror(-target->load_error));
                else if (target->load_state == UNIT_MASKED)
                        log_error("Default target masked.");

                if (!target || target->load_state != UNIT_LOADED) {
                        log_info("Trying to load rescue target...");

                        r = manager_load_unit(m, SPECIAL_RESCUE_TARGET, NULL, &error, &target);
                        if (r < 0) {
                                log_error("Failed to load rescue target: %s", bus_error(&error, r));
                                dbus_error_free(&error);
                                goto finish;
                        } else if (target->load_state == UNIT_ERROR || target->load_state == UNIT_NOT_FOUND) {
                                log_error("Failed to load rescue target: %s", strerror(-target->load_error));
                                goto finish;
                        } else if (target->load_state == UNIT_MASKED) {
                                log_error("Rescue target masked.");
                                goto finish;
                        }
                }

                assert(target->load_state == UNIT_LOADED);

                if (arg_action == ACTION_TEST) {
                        printf("-> By units:\n");
                        manager_dump_units(m, stdout, "\t");
                }

                r = manager_add_job(m, JOB_START, target, JOB_ISOLATE, false, &error, &default_unit_job);
                if (r == -EPERM) {
                        log_debug("Default target could not be isolated, starting instead: %s", bus_error(&error, r));
                        dbus_error_free(&error);

                        r = manager_add_job(m, JOB_START, target, JOB_REPLACE, false, &error, &default_unit_job);
                        if (r < 0) {
                                log_error("Failed to start default target: %s", bus_error(&error, r));
                                dbus_error_free(&error);
                                goto finish;
                        }
                } else if (r < 0) {
                        log_error("Failed to isolate default target: %s", bus_error(&error, r));
                        dbus_error_free(&error);
                        goto finish;
                }

                m->default_unit_job_id = default_unit_job->id;

                after_startup = now(CLOCK_MONOTONIC);
                log_full(arg_action == ACTION_TEST ? LOG_INFO : LOG_DEBUG,
                         "Loaded units and determined initial transaction in %s.",
                         format_timespan(timespan, sizeof(timespan), after_startup - before_startup, 0));

                if (arg_action == ACTION_TEST) {
                        printf("-> By jobs:\n");
                        manager_dump_jobs(m, stdout, "\t");
                        retval = EXIT_SUCCESS;
                        goto finish;
                }
        }

        for (;;) {
                r = manager_loop(m);
                if (r < 0) {
                        log_error("Failed to run mainloop: %s", strerror(-r));
                        goto finish;
                }

                switch (m->exit_code) {

                case MANAGER_EXIT:
                        retval = EXIT_SUCCESS;
                        log_debug("Exit.");
                        goto finish;

                case MANAGER_RELOAD:
                        log_info("Reloading.");
                        r = manager_reload(m);
                        if (r < 0)
                                log_error("Failed to reload: %s", strerror(-r));
                        break;

                case MANAGER_REEXECUTE:

                        if (prepare_reexecute(m, &serialization, &fds, false) < 0)
                                goto finish;

                        reexecute = true;
                        log_notice("Reexecuting.");
                        goto finish;

                case MANAGER_SWITCH_ROOT:
                        /* Steal the switch root parameters */
                        switch_root_dir = m->switch_root;
                        switch_root_init = m->switch_root_init;
                        m->switch_root = m->switch_root_init = NULL;

                        if (!switch_root_init)
                                if (prepare_reexecute(m, &serialization, &fds, true) < 0)
                                        goto finish;

                        reexecute = true;
                        log_notice("Switching root.");
                        goto finish;

                case MANAGER_REBOOT:
                case MANAGER_POWEROFF:
                case MANAGER_HALT:
                case MANAGER_KEXEC: {
                        static const char * const table[_MANAGER_EXIT_CODE_MAX] = {
                                [MANAGER_REBOOT] = "reboot",
                                [MANAGER_POWEROFF] = "poweroff",
                                [MANAGER_HALT] = "halt",
                                [MANAGER_KEXEC] = "kexec"
                        };

                        assert_se(shutdown_verb = table[m->exit_code]);
                        arm_reboot_watchdog = m->exit_code == MANAGER_REBOOT;

                        log_notice("Shutting down.");
                        goto finish;
                }

                default:
                        assert_not_reached("Unknown exit code.");
                }
        }

finish:
        if (m)
                manager_free(m);

        for (j = 0; j < RLIMIT_NLIMITS; j++)
                free(arg_default_rlimit[j]);

        free(arg_default_unit);
        free_join_controllers();

        dbus_shutdown();
        label_finish();

        if (reexecute) {
                const char **args;
                unsigned i, args_size;

                /* Close and disarm the watchdog, so that the new
                 * instance can reinitialize it, but doesn't get
                 * rebooted while we do that */
                watchdog_close(true);

                /* Reset the RLIMIT_NOFILE to the kernel default, so
                 * that the new systemd can pass the kernel default to
                 * its child processes */
                if (saved_rlimit_nofile.rlim_cur > 0)
                        setrlimit(RLIMIT_NOFILE, &saved_rlimit_nofile);

                if (switch_root_dir) {
                        /* Kill all remaining processes from the
                         * initrd, but don't wait for them, so that we
                         * can handle the SIGCHLD for them after
                         * deserializing. */
                        broadcast_signal(SIGTERM, false);

                        /* And switch root */
                        r = switch_root(switch_root_dir);
                        if (r < 0)
                                log_error("Failed to switch root, ignoring: %s", strerror(-r));
                }

                args_size = MAX(6, argc+1);
                args = newa(const char*, args_size);

                if (!switch_root_init) {
                        char sfd[16];

                        /* First try to spawn ourselves with the right
                         * path, and with full serialization. We do
                         * this only if the user didn't specify an
                         * explicit init to spawn. */

                        assert(serialization);
                        assert(fds);

                        snprintf(sfd, sizeof(sfd), "%i", fileno(serialization));
                        char_array_0(sfd);

                        i = 0;
                        args[i++] = SYSTEMD_BINARY_PATH;
                        if (switch_root_dir)
                                args[i++] = "--switched-root";
                        args[i++] = arg_running_as == SYSTEMD_SYSTEM ? "--system" : "--user";
                        args[i++] = "--deserialize";
                        args[i++] = sfd;
                        args[i++] = NULL;

                        /* do not pass along the environment we inherit from the kernel or initrd */
                        if (switch_root_dir)
                                clearenv();

                        assert(i <= args_size);
                        execv(args[0], (char* const*) args);
                }

                /* Try the fallback, if there is any, without any
                 * serialization. We pass the original argv[] and
                 * envp[]. (Well, modulo the ordering changes due to
                 * getopt() in argv[], and some cleanups in envp[],
                 * but let's hope that doesn't matter.) */

                if (serialization) {
                        fclose(serialization);
                        serialization = NULL;
                }

                if (fds) {
                        fdset_free(fds);
                        fds = NULL;
                }

                /* Reopen the console */
                make_console_stdio();

                for (j = 1, i = 1; j < argc; j++)
                        args[i++] = argv[j];
                args[i++] = NULL;
                assert(i <= args_size);

                if (switch_root_init) {
                        args[0] = switch_root_init;
                        execv(args[0], (char* const*) args);
                        log_warning("Failed to execute configured init, trying fallback: %m");
                }

                args[0] = "/sbin/init";
                execv(args[0], (char* const*) args);

                if (errno == ENOENT) {
                        log_warning("No /sbin/init, trying fallback");

                        args[0] = "/bin/sh";
                        args[1] = NULL;
                        execv(args[0], (char* const*) args);
                        log_error("Failed to execute /bin/sh, giving up: %m");
                } else
                        log_warning("Failed to execute /sbin/init, giving up: %m");
        }

        if (serialization)
                fclose(serialization);

        if (fds)
                fdset_free(fds);

        if (shutdown_verb) {
                const char * command_line[] = {
                        SYSTEMD_SHUTDOWN_BINARY_PATH,
                        shutdown_verb,
                        NULL
                };
                char **env_block;

                if (arm_reboot_watchdog && arg_shutdown_watchdog > 0) {
                        char e[32];

                        /* If we reboot let's set the shutdown
                         * watchdog and tell the shutdown binary to
                         * repeatedly ping it */
                        watchdog_set_timeout(&arg_shutdown_watchdog);
                        watchdog_close(false);

                        /* Tell the binary how often to ping */
                        snprintf(e, sizeof(e), "WATCHDOG_USEC=%llu", (unsigned long long) arg_shutdown_watchdog);
                        char_array_0(e);

                        env_block = strv_append(environ, e);
                } else {
                        env_block = strv_copy(environ);
                        watchdog_close(true);
                }

                /* Avoid the creation of new processes forked by the
                 * kernel; at this point, we will not listen to the
                 * signals anyway */
                if (detect_container(NULL) <= 0)
                        cg_uninstall_release_agent(SYSTEMD_CGROUP_CONTROLLER);

                execve(SYSTEMD_SHUTDOWN_BINARY_PATH, (char **) command_line, env_block);
                free(env_block);
                log_error("Failed to execute shutdown binary, freezing: %m");
        }

        if (getpid() == 1)
                freeze();

        return retval;
}
