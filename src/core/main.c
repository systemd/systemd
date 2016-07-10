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

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef HAVE_SECCOMP
#include <seccomp.h>
#endif
#ifdef HAVE_VALGRIND_VALGRIND_H
#include <valgrind/valgrind.h>
#endif

#include "sd-bus.h"
#include "sd-daemon.h"

#include "alloc-util.h"
#include "architecture.h"
#include "build.h"
#include "bus-error.h"
#include "bus-util.h"
#include "capability-util.h"
#include "clock-util.h"
#include "conf-parser.h"
#include "cpu-set-util.h"
#include "dbus-manager.h"
#include "def.h"
#include "env-util.h"
#include "fd-util.h"
#include "fdset.h"
#include "fileio.h"
#include "formats-util.h"
#include "fs-util.h"
#include "hostname-setup.h"
#include "ima-setup.h"
#include "killall.h"
#include "kmod-setup.h"
#include "load-fragment.h"
#include "log.h"
#include "loopback-setup.h"
#include "machine-id-setup.h"
#include "manager.h"
#include "missing.h"
#include "mount-setup.h"
#include "pager.h"
#include "parse-util.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "raw-clone.h"
#include "rlimit-util.h"
#include "selinux-setup.h"
#include "selinux-util.h"
#include "signal-util.h"
#include "smack-setup.h"
#include "special.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "strv.h"
#include "switch-root.h"
#include "terminal-util.h"
#include "umask-util.h"
#include "user-util.h"
#include "virt.h"
#include "watchdog.h"

static enum {
        ACTION_RUN,
        ACTION_HELP,
        ACTION_VERSION,
        ACTION_TEST,
        ACTION_DUMP_CONFIGURATION_ITEMS,
        ACTION_DONE
} arg_action = ACTION_RUN;
static char *arg_default_unit = NULL;
static bool arg_system = false;
static bool arg_dump_core = true;
static int arg_crash_chvt = -1;
static bool arg_crash_shell = false;
static bool arg_crash_reboot = false;
static bool arg_confirm_spawn = false;
static ShowStatus arg_show_status = _SHOW_STATUS_UNSET;
static bool arg_switched_root = false;
static bool arg_no_pager = false;
static char ***arg_join_controllers = NULL;
static ExecOutput arg_default_std_output = EXEC_OUTPUT_JOURNAL;
static ExecOutput arg_default_std_error = EXEC_OUTPUT_INHERIT;
static usec_t arg_default_restart_usec = DEFAULT_RESTART_USEC;
static usec_t arg_default_timeout_start_usec = DEFAULT_TIMEOUT_USEC;
static usec_t arg_default_timeout_stop_usec = DEFAULT_TIMEOUT_USEC;
static usec_t arg_default_start_limit_interval = DEFAULT_START_LIMIT_INTERVAL;
static unsigned arg_default_start_limit_burst = DEFAULT_START_LIMIT_BURST;
static usec_t arg_runtime_watchdog = 0;
static usec_t arg_shutdown_watchdog = 10 * USEC_PER_MINUTE;
static char **arg_default_environment = NULL;
static struct rlimit *arg_default_rlimit[_RLIMIT_MAX] = {};
static uint64_t arg_capability_bounding_set = CAP_ALL;
static nsec_t arg_timer_slack_nsec = NSEC_INFINITY;
static usec_t arg_default_timer_accuracy_usec = 1 * USEC_PER_MINUTE;
static Set* arg_syscall_archs = NULL;
static FILE* arg_serialization = NULL;
static bool arg_default_cpu_accounting = false;
static bool arg_default_io_accounting = false;
static bool arg_default_blockio_accounting = false;
static bool arg_default_memory_accounting = false;
static bool arg_default_tasks_accounting = true;
static uint64_t arg_default_tasks_max = UINT64_C(512);
static sd_id128_t arg_machine_id = {};

noreturn static void freeze_or_reboot(void) {

        if (arg_crash_reboot) {
                log_notice("Rebooting in 10s...");
                (void) sleep(10);

                log_notice("Rebooting now...");
                (void) reboot(RB_AUTOBOOT);
                log_emergency_errno(errno, "Failed to reboot: %m");
        }

        log_emergency("Freezing execution.");
        freeze();
}

noreturn static void crash(int sig) {
        struct sigaction sa;
        pid_t pid;

        if (getpid() != 1)
                /* Pass this on immediately, if this is not PID 1 */
                (void) raise(sig);
        else if (!arg_dump_core)
                log_emergency("Caught <%s>, not dumping core.", signal_to_string(sig));
        else {
                sa = (struct sigaction) {
                        .sa_handler = nop_signal_handler,
                        .sa_flags = SA_NOCLDSTOP|SA_RESTART,
                };

                /* We want to wait for the core process, hence let's enable SIGCHLD */
                (void) sigaction(SIGCHLD, &sa, NULL);

                pid = raw_clone(SIGCHLD);
                if (pid < 0)
                        log_emergency_errno(errno, "Caught <%s>, cannot fork for core dump: %m", signal_to_string(sig));
                else if (pid == 0) {
                        /* Enable default signal handler for core dump */

                        sa = (struct sigaction) {
                                .sa_handler = SIG_DFL,
                        };
                        (void) sigaction(sig, &sa, NULL);

                        /* Don't limit the coredump size */
                        (void) setrlimit(RLIMIT_CORE, &RLIMIT_MAKE_CONST(RLIM_INFINITY));

                        /* Just to be sure... */
                        (void) chdir("/");

                        /* Raise the signal again */
                        pid = raw_getpid();
                        (void) kill(pid, sig); /* raise() would kill the parent */

                        assert_not_reached("We shouldn't be here...");
                        _exit(EXIT_FAILURE);
                } else {
                        siginfo_t status;
                        int r;

                        /* Order things nicely. */
                        r = wait_for_terminate(pid, &status);
                        if (r < 0)
                                log_emergency_errno(r, "Caught <%s>, waitpid() failed: %m", signal_to_string(sig));
                        else if (status.si_code != CLD_DUMPED)
                                log_emergency("Caught <%s>, core dump failed (child "PID_FMT", code=%s, status=%i/%s).",
                                              signal_to_string(sig),
                                              pid, sigchld_code_to_string(status.si_code),
                                              status.si_status,
                                              strna(status.si_code == CLD_EXITED
                                                    ? exit_status_to_string(status.si_status, EXIT_STATUS_FULL)
                                                    : signal_to_string(status.si_status)));
                        else
                                log_emergency("Caught <%s>, dumped core as pid "PID_FMT".", signal_to_string(sig), pid);
                }
        }

        if (arg_crash_chvt >= 0)
                (void) chvt(arg_crash_chvt);

        sa = (struct sigaction) {
                .sa_handler = SIG_IGN,
                .sa_flags = SA_NOCLDSTOP|SA_NOCLDWAIT|SA_RESTART,
        };

        /* Let the kernel reap children for us */
        (void) sigaction(SIGCHLD, &sa, NULL);

        if (arg_crash_shell) {
                log_notice("Executing crash shell in 10s...");
                (void) sleep(10);

                pid = raw_clone(SIGCHLD);
                if (pid < 0)
                        log_emergency_errno(errno, "Failed to fork off crash shell: %m");
                else if (pid == 0) {
                        (void) setsid();
                        (void) make_console_stdio();
                        (void) execle("/bin/sh", "/bin/sh", NULL, environ);

                        log_emergency_errno(errno, "execle() failed: %m");
                        _exit(EXIT_FAILURE);
                } else {
                        log_info("Spawned crash shell as PID "PID_FMT".", pid);
                        (void) wait_for_terminate(pid, NULL);
                }
        }

        freeze_or_reboot();
}

static void install_crash_handler(void) {
        static const struct sigaction sa = {
                .sa_handler = crash,
                .sa_flags = SA_NODEFER, /* So that we can raise the signal again from the signal handler */
        };
        int r;

        /* We ignore the return value here, since, we don't mind if we
         * cannot set up a crash handler */
        r = sigaction_many(&sa, SIGNALS_CRASH_HANDLER, -1);
        if (r < 0)
                log_debug_errno(r, "I had trouble setting up the crash handler, ignoring: %m");
}

static int console_setup(void) {
        _cleanup_close_ int tty_fd = -1;
        int r;

        tty_fd = open_terminal("/dev/console", O_WRONLY|O_NOCTTY|O_CLOEXEC);
        if (tty_fd < 0)
                return log_error_errno(tty_fd, "Failed to open /dev/console: %m");

        /* We don't want to force text mode.  plymouth may be showing
         * pictures already from initrd. */
        r = reset_terminal_fd(tty_fd, false);
        if (r < 0)
                return log_error_errno(r, "Failed to reset /dev/console: %m");

        return 0;
}

static int parse_crash_chvt(const char *value) {
        int b;

        if (safe_atoi(value, &arg_crash_chvt) >= 0)
                return 0;

        b = parse_boolean(value);
        if (b < 0)
                return b;

        if (b > 0)
                arg_crash_chvt = 0; /* switch to where kmsg goes */
        else
                arg_crash_chvt = -1; /* turn off switching */

        return 0;
}

static int set_machine_id(const char *m) {
        assert(m);

        if (sd_id128_from_string(m, &arg_machine_id) < 0)
                return -EINVAL;

        if (sd_id128_is_null(arg_machine_id))
                return -EINVAL;

        return 0;
}

static int parse_proc_cmdline_item(const char *key, const char *value) {

        int r;

        assert(key);

        if (streq(key, "systemd.unit") && value) {

                if (!in_initrd())
                        return free_and_strdup(&arg_default_unit, value);

        } else if (streq(key, "rd.systemd.unit") && value) {

                if (in_initrd())
                        return free_and_strdup(&arg_default_unit, value);

        } else if (streq(key, "systemd.dump_core") && value) {

                r = parse_boolean(value);
                if (r < 0)
                        log_warning("Failed to parse dump core switch %s. Ignoring.", value);
                else
                        arg_dump_core = r;

        } else if (streq(key, "systemd.crash_chvt") && value) {

                if (parse_crash_chvt(value) < 0)
                        log_warning("Failed to parse crash chvt switch %s. Ignoring.", value);

        } else if (streq(key, "systemd.crash_shell") && value) {

                r = parse_boolean(value);
                if (r < 0)
                        log_warning("Failed to parse crash shell switch %s. Ignoring.", value);
                else
                        arg_crash_shell = r;

        } else if (streq(key, "systemd.crash_reboot") && value) {

                r = parse_boolean(value);
                if (r < 0)
                        log_warning("Failed to parse crash reboot switch %s. Ignoring.", value);
                else
                        arg_crash_reboot = r;

        } else if (streq(key, "systemd.confirm_spawn") && value) {

                r = parse_boolean(value);
                if (r < 0)
                        log_warning("Failed to parse confirm spawn switch %s. Ignoring.", value);
                else
                        arg_confirm_spawn = r;

        } else if (streq(key, "systemd.show_status") && value) {

                r = parse_show_status(value, &arg_show_status);
                if (r < 0)
                        log_warning("Failed to parse show status switch %s. Ignoring.", value);

        } else if (streq(key, "systemd.default_standard_output") && value) {

                r = exec_output_from_string(value);
                if (r < 0)
                        log_warning("Failed to parse default standard output switch %s. Ignoring.", value);
                else
                        arg_default_std_output = r;

        } else if (streq(key, "systemd.default_standard_error") && value) {

                r = exec_output_from_string(value);
                if (r < 0)
                        log_warning("Failed to parse default standard error switch %s. Ignoring.", value);
                else
                        arg_default_std_error = r;

        } else if (streq(key, "systemd.setenv") && value) {

                if (env_assignment_is_valid(value)) {
                        char **env;

                        env = strv_env_set(arg_default_environment, value);
                        if (env)
                                arg_default_environment = env;
                        else
                                log_warning_errno(ENOMEM, "Setting environment variable '%s' failed, ignoring: %m", value);
                } else
                        log_warning("Environment variable name '%s' is not valid. Ignoring.", value);

        } else if (streq(key, "systemd.machine_id") && value) {

               r = set_machine_id(value);
               if (r < 0)
                       log_warning("MachineID '%s' is not valid. Ignoring.", value);

        } else if (streq(key, "quiet") && !value) {

                if (arg_show_status == _SHOW_STATUS_UNSET)
                        arg_show_status = SHOW_STATUS_AUTO;

        } else if (streq(key, "debug") && !value) {

                /* Note that log_parse_environment() handles 'debug'
                 * too, and sets the log level to LOG_DEBUG. */

                if (detect_container() > 0)
                        log_set_target(LOG_TARGET_CONSOLE);

        } else if (!value) {
                const char *target;

                /* SysV compatibility */
                target = runlevel_to_target(key);
                if (target)
                        return free_and_strdup(&arg_default_unit, target);

        } else if (streq(key, "systemd.default_timeout_start_sec") && value) {

                r = parse_sec(value, &arg_default_timeout_start_usec);
                if (r < 0)
                        log_warning_errno(r, "Failed to parse default start timeout: %s, ignoring.", value);

                if (arg_default_timeout_start_usec <= 0)
                        arg_default_timeout_start_usec = USEC_INFINITY;
        }

        return 0;
}

#define DEFINE_SETTER(name, func, descr)                              \
        static int name(const char *unit,                             \
                        const char *filename,                         \
                        unsigned line,                                \
                        const char *section,                          \
                        unsigned section_line,                        \
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
                        log_syntax(unit, LOG_ERR, filename, line, r,  \
                                   "Invalid " descr "'%s': %m",       \
                                   rvalue);                           \
                                                                      \
                return 0;                                             \
        }

DEFINE_SETTER(config_parse_level2, log_set_max_level_from_string, "log level")
DEFINE_SETTER(config_parse_target, log_set_target_from_string, "target")
DEFINE_SETTER(config_parse_color, log_show_color_from_string, "color" )
DEFINE_SETTER(config_parse_location, log_show_location_from_string, "location")

static int config_parse_cpu_affinity2(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_cpu_free_ cpu_set_t *c = NULL;
        int ncpus;

        ncpus = parse_cpu_set_and_warn(rvalue, &c, unit, filename, line, lvalue);
        if (ncpus < 0)
                return ncpus;

        if (sched_setaffinity(0, CPU_ALLOC_SIZE(ncpus), c) < 0)
                log_warning("Failed to set CPU affinity: %m");

        return 0;
}

static int config_parse_show_status(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        int k;
        ShowStatus *b = data;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        k = parse_show_status(rvalue, b);
        if (k < 0) {
                log_syntax(unit, LOG_ERR, filename, line, k, "Failed to parse show status setting, ignoring: %s", rvalue);
                return 0;
        }

        return 0;
}

static int config_parse_crash_chvt(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = parse_crash_chvt(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse CrashChangeVT= setting, ignoring: %s", rvalue);
                return 0;
        }

        return 0;
}

static int config_parse_join_controllers(const char *unit,
                                         const char *filename,
                                         unsigned line,
                                         const char *section,
                                         unsigned section_line,
                                         const char *lvalue,
                                         int ltype,
                                         const char *rvalue,
                                         void *data,
                                         void *userdata) {

        const char *whole_rvalue = rvalue;
        unsigned n = 0;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        arg_join_controllers = strv_free_free(arg_join_controllers);

        for (;;) {
                _cleanup_free_ char *word = NULL;
                char **l;
                int r;

                r = extract_first_word(&rvalue, &word, WHITESPACE, EXTRACT_QUOTES);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Invalid value for %s: %s", lvalue, whole_rvalue);
                        return r;
                }
                if (r == 0)
                        break;

                l = strv_split(word, ",");
                if (!l)
                        return log_oom();
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
                                        if (strv_extend_strv(&l, *a, false) < 0) {
                                                strv_free(l);
                                                strv_free_free(t);
                                                return log_oom();
                                        }

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
        if (!isempty(rvalue))
                log_syntax(unit, LOG_ERR, filename, line, 0, "Trailing garbage, ignoring.");

        return 0;
}

static int parse_config_file(void) {

        const ConfigTableItem items[] = {
                { "Manager", "LogLevel",                  config_parse_level2,           0, NULL                                   },
                { "Manager", "LogTarget",                 config_parse_target,           0, NULL                                   },
                { "Manager", "LogColor",                  config_parse_color,            0, NULL                                   },
                { "Manager", "LogLocation",               config_parse_location,         0, NULL                                   },
                { "Manager", "DumpCore",                  config_parse_bool,             0, &arg_dump_core                         },
                { "Manager", "CrashChVT", /* legacy */    config_parse_crash_chvt,       0, NULL                                   },
                { "Manager", "CrashChangeVT",             config_parse_crash_chvt,       0, NULL                                   },
                { "Manager", "CrashShell",                config_parse_bool,             0, &arg_crash_shell                       },
                { "Manager", "CrashReboot",               config_parse_bool,             0, &arg_crash_reboot                      },
                { "Manager", "ShowStatus",                config_parse_show_status,      0, &arg_show_status                       },
                { "Manager", "CPUAffinity",               config_parse_cpu_affinity2,    0, NULL                                   },
                { "Manager", "JoinControllers",           config_parse_join_controllers, 0, &arg_join_controllers                  },
                { "Manager", "RuntimeWatchdogSec",        config_parse_sec,              0, &arg_runtime_watchdog                  },
                { "Manager", "ShutdownWatchdogSec",       config_parse_sec,              0, &arg_shutdown_watchdog                 },
                { "Manager", "CapabilityBoundingSet",     config_parse_capability_set,   0, &arg_capability_bounding_set           },
#ifdef HAVE_SECCOMP
                { "Manager", "SystemCallArchitectures",   config_parse_syscall_archs,    0, &arg_syscall_archs                     },
#endif
                { "Manager", "TimerSlackNSec",            config_parse_nsec,             0, &arg_timer_slack_nsec                  },
                { "Manager", "DefaultTimerAccuracySec",   config_parse_sec,              0, &arg_default_timer_accuracy_usec       },
                { "Manager", "DefaultStandardOutput",     config_parse_output,           0, &arg_default_std_output                },
                { "Manager", "DefaultStandardError",      config_parse_output,           0, &arg_default_std_error                 },
                { "Manager", "DefaultTimeoutStartSec",    config_parse_sec,              0, &arg_default_timeout_start_usec        },
                { "Manager", "DefaultTimeoutStopSec",     config_parse_sec,              0, &arg_default_timeout_stop_usec         },
                { "Manager", "DefaultRestartSec",         config_parse_sec,              0, &arg_default_restart_usec              },
                { "Manager", "DefaultStartLimitInterval", config_parse_sec,              0, &arg_default_start_limit_interval      }, /* obsolete alias */
                { "Manager", "DefaultStartLimitIntervalSec",config_parse_sec,            0, &arg_default_start_limit_interval      },
                { "Manager", "DefaultStartLimitBurst",    config_parse_unsigned,         0, &arg_default_start_limit_burst         },
                { "Manager", "DefaultEnvironment",        config_parse_environ,          0, &arg_default_environment               },
                { "Manager", "DefaultLimitCPU",           config_parse_limit,            RLIMIT_CPU, arg_default_rlimit            },
                { "Manager", "DefaultLimitFSIZE",         config_parse_limit,            RLIMIT_FSIZE, arg_default_rlimit          },
                { "Manager", "DefaultLimitDATA",          config_parse_limit,            RLIMIT_DATA, arg_default_rlimit           },
                { "Manager", "DefaultLimitSTACK",         config_parse_limit,            RLIMIT_STACK, arg_default_rlimit          },
                { "Manager", "DefaultLimitCORE",          config_parse_limit,            RLIMIT_CORE, arg_default_rlimit           },
                { "Manager", "DefaultLimitRSS",           config_parse_limit,            RLIMIT_RSS, arg_default_rlimit            },
                { "Manager", "DefaultLimitNOFILE",        config_parse_limit,            RLIMIT_NOFILE, arg_default_rlimit         },
                { "Manager", "DefaultLimitAS",            config_parse_limit,            RLIMIT_AS, arg_default_rlimit             },
                { "Manager", "DefaultLimitNPROC",         config_parse_limit,            RLIMIT_NPROC, arg_default_rlimit          },
                { "Manager", "DefaultLimitMEMLOCK",       config_parse_limit,            RLIMIT_MEMLOCK, arg_default_rlimit        },
                { "Manager", "DefaultLimitLOCKS",         config_parse_limit,            RLIMIT_LOCKS, arg_default_rlimit          },
                { "Manager", "DefaultLimitSIGPENDING",    config_parse_limit,            RLIMIT_SIGPENDING, arg_default_rlimit     },
                { "Manager", "DefaultLimitMSGQUEUE",      config_parse_limit,            RLIMIT_MSGQUEUE, arg_default_rlimit       },
                { "Manager", "DefaultLimitNICE",          config_parse_limit,            RLIMIT_NICE, arg_default_rlimit           },
                { "Manager", "DefaultLimitRTPRIO",        config_parse_limit,            RLIMIT_RTPRIO, arg_default_rlimit         },
                { "Manager", "DefaultLimitRTTIME",        config_parse_limit,            RLIMIT_RTTIME, arg_default_rlimit         },
                { "Manager", "DefaultCPUAccounting",      config_parse_bool,             0, &arg_default_cpu_accounting            },
                { "Manager", "DefaultIOAccounting",       config_parse_bool,             0, &arg_default_io_accounting             },
                { "Manager", "DefaultBlockIOAccounting",  config_parse_bool,             0, &arg_default_blockio_accounting        },
                { "Manager", "DefaultMemoryAccounting",   config_parse_bool,             0, &arg_default_memory_accounting         },
                { "Manager", "DefaultTasksAccounting",    config_parse_bool,             0, &arg_default_tasks_accounting          },
                { "Manager", "DefaultTasksMax",           config_parse_tasks_max,        0, &arg_default_tasks_max                 },
                {}
        };

        const char *fn, *conf_dirs_nulstr;

        fn = arg_system ?
                PKGSYSCONFDIR "/system.conf" :
                PKGSYSCONFDIR "/user.conf";

        conf_dirs_nulstr = arg_system ?
                CONF_PATHS_NULSTR("systemd/system.conf.d") :
                CONF_PATHS_NULSTR("systemd/user.conf.d");

        config_parse_many(fn, conf_dirs_nulstr, "Manager\0", config_item_table_lookup, items, false, NULL);

        /* Traditionally "0" was used to turn off the default unit timeouts. Fix this up so that we used USEC_INFINITY
         * like everywhere else. */
        if (arg_default_timeout_start_usec <= 0)
                arg_default_timeout_start_usec = USEC_INFINITY;
        if (arg_default_timeout_stop_usec <= 0)
                arg_default_timeout_stop_usec = USEC_INFINITY;

        return 0;
}

static void manager_set_defaults(Manager *m) {

        assert(m);

        m->default_timer_accuracy_usec = arg_default_timer_accuracy_usec;
        m->default_std_output = arg_default_std_output;
        m->default_std_error = arg_default_std_error;
        m->default_timeout_start_usec = arg_default_timeout_start_usec;
        m->default_timeout_stop_usec = arg_default_timeout_stop_usec;
        m->default_restart_usec = arg_default_restart_usec;
        m->default_start_limit_interval = arg_default_start_limit_interval;
        m->default_start_limit_burst = arg_default_start_limit_burst;
        m->default_cpu_accounting = arg_default_cpu_accounting;
        m->default_io_accounting = arg_default_io_accounting;
        m->default_blockio_accounting = arg_default_blockio_accounting;
        m->default_memory_accounting = arg_default_memory_accounting;
        m->default_tasks_accounting = arg_default_tasks_accounting;
        m->default_tasks_max = arg_default_tasks_max;

        manager_set_default_rlimits(m, arg_default_rlimit);
        manager_environment_add(m, NULL, arg_default_environment);
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
                ARG_NO_PAGER,
                ARG_VERSION,
                ARG_DUMP_CONFIGURATION_ITEMS,
                ARG_DUMP_CORE,
                ARG_CRASH_CHVT,
                ARG_CRASH_SHELL,
                ARG_CRASH_REBOOT,
                ARG_CONFIRM_SPAWN,
                ARG_SHOW_STATUS,
                ARG_DESERIALIZE,
                ARG_SWITCHED_ROOT,
                ARG_DEFAULT_STD_OUTPUT,
                ARG_DEFAULT_STD_ERROR,
                ARG_MACHINE_ID
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
                { "no-pager",                 no_argument,       NULL, ARG_NO_PAGER                 },
                { "help",                     no_argument,       NULL, 'h'                          },
                { "version",                  no_argument,       NULL, ARG_VERSION                  },
                { "dump-configuration-items", no_argument,       NULL, ARG_DUMP_CONFIGURATION_ITEMS },
                { "dump-core",                optional_argument, NULL, ARG_DUMP_CORE                },
                { "crash-chvt",               required_argument, NULL, ARG_CRASH_CHVT               },
                { "crash-shell",              optional_argument, NULL, ARG_CRASH_SHELL              },
                { "crash-reboot",             optional_argument, NULL, ARG_CRASH_REBOOT             },
                { "confirm-spawn",            optional_argument, NULL, ARG_CONFIRM_SPAWN            },
                { "show-status",              optional_argument, NULL, ARG_SHOW_STATUS              },
                { "deserialize",              required_argument, NULL, ARG_DESERIALIZE              },
                { "switched-root",            no_argument,       NULL, ARG_SWITCHED_ROOT            },
                { "default-standard-output",  required_argument, NULL, ARG_DEFAULT_STD_OUTPUT,      },
                { "default-standard-error",   required_argument, NULL, ARG_DEFAULT_STD_ERROR,       },
                { "machine-id",               required_argument, NULL, ARG_MACHINE_ID               },
                {}
        };

        int c, r;

        assert(argc >= 1);
        assert(argv);

        if (getpid() == 1)
                opterr = 0;

        while ((c = getopt_long(argc, argv, "hDbsz:", options, NULL)) >= 0)

                switch (c) {

                case ARG_LOG_LEVEL:
                        r = log_set_max_level_from_string(optarg);
                        if (r < 0) {
                                log_error("Failed to parse log level %s.", optarg);
                                return r;
                        }

                        break;

                case ARG_LOG_TARGET:
                        r = log_set_target_from_string(optarg);
                        if (r < 0) {
                                log_error("Failed to parse log target %s.", optarg);
                                return r;
                        }

                        break;

                case ARG_LOG_COLOR:

                        if (optarg) {
                                r = log_show_color_from_string(optarg);
                                if (r < 0) {
                                        log_error("Failed to parse log color setting %s.", optarg);
                                        return r;
                                }
                        } else
                                log_show_color(true);

                        break;

                case ARG_LOG_LOCATION:
                        if (optarg) {
                                r = log_show_location_from_string(optarg);
                                if (r < 0) {
                                        log_error("Failed to parse log location setting %s.", optarg);
                                        return r;
                                }
                        } else
                                log_show_location(true);

                        break;

                case ARG_DEFAULT_STD_OUTPUT:
                        r = exec_output_from_string(optarg);
                        if (r < 0) {
                                log_error("Failed to parse default standard output setting %s.", optarg);
                                return r;
                        } else
                                arg_default_std_output = r;
                        break;

                case ARG_DEFAULT_STD_ERROR:
                        r = exec_output_from_string(optarg);
                        if (r < 0) {
                                log_error("Failed to parse default standard error output setting %s.", optarg);
                                return r;
                        } else
                                arg_default_std_error = r;
                        break;

                case ARG_UNIT:

                        r = free_and_strdup(&arg_default_unit, optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set default unit %s: %m", optarg);

                        break;

                case ARG_SYSTEM:
                        arg_system = true;
                        break;

                case ARG_USER:
                        arg_system = false;
                        break;

                case ARG_TEST:
                        arg_action = ACTION_TEST;
                        break;

                case ARG_NO_PAGER:
                        arg_no_pager = true;
                        break;

                case ARG_VERSION:
                        arg_action = ACTION_VERSION;
                        break;

                case ARG_DUMP_CONFIGURATION_ITEMS:
                        arg_action = ACTION_DUMP_CONFIGURATION_ITEMS;
                        break;

                case ARG_DUMP_CORE:
                        if (!optarg)
                                arg_dump_core = true;
                        else {
                                r = parse_boolean(optarg);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse dump core boolean: %s", optarg);
                                arg_dump_core = r;
                        }
                        break;

                case ARG_CRASH_CHVT:
                        r = parse_crash_chvt(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse crash virtual terminal index: %s", optarg);
                        break;

                case ARG_CRASH_SHELL:
                        if (!optarg)
                                arg_crash_shell = true;
                        else {
                                r = parse_boolean(optarg);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse crash shell boolean: %s", optarg);
                                arg_crash_shell = r;
                        }
                        break;

                case ARG_CRASH_REBOOT:
                        if (!optarg)
                                arg_crash_reboot = true;
                        else {
                                r = parse_boolean(optarg);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse crash shell boolean: %s", optarg);
                                arg_crash_reboot = r;
                        }
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
                        if (optarg) {
                                r = parse_show_status(optarg, &arg_show_status);
                                if (r < 0) {
                                        log_error("Failed to parse show status boolean %s.", optarg);
                                        return r;
                                }
                        } else
                                arg_show_status = SHOW_STATUS_YES;
                        break;

                case ARG_DESERIALIZE: {
                        int fd;
                        FILE *f;

                        r = safe_atoi(optarg, &fd);
                        if (r < 0 || fd < 0) {
                                log_error("Failed to parse deserialize option %s.", optarg);
                                return -EINVAL;
                        }

                        (void) fd_cloexec(fd, true);

                        f = fdopen(fd, "r");
                        if (!f)
                                return log_error_errno(errno, "Failed to open serialization fd: %m");

                        safe_fclose(arg_serialization);
                        arg_serialization = f;

                        break;
                }

                case ARG_SWITCHED_ROOT:
                        arg_switched_root = true;
                        break;

                case ARG_MACHINE_ID:
                        r = set_machine_id(optarg);
                        if (r < 0) {
                                log_error("MachineID '%s' is not valid.", optarg);
                                return r;
                        }
                        break;

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
                        if (getpid() != 1)
                                return -EINVAL;
                        else
                                return 0;

                default:
                        assert_not_reached("Unhandled option code.");
                }

        if (optind < argc && getpid() != 1) {
                /* Hmm, when we aren't run as init system
                 * let's complain about excess arguments */

                log_error("Excess arguments.");
                return -EINVAL;
        }

        return 0;
}

static int help(void) {

        printf("%s [OPTIONS...]\n\n"
               "Starts up and maintains the system or user services.\n\n"
               "  -h --help                      Show this help\n"
               "     --test                      Determine startup sequence, dump it and exit\n"
               "     --no-pager                  Do not pipe output into a pager\n"
               "     --dump-configuration-items  Dump understood unit configuration items\n"
               "     --unit=UNIT                 Set default unit\n"
               "     --system                    Run a system instance, even if PID != 1\n"
               "     --user                      Run a user instance\n"
               "     --dump-core[=BOOL]          Dump core on crash\n"
               "     --crash-vt=NR               Change to specified VT on crash\n"
               "     --crash-reboot[=BOOL]       Reboot on crash\n"
               "     --crash-shell[=BOOL]        Run shell on crash\n"
               "     --confirm-spawn[=BOOL]      Ask for confirmation when spawning processes\n"
               "     --show-status[=BOOL]        Show status updates on the console during bootup\n"
               "     --log-target=TARGET         Set log target (console, journal, kmsg, journal-or-kmsg, null)\n"
               "     --log-level=LEVEL           Set log level (debug, info, notice, warning, err, crit, alert, emerg)\n"
               "     --log-color[=BOOL]          Highlight important log messages\n"
               "     --log-location[=BOOL]       Include code location in log messages\n"
               "     --default-standard-output=  Set default standard output for services\n"
               "     --default-standard-error=   Set default standard error output for services\n",
               program_invocation_short_name);

        return 0;
}

static int prepare_reexecute(Manager *m, FILE **_f, FDSet **_fds, bool switching_root) {
        _cleanup_fdset_free_ FDSet *fds = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(m);
        assert(_f);
        assert(_fds);

        r = manager_open_serialization(m, &f);
        if (r < 0)
                return log_error_errno(r, "Failed to create serialization file: %m");

        /* Make sure nothing is really destructed when we shut down */
        m->n_reloading++;
        bus_manager_send_reloading(m, true);

        fds = fdset_new();
        if (!fds)
                return log_oom();

        r = manager_serialize(m, f, fds, switching_root);
        if (r < 0)
                return log_error_errno(r, "Failed to serialize state: %m");

        if (fseeko(f, 0, SEEK_SET) == (off_t) -1)
                return log_error_errno(errno, "Failed to rewind serialization fd: %m");

        r = fd_cloexec(fileno(f), false);
        if (r < 0)
                return log_error_errno(r, "Failed to disable O_CLOEXEC for serialization: %m");

        r = fdset_cloexec(fds, false);
        if (r < 0)
                return log_error_errno(r, "Failed to disable O_CLOEXEC for serialization fds: %m");

        *_f = f;
        *_fds = fds;

        f = NULL;
        fds = NULL;

        return 0;
}

static int bump_rlimit_nofile(struct rlimit *saved_rlimit) {
        struct rlimit nl;
        int r;

        assert(saved_rlimit);

        /* Save the original RLIMIT_NOFILE so that we can reset it
         * later when transitioning from the initrd to the main
         * systemd or suchlike. */
        if (getrlimit(RLIMIT_NOFILE, saved_rlimit) < 0)
                return log_error_errno(errno, "Reading RLIMIT_NOFILE failed: %m");

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
        if (r < 0)
                return log_error_errno(r, "Setting RLIMIT_NOFILE failed: %m");

        return 0;
}

static void test_usr(void) {

        /* Check that /usr is not a separate fs */

        if (dir_is_empty("/usr") <= 0)
                return;

        log_warning("/usr appears to be on its own filesystem and is not already mounted. This is not a supported setup. "
                    "Some things will probably break (sometimes even silently) in mysterious ways. "
                    "Consult http://freedesktop.org/wiki/Software/systemd/separate-usr-is-broken for more information.");
}

static int initialize_join_controllers(void) {
        /* By default, mount "cpu" + "cpuacct" together, and "net_cls"
         * + "net_prio". We'd like to add "cpuset" to the mix, but
         * "cpuset" doesn't really work for groups with no initialized
         * attributes. */

        arg_join_controllers = new(char**, 3);
        if (!arg_join_controllers)
                return -ENOMEM;

        arg_join_controllers[0] = strv_new("cpu", "cpuacct", NULL);
        if (!arg_join_controllers[0])
                goto oom;

        arg_join_controllers[1] = strv_new("net_cls", "net_prio", NULL);
        if (!arg_join_controllers[1])
                goto oom;

        arg_join_controllers[2] = NULL;
        return 0;

oom:
        arg_join_controllers = strv_free_free(arg_join_controllers);
        return -ENOMEM;
}

static int enforce_syscall_archs(Set *archs) {
#ifdef HAVE_SECCOMP
        scmp_filter_ctx *seccomp;
        Iterator i;
        void *id;
        int r;

        seccomp = seccomp_init(SCMP_ACT_ALLOW);
        if (!seccomp)
                return log_oom();

        SET_FOREACH(id, arg_syscall_archs, i) {
                r = seccomp_arch_add(seccomp, PTR_TO_UINT32(id) - 1);
                if (r == -EEXIST)
                        continue;
                if (r < 0) {
                        log_error_errno(r, "Failed to add architecture to seccomp: %m");
                        goto finish;
                }
        }

        r = seccomp_attr_set(seccomp, SCMP_FLTATR_CTL_NNP, 0);
        if (r < 0) {
                log_error_errno(r, "Failed to unset NO_NEW_PRIVS: %m");
                goto finish;
        }

        r = seccomp_load(seccomp);
        if (r < 0)
                log_error_errno(r, "Failed to add install architecture seccomp: %m");

finish:
        seccomp_release(seccomp);
        return r;
#else
        return 0;
#endif
}

static int status_welcome(void) {
        _cleanup_free_ char *pretty_name = NULL, *ansi_color = NULL;
        int r;

        r = parse_env_file("/etc/os-release", NEWLINE,
                           "PRETTY_NAME", &pretty_name,
                           "ANSI_COLOR", &ansi_color,
                           NULL);
        if (r == -ENOENT)
                r = parse_env_file("/usr/lib/os-release", NEWLINE,
                                   "PRETTY_NAME", &pretty_name,
                                   "ANSI_COLOR", &ansi_color,
                                   NULL);

        if (r < 0 && r != -ENOENT)
                log_warning_errno(r, "Failed to read os-release file: %m");

        if (log_get_show_color())
                return status_printf(NULL, false, false,
                                     "\nWelcome to \x1B[%sm%s\x1B[0m!\n",
                                     isempty(ansi_color) ? "1" : ansi_color,
                                     isempty(pretty_name) ? "Linux" : pretty_name);
        else
                return status_printf(NULL, false, false,
                                     "\nWelcome to %s!\n",
                                     isempty(pretty_name) ? "Linux" : pretty_name);
}

static int write_container_id(void) {
        const char *c;
        int r;

        c = getenv("container");
        if (isempty(c))
                return 0;

        RUN_WITH_UMASK(0022)
                r = write_string_file("/run/systemd/container", c, WRITE_STRING_FILE_CREATE);
        if (r < 0)
                return log_warning_errno(r, "Failed to write /run/systemd/container, ignoring: %m");

        return 1;
}

static int bump_unix_max_dgram_qlen(void) {
        _cleanup_free_ char *qlen = NULL;
        unsigned long v;
        int r;

        /* Let's bump the net.unix.max_dgram_qlen sysctl. The kernel
         * default of 16 is simply too low. We set the value really
         * really early during boot, so that it is actually applied to
         * all our sockets, including the $NOTIFY_SOCKET one. */

        r = read_one_line_file("/proc/sys/net/unix/max_dgram_qlen", &qlen);
        if (r < 0)
                return log_warning_errno(r, "Failed to read AF_UNIX datagram queue length, ignoring: %m");

        r = safe_atolu(qlen, &v);
        if (r < 0)
                return log_warning_errno(r, "Failed to parse AF_UNIX datagram queue length, ignoring: %m");

        if (v >= DEFAULT_UNIX_MAX_DGRAM_QLEN)
                return 0;

        qlen = mfree(qlen);
        if (asprintf(&qlen, "%lu\n", DEFAULT_UNIX_MAX_DGRAM_QLEN) < 0)
                return log_oom();

        r = write_string_file("/proc/sys/net/unix/max_dgram_qlen", qlen, 0);
        if (r < 0)
                return log_full_errno(IN_SET(r, -EROFS, -EPERM, -EACCES) ? LOG_DEBUG : LOG_WARNING, r,
                                      "Failed to bump AF_UNIX datagram queue length, ignoring: %m");

        return 1;
}

static int fixup_environment(void) {
        _cleanup_free_ char *term = NULL;
        int r;

        /* When started as PID1, the kernel uses /dev/console
         * for our stdios and uses TERM=linux whatever the
         * backend device used by the console. We try to make
         * a better guess here since some consoles might not
         * have support for color mode for example.
         *
         * However if TERM was configured through the kernel
         * command line then leave it alone. */

        r = get_proc_cmdline_key("TERM=", &term);
        if (r < 0)
                return r;

        if (r == 0) {
                term = strdup(default_term_for_tty("/dev/console") + 5);
                if (!term)
                        return -errno;
        }

        if (setenv("TERM", term, 1) < 0)
                return -errno;

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
        dual_timestamp initrd_timestamp = DUAL_TIMESTAMP_NULL;
        dual_timestamp userspace_timestamp = DUAL_TIMESTAMP_NULL;
        dual_timestamp kernel_timestamp = DUAL_TIMESTAMP_NULL;
        dual_timestamp security_start_timestamp = DUAL_TIMESTAMP_NULL;
        dual_timestamp security_finish_timestamp = DUAL_TIMESTAMP_NULL;
        static char systemd[] = "systemd";
        bool skip_setup = false;
        unsigned j;
        bool loaded_policy = false;
        bool arm_reboot_watchdog = false;
        bool queue_default_job = false;
        bool empty_etc = false;
        char *switch_root_dir = NULL, *switch_root_init = NULL;
        struct rlimit saved_rlimit_nofile = RLIMIT_MAKE_CONST(0);
        const char *error_message = NULL;

#ifdef HAVE_SYSV_COMPAT
        if (getpid() != 1 && strstr(program_invocation_short_name, "init")) {
                /* This is compatibility support for SysV, where
                 * calling init as a user is identical to telinit. */

                execv(SYSTEMCTL_BINARY_PATH, argv);
                log_error_errno(errno, "Failed to exec " SYSTEMCTL_BINARY_PATH ": %m");
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

        log_set_upgrade_syslog_to_journal(true);

        /* Disable the umask logic */
        if (getpid() == 1)
                umask(0);

        if (getpid() == 1 && detect_container() <= 0) {

                /* Running outside of a container as PID 1 */
                arg_system = true;
                log_set_target(LOG_TARGET_KMSG);
                log_open();

                if (in_initrd())
                        initrd_timestamp = userspace_timestamp;

                if (!skip_setup) {
                        r = mount_setup_early();
                        if (r < 0) {
                                error_message = "Failed to early mount API filesystems";
                                goto finish;
                        }
                        dual_timestamp_get(&security_start_timestamp);
                        if (mac_selinux_setup(&loaded_policy) < 0) {
                                error_message = "Failed to load SELinux policy";
                                goto finish;
                        } else if (ima_setup() < 0) {
                                error_message = "Failed to load IMA policy";
                                goto finish;
                        } else if (mac_smack_setup(&loaded_policy) < 0) {
                                error_message = "Failed to load SMACK policy";
                                goto finish;
                        }
                        dual_timestamp_get(&security_finish_timestamp);
                }

                if (mac_selinux_init() < 0) {
                        error_message = "Failed to initialize SELinux policy";
                        goto finish;
                }

                if (!skip_setup) {
                        if (clock_is_localtime(NULL) > 0) {
                                int min;

                                /*
                                 * The very first call of settimeofday() also does a time warp in the kernel.
                                 *
                                 * In the rtc-in-local time mode, we set the kernel's timezone, and rely on
                                 * external tools to take care of maintaining the RTC and do all adjustments.
                                 * This matches the behavior of Windows, which leaves the RTC alone if the
                                 * registry tells that the RTC runs in UTC.
                                 */
                                r = clock_set_timezone(&min);
                                if (r < 0)
                                        log_error_errno(r, "Failed to apply local time delta, ignoring: %m");
                                else
                                        log_info("RTC configured in localtime, applying delta of %i minutes to system time.", min);
                        } else if (!in_initrd()) {
                                /*
                                 * Do a dummy very first call to seal the kernel's time warp magic.
                                 *
                                 * Do not call this from inside the initrd. The initrd might not
                                 * carry /etc/adjtime with LOCAL, but the real system could be set up
                                 * that way. In such case, we need to delay the time-warp or the sealing
                                 * until we reach the real system.
                                 *
                                 * Do no set the kernel's timezone. The concept of local time cannot
                                 * be supported reliably, the time will jump or be incorrect at every daylight
                                 * saving time change. All kernel local time concepts will be treated
                                 * as UTC that way.
                                 */
                                (void) clock_reset_timewarp();
                        }

                        r = clock_apply_epoch();
                        if (r < 0)
                                log_error_errno(r, "Current system time is before build time, but cannot correct: %m");
                        else if (r > 0)
                                log_info("System time before build time, advancing clock.");
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
                arg_system = true;
                log_set_target(LOG_TARGET_CONSOLE);
                log_close_console(); /* force reopen of /dev/console */
                log_open();

                /* For the later on, see above... */
                log_set_target(LOG_TARGET_JOURNAL);

                /* clear the kernel timestamp,
                 * because we are in a container */
                kernel_timestamp = DUAL_TIMESTAMP_NULL;
        } else {
                /* Running as user instance */
                arg_system = false;
                log_set_target(LOG_TARGET_AUTO);
                log_open();

                /* clear the kernel timestamp,
                 * because we are not PID 1 */
                kernel_timestamp = DUAL_TIMESTAMP_NULL;
        }

        if (getpid() == 1) {
                /* Don't limit the core dump size, so that coredump handlers such as systemd-coredump (which honour the limit)
                 * will process core dumps for system services by default. */
                (void) setrlimit(RLIMIT_CORE, &RLIMIT_MAKE_CONST(RLIM_INFINITY));

                /* But at the same time, turn off the core_pattern logic by default, so that no coredumps are stored
                 * until the systemd-coredump tool is enabled via sysctl. */
                if (!skip_setup)
                        (void) write_string_file("/proc/sys/kernel/core_pattern", "|/bin/false", 0);
        }

        if (arg_system) {
                /* We expect the environment to be set correctly
                 * if run inside a container. */
                if (detect_container() <= 0)
                        if (fixup_environment() < 0) {
                                error_message = "Failed to fix up PID1 environment";
                                goto finish;
                        }

                /* Try to figure out if we can use colors with the console. No
                 * need to do that for user instances since they never log
                 * into the console. */
                log_show_color(colors_enabled());
                make_null_stdio();
        }

        /* Initialize default unit */
        r = free_and_strdup(&arg_default_unit, SPECIAL_DEFAULT_TARGET);
        if (r < 0) {
                log_emergency_errno(r, "Failed to set default unit %s: %m", SPECIAL_DEFAULT_TARGET);
                error_message = "Failed to set default unit";
                goto finish;
        }

        r = initialize_join_controllers();
        if (r < 0) {
                error_message = "Failed to initialize cgroup controllers";
                goto finish;
        }

        /* Mount /proc, /sys and friends, so that /proc/cmdline and
         * /proc/$PID/fd is available. */
        if (getpid() == 1) {

                /* Load the kernel modules early, so that we kdbus.ko is loaded before kdbusfs shall be mounted */
                if (!skip_setup)
                        kmod_setup();

                r = mount_setup(loaded_policy);
                if (r < 0) {
                        error_message = "Failed to mount API filesystems";
                        goto finish;
                }
        }

        /* Reset all signal handlers. */
        (void) reset_all_signal_handlers();
        (void) ignore_signals(SIGNALS_IGNORE, -1);

        if (parse_config_file() < 0) {
                error_message = "Failed to parse config file";
                goto finish;
        }

        if (arg_system) {
                r = parse_proc_cmdline(parse_proc_cmdline_item);
                if (r < 0)
                        log_warning_errno(r, "Failed to parse kernel command line, ignoring: %m");
        }

        /* Note that this also parses bits from the kernel command
         * line, including "debug". */
        log_parse_environment();

        if (parse_argv(argc, argv) < 0) {
                error_message = "Failed to parse commandline arguments";
                goto finish;
        }

        if (arg_action == ACTION_TEST &&
            geteuid() == 0) {
                log_error("Don't run test mode as root.");
                goto finish;
        }

        if (!arg_system &&
            arg_action == ACTION_RUN &&
            sd_booted() <= 0) {
                log_error("Trying to run as user instance, but the system has not been booted with systemd.");
                goto finish;
        }

        if (arg_system &&
            arg_action == ACTION_RUN &&
            running_in_chroot() > 0) {
                log_error("Cannot be run in a chroot() environment.");
                goto finish;
        }

        if (arg_action == ACTION_TEST)
                skip_setup = true;

        if (arg_action == ACTION_TEST || arg_action == ACTION_HELP)
                pager_open(arg_no_pager, false);

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

        if (!arg_system &&
            !getenv("XDG_RUNTIME_DIR")) {
                log_error("Trying to run as user instance, but $XDG_RUNTIME_DIR is not set.");
                goto finish;
        }

        assert_se(arg_action == ACTION_RUN || arg_action == ACTION_TEST);

        /* Close logging fds, in order not to confuse fdset below */
        log_close();

        /* Remember open file descriptors for later deserialization */
        r = fdset_new_fill(&fds);
        if (r < 0) {
                log_emergency_errno(r, "Failed to allocate fd set: %m");
                error_message = "Failed to allocate fd set";
                goto finish;
        } else
                fdset_cloexec(fds, true);

        if (arg_serialization)
                assert_se(fdset_remove(fds, fileno(arg_serialization)) >= 0);

        if (arg_system)
                /* Become a session leader if we aren't one yet. */
                setsid();

        /* Move out of the way, so that we won't block unmounts */
        assert_se(chdir("/") == 0);

        /* Reset the console, but only if this is really init and we
         * are freshly booted */
        if (arg_system && arg_action == ACTION_RUN) {

                /* If we are init, we connect stdin/stdout/stderr to
                 * /dev/null and make sure we don't have a controlling
                 * tty. */
                release_terminal();

                if (getpid() == 1 && !skip_setup)
                        console_setup();
        }

        /* Open the logging devices, if possible and necessary */
        log_open();

        if (arg_show_status == _SHOW_STATUS_UNSET)
                arg_show_status = SHOW_STATUS_YES;

        /* Make sure we leave a core dump without panicing the
         * kernel. */
        if (getpid() == 1) {
                install_crash_handler();

                r = mount_cgroup_controllers(arg_join_controllers);
                if (r < 0)
                        goto finish;
        }

        if (arg_system) {
                int v;

                log_info(PACKAGE_STRING " running in %ssystem mode. (" SYSTEMD_FEATURES ")",
                         arg_action == ACTION_TEST ? "test " : "" );

                v = detect_virtualization();
                if (v > 0)
                        log_info("Detected virtualization %s.", virtualization_to_string(v));

                write_container_id();

                log_info("Detected architecture %s.", architecture_to_string(uname_architecture()));

                if (in_initrd())
                        log_info("Running in initial RAM disk.");

                /* Let's check whether /etc is already populated. We
                 * don't actually really check for that, but use
                 * /etc/machine-id as flag file. This allows container
                 * managers and installers to provision a couple of
                 * files already. If the container manager wants to
                 * provision the machine ID itself it should pass
                 * $container_uuid to PID 1. */

                empty_etc = access("/etc/machine-id", F_OK) < 0;
                if (empty_etc)
                        log_info("Running with unpopulated /etc.");
        } else {
                _cleanup_free_ char *t;

                t = uid_to_name(getuid());
                log_debug(PACKAGE_STRING " running in %suser mode for user "UID_FMT"/%s. (" SYSTEMD_FEATURES ")",
                          arg_action == ACTION_TEST ? " test" : "", getuid(), t);
        }

        if (arg_system && !skip_setup) {
                if (arg_show_status > 0)
                        status_welcome();

                hostname_setup();
                machine_id_setup(NULL, arg_machine_id);
                loopback_setup();
                bump_unix_max_dgram_qlen();

                test_usr();
        }

        if (arg_system && arg_runtime_watchdog > 0 && arg_runtime_watchdog != USEC_INFINITY)
                watchdog_set_timeout(&arg_runtime_watchdog);

        if (arg_timer_slack_nsec != NSEC_INFINITY)
                if (prctl(PR_SET_TIMERSLACK, arg_timer_slack_nsec) < 0)
                        log_error_errno(errno, "Failed to adjust timer slack: %m");

        if (!cap_test_all(arg_capability_bounding_set)) {
                r = capability_bounding_set_drop_usermode(arg_capability_bounding_set);
                if (r < 0) {
                        log_emergency_errno(r, "Failed to drop capability bounding set of usermode helpers: %m");
                        error_message = "Failed to drop capability bounding set of usermode helpers";
                        goto finish;
                }
                r = capability_bounding_set_drop(arg_capability_bounding_set, true);
                if (r < 0) {
                        log_emergency_errno(r, "Failed to drop capability bounding set: %m");
                        error_message = "Failed to drop capability bounding set";
                        goto finish;
                }
        }

        if (arg_syscall_archs) {
                r = enforce_syscall_archs(arg_syscall_archs);
                if (r < 0) {
                        error_message = "Failed to set syscall architectures";
                        goto finish;
                }
        }

        if (!arg_system)
                /* Become reaper of our children */
                if (prctl(PR_SET_CHILD_SUBREAPER, 1) < 0)
                        log_warning_errno(errno, "Failed to make us a subreaper: %m");

        if (arg_system) {
                bump_rlimit_nofile(&saved_rlimit_nofile);

                if (empty_etc) {
                        r = unit_file_preset_all(UNIT_FILE_SYSTEM, false, NULL, UNIT_FILE_PRESET_ENABLE_ONLY, false, NULL, 0);
                        if (r < 0)
                                log_full_errno(r == -EEXIST ? LOG_NOTICE : LOG_WARNING, r, "Failed to populate /etc with preset unit settings, ignoring: %m");
                        else
                                log_info("Populated /etc with preset unit settings.");
                }
        }

        r = manager_new(arg_system ? UNIT_FILE_SYSTEM : UNIT_FILE_USER, arg_action == ACTION_TEST, &m);
        if (r < 0) {
                log_emergency_errno(r, "Failed to allocate manager object: %m");
                error_message = "Failed to allocate manager object";
                goto finish;
        }

        m->confirm_spawn = arg_confirm_spawn;
        m->runtime_watchdog = arg_runtime_watchdog;
        m->shutdown_watchdog = arg_shutdown_watchdog;
        m->userspace_timestamp = userspace_timestamp;
        m->kernel_timestamp = kernel_timestamp;
        m->initrd_timestamp = initrd_timestamp;
        m->security_start_timestamp = security_start_timestamp;
        m->security_finish_timestamp = security_finish_timestamp;

        manager_set_defaults(m);
        manager_set_show_status(m, arg_show_status);
        manager_set_first_boot(m, empty_etc);

        /* Remember whether we should queue the default job */
        queue_default_job = !arg_serialization || arg_switched_root;

        before_startup = now(CLOCK_MONOTONIC);

        r = manager_startup(m, arg_serialization, fds);
        if (r < 0)
                log_error_errno(r, "Failed to fully start up daemon: %m");

        /* This will close all file descriptors that were opened, but
         * not claimed by any unit. */
        fds = fdset_free(fds);

        arg_serialization = safe_fclose(arg_serialization);

        if (queue_default_job) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                Unit *target = NULL;
                Job *default_unit_job;

                log_debug("Activating default unit: %s", arg_default_unit);

                r = manager_load_unit(m, arg_default_unit, NULL, &error, &target);
                if (r < 0)
                        log_error("Failed to load default target: %s", bus_error_message(&error, r));
                else if (target->load_state == UNIT_ERROR || target->load_state == UNIT_NOT_FOUND)
                        log_error_errno(target->load_error, "Failed to load default target: %m");
                else if (target->load_state == UNIT_MASKED)
                        log_error("Default target masked.");

                if (!target || target->load_state != UNIT_LOADED) {
                        log_info("Trying to load rescue target...");

                        r = manager_load_unit(m, SPECIAL_RESCUE_TARGET, NULL, &error, &target);
                        if (r < 0) {
                                log_emergency("Failed to load rescue target: %s", bus_error_message(&error, r));
                                error_message = "Failed to load rescue target";
                                goto finish;
                        } else if (target->load_state == UNIT_ERROR || target->load_state == UNIT_NOT_FOUND) {
                                log_emergency_errno(target->load_error, "Failed to load rescue target: %m");
                                error_message = "Failed to load rescue target";
                                goto finish;
                        } else if (target->load_state == UNIT_MASKED) {
                                log_emergency("Rescue target masked.");
                                error_message = "Rescue target masked";
                                goto finish;
                        }
                }

                assert(target->load_state == UNIT_LOADED);

                if (arg_action == ACTION_TEST) {
                        printf("-> By units:\n");
                        manager_dump_units(m, stdout, "\t");
                }

                r = manager_add_job(m, JOB_START, target, JOB_ISOLATE, &error, &default_unit_job);
                if (r == -EPERM) {
                        log_debug("Default target could not be isolated, starting instead: %s", bus_error_message(&error, r));

                        sd_bus_error_free(&error);

                        r = manager_add_job(m, JOB_START, target, JOB_REPLACE, &error, &default_unit_job);
                        if (r < 0) {
                                log_emergency("Failed to start default target: %s", bus_error_message(&error, r));
                                error_message = "Failed to start default target";
                                goto finish;
                        }
                } else if (r < 0) {
                        log_emergency("Failed to isolate default target: %s", bus_error_message(&error, r));
                        error_message = "Failed to isolate default target";
                        goto finish;
                }

                m->default_unit_job_id = default_unit_job->id;

                after_startup = now(CLOCK_MONOTONIC);
                log_full(arg_action == ACTION_TEST ? LOG_INFO : LOG_DEBUG,
                         "Loaded units and determined initial transaction in %s.",
                         format_timespan(timespan, sizeof(timespan), after_startup - before_startup, 100 * USEC_PER_MSEC));

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
                        log_emergency_errno(r, "Failed to run main loop: %m");
                        error_message = "Failed to run main loop";
                        goto finish;
                }

                switch (m->exit_code) {

                case MANAGER_RELOAD:
                        log_info("Reloading.");

                        r = parse_config_file();
                        if (r < 0)
                                log_error("Failed to parse config file.");

                        manager_set_defaults(m);

                        r = manager_reload(m);
                        if (r < 0)
                                log_error_errno(r, "Failed to reload: %m");
                        break;

                case MANAGER_REEXECUTE:

                        if (prepare_reexecute(m, &arg_serialization, &fds, false) < 0) {
                                error_message = "Failed to prepare for reexecution";
                                goto finish;
                        }

                        reexecute = true;
                        log_notice("Reexecuting.");
                        goto finish;

                case MANAGER_SWITCH_ROOT:
                        /* Steal the switch root parameters */
                        switch_root_dir = m->switch_root;
                        switch_root_init = m->switch_root_init;
                        m->switch_root = m->switch_root_init = NULL;

                        if (!switch_root_init)
                                if (prepare_reexecute(m, &arg_serialization, &fds, true) < 0) {
                                        error_message = "Failed to prepare for reexecution";
                                        goto finish;
                                }

                        reexecute = true;
                        log_notice("Switching root.");
                        goto finish;

                case MANAGER_EXIT:
                        retval = m->return_value;

                        if (MANAGER_IS_USER(m)) {
                                log_debug("Exit.");
                                goto finish;
                        }

                        /* fallthrough */
                case MANAGER_REBOOT:
                case MANAGER_POWEROFF:
                case MANAGER_HALT:
                case MANAGER_KEXEC: {
                        static const char * const table[_MANAGER_EXIT_CODE_MAX] = {
                                [MANAGER_EXIT] = "exit",
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
        pager_close();

        if (m)
                arg_shutdown_watchdog = m->shutdown_watchdog;

        m = manager_free(m);

        for (j = 0; j < ELEMENTSOF(arg_default_rlimit); j++)
                arg_default_rlimit[j] = mfree(arg_default_rlimit[j]);

        arg_default_unit = mfree(arg_default_unit);
        arg_join_controllers = strv_free_free(arg_join_controllers);
        arg_default_environment = strv_free(arg_default_environment);
        arg_syscall_archs = set_free(arg_syscall_archs);

        mac_selinux_finish();

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
                        (void) setrlimit(RLIMIT_NOFILE, &saved_rlimit_nofile);

                if (switch_root_dir) {
                        /* Kill all remaining processes from the
                         * initrd, but don't wait for them, so that we
                         * can handle the SIGCHLD for them after
                         * deserializing. */
                        broadcast_signal(SIGTERM, false, true);

                        /* And switch root with MS_MOVE, because we remove the old directory afterwards and detach it. */
                        r = switch_root(switch_root_dir, "/mnt", true, MS_MOVE);
                        if (r < 0)
                                log_error_errno(r, "Failed to switch root, trying to continue: %m");
                }

                /* Reopen the console */
                (void) make_console_stdio();

                args_size = MAX(6, argc+1);
                args = newa(const char*, args_size);

                if (!switch_root_init) {
                        char sfd[DECIMAL_STR_MAX(int) + 1];

                        /* First try to spawn ourselves with the right
                         * path, and with full serialization. We do
                         * this only if the user didn't specify an
                         * explicit init to spawn. */

                        assert(arg_serialization);
                        assert(fds);

                        xsprintf(sfd, "%i", fileno(arg_serialization));

                        i = 0;
                        args[i++] = SYSTEMD_BINARY_PATH;
                        if (switch_root_dir)
                                args[i++] = "--switched-root";
                        args[i++] = arg_system ? "--system" : "--user";
                        args[i++] = "--deserialize";
                        args[i++] = sfd;
                        args[i++] = NULL;

                        assert(i <= args_size);

                        /*
                         * We want valgrind to print its memory usage summary before reexecution.
                         * Valgrind won't do this is on its own on exec(), but it will do it on exit().
                         * Hence, to ensure we get a summary here, fork() off a child, let it exit() cleanly,
                         * so that it prints the summary, and wait() for it in the parent, before proceeding into the exec().
                         */
                        valgrind_summary_hack();

                        (void) execv(args[0], (char* const*) args);
                }

                /* Try the fallback, if there is any, without any
                 * serialization. We pass the original argv[] and
                 * envp[]. (Well, modulo the ordering changes due to
                 * getopt() in argv[], and some cleanups in envp[],
                 * but let's hope that doesn't matter.) */

                arg_serialization = safe_fclose(arg_serialization);
                fds = fdset_free(fds);

                for (j = 1, i = 1; j < (unsigned) argc; j++)
                        args[i++] = argv[j];
                args[i++] = NULL;
                assert(i <= args_size);

                /* Reenable any blocked signals, especially important
                 * if we switch from initial ramdisk to init=... */
                (void) reset_all_signal_handlers();
                (void) reset_signal_mask();

                if (switch_root_init) {
                        args[0] = switch_root_init;
                        (void) execv(args[0], (char* const*) args);
                        log_warning_errno(errno, "Failed to execute configured init, trying fallback: %m");
                }

                args[0] = "/sbin/init";
                (void) execv(args[0], (char* const*) args);

                if (errno == ENOENT) {
                        log_warning("No /sbin/init, trying fallback");

                        args[0] = "/bin/sh";
                        args[1] = NULL;
                        (void) execv(args[0], (char* const*) args);
                        log_error_errno(errno, "Failed to execute /bin/sh, giving up: %m");
                } else
                        log_warning_errno(errno, "Failed to execute /sbin/init, giving up: %m");
        }

        arg_serialization = safe_fclose(arg_serialization);
        fds = fdset_free(fds);

#ifdef HAVE_VALGRIND_VALGRIND_H
        /* If we are PID 1 and running under valgrind, then let's exit
         * here explicitly. valgrind will only generate nice output on
         * exit(), not on exec(), hence let's do the former not the
         * latter here. */
        if (getpid() == 1 && RUNNING_ON_VALGRIND)
                return 0;
#endif

        if (shutdown_verb) {
                char log_level[DECIMAL_STR_MAX(int) + 1];
                char exit_code[DECIMAL_STR_MAX(uint8_t) + 1];
                const char* command_line[11] = {
                        SYSTEMD_SHUTDOWN_BINARY_PATH,
                        shutdown_verb,
                        "--log-level", log_level,
                        "--log-target",
                };
                unsigned pos = 5;
                _cleanup_strv_free_ char **env_block = NULL;

                assert(command_line[pos] == NULL);
                env_block = strv_copy(environ);

                xsprintf(log_level, "%d", log_get_max_level());

                switch (log_get_target()) {

                case LOG_TARGET_KMSG:
                case LOG_TARGET_JOURNAL_OR_KMSG:
                case LOG_TARGET_SYSLOG_OR_KMSG:
                        command_line[pos++] = "kmsg";
                        break;

                case LOG_TARGET_NULL:
                        command_line[pos++] = "null";
                        break;

                case LOG_TARGET_CONSOLE:
                default:
                        command_line[pos++] = "console";
                        break;
                };

                if (log_get_show_color())
                        command_line[pos++] = "--log-color";

                if (log_get_show_location())
                        command_line[pos++] = "--log-location";

                if (streq(shutdown_verb, "exit")) {
                        command_line[pos++] = "--exit-code";
                        command_line[pos++] = exit_code;
                        xsprintf(exit_code, "%d", retval);
                }

                assert(pos < ELEMENTSOF(command_line));

                if (arm_reboot_watchdog && arg_shutdown_watchdog > 0 && arg_shutdown_watchdog != USEC_INFINITY) {
                        char *e;

                        /* If we reboot let's set the shutdown
                         * watchdog and tell the shutdown binary to
                         * repeatedly ping it */
                        r = watchdog_set_timeout(&arg_shutdown_watchdog);
                        watchdog_close(r < 0);

                        /* Tell the binary how often to ping, ignore failure */
                        if (asprintf(&e, "WATCHDOG_USEC="USEC_FMT, arg_shutdown_watchdog) > 0)
                                (void) strv_push(&env_block, e);
                } else
                        watchdog_close(true);

                /* Avoid the creation of new processes forked by the
                 * kernel; at this point, we will not listen to the
                 * signals anyway */
                if (detect_container() <= 0)
                        (void) cg_uninstall_release_agent(SYSTEMD_CGROUP_CONTROLLER);

                execve(SYSTEMD_SHUTDOWN_BINARY_PATH, (char **) command_line, env_block);
                log_error_errno(errno, "Failed to execute shutdown binary, %s: %m",
                          getpid() == 1 ? "freezing" : "quitting");
        }

        if (getpid() == 1) {
                if (error_message)
                        manager_status_printf(NULL, STATUS_TYPE_EMERGENCY,
                                              ANSI_HIGHLIGHT_RED "!!!!!!" ANSI_NORMAL,
                                              "%s, freezing.", error_message);
                freeze_or_reboot();
        }

        return retval;
}
