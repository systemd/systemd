/* SPDX-License-Identifier: LGPL-2.1+ */

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
#if HAVE_SECCOMP
#include <seccomp.h>
#endif
#if HAVE_VALGRIND_VALGRIND_H
#include <valgrind/valgrind.h>
#endif

#include "sd-bus.h"
#include "sd-daemon.h"
#include "sd-messages.h"

#include "alloc-util.h"
#include "architecture.h"
#include "build.h"
#include "bus-error.h"
#include "bus-util.h"
#include "capability-util.h"
#include "cgroup-util.h"
#include "clock-util.h"
#include "conf-parser.h"
#include "cpu-set-util.h"
#include "dbus.h"
#include "dbus-manager.h"
#include "def.h"
#include "emergency-action.h"
#include "env-util.h"
#include "exit-status.h"
#include "fd-util.h"
#include "fdset.h"
#include "fileio.h"
#include "format-util.h"
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
#include "os-util.h"
#include "pager.h"
#include "parse-util.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "raw-clone.h"
#include "rlimit-util.h"
#if HAVE_SECCOMP
#include "seccomp-util.h"
#endif
#include "selinux-setup.h"
#include "selinux-util.h"
#include "signal-util.h"
#include "smack-setup.h"
#include "special.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "strv.h"
#include "switch-root.h"
#include "sysctl-util.h"
#include "terminal-util.h"
#include "umask-util.h"
#include "user-util.h"
#include "util.h"
#include "virt.h"
#include "watchdog.h"

static enum {
        ACTION_RUN,
        ACTION_HELP,
        ACTION_VERSION,
        ACTION_TEST,
        ACTION_DUMP_CONFIGURATION_ITEMS,
        ACTION_DUMP_BUS_PROPERTIES,
} arg_action = ACTION_RUN;
static char *arg_default_unit = NULL;
static bool arg_system = false;
static bool arg_dump_core = true;
static int arg_crash_chvt = -1;
static bool arg_crash_shell = false;
static bool arg_crash_reboot = false;
static char *arg_confirm_spawn = NULL;
static ShowStatus arg_show_status = _SHOW_STATUS_INVALID;
static bool arg_switched_root = false;
static PagerFlags arg_pager_flags = 0;
static bool arg_service_watchdogs = true;
static ExecOutput arg_default_std_output = EXEC_OUTPUT_JOURNAL;
static ExecOutput arg_default_std_error = EXEC_OUTPUT_INHERIT;
static usec_t arg_default_restart_usec = DEFAULT_RESTART_USEC;
static usec_t arg_default_timeout_start_usec = DEFAULT_TIMEOUT_USEC;
static usec_t arg_default_timeout_stop_usec = DEFAULT_TIMEOUT_USEC;
static usec_t arg_default_start_limit_interval = DEFAULT_START_LIMIT_INTERVAL;
static unsigned arg_default_start_limit_burst = DEFAULT_START_LIMIT_BURST;
static usec_t arg_runtime_watchdog = 0;
static usec_t arg_shutdown_watchdog = 10 * USEC_PER_MINUTE;
static char *arg_early_core_pattern = NULL;
static char *arg_watchdog_device = NULL;
static char **arg_default_environment = NULL;
static struct rlimit *arg_default_rlimit[_RLIMIT_MAX] = {};
static uint64_t arg_capability_bounding_set = CAP_ALL;
static bool arg_no_new_privs = false;
static nsec_t arg_timer_slack_nsec = NSEC_INFINITY;
static usec_t arg_default_timer_accuracy_usec = 1 * USEC_PER_MINUTE;
static Set* arg_syscall_archs = NULL;
static FILE* arg_serialization = NULL;
static int arg_default_cpu_accounting = -1;
static bool arg_default_io_accounting = false;
static bool arg_default_ip_accounting = false;
static bool arg_default_blockio_accounting = false;
static bool arg_default_memory_accounting = MEMORY_ACCOUNTING_DEFAULT;
static bool arg_default_tasks_accounting = true;
static uint64_t arg_default_tasks_max = UINT64_MAX;
static sd_id128_t arg_machine_id = {};
static EmergencyAction arg_cad_burst_action = EMERGENCY_ACTION_REBOOT_FORCE;

_noreturn_ static void freeze_or_reboot(void) {

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

_noreturn_ static void crash(int sig) {
        struct sigaction sa;
        pid_t pid;

        if (getpid_cached() != 1)
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
                                                    ? exit_status_to_string(status.si_status, EXIT_STATUS_MINIMAL)
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

static int parse_confirm_spawn(const char *value, char **console) {
        char *s;
        int r;

        r = value ? parse_boolean(value) : 1;
        if (r == 0) {
                *console = NULL;
                return 0;
        }

        if (r > 0) /* on with default tty */
                s = strdup("/dev/console");
        else if (is_path(value)) /* on with fully qualified path */
                s = strdup(value);
        else /* on with only a tty file name, not a fully qualified path */
                s = strjoin("/dev/", value);
        if (!s)
                return -ENOMEM;

        *console = s;
        return 0;
}

static int set_machine_id(const char *m) {
        sd_id128_t t;
        assert(m);

        if (sd_id128_from_string(m, &t) < 0)
                return -EINVAL;

        if (sd_id128_is_null(t))
                return -EINVAL;

        arg_machine_id = t;
        return 0;
}

static int parse_proc_cmdline_item(const char *key, const char *value, void *data) {

        int r;

        assert(key);

        if (STR_IN_SET(key, "systemd.unit", "rd.systemd.unit")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                if (!unit_name_is_valid(value, UNIT_NAME_PLAIN|UNIT_NAME_INSTANCE))
                        log_warning("Unit name specified on %s= is not valid, ignoring: %s", key, value);
                else if (in_initrd() == !!startswith(key, "rd.")) {
                        if (free_and_strdup(&arg_default_unit, value) < 0)
                                return log_oom();
                }

        } else if (proc_cmdline_key_streq(key, "systemd.dump_core")) {

                r = value ? parse_boolean(value) : true;
                if (r < 0)
                        log_warning_errno(r, "Failed to parse dump core switch %s, ignoring: %m", value);
                else
                        arg_dump_core = r;

        } else if (proc_cmdline_key_streq(key, "systemd.early_core_pattern")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                if (path_is_absolute(value))
                        (void) parse_path_argument_and_warn(value, false, &arg_early_core_pattern);
                else
                        log_warning("Specified core pattern '%s' is not an absolute path, ignoring.", value);

        } else if (proc_cmdline_key_streq(key, "systemd.crash_chvt")) {

                if (!value)
                        arg_crash_chvt = 0; /* turn on */
                else {
                        r = parse_crash_chvt(value);
                        if (r < 0)
                                log_warning_errno(r, "Failed to parse crash chvt switch %s, ignoring: %m", value);
                }

        } else if (proc_cmdline_key_streq(key, "systemd.crash_shell")) {

                r = value ? parse_boolean(value) : true;
                if (r < 0)
                        log_warning_errno(r, "Failed to parse crash shell switch %s, ignoring: %m", value);
                else
                        arg_crash_shell = r;

        } else if (proc_cmdline_key_streq(key, "systemd.crash_reboot")) {

                r = value ? parse_boolean(value) : true;
                if (r < 0)
                        log_warning_errno(r, "Failed to parse crash reboot switch %s, ignoring: %m", value);
                else
                        arg_crash_reboot = r;

        } else if (proc_cmdline_key_streq(key, "systemd.confirm_spawn")) {
                char *s;

                r = parse_confirm_spawn(value, &s);
                if (r < 0)
                        log_warning_errno(r, "Failed to parse confirm_spawn switch %s, ignoring: %m", value);
                else
                        free_and_replace(arg_confirm_spawn, s);

        } else if (proc_cmdline_key_streq(key, "systemd.service_watchdogs")) {

                r = value ? parse_boolean(value) : true;
                if (r < 0)
                        log_warning_errno(r, "Failed to parse service watchdog switch %s, ignoring: %m", value);
                else
                        arg_service_watchdogs = r;

        } else if (proc_cmdline_key_streq(key, "systemd.show_status")) {

                if (value) {
                        r = parse_show_status(value, &arg_show_status);
                        if (r < 0)
                                log_warning_errno(r, "Failed to parse show status switch %s, ignoring: %m", value);
                } else
                        arg_show_status = SHOW_STATUS_YES;

        } else if (proc_cmdline_key_streq(key, "systemd.default_standard_output")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = exec_output_from_string(value);
                if (r < 0)
                        log_warning_errno(r, "Failed to parse default standard output switch %s, ignoring: %m", value);
                else
                        arg_default_std_output = r;

        } else if (proc_cmdline_key_streq(key, "systemd.default_standard_error")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = exec_output_from_string(value);
                if (r < 0)
                        log_warning_errno(r, "Failed to parse default standard error switch %s, ignoring: %m", value);
                else
                        arg_default_std_error = r;

        } else if (streq(key, "systemd.setenv")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                if (env_assignment_is_valid(value)) {
                        char **env;

                        env = strv_env_set(arg_default_environment, value);
                        if (!env)
                                return log_oom();

                        arg_default_environment = env;
                } else
                        log_warning("Environment variable name '%s' is not valid. Ignoring.", value);

        } else if (proc_cmdline_key_streq(key, "systemd.machine_id")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = set_machine_id(value);
                if (r < 0)
                        log_warning_errno(r, "MachineID '%s' is not valid, ignoring: %m", value);

        } else if (proc_cmdline_key_streq(key, "systemd.default_timeout_start_sec")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = parse_sec(value, &arg_default_timeout_start_usec);
                if (r < 0)
                        log_warning_errno(r, "Failed to parse default start timeout '%s', ignoring: %m", value);

                if (arg_default_timeout_start_usec <= 0)
                        arg_default_timeout_start_usec = USEC_INFINITY;

        } else if (proc_cmdline_key_streq(key, "systemd.watchdog_device")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                (void) parse_path_argument_and_warn(value, false, &arg_watchdog_device);

        } else if (streq(key, "quiet") && !value) {

                if (arg_show_status == _SHOW_STATUS_INVALID)
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

DEFINE_SETTER(config_parse_level2, log_set_max_level_from_string, "log level");
DEFINE_SETTER(config_parse_target, log_set_target_from_string, "target");
DEFINE_SETTER(config_parse_color, log_show_color_from_string, "color" );
DEFINE_SETTER(config_parse_location, log_show_location_from_string, "location");

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
                log_warning_errno(errno, "Failed to set CPU affinity: %m");

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

static int config_parse_output_restricted(
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

        ExecOutput t, *eo = data;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        t = exec_output_from_string(rvalue);
        if (t < 0) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse output type, ignoring: %s", rvalue);
                return 0;
        }

        if (IN_SET(t, EXEC_OUTPUT_SOCKET, EXEC_OUTPUT_NAMED_FD, EXEC_OUTPUT_FILE, EXEC_OUTPUT_FILE_APPEND)) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Standard output types socket, fd:, file:, append: are not supported as defaults, ignoring: %s", rvalue);
                return 0;
        }

        *eo = t;
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
                { "Manager", "JoinControllers",           config_parse_warn_compat,      DISABLED_CONFIGURATION, NULL              },
                { "Manager", "RuntimeWatchdogSec",        config_parse_sec,              0, &arg_runtime_watchdog                  },
                { "Manager", "ShutdownWatchdogSec",       config_parse_sec,              0, &arg_shutdown_watchdog                 },
                { "Manager", "WatchdogDevice",            config_parse_path,             0, &arg_watchdog_device                   },
                { "Manager", "CapabilityBoundingSet",     config_parse_capability_set,   0, &arg_capability_bounding_set           },
                { "Manager", "NoNewPrivileges",           config_parse_bool,             0, &arg_no_new_privs                      },
#if HAVE_SECCOMP
                { "Manager", "SystemCallArchitectures",   config_parse_syscall_archs,    0, &arg_syscall_archs                     },
#endif
                { "Manager", "TimerSlackNSec",            config_parse_nsec,             0, &arg_timer_slack_nsec                  },
                { "Manager", "DefaultTimerAccuracySec",   config_parse_sec,              0, &arg_default_timer_accuracy_usec       },
                { "Manager", "DefaultStandardOutput",     config_parse_output_restricted,0, &arg_default_std_output                },
                { "Manager", "DefaultStandardError",      config_parse_output_restricted,0, &arg_default_std_error                 },
                { "Manager", "DefaultTimeoutStartSec",    config_parse_sec,              0, &arg_default_timeout_start_usec        },
                { "Manager", "DefaultTimeoutStopSec",     config_parse_sec,              0, &arg_default_timeout_stop_usec         },
                { "Manager", "DefaultRestartSec",         config_parse_sec,              0, &arg_default_restart_usec              },
                { "Manager", "DefaultStartLimitInterval", config_parse_sec,              0, &arg_default_start_limit_interval      }, /* obsolete alias */
                { "Manager", "DefaultStartLimitIntervalSec",config_parse_sec,            0, &arg_default_start_limit_interval      },
                { "Manager", "DefaultStartLimitBurst",    config_parse_unsigned,         0, &arg_default_start_limit_burst         },
                { "Manager", "DefaultEnvironment",        config_parse_environ,          0, &arg_default_environment               },
                { "Manager", "DefaultLimitCPU",           config_parse_rlimit,           RLIMIT_CPU, arg_default_rlimit            },
                { "Manager", "DefaultLimitFSIZE",         config_parse_rlimit,           RLIMIT_FSIZE, arg_default_rlimit          },
                { "Manager", "DefaultLimitDATA",          config_parse_rlimit,           RLIMIT_DATA, arg_default_rlimit           },
                { "Manager", "DefaultLimitSTACK",         config_parse_rlimit,           RLIMIT_STACK, arg_default_rlimit          },
                { "Manager", "DefaultLimitCORE",          config_parse_rlimit,           RLIMIT_CORE, arg_default_rlimit           },
                { "Manager", "DefaultLimitRSS",           config_parse_rlimit,           RLIMIT_RSS, arg_default_rlimit            },
                { "Manager", "DefaultLimitNOFILE",        config_parse_rlimit,           RLIMIT_NOFILE, arg_default_rlimit         },
                { "Manager", "DefaultLimitAS",            config_parse_rlimit,           RLIMIT_AS, arg_default_rlimit             },
                { "Manager", "DefaultLimitNPROC",         config_parse_rlimit,           RLIMIT_NPROC, arg_default_rlimit          },
                { "Manager", "DefaultLimitMEMLOCK",       config_parse_rlimit,           RLIMIT_MEMLOCK, arg_default_rlimit        },
                { "Manager", "DefaultLimitLOCKS",         config_parse_rlimit,           RLIMIT_LOCKS, arg_default_rlimit          },
                { "Manager", "DefaultLimitSIGPENDING",    config_parse_rlimit,           RLIMIT_SIGPENDING, arg_default_rlimit     },
                { "Manager", "DefaultLimitMSGQUEUE",      config_parse_rlimit,           RLIMIT_MSGQUEUE, arg_default_rlimit       },
                { "Manager", "DefaultLimitNICE",          config_parse_rlimit,           RLIMIT_NICE, arg_default_rlimit           },
                { "Manager", "DefaultLimitRTPRIO",        config_parse_rlimit,           RLIMIT_RTPRIO, arg_default_rlimit         },
                { "Manager", "DefaultLimitRTTIME",        config_parse_rlimit,           RLIMIT_RTTIME, arg_default_rlimit         },
                { "Manager", "DefaultCPUAccounting",      config_parse_tristate,         0, &arg_default_cpu_accounting            },
                { "Manager", "DefaultIOAccounting",       config_parse_bool,             0, &arg_default_io_accounting             },
                { "Manager", "DefaultIPAccounting",       config_parse_bool,             0, &arg_default_ip_accounting             },
                { "Manager", "DefaultBlockIOAccounting",  config_parse_bool,             0, &arg_default_blockio_accounting        },
                { "Manager", "DefaultMemoryAccounting",   config_parse_bool,             0, &arg_default_memory_accounting         },
                { "Manager", "DefaultTasksAccounting",    config_parse_bool,             0, &arg_default_tasks_accounting          },
                { "Manager", "DefaultTasksMax",           config_parse_tasks_max,        0, &arg_default_tasks_max                 },
                { "Manager", "CtrlAltDelBurstAction",     config_parse_emergency_action, 0, &arg_cad_burst_action                  },
                {}
        };

        const char *fn, *conf_dirs_nulstr;

        fn = arg_system ?
                PKGSYSCONFDIR "/system.conf" :
                PKGSYSCONFDIR "/user.conf";

        conf_dirs_nulstr = arg_system ?
                CONF_PATHS_NULSTR("systemd/system.conf.d") :
                CONF_PATHS_NULSTR("systemd/user.conf.d");

        (void) config_parse_many_nulstr(fn, conf_dirs_nulstr, "Manager\0", config_item_table_lookup, items, CONFIG_PARSE_WARN, NULL);

        /* Traditionally "0" was used to turn off the default unit timeouts. Fix this up so that we used USEC_INFINITY
         * like everywhere else. */
        if (arg_default_timeout_start_usec <= 0)
                arg_default_timeout_start_usec = USEC_INFINITY;
        if (arg_default_timeout_stop_usec <= 0)
                arg_default_timeout_stop_usec = USEC_INFINITY;

        return 0;
}

static void set_manager_defaults(Manager *m) {

        assert(m);

        /* Propagates the various default unit property settings into the manager object, i.e. properties that do not
         * affect the manager itself, but are just what newly allocated units will have set if they haven't set
         * anything else. (Also see set_manager_settings() for the settings that affect the manager's own behaviour) */

        m->default_timer_accuracy_usec = arg_default_timer_accuracy_usec;
        m->default_std_output = arg_default_std_output;
        m->default_std_error = arg_default_std_error;
        m->default_timeout_start_usec = arg_default_timeout_start_usec;
        m->default_timeout_stop_usec = arg_default_timeout_stop_usec;
        m->default_restart_usec = arg_default_restart_usec;
        m->default_start_limit_interval = arg_default_start_limit_interval;
        m->default_start_limit_burst = arg_default_start_limit_burst;

        /* On 4.15+ with unified hierarchy, CPU accounting is essentially free as it doesn't require the CPU
         * controller to be enabled, so the default is to enable it unless we got told otherwise. */
        if (arg_default_cpu_accounting >= 0)
                m->default_cpu_accounting = arg_default_cpu_accounting;
        else
                m->default_cpu_accounting = cpu_accounting_is_cheap();

        m->default_io_accounting = arg_default_io_accounting;
        m->default_ip_accounting = arg_default_ip_accounting;
        m->default_blockio_accounting = arg_default_blockio_accounting;
        m->default_memory_accounting = arg_default_memory_accounting;
        m->default_tasks_accounting = arg_default_tasks_accounting;
        m->default_tasks_max = arg_default_tasks_max;

        (void) manager_set_default_rlimits(m, arg_default_rlimit);

        (void) manager_default_environment(m);
        (void) manager_transient_environment_add(m, arg_default_environment);
}

static void set_manager_settings(Manager *m) {

        assert(m);

        /* Propagates the various manager settings into the manager object, i.e. properties that effect the manager
         * itself (as opposed to just being inherited into newly allocated units, see set_manager_defaults() above). */

        m->confirm_spawn = arg_confirm_spawn;
        m->service_watchdogs = arg_service_watchdogs;
        m->runtime_watchdog = arg_runtime_watchdog;
        m->shutdown_watchdog = arg_shutdown_watchdog;
        m->cad_burst_action = arg_cad_burst_action;

        manager_set_show_status(m, arg_show_status);
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
                ARG_DUMP_BUS_PROPERTIES,
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
                ARG_MACHINE_ID,
                ARG_SERVICE_WATCHDOGS,
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
                { "dump-bus-properties",      no_argument,       NULL, ARG_DUMP_BUS_PROPERTIES      },
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
                { "service-watchdogs",        required_argument, NULL, ARG_SERVICE_WATCHDOGS        },
                {}
        };

        int c, r;

        assert(argc >= 1);
        assert(argv);

        if (getpid_cached() == 1)
                opterr = 0;

        while ((c = getopt_long(argc, argv, "hDbsz:", options, NULL)) >= 0)

                switch (c) {

                case ARG_LOG_LEVEL:
                        r = log_set_max_level_from_string(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse log level \"%s\": %m", optarg);

                        break;

                case ARG_LOG_TARGET:
                        r = log_set_target_from_string(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse log target \"%s\": %m", optarg);

                        break;

                case ARG_LOG_COLOR:

                        if (optarg) {
                                r = log_show_color_from_string(optarg);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse log color setting \"%s\": %m",
                                                               optarg);
                        } else
                                log_show_color(true);

                        break;

                case ARG_LOG_LOCATION:
                        if (optarg) {
                                r = log_show_location_from_string(optarg);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse log location setting \"%s\": %m",
                                                               optarg);
                        } else
                                log_show_location(true);

                        break;

                case ARG_DEFAULT_STD_OUTPUT:
                        r = exec_output_from_string(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse default standard output setting \"%s\": %m",
                                                       optarg);
                        arg_default_std_output = r;
                        break;

                case ARG_DEFAULT_STD_ERROR:
                        r = exec_output_from_string(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse default standard error output setting \"%s\": %m",
                                                       optarg);
                        arg_default_std_error = r;
                        break;

                case ARG_UNIT:
                        r = free_and_strdup(&arg_default_unit, optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set default unit \"%s\": %m", optarg);

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
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_VERSION:
                        arg_action = ACTION_VERSION;
                        break;

                case ARG_DUMP_CONFIGURATION_ITEMS:
                        arg_action = ACTION_DUMP_CONFIGURATION_ITEMS;
                        break;

                case ARG_DUMP_BUS_PROPERTIES:
                        arg_action = ACTION_DUMP_BUS_PROPERTIES;
                        break;

                case ARG_DUMP_CORE:
                        if (!optarg)
                                arg_dump_core = true;
                        else {
                                r = parse_boolean(optarg);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse dump core boolean: \"%s\": %m",
                                                               optarg);
                                arg_dump_core = r;
                        }
                        break;

                case ARG_CRASH_CHVT:
                        r = parse_crash_chvt(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse crash virtual terminal index: \"%s\": %m",
                                                       optarg);
                        break;

                case ARG_CRASH_SHELL:
                        if (!optarg)
                                arg_crash_shell = true;
                        else {
                                r = parse_boolean(optarg);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse crash shell boolean: \"%s\": %m",
                                                               optarg);
                                arg_crash_shell = r;
                        }
                        break;

                case ARG_CRASH_REBOOT:
                        if (!optarg)
                                arg_crash_reboot = true;
                        else {
                                r = parse_boolean(optarg);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse crash shell boolean: \"%s\": %m",
                                                               optarg);
                                arg_crash_reboot = r;
                        }
                        break;

                case ARG_CONFIRM_SPAWN:
                        arg_confirm_spawn = mfree(arg_confirm_spawn);

                        r = parse_confirm_spawn(optarg, &arg_confirm_spawn);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse confirm spawn option: \"%s\": %m",
                                                       optarg);
                        break;

                case ARG_SERVICE_WATCHDOGS:
                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse service watchdogs boolean: \"%s\": %m",
                                                       optarg);
                        arg_service_watchdogs = r;
                        break;

                case ARG_SHOW_STATUS:
                        if (optarg) {
                                r = parse_show_status(optarg, &arg_show_status);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse show status boolean: \"%s\": %m",
                                                               optarg);
                        } else
                                arg_show_status = SHOW_STATUS_YES;
                        break;

                case ARG_DESERIALIZE: {
                        int fd;
                        FILE *f;

                        r = safe_atoi(optarg, &fd);
                        if (r < 0)
                                log_error_errno(r, "Failed to parse deserialize option \"%s\": %m", optarg);
                        if (fd < 0) {
                                log_error("Invalid deserialize fd: %d", fd);
                                return -EINVAL;
                        }

                        (void) fd_cloexec(fd, true);

                        f = fdopen(fd, "r");
                        if (!f)
                                return log_error_errno(errno, "Failed to open serialization fd %d: %m", fd);

                        safe_fclose(arg_serialization);
                        arg_serialization = f;

                        break;
                }

                case ARG_SWITCHED_ROOT:
                        arg_switched_root = true;
                        break;

                case ARG_MACHINE_ID:
                        r = set_machine_id(optarg);
                        if (r < 0)
                                return log_error_errno(r, "MachineID '%s' is not valid: %m", optarg);
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
                        if (getpid_cached() != 1)
                                return -EINVAL;
                        else
                                return 0;

                default:
                        assert_not_reached("Unhandled option code.");
                }

        if (optind < argc && getpid_cached() != 1) {
                /* Hmm, when we aren't run as init system
                 * let's complain about excess arguments */

                log_error("Excess arguments.");
                return -EINVAL;
        }

        return 0;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...]\n\n"
               "Starts up and maintains the system or user services.\n\n"
               "  -h --help                      Show this help\n"
               "     --version                   Show version\n"
               "     --test                      Determine startup sequence, dump it and exit\n"
               "     --no-pager                  Do not pipe output into a pager\n"
               "     --dump-configuration-items  Dump understood unit configuration items\n"
               "     --dump-bus-properties       Dump exposed bus properties\n"
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
               "     --default-standard-error=   Set default standard error output for services\n"
               "\nSee the %s for details.\n"
               , program_invocation_short_name
               , link
        );

        return 0;
}

static int prepare_reexecute(
                Manager *m,
                FILE **ret_f,
                FDSet **ret_fds,
                bool switching_root) {

        _cleanup_fdset_free_ FDSet *fds = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(m);
        assert(ret_f);
        assert(ret_fds);

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
                return r;

        if (fseeko(f, 0, SEEK_SET) == (off_t) -1)
                return log_error_errno(errno, "Failed to rewind serialization fd: %m");

        r = fd_cloexec(fileno(f), false);
        if (r < 0)
                return log_error_errno(r, "Failed to disable O_CLOEXEC for serialization: %m");

        r = fdset_cloexec(fds, false);
        if (r < 0)
                return log_error_errno(r, "Failed to disable O_CLOEXEC for serialization fds: %m");

        *ret_f = TAKE_PTR(f);
        *ret_fds = TAKE_PTR(fds);

        return 0;
}

static void bump_file_max_and_nr_open(void) {

        /* Let's bump fs.file-max and fs.nr_open to their respective maximums. On current kernels large numbers of file
         * descriptors are no longer a performance problem and their memory is properly tracked by memcg, thus counting
         * them and limiting them in another two layers of limits is unnecessary and just complicates things. This
         * function hence turns off 2 of the 4 levels of limits on file descriptors, and makes RLIMIT_NOLIMIT (soft +
         * hard) the only ones that really matter. */

#if BUMP_PROC_SYS_FS_FILE_MAX || BUMP_PROC_SYS_FS_NR_OPEN
        _cleanup_free_ char *t = NULL;
        int r;
#endif

#if BUMP_PROC_SYS_FS_FILE_MAX
        /* I so wanted to use STRINGIFY(ULONG_MAX) here, but alas we can't as glibc/gcc define that as
         * "(0x7fffffffffffffffL * 2UL + 1UL)". Seriously. 😢 */
        if (asprintf(&t, "%lu\n", ULONG_MAX) < 0) {
                log_oom();
                return;
        }

        r = sysctl_write("fs/file-max", t);
        if (r < 0)
                log_full_errno(IN_SET(r, -EROFS, -EPERM, -EACCES) ? LOG_DEBUG : LOG_WARNING, r, "Failed to bump fs.file-max, ignoring: %m");
#endif

#if BUMP_PROC_SYS_FS_FILE_MAX && BUMP_PROC_SYS_FS_NR_OPEN
        t = mfree(t);
#endif

#if BUMP_PROC_SYS_FS_NR_OPEN
        int v = INT_MAX;

        /* Arg! The kernel enforces maximum and minimum values on the fs.nr_open, but we don't really know what they
         * are. The expression by which the maximum is determined is dependent on the architecture, and is something we
         * don't really want to copy to userspace, as it is dependent on implementation details of the kernel. Since
         * the kernel doesn't expose the maximum value to us, we can only try and hope. Hence, let's start with
         * INT_MAX, and then keep halving the value until we find one that works. Ugly? Yes, absolutely, but kernel
         * APIs are kernel APIs, so what do can we do... 🤯 */

        for (;;) {
                int k;

                v &= ~(__SIZEOF_POINTER__ - 1); /* Round down to next multiple of the pointer size */
                if (v < 1024) {
                        log_warning("Can't bump fs.nr_open, value too small.");
                        break;
                }

                k = read_nr_open();
                if (k < 0) {
                        log_error_errno(k, "Failed to read fs.nr_open: %m");
                        break;
                }
                if (k >= v) { /* Already larger */
                        log_debug("Skipping bump, value is already larger.");
                        break;
                }

                if (asprintf(&t, "%i\n", v) < 0) {
                        log_oom();
                        return;
                }

                r = sysctl_write("fs/nr_open", t);
                t = mfree(t);
                if (r == -EINVAL) {
                        log_debug("Couldn't write fs.nr_open as %i, halving it.", v);
                        v /= 2;
                        continue;
                }
                if (r < 0) {
                        log_full_errno(IN_SET(r, -EROFS, -EPERM, -EACCES) ? LOG_DEBUG : LOG_WARNING, r, "Failed to bump fs.nr_open, ignoring: %m");
                        break;
                }

                log_debug("Successfully bumped fs.nr_open to %i", v);
                break;
        }
#endif
}

static int bump_rlimit_nofile(struct rlimit *saved_rlimit) {
        int r, nr;

        assert(saved_rlimit);

        /* Save the original RLIMIT_NOFILE so that we can reset it later when transitioning from the initrd to the main
         * systemd or suchlike. */
        if (getrlimit(RLIMIT_NOFILE, saved_rlimit) < 0)
                return log_warning_errno(errno, "Reading RLIMIT_NOFILE failed, ignoring: %m");

        /* Get the underlying absolute limit the kernel enforces */
        nr = read_nr_open();

        /* Make sure forked processes get limits based on the original kernel setting */
        if (!arg_default_rlimit[RLIMIT_NOFILE]) {
                struct rlimit *rl;

                rl = newdup(struct rlimit, saved_rlimit, 1);
                if (!rl)
                        return log_oom();

                /* Bump the hard limit for system services to a substantially higher value. The default hard limit
                 * current kernels set is pretty low (4K), mostly for historical reasons. According to kernel
                 * developers, the fd handling in recent kernels has been optimized substantially enough, so that we
                 * can bump the limit now, without paying too high a price in memory or performance. Note however that
                 * we only bump the hard limit, not the soft limit. That's because select() works the way it works, and
                 * chokes on fds >= 1024. If we'd bump the soft limit globally, it might accidentally happen to
                 * unexpecting programs that they get fds higher than what they can process using select(). By only
                 * bumping the hard limit but leaving the low limit as it is we avoid this pitfall: programs that are
                 * written by folks aware of the select() problem in mind (and thus use poll()/epoll instead of
                 * select(), the way everybody should) can explicitly opt into high fds by bumping their soft limit
                 * beyond 1024, to the hard limit we pass. */
                if (arg_system)
                        rl->rlim_max = MIN((rlim_t) nr, MAX(rl->rlim_max, (rlim_t) HIGH_RLIMIT_NOFILE));

                arg_default_rlimit[RLIMIT_NOFILE] = rl;
        }

        /* Bump up the resource limit for ourselves substantially, all the way to the maximum the kernel allows, for
         * both hard and soft. */
        r = setrlimit_closest(RLIMIT_NOFILE, &RLIMIT_MAKE_CONST(nr));
        if (r < 0)
                return log_warning_errno(r, "Setting RLIMIT_NOFILE failed, ignoring: %m");

        return 0;
}

static int bump_rlimit_memlock(struct rlimit *saved_rlimit) {
        int r;

        assert(saved_rlimit);

        /* BPF_MAP_TYPE_LPM_TRIE bpf maps are charged against RLIMIT_MEMLOCK, even if we have CAP_IPC_LOCK which should
         * normally disable such checks. We need them to implement IPAccessAllow= and IPAccessDeny=, hence let's bump
         * the value high enough for our user. */

        if (getrlimit(RLIMIT_MEMLOCK, saved_rlimit) < 0)
                return log_warning_errno(errno, "Reading RLIMIT_MEMLOCK failed, ignoring: %m");

        r = setrlimit_closest(RLIMIT_MEMLOCK, &RLIMIT_MAKE_CONST(HIGH_RLIMIT_MEMLOCK));
        if (r < 0)
                return log_warning_errno(r, "Setting RLIMIT_MEMLOCK failed, ignoring: %m");

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

static int enforce_syscall_archs(Set *archs) {
#if HAVE_SECCOMP
        int r;

        if (!is_seccomp_available())
                return 0;

        r = seccomp_restrict_archs(arg_syscall_archs);
        if (r < 0)
                return log_error_errno(r, "Failed to enforce system call architecture restrication: %m");
#endif
        return 0;
}

static int status_welcome(void) {
        _cleanup_free_ char *pretty_name = NULL, *ansi_color = NULL;
        int r;

        if (IN_SET(arg_show_status, SHOW_STATUS_NO, SHOW_STATUS_AUTO))
                return 0;

        r = parse_os_release(NULL,
                             "PRETTY_NAME", &pretty_name,
                             "ANSI_COLOR", &ansi_color,
                             NULL);
        if (r < 0)
                log_full_errno(r == -ENOENT ? LOG_DEBUG : LOG_WARNING, r,
                               "Failed to read os-release file, ignoring: %m");

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

        /* Let's bump the net.unix.max_dgram_qlen sysctl. The kernel default of 16 is simply too low. We set the value
         * really really early during boot, so that it is actually applied to all our sockets, including the
         * $NOTIFY_SOCKET one. */

        r = read_one_line_file("/proc/sys/net/unix/max_dgram_qlen", &qlen);
        if (r < 0)
                return log_full_errno(r == -ENOENT ? LOG_DEBUG : LOG_WARNING, r, "Failed to read AF_UNIX datagram queue length, ignoring: %m");

        r = safe_atolu(qlen, &v);
        if (r < 0)
                return log_warning_errno(r, "Failed to parse AF_UNIX datagram queue length '%s', ignoring: %m", qlen);

        if (v >= DEFAULT_UNIX_MAX_DGRAM_QLEN)
                return 0;

        r = write_string_filef("/proc/sys/net/unix/max_dgram_qlen", WRITE_STRING_FILE_DISABLE_BUFFER, "%lu", DEFAULT_UNIX_MAX_DGRAM_QLEN);
        if (r < 0)
                return log_full_errno(IN_SET(r, -EROFS, -EPERM, -EACCES) ? LOG_DEBUG : LOG_WARNING, r,
                                      "Failed to bump AF_UNIX datagram queue length, ignoring: %m");

        return 1;
}

static int fixup_environment(void) {
        _cleanup_free_ char *term = NULL;
        const char *t;
        int r;

        /* Only fix up the environment when we are started as PID 1 */
        if (getpid_cached() != 1)
                return 0;

        /* We expect the environment to be set correctly if run inside a container. */
        if (detect_container() > 0)
                return 0;

        /* When started as PID1, the kernel uses /dev/console for our stdios and uses TERM=linux whatever the backend
         * device used by the console. We try to make a better guess here since some consoles might not have support
         * for color mode for example.
         *
         * However if TERM was configured through the kernel command line then leave it alone. */
        r = proc_cmdline_get_key("TERM", 0, &term);
        if (r < 0)
                return r;

        t = term ?: default_term_for_tty("/dev/console");

        if (setenv("TERM", t, 1) < 0)
                return -errno;

        return 0;
}

static void redirect_telinit(int argc, char *argv[]) {

        /* This is compatibility support for SysV, where calling init as a user is identical to telinit. */

#if HAVE_SYSV_COMPAT
        if (getpid_cached() == 1)
                return;

        if (!strstr(program_invocation_short_name, "init"))
                return;

        execv(SYSTEMCTL_BINARY_PATH, argv);
        log_error_errno(errno, "Failed to exec " SYSTEMCTL_BINARY_PATH ": %m");
        exit(EXIT_FAILURE);
#endif
}

static int become_shutdown(
                const char *shutdown_verb,
                int retval) {

        char log_level[DECIMAL_STR_MAX(int) + 1],
                exit_code[DECIMAL_STR_MAX(uint8_t) + 1],
                timeout[DECIMAL_STR_MAX(usec_t) + 1];

        const char* command_line[13] = {
                SYSTEMD_SHUTDOWN_BINARY_PATH,
                shutdown_verb,
                "--timeout", timeout,
                "--log-level", log_level,
                "--log-target",
        };

        _cleanup_strv_free_ char **env_block = NULL;
        size_t pos = 7;
        int r;

        assert(shutdown_verb);
        assert(!command_line[pos]);
        env_block = strv_copy(environ);

        xsprintf(log_level, "%d", log_get_max_level());
        xsprintf(timeout, "%" PRI_USEC "us", arg_default_timeout_stop_usec);

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

        if (streq(shutdown_verb, "reboot") &&
            arg_shutdown_watchdog > 0 &&
            arg_shutdown_watchdog != USEC_INFINITY) {

                char *e;

                /* If we reboot let's set the shutdown
                 * watchdog and tell the shutdown binary to
                 * repeatedly ping it */
                r = watchdog_set_timeout(&arg_shutdown_watchdog);
                watchdog_close(r < 0);

                /* Tell the binary how often to ping, ignore failure */
                if (asprintf(&e, "WATCHDOG_USEC="USEC_FMT, arg_shutdown_watchdog) > 0)
                        (void) strv_consume(&env_block, e);

                if (arg_watchdog_device &&
                    asprintf(&e, "WATCHDOG_DEVICE=%s", arg_watchdog_device) > 0)
                        (void) strv_consume(&env_block, e);
        } else
                watchdog_close(true);

        /* Avoid the creation of new processes forked by the
         * kernel; at this point, we will not listen to the
         * signals anyway */
        if (detect_container() <= 0)
                (void) cg_uninstall_release_agent(SYSTEMD_CGROUP_CONTROLLER);

        execve(SYSTEMD_SHUTDOWN_BINARY_PATH, (char **) command_line, env_block);
        return -errno;
}

static void initialize_clock(void) {
        int r;

        if (clock_is_localtime(NULL) > 0) {
                int min;

                /*
                 * The very first call of settimeofday() also does a time warp in the kernel.
                 *
                 * In the rtc-in-local time mode, we set the kernel's timezone, and rely on external tools to take care
                 * of maintaining the RTC and do all adjustments.  This matches the behavior of Windows, which leaves
                 * the RTC alone if the registry tells that the RTC runs in UTC.
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
                 * Do not call this from inside the initrd. The initrd might not carry /etc/adjtime with LOCAL, but the
                 * real system could be set up that way. In such case, we need to delay the time-warp or the sealing
                 * until we reach the real system.
                 *
                 * Do no set the kernel's timezone. The concept of local time cannot be supported reliably, the time
                 * will jump or be incorrect at every daylight saving time change. All kernel local time concepts will
                 * be treated as UTC that way.
                 */
                (void) clock_reset_timewarp();
        }

        r = clock_apply_epoch();
        if (r < 0)
                log_error_errno(r, "Current system time is before build time, but cannot correct: %m");
        else if (r > 0)
                log_info("System time before build time, advancing clock.");
}

static void initialize_coredump(bool skip_setup) {
#if ENABLE_COREDUMP
        if (getpid_cached() != 1)
                return;

        /* Don't limit the core dump size, so that coredump handlers such as systemd-coredump (which honour the limit)
         * will process core dumps for system services by default. */
        if (setrlimit(RLIMIT_CORE, &RLIMIT_MAKE_CONST(RLIM_INFINITY)) < 0)
                log_warning_errno(errno, "Failed to set RLIMIT_CORE: %m");

        /* But at the same time, turn off the core_pattern logic by default, so that no
         * coredumps are stored until the systemd-coredump tool is enabled via
         * sysctl. However it can be changed via the kernel command line later so core
         * dumps can still be generated during early startup and in initramfs. */
        if (!skip_setup)
                disable_coredumps();
#endif
}

static void initialize_core_pattern(bool skip_setup) {
        int r;

        if (skip_setup || !arg_early_core_pattern)
                return;

        if (getpid_cached() != 1)
                return;

        r = write_string_file("/proc/sys/kernel/core_pattern", arg_early_core_pattern, WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                log_warning_errno(r, "Failed to write '%s' to /proc/sys/kernel/core_pattern, ignoring: %m", arg_early_core_pattern);
}

static void do_reexecute(
                int argc,
                char *argv[],
                const struct rlimit *saved_rlimit_nofile,
                const struct rlimit *saved_rlimit_memlock,
                FDSet *fds,
                const char *switch_root_dir,
                const char *switch_root_init,
                const char **ret_error_message) {

        unsigned i, j, args_size;
        const char **args;
        int r;

        assert(saved_rlimit_nofile);
        assert(saved_rlimit_memlock);
        assert(ret_error_message);

        /* Close and disarm the watchdog, so that the new instance can reinitialize it, but doesn't get rebooted while
         * we do that */
        watchdog_close(true);

        /* Reset the RLIMIT_NOFILE to the kernel default, so that the new systemd can pass the kernel default to its
         * child processes */

        if (saved_rlimit_nofile->rlim_cur > 0)
                (void) setrlimit(RLIMIT_NOFILE, saved_rlimit_nofile);
        if (saved_rlimit_memlock->rlim_cur != (rlim_t) -1)
                (void) setrlimit(RLIMIT_MEMLOCK, saved_rlimit_memlock);

        if (switch_root_dir) {
                /* Kill all remaining processes from the initrd, but don't wait for them, so that we can handle the
                 * SIGCHLD for them after deserializing. */
                broadcast_signal(SIGTERM, false, true, arg_default_timeout_stop_usec);

                /* And switch root with MS_MOVE, because we remove the old directory afterwards and detach it. */
                r = switch_root(switch_root_dir, "/mnt", true, MS_MOVE);
                if (r < 0)
                        log_error_errno(r, "Failed to switch root, trying to continue: %m");
        }

        args_size = MAX(6, argc+1);
        args = newa(const char*, args_size);

        if (!switch_root_init) {
                char sfd[DECIMAL_STR_MAX(int) + 1];

                /* First try to spawn ourselves with the right path, and with full serialization. We do this only if
                 * the user didn't specify an explicit init to spawn. */

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
                 * We want valgrind to print its memory usage summary before reexecution.  Valgrind won't do this is on
                 * its own on exec(), but it will do it on exit().  Hence, to ensure we get a summary here, fork() off
                 * a child, let it exit() cleanly, so that it prints the summary, and wait() for it in the parent,
                 * before proceeding into the exec().
                 */
                valgrind_summary_hack();

                (void) execv(args[0], (char* const*) args);
                log_debug_errno(errno, "Failed to execute our own binary, trying fallback: %m");
        }

        /* Try the fallback, if there is any, without any serialization. We pass the original argv[] and envp[]. (Well,
         * modulo the ordering changes due to getopt() in argv[], and some cleanups in envp[], but let's hope that
         * doesn't matter.) */

        arg_serialization = safe_fclose(arg_serialization);
        fds = fdset_free(fds);

        /* Reopen the console */
        (void) make_console_stdio();

        for (j = 1, i = 1; j < (unsigned) argc; j++)
                args[i++] = argv[j];
        args[i++] = NULL;
        assert(i <= args_size);

        /* Reenable any blocked signals, especially important if we switch from initial ramdisk to init=... */
        (void) reset_all_signal_handlers();
        (void) reset_signal_mask();

        if (switch_root_init) {
                args[0] = switch_root_init;
                (void) execv(args[0], (char* const*) args);
                log_warning_errno(errno, "Failed to execute configured init, trying fallback: %m");
        }

        args[0] = "/sbin/init";
        (void) execv(args[0], (char* const*) args);
        r = -errno;

        manager_status_printf(NULL, STATUS_TYPE_EMERGENCY,
                              ANSI_HIGHLIGHT_RED "  !!  " ANSI_NORMAL,
                              "Failed to execute /sbin/init");

        if (r == -ENOENT) {
                log_warning("No /sbin/init, trying fallback");

                args[0] = "/bin/sh";
                args[1] = NULL;
                (void) execv(args[0], (char* const*) args);
                log_error_errno(errno, "Failed to execute /bin/sh, giving up: %m");
        } else
                log_warning_errno(r, "Failed to execute /sbin/init, giving up: %m");

        *ret_error_message = "Failed to execute fallback shell";
}

static int invoke_main_loop(
                Manager *m,
                bool *ret_reexecute,
                int *ret_retval,                   /* Return parameters relevant for shutting down */
                const char **ret_shutdown_verb,    /* … */
                FDSet **ret_fds,                   /* Return parameters for reexecuting */
                char **ret_switch_root_dir,        /* … */
                char **ret_switch_root_init,       /* … */
                const char **ret_error_message) {

        int r;

        assert(m);
        assert(ret_reexecute);
        assert(ret_retval);
        assert(ret_shutdown_verb);
        assert(ret_fds);
        assert(ret_switch_root_dir);
        assert(ret_switch_root_init);
        assert(ret_error_message);

        for (;;) {
                r = manager_loop(m);
                if (r < 0) {
                        *ret_error_message = "Failed to run main loop";
                        return log_emergency_errno(r, "Failed to run main loop: %m");
                }

                switch ((ManagerObjective) r) {

                case MANAGER_RELOAD: {
                        LogTarget saved_log_target;
                        int saved_log_level;

                        log_info("Reloading.");

                        /* First, save any overridden log level/target, then parse the configuration file, which might
                         * change the log level to new settings. */

                        saved_log_level = m->log_level_overridden ? log_get_max_level() : -1;
                        saved_log_target = m->log_target_overridden ? log_get_target() : _LOG_TARGET_INVALID;

                        r = parse_config_file();
                        if (r < 0)
                                log_warning_errno(r, "Failed to parse config file, ignoring: %m");

                        set_manager_defaults(m);

                        if (saved_log_level >= 0)
                                manager_override_log_level(m, saved_log_level);
                        if (saved_log_target >= 0)
                                manager_override_log_target(m, saved_log_target);

                        r = manager_reload(m);
                        if (r < 0)
                                /* Reloading failed before the point of no return. Let's continue running as if nothing happened. */
                                m->objective = MANAGER_OK;

                        break;
                }

                case MANAGER_REEXECUTE:

                        r = prepare_reexecute(m, &arg_serialization, ret_fds, false);
                        if (r < 0) {
                                *ret_error_message = "Failed to prepare for reexecution";
                                return r;
                        }

                        log_notice("Reexecuting.");

                        *ret_reexecute = true;
                        *ret_retval = EXIT_SUCCESS;
                        *ret_shutdown_verb = NULL;
                        *ret_switch_root_dir = *ret_switch_root_init = NULL;

                        return 0;

                case MANAGER_SWITCH_ROOT:
                        if (!m->switch_root_init) {
                                r = prepare_reexecute(m, &arg_serialization, ret_fds, true);
                                if (r < 0) {
                                        *ret_error_message = "Failed to prepare for reexecution";
                                        return r;
                                }
                        } else
                                *ret_fds = NULL;

                        log_notice("Switching root.");

                        *ret_reexecute = true;
                        *ret_retval = EXIT_SUCCESS;
                        *ret_shutdown_verb = NULL;

                        /* Steal the switch root parameters */
                        *ret_switch_root_dir = m->switch_root;
                        *ret_switch_root_init = m->switch_root_init;
                        m->switch_root = m->switch_root_init = NULL;

                        return 0;

                case MANAGER_EXIT:

                        if (MANAGER_IS_USER(m)) {
                                log_debug("Exit.");

                                *ret_reexecute = false;
                                *ret_retval = m->return_value;
                                *ret_shutdown_verb = NULL;
                                *ret_fds = NULL;
                                *ret_switch_root_dir = *ret_switch_root_init = NULL;

                                return 0;
                        }

                        _fallthrough_;
                case MANAGER_REBOOT:
                case MANAGER_POWEROFF:
                case MANAGER_HALT:
                case MANAGER_KEXEC: {
                        static const char * const table[_MANAGER_OBJECTIVE_MAX] = {
                                [MANAGER_EXIT]     = "exit",
                                [MANAGER_REBOOT]   = "reboot",
                                [MANAGER_POWEROFF] = "poweroff",
                                [MANAGER_HALT]     = "halt",
                                [MANAGER_KEXEC]    = "kexec",
                        };

                        log_notice("Shutting down.");

                        *ret_reexecute = false;
                        *ret_retval = m->return_value;
                        assert_se(*ret_shutdown_verb = table[m->objective]);
                        *ret_fds = NULL;
                        *ret_switch_root_dir = *ret_switch_root_init = NULL;

                        return 0;
                }

                default:
                        assert_not_reached("Unknown or unexpected manager objective.");
                }
        }
}

static void log_execution_mode(bool *ret_first_boot) {
        assert(ret_first_boot);

        if (arg_system) {
                int v;

                log_info(PACKAGE_STRING " running in %ssystem mode. (" SYSTEMD_FEATURES ")",
                         arg_action == ACTION_TEST ? "test " : "" );

                v = detect_virtualization();
                if (v > 0)
                        log_info("Detected virtualization %s.", virtualization_to_string(v));

                log_info("Detected architecture %s.", architecture_to_string(uname_architecture()));

                if (in_initrd()) {
                        *ret_first_boot = false;
                        log_info("Running in initial RAM disk.");
                } else {
                        /* Let's check whether we are in first boot, i.e. whether /etc is still unpopulated. We use
                         * /etc/machine-id as flag file, for this: if it exists we assume /etc is populated, if it
                         * doesn't it's unpopulated. This allows container managers and installers to provision a
                         * couple of files already. If the container manager wants to provision the machine ID itself
                         * it should pass $container_uuid to PID 1. */

                        *ret_first_boot = access("/etc/machine-id", F_OK) < 0;
                        if (*ret_first_boot)
                                log_info("Running with unpopulated /etc.");
                }
        } else {
                if (DEBUG_LOGGING) {
                        _cleanup_free_ char *t;

                        t = uid_to_name(getuid());
                        log_debug(PACKAGE_STRING " running in %suser mode for user " UID_FMT "/%s. (" SYSTEMD_FEATURES ")",
                                  arg_action == ACTION_TEST ? " test" : "", getuid(), strna(t));
                }

                *ret_first_boot = false;
        }
}

static int initialize_runtime(
                bool skip_setup,
                struct rlimit *saved_rlimit_nofile,
                struct rlimit *saved_rlimit_memlock,
                const char **ret_error_message) {

        int r;

        assert(ret_error_message);

        /* Sets up various runtime parameters. Many of these initializations are conditionalized:
         *
         * - Some only apply to --system instances
         * - Some only apply to --user instances
         * - Some only apply when we first start up, but not when we reexecute
         */

        if (arg_action != ACTION_RUN)
                return 0;

        if (arg_system) {
                /* Make sure we leave a core dump without panicing the kernel. */
                install_crash_handler();

                if (!skip_setup) {
                        r = mount_cgroup_controllers();
                        if (r < 0) {
                                *ret_error_message = "Failed to mount cgroup hierarchies";
                                return r;
                        }

                        status_welcome();
                        hostname_setup();
                        machine_id_setup(NULL, arg_machine_id, NULL);
                        loopback_setup();
                        bump_unix_max_dgram_qlen();
                        bump_file_max_and_nr_open();
                        test_usr();
                        write_container_id();
                }

                if (arg_watchdog_device) {
                        r = watchdog_set_device(arg_watchdog_device);
                        if (r < 0)
                                log_warning_errno(r, "Failed to set watchdog device to %s, ignoring: %m", arg_watchdog_device);
                }

                if (arg_runtime_watchdog > 0 && arg_runtime_watchdog != USEC_INFINITY)
                        watchdog_set_timeout(&arg_runtime_watchdog);
        }

        if (arg_timer_slack_nsec != NSEC_INFINITY)
                if (prctl(PR_SET_TIMERSLACK, arg_timer_slack_nsec) < 0)
                        log_warning_errno(errno, "Failed to adjust timer slack, ignoring: %m");

        if (arg_system && !cap_test_all(arg_capability_bounding_set)) {
                r = capability_bounding_set_drop_usermode(arg_capability_bounding_set);
                if (r < 0) {
                        *ret_error_message = "Failed to drop capability bounding set of usermode helpers";
                        return log_emergency_errno(r, "Failed to drop capability bounding set of usermode helpers: %m");
                }

                r = capability_bounding_set_drop(arg_capability_bounding_set, true);
                if (r < 0) {
                        *ret_error_message = "Failed to drop capability bounding set";
                        return log_emergency_errno(r, "Failed to drop capability bounding set: %m");
                }
        }

        if (arg_system && arg_no_new_privs) {
                if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
                        *ret_error_message = "Failed to disable new privileges";
                        return log_emergency_errno(errno, "Failed to disable new privileges: %m");
                }
        }

        if (arg_syscall_archs) {
                r = enforce_syscall_archs(arg_syscall_archs);
                if (r < 0) {
                        *ret_error_message = "Failed to set syscall architectures";
                        return r;
                }
        }

        if (!arg_system)
                /* Become reaper of our children */
                if (prctl(PR_SET_CHILD_SUBREAPER, 1) < 0)
                        log_warning_errno(errno, "Failed to make us a subreaper: %m");

        /* Bump up RLIMIT_NOFILE for systemd itself */
        (void) bump_rlimit_nofile(saved_rlimit_nofile);
        (void) bump_rlimit_memlock(saved_rlimit_memlock);

        return 0;
}

static int do_queue_default_job(
                Manager *m,
                const char **ret_error_message) {

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        Job *default_unit_job;
        Unit *target = NULL;
        int r;

        log_debug("Activating default unit: %s", arg_default_unit);

        r = manager_load_startable_unit_or_warn(m, arg_default_unit, NULL, &target);
        if (r < 0) {
                log_info("Falling back to rescue target: " SPECIAL_RESCUE_TARGET);

                r = manager_load_startable_unit_or_warn(m, SPECIAL_RESCUE_TARGET, NULL, &target);
                if (r < 0) {
                        *ret_error_message = r == -ERFKILL ? "Rescue target masked"
                                                           : "Failed to load rescue target";
                        return r;
                }
        }

        assert(target->load_state == UNIT_LOADED);

        r = manager_add_job(m, JOB_START, target, JOB_ISOLATE, &error, &default_unit_job);
        if (r == -EPERM) {
                log_debug_errno(r, "Default target could not be isolated, starting instead: %s", bus_error_message(&error, r));

                sd_bus_error_free(&error);

                r = manager_add_job(m, JOB_START, target, JOB_REPLACE, &error, &default_unit_job);
                if (r < 0) {
                        *ret_error_message = "Failed to start default target";
                        return log_emergency_errno(r, "Failed to start default target: %s", bus_error_message(&error, r));
                }

        } else if (r < 0) {
                *ret_error_message = "Failed to isolate default target";
                return log_emergency_errno(r, "Failed to isolate default target: %s", bus_error_message(&error, r));
        }

        m->default_unit_job_id = default_unit_job->id;

        return 0;
}

static void free_arguments(void) {

        /* Frees all arg_* variables, with the exception of arg_serialization */
        rlimit_free_all(arg_default_rlimit);

        arg_default_unit = mfree(arg_default_unit);
        arg_confirm_spawn = mfree(arg_confirm_spawn);
        arg_default_environment = strv_free(arg_default_environment);
        arg_syscall_archs = set_free(arg_syscall_archs);
}

static int load_configuration(int argc, char **argv, const char **ret_error_message) {
        int r;

        assert(ret_error_message);

        arg_default_tasks_max = system_tasks_max_scale(DEFAULT_TASKS_MAX_PERCENTAGE, 100U);

        r = parse_config_file();
        if (r < 0) {
                *ret_error_message = "Failed to parse config file";
                return r;
        }

        if (arg_system) {
                r = proc_cmdline_parse(parse_proc_cmdline_item, NULL, 0);
                if (r < 0)
                        log_warning_errno(r, "Failed to parse kernel command line, ignoring: %m");
        }

        /* Note that this also parses bits from the kernel command line, including "debug". */
        log_parse_environment();

        r = parse_argv(argc, argv);
        if (r < 0) {
                *ret_error_message = "Failed to parse commandline arguments";
                return r;
        }

        /* Initialize default unit */
        if (!arg_default_unit) {
                arg_default_unit = strdup(SPECIAL_DEFAULT_TARGET);
                if (!arg_default_unit) {
                        *ret_error_message = "Failed to set default unit";
                        return log_oom();
                }
        }

        /* Initialize the show status setting if it hasn't been set explicitly yet */
        if (arg_show_status == _SHOW_STATUS_INVALID)
                arg_show_status = SHOW_STATUS_YES;

        return 0;
}

static int safety_checks(void) {

        if (getpid_cached() == 1 &&
            arg_action != ACTION_RUN) {
                log_error("Unsupported execution mode while PID 1.");
                return -EPERM;
        }

        if (getpid_cached() == 1 &&
            !arg_system) {
                log_error("Can't run --user mode as PID 1.");
                return -EPERM;
        }

        if (arg_action == ACTION_RUN &&
            arg_system &&
            getpid_cached() != 1) {
                log_error("Can't run system mode unless PID 1.");
                return -EPERM;
        }

        if (arg_action == ACTION_TEST &&
            geteuid() == 0) {
                log_error("Don't run test mode as root.");
                return -EPERM;
        }

        if (!arg_system &&
            arg_action == ACTION_RUN &&
            sd_booted() <= 0) {
                log_error("Trying to run as user instance, but the system has not been booted with systemd.");
                return -EOPNOTSUPP;
        }

        if (!arg_system &&
            arg_action == ACTION_RUN &&
            !getenv("XDG_RUNTIME_DIR")) {
                log_error("Trying to run as user instance, but $XDG_RUNTIME_DIR is not set.");
                return -EUNATCH;
        }

        if (arg_system &&
            arg_action == ACTION_RUN &&
            running_in_chroot() > 0) {
                log_error("Cannot be run in a chroot() environment.");
                return -EOPNOTSUPP;
        }

        return 0;
}

static int initialize_security(
                bool *loaded_policy,
                dual_timestamp *security_start_timestamp,
                dual_timestamp *security_finish_timestamp,
                const char **ret_error_message) {

        int r;

        assert(loaded_policy);
        assert(security_start_timestamp);
        assert(security_finish_timestamp);
        assert(ret_error_message);

        dual_timestamp_get(security_start_timestamp);

        r = mac_selinux_setup(loaded_policy);
        if (r < 0) {
                *ret_error_message = "Failed to load SELinux policy";
                return r;
        }

        r = mac_smack_setup(loaded_policy);
        if (r < 0) {
                *ret_error_message = "Failed to load SMACK policy";
                return r;
        }

        r = ima_setup();
        if (r < 0) {
                *ret_error_message = "Failed to load IMA policy";
                return r;
        }

        dual_timestamp_get(security_finish_timestamp);
        return 0;
}

static void test_summary(Manager *m) {
        assert(m);

        printf("-> By units:\n");
        manager_dump_units(m, stdout, "\t");

        printf("-> By jobs:\n");
        manager_dump_jobs(m, stdout, "\t");
}

static int collect_fds(FDSet **ret_fds, const char **ret_error_message) {
        int r;

        assert(ret_fds);
        assert(ret_error_message);

        r = fdset_new_fill(ret_fds);
        if (r < 0) {
                *ret_error_message = "Failed to allocate fd set";
                return log_emergency_errno(r, "Failed to allocate fd set: %m");
        }

        fdset_cloexec(*ret_fds, true);

        if (arg_serialization)
                assert_se(fdset_remove(*ret_fds, fileno(arg_serialization)) >= 0);

        return 0;
}

static void setup_console_terminal(bool skip_setup) {

        if (!arg_system)
                return;

        /* Become a session leader if we aren't one yet. */
        (void) setsid();

        /* If we are init, we connect stdin/stdout/stderr to /dev/null and make sure we don't have a controlling
         * tty. */
        (void) release_terminal();

        /* Reset the console, but only if this is really init and we are freshly booted */
        if (getpid_cached() == 1 && !skip_setup)
                (void) console_setup();
}

static bool early_skip_setup_check(int argc, char *argv[]) {
        bool found_deserialize = false;
        int i;

        /* Determine if this is a reexecution or normal bootup. We do the full command line parsing much later, so
         * let's just have a quick peek here. Note that if we have switched root, do all the special setup things
         * anyway, even if in that case we also do deserialization. */

        for (i = 1; i < argc; i++) {
                if (streq(argv[i], "--switched-root"))
                        return false; /* If we switched root, don't skip the setup. */
                else if (streq(argv[i], "--deserialize"))
                        found_deserialize = true;
        }

        return found_deserialize; /* When we are deserializing, then we are reexecuting, hence avoid the extensive setup */
}

int main(int argc, char *argv[]) {

        dual_timestamp initrd_timestamp = DUAL_TIMESTAMP_NULL, userspace_timestamp = DUAL_TIMESTAMP_NULL, kernel_timestamp = DUAL_TIMESTAMP_NULL,
                security_start_timestamp = DUAL_TIMESTAMP_NULL, security_finish_timestamp = DUAL_TIMESTAMP_NULL;
        struct rlimit saved_rlimit_nofile = RLIMIT_MAKE_CONST(0), saved_rlimit_memlock = RLIMIT_MAKE_CONST((rlim_t) -1);
        bool skip_setup, loaded_policy = false, queue_default_job = false, first_boot = false, reexecute = false;
        char *switch_root_dir = NULL, *switch_root_init = NULL;
        usec_t before_startup, after_startup;
        static char systemd[] = "systemd";
        char timespan[FORMAT_TIMESPAN_MAX];
        const char *shutdown_verb = NULL, *error_message = NULL;
        int r, retval = EXIT_FAILURE;
        Manager *m = NULL;
        FDSet *fds = NULL;

        /* SysV compatibility: redirect init → telinit */
        redirect_telinit(argc, argv);

        /* Take timestamps early on */
        dual_timestamp_from_monotonic(&kernel_timestamp, 0);
        dual_timestamp_get(&userspace_timestamp);

        /* Figure out whether we need to do initialize the system, or if we already did that because we are
         * reexecuting */
        skip_setup = early_skip_setup_check(argc, argv);

        /* If we get started via the /sbin/init symlink then we are called 'init'. After a subsequent reexecution we
         * are then called 'systemd'. That is confusing, hence let's call us systemd right-away. */
        program_invocation_short_name = systemd;
        (void) prctl(PR_SET_NAME, systemd);

        /* Save the original command line */
        saved_argv = argv;
        saved_argc = argc;

        /* Make sure that if the user says "syslog" we actually log to the journal. */
        log_set_upgrade_syslog_to_journal(true);

        if (getpid_cached() == 1) {
                /* When we run as PID 1 force system mode */
                arg_system = true;

                /* Disable the umask logic */
                umask(0);

                /* Make sure that at least initially we do not ever log to journald/syslogd, because it might not be
                 * activated yet (even though the log socket for it exists). */
                log_set_prohibit_ipc(true);

                /* Always reopen /dev/console when running as PID 1 or one of its pre-execve() children. This is
                 * important so that we never end up logging to any foreign stderr, for example if we have to log in a
                 * child process right before execve()'ing the actual binary, at a point in time where socket
                 * activation stderr/stdout area already set up. */
                log_set_always_reopen_console(true);

                if (detect_container() <= 0) {

                        /* Running outside of a container as PID 1 */
                        log_set_target(LOG_TARGET_KMSG);
                        log_open();

                        if (in_initrd())
                                initrd_timestamp = userspace_timestamp;

                        if (!skip_setup) {
                                r = mount_setup_early();
                                if (r < 0) {
                                        error_message = "Failed to mount early API filesystems";
                                        goto finish;
                                }

                                r = initialize_security(
                                                &loaded_policy,
                                                &security_start_timestamp,
                                                &security_finish_timestamp,
                                                &error_message);
                                if (r < 0)
                                        goto finish;
                        }

                        if (mac_selinux_init() < 0) {
                                error_message = "Failed to initialize SELinux policy";
                                goto finish;
                        }

                        if (!skip_setup)
                                initialize_clock();

                        /* Set the default for later on, but don't actually open the logs like this for now. Note that
                         * if we are transitioning from the initrd there might still be journal fd open, and we
                         * shouldn't attempt opening that before we parsed /proc/cmdline which might redirect output
                         * elsewhere. */
                        log_set_target(LOG_TARGET_JOURNAL_OR_KMSG);

                } else {
                        /* Running inside a container, as PID 1 */
                        log_set_target(LOG_TARGET_CONSOLE);
                        log_open();

                        /* For later on, see above... */
                        log_set_target(LOG_TARGET_JOURNAL);

                        /* clear the kernel timestamp,
                         * because we are in a container */
                        kernel_timestamp = DUAL_TIMESTAMP_NULL;
                }

                initialize_coredump(skip_setup);

                r = fixup_environment();
                if (r < 0) {
                        log_emergency_errno(r, "Failed to fix up PID 1 environment: %m");
                        error_message = "Failed to fix up PID1 environment";
                        goto finish;
                }

        } else {
                /* Running as user instance */
                arg_system = false;
                log_set_target(LOG_TARGET_AUTO);
                log_open();

                /* clear the kernel timestamp,
                 * because we are not PID 1 */
                kernel_timestamp = DUAL_TIMESTAMP_NULL;
        }

        if (arg_system) {
                /* Try to figure out if we can use colors with the console. No need to do that for user instances since
                 * they never log into the console. */
                log_show_color(colors_enabled());

                r = make_null_stdio();
                if (r < 0)
                        log_warning_errno(r, "Failed to redirect standard streams to /dev/null, ignoring: %m");
        }

        /* Mount /proc, /sys and friends, so that /proc/cmdline and
         * /proc/$PID/fd is available. */
        if (getpid_cached() == 1) {

                /* Load the kernel modules early. */
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

        r = load_configuration(argc, argv, &error_message);
        if (r < 0)
                goto finish;

        r = safety_checks();
        if (r < 0)
                goto finish;

        if (IN_SET(arg_action, ACTION_TEST, ACTION_HELP, ACTION_DUMP_CONFIGURATION_ITEMS, ACTION_DUMP_BUS_PROPERTIES))
                (void) pager_open(arg_pager_flags);

        if (arg_action != ACTION_RUN)
                skip_setup = true;

        if (arg_action == ACTION_HELP) {
                retval = help() < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
                goto finish;
        } else if (arg_action == ACTION_VERSION) {
                retval = version();
                goto finish;
        } else if (arg_action == ACTION_DUMP_CONFIGURATION_ITEMS) {
                unit_dump_config_items(stdout);
                retval = EXIT_SUCCESS;
                goto finish;
        } else if (arg_action == ACTION_DUMP_BUS_PROPERTIES) {
                dump_bus_properties(stdout);
                retval = EXIT_SUCCESS;
                goto finish;
        }

        assert_se(IN_SET(arg_action, ACTION_RUN, ACTION_TEST));

        /* Move out of the way, so that we won't block unmounts */
        assert_se(chdir("/") == 0);

        if (arg_action == ACTION_RUN) {

                /* A core pattern might have been specified via the cmdline.  */
                initialize_core_pattern(skip_setup);

                /* Close logging fds, in order not to confuse collecting passed fds and terminal logic below */
                log_close();

                /* Remember open file descriptors for later deserialization */
                r = collect_fds(&fds, &error_message);
                if (r < 0)
                        goto finish;

                /* Give up any control of the console, but make sure its initialized. */
                setup_console_terminal(skip_setup);

                /* Open the logging devices, if possible and necessary */
                log_open();
        }

        log_execution_mode(&first_boot);

        r = initialize_runtime(skip_setup,
                               &saved_rlimit_nofile,
                               &saved_rlimit_memlock,
                               &error_message);
        if (r < 0)
                goto finish;

        r = manager_new(arg_system ? UNIT_FILE_SYSTEM : UNIT_FILE_USER,
                        arg_action == ACTION_TEST ? MANAGER_TEST_FULL : 0,
                        &m);
        if (r < 0) {
                log_emergency_errno(r, "Failed to allocate manager object: %m");
                error_message = "Failed to allocate manager object";
                goto finish;
        }

        m->timestamps[MANAGER_TIMESTAMP_KERNEL] = kernel_timestamp;
        m->timestamps[MANAGER_TIMESTAMP_INITRD] = initrd_timestamp;
        m->timestamps[MANAGER_TIMESTAMP_USERSPACE] = userspace_timestamp;
        m->timestamps[manager_timestamp_initrd_mangle(MANAGER_TIMESTAMP_SECURITY_START)] = security_start_timestamp;
        m->timestamps[manager_timestamp_initrd_mangle(MANAGER_TIMESTAMP_SECURITY_FINISH)] = security_finish_timestamp;

        set_manager_defaults(m);
        set_manager_settings(m);
        manager_set_first_boot(m, first_boot);

        /* Remember whether we should queue the default job */
        queue_default_job = !arg_serialization || arg_switched_root;

        before_startup = now(CLOCK_MONOTONIC);

        r = manager_startup(m, arg_serialization, fds);
        if (r < 0) {
                error_message = "Failed to start up manager";
                goto finish;
        }

        /* This will close all file descriptors that were opened, but not claimed by any unit. */
        fds = fdset_free(fds);
        arg_serialization = safe_fclose(arg_serialization);

        if (queue_default_job) {
                r = do_queue_default_job(m, &error_message);
                if (r < 0)
                        goto finish;
        }

        after_startup = now(CLOCK_MONOTONIC);

        log_full(arg_action == ACTION_TEST ? LOG_INFO : LOG_DEBUG,
                 "Loaded units and determined initial transaction in %s.",
                 format_timespan(timespan, sizeof(timespan), after_startup - before_startup, 100 * USEC_PER_MSEC));

        if (arg_action == ACTION_TEST) {
                test_summary(m);
                retval = EXIT_SUCCESS;
                goto finish;
        }

        (void) invoke_main_loop(m,
                                &reexecute,
                                &retval,
                                &shutdown_verb,
                                &fds,
                                &switch_root_dir,
                                &switch_root_init,
                                &error_message);

finish:
        pager_close();

        if (m) {
                arg_shutdown_watchdog = m->shutdown_watchdog;
                m = manager_free(m);
        }

        free_arguments();
        mac_selinux_finish();

        if (reexecute)
                do_reexecute(argc, argv,
                             &saved_rlimit_nofile,
                             &saved_rlimit_memlock,
                             fds,
                             switch_root_dir,
                             switch_root_init,
                             &error_message); /* This only returns if reexecution failed */

        arg_serialization = safe_fclose(arg_serialization);
        fds = fdset_free(fds);

#if HAVE_VALGRIND_VALGRIND_H
        /* If we are PID 1 and running under valgrind, then let's exit
         * here explicitly. valgrind will only generate nice output on
         * exit(), not on exec(), hence let's do the former not the
         * latter here. */
        if (getpid_cached() == 1 && RUNNING_ON_VALGRIND) {
                /* Cleanup watchdog_device strings for valgrind. We need them
                 * in become_shutdown() so normally we cannot free them yet. */
                watchdog_free_device();
                arg_watchdog_device = mfree(arg_watchdog_device);
                return retval;
        }
#endif

        if (shutdown_verb) {
                r = become_shutdown(shutdown_verb, retval);
                log_error_errno(r, "Failed to execute shutdown binary, %s: %m", getpid_cached() == 1 ? "freezing" : "quitting");
                error_message = "Failed to execute shutdown binary";
        }

        watchdog_free_device();
        arg_watchdog_device = mfree(arg_watchdog_device);

        if (getpid_cached() == 1) {
                if (error_message)
                        manager_status_printf(NULL, STATUS_TYPE_EMERGENCY,
                                              ANSI_HIGHLIGHT_RED "!!!!!!" ANSI_NORMAL,
                                              "%s, freezing.", error_message);
                freeze_or_reboot();
        }

        return retval;
}
