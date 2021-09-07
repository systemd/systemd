/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/reboot.h>
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
#include "apparmor-setup.h"
#include "architecture.h"
#include "build.h"
#include "bus-error.h"
#include "bus-util.h"
#include "capability-util.h"
#include "cgroup-util.h"
#include "clock-util.h"
#include "conf-parser.h"
#include "cpu-set-util.h"
#include "dbus-manager.h"
#include "dbus.h"
#include "def.h"
#include "dev-setup.h"
#include "efi-random.h"
#include "efivars.h"
#include "emergency-action.h"
#include "env-util.h"
#include "exit-status.h"
#include "fd-util.h"
#include "fdset.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "hexdecoct.h"
#include "hostname-setup.h"
#include "ima-setup.h"
#include "killall.h"
#include "kmod-setup.h"
#include "limits-util.h"
#include "load-fragment.h"
#include "log.h"
#include "loopback-setup.h"
#include "machine-id-setup.h"
#include "manager.h"
#include "manager-dump.h"
#include "mkdir.h"
#include "mount-setup.h"
#include "os-util.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "random-util.h"
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

#if HAS_FEATURE_ADDRESS_SANITIZER
#include <sanitizer/lsan_interface.h>
#endif

#define DEFAULT_TASKS_MAX ((TasksMax) { 15U, 100U }) /* 15% */

static enum {
        ACTION_RUN,
        ACTION_HELP,
        ACTION_VERSION,
        ACTION_TEST,
        ACTION_DUMP_CONFIGURATION_ITEMS,
        ACTION_DUMP_BUS_PROPERTIES,
        ACTION_BUS_INTROSPECT,
} arg_action = ACTION_RUN;

static const char *arg_bus_introspect = NULL;

/* Those variables are initialized to 0 automatically, so we avoid uninitialized memory access.  Real
 * defaults are assigned in reset_arguments() below. */
static char *arg_default_unit;
static bool arg_system;
static bool arg_dump_core;
static int arg_crash_chvt;
static bool arg_crash_shell;
static bool arg_crash_reboot;
static char *arg_confirm_spawn;
static ShowStatus arg_show_status;
static StatusUnitFormat arg_status_unit_format;
static bool arg_switched_root;
static PagerFlags arg_pager_flags;
static bool arg_service_watchdogs;
static ExecOutput arg_default_std_output;
static ExecOutput arg_default_std_error;
static usec_t arg_default_restart_usec;
static usec_t arg_default_timeout_start_usec;
static usec_t arg_default_timeout_stop_usec;
static usec_t arg_default_timeout_abort_usec;
static bool arg_default_timeout_abort_set;
static usec_t arg_default_start_limit_interval;
static unsigned arg_default_start_limit_burst;
static usec_t arg_runtime_watchdog;
static usec_t arg_reboot_watchdog;
static usec_t arg_kexec_watchdog;
static char *arg_early_core_pattern;
static char *arg_watchdog_device;
static char **arg_default_environment;
static char **arg_manager_environment;
static struct rlimit *arg_default_rlimit[_RLIMIT_MAX];
static uint64_t arg_capability_bounding_set;
static bool arg_no_new_privs;
static nsec_t arg_timer_slack_nsec;
static usec_t arg_default_timer_accuracy_usec;
static Set* arg_syscall_archs;
static FILE* arg_serialization;
static int arg_default_cpu_accounting;
static bool arg_default_io_accounting;
static bool arg_default_ip_accounting;
static bool arg_default_blockio_accounting;
static bool arg_default_memory_accounting;
static bool arg_default_tasks_accounting;
static TasksMax arg_default_tasks_max;
static sd_id128_t arg_machine_id;
static EmergencyAction arg_cad_burst_action;
static OOMPolicy arg_default_oom_policy;
static CPUSet arg_cpu_affinity;
static NUMAPolicy arg_numa_policy;
static usec_t arg_clock_usec;
static void *arg_random_seed;
static size_t arg_random_seed_size;

/* A copy of the original environment block */
static char **saved_env = NULL;

static int parse_configuration(const struct rlimit *saved_rlimit_nofile,
                               const struct rlimit *saved_rlimit_memlock);

static int manager_find_user_config_paths(char ***ret_files, char ***ret_dirs) {
        _cleanup_free_ char *base = NULL;
        _cleanup_strv_free_ char **files = NULL, **dirs = NULL;
        int r;

        r = xdg_user_config_dir(&base, "/systemd");
        if (r < 0)
                return r;

        r = strv_extendf(&files, "%s/user.conf", base);
        if (r < 0)
                return r;

        r = strv_extend(&files, PKGSYSCONFDIR "/user.conf");
        if (r < 0)
                return r;

        r = strv_consume(&dirs, TAKE_PTR(base));
        if (r < 0)
                return r;

        r = strv_extend_strv(&dirs, CONF_PATHS_STRV("systemd"), false);
        if (r < 0)
                return r;

        *ret_files = TAKE_PTR(files);
        *ret_dirs = TAKE_PTR(dirs);
        return 0;
}

_noreturn_ static void freeze_or_exit_or_reboot(void) {

        /* If we are running in a container, let's prefer exiting, after all we can propagate an exit code to
         * the container manager, and thus inform it that something went wrong. */
        if (detect_container() > 0) {
                log_emergency("Exiting PID 1...");
                _exit(EXIT_EXCEPTION);
        }

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
                        _exit(EXIT_EXCEPTION);
                } else {
                        siginfo_t status;
                        int r;

                        /* Order things nicely. */
                        r = wait_for_terminate(pid, &status);
                        if (r < 0)
                                log_emergency_errno(r, "Caught <%s>, waitpid() failed: %m", signal_to_string(sig));
                        else if (status.si_code != CLD_DUMPED) {
                                const char *s = status.si_code == CLD_EXITED
                                        ? exit_status_to_string(status.si_status, EXIT_STATUS_LIBC)
                                        : signal_to_string(status.si_status);

                                log_emergency("Caught <%s>, core dump failed (child "PID_FMT", code=%s, status=%i/%s).",
                                              signal_to_string(sig),
                                              pid,
                                              sigchld_code_to_string(status.si_code),
                                              status.si_status, strna(s));
                        } else
                                log_emergency("Caught <%s>, dumped core as pid "PID_FMT".",
                                              signal_to_string(sig), pid);
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
                        (void) rlimit_nofile_safe();
                        (void) execle("/bin/sh", "/bin/sh", NULL, environ);

                        log_emergency_errno(errno, "execle() failed: %m");
                        _exit(EXIT_EXCEPTION);
                } else {
                        log_info("Spawned crash shell as PID "PID_FMT".", pid);
                        (void) wait_for_terminate(pid, NULL);
                }
        }

        freeze_or_exit_or_reboot();
}

static void install_crash_handler(void) {
        static const struct sigaction sa = {
                .sa_handler = crash,
                .sa_flags = SA_NODEFER, /* So that we can raise the signal again from the signal handler */
        };
        int r;

        /* We ignore the return value here, since, we don't mind if we cannot set up a crash handler */
        r = sigaction_many(&sa, SIGNALS_CRASH_HANDLER);
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
                else if (in_initrd() == !!startswith(key, "rd."))
                        return free_and_strdup_warn(&arg_default_unit, value);

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
                        (void) parse_path_argument(value, false, &arg_early_core_pattern);
                else
                        log_warning("Specified core pattern '%s' is not an absolute path, ignoring.", value);

        } else if (proc_cmdline_key_streq(key, "systemd.crash_chvt")) {

                if (!value)
                        arg_crash_chvt = 0; /* turn on */
                else {
                        r = parse_crash_chvt(value, &arg_crash_chvt);
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

        } else if (proc_cmdline_key_streq(key, "systemd.status_unit_format")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = status_unit_format_from_string(value);
                if (r < 0)
                        log_warning_errno(r, "Failed to parse %s=%s, ignoring: %m", key, value);
                else
                        arg_status_unit_format = r;

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

                if (!env_assignment_is_valid(value))
                        log_warning("Environment variable assignment '%s' is not valid. Ignoring.", value);
                else {
                        r = strv_env_replace_strdup(&arg_default_environment, value);
                        if (r < 0)
                                return log_oom();
                }

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

        } else if (proc_cmdline_key_streq(key, "systemd.cpu_affinity")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = parse_cpu_set(value, &arg_cpu_affinity);
                if (r < 0)
                        log_warning_errno(r, "Failed to parse CPU affinity mask '%s', ignoring: %m", value);

        } else if (proc_cmdline_key_streq(key, "systemd.watchdog_device")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                (void) parse_path_argument(value, false, &arg_watchdog_device);

        } else if (proc_cmdline_key_streq(key, "systemd.clock_usec")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = safe_atou64(value, &arg_clock_usec);
                if (r < 0)
                        log_warning_errno(r, "Failed to parse systemd.clock_usec= argument, ignoring: %s", value);

        } else if (proc_cmdline_key_streq(key, "systemd.random_seed")) {
                void *p;
                size_t sz;

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = unbase64mem(value, SIZE_MAX, &p, &sz);
                if (r < 0)
                        log_warning_errno(r, "Failed to parse systemd.random_seed= argument, ignoring: %s", value);

                free(arg_random_seed);
                arg_random_seed = sz > 0 ? p : mfree(p);
                arg_random_seed_size = sz;

        } else if (streq(key, "quiet") && !value) {

                if (arg_show_status == _SHOW_STATUS_INVALID)
                        arg_show_status = SHOW_STATUS_ERROR;

        } else if (streq(key, "debug") && !value) {

                /* Note that log_parse_environment() handles 'debug'
                 * too, and sets the log level to LOG_DEBUG. */

                if (detect_container() > 0)
                        log_set_target(LOG_TARGET_CONSOLE);

        } else if (!value) {
                const char *target;

                /* Compatible with SysV, but supported independently even if SysV compatibility is disabled. */
                target = runlevel_to_target(key);
                if (target)
                        return free_and_strdup_warn(&arg_default_unit, target);
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
DEFINE_SETTER(config_parse_color, log_show_color_from_string, "color");
DEFINE_SETTER(config_parse_location, log_show_location_from_string, "location");
DEFINE_SETTER(config_parse_time, log_show_time_from_string, "time");

static int config_parse_default_timeout_abort(
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
        int r;

        r = config_parse_timeout_abort(unit, filename, line, section, section_line, lvalue, ltype, rvalue,
                                       &arg_default_timeout_abort_usec, userdata);
        if (r >= 0)
                arg_default_timeout_abort_set = r;
        return 0;
}

static int parse_config_file(void) {
        const ConfigTableItem items[] = {
                { "Manager", "LogLevel",                     config_parse_level2,                0, NULL                                   },
                { "Manager", "LogTarget",                    config_parse_target,                0, NULL                                   },
                { "Manager", "LogColor",                     config_parse_color,                 0, NULL                                   },
                { "Manager", "LogLocation",                  config_parse_location,              0, NULL                                   },
                { "Manager", "LogTime",                      config_parse_time,                  0, NULL                                   },
                { "Manager", "DumpCore",                     config_parse_bool,                  0, &arg_dump_core                         },
                { "Manager", "CrashChVT", /* legacy */       config_parse_crash_chvt,            0, &arg_crash_chvt                        },
                { "Manager", "CrashChangeVT",                config_parse_crash_chvt,            0, &arg_crash_chvt                        },
                { "Manager", "CrashShell",                   config_parse_bool,                  0, &arg_crash_shell                       },
                { "Manager", "CrashReboot",                  config_parse_bool,                  0, &arg_crash_reboot                      },
                { "Manager", "ShowStatus",                   config_parse_show_status,           0, &arg_show_status                       },
                { "Manager", "StatusUnitFormat",             config_parse_status_unit_format,    0, &arg_status_unit_format                },
                { "Manager", "CPUAffinity",                  config_parse_cpu_affinity2,         0, &arg_cpu_affinity                      },
                { "Manager", "NUMAPolicy",                   config_parse_numa_policy,           0, &arg_numa_policy.type                  },
                { "Manager", "NUMAMask",                     config_parse_numa_mask,             0, &arg_numa_policy                       },
                { "Manager", "JoinControllers",              config_parse_warn_compat,           DISABLED_CONFIGURATION, NULL              },
                { "Manager", "RuntimeWatchdogSec",           config_parse_sec,                   0, &arg_runtime_watchdog                  },
                { "Manager", "RebootWatchdogSec",            config_parse_sec,                   0, &arg_reboot_watchdog                   },
                { "Manager", "ShutdownWatchdogSec",          config_parse_sec,                   0, &arg_reboot_watchdog                   }, /* obsolete alias */
                { "Manager", "KExecWatchdogSec",             config_parse_sec,                   0, &arg_kexec_watchdog                    },
                { "Manager", "WatchdogDevice",               config_parse_path,                  0, &arg_watchdog_device                   },
                { "Manager", "CapabilityBoundingSet",        config_parse_capability_set,        0, &arg_capability_bounding_set           },
                { "Manager", "NoNewPrivileges",              config_parse_bool,                  0, &arg_no_new_privs                      },
#if HAVE_SECCOMP
                { "Manager", "SystemCallArchitectures",      config_parse_syscall_archs,         0, &arg_syscall_archs                     },
#endif
                { "Manager", "TimerSlackNSec",               config_parse_nsec,                  0, &arg_timer_slack_nsec                  },
                { "Manager", "DefaultTimerAccuracySec",      config_parse_sec,                   0, &arg_default_timer_accuracy_usec       },
                { "Manager", "DefaultStandardOutput",        config_parse_output_restricted,     0, &arg_default_std_output                },
                { "Manager", "DefaultStandardError",         config_parse_output_restricted,     0, &arg_default_std_error                 },
                { "Manager", "DefaultTimeoutStartSec",       config_parse_sec,                   0, &arg_default_timeout_start_usec        },
                { "Manager", "DefaultTimeoutStopSec",        config_parse_sec,                   0, &arg_default_timeout_stop_usec         },
                { "Manager", "DefaultTimeoutAbortSec",       config_parse_default_timeout_abort, 0, NULL         },
                { "Manager", "DefaultRestartSec",            config_parse_sec,                   0, &arg_default_restart_usec              },
                { "Manager", "DefaultStartLimitInterval",    config_parse_sec,                   0, &arg_default_start_limit_interval      }, /* obsolete alias */
                { "Manager", "DefaultStartLimitIntervalSec", config_parse_sec,                   0, &arg_default_start_limit_interval      },
                { "Manager", "DefaultStartLimitBurst",       config_parse_unsigned,              0, &arg_default_start_limit_burst         },
                { "Manager", "DefaultEnvironment",           config_parse_environ,               0, &arg_default_environment               },
                { "Manager", "ManagerEnvironment",           config_parse_environ,               0, &arg_manager_environment               },
                { "Manager", "DefaultLimitCPU",              config_parse_rlimit,                RLIMIT_CPU, arg_default_rlimit            },
                { "Manager", "DefaultLimitFSIZE",            config_parse_rlimit,                RLIMIT_FSIZE, arg_default_rlimit          },
                { "Manager", "DefaultLimitDATA",             config_parse_rlimit,                RLIMIT_DATA, arg_default_rlimit           },
                { "Manager", "DefaultLimitSTACK",            config_parse_rlimit,                RLIMIT_STACK, arg_default_rlimit          },
                { "Manager", "DefaultLimitCORE",             config_parse_rlimit,                RLIMIT_CORE, arg_default_rlimit           },
                { "Manager", "DefaultLimitRSS",              config_parse_rlimit,                RLIMIT_RSS, arg_default_rlimit            },
                { "Manager", "DefaultLimitNOFILE",           config_parse_rlimit,                RLIMIT_NOFILE, arg_default_rlimit         },
                { "Manager", "DefaultLimitAS",               config_parse_rlimit,                RLIMIT_AS, arg_default_rlimit             },
                { "Manager", "DefaultLimitNPROC",            config_parse_rlimit,                RLIMIT_NPROC, arg_default_rlimit          },
                { "Manager", "DefaultLimitMEMLOCK",          config_parse_rlimit,                RLIMIT_MEMLOCK, arg_default_rlimit        },
                { "Manager", "DefaultLimitLOCKS",            config_parse_rlimit,                RLIMIT_LOCKS, arg_default_rlimit          },
                { "Manager", "DefaultLimitSIGPENDING",       config_parse_rlimit,                RLIMIT_SIGPENDING, arg_default_rlimit     },
                { "Manager", "DefaultLimitMSGQUEUE",         config_parse_rlimit,                RLIMIT_MSGQUEUE, arg_default_rlimit       },
                { "Manager", "DefaultLimitNICE",             config_parse_rlimit,                RLIMIT_NICE, arg_default_rlimit           },
                { "Manager", "DefaultLimitRTPRIO",           config_parse_rlimit,                RLIMIT_RTPRIO, arg_default_rlimit         },
                { "Manager", "DefaultLimitRTTIME",           config_parse_rlimit,                RLIMIT_RTTIME, arg_default_rlimit         },
                { "Manager", "DefaultCPUAccounting",         config_parse_tristate,              0, &arg_default_cpu_accounting            },
                { "Manager", "DefaultIOAccounting",          config_parse_bool,                  0, &arg_default_io_accounting             },
                { "Manager", "DefaultIPAccounting",          config_parse_bool,                  0, &arg_default_ip_accounting             },
                { "Manager", "DefaultBlockIOAccounting",     config_parse_bool,                  0, &arg_default_blockio_accounting        },
                { "Manager", "DefaultMemoryAccounting",      config_parse_bool,                  0, &arg_default_memory_accounting         },
                { "Manager", "DefaultTasksAccounting",       config_parse_bool,                  0, &arg_default_tasks_accounting          },
                { "Manager", "DefaultTasksMax",              config_parse_tasks_max,             0, &arg_default_tasks_max                 },
                { "Manager", "CtrlAltDelBurstAction",        config_parse_emergency_action,      0, &arg_cad_burst_action                  },
                { "Manager", "DefaultOOMPolicy",             config_parse_oom_policy,            0, &arg_default_oom_policy                },
                {}
        };

        _cleanup_strv_free_ char **files = NULL, **dirs = NULL;
        const char *suffix;
        int r;

        if (arg_system)
                suffix = "system.conf.d";
        else {
                r = manager_find_user_config_paths(&files, &dirs);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine config file paths: %m");

                suffix = "user.conf.d";
        }

        (void) config_parse_many(
                        (const char* const*) (files ?: STRV_MAKE(PKGSYSCONFDIR "/system.conf")),
                        (const char* const*) (dirs ?: CONF_PATHS_STRV("systemd")),
                        suffix,
                        "Manager\0",
                        config_item_table_lookup, items,
                        CONFIG_PARSE_WARN,
                        NULL,
                        NULL);

        /* Traditionally "0" was used to turn off the default unit timeouts. Fix this up so that we use
         * USEC_INFINITY like everywhere else. */
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
        m->default_timeout_abort_usec = arg_default_timeout_abort_usec;
        m->default_timeout_abort_set = arg_default_timeout_abort_set;
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
        m->default_oom_policy = arg_default_oom_policy;

        (void) manager_set_default_rlimits(m, arg_default_rlimit);

        (void) manager_default_environment(m);
        (void) manager_transient_environment_add(m, arg_default_environment);
}

static void set_manager_settings(Manager *m) {

        assert(m);

        /* Propagates the various manager settings into the manager object, i.e. properties that
         * effect the manager itself (as opposed to just being inherited into newly allocated
         * units, see set_manager_defaults() above). */

        m->confirm_spawn = arg_confirm_spawn;
        m->service_watchdogs = arg_service_watchdogs;
        m->cad_burst_action = arg_cad_burst_action;

        manager_set_watchdog(m, WATCHDOG_RUNTIME, arg_runtime_watchdog);
        manager_set_watchdog(m, WATCHDOG_REBOOT, arg_reboot_watchdog);
        manager_set_watchdog(m, WATCHDOG_KEXEC, arg_kexec_watchdog);

        manager_set_show_status(m, arg_show_status, "commandline");
        m->status_unit_format = arg_status_unit_format;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_LOG_LEVEL = 0x100,
                ARG_LOG_TARGET,
                ARG_LOG_COLOR,
                ARG_LOG_LOCATION,
                ARG_LOG_TIME,
                ARG_UNIT,
                ARG_SYSTEM,
                ARG_USER,
                ARG_TEST,
                ARG_NO_PAGER,
                ARG_VERSION,
                ARG_DUMP_CONFIGURATION_ITEMS,
                ARG_DUMP_BUS_PROPERTIES,
                ARG_BUS_INTROSPECT,
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
                { "log-time",                 optional_argument, NULL, ARG_LOG_TIME                 },
                { "unit",                     required_argument, NULL, ARG_UNIT                     },
                { "system",                   no_argument,       NULL, ARG_SYSTEM                   },
                { "user",                     no_argument,       NULL, ARG_USER                     },
                { "test",                     no_argument,       NULL, ARG_TEST                     },
                { "no-pager",                 no_argument,       NULL, ARG_NO_PAGER                 },
                { "help",                     no_argument,       NULL, 'h'                          },
                { "version",                  no_argument,       NULL, ARG_VERSION                  },
                { "dump-configuration-items", no_argument,       NULL, ARG_DUMP_CONFIGURATION_ITEMS },
                { "dump-bus-properties",      no_argument,       NULL, ARG_DUMP_BUS_PROPERTIES      },
                { "bus-introspect",           required_argument, NULL, ARG_BUS_INTROSPECT           },
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
        bool user_arg_seen = false;

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

                case ARG_LOG_TIME:

                        if (optarg) {
                                r = log_show_time_from_string(optarg);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse log time setting \"%s\": %m",
                                                               optarg);
                        } else
                                log_show_time(true);

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
                        user_arg_seen = true;
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

                case ARG_BUS_INTROSPECT:
                        arg_bus_introspect = optarg;
                        arg_action = ACTION_BUS_INTROSPECT;
                        break;

                case ARG_DUMP_CORE:
                        r = parse_boolean_argument("--dump-core", optarg, &arg_dump_core);
                        if (r < 0)
                                return r;
                        break;

                case ARG_CRASH_CHVT:
                        r = parse_crash_chvt(optarg, &arg_crash_chvt);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse crash virtual terminal index: \"%s\": %m",
                                                       optarg);
                        break;

                case ARG_CRASH_SHELL:
                        r = parse_boolean_argument("--crash-shell", optarg, &arg_crash_shell);
                        if (r < 0)
                                return r;
                        break;

                case ARG_CRASH_REBOOT:
                        r = parse_boolean_argument("--crash-reboot", optarg, &arg_crash_reboot);
                        if (r < 0)
                                return r;
                        break;

                case ARG_CONFIRM_SPAWN:
                        arg_confirm_spawn = mfree(arg_confirm_spawn);

                        r = parse_confirm_spawn(optarg, &arg_confirm_spawn);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse confirm spawn option: \"%s\": %m",
                                                       optarg);
                        break;

                case ARG_SERVICE_WATCHDOGS:
                        r = parse_boolean_argument("--service-watchdogs=", optarg, &arg_service_watchdogs);
                        if (r < 0)
                                return r;
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
                        if (fd < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Invalid deserialize fd: %d",
                                                       fd);

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
                        /* Just to eat away the sysvinit kernel cmdline args that we'll parse in
                         * parse_proc_cmdline_item() or ignore, without any getopt() error messages.
                         */
                case '?':
                        if (getpid_cached() != 1)
                                return -EINVAL;
                        else
                                return 0;

                default:
                        assert_not_reached("Unhandled option code.");
                }

        if (optind < argc && getpid_cached() != 1)
                /* Hmm, when we aren't run as init system let's complain about excess arguments */
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Excess arguments.");

        if (arg_action == ACTION_RUN && !arg_system && !user_arg_seen)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Explicit --user argument required to run as user manager.");

        return 0;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...]\n\n"
               "%sStarts and monitors system and user services.%s\n\n"
               "This program takes no positional arguments.\n\n"
               "%sOptions%s:\n"
               "  -h --help                      Show this help\n"
               "     --version                   Show version\n"
               "     --test                      Determine initial transaction, dump it and exit\n"
               "     --system                    In combination with --test: operate as system service manager\n"
               "     --user                      In combination with --test: operate as per-user service manager\n"
               "     --no-pager                  Do not pipe output into a pager\n"
               "     --dump-configuration-items  Dump understood unit configuration items\n"
               "     --dump-bus-properties       Dump exposed bus properties\n"
               "     --bus-introspect=PATH       Write XML introspection data\n"
               "     --unit=UNIT                 Set default unit\n"
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
               "     --log-time[=BOOL]           Prefix log messages with current time\n"
               "     --default-standard-output=  Set default standard output for services\n"
               "     --default-standard-error=   Set default standard error output for services\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               ansi_underline(),
               ansi_normal(),
               link);

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
        int r;
#endif

#if BUMP_PROC_SYS_FS_FILE_MAX
        /* The maximum the kernel allows for this since 5.2 is LONG_MAX, use that. (Previously things were
         * different, but the operation would fail silently.) */
        r = sysctl_writef("fs/file-max", "%li\n", LONG_MAX);
        if (r < 0)
                log_full_errno(IN_SET(r, -EROFS, -EPERM, -EACCES) ? LOG_DEBUG : LOG_WARNING, r, "Failed to bump fs.file-max, ignoring: %m");
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

                r = sysctl_writef("fs/nr_open", "%i\n", v);
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
        struct rlimit new_rlimit;
        int r, nr;

        /* Get the underlying absolute limit the kernel enforces */
        nr = read_nr_open();

        /* Calculate the new limits to use for us. Never lower from what we inherited. */
        new_rlimit = (struct rlimit) {
                .rlim_cur = MAX((rlim_t) nr, saved_rlimit->rlim_cur),
                .rlim_max = MAX((rlim_t) nr, saved_rlimit->rlim_max),
        };

        /* Shortcut if nothing changes. */
        if (saved_rlimit->rlim_max >= new_rlimit.rlim_max &&
            saved_rlimit->rlim_cur >= new_rlimit.rlim_cur) {
                log_debug("RLIMIT_NOFILE is already as high or higher than we need it, not bumping.");
                return 0;
        }

        /* Bump up the resource limit for ourselves substantially, all the way to the maximum the kernel allows, for
         * both hard and soft. */
        r = setrlimit_closest(RLIMIT_NOFILE, &new_rlimit);
        if (r < 0)
                return log_warning_errno(r, "Setting RLIMIT_NOFILE failed, ignoring: %m");

        return 0;
}

static int bump_rlimit_memlock(struct rlimit *saved_rlimit) {
        struct rlimit new_rlimit;
        uint64_t mm;
        int r;

        /* BPF_MAP_TYPE_LPM_TRIE bpf maps are charged against RLIMIT_MEMLOCK, even if we have CAP_IPC_LOCK which should
         * normally disable such checks. We need them to implement IPAddressAllow= and IPAddressDeny=, hence let's bump
         * the value high enough for our user. */

        /* Using MAX() on resource limits only is safe if RLIM_INFINITY is > 0. POSIX declares that rlim_t
         * must be unsigned, hence this is a given, but let's make this clear here. */
        assert_cc(RLIM_INFINITY > 0);

        mm = physical_memory_scale(1, 8); /* Let's scale how much we allow to be locked by the amount of physical
                                           * RAM. We allow an eighth to be locked by us, just to pick a value. */

        new_rlimit = (struct rlimit) {
                .rlim_cur = MAX3(HIGH_RLIMIT_MEMLOCK, saved_rlimit->rlim_cur, mm),
                .rlim_max = MAX3(HIGH_RLIMIT_MEMLOCK, saved_rlimit->rlim_max, mm),
        };

        if (saved_rlimit->rlim_max >= new_rlimit.rlim_cur &&
            saved_rlimit->rlim_cur >= new_rlimit.rlim_max) {
                log_debug("RLIMIT_MEMLOCK is already as high or higher than we need it, not bumping.");
                return 0;
        }

        r = setrlimit_closest(RLIMIT_MEMLOCK, &new_rlimit);
        if (r < 0)
                return log_warning_errno(r, "Setting RLIMIT_MEMLOCK failed, ignoring: %m");

        return 0;
}

static void test_usr(void) {

        /* Check that /usr is either on the same file system as / or mounted already. */

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

        if (!show_status_on(arg_show_status))
                return 0;

        r = parse_os_release(NULL,
                             "PRETTY_NAME", &pretty_name,
                             "ANSI_COLOR", &ansi_color);
        if (r < 0)
                log_full_errno(r == -ENOENT ? LOG_DEBUG : LOG_WARNING, r,
                               "Failed to read os-release file, ignoring: %m");

        if (log_get_show_color())
                return status_printf(NULL, 0,
                                     "\nWelcome to \x1B[%sm%s\x1B[0m!\n",
                                     isempty(ansi_color) ? "1" : ansi_color,
                                     isempty(pretty_name) ? "Linux" : pretty_name);
        else
                return status_printf(NULL, 0,
                                     "\nWelcome to %s!\n",
                                     isempty(pretty_name) ? "Linux" : pretty_name);
}

static int write_container_id(void) {
        const char *c;
        int r = 0;  /* avoid false maybe-uninitialized warning */

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

        /* The kernels sets HOME=/ for init. Let's undo this. */
        if (path_equal_ptr(getenv("HOME"), "/"))
                assert_se(unsetenv("HOME") == 0);

        return 0;
}

static void redirect_telinit(int argc, char *argv[]) {

        /* This is compatibility support for SysV, where calling init as a user is identical to telinit. */

#if HAVE_SYSV_COMPAT
        if (getpid_cached() == 1)
                return;

        if (!invoked_as(argv, "init"))
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
        usec_t watchdog_timer = 0;

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

        if (log_get_show_time())
                command_line[pos++] = "--log-time";

        if (streq(shutdown_verb, "exit")) {
                command_line[pos++] = "--exit-code";
                command_line[pos++] = exit_code;
                xsprintf(exit_code, "%d", retval);
        }

        assert(pos < ELEMENTSOF(command_line));

        if (streq(shutdown_verb, "reboot"))
                watchdog_timer = arg_reboot_watchdog;
        else if (streq(shutdown_verb, "kexec"))
                watchdog_timer = arg_kexec_watchdog;

        if (watchdog_timer > 0 && watchdog_timer != USEC_INFINITY) {

                char *e;

                /* If we reboot or kexec let's set the shutdown
                 * watchdog and tell the shutdown binary to
                 * repeatedly ping it */
                r = watchdog_set_timeout(&watchdog_timer);
                watchdog_close(r < 0);

                /* Tell the binary how often to ping, ignore failure */
                if (asprintf(&e, "WATCHDOG_USEC="USEC_FMT, watchdog_timer) > 0)
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

        /* This is called very early on, before we parse the kernel command line or otherwise figure out why
         * we are running, but only once. */

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

        } else if (!in_initrd())
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

        r = clock_apply_epoch();
        if (r < 0)
                log_error_errno(r, "Current system time is before build time, but cannot correct: %m");
        else if (r > 0)
                log_info("System time before build time, advancing clock.");
}

static void apply_clock_update(void) {
        struct timespec ts;

        /* This is called later than initialize_clock(), i.e. after we parsed configuration files/kernel
         * command line and such. */

        if (arg_clock_usec == 0)
                return;

        if (getpid_cached() != 1)
                return;

        if (clock_settime(CLOCK_REALTIME, timespec_store(&ts, arg_clock_usec)) < 0)
                log_error_errno(errno, "Failed to set system clock to time specified on kernel command line: %m");
        else {
                char buf[FORMAT_TIMESTAMP_MAX];

                log_info("Set system clock to %s, as specified on the kernel command line.",
                         format_timestamp(buf, sizeof(buf), arg_clock_usec));
        }
}

static void cmdline_take_random_seed(void) {
        size_t suggested;
        int r;

        if (arg_random_seed_size == 0)
                return;

        if (getpid_cached() != 1)
                return;

        assert(arg_random_seed);
        suggested = random_pool_size();

        if (arg_random_seed_size < suggested)
                log_warning("Random seed specified on kernel command line has size %zu, but %zu bytes required to fill entropy pool.",
                            arg_random_seed_size, suggested);

        r = random_write_entropy(-1, arg_random_seed, arg_random_seed_size, true);
        if (r < 0) {
                log_warning_errno(r, "Failed to credit entropy specified on kernel command line, ignoring: %m");
                return;
        }

        log_notice("Successfully credited entropy passed on kernel command line.\n"
                   "Note that the seed provided this way is accessible to unprivileged programs. This functionality should not be used outside of testing environments.");
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

static void update_cpu_affinity(bool skip_setup) {
        _cleanup_free_ char *mask = NULL;

        if (skip_setup || !arg_cpu_affinity.set)
                return;

        assert(arg_cpu_affinity.allocated > 0);

        mask = cpu_set_to_string(&arg_cpu_affinity);
        log_debug("Setting CPU affinity to %s.", strnull(mask));

        if (sched_setaffinity(0, arg_cpu_affinity.allocated, arg_cpu_affinity.set) < 0)
                log_warning_errno(errno, "Failed to set CPU affinity: %m");
}

static void update_numa_policy(bool skip_setup) {
        int r;
        _cleanup_free_ char *nodes = NULL;
        const char * policy = NULL;

        if (skip_setup || !mpol_is_valid(numa_policy_get_type(&arg_numa_policy)))
                return;

        if (DEBUG_LOGGING) {
                policy = mpol_to_string(numa_policy_get_type(&arg_numa_policy));
                nodes = cpu_set_to_range_string(&arg_numa_policy.nodes);
                log_debug("Setting NUMA policy to %s, with nodes %s.", strnull(policy), strnull(nodes));
        }

        r = apply_numa_policy(&arg_numa_policy);
        if (r == -EOPNOTSUPP)
                log_debug_errno(r, "NUMA support not available, ignoring.");
        else if (r < 0)
                log_warning_errno(r, "Failed to set NUMA memory policy: %m");
}

static void filter_args(const char* dst[], unsigned *pos, char **src, int argc) {
        assert(dst);
        assert(pos);

        /* Copy some filtered arguments into the dst array from src. */
        for (int i = 1; i < argc; i++) {
                if (STR_IN_SET(src[i],
                               "--switched-root",
                               "--system",
                               "--user"))
                        continue;

                if (startswith(src[i], "--deserialize="))
                        continue;
                if (streq(src[i], "--deserialize")) {
                        i++;                            /* Skip the argument too */
                        continue;
                }

                /* Skip target unit designators. We already acted upon this information and have queued
                 * appropriate jobs. We don't want to redo all this after reexecution. */
                if (startswith(src[i], "--unit="))
                        continue;
                if (streq(src[i], "--unit")) {
                        i++;                            /* Skip the argument too */
                        continue;
                }

                if (startswith(src[i],
                               in_initrd() ? "rd.systemd.unit=" : "systemd.unit="))
                        continue;

                if (runlevel_to_target(src[i]))
                        continue;

                /* Seems we have a good old option. Let's pass it over to the new instance. */
                dst[*pos] = src[i];
                (*pos)++;
        }
}

static void do_reexecute(
                int argc,
                char* argv[],
                const struct rlimit *saved_rlimit_nofile,
                const struct rlimit *saved_rlimit_memlock,
                FDSet *fds,
                const char *switch_root_dir,
                const char *switch_root_init,
                const char **ret_error_message) {

        unsigned i, args_size;
        const char **args;
        int r;

        assert(saved_rlimit_nofile);
        assert(saved_rlimit_memlock);
        assert(ret_error_message);

        /* Close and disarm the watchdog, so that the new instance can reinitialize it, but doesn't get rebooted while
         * we do that */
        watchdog_close(true);

        /* Reset RLIMIT_NOFILE + RLIMIT_MEMLOCK back to the kernel defaults, so that the new systemd can pass
         * the kernel default to its child processes */
        if (saved_rlimit_nofile->rlim_cur != 0)
                (void) setrlimit(RLIMIT_NOFILE, saved_rlimit_nofile);
        if (saved_rlimit_memlock->rlim_cur != RLIM_INFINITY)
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

        args_size = argc + 6;
        args = newa(const char*, args_size);

        if (!switch_root_init) {
                char sfd[DECIMAL_STR_MAX(int)];

                /* First try to spawn ourselves with the right path, and with full serialization. We do this only if
                 * the user didn't specify an explicit init to spawn. */

                assert(arg_serialization);
                assert(fds);

                xsprintf(sfd, "%i", fileno(arg_serialization));

                i = 1;         /* Leave args[0] empty for now. */
                filter_args(args, &i, argv, argc);

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

                args[0] = SYSTEMD_BINARY_PATH;
                (void) execv(args[0], (char* const*) args);
                log_debug_errno(errno, "Failed to execute our own binary %s, trying fallback: %m", args[0]);
        }

        /* Try the fallback, if there is any, without any serialization. We pass the original argv[] and envp[]. (Well,
         * modulo the ordering changes due to getopt() in argv[], and some cleanups in envp[], but let's hope that
         * doesn't matter.) */

        arg_serialization = safe_fclose(arg_serialization);
        fds = fdset_free(fds);

        /* Reopen the console */
        (void) make_console_stdio();

        i = 1;         /* Leave args[0] empty for now. */
        for (int j = 1; j <= argc; j++)
                args[i++] = argv[j];
        assert(i <= args_size);

        /* Re-enable any blocked signals, especially important if we switch from initial ramdisk to init=... */
        (void) reset_all_signal_handlers();
        (void) reset_signal_mask();
        (void) rlimit_nofile_safe();

        if (switch_root_init) {
                args[0] = switch_root_init;
                (void) execve(args[0], (char* const*) args, saved_env);
                log_warning_errno(errno, "Failed to execute configured init %s, trying fallback: %m", args[0]);
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
                (void) execve(args[0], (char* const*) args, saved_env);
                log_error_errno(errno, "Failed to execute /bin/sh, giving up: %m");
        } else
                log_warning_errno(r, "Failed to execute /sbin/init, giving up: %m");

        *ret_error_message = "Failed to execute fallback shell";
}

static int invoke_main_loop(
                Manager *m,
                const struct rlimit *saved_rlimit_nofile,
                const struct rlimit *saved_rlimit_memlock,
                bool *ret_reexecute,
                int *ret_retval,                   /* Return parameters relevant for shutting down */
                const char **ret_shutdown_verb,    /* … */
                FDSet **ret_fds,                   /* Return parameters for reexecuting */
                char **ret_switch_root_dir,        /* … */
                char **ret_switch_root_init,       /* … */
                const char **ret_error_message) {

        int r;

        assert(m);
        assert(saved_rlimit_nofile);
        assert(saved_rlimit_memlock);
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

                        (void) parse_configuration(saved_rlimit_nofile, saved_rlimit_memlock);

                        set_manager_defaults(m);
                        set_manager_settings(m);

                        update_cpu_affinity(false);
                        update_numa_policy(false);

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
                        *ret_switch_root_dir = TAKE_PTR(m->switch_root);
                        *ret_switch_root_init = TAKE_PTR(m->switch_root_init);

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

                log_info("systemd " GIT_VERSION " running in %ssystem mode (%s)",
                         arg_action == ACTION_TEST ? "test " : "",
                         systemd_features);

                v = detect_virtualization();
                if (v > 0)
                        log_info("Detected virtualization %s.", virtualization_to_string(v));

                log_info("Detected architecture %s.", architecture_to_string(uname_architecture()));

                if (in_initrd()) {
                        *ret_first_boot = false;
                        log_info("Running in initial RAM disk.");
                } else {
                        int r;
                        _cleanup_free_ char *id_text = NULL;

                        /* Let's check whether we are in first boot.  We use /etc/machine-id as flag file
                         * for this: If it is missing or contains the value "uninitialized", this is the
                         * first boot.  In any other case, it is not.  This allows container managers and
                         * installers to provision a couple of files already.  If the container manager
                         * wants to provision the machine ID itself it should pass $container_uuid to PID 1. */

                        r = read_one_line_file("/etc/machine-id", &id_text);
                        if (r < 0 || streq(id_text, "uninitialized")) {
                                if (r < 0 && r != -ENOENT)
                                        log_warning_errno(r, "Unexpected error while reading /etc/machine-id, ignoring: %m");

                                *ret_first_boot = true;
                                log_info("Detected first boot.");
                        } else {
                                *ret_first_boot = false;
                                log_debug("Detected initialized system, this is not the first boot.");
                        }
                }
        } else {
                if (DEBUG_LOGGING) {
                        _cleanup_free_ char *t = NULL;

                        t = uid_to_name(getuid());
                        log_debug("systemd " GIT_VERSION " running in %suser mode for user " UID_FMT "/%s. (%s)",
                                  arg_action == ACTION_TEST ? " test" : "",
                                  getuid(), strna(t), systemd_features);
                }

                *ret_first_boot = false;
        }
}

static int initialize_runtime(
                bool skip_setup,
                bool first_boot,
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

        update_cpu_affinity(skip_setup);
        update_numa_policy(skip_setup);

        if (arg_system) {
                /* Make sure we leave a core dump without panicking the kernel. */
                install_crash_handler();

                if (!skip_setup) {
                        r = mount_cgroup_controllers();
                        if (r < 0) {
                                *ret_error_message = "Failed to mount cgroup hierarchies";
                                return r;
                        }

                        status_welcome();
                        (void) hostname_setup(true);
                        /* Force transient machine-id on first boot. */
                        machine_id_setup(NULL, first_boot, arg_machine_id, NULL);
                        (void) loopback_setup();
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
        } else {
                _cleanup_free_ char *p = NULL;

                /* Create the runtime directory and place the inaccessible device nodes there, if we run in
                 * user mode. In system mode mount_setup() already did that. */

                r = xdg_user_runtime_dir(&p, "/systemd");
                if (r < 0) {
                        *ret_error_message = "$XDG_RUNTIME_DIR is not set";
                        return log_emergency_errno(r, "Failed to determine $XDG_RUNTIME_DIR path: %m");
                }

                (void) mkdir_p_label(p, 0755);
                (void) make_inaccessible_nodes(p, UID_INVALID, GID_INVALID);
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
        const char *unit;
        Job *job;
        Unit *target;
        int r;

        if (arg_default_unit)
                unit = arg_default_unit;
        else if (in_initrd())
                unit = SPECIAL_INITRD_TARGET;
        else
                unit = SPECIAL_DEFAULT_TARGET;

        log_debug("Activating default unit: %s", unit);

        r = manager_load_startable_unit_or_warn(m, unit, NULL, &target);
        if (r < 0 && in_initrd() && !arg_default_unit) {
                /* Fall back to default.target, which we used to always use by default. Only do this if no
                 * explicit configuration was given. */

                log_info("Falling back to " SPECIAL_DEFAULT_TARGET ".");

                r = manager_load_startable_unit_or_warn(m, SPECIAL_DEFAULT_TARGET, NULL, &target);
        }
        if (r < 0) {
                log_info("Falling back to " SPECIAL_RESCUE_TARGET ".");

                r = manager_load_startable_unit_or_warn(m, SPECIAL_RESCUE_TARGET, NULL, &target);
                if (r < 0) {
                        *ret_error_message = r == -ERFKILL ? SPECIAL_RESCUE_TARGET " masked"
                                                           : "Failed to load " SPECIAL_RESCUE_TARGET;
                        return r;
                }
        }

        assert(target->load_state == UNIT_LOADED);

        r = manager_add_job(m, JOB_START, target, JOB_ISOLATE, NULL, &error, &job);
        if (r == -EPERM) {
                log_debug_errno(r, "Default target could not be isolated, starting instead: %s", bus_error_message(&error, r));

                sd_bus_error_free(&error);

                r = manager_add_job(m, JOB_START, target, JOB_REPLACE, NULL, &error, &job);
                if (r < 0) {
                        *ret_error_message = "Failed to start default target";
                        return log_emergency_errno(r, "Failed to start default target: %s", bus_error_message(&error, r));
                }

        } else if (r < 0) {
                *ret_error_message = "Failed to isolate default target";
                return log_emergency_errno(r, "Failed to isolate default target: %s", bus_error_message(&error, r));
        } else
                log_info("Queued %s job for default target %s.",
                         job_type_to_string(job->type),
                         unit_status_string(job->unit, NULL));

        m->default_unit_job_id = job->id;

        return 0;
}

static void save_rlimits(struct rlimit *saved_rlimit_nofile,
                         struct rlimit *saved_rlimit_memlock) {

        assert(saved_rlimit_nofile);
        assert(saved_rlimit_memlock);

        if (getrlimit(RLIMIT_NOFILE, saved_rlimit_nofile) < 0)
                log_warning_errno(errno, "Reading RLIMIT_NOFILE failed, ignoring: %m");

        if (getrlimit(RLIMIT_MEMLOCK, saved_rlimit_memlock) < 0)
                log_warning_errno(errno, "Reading RLIMIT_MEMLOCK failed, ignoring: %m");
}

static void fallback_rlimit_nofile(const struct rlimit *saved_rlimit_nofile) {
        struct rlimit *rl;

        if (arg_default_rlimit[RLIMIT_NOFILE])
                return;

        /* Make sure forked processes get limits based on the original kernel setting */

        rl = newdup(struct rlimit, saved_rlimit_nofile, 1);
        if (!rl) {
                log_oom();
                return;
        }

        /* Bump the hard limit for system services to a substantially higher value. The default
         * hard limit current kernels set is pretty low (4K), mostly for historical
         * reasons. According to kernel developers, the fd handling in recent kernels has been
         * optimized substantially enough, so that we can bump the limit now, without paying too
         * high a price in memory or performance. Note however that we only bump the hard limit,
         * not the soft limit. That's because select() works the way it works, and chokes on fds
         * >= 1024. If we'd bump the soft limit globally, it might accidentally happen to
         * unexpecting programs that they get fds higher than what they can process using
         * select(). By only bumping the hard limit but leaving the low limit as it is we avoid
         * this pitfall:  programs that are written by folks aware of the select() problem in mind
         * (and thus use poll()/epoll instead of select(), the way everybody should) can
         * explicitly opt into high fds by bumping their soft limit beyond 1024, to the hard limit
         * we pass. */
        if (arg_system) {
                int nr;

                /* Get the underlying absolute limit the kernel enforces */
                nr = read_nr_open();

                rl->rlim_max = MIN((rlim_t) nr, MAX(rl->rlim_max, (rlim_t) HIGH_RLIMIT_NOFILE));
        }

        /* If for some reason we were invoked with a soft limit above 1024 (which should never
         * happen!, but who knows what we get passed in from pam_limit when invoked as --user
         * instance), then lower what we pass on to not confuse our children */
        rl->rlim_cur = MIN(rl->rlim_cur, (rlim_t) FD_SETSIZE);

        arg_default_rlimit[RLIMIT_NOFILE] = rl;
}

static void fallback_rlimit_memlock(const struct rlimit *saved_rlimit_memlock) {
        struct rlimit *rl;

        /* Pass the original value down to invoked processes */

        if (arg_default_rlimit[RLIMIT_MEMLOCK])
                return;

        rl = newdup(struct rlimit, saved_rlimit_memlock, 1);
        if (!rl) {
                log_oom();
                return;
        }

        arg_default_rlimit[RLIMIT_MEMLOCK] = rl;
}

static void setenv_manager_environment(void) {
        char **p;
        int r;

        STRV_FOREACH(p, arg_manager_environment) {
                log_debug("Setting '%s' in our own environment.", *p);

                r = putenv_dup(*p, true);
                if (r < 0)
                        log_warning_errno(errno, "Failed to setenv \"%s\", ignoring: %m", *p);
        }
}

static void reset_arguments(void) {
        /* Frees/resets arg_* variables, with a few exceptions commented below. */

        arg_default_unit = mfree(arg_default_unit);

        /* arg_system — ignore */

        arg_dump_core = true;
        arg_crash_chvt = -1;
        arg_crash_shell = false;
        arg_crash_reboot = false;
        arg_confirm_spawn = mfree(arg_confirm_spawn);
        arg_show_status = _SHOW_STATUS_INVALID;
        arg_status_unit_format = STATUS_UNIT_FORMAT_DEFAULT;
        arg_switched_root = false;
        arg_pager_flags = 0;
        arg_service_watchdogs = true;
        arg_default_std_output = EXEC_OUTPUT_JOURNAL;
        arg_default_std_error = EXEC_OUTPUT_INHERIT;
        arg_default_restart_usec = DEFAULT_RESTART_USEC;
        arg_default_timeout_start_usec = DEFAULT_TIMEOUT_USEC;
        arg_default_timeout_stop_usec = DEFAULT_TIMEOUT_USEC;
        arg_default_timeout_abort_usec = DEFAULT_TIMEOUT_USEC;
        arg_default_timeout_abort_set = false;
        arg_default_start_limit_interval = DEFAULT_START_LIMIT_INTERVAL;
        arg_default_start_limit_burst = DEFAULT_START_LIMIT_BURST;
        arg_runtime_watchdog = 0;
        arg_reboot_watchdog = 10 * USEC_PER_MINUTE;
        arg_kexec_watchdog = 0;
        arg_early_core_pattern = NULL;
        arg_watchdog_device = NULL;

        arg_default_environment = strv_free(arg_default_environment);
        arg_manager_environment = strv_free(arg_manager_environment);
        rlimit_free_all(arg_default_rlimit);

        arg_capability_bounding_set = CAP_ALL;
        arg_no_new_privs = false;
        arg_timer_slack_nsec = NSEC_INFINITY;
        arg_default_timer_accuracy_usec = 1 * USEC_PER_MINUTE;

        arg_syscall_archs = set_free(arg_syscall_archs);

        /* arg_serialization — ignore */

        arg_default_cpu_accounting = -1;
        arg_default_io_accounting = false;
        arg_default_ip_accounting = false;
        arg_default_blockio_accounting = false;
        arg_default_memory_accounting = MEMORY_ACCOUNTING_DEFAULT;
        arg_default_tasks_accounting = true;
        arg_default_tasks_max = DEFAULT_TASKS_MAX;
        arg_machine_id = (sd_id128_t) {};
        arg_cad_burst_action = EMERGENCY_ACTION_REBOOT_FORCE;
        arg_default_oom_policy = OOM_STOP;

        cpu_set_reset(&arg_cpu_affinity);
        numa_policy_reset(&arg_numa_policy);

        arg_random_seed = mfree(arg_random_seed);
        arg_random_seed_size = 0;
        arg_clock_usec = 0;
}

static int parse_configuration(const struct rlimit *saved_rlimit_nofile,
                               const struct rlimit *saved_rlimit_memlock) {
        int r;

        assert(saved_rlimit_nofile);
        assert(saved_rlimit_memlock);

        /* Assign configuration defaults */
        reset_arguments();

        r = parse_config_file();
        if (r < 0)
                log_warning_errno(r, "Failed to parse config file, ignoring: %m");

        if (arg_system) {
                r = proc_cmdline_parse(parse_proc_cmdline_item, NULL, 0);
                if (r < 0)
                        log_warning_errno(r, "Failed to parse kernel command line, ignoring: %m");
        }

        /* Initialize some default rlimits for services if they haven't been configured */
        fallback_rlimit_nofile(saved_rlimit_nofile);
        fallback_rlimit_memlock(saved_rlimit_memlock);

        /* Note that this also parses bits from the kernel command line, including "debug". */
        log_parse_environment();

        /* Initialize the show status setting if it hasn't been set explicitly yet */
        if (arg_show_status == _SHOW_STATUS_INVALID)
                arg_show_status = SHOW_STATUS_YES;

        /* Push variables into the manager environment block */
        setenv_manager_environment();

        /* Parse log environment variables again to take into account any new environment variables. */
        log_parse_environment();

        return 0;
}

static int safety_checks(void) {

        if (getpid_cached() == 1 &&
            arg_action != ACTION_RUN)
                return log_error_errno(SYNTHETIC_ERRNO(EPERM),
                                       "Unsupported execution mode while PID 1.");

        if (getpid_cached() == 1 &&
            !arg_system)
                return log_error_errno(SYNTHETIC_ERRNO(EPERM),
                                       "Can't run --user mode as PID 1.");

        if (arg_action == ACTION_RUN &&
            arg_system &&
            getpid_cached() != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EPERM),
                                       "Can't run system mode unless PID 1.");

        if (arg_action == ACTION_TEST &&
            geteuid() == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EPERM),
                                       "Don't run test mode as root.");

        if (!arg_system &&
            arg_action == ACTION_RUN &&
            sd_booted() <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Trying to run as user instance, but the system has not been booted with systemd.");

        if (!arg_system &&
            arg_action == ACTION_RUN &&
            !getenv("XDG_RUNTIME_DIR"))
                return log_error_errno(SYNTHETIC_ERRNO(EUNATCH),
                                       "Trying to run as user instance, but $XDG_RUNTIME_DIR is not set.");

        if (arg_system &&
            arg_action == ACTION_RUN &&
            running_in_chroot() > 0)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Cannot be run in a chroot() environment.");

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

        r = mac_apparmor_setup();
        if (r < 0) {
                *ret_error_message = "Failed to load AppArmor policy";
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

        /* Determine if this is a reexecution or normal bootup. We do the full command line parsing much later, so
         * let's just have a quick peek here. Note that if we have switched root, do all the special setup things
         * anyway, even if in that case we also do deserialization. */

        for (int i = 1; i < argc; i++)
                if (streq(argv[i], "--switched-root"))
                        return false; /* If we switched root, don't skip the setup. */
                else if (streq(argv[i], "--deserialize"))
                        found_deserialize = true;

        return found_deserialize; /* When we are deserializing, then we are reexecuting, hence avoid the extensive setup */
}

static int save_env(void) {
        char **l;

        l = strv_copy(environ);
        if (!l)
                return -ENOMEM;

        strv_free_and_replace(saved_env, l);
        return 0;
}

int main(int argc, char *argv[]) {

        dual_timestamp initrd_timestamp = DUAL_TIMESTAMP_NULL, userspace_timestamp = DUAL_TIMESTAMP_NULL, kernel_timestamp = DUAL_TIMESTAMP_NULL,
                security_start_timestamp = DUAL_TIMESTAMP_NULL, security_finish_timestamp = DUAL_TIMESTAMP_NULL;
        struct rlimit saved_rlimit_nofile = RLIMIT_MAKE_CONST(0),
                saved_rlimit_memlock = RLIMIT_MAKE_CONST(RLIM_INFINITY); /* The original rlimits we passed
                                                                          * in. Note we use different values
                                                                          * for the two that indicate whether
                                                                          * these fields are initialized! */
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
        save_argc_argv(argc, argv);

        /* Save the original environment as we might need to restore it if we're requested to execute another
         * system manager later. */
        r = save_env();
        if (r < 0) {
                error_message = "Failed to copy environment block";
                goto finish;
        }

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

                                /* Let's open the log backend a second time, in case the first time didn't
                                 * work. Quite possibly we have mounted /dev just now, so /dev/kmsg became
                                 * available, and it previously wasn't. */
                                log_open();

                                disable_printk_ratelimit();

                                r = initialize_security(
                                                &loaded_policy,
                                                &security_start_timestamp,
                                                &security_finish_timestamp,
                                                &error_message);
                                if (r < 0)
                                        goto finish;
                        }

                        if (mac_selinux_init() < 0) {
                                error_message = "Failed to initialize SELinux support";
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

                        /* clear the kernel timestamp, because we are in a container */
                        kernel_timestamp = DUAL_TIMESTAMP_NULL;
                }

                initialize_coredump(skip_setup);

                r = fixup_environment();
                if (r < 0) {
                        log_emergency_errno(r, "Failed to fix up PID 1 environment: %m");
                        error_message = "Failed to fix up PID1 environment";
                        goto finish;
                }

                /* Try to figure out if we can use colors with the console. No need to do that for user instances since
                 * they never log into the console. */
                log_show_color(colors_enabled());

                r = make_null_stdio();
                if (r < 0)
                        log_warning_errno(r, "Failed to redirect standard streams to /dev/null, ignoring: %m");

                /* Load the kernel modules early. */
                if (!skip_setup)
                        kmod_setup();

                /* Mount /proc, /sys and friends, so that /proc/cmdline and /proc/$PID/fd is available. */
                r = mount_setup(loaded_policy, skip_setup);
                if (r < 0) {
                        error_message = "Failed to mount API filesystems";
                        goto finish;
                }

                /* The efivarfs is now mounted, let's read the random seed off it */
                (void) efi_take_random_seed();

                /* Cache command-line options passed from EFI variables */
                if (!skip_setup)
                        (void) cache_efi_options_variable();
        } else {
                /* Running as user instance */
                arg_system = false;
                log_set_target(LOG_TARGET_AUTO);
                log_open();

                /* clear the kernel timestamp, because we are not PID 1 */
                kernel_timestamp = DUAL_TIMESTAMP_NULL;

                if (mac_selinux_init() < 0) {
                        error_message = "Failed to initialize SELinux support";
                        goto finish;
                }
        }

        /* Save the original RLIMIT_NOFILE/RLIMIT_MEMLOCK so that we can reset it later when
         * transitioning from the initrd to the main systemd or suchlike. */
        save_rlimits(&saved_rlimit_nofile, &saved_rlimit_memlock);

        /* Reset all signal handlers. */
        (void) reset_all_signal_handlers();
        (void) ignore_signals(SIGNALS_IGNORE);

        (void) parse_configuration(&saved_rlimit_nofile, &saved_rlimit_memlock);

        r = parse_argv(argc, argv);
        if (r < 0) {
                error_message = "Failed to parse commandline arguments";
                goto finish;
        }

        r = safety_checks();
        if (r < 0)
                goto finish;

        if (IN_SET(arg_action, ACTION_TEST, ACTION_HELP, ACTION_DUMP_CONFIGURATION_ITEMS, ACTION_DUMP_BUS_PROPERTIES, ACTION_BUS_INTROSPECT))
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
        } else if (arg_action == ACTION_BUS_INTROSPECT) {
                r = bus_manager_introspect_implementations(stdout, arg_bus_introspect);
                retval = r >= 0 ? EXIT_SUCCESS : EXIT_FAILURE;
                goto finish;
        }

        assert_se(IN_SET(arg_action, ACTION_RUN, ACTION_TEST));

        /* Move out of the way, so that we won't block unmounts */
        assert_se(chdir("/") == 0);

        if (arg_action == ACTION_RUN) {
                if (!skip_setup) {
                        /* Apply the systemd.clock_usec= kernel command line switch */
                        apply_clock_update();

                        /* Apply random seed from kernel command line */
                        cmdline_take_random_seed();
                }

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
                               first_boot,
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
                manager_test_summary(m);
                retval = EXIT_SUCCESS;
                goto finish;
        }

        (void) invoke_main_loop(m,
                                &saved_rlimit_nofile,
                                &saved_rlimit_memlock,
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
                arg_reboot_watchdog = manager_get_watchdog(m, WATCHDOG_REBOOT);
                arg_kexec_watchdog = manager_get_watchdog(m, WATCHDOG_KEXEC);
                m = manager_free(m);
        }

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

        saved_env = strv_free(saved_env);

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
                reset_arguments();
                return retval;
        }
#endif

#if HAS_FEATURE_ADDRESS_SANITIZER
        __lsan_do_leak_check();
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
                                              "%s.", error_message);
                freeze_or_exit_or_reboot();
        }

        reset_arguments();
        return retval;
}
