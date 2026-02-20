/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-daemon.h"
#include "sd-event.h"
#include "sd-json.h"

#include "alloc-util.h"
#include "argv-util.h"
#include "ask-password-agent.h"
#include "build.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-map-properties.h"
#include "bus-message-util.h"
#include "bus-unit-util.h"
#include "bus-util.h"
#include "bus-wait-for-jobs.h"
#include "calendarspec.h"
#include "capability-util.h"
#include "capsule-util.h"
#include "chase.h"
#include "env-util.h"
#include "errno-util.h"
#include "escape.h"
#include "event-util.h"
#include "exec-util.h"
#include "exit-status.h"
#include "fd-util.h"
#include "fork-notify.h"
#include "format-table.h"
#include "format-util.h"
#include "fs-util.h"
#include "hostname-util.h"
#include "log.h"
#include "main-func.h"
#include "osc-context.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "pidref.h"
#include "polkit-agent.h"
#include "pretty-print.h"
#include "process-util.h"
#include "ptyfwd.h"
#include "runtime-scope.h"
#include "signal-util.h"
#include "special.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "time-util.h"
#include "unit-def.h"
#include "unit-name.h"
#include "user-util.h"
#include "virt.h"

static bool arg_ask_password = true;
static bool arg_scope = false;
static bool arg_remain_after_exit = false;
static bool arg_no_block = false;
static bool arg_wait = false;
static const char *arg_unit = NULL;
static char *arg_description = NULL;
static char *arg_slice = NULL;
static bool arg_slice_inherit = false;
static bool arg_expand_environment = true;
static bool arg_send_sighup = false;
static BusTransport arg_transport = BUS_TRANSPORT_LOCAL;
static const char *arg_host = NULL;
static RuntimeScope arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
static const char *arg_service_type = NULL;
static char *arg_exec_user = NULL;
static const char *arg_exec_group = NULL;
static int arg_nice = 0;
static bool arg_nice_set = false;
static char **arg_environment = NULL;
static char **arg_property = NULL;
static enum {
        ARG_STDIO_NONE   = 0,      /* The default, as it is for normal services, stdin connected to
                                    * /dev/null, and stdout+stderr to the journal */
        ARG_STDIO_PTY    = 1 << 0, /* Interactive behaviour, requested by --pty/--pty-late: we allocate a pty
                                    * and connect it to the TTY we are invoked from */
        ARG_STDIO_DIRECT = 1 << 1, /* Directly pass our stdin/stdout/stderr to the activated service, useful
                                    * for usage in shell pipelines, requested by --pipe */
        ARG_STDIO_AUTO   = ARG_STDIO_PTY | ARG_STDIO_DIRECT,
                                   /* If --pipe and --pty/--pty-late are used together we use --pty/--pty-late
                                    * when invoked on a TTY, and --pipe otherwise */
} arg_stdio = ARG_STDIO_NONE;
static int arg_pty_late = -1; /* tristate */
static char **arg_path_property = NULL;
static char **arg_socket_property = NULL;
static char **arg_timer_property = NULL;
static bool arg_with_timer = false;
static bool arg_quiet = false;
static bool arg_verbose = false;
static bool arg_aggressive_gc = false;
static char *arg_working_directory = NULL;
static char *arg_root_directory = NULL;
static bool arg_shell = false;
static JobMode arg_job_mode = JOB_FAIL;
static char **arg_cmdline = NULL;
static char *arg_exec_path = NULL;
static bool arg_ignore_failure = false;
static char *arg_background = NULL;
static PagerFlags arg_pager_flags = 0;
static sd_json_format_flags_t arg_json_format_flags = SD_JSON_FORMAT_OFF;
static char *arg_shell_prompt_prefix = NULL;
static int arg_lightweight = -1;
static char *arg_area = NULL;
static bool arg_via_shell = false;
static bool arg_empower = false;

STATIC_DESTRUCTOR_REGISTER(arg_description, freep);
STATIC_DESTRUCTOR_REGISTER(arg_slice, freep);
STATIC_DESTRUCTOR_REGISTER(arg_exec_user, freep);
STATIC_DESTRUCTOR_REGISTER(arg_environment, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_property, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_path_property, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_socket_property, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_timer_property, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_working_directory, freep);
STATIC_DESTRUCTOR_REGISTER(arg_cmdline, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_exec_path, freep);
STATIC_DESTRUCTOR_REGISTER(arg_background, freep);
STATIC_DESTRUCTOR_REGISTER(arg_shell_prompt_prefix, freep);
STATIC_DESTRUCTOR_REGISTER(arg_area, freep);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        pager_open(arg_pager_flags);

        r = terminal_urlify_man("systemd-run", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] COMMAND [ARGUMENTS...]\n"
               "\n%5$sRun the specified command in a transient scope or service.%6$s\n\n"
               "  -h --help                       Show this help\n"
               "     --version                    Show package version\n"
               "     --no-ask-password            Do not prompt for password\n"
               "     --user                       Run as user unit\n"
               "  -H --host=[USER@]HOST           Operate on remote host\n"
               "  -M --machine=CONTAINER          Operate on local container\n"
               "     --scope                      Run this as scope rather than service\n"
               "  -u --unit=UNIT                  Run under the specified unit name\n"
               "  -p --property=NAME=VALUE        Set service or scope unit property\n"
               "     --description=TEXT           Description for unit\n"
               "     --slice=SLICE                Run in the specified slice\n"
               "     --slice-inherit              Inherit the slice from the caller\n"
               "     --expand-environment=BOOL    Control expansion of environment variables\n"
               "     --no-block                   Do not wait until operation finished\n"
               "  -r --remain-after-exit          Leave service around until explicitly stopped\n"
               "     --wait                       Wait until service stopped again\n"
               "     --send-sighup                Send SIGHUP when terminating\n"
               "     --service-type=TYPE          Service type\n"
               "     --uid=USER                   Run as system user\n"
               "     --gid=GROUP                  Run as system group\n"
               "     --nice=NICE                  Nice level\n"
               "     --working-directory=PATH     Set working directory\n"
               "  -d --same-dir                   Inherit working directory from caller\n"
               "     --root-directory=PATH        Set root directory\n"
               "  -R --same-root-dir              Inherit root directory from caller\n"
               "  -E --setenv=NAME[=VALUE]        Set environment variable\n"
               "  -t --pty                        Run service on pseudo TTY as STDIN/STDOUT/\n"
               "                                  STDERR\n"
               "  -T --pty-late                   Just like --pty, but leave TTY access to\n"
               "                                  agents until unit is started up\n"
               "  -P --pipe                       Pass STDIN/STDOUT/STDERR directly to service\n"
               "  -q --quiet                      Suppress information messages during runtime\n"
               "  -v --verbose                    Show unit logs while executing operation\n"
               "     --json=pretty|short|off      Print unit name and invocation id as JSON\n"
               "  -G --collect                    Unload unit after it ran, even when failed\n"
               "  -S --shell                      Invoke a $SHELL interactively\n"
               "     --job-mode=MODE              Specify how to deal with already queued jobs,\n"
               "                                  when queueing a new job\n"
               "     --ignore-failure             Ignore the exit status of the invoked process\n"
               "     --background=COLOR           Set ANSI color for background\n"
               "     --no-pager                   Do not pipe output into a pager\n"
               "\n%3$sPath options:%4$s\n"
               "     --path-property=NAME=VALUE   Set path unit property\n"
               "\n%3$sSocket options:%4$s\n"
               "     --socket-property=NAME=VALUE Set socket unit property\n"
               "\n%3$sTimer options:%4$s\n"
               "     --on-active=SECONDS          Run after SECONDS delay\n"
               "     --on-boot=SECONDS            Run SECONDS after machine was booted up\n"
               "     --on-startup=SECONDS         Run SECONDS after systemd activation\n"
               "     --on-unit-active=SECONDS     Run SECONDS after the last activation\n"
               "     --on-unit-inactive=SECONDS   Run SECONDS after the last deactivation\n"
               "     --on-calendar=SPEC           Realtime timer\n"
               "     --on-timezone-change         Run when the timezone changes\n"
               "     --on-clock-change            Run when the realtime clock jumps\n"
               "     --timer-property=NAME=VALUE  Set timer unit property\n"
               "\nSee the %2$s for details.\n",
               program_invocation_short_name,
               link,
               ansi_underline(), ansi_normal(),
               ansi_highlight(), ansi_normal());

        return 0;
}

static int help_sudo_mode(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("run0", "1", &link);
        if (r < 0)
                return log_oom();

        /* NB: Let's not go overboard with short options: we try to keep a modicum of compatibility with
         * sudo's short switches, hence please do not introduce new short switches unless they have a roughly
         * equivalent purpose on sudo. Use long options for everything private to run0. */

        printf("%s [OPTIONS...] COMMAND [ARGUMENTS...]\n"
               "\n%sElevate privileges interactively.%s\n\n"
               "  -h --help                       Show this help\n"
               "  -V --version                    Show package version\n"
               "     --no-ask-password            Do not prompt for password\n"
               "     --machine=CONTAINER          Operate on local container\n"
               "     --unit=UNIT                  Run under the specified unit name\n"
               "     --property=NAME=VALUE        Set service or scope unit property\n"
               "     --description=TEXT           Description for unit\n"
               "     --slice=SLICE                Run in the specified slice\n"
               "     --slice-inherit              Inherit the slice\n"
               "  -u --user=USER                  Run as system user\n"
               "  -g --group=GROUP                Run as system group\n"
               "     --nice=NICE                  Nice level\n"
               "  -D --chdir=PATH                 Set working directory\n"
               "     --via-shell                  Invoke command via target user's login shell\n"
               "  -i                              Shortcut for --via-shell --chdir='~'\n"
               "     --setenv=NAME[=VALUE]        Set environment variable\n"
               "     --background=COLOR           Set ANSI color for background\n"
               "     --pty                        Request allocation of a pseudo TTY for stdio\n"
               "     --pty-late                   Just like --pty, but leave TTY access to agents\n"
               "                                  until unit is started up\n"
               "     --pipe                       Request direct pipe for stdio\n"
               "     --shell-prompt-prefix=PREFIX Set $SHELL_PROMPT_PREFIX\n"
               "     --lightweight=BOOLEAN        Control whether to register a session with service manager\n"
               "                                  or without\n"
               "     --area=AREA                  Home area to log into\n"
               "     --empower                    Give privileges to selected or current user\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
}

static bool become_root(void) {
        if (arg_runtime_scope != RUNTIME_SCOPE_SYSTEM)
                return false;

        if (!arg_exec_user) {
                assert(!arg_empower); /* assume default user has been set */
                return true;
        }

        return STR_IN_SET(arg_exec_user, "root", "0");
}

static int add_timer_property(const char *name, const char *val) {
        char *p;

        assert(name);
        assert(val);

        p = strjoin(name, "=", val);
        if (!p)
                return log_oom();

        if (strv_consume(&arg_timer_property, p) < 0)
                return log_oom();

        return 0;
}

static char** make_login_shell_cmdline(const char *shell) {
        _cleanup_free_ char *argv0 = NULL;

        assert(shell);

        argv0 = strjoin("-", shell); /* The - is how shells determine if they shall be consider login shells */
        if (!argv0)
                return NULL;

        return strv_new(argv0);
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_USER,
                ARG_SYSTEM,
                ARG_SCOPE,
                ARG_DESCRIPTION,
                ARG_SLICE,
                ARG_SLICE_INHERIT,
                ARG_EXPAND_ENVIRONMENT,
                ARG_SEND_SIGHUP,
                ARG_SERVICE_TYPE,
                ARG_EXEC_USER,
                ARG_EXEC_GROUP,
                ARG_NICE,
                ARG_ON_ACTIVE,
                ARG_ON_BOOT,
                ARG_ON_STARTUP,
                ARG_ON_UNIT_ACTIVE,
                ARG_ON_UNIT_INACTIVE,
                ARG_ON_CALENDAR,
                ARG_ON_TIMEZONE_CHANGE,
                ARG_ON_CLOCK_CHANGE,
                ARG_TIMER_PROPERTY,
                ARG_PATH_PROPERTY,
                ARG_SOCKET_PROPERTY,
                ARG_NO_BLOCK,
                ARG_NO_ASK_PASSWORD,
                ARG_WAIT,
                ARG_WORKING_DIRECTORY,
                ARG_ROOT_DIRECTORY,
                ARG_JOB_MODE,
                ARG_IGNORE_FAILURE,
                ARG_BACKGROUND,
                ARG_NO_PAGER,
                ARG_JSON,
        };

        static const struct option options[] = {
                { "help",               no_argument,       NULL, 'h'                    },
                { "version",            no_argument,       NULL, ARG_VERSION            },
                { "user",               no_argument,       NULL, ARG_USER               },
                { "system",             no_argument,       NULL, ARG_SYSTEM             },
                { "capsule",            required_argument, NULL, 'C'                    },
                { "scope",              no_argument,       NULL, ARG_SCOPE              },
                { "unit",               required_argument, NULL, 'u'                    },
                { "description",        required_argument, NULL, ARG_DESCRIPTION        },
                { "slice",              required_argument, NULL, ARG_SLICE              },
                { "slice-inherit",      no_argument,       NULL, ARG_SLICE_INHERIT      },
                { "remain-after-exit",  no_argument,       NULL, 'r'                    },
                { "expand-environment", required_argument, NULL, ARG_EXPAND_ENVIRONMENT },
                { "send-sighup",        no_argument,       NULL, ARG_SEND_SIGHUP        },
                { "host",               required_argument, NULL, 'H'                    },
                { "machine",            required_argument, NULL, 'M'                    },
                { "service-type",       required_argument, NULL, ARG_SERVICE_TYPE       },
                { "wait",               no_argument,       NULL, ARG_WAIT               },
                { "uid",                required_argument, NULL, ARG_EXEC_USER          },
                { "gid",                required_argument, NULL, ARG_EXEC_GROUP         },
                { "nice",               required_argument, NULL, ARG_NICE               },
                { "setenv",             required_argument, NULL, 'E'                    },
                { "property",           required_argument, NULL, 'p'                    },
                { "tty",                no_argument,       NULL, 't'                    }, /* deprecated alias */
                { "pty",                no_argument,       NULL, 't'                    },
                { "pty-late",           no_argument,       NULL, 'T'                    },
                { "pipe",               no_argument,       NULL, 'P'                    },
                { "quiet",              no_argument,       NULL, 'q'                    },
                { "verbose",            no_argument,       NULL, 'v'                    },
                { "on-active",          required_argument, NULL, ARG_ON_ACTIVE          },
                { "on-boot",            required_argument, NULL, ARG_ON_BOOT            },
                { "on-startup",         required_argument, NULL, ARG_ON_STARTUP         },
                { "on-unit-active",     required_argument, NULL, ARG_ON_UNIT_ACTIVE     },
                { "on-unit-inactive",   required_argument, NULL, ARG_ON_UNIT_INACTIVE   },
                { "on-calendar",        required_argument, NULL, ARG_ON_CALENDAR        },
                { "on-timezone-change", no_argument,       NULL, ARG_ON_TIMEZONE_CHANGE },
                { "on-clock-change",    no_argument,       NULL, ARG_ON_CLOCK_CHANGE    },
                { "timer-property",     required_argument, NULL, ARG_TIMER_PROPERTY     },
                { "path-property",      required_argument, NULL, ARG_PATH_PROPERTY      },
                { "socket-property",    required_argument, NULL, ARG_SOCKET_PROPERTY    },
                { "no-block",           no_argument,       NULL, ARG_NO_BLOCK           },
                { "no-ask-password",    no_argument,       NULL, ARG_NO_ASK_PASSWORD    },
                { "collect",            no_argument,       NULL, 'G'                    },
                { "working-directory",  required_argument, NULL, ARG_WORKING_DIRECTORY  },
                { "same-dir",           no_argument,       NULL, 'd'                    },
                { "root-directory",     required_argument, NULL, ARG_ROOT_DIRECTORY     },
                { "same-root-dir",      no_argument,       NULL, 'R'                    },
                { "shell",              no_argument,       NULL, 'S'                    },
                { "job-mode",           required_argument, NULL, ARG_JOB_MODE           },
                { "ignore-failure",     no_argument,       NULL, ARG_IGNORE_FAILURE     },
                { "background",         required_argument, NULL, ARG_BACKGROUND         },
                { "no-pager",           no_argument,       NULL, ARG_NO_PAGER           },
                { "json",               required_argument, NULL, ARG_JSON               },
                {},
        };

        bool with_trigger = false, same_dir = false;
        int r, c;

        assert(argc >= 0);
        assert(argv);

        /* Resetting to 0 forces the invocation of an internal initialization routine of getopt_long()
         * that checks for GNU extensions in optstring ('-' or '+' at the beginning). */
        optind = 0;
        while ((c = getopt_long(argc, argv, "+hrC:H:M:E:p:tTPqvGdSu:", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_NO_ASK_PASSWORD:
                        arg_ask_password = false;
                        break;

                case ARG_USER:
                        arg_runtime_scope = RUNTIME_SCOPE_USER;
                        break;

                case ARG_SYSTEM:
                        arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
                        break;

                case 'C':
                        r = capsule_name_is_valid(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Unable to validate capsule name '%s': %m", optarg);
                        if (r == 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid capsule name: %s", optarg);

                        arg_host = optarg;
                        arg_transport = BUS_TRANSPORT_CAPSULE;
                        arg_runtime_scope = RUNTIME_SCOPE_USER;
                        break;

                case ARG_SCOPE:
                        arg_scope = true;
                        break;

                case 'u':
                        arg_unit = optarg;
                        break;

                case ARG_DESCRIPTION:
                        r = free_and_strdup_warn(&arg_description, optarg);
                        if (r < 0)
                                return r;
                        break;

                case ARG_SLICE:
                        r = free_and_strdup_warn(&arg_slice, optarg);
                        if (r < 0)
                                return r;
                        break;

                case ARG_SLICE_INHERIT:
                        arg_slice_inherit = true;
                        break;

                case ARG_EXPAND_ENVIRONMENT:
                        r = parse_boolean_argument("--expand-environment=", optarg, &arg_expand_environment);
                        if (r < 0)
                                return r;
                        break;

                case ARG_SEND_SIGHUP:
                        arg_send_sighup = true;
                        break;

                case 'r':
                        arg_remain_after_exit = true;
                        break;

                case 'H':
                        arg_transport = BUS_TRANSPORT_REMOTE;
                        arg_host = optarg;
                        break;

                case 'M':
                        r = parse_machine_argument(optarg, &arg_host, &arg_transport);
                        if (r < 0)
                                return r;
                        break;

                case ARG_SERVICE_TYPE:
                        arg_service_type = optarg;
                        break;

                case ARG_EXEC_USER:
                        r = free_and_strdup_warn(&arg_exec_user, optarg);
                        if (r < 0)
                                return r;
                        break;

                case ARG_EXEC_GROUP:
                        arg_exec_group = optarg;
                        break;

                case ARG_NICE:
                        r = parse_nice(optarg, &arg_nice);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse nice value: %s", optarg);

                        arg_nice_set = true;
                        break;

                case 'E':
                        r = strv_env_replace_strdup_passthrough(&arg_environment, optarg);
                        if (r < 0)
                                return log_error_errno(r, "Cannot assign environment variable %s: %m", optarg);

                        break;

                case 'p':
                        if (strv_extend(&arg_property, optarg) < 0)
                                return log_oom();

                        break;

                case 'T': /* --pty-late */
                case 't': /* --pty */
                        arg_stdio |= ARG_STDIO_PTY;
                        arg_pty_late = c == 'T';
                        break;

                case 'P': /* --pipe */
                        arg_stdio |= ARG_STDIO_DIRECT;
                        break;

                case 'q':
                        arg_quiet = true;
                        break;

                case 'v':
                        arg_verbose = true;
                        break;

                case ARG_ON_ACTIVE:
                        r = add_timer_property("OnActiveSec", optarg);
                        if (r < 0)
                                return r;

                        arg_with_timer = true;
                        break;

                case ARG_ON_BOOT:
                        r = add_timer_property("OnBootSec", optarg);
                        if (r < 0)
                                return r;

                        arg_with_timer = true;
                        break;

                case ARG_ON_STARTUP:
                        r = add_timer_property("OnStartupSec", optarg);
                        if (r < 0)
                                return r;

                        arg_with_timer = true;
                        break;

                case ARG_ON_UNIT_ACTIVE:
                        r = add_timer_property("OnUnitActiveSec", optarg);
                        if (r < 0)
                                return r;

                        arg_with_timer = true;
                        break;

                case ARG_ON_UNIT_INACTIVE:
                        r = add_timer_property("OnUnitInactiveSec", optarg);
                        if (r < 0)
                                return r;

                        arg_with_timer = true;
                        break;

                case ARG_ON_CALENDAR: {
                        _cleanup_(calendar_spec_freep) CalendarSpec *cs = NULL;

                        r = calendar_spec_from_string(optarg, &cs);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse calendar event specification: %m");

                        /* Let's make sure the given calendar event is not in the past */
                        r = calendar_spec_next_usec(cs, now(CLOCK_REALTIME), NULL);
                        if (r == -ENOENT)
                                /* The calendar event is in the past — let's warn about this, but install it
                                 * anyway as is. The service manager will trigger the service right away.
                                 * Moreover, the server side might have a different clock or timezone than we
                                 * do, hence it should decide when or whether to run something. */
                                log_warning("Specified calendar expression is in the past, proceeding anyway.");
                        else if (r < 0)
                                return log_error_errno(r, "Failed to calculate next time calendar expression elapses: %m");

                        r = add_timer_property("OnCalendar", optarg);
                        if (r < 0)
                                return r;

                        arg_with_timer = true;
                        break;
                }

                case ARG_ON_TIMEZONE_CHANGE:
                        r = add_timer_property("OnTimezoneChange", "yes");
                        if (r < 0)
                                return r;

                        arg_with_timer = true;
                        break;

                case ARG_ON_CLOCK_CHANGE:
                        r = add_timer_property("OnClockChange", "yes");
                        if (r < 0)
                                return r;

                        arg_with_timer = true;
                        break;

                case ARG_TIMER_PROPERTY:

                        if (strv_extend(&arg_timer_property, optarg) < 0)
                                return log_oom();

                        arg_with_timer = arg_with_timer ||
                                STARTSWITH_SET(optarg,
                                               "OnActiveSec=",
                                               "OnBootSec=",
                                               "OnStartupSec=",
                                               "OnUnitActiveSec=",
                                               "OnUnitInactiveSec=",
                                               "OnCalendar=");
                        break;

                case ARG_PATH_PROPERTY:

                        if (strv_extend(&arg_path_property, optarg) < 0)
                                return log_oom();

                        break;

                case ARG_SOCKET_PROPERTY:

                        if (strv_extend(&arg_socket_property, optarg) < 0)
                                return log_oom();

                        break;

                case ARG_NO_BLOCK:
                        arg_no_block = true;
                        break;

                case ARG_WAIT:
                        arg_wait = true;
                        break;

                case ARG_WORKING_DIRECTORY:
                        r = parse_path_argument(optarg, true, &arg_working_directory);
                        if (r < 0)
                                return r;

                        same_dir = false;
                        break;

                case 'd': {
                        _cleanup_free_ char *p = NULL;

                        r = safe_getcwd(&p);
                        if (r < 0)
                                return log_error_errno(r, "Failed to get current working directory: %m");

                        if (empty_or_root(p))
                                arg_working_directory = mfree(arg_working_directory);
                        else
                                free_and_replace(arg_working_directory, p);

                        same_dir = true;
                        break;
                }

                case ARG_ROOT_DIRECTORY:
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_root_directory);
                        if (r < 0)
                                return r;

                        break;

                case 'R':
                        r = free_and_strdup_warn(&arg_root_directory, "/");
                        if (r < 0)
                                return r;

                        break;

                case 'G':
                        arg_aggressive_gc = true;
                        break;

                case 'S':
                        arg_shell = true;
                        break;

                case ARG_JOB_MODE:
                        if (streq(optarg, "help"))
                                return DUMP_STRING_TABLE(job_mode, JobMode, _JOB_MODE_MAX);

                        r = job_mode_from_string(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Invalid job mode: %s", optarg);

                        arg_job_mode = r;
                        break;

                case ARG_IGNORE_FAILURE:
                        arg_ignore_failure = true;
                        break;

                case ARG_BACKGROUND:
                        r = parse_background_argument(optarg, &arg_background);
                        if (r < 0)
                                return r;
                        break;

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_JSON:
                        r = parse_json_argument(optarg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        /* If we are talking to the per-user instance PolicyKit isn't going to help */
        if (arg_runtime_scope == RUNTIME_SCOPE_USER)
                arg_ask_password = false;

        with_trigger = !!arg_path_property || !!arg_socket_property || arg_with_timer;

        /* currently, only single trigger (path, socket, timer) unit can be created simultaneously */
        if (!!arg_path_property + !!arg_socket_property + (int) arg_with_timer > 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Only single trigger (path, socket, timer) unit can be created.");

        if (arg_shell) {
                /* If --shell is imply --pty --pipe --same-dir --service-type=exec --wait --collect, unless otherwise
                 * specified. */

                if (!arg_scope) {
                        if (arg_stdio == ARG_STDIO_NONE)
                                arg_stdio = ARG_STDIO_AUTO;

                        if (!arg_working_directory) {
                                r = safe_getcwd(&arg_working_directory);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to get current working directory: %m");
                        }

                        if (!arg_service_type)
                                arg_service_type = "exec";

                        arg_wait = true;
                }

                arg_aggressive_gc = true;
        }

        if (arg_stdio == ARG_STDIO_AUTO)
                /* If we both --pty/--pty-late and --pipe are specified we'll automatically pick --pty/--pty-late if we
                 * are connected fully to a TTY and pick direct fd passing otherwise. This way, we
                 * automatically adapt to usage in a shell pipeline, but we are neatly interactive with
                 * tty-level isolation otherwise. */
                arg_stdio = isatty_safe(STDIN_FILENO) && isatty_safe(STDOUT_FILENO) && isatty_safe(STDERR_FILENO) ?
                        ARG_STDIO_PTY :
                        ARG_STDIO_DIRECT;

        if (arg_pty_late < 0)
                arg_pty_late = false; /* For systemd-run this defaults to false, for compat reasons */

        if (argc > optind) {
                char **l;

                if (arg_shell)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "If --shell is used, no command line is expected.");

                l = strv_copy(argv + optind);
                if (!l)
                        return log_oom();

                strv_free_and_replace(arg_cmdline, l);

        } else if (arg_shell) {
                _cleanup_free_ char *s = NULL;
                char **l;

                r = get_shell(&s);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine shell: %m");

                l = strv_new(s);
                if (!l)
                        return log_oom();

                strv_free_and_replace(arg_cmdline, l);

        } else if (!arg_unit || !with_trigger)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Command line to execute required.");

        if (arg_runtime_scope == RUNTIME_SCOPE_USER && arg_transport == BUS_TRANSPORT_REMOTE)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Execution in user context is not supported on remote systems.");

        if (arg_scope && arg_transport == BUS_TRANSPORT_REMOTE)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Scope execution is not supported on remote systems.");

        if (arg_scope && (arg_remain_after_exit || arg_service_type))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "--remain-after-exit and --service-type= are not supported in --scope mode.");

        if (arg_stdio != ARG_STDIO_NONE) {
                if (with_trigger || arg_scope)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "--pty/--pty-late/--pipe is not compatible in trigger (path/socket/timer units) or --scope mode.");

                if (arg_transport == BUS_TRANSPORT_REMOTE)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "--pty/--pty-late/--pipe is only supported when connecting to the local system or containers.");

                if (arg_no_block)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "--pty/--pty-late/--pipe is not compatible with --no-block.");
        }

        if (arg_stdio == ARG_STDIO_PTY && arg_pty_late && streq_ptr(arg_service_type, "oneshot"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "--pty-late is not compatible with --service-type=oneshot.");

        if (arg_scope && with_trigger)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Path, socket or timer options are not supported in --scope mode.");

        if (arg_timer_property && !arg_with_timer)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "--timer-property= has no effect without any other timer options.");

        if (arg_wait) {
                if (arg_no_block)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "--wait may not be combined with --no-block.");

                if (with_trigger)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "--wait may not be combined with path, socket or timer operations.");

                if (arg_scope)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "--wait may not be combined with --scope.");
        }

        if (arg_scope && arg_root_directory)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "--root-directory= is not supported in --scope mode.");

        if (same_dir && arg_root_directory && !path_equal(arg_root_directory, "/"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "--same-dir cannot be used with a root directory other than '/'");

        return 1;
}

static double shell_prompt_hue(void) {
        if (become_root())
                return 0; /* red */

        if (arg_empower)
                return 30; /* orange */

        return 60; /* yellow */
}

static Glyph shell_prompt_glyph(void) {
        if (become_root())
                return GLYPH_SUPERHERO;

        if (arg_empower)
                return GLYPH_PUMPKIN;

        return GLYPH_IDCARD;
}

static Glyph pty_window_glyph(void) {
        if (become_root())
                return GLYPH_RED_CIRCLE;

        if (arg_empower)
                return GLYPH_ORANGE_CIRCLE;

        return GLYPH_YELLOW_CIRCLE;
}

static int parse_argv_sudo_mode(int argc, char *argv[]) {

        enum {
                ARG_NO_ASK_PASSWORD = 0x100,
                ARG_MACHINE,
                ARG_UNIT,
                ARG_PROPERTY,
                ARG_DESCRIPTION,
                ARG_SLICE,
                ARG_SLICE_INHERIT,
                ARG_NICE,
                ARG_SETENV,
                ARG_BACKGROUND,
                ARG_PTY,
                ARG_PTY_LATE,
                ARG_PIPE,
                ARG_SHELL_PROMPT_PREFIX,
                ARG_LIGHTWEIGHT,
                ARG_AREA,
                ARG_VIA_SHELL,
                ARG_EMPOWER,
                ARG_SAME_ROOT_DIR,
        };

        /* If invoked as "run0" binary, let's expose a more sudo-like interface. We add various extensions
         * though (but limit the extension to long options). */

        static const struct option options[] = {
                { "help",                no_argument,       NULL, 'h'                     },
                { "version",             no_argument,       NULL, 'V'                     },
                { "no-ask-password",     no_argument,       NULL, ARG_NO_ASK_PASSWORD     },
                { "machine",             required_argument, NULL, ARG_MACHINE             },
                { "unit",                required_argument, NULL, ARG_UNIT                },
                { "property",            required_argument, NULL, ARG_PROPERTY            },
                { "description",         required_argument, NULL, ARG_DESCRIPTION         },
                { "slice",               required_argument, NULL, ARG_SLICE               },
                { "slice-inherit",       no_argument,       NULL, ARG_SLICE_INHERIT       },
                { "user",                required_argument, NULL, 'u'                     },
                { "group",               required_argument, NULL, 'g'                     },
                { "nice",                required_argument, NULL, ARG_NICE                },
                { "chdir",               required_argument, NULL, 'D'                     },
                { "via-shell",           no_argument,       NULL, ARG_VIA_SHELL           },
                { "login",               no_argument,       NULL, 'i'                     }, /* compat with sudo, --via-shell + --chdir='~' */
                { "setenv",              required_argument, NULL, ARG_SETENV              },
                { "background",          required_argument, NULL, ARG_BACKGROUND          },
                { "pty",                 no_argument,       NULL, ARG_PTY                 },
                { "pty-late",            no_argument,       NULL, ARG_PTY_LATE            },
                { "pipe",                no_argument,       NULL, ARG_PIPE                },
                { "shell-prompt-prefix", required_argument, NULL, ARG_SHELL_PROMPT_PREFIX },
                { "lightweight",         required_argument, NULL, ARG_LIGHTWEIGHT         },
                { "area",                required_argument, NULL, ARG_AREA                },
                { "empower",             no_argument,       NULL, ARG_EMPOWER             },
                { "same-root-dir",       no_argument,       NULL, ARG_SAME_ROOT_DIR       },
                {},
        };

        int r, c;

        assert(argc >= 0);
        assert(argv);

        /* Resetting to 0 forces the invocation of an internal initialization routine of getopt_long()
         * that checks for GNU extensions in optstring ('-' or '+' at the beginning). */
        optind = 0;
        while ((c = getopt_long(argc, argv, "+hVu:g:D:i", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help_sudo_mode();

                case 'V':
                        return version();

                case ARG_NO_ASK_PASSWORD:
                        arg_ask_password = false;
                        break;

                case ARG_MACHINE:
                        r = parse_machine_argument(optarg, &arg_host, &arg_transport);
                        if (r < 0)
                                return r;
                        break;

                case ARG_UNIT:
                        arg_unit = optarg;
                        break;

                case ARG_PROPERTY:
                        if (strv_extend(&arg_property, optarg) < 0)
                                return log_oom();

                        break;

                case ARG_DESCRIPTION:
                        r = free_and_strdup_warn(&arg_description, optarg);
                        if (r < 0)
                                return r;
                        break;

                case ARG_SLICE:
                        r = free_and_strdup_warn(&arg_slice, optarg);
                        if (r < 0)
                                return r;
                        break;

                case ARG_SLICE_INHERIT:
                        arg_slice_inherit = true;
                        break;

                case 'u':
                        r = free_and_strdup_warn(&arg_exec_user, optarg);
                        if (r < 0)
                                return r;
                        break;

                case 'g':
                        arg_exec_group = optarg;
                        break;

                case ARG_NICE:
                        r = parse_nice(optarg, &arg_nice);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse nice value: %s", optarg);

                        arg_nice_set = true;
                        break;

                case 'D':
                        if (streq(optarg, "~"))
                                r = free_and_strdup_warn(&arg_working_directory, optarg);
                        else
                                /* Root will be manually suppressed later. */
                                r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_working_directory);
                        if (r < 0)
                                return r;

                        break;

                case ARG_SETENV:
                        r = strv_env_replace_strdup_passthrough(&arg_environment, optarg);
                        if (r < 0)
                                return log_error_errno(r, "Cannot assign environment variable %s: %m", optarg);

                        break;

                case ARG_BACKGROUND:
                        r = parse_background_argument(optarg, &arg_background);
                        if (r < 0)
                                return r;

                        break;

                case ARG_PTY:
                case ARG_PTY_LATE:
                        arg_stdio |= ARG_STDIO_PTY;
                        arg_pty_late = c == ARG_PTY_LATE;
                        break;

                case ARG_PIPE:
                        arg_stdio |= ARG_STDIO_DIRECT;
                        break;

                case ARG_SHELL_PROMPT_PREFIX:
                        r = free_and_strdup_warn(&arg_shell_prompt_prefix, optarg);
                        if (r < 0)
                                return r;
                        break;

                case ARG_LIGHTWEIGHT:
                        r = parse_tristate_argument_with_auto("--lightweight=", optarg, &arg_lightweight);
                        if (r < 0)
                                return r;
                        break;

                case ARG_AREA:
                        /* We allow an empty --area= specification to allow logging into the primary home directory */
                        if (!isempty(optarg) && !filename_is_valid(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid area name, refusing: %s", optarg);

                        r = free_and_strdup_warn(&arg_area, optarg);
                        if (r < 0)
                                return r;

                        break;

                case 'i':
                        r = free_and_strdup_warn(&arg_working_directory, "~");
                        if (r < 0)
                                return r;

                        _fallthrough_;
                case ARG_VIA_SHELL:
                        arg_via_shell = true;
                        break;

                case ARG_EMPOWER:
                        arg_empower = true;
                        break;

                case ARG_SAME_ROOT_DIR:
                        r = free_and_strdup_warn(&arg_root_directory, "/");
                        if (r < 0)
                                return r;

                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (!arg_working_directory) {
                if (arg_exec_user || arg_area) {
                        /* When switching to a specific user or an area, also switch to its home directory. */
                        arg_working_directory = strdup("~");
                        if (!arg_working_directory)
                                return log_oom();
                } else {
                        /* When elevating privileges without this being specified, then stay in the current directory */
                        r = safe_getcwd(&arg_working_directory);
                        if (r < 0)
                                return log_error_errno(r, "Failed to get current working directory: %m");
                }
        } else {
                /* Root was not suppressed earlier, to allow the above check to work properly. */
                if (empty_or_root(arg_working_directory))
                        arg_working_directory = mfree(arg_working_directory);
        }

        if (!arg_exec_user && (arg_area || arg_empower)) {
                /* If the user specifies --area= but not --user= then consider this an area switch request,
                 * and default to logging into our own account.
                 *
                 * If the user specifies --empower but not --user= then consider this a request to empower
                 * the current user. */

                arg_exec_user = getusername_malloc();
                if (!arg_exec_user)
                        return log_oom();
        }

        arg_service_type = "exec";
        arg_quiet = true;
        arg_wait = true;
        arg_aggressive_gc = true;

        if (IN_SET(arg_stdio, ARG_STDIO_NONE, ARG_STDIO_AUTO))
                arg_stdio = isatty_safe(STDIN_FILENO) && isatty_safe(STDOUT_FILENO) && isatty_safe(STDERR_FILENO) ? ARG_STDIO_PTY : ARG_STDIO_DIRECT;
        log_debug("Using %s stdio mode.", arg_stdio == ARG_STDIO_PTY ? "pty" : "direct");
        if (arg_pty_late < 0)
                arg_pty_late = arg_ask_password; /* for run0 this defaults to on, except if --no-ask-pasword is used */

        arg_expand_environment = false;
        arg_send_sighup = true;

        _cleanup_strv_free_ char **l = NULL;
        if (argc > optind) {
                l = strv_copy(argv + optind);
                if (!l)
                        return log_oom();
        } else if (!arg_via_shell) {
                const char *e;

                e = strv_env_get(arg_environment, "SHELL");
                if (e) {
                        arg_exec_path = strdup(e);
                        if (!arg_exec_path)
                                return log_oom();
                } else {
                        if (arg_transport == BUS_TRANSPORT_LOCAL) {
                                r = get_shell(&arg_exec_path);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to determine shell: %m");
                        } else {
                                arg_exec_path = strdup("/bin/sh");
                                if (!arg_exec_path)
                                        return log_oom();
                        }

                        r = strv_env_assign(&arg_environment, "SHELL", arg_exec_path);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set $SHELL environment variable: %m");
                }

                l = make_login_shell_cmdline(arg_exec_path);
                if (!l)
                        return log_oom();
        }

        if (arg_via_shell) {
                arg_exec_path = strdup(_PATH_BSHELL);
                if (!arg_exec_path)
                        return log_oom();

                r = strv_prepend(&l, "-sh");
                if (r < 0)
                        return log_oom();
        }

        strv_free_and_replace(arg_cmdline, l);

        if (!arg_slice) {
                arg_slice = strdup(SPECIAL_USER_SLICE);
                if (!arg_slice)
                        return log_oom();
        }

        _cleanup_free_ char *un = NULL;
        un = getusername_malloc();
        if (!un)
                return log_oom();

        /* Set a bunch of environment variables in a roughly sudo-compatible way */
        r = strv_env_assign(&arg_environment, "SUDO_USER", un);
        if (r < 0)
                return log_error_errno(r, "Failed to set $SUDO_USER environment variable: %m");

        r = strv_env_assignf(&arg_environment, "SUDO_UID", UID_FMT, getuid());
        if (r < 0)
                return log_error_errno(r, "Failed to set $SUDO_UID environment variable: %m");

        r = strv_env_assignf(&arg_environment, "SUDO_GID", GID_FMT, getgid());
        if (r < 0)
                return log_error_errno(r, "Failed to set $SUDO_GID environment variable: %m");

        if (strv_extendf(&arg_property, "LogExtraFields=ELEVATED_UID=" UID_FMT, getuid()) < 0)
                return log_oom();

        if (strv_extendf(&arg_property, "LogExtraFields=ELEVATED_GID=" GID_FMT, getgid()) < 0)
                return log_oom();

        if (strv_extendf(&arg_property, "LogExtraFields=ELEVATED_USER=%s", un) < 0)
                return log_oom();

        if (strv_extend(&arg_property, "PAMName=systemd-run0") < 0)
                return log_oom();

        /* The service manager ignores SIGPIPE for all spawned processes by default. Let's explicitly override
         * that here, since we're primarily invoked in interactive environments where this does matter. */
        if (strv_extend(&arg_property, "IgnoreSIGPIPE=no") < 0)
                return log_oom();

        if (!arg_background && arg_stdio == ARG_STDIO_PTY) {
                r = terminal_tint_color(shell_prompt_hue(), &arg_background);
                if (r < 0)
                        log_debug_errno(r, "Unable to get terminal background color, not tinting background: %m");
        }

        if (!arg_shell_prompt_prefix) {
                const char *e = secure_getenv("SYSTEMD_RUN_SHELL_PROMPT_PREFIX");
                if (e) {
                        arg_shell_prompt_prefix = strdup(e);
                        if (!arg_shell_prompt_prefix)
                                return log_oom();
                } else if (emoji_enabled()) {
                        arg_shell_prompt_prefix = strjoin(glyph(shell_prompt_glyph()), " ");
                        if (!arg_shell_prompt_prefix)
                                return log_oom();
                }
        }

        if (!isempty(arg_shell_prompt_prefix)) {
                r = strv_env_assign(&arg_environment, "SHELL_PROMPT_PREFIX", arg_shell_prompt_prefix);
                if (r < 0)
                        return log_error_errno(r, "Failed to set $SHELL_PROMPT_PREFIX environment variable: %m");
        }

        if (!strv_env_get(arg_environment, "XDG_SESSION_CLASS")) {

                /* If logging into an area, imply lightweight mode */
                if (arg_lightweight < 0 && !isempty(arg_area))
                        arg_lightweight = true;

                /* When using run0 to acquire privileges temporarily, let's not pull in session manager by
                 * default. Note that pam_logind/systemd-logind doesn't distinguish between run0-style privilege
                 * escalation on a TTY and first class (getty-style) TTY logins (and thus gives root a per-session
                 * manager for interactive TTY sessions), hence let's override the logic explicitly here. We only do
                 * this for root or --empower though, under the assumption that if a regular user temporarily
                 * transitions into another regular user it's a better default that the full user environment is
                 * uniformly available. */
                if (arg_lightweight < 0 && (become_root() || arg_empower))
                        arg_lightweight = true;

                if (arg_lightweight >= 0) {
                        const char *class =
                                arg_lightweight ? (arg_stdio == ARG_STDIO_PTY ? (become_root() ? "user-early-light" : "user-light") : "background-light") :
                                                  (arg_stdio == ARG_STDIO_PTY ? (become_root() ? "user-early" : "user") : "background");

                        log_debug("Setting XDG_SESSION_CLASS to '%s'.", class);

                        r = strv_env_assign(&arg_environment, "XDG_SESSION_CLASS", class);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set $XDG_SESSION_CLASS environment variable: %m");
                }
        }

        if (arg_area) {
                r = strv_env_assign(&arg_environment, "XDG_AREA", arg_area);
                if (r < 0)
                        return log_error_errno(r, "Failed to set $XDG_AREA environment variable: %m");
        }

        return 1;
}

static int transient_unit_set_properties(sd_bus_message *m, UnitType t, char **properties) {
        int r;

        assert(m);

        r = sd_bus_message_append(m, "(sv)", "Description", "s", arg_description);
        if (r < 0)
                return bus_log_create_error(r);

        if (arg_aggressive_gc) {
                r = sd_bus_message_append(m, "(sv)", "CollectMode", "s", "inactive-or-failed");
                if (r < 0)
                        return bus_log_create_error(r);
        }

        r = sd_bus_is_bus_client(sd_bus_message_get_bus(m));
        if (r < 0)
                return log_error_errno(r, "Can't determine if bus connection is direct or to broker: %m");
        if (r > 0) {
                /* Pin the object as least as long as we are around. Note that AddRef (currently) only works
                 * if we talk via the bus though. */
                r = sd_bus_message_append(m, "(sv)", "AddRef", "b", 1);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        return bus_append_unit_property_assignment_many(m, t, properties);
}

static int transient_cgroup_set_properties(sd_bus_message *m) {
        _cleanup_free_ char *name = NULL;
        _cleanup_free_ char *slice = NULL;
        int r;

        assert(m);

        if (arg_slice_inherit) {
                char *end;

                switch (arg_runtime_scope) {

                case RUNTIME_SCOPE_USER:
                        r = cg_pid_get_user_slice(0, &name);
                        break;

                case RUNTIME_SCOPE_SYSTEM:
                        r = cg_pid_get_slice(0, &name);
                        break;

                default:
                        assert_not_reached();
                }

                if (r < 0)
                        return log_error_errno(r, "Failed to get PID slice: %m");

                end = endswith(name, ".slice");
                if (!end)
                        return -ENXIO;
                *end = 0;
        }

        if (!isempty(arg_slice) && !strextend_with_separator(&name, "-", arg_slice))
                return log_oom();

        if (!name)
                return 0;

        r = unit_name_mangle_with_suffix(name, "as slice",
                                         arg_quiet ? 0 : UNIT_NAME_MANGLE_WARN,
                                         ".slice", &slice);
        if (r < 0)
                return log_error_errno(r, "Failed to mangle name '%s': %m", arg_slice);

        r = sd_bus_message_append(m, "(sv)", "Slice", "s", slice);
        if (r < 0)
                return bus_log_create_error(r);

        return 0;
}

static int transient_kill_set_properties(sd_bus_message *m) {
        int r;

        assert(m);

        if (arg_send_sighup) {
                r = sd_bus_message_append(m, "(sv)", "SendSIGHUP", "b", arg_send_sighup);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        return 0;
}

static int transient_service_set_properties(sd_bus_message *m, const char *pty_path, int pty_fd) {
        int r, send_term; /* tri-state */

        /* Use ExecStartEx if new exec flags are required. */
        bool use_ex_prop = !arg_expand_environment || arg_via_shell;

        assert(m);
        assert((!!pty_path) == (pty_fd >= 0));

        r = transient_unit_set_properties(m, UNIT_SERVICE, arg_property);
        if (r < 0)
                return r;

        r = transient_kill_set_properties(m);
        if (r < 0)
                return r;

        r = transient_cgroup_set_properties(m);
        if (r < 0)
                return r;

        if (arg_remain_after_exit) {
                r = sd_bus_message_append(m, "(sv)", "RemainAfterExit", "b", arg_remain_after_exit);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        if (arg_service_type) {
                r = sd_bus_message_append(m, "(sv)", "Type", "s", arg_service_type);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        if (arg_exec_user) {
                r = sd_bus_message_append(m, "(sv)", "User", "s", arg_exec_user);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        if (arg_exec_group) {
                r = sd_bus_message_append(m, "(sv)", "Group", "s", arg_exec_group);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        if (arg_empower) {
                r = sd_bus_message_append(m, "(sv)", "AmbientCapabilities", "t", CAP_MASK_ALL);
                if (r < 0)
                        return bus_log_create_error(r);

                r = getgrnam_malloc("empower", /* ret= */ NULL);
                if (r < 0 && r != -ESRCH)
                        return log_error_errno(r, "Failed to look up group 'empower' via NSS: %m");
                if (r >= 0) {
                        r = sd_bus_message_append(m, "(sv)", "SupplementaryGroups", "as", 1, "empower");
                        if (r < 0)
                                return bus_log_create_error(r);
                }
        }

        if (arg_nice_set) {
                r = sd_bus_message_append(m, "(sv)", "Nice", "i", arg_nice);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        if (arg_working_directory) {
                r = sd_bus_message_append(m, "(sv)", "WorkingDirectory", "s", arg_working_directory);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        if (arg_root_directory) {
                _cleanup_close_ int fd = open_tree(AT_FDCWD, arg_root_directory, OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC|AT_RECURSIVE);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to clone mount tree at '%s': %m", arg_root_directory);

                r = sd_bus_message_append(m, "(sv)", "RootDirectoryFileDescriptor", "h", fd);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        if (pty_path) {
                r = sd_bus_message_append(m, "(sv)(sv)(sv)(sv)",
                                          "TTYPath", "s", pty_path,
                                          "StandardInputFileDescriptor", "h", pty_fd,
                                          "StandardOutputFileDescriptor", "h", pty_fd,
                                          "StandardErrorFileDescriptor", "h", pty_fd);
                if (r < 0)
                        return bus_log_create_error(r);

                send_term = true;

        } else if (arg_stdio == ARG_STDIO_DIRECT) {
                r = sd_bus_message_append(m,
                                          "(sv)(sv)(sv)",
                                          "StandardInputFileDescriptor", "h", STDIN_FILENO,
                                          "StandardOutputFileDescriptor", "h", STDOUT_FILENO,
                                          "StandardErrorFileDescriptor", "h", STDERR_FILENO);
                if (r < 0)
                        return bus_log_create_error(r);

                send_term = -1;
        } else
                send_term = false;

        if (send_term != 0) {
                const char *e, *colorterm = NULL, *no_color = NULL;

                /* Propagate $TERM + $COLORTERM + $NO_COLOR if we are actually connected to a TTY */
                if (isatty_safe(STDIN_FILENO) || isatty_safe(STDOUT_FILENO) || isatty_safe(STDERR_FILENO)) {
                        e = strv_find_prefix(environ, "TERM=");
                        send_term = !!e;

                        if (send_term) {
                                /* If we send $TERM along, then also propagate $COLORTERM + $NO_COLOR right with it */
                                colorterm = strv_find_prefix(environ, "COLORTERM=");
                                no_color = strv_find_prefix(environ, "NO_COLOR=");
                        }
                } else
                        /* If we are not connected to any TTY ourselves, then send TERM=dumb, but only if we
                         * really need to (because we actually allocated a TTY for the service) */
                        e = "TERM=dumb";

                if (send_term > 0) {
                        r = sd_bus_message_append(
                                        m,
                                        "(sv)",
                                        "Environment", "as", 1, e);
                        if (r < 0)
                                return bus_log_create_error(r);

                        if (colorterm) {
                                r = sd_bus_message_append(
                                                m,
                                                "(sv)",
                                                "Environment", "as", 1, colorterm);
                                if (r < 0)
                                        return bus_log_create_error(r);
                        }

                        if (no_color) {
                                r = sd_bus_message_append(
                                                m,
                                                "(sv)",
                                                "Environment", "as", 1, no_color);
                                if (r < 0)
                                        return bus_log_create_error(r);
                        }
                }
        }

        if (!strv_isempty(arg_environment)) {
                r = sd_bus_message_open_container(m, 'r', "sv");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "s", "Environment");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_open_container(m, 'v', "as");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append_strv(m, arg_environment);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        /* Exec container */
        if (!strv_isempty(arg_cmdline)) {
                r = sd_bus_message_open_container(m, 'r', "sv");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "s",
                                          use_ex_prop ? "ExecStartEx" : "ExecStart");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_open_container(m, 'v',
                                                  use_ex_prop ? "a(sasas)" : "a(sasb)");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_open_container(m, 'a',
                                                  use_ex_prop ? "(sasas)" : "(sasb)");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_open_container(m, 'r',
                                                  use_ex_prop ? "sasas" : "sasb");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "s", arg_exec_path ?: arg_cmdline[0]);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append_strv(m, arg_cmdline);
                if (r < 0)
                        return bus_log_create_error(r);

                if (use_ex_prop) {
                        _cleanup_strv_free_ char **opts = NULL;

                        r = exec_command_flags_to_strv(
                                        (arg_expand_environment ? 0 : EXEC_COMMAND_NO_ENV_EXPAND)|
                                        (arg_ignore_failure ? EXEC_COMMAND_IGNORE_FAILURE : 0)|
                                        (arg_via_shell ? EXEC_COMMAND_VIA_SHELL : 0),
                                        &opts);
                        if (r < 0)
                                return log_error_errno(r, "Failed to format execute flags: %m");

                        r = sd_bus_message_append_strv(m, opts);
                } else
                        r = sd_bus_message_append(m, "b", arg_ignore_failure);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        return 0;
}

static int transient_scope_set_properties(sd_bus_message *m, bool allow_pidfd) {
        int r;

        assert(m);

        r = transient_unit_set_properties(m, UNIT_SCOPE, arg_property);
        if (r < 0)
                return r;

        r = transient_kill_set_properties(m);
        if (r < 0)
                return r;

        r = transient_cgroup_set_properties(m);
        if (r < 0)
                return r;

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;

        r = pidref_set_self(&pidref);
        if (r < 0)
                return r;

        r = bus_append_scope_pidref(m, &pidref, allow_pidfd);
        if (r < 0)
                return bus_log_create_error(r);

        return 0;
}

static int transient_timer_set_properties(sd_bus_message *m) {
        int r;

        assert(m);

        r = transient_unit_set_properties(m, UNIT_TIMER, arg_timer_property);
        if (r < 0)
                return r;

        /* Automatically clean up our transient timers */
        r = sd_bus_message_append(m, "(sv)", "RemainAfterElapse", "b", false);
        if (r < 0)
                return bus_log_create_error(r);

        return 0;
}

static int make_unit_name(UnitType t, char **ret) {
        int r;

        assert(t >= 0);
        assert(t < _UNIT_TYPE_MAX);
        assert(ret);

        /* Preferably use our PID + pidfd ID as identifier, if available. It's a boot time unique identifier
         * managed by the kernel. Unfortunately only new kernels support this, hence we keep some fallback
         * logic in place. */

        _cleanup_(pidref_done) PidRef self = PIDREF_NULL;
        r = pidref_set_self(&self);
        if (r < 0)
                return log_error_errno(r, "Failed to get reference to my own process: %m");

        r = pidref_acquire_pidfd_id(&self);
        if (r < 0) {
                log_debug_errno(r, "Failed to acquire pidfd ID of myself, defaulting to randomized unit name: %m");

                /* We couldn't get the pidfd id. In that case, just pick a random uuid as name */
                sd_id128_t rnd;
                r = sd_id128_randomize(&rnd);
                if (r < 0)
                        return log_error_errno(r, "Failed to generate random run unit name: %m");

                r = asprintf(ret, "run-r" SD_ID128_FORMAT_STR ".%s", SD_ID128_FORMAT_VAL(rnd), unit_type_to_string(t));
        } else
                r = asprintf(ret, "run-p" PID_FMT "-i%" PRIu64 ".%s", self.pid, self.fd_id, unit_type_to_string(t));
        if (r < 0)
                return log_oom();

        return 0;
}

static int connect_bus(sd_bus **ret) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        assert(ret);

        /* If --wait is used connect via the bus, unconditionally, as ref/unref is not supported via the
         * limited direct connection */
        if (arg_wait ||
            arg_stdio != ARG_STDIO_NONE ||
            (arg_runtime_scope == RUNTIME_SCOPE_USER && !IN_SET(arg_transport, BUS_TRANSPORT_LOCAL, BUS_TRANSPORT_CAPSULE)))
                r = bus_connect_transport(arg_transport, arg_host, arg_runtime_scope, &bus);
        else
                r = bus_connect_transport_systemd(arg_transport, arg_host, arg_runtime_scope, &bus);
        if (r < 0)
                return bus_log_connect_error(r, arg_transport, arg_runtime_scope);

        (void) sd_bus_set_allow_interactive_authorization(bus, arg_ask_password);

        *ret = TAKE_PTR(bus);
        return 0;
}

typedef struct RunContext {
        sd_event *event;
        PTYForward *forward;
        char *unit;
        char *bus_path;
        char *start_job;
        int pty_fd;

        /* Bus objects */
        sd_bus *bus;
        sd_bus_slot *match_properties_changed;
        sd_bus_slot *match_disconnected;
        sd_event_source *retry_timer;

        /* Current state of the unit */
        char *active_state;
        char *job;

        /* The exit data of the unit */
        uint64_t inactive_exit_usec;
        uint64_t inactive_enter_usec;
        char *result;
        uint64_t cpu_usage_nsec;
        uint64_t memory_peak;
        uint64_t memory_swap_peak;
        uint64_t ip_ingress_bytes;
        uint64_t ip_egress_bytes;
        uint64_t io_read_bytes;
        uint64_t io_write_bytes;
        uint32_t exit_code;
        uint32_t exit_status;
} RunContext;

static int run_context_update(RunContext *c);
static int run_context_attach_bus(RunContext *c, sd_bus *bus);
static void run_context_detach_bus(RunContext *c);
static int run_context_reconnect(RunContext *c);
static int run_context_setup_ptyfwd(RunContext *c);

static void run_context_done(RunContext *c) {
        assert(c);

        run_context_detach_bus(c);

        c->retry_timer = sd_event_source_disable_unref(c->retry_timer);
        c->forward = pty_forward_free(c->forward);
        c->event = sd_event_unref(c->event);

        free(c->active_state);
        free(c->job);
        free(c->result);
        free(c->unit);
        free(c->bus_path);
        free(c->start_job);

        safe_close(c->pty_fd);
}

static int on_retry_timer(sd_event_source *s, uint64_t usec, void *userdata) {
        RunContext *c = ASSERT_PTR(userdata);

        c->retry_timer = sd_event_source_disable_unref(c->retry_timer);

        return run_context_reconnect(c);
}

static int run_context_reconnect(RunContext *c) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
        int r;

        assert(c);

        run_context_detach_bus(c);

        r = connect_bus(&bus);
        if (r < 0)
                goto retry_timer;

        r = sd_bus_call_method(bus,
                               "org.freedesktop.systemd1",
                               c->bus_path,
                               "org.freedesktop.systemd1.Unit",
                               "Ref",
                               &error,
                               /* ret_reply= */ NULL,
                               /* types= */ NULL);
        if (r < 0) {
                /* Hmm, the service manager probably hasn't finished reexecution just yet? Try again later. */
                if (bus_error_is_connection(&error) || bus_error_is_unknown_service(&error))
                        goto retry_timer;

                if (sd_bus_error_has_name(&error, SD_BUS_ERROR_UNKNOWN_OBJECT))
                        log_warning_errno(r, "Unit deactivated during reconnection to the bus, exiting.");
                else
                        log_error_errno(r, "Failed to re-add reference to unit: %s", bus_error_message(&error, r));

                (void) sd_event_exit(c->event, EXIT_FAILURE);
                return r;
        }

        r = run_context_attach_bus(c, bus);
        if (r < 0) {
                (void) sd_event_exit(c->event, EXIT_FAILURE);
                return r;
        }

        log_info("Reconnected to bus.");

        return run_context_update(c);

retry_timer:
        log_warning_errno(r, "Failed to reconnect, retrying in 2s: %m");

        r = event_reset_time_relative(
                        c->event,
                        &c->retry_timer,
                        CLOCK_MONOTONIC,
                        2 * USEC_PER_SEC, /* accuracy= */ 0,
                        on_retry_timer, c,
                        SD_EVENT_PRIORITY_NORMAL,
                        "retry-timeout",
                        /* force_reset= */ false);
        if (r < 0) {
                (void) sd_event_exit(c->event, EXIT_FAILURE);
                return log_error_errno(r, "Failed to install retry timer: %m");
        }

        return 0;
}

static int run_context_check_started(RunContext *c) {
        int r;

        assert(c);

        if (!c->start_job)
                return 0; /* Already started? */

        if (streq_ptr(c->start_job, c->job))
                return 0; /* The start job is still active. */

        /* The start job is finished. */
        c->start_job = mfree(c->start_job);

        /* Setup ptyfwd now if --pty-late is specified. */
        r = run_context_setup_ptyfwd(c);
        if (r < 0) {
                (void) sd_event_exit(c->event, EXIT_FAILURE);
                return r;
        }

        if (STRPTR_IN_SET(c->active_state, "inactive", "failed"))
                return 0; /* Already finished or failed? */

        /* Notify our caller that the service is now running, just in case. */
        (void) sd_notifyf(/* unset_environment= */ false,
                          "READY=1\n"
                          "RUN_UNIT=%s",
                          c->unit);
        return 0;
}

static void run_context_check_done(RunContext *c) {
        int r;

        assert(c);

        if (!STRPTR_IN_SET(c->active_state, "inactive", "failed") ||
            c->start_job ||   /* our start job */
            c->job)           /* any other job */
                return;

        if (!c->forward)
                return (void) sd_event_exit(c->event, EXIT_SUCCESS);

        /* If the service is gone, it's time to drain the output */
        r = pty_forward_drain(c->forward);
        if (r < 0) {
                log_error_errno(r, "Failed to drain PTY forwarder: %m");
                return (void) sd_event_exit(c->event, EXIT_FAILURE);
        }

        /* Tell the forwarder to exit on the next vhangup(), so that we still flush out what might be queued
         * and exit then. */
        r = pty_forward_honor_vhangup(c->forward);
        if (r < 0) {
                log_error_errno(r, "Failed to make PTY forwarder honor vhangup(): %m");
                return (void) sd_event_exit(c->event, EXIT_FAILURE);
        }
}

static int map_job(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        char **p = ASSERT_PTR(userdata);
        const char *job;
        uint32_t id;
        int r;

        assert(m);

        r = sd_bus_message_read(m, "(uo)", &id, &job);
        if (r < 0)
                return r;

        return free_and_strdup(p, id == 0 ? NULL : job);
}

static int run_context_update(RunContext *c) {

        static const struct bus_properties_map map[] = {
                { "ActiveState",                     "s",    NULL,    offsetof(RunContext, active_state)        },
                { "InactiveExitTimestampMonotonic",  "t",    NULL,    offsetof(RunContext, inactive_exit_usec)  },
                { "InactiveEnterTimestampMonotonic", "t",    NULL,    offsetof(RunContext, inactive_enter_usec) },
                { "Result",                          "s",    NULL,    offsetof(RunContext, result)              },
                { "ExecMainCode",                    "i",    NULL,    offsetof(RunContext, exit_code)           },
                { "ExecMainStatus",                  "i",    NULL,    offsetof(RunContext, exit_status)         },
                { "CPUUsageNSec",                    "t",    NULL,    offsetof(RunContext, cpu_usage_nsec)      },
                { "MemoryPeak",                      "t",    NULL,    offsetof(RunContext, memory_peak)         },
                { "MemorySwapPeak",                  "t",    NULL,    offsetof(RunContext, memory_swap_peak)    },
                { "IPIngressBytes",                  "t",    NULL,    offsetof(RunContext, ip_ingress_bytes)    },
                { "IPEgressBytes",                   "t",    NULL,    offsetof(RunContext, ip_egress_bytes)     },
                { "IOReadBytes",                     "t",    NULL,    offsetof(RunContext, io_read_bytes)       },
                { "IOWriteBytes",                    "t",    NULL,    offsetof(RunContext, io_write_bytes)      },
                { "Job",                             "(uo)", map_job, offsetof(RunContext, job)                 },
                {}
        };

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(c);
        assert(c->bus);

        r = bus_map_all_properties(
                        c->bus,
                        "org.freedesktop.systemd1",
                        c->bus_path,
                        map,
                        BUS_MAP_STRDUP,
                        &error,
                        NULL,
                        c);
        if (r < 0) {
                /* If this is a connection error, then try to reconnect. This might be because the service
                 * manager is being restarted. Handle this gracefully. */
                if (bus_error_is_connection(&error) || bus_error_is_unknown_service(&error)) {
                        log_info_errno(r, "Bus call failed due to connection problems. Trying to reconnect...");
                        /* Not propagating error, because we handled it already, by reconnecting. */
                        return run_context_reconnect(c);
                }

                (void) sd_event_exit(c->event, EXIT_FAILURE);
                return log_error_errno(r, "Failed to query unit state: %s", bus_error_message(&error, r));
        }

        r = run_context_check_started(c);
        if (r < 0)
                return r;

        run_context_check_done(c);
        return 0;
}

static int on_properties_changed(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        return run_context_update(ASSERT_PTR(userdata));
}

static int on_disconnected(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        /* If our connection gets terminated, then try to reconnect. This might be because the service
         * manager is being restarted. Handle this gracefully. */
        log_info("Got disconnected from bus connection. Trying to reconnect...");
        return run_context_reconnect(ASSERT_PTR(userdata));
}

static int run_context_attach_bus(RunContext *c, sd_bus *bus) {
        int r;

        assert(c);
        assert(bus);

        assert(!c->bus);
        assert(!c->match_properties_changed);
        assert(!c->match_disconnected);

        c->bus = sd_bus_ref(bus);

        r = sd_bus_match_signal_async(
                        c->bus,
                        &c->match_properties_changed,
                        "org.freedesktop.systemd1",
                        c->bus_path,
                        "org.freedesktop.DBus.Properties",
                        "PropertiesChanged",
                        on_properties_changed, NULL, c);
        if (r < 0)
                return log_error_errno(r, "Failed to request PropertiesChanged signal match: %m");

        r = sd_bus_match_signal_async(
                        bus,
                        &c->match_disconnected,
                        "org.freedesktop.DBus.Local",
                        /* path= */ NULL,
                        "org.freedesktop.DBus.Local",
                        "Disconnected",
                        on_disconnected, NULL, c);
        if (r < 0)
                return log_error_errno(r, "Failed to request Disconnected signal match: %m");

        r = sd_bus_attach_event(c->bus, c->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach bus to event loop: %m");

        return 0;
}

static void run_context_detach_bus(RunContext *c) {
        assert(c);

        if (c->bus) {
                (void) sd_bus_detach_event(c->bus);
                c->bus = sd_bus_unref(c->bus);
        }

        c->match_properties_changed = sd_bus_slot_unref(c->match_properties_changed);
        c->match_disconnected = sd_bus_slot_unref(c->match_disconnected);
}

static int pty_forward_handler(PTYForward *f, int rcode, void *userdata) {
        RunContext *c = ASSERT_PTR(userdata);

        assert(f);

        if (rcode == -ECANCELED) {
                log_debug_errno(rcode, "PTY forwarder disconnected.");
                if (!arg_wait)
                        return sd_event_exit(c->event, EXIT_SUCCESS);

                /* If --wait is specified, we'll only exit the pty forwarding, but will continue to wait
                 * for the service to end. If the user hits ^C we'll exit too. */
        } else if (rcode < 0) {
                (void) sd_event_exit(c->event, EXIT_FAILURE);
                return log_error_errno(rcode, "Error on PTY forwarding logic: %m");
        }

        c->forward = pty_forward_free(c->forward);

        run_context_check_done(c);
        return 0;
}

static int make_transient_service_unit(
                sd_bus *bus,
                sd_bus_message **message,
                const char *service,
                const char *pty_path,
                int pty_fd) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        int r;

        assert(bus);
        assert(message);
        assert(service);

        r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, "StartTransientUnit");
        if (r < 0)
                return bus_log_create_error(r);

        /* Name and mode */
        r = sd_bus_message_append(m, "ss", service, job_mode_to_string(arg_job_mode));
        if (r < 0)
                return bus_log_create_error(r);

        /* Properties */
        r = sd_bus_message_open_container(m, 'a', "(sv)");
        if (r < 0)
                return bus_log_create_error(r);

        r = transient_service_set_properties(m, pty_path, pty_fd);
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        /* Auxiliary units */
        r = sd_bus_message_append(m, "a(sa(sv))", 0);
        if (r < 0)
                return bus_log_create_error(r);

        *message = TAKE_PTR(m);
        return 0;
}

static int bus_call_with_hint(
                sd_bus *bus,
                sd_bus_message *message,
                const char *name,
                sd_bus_message **reply) {

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        r = sd_bus_call(bus, message, 0, &error, reply);
        if (r < 0) {
                log_error_errno(r, "Failed to start transient %s unit: %s", name, bus_error_message(&error, r));

                if (!arg_expand_environment &&
                    sd_bus_error_has_names(&error,
                                           SD_BUS_ERROR_UNKNOWN_PROPERTY,
                                           SD_BUS_ERROR_PROPERTY_READ_ONLY))
                        log_notice_errno(r, "Hint: --expand-environment=no is not supported by old systemd");
        }

        return r;
}

static int acquire_invocation_id(sd_bus *bus, const char *unit, sd_id128_t *ret) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_free_ char *object = NULL;
        int r;

        assert(bus);
        assert(ret);

        if (unit) {
                object = unit_dbus_path_from_name(unit);
                if (!object)
                        return log_oom();
        }

        r = sd_bus_get_property(bus,
                                "org.freedesktop.systemd1",
                                object ?: "/org/freedesktop/systemd1/unit/self",
                                "org.freedesktop.systemd1.Unit",
                                "InvocationID",
                                &error,
                                &reply,
                                "ay");
        if (r < 0) {
                /* Let's ignore connection errors. This might be caused by that the service manager is being
                 * restarted. Handle this gracefully. */
                if (bus_error_is_connection(&error) || bus_error_is_unknown_service(&error)) {
                        log_debug_errno(r, "Invocation ID request failed due to bus connection problems, ignoring: %s",
                                        bus_error_message(&error, r));
                        *ret = SD_ID128_NULL;
                        return 0;
                }

                return log_error_errno(r, "Failed to request invocation ID for unit: %s", bus_error_message(&error, r));
        }

        r = bus_message_read_id128(reply, ret);
        if (r < 0)
                return bus_log_parse_error(r);

        return r; /* Return true when we get a non-null invocation ID. */
}

static int fchown_to_capsule(int fd, const char *capsule) {
        _cleanup_free_ char *p = NULL;
        int r;

        assert(fd >= 0);
        assert(capsule);

        p = path_join("/run/capsules/", capsule);
        if (!p)
                return -ENOMEM;

        struct stat st;
        r = chase_and_stat(p, /* root= */ NULL, CHASE_SAFE|CHASE_PROHIBIT_SYMLINKS, /* ret_path= */ NULL, &st);
        if (r < 0)
                return r;

        return fchmod_and_chown(fd, 0600, st.st_uid, st.st_gid);
}

static int print_unit_invocation(const char *unit, sd_id128_t invocation_id) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        assert(unit);

        if (!sd_json_format_enabled(arg_json_format_flags)) {
                if (sd_id128_is_null(invocation_id))
                        log_info("Running as unit: %s", unit);
                else
                        log_info("Running as unit: %s; invocation ID: " SD_ID128_FORMAT_STR, unit, SD_ID128_FORMAT_VAL(invocation_id));
                return 0;
        }

        r = sd_json_variant_set_field_string(&v, "unit", unit);
        if (r < 0)
                return r;

        if (!sd_id128_is_null(invocation_id)) {
                r = sd_json_variant_set_field_id128(&v, "invocation_id", invocation_id);
                if (r < 0)
                        return r;
        }

        return sd_json_variant_dump(v, arg_json_format_flags, stdout, NULL);
}

static int run_context_setup_ptyfwd(RunContext *c) {
        int r;

        assert(c);

        if (c->pty_fd < 0 || c->forward)
                return 0;

        /* Stop agents now that we are online, to avoid TTY conflicts */
        polkit_agent_close();
        ask_password_agent_close();

        if (!arg_quiet)
                log_info("Press ^] three times within 1s to disconnect TTY.");

        r = pty_forward_new(c->event, c->pty_fd, PTY_FORWARD_IGNORE_INITIAL_VHANGUP, &c->forward);
        if (r < 0)
                return log_error_errno(r, "Failed to create PTY forwarder: %m");

        pty_forward_set_hangup_handler(c->forward, pty_forward_handler, c);

        /* Make sure to process any TTY events before we process bus events */
        (void) pty_forward_set_priority(c->forward, SD_EVENT_PRIORITY_IMPORTANT);

        if (!isempty(arg_background))
                (void) pty_forward_set_background_color(c->forward, arg_background);

        (void) pty_forward_set_window_title(c->forward, pty_window_glyph(), arg_host, arg_cmdline);
        return 0;
}

static int run_context_show_result(RunContext *c) {
        int r;

        assert(c);

        _cleanup_(table_unrefp) Table *t = table_new_vertical();
        if (!t)
                return log_oom();

        if (!isempty(c->result)) {
                r = table_add_many(
                                t,
                                TABLE_FIELD, "Finished with result",
                                TABLE_STRING, c->result,
                                TABLE_SET_COLOR, streq(c->result, "success") ? ansi_highlight_green() : ansi_highlight_red());
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (c->exit_code > 0) {
                r = table_add_cell(
                                t,
                                /* ret_cell= */ NULL,
                                TABLE_FIELD,
                                "Main processes terminated with");
                if (r < 0)
                        return table_log_add_error(r);

                r = table_add_cell_stringf(
                                t,
                                /* ret_cell= */ NULL,
                                "code=%s, status=%u/%s",
                                sigchld_code_to_string(c->exit_code),
                                c->exit_status,
                                strna(c->exit_code == CLD_EXITED ?
                                      exit_status_to_string(c->exit_status, EXIT_STATUS_FULL) :
                                      signal_to_string(c->exit_status)));
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (timestamp_is_set(c->inactive_enter_usec) &&
            timestamp_is_set(c->inactive_exit_usec) &&
            c->inactive_enter_usec > c->inactive_exit_usec) {
                r = table_add_many(
                                t,
                                TABLE_FIELD, "Service runtime",
                                TABLE_TIMESPAN_MSEC, c->inactive_enter_usec - c->inactive_exit_usec);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (c->cpu_usage_nsec != NSEC_INFINITY) {
                r = table_add_many(
                                t,
                                TABLE_FIELD, "CPU time consumed",
                                TABLE_TIMESPAN_MSEC, DIV_ROUND_UP(c->cpu_usage_nsec, NSEC_PER_USEC));
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (c->memory_peak != UINT64_MAX) {
                const char *swap;

                if (c->memory_swap_peak != UINT64_MAX)
                        swap = strjoina(" (swap: ", FORMAT_BYTES(c->memory_swap_peak), ")");
                else
                        swap = "";

                r = table_add_cell(
                                t,
                                /* ret_cell= */ NULL,
                                TABLE_FIELD, "Memory peak");
                if (r < 0)
                        return table_log_add_error(r);

                r = table_add_cell_stringf(
                                t,
                                /* ret_cell= */ NULL,
                                "%s%s",
                                FORMAT_BYTES(c->memory_peak), swap);
                if (r < 0)
                        return table_log_add_error(r);
        }

        const char *ip_ingress = NULL, *ip_egress = NULL;
        if (!IN_SET(c->ip_ingress_bytes, 0, UINT64_MAX))
                ip_ingress = strjoina("received ", FORMAT_BYTES(c->ip_ingress_bytes));
        if (!IN_SET(c->ip_egress_bytes, 0, UINT64_MAX))
                ip_egress = strjoina("sent ", FORMAT_BYTES(c->ip_egress_bytes));

        if (ip_ingress || ip_egress) {
                r = table_add_cell(
                                t,
                                /* ret_cell= */ NULL,
                                TABLE_FIELD, "IP Traffic");
                if (r < 0)
                        return table_log_add_error(r);

                r = table_add_cell_stringf(
                                t,
                                /* ret_cell= */ NULL,
                                "%s%s%s", strempty(ip_ingress), ip_ingress && ip_egress ? ", " : "", strempty(ip_egress));
                if (r < 0)
                        return table_log_add_error(r);
        }

        const char *io_read = NULL, *io_write = NULL;
        if (!IN_SET(c->io_read_bytes, 0, UINT64_MAX))
                io_read = strjoina("read ", FORMAT_BYTES(c->io_read_bytes));
        if (!IN_SET(c->io_write_bytes, 0, UINT64_MAX))
                io_write = strjoina("written ", FORMAT_BYTES(c->io_write_bytes));

        if (io_read || io_write) {
                r = table_add_cell(
                                t,
                                /* ret_cell= */ NULL,
                                TABLE_FIELD, "IO Bytes");
                if (r < 0)
                        return table_log_add_error(r);

                r = table_add_cell_stringf(
                                t,
                                /* ret_cell= */ NULL,
                                "%s%s%s", strempty(io_read), io_read && io_write ? ", " : "", strempty(io_write));
                if (r < 0)
                        return table_log_add_error(r);
        }

        r = table_print(t, stderr);
        if (r < 0)
                return table_log_print_error(r);

        return 0;
}

static int start_transient_service(sd_bus *bus) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        _cleanup_free_ char *pty_path = NULL;
        _cleanup_close_ int peer_fd = -EBADF;
        int r;

        assert(bus);

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);
        (void) ask_password_agent_open_if_enabled(arg_transport, arg_ask_password);

        _cleanup_(run_context_done) RunContext c = {
                .pty_fd = -EBADF,
                .cpu_usage_nsec = NSEC_INFINITY,
                .memory_peak = UINT64_MAX,
                .memory_swap_peak = UINT64_MAX,
                .ip_ingress_bytes = UINT64_MAX,
                .ip_egress_bytes = UINT64_MAX,
                .io_read_bytes = UINT64_MAX,
                .io_write_bytes = UINT64_MAX,
                .inactive_exit_usec = USEC_INFINITY,
                .inactive_enter_usec = USEC_INFINITY,
        };

        if (arg_stdio == ARG_STDIO_PTY) {

                if (IN_SET(arg_transport, BUS_TRANSPORT_LOCAL, BUS_TRANSPORT_CAPSULE)) {
                        c.pty_fd = openpt_allocate(O_RDWR|O_NOCTTY|O_CLOEXEC|O_NONBLOCK, &pty_path);
                        if (c.pty_fd < 0)
                                return log_error_errno(c.pty_fd, "Failed to acquire pseudo tty: %m");

                        peer_fd = pty_open_peer(c.pty_fd, O_RDWR|O_NOCTTY|O_CLOEXEC);
                        if (peer_fd < 0)
                                return log_error_errno(peer_fd, "Failed to open pty peer: %m");

                        if (arg_transport == BUS_TRANSPORT_CAPSULE) {
                                /* If we are in capsule mode, we must give the capsule UID/GID access to the PTY we just allocated first. */

                                r = fchown_to_capsule(peer_fd, arg_host);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to chown tty to capsule UID/GID: %m");
                        }

                } else if (arg_transport == BUS_TRANSPORT_MACHINE) {
                        _cleanup_(sd_bus_unrefp) sd_bus *system_bus = NULL;
                        _cleanup_(sd_bus_message_unrefp) sd_bus_message *pty_reply = NULL;
                        const char *s;

                        r = sd_bus_default_system(&system_bus);
                        if (r < 0)
                                return log_error_errno(r, "Failed to connect to system bus: %m");

                        (void) sd_bus_set_allow_interactive_authorization(system_bus, arg_ask_password);

                        /* Chop off a username prefix. We allow this for sd-bus machine connections, hence
                         * support that here too. */
                        _cleanup_free_ char *h = NULL;
                        r = split_user_at_host(arg_host, /* ret_user= */ NULL, &h);
                        if (r < 0)
                                return log_error_errno(r, "Failed to split host specification '%s': %m", arg_host);

                        r = bus_call_method(
                                        system_bus,
                                        bus_machine_mgr,
                                        "OpenMachinePTY",
                                        &error,
                                        &pty_reply,
                                        "s", h ?: ".host");
                        if (r < 0)
                                return log_error_errno(r, "Failed to get machine PTY: %s", bus_error_message(&error, r));

                        r = sd_bus_message_read(pty_reply, "hs", &c.pty_fd, &s);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        c.pty_fd = fcntl(c.pty_fd, F_DUPFD_CLOEXEC, 3);
                        if (c.pty_fd < 0)
                                return log_error_errno(errno, "Failed to duplicate master fd: %m");

                        pty_path = strdup(s);
                        if (!pty_path)
                                return log_oom();

                        peer_fd = pty_open_peer(c.pty_fd, O_RDWR|O_NOCTTY|O_CLOEXEC);
                        if (peer_fd < 0)
                                return log_error_errno(peer_fd, "Failed to open PTY peer: %m");
                } else
                        assert_not_reached();
        }

        if (arg_unit) {
                r = unit_name_mangle_with_suffix(
                                arg_unit,
                                "as unit",
                                arg_quiet ? 0 : UNIT_NAME_MANGLE_WARN,
                                ".service",
                                &c.unit);
                if (r < 0)
                        return log_error_errno(r, "Failed to mangle unit name: %m");
        } else {
                r = make_unit_name(UNIT_SERVICE, &c.unit);
                if (r < 0)
                        return r;
        }

        /* Optionally, wait for the start job to complete. If we are supposed to read the service's stdin
         * lets skip this however, because we should start that already when the start job is running, and
         * there's little point in waiting for the start job to complete in that case anyway, as we'll wait
         * for EOF anyway, which is going to be much later. Similar applies to --wait where we're going
         * to wait for the service to terminate. */
        if (!arg_no_block && !arg_wait && arg_stdio == ARG_STDIO_NONE) {
                r = bus_wait_for_jobs_new(bus, &w);
                if (r < 0)
                        return log_error_errno(r, "Could not watch jobs: %m");
        }

        r = make_transient_service_unit(bus, &m, c.unit, pty_path, peer_fd);
        if (r < 0)
                return r;
        peer_fd = safe_close(peer_fd);

        _cleanup_(fork_notify_terminate) PidRef journal_pid = PIDREF_NULL;
        if (arg_verbose)
                (void) journal_fork(arg_runtime_scope, STRV_MAKE(c.unit), &journal_pid);

        r = bus_call_with_hint(bus, m, "service", &reply);
        if (r < 0)
                return r;

        const char *object;
        r = sd_bus_message_read(reply, "o", &object);
        if (r < 0)
                return bus_log_parse_error(r);

        if (w) {
                r = bus_wait_for_jobs_one(
                                w,
                                object,
                                arg_quiet ? 0 : BUS_WAIT_JOBS_LOG_ERROR,
                                arg_runtime_scope == RUNTIME_SCOPE_USER ? STRV_MAKE_CONST("--user") : NULL);
                if (r < 0)
                        return r;
        } else if (!arg_no_block) {
                c.start_job = strdup(object);
                if (!c.start_job)
                        return log_oom();
        }

        if (!arg_quiet) {
                sd_id128_t invocation_id;

                r = acquire_invocation_id(bus, c.unit, &invocation_id);
                if (r < 0)
                        return r;

                r = print_unit_invocation(c.unit, invocation_id);
                if (r < 0)
                        return r;
        }

        if (arg_wait || arg_stdio != ARG_STDIO_NONE) {
                c.bus_path = unit_dbus_path_from_name(c.unit);
                if (!c.bus_path)
                        return log_oom();

                r = sd_event_default(&c.event);
                if (r < 0)
                        return log_error_errno(r, "Failed to get event loop: %m");

                _cleanup_(osc_context_closep) sd_id128_t osc_context_id = SD_ID128_NULL;
                if (c.pty_fd >= 0) {
                        if (arg_exec_user && !terminal_is_dumb()) {
                                r = osc_context_open_chpriv(arg_exec_user, /* ret_seq= */ NULL, &osc_context_id);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to set OSC context: %m");
                        }

                        (void) sd_event_set_signal_exit(c.event, true);

                        assert(arg_pty_late >= 0);
                        if (!arg_pty_late) { /* If late PTY mode is off, start pty forwarder immediately */
                                r = run_context_setup_ptyfwd(&c);
                                if (r < 0)
                                        return r;
                        }
                }

                r = run_context_attach_bus(&c, bus);
                if (r < 0)
                        return r;

                r = run_context_update(&c);
                if (r < 0)
                        return r;

                r = sd_event_loop(c.event);
                if (r < 0)
                        return log_error_errno(r, "Failed to run event loop: %m");

                /* Close the journal watch logic before we output the exit summary */
                fork_notify_terminate(&journal_pid);

                if (arg_wait && !arg_quiet)
                        run_context_show_result(&c);

                /* Try to propagate the service's return value. But if the service defines
                 * e.g. SuccessExitStatus, honour this, and return 0 to mean "success". */
                if (streq_ptr(c.result, "success"))
                        return EXIT_SUCCESS;
                if (streq_ptr(c.result, "exit-code") && c.exit_status > 0)
                        return c.exit_status;
                if (streq_ptr(c.result, "signal"))
                        return EXIT_EXCEPTION;
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}

static int start_transient_scope(sd_bus *bus) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        _cleanup_strv_free_ char **env = NULL, **user_env = NULL;
        _cleanup_free_ char *scope = NULL;
        const char *object = NULL;
        sd_id128_t invocation_id;
        bool allow_pidfd = true;
        int r;

        assert(bus);
        assert(!strv_isempty(arg_cmdline));

        r = bus_wait_for_jobs_new(bus, &w);
        if (r < 0)
                return log_error_errno(r, "Could not watch jobs: %m");

        if (arg_unit) {
                r = unit_name_mangle_with_suffix(arg_unit, "as unit",
                                                 arg_quiet ? 0 : UNIT_NAME_MANGLE_WARN,
                                                 ".scope", &scope);
                if (r < 0)
                        return log_error_errno(r, "Failed to mangle scope name: %m");
        } else {
                r = make_unit_name(UNIT_SCOPE, &scope);
                if (r < 0)
                        return r;
        }

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);
        (void) ask_password_agent_open_if_enabled(arg_transport, arg_ask_password);

        for (;;) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

                r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, "StartTransientUnit");
                if (r < 0)
                        return bus_log_create_error(r);

                /* Name and Mode */
                r = sd_bus_message_append(m, "ss", scope, job_mode_to_string(arg_job_mode));
                if (r < 0)
                        return bus_log_create_error(r);

                /* Properties */
                r = sd_bus_message_open_container(m, 'a', "(sv)");
                if (r < 0)
                        return bus_log_create_error(r);

                r = transient_scope_set_properties(m, allow_pidfd);
                if (r < 0)
                        return r;

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return bus_log_create_error(r);

                /* Auxiliary units */
                r = sd_bus_message_append(m, "a(sa(sv))", 0);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_call(bus, m, 0, &error, &reply);
                if (r < 0) {
                        if (sd_bus_error_has_names(&error, SD_BUS_ERROR_UNKNOWN_PROPERTY, SD_BUS_ERROR_PROPERTY_READ_ONLY) && allow_pidfd) {
                                log_debug("Retrying with classic PIDs.");
                                allow_pidfd = false;
                                continue;
                        }

                        return log_error_errno(r, "Failed to start transient scope unit: %s", bus_error_message(&error, r));
                }

                break;
        }

        r = sd_bus_message_read(reply, "o", &object);
        if (r < 0)
                return bus_log_parse_error(r);

        r = bus_wait_for_jobs_one(w, object, arg_quiet ? 0 : BUS_WAIT_JOBS_LOG_ERROR,
                                  arg_runtime_scope == RUNTIME_SCOPE_USER ? STRV_MAKE_CONST("--user") : NULL);
        if (r < 0)
                return r;

        r = acquire_invocation_id(bus, NULL, &invocation_id);
        if (r < 0)
                return r;
        if (r == 0)
                log_debug("No invocation ID set.");
        else {
                if (strv_extendf(&user_env, "INVOCATION_ID=" SD_ID128_FORMAT_STR, SD_ID128_FORMAT_VAL(invocation_id)) < 0)
                        return log_oom();
        }

        /* Stop agents before we pass control away and before we drop privileges, to avoid TTY conflicts and
         * before we become unable to stop agents. */
        polkit_agent_close();
        ask_password_agent_close();

        if (arg_nice_set) {
                if (setpriority(PRIO_PROCESS, 0, arg_nice) < 0)
                        return log_error_errno(errno, "Failed to set nice level: %m");
        }

        if (arg_exec_group) {
                gid_t gid;

                r = get_group_creds(&arg_exec_group, &gid, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve group '%s': %s",
                                               arg_exec_group, STRERROR_GROUP(r));

                if (setresgid(gid, gid, gid) < 0)
                        return log_error_errno(errno, "Failed to change GID to " GID_FMT ": %m", gid);
        }

        if (arg_exec_user) {
                const char *un = arg_exec_user, *home, *shell;
                uid_t uid;
                gid_t gid;

                r = get_user_creds(&un, &uid, &gid, &home, &shell,
                                   USER_CREDS_CLEAN|USER_CREDS_SUPPRESS_PLACEHOLDER|USER_CREDS_PREFER_NSS);
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve user '%s': %s",
                                               arg_exec_user, STRERROR_USER(r));

                r = free_and_strdup_warn(&arg_exec_user, un);
                if (r < 0)
                        return r;

                if (home) {
                        r = strv_extendf(&user_env, "HOME=%s", home);
                        if (r < 0)
                                return log_oom();
                }

                if (shell) {
                        r = strv_extendf(&user_env, "SHELL=%s", shell);
                        if (r < 0)
                                return log_oom();
                }

                r = strv_extendf(&user_env, "USER=%s", arg_exec_user);
                if (r < 0)
                        return log_oom();

                r = strv_extendf(&user_env, "LOGNAME=%s", arg_exec_user);
                if (r < 0)
                        return log_oom();

                if (!arg_exec_group) {
                        if (setresgid(gid, gid, gid) < 0)
                                return log_error_errno(errno, "Failed to change GID to " GID_FMT ": %m", gid);
                }

                if (setresuid(uid, uid, uid) < 0)
                        return log_error_errno(errno, "Failed to change UID to " UID_FMT ": %m", uid);
        }

        if (arg_working_directory && chdir(arg_working_directory) < 0)
                return log_error_errno(errno, "Failed to change directory to '%s': %m", arg_working_directory);

        env = strv_env_merge(environ, user_env, arg_environment);
        if (!env)
                return log_oom();

        if (!arg_quiet) {
                r = print_unit_invocation(scope, invocation_id);
                if (r < 0)
                        return r;
        }

        if (arg_expand_environment) {
                _cleanup_strv_free_ char **expanded_cmdline = NULL, **unset_variables = NULL, **bad_variables = NULL;

                r = replace_env_argv(arg_cmdline, env, &expanded_cmdline, &unset_variables, &bad_variables);
                if (r < 0)
                        return log_error_errno(r, "Failed to expand environment variables: %m");

                free_and_replace(arg_cmdline, expanded_cmdline);

                if (!strv_isempty(unset_variables)) {
                        _cleanup_free_ char *ju = strv_join(unset_variables, ", ");
                        log_warning("Referenced but unset environment variable evaluates to an empty string: %s", strna(ju));
                }

                if (!strv_isempty(bad_variables)) {
                        _cleanup_free_ char *jb = strv_join(bad_variables, ", ");
                        log_warning("Invalid environment variable name evaluates to an empty string: %s", strna(jb));
                }
        }

        execvpe(arg_cmdline[0], arg_cmdline, env);

        return log_error_errno(errno, "Failed to execute: %m");
}

static int make_transient_trigger_unit(
                sd_bus *bus,
                sd_bus_message **message,
                const char *suffix,
                const char *trigger,
                const char *service) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        int r;

        assert(bus);
        assert(message);
        assert(suffix);
        assert(trigger);
        assert(service);

        r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, "StartTransientUnit");
        if (r < 0)
                return bus_log_create_error(r);

        /* Name and Mode */
        r = sd_bus_message_append(m, "ss", trigger, job_mode_to_string(arg_job_mode));
        if (r < 0)
                return bus_log_create_error(r);

        /* Properties */
        r = sd_bus_message_open_container(m, 'a', "(sv)");
        if (r < 0)
                return bus_log_create_error(r);

        if (streq(suffix, ".path"))
                r = transient_unit_set_properties(m, UNIT_PATH, arg_path_property);
        else if (streq(suffix, ".socket"))
                r = transient_unit_set_properties(m, UNIT_SOCKET, arg_socket_property);
        else if (streq(suffix, ".timer"))
                r = transient_timer_set_properties(m);
        else
                assert_not_reached();
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'a', "(sa(sv))");
        if (r < 0)
                return bus_log_create_error(r);

        if (!strv_isempty(arg_cmdline)) {
                r = sd_bus_message_open_container(m, 'r', "sa(sv)");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "s", service);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_open_container(m, 'a', "(sv)");
                if (r < 0)
                        return bus_log_create_error(r);

                r = transient_service_set_properties(m, /* pty_path= */ NULL, /* pty_fd= */ -EBADF);
                if (r < 0)
                        return r;

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        *message = TAKE_PTR(m);
        return 0;
}

static int start_transient_trigger(sd_bus *bus, const char *suffix) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        _cleanup_free_ char *trigger = NULL, *service = NULL;
        const char *object = NULL;
        int r;

        assert(bus);
        assert(suffix);

        r = bus_wait_for_jobs_new(bus, &w);
        if (r < 0)
                return log_error_errno(r, "Could not watch jobs: %m");

        if (arg_unit) {
                switch (unit_name_to_type(arg_unit)) {

                case UNIT_SERVICE:
                        service = strdup(arg_unit);
                        if (!service)
                                return log_oom();

                        r = unit_name_change_suffix(service, suffix, &trigger);
                        if (r < 0)
                                return log_error_errno(r, "Failed to change unit suffix: %m");
                        break;

                case UNIT_TIMER:
                        trigger = strdup(arg_unit);
                        if (!trigger)
                                return log_oom();

                        r = unit_name_change_suffix(trigger, ".service", &service);
                        if (r < 0)
                                return log_error_errno(r, "Failed to change unit suffix: %m");
                        break;

                default:
                        r = unit_name_mangle_with_suffix(arg_unit, "as unit",
                                                         arg_quiet ? 0 : UNIT_NAME_MANGLE_WARN,
                                                         ".service", &service);
                        if (r < 0)
                                return log_error_errno(r, "Failed to mangle unit name: %m");

                        r = unit_name_mangle_with_suffix(arg_unit, "as trigger",
                                                         arg_quiet ? 0 : UNIT_NAME_MANGLE_WARN,
                                                         suffix, &trigger);
                        if (r < 0)
                                return log_error_errno(r, "Failed to mangle unit name: %m");

                        break;
                }
        } else {
                r = make_unit_name(UNIT_SERVICE, &service);
                if (r < 0)
                        return r;

                r = unit_name_change_suffix(service, suffix, &trigger);
                if (r < 0)
                        return log_error_errno(r, "Failed to change unit suffix: %m");
        }

        r = make_transient_trigger_unit(bus, &m, suffix, trigger, service);
        if (r < 0)
                return r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);
        (void) ask_password_agent_open_if_enabled(arg_transport, arg_ask_password);

        r = bus_call_with_hint(bus, m, suffix + 1, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_read(reply, "o", &object);
        if (r < 0)
                return bus_log_parse_error(r);

        r = bus_wait_for_jobs_one(w, object, arg_quiet ? 0 : BUS_WAIT_JOBS_LOG_ERROR,
                                  arg_runtime_scope == RUNTIME_SCOPE_USER ? STRV_MAKE_CONST("--user") : NULL);
        if (r < 0)
                return r;

        if (!arg_quiet) {
                log_info("Running %s as unit: %s", suffix + 1, trigger);
                if (!strv_isempty(arg_cmdline))
                        log_info("Will run service as unit: %s", service);
        }

        return EXIT_SUCCESS;
}

static bool shall_make_executable_absolute(void) {
        if (arg_exec_path)
                return false;
        if (strv_isempty(arg_cmdline))
                return false;
        if (arg_transport != BUS_TRANSPORT_LOCAL)
                return false;
        if (!empty_or_root(arg_root_directory))
                return false;
        /* If we're running in a chroot, our view of the filesystem might be completely different from pid1's
         * view of the filesystem, hence don't try to resolve the executable in that case. */
        if (!arg_root_directory && running_in_chroot() > 0)
                return false;

        FOREACH_STRING(f, "RootDirectory=", "RootImage=", "RootMStack=", "ExecSearchPath=", "MountImages=", "ExtensionImages=")
                if (strv_find_startswith(arg_property, f))
                        return false;

        return true;
}

static int run(int argc, char* argv[]) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        log_setup();

        if (invoked_as(argv, "run0"))
                r = parse_argv_sudo_mode(argc, argv);
        else
                r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (shall_make_executable_absolute()) {
                /* Patch in an absolute path to fail early for user convenience, but only when we can do it
                 * (i.e. we will be running from the same file system). This also uses the user's $PATH,
                 * while we use a fixed search path in the manager. */

                _cleanup_free_ char *command = NULL;
                r = find_executable(arg_cmdline[0], &command);
                if (ERRNO_IS_NEG_PRIVILEGE(r))
                        log_debug_errno(r, "Failed to find executable '%s' due to permission problems, leaving path as is: %m", arg_cmdline[0]);
                else if (r < 0)
                        return log_error_errno(r, "Failed to find executable %s: %m", arg_cmdline[0]);
                else
                        free_and_replace(arg_cmdline[0], command);
        }

        if (!arg_description) {
                _cleanup_free_ char *t = NULL;

                if (strv_isempty(arg_cmdline))
                        t = strdup(arg_unit);
                else if (arg_via_shell) {
                        if (arg_cmdline[1])
                                t = quote_command_line(arg_cmdline + 1, SHELL_ESCAPE_EMPTY);
                        else
                                t = strjoin("LOGIN", arg_exec_user ? ": " : NULL, arg_exec_user);
                } else if (startswith(arg_cmdline[0], "-")) {
                        /* Drop the login shell marker from the command line when generating the description,
                         * in order to minimize user confusion. */
                        _cleanup_strv_free_ char **l = strv_copy(arg_cmdline);
                        if (!l)
                                return log_oom();

                        r = free_and_strdup_warn(l + 0, l[0] + 1);
                        if (r < 0)
                                return r;

                        t = quote_command_line(l, SHELL_ESCAPE_EMPTY);
                } else
                        t = quote_command_line(arg_cmdline, SHELL_ESCAPE_EMPTY);
                if (!t)
                        return log_oom();

                arg_description = strjoin("[", program_invocation_short_name, "] ", t);
                if (!arg_description)
                        return log_oom();
        }

        r = connect_bus(&bus);
        if (r < 0)
                return r;

        if (arg_scope)
                return start_transient_scope(bus);
        if (arg_path_property)
                return start_transient_trigger(bus, ".path");
        if (arg_socket_property)
                return start_transient_trigger(bus, ".socket");
        if (arg_with_timer)
                return start_transient_trigger(bus, ".timer");
        return start_transient_service(bus);
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
