/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "sd-bus.h"
#include "sd-event.h"

#include "alloc-util.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-map-properties.h"
#include "bus-unit-util.h"
#include "bus-wait-for-jobs.h"
#include "calendarspec.h"
#include "env-util.h"
#include "exit-status.h"
#include "fd-util.h"
#include "format-util.h"
#include "main-func.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "process-util.h"
#include "ptyfwd.h"
#include "signal-util.h"
#include "spawn-polkit-agent.h"
#include "strv.h"
#include "terminal-util.h"
#include "unit-def.h"
#include "unit-name.h"
#include "user-util.h"

static bool arg_ask_password = true;
static bool arg_scope = false;
static bool arg_remain_after_exit = false;
static bool arg_no_block = false;
static bool arg_wait = false;
static const char *arg_unit = NULL;
static const char *arg_description = NULL;
static const char *arg_slice = NULL;
static bool arg_slice_inherit = false;
static bool arg_send_sighup = false;
static BusTransport arg_transport = BUS_TRANSPORT_LOCAL;
static const char *arg_host = NULL;
static bool arg_user = false;
static const char *arg_service_type = NULL;
static const char *arg_exec_user = NULL;
static const char *arg_exec_group = NULL;
static int arg_nice = 0;
static bool arg_nice_set = false;
static char **arg_environment = NULL;
static char **arg_property = NULL;
static enum {
        ARG_STDIO_NONE,      /* The default, as it is for normal services, stdin connected to /dev/null, and stdout+stderr to the journal */
        ARG_STDIO_PTY,       /* Interactive behaviour, requested by --pty: we allocate a pty and connect it to the TTY we are invoked from */
        ARG_STDIO_DIRECT,    /* Directly pass our stdin/stdout/stderr to the activated service, useful for usage in shell pipelines, requested by --pipe */
        ARG_STDIO_AUTO,      /* If --pipe and --pty are used together we use --pty when invoked on a TTY, and --pipe otherwise */
} arg_stdio = ARG_STDIO_NONE;
static char **arg_path_property = NULL;
static char **arg_socket_property = NULL;
static char **arg_timer_property = NULL;
static bool arg_with_timer = false;
static bool arg_quiet = false;
static bool arg_aggressive_gc = false;
static char *arg_working_directory = NULL;
static bool arg_shell = false;
static char **arg_cmdline = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_environment, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_property, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_path_property, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_socket_property, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_timer_property, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_working_directory, freep);
STATIC_DESTRUCTOR_REGISTER(arg_cmdline, strv_freep);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-run", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] COMMAND [ARGUMENTS...]\n"
               "\n%sRun the specified command in a transient scope or service.%s\n\n"
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
               "     --slice-inherit              Inherit the slice\n"
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
               "  -E --setenv=NAME=VALUE          Set environment\n"
               "  -t --pty                        Run service on pseudo TTY as STDIN/STDOUT/\n"
               "                                  STDERR\n"
               "  -P --pipe                       Pass STDIN/STDOUT/STDERR directly to service\n"
               "  -q --quiet                      Suppress information messages during runtime\n"
               "  -G --collect                    Unload unit after it ran, even when failed\n"
               "  -S --shell                      Invoke a $SHELL interactively\n\n"
               "Path options:\n"
               "     --path-property=NAME=VALUE   Set path unit property\n\n"
               "Socket options:\n"
               "     --socket-property=NAME=VALUE Set socket unit property\n\n"
               "Timer options:\n"
               "     --on-active=SECONDS          Run after SECONDS delay\n"
               "     --on-boot=SECONDS            Run SECONDS after machine was booted up\n"
               "     --on-startup=SECONDS         Run SECONDS after systemd activation\n"
               "     --on-unit-active=SECONDS     Run SECONDS after the last activation\n"
               "     --on-unit-inactive=SECONDS   Run SECONDS after the last deactivation\n"
               "     --on-calendar=SPEC           Realtime timer\n"
               "     --on-timezone-change         Run when the timezone changes\n"
               "     --on-clock-change            Run when the realtime clock jumps\n"
               "     --timer-property=NAME=VALUE  Set timer unit property\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
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

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_USER,
                ARG_SYSTEM,
                ARG_SCOPE,
                ARG_DESCRIPTION,
                ARG_SLICE,
                ARG_SLICE_INHERIT,
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
                ARG_SHELL,
        };

        static const struct option options[] = {
                { "help",              no_argument,       NULL, 'h'                   },
                { "version",           no_argument,       NULL, ARG_VERSION           },
                { "user",              no_argument,       NULL, ARG_USER              },
                { "system",            no_argument,       NULL, ARG_SYSTEM            },
                { "scope",             no_argument,       NULL, ARG_SCOPE             },
                { "unit",              required_argument, NULL, 'u'                   },
                { "description",       required_argument, NULL, ARG_DESCRIPTION       },
                { "slice",             required_argument, NULL, ARG_SLICE             },
                { "slice-inherit",     no_argument,       NULL, ARG_SLICE_INHERIT     },
                { "remain-after-exit", no_argument,       NULL, 'r'                   },
                { "send-sighup",       no_argument,       NULL, ARG_SEND_SIGHUP       },
                { "host",              required_argument, NULL, 'H'                   },
                { "machine",           required_argument, NULL, 'M'                   },
                { "service-type",      required_argument, NULL, ARG_SERVICE_TYPE      },
                { "wait",              no_argument,       NULL, ARG_WAIT              },
                { "uid",               required_argument, NULL, ARG_EXEC_USER         },
                { "gid",               required_argument, NULL, ARG_EXEC_GROUP        },
                { "nice",              required_argument, NULL, ARG_NICE              },
                { "setenv",            required_argument, NULL, 'E'                   },
                { "property",          required_argument, NULL, 'p'                   },
                { "tty",               no_argument,       NULL, 't'                   }, /* deprecated alias */
                { "pty",               no_argument,       NULL, 't'                   },
                { "pipe",              no_argument,       NULL, 'P'                   },
                { "quiet",             no_argument,       NULL, 'q'                   },
                { "on-active",         required_argument, NULL, ARG_ON_ACTIVE         },
                { "on-boot",           required_argument, NULL, ARG_ON_BOOT           },
                { "on-startup",        required_argument, NULL, ARG_ON_STARTUP        },
                { "on-unit-active",    required_argument, NULL, ARG_ON_UNIT_ACTIVE    },
                { "on-unit-inactive",  required_argument, NULL, ARG_ON_UNIT_INACTIVE  },
                { "on-calendar",       required_argument, NULL, ARG_ON_CALENDAR       },
                { "on-timezone-change",no_argument,       NULL, ARG_ON_TIMEZONE_CHANGE},
                { "on-clock-change",   no_argument,       NULL, ARG_ON_CLOCK_CHANGE   },
                { "timer-property",    required_argument, NULL, ARG_TIMER_PROPERTY    },
                { "path-property",     required_argument, NULL, ARG_PATH_PROPERTY     },
                { "socket-property",   required_argument, NULL, ARG_SOCKET_PROPERTY   },
                { "no-block",          no_argument,       NULL, ARG_NO_BLOCK          },
                { "no-ask-password",   no_argument,       NULL, ARG_NO_ASK_PASSWORD   },
                { "collect",           no_argument,       NULL, 'G'                   },
                { "working-directory", required_argument, NULL, ARG_WORKING_DIRECTORY },
                { "same-dir",          no_argument,       NULL, 'd'                   },
                { "shell",             no_argument,       NULL, 'S'                   },
                {},
        };

        bool with_trigger = false;
        int r, c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "+hrH:M:E:p:tPqGdSu:", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_NO_ASK_PASSWORD:
                        arg_ask_password = false;
                        break;

                case ARG_USER:
                        arg_user = true;
                        break;

                case ARG_SYSTEM:
                        arg_user = false;
                        break;

                case ARG_SCOPE:
                        arg_scope = true;
                        break;

                case 'u':
                        arg_unit = optarg;
                        break;

                case ARG_DESCRIPTION:
                        arg_description = optarg;
                        break;

                case ARG_SLICE:
                        arg_slice = optarg;
                        break;

                case ARG_SLICE_INHERIT:
                        arg_slice_inherit = true;
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
                        arg_transport = BUS_TRANSPORT_MACHINE;
                        arg_host = optarg;
                        break;

                case ARG_SERVICE_TYPE:
                        arg_service_type = optarg;
                        break;

                case ARG_EXEC_USER:
                        arg_exec_user = optarg;
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
                        if (strv_extend(&arg_environment, optarg) < 0)
                                return log_oom();

                        break;

                case 'p':
                        if (strv_extend(&arg_property, optarg) < 0)
                                return log_oom();

                        break;

                case 't': /* --pty */
                        if (IN_SET(arg_stdio, ARG_STDIO_DIRECT, ARG_STDIO_AUTO)) /* if --pipe is already used, upgrade to auto mode */
                                arg_stdio = ARG_STDIO_AUTO;
                        else
                                arg_stdio = ARG_STDIO_PTY;
                        break;

                case 'P': /* --pipe */
                        if (IN_SET(arg_stdio, ARG_STDIO_PTY, ARG_STDIO_AUTO)) /* If --pty is already used, upgrade to auto mode */
                                arg_stdio = ARG_STDIO_AUTO;
                        else
                                arg_stdio = ARG_STDIO_DIRECT;
                        break;

                case 'q':
                        arg_quiet = true;
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
                        break;
                }

                case 'G':
                        arg_aggressive_gc = true;
                        break;

                case 'S':
                        arg_shell = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        /* If we are talking to the per-user instance PolicyKit isn't going to help */
        if (arg_user)
                arg_ask_password = false;

        with_trigger = !!arg_path_property || !!arg_socket_property || arg_with_timer;

        /* currently, only single trigger (path, socket, timer) unit can be created simultaneously */
        if ((int) !!arg_path_property + (int) !!arg_socket_property + (int) arg_with_timer > 1)
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

                        if (!arg_service_type) {
                                arg_service_type = strdup("exec");
                                if (!arg_service_type)
                                        return log_oom();
                        }

                        arg_wait = true;
                }

                arg_aggressive_gc = true;
        }

        if (arg_stdio == ARG_STDIO_AUTO)
                /* If we both --pty and --pipe are specified we'll automatically pick --pty if we are connected fully
                 * to a TTY and pick direct fd passing otherwise. This way, we automatically adapt to usage in a shell
                 * pipeline, but we are neatly interactive with tty-level isolation otherwise. */
                arg_stdio = isatty(STDIN_FILENO) && isatty(STDOUT_FILENO) && isatty(STDERR_FILENO) ?
                        ARG_STDIO_PTY :
                        ARG_STDIO_DIRECT;

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

        if (arg_user && arg_transport == BUS_TRANSPORT_REMOTE)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Execution in user context is not supported on remote systems.");

        if (arg_scope && arg_transport == BUS_TRANSPORT_REMOTE)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Scope execution is not supported on remote systems.");

        if (arg_scope && (arg_remain_after_exit || arg_service_type))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "--remain-after-exit and --service-type= are not supported in --scope mode.");

        if (arg_stdio != ARG_STDIO_NONE && (with_trigger || arg_scope))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "--pty/--pipe is not compatible in timer or --scope mode.");

        if (arg_stdio != ARG_STDIO_NONE && arg_transport == BUS_TRANSPORT_REMOTE)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "--pty/--pipe is only supported when connecting to the local system or containers.");

        if (arg_stdio != ARG_STDIO_NONE && arg_no_block)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "--pty/--pipe is not compatible with --no-block.");

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

        return 1;
}

static int transient_unit_set_properties(sd_bus_message *m, UnitType t, char **properties) {
        int r;

        r = sd_bus_message_append(m, "(sv)", "Description", "s", arg_description);
        if (r < 0)
                return bus_log_create_error(r);

        if (arg_aggressive_gc) {
                r = sd_bus_message_append(m, "(sv)", "CollectMode", "s", "inactive-or-failed");
                if (r < 0)
                        return bus_log_create_error(r);
        }

        r = bus_append_unit_property_assignment_many(m, t, properties);
        if (r < 0)
                return r;

        return 0;
}

static int transient_cgroup_set_properties(sd_bus_message *m) {
        _cleanup_free_ char *name = NULL;
        _cleanup_free_ char *slice = NULL;
        int r;
        assert(m);

        if (arg_slice_inherit) {
                char *end;

                if (arg_user)
                        r = cg_pid_get_user_slice(0, &name);
                else
                        r = cg_pid_get_slice(0, &name);
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

static int transient_service_set_properties(sd_bus_message *m, const char *pty_path) {
        bool send_term = false;
        int r;

        assert(m);

        r = transient_unit_set_properties(m, UNIT_SERVICE, arg_property);
        if (r < 0)
                return r;

        r = transient_kill_set_properties(m);
        if (r < 0)
                return r;

        r = transient_cgroup_set_properties(m);
        if (r < 0)
                return r;

        if (arg_wait || arg_stdio != ARG_STDIO_NONE) {
                r = sd_bus_message_append(m, "(sv)", "AddRef", "b", 1);
                if (r < 0)
                        return bus_log_create_error(r);
        }

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

        if (pty_path) {
                r = sd_bus_message_append(m,
                                          "(sv)(sv)(sv)(sv)",
                                          "StandardInput", "s", "tty",
                                          "StandardOutput", "s", "tty",
                                          "StandardError", "s", "tty",
                                          "TTYPath", "s", pty_path);
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

                send_term = isatty(STDIN_FILENO) || isatty(STDOUT_FILENO) || isatty(STDERR_FILENO);
        }

        if (send_term) {
                const char *e;

                e = getenv("TERM");
                if (e) {
                        char *n;

                        n = strjoina("TERM=", e);
                        r = sd_bus_message_append(m,
                                                  "(sv)",
                                                  "Environment", "as", 1, n);
                        if (r < 0)
                                return bus_log_create_error(r);
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

                r = sd_bus_message_append(m, "s", "ExecStart");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_open_container(m, 'v', "a(sasb)");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_open_container(m, 'a', "(sasb)");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_open_container(m, 'r', "sasb");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "s", arg_cmdline[0]);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append_strv(m, arg_cmdline);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "b", false);
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

static int transient_scope_set_properties(sd_bus_message *m) {
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

        r = sd_bus_message_append(m, "(sv)", "PIDs", "au", 1, (uint32_t) getpid_cached());
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

static int make_unit_name(sd_bus *bus, UnitType t, char **ret) {
        const char *unique, *id;
        char *p;
        int r;

        assert(bus);
        assert(t >= 0);
        assert(t < _UNIT_TYPE_MAX);

        r = sd_bus_get_unique_name(bus, &unique);
        if (r < 0) {
                sd_id128_t rnd;

                /* We couldn't get the unique name, which is a pretty
                 * common case if we are connected to systemd
                 * directly. In that case, just pick a random uuid as
                 * name */

                r = sd_id128_randomize(&rnd);
                if (r < 0)
                        return log_error_errno(r, "Failed to generate random run unit name: %m");

                if (asprintf(ret, "run-r" SD_ID128_FORMAT_STR ".%s", SD_ID128_FORMAT_VAL(rnd), unit_type_to_string(t)) < 0)
                        return log_oom();

                return 0;
        }

        /* We managed to get the unique name, then let's use that to name our transient units. */

        id = startswith(unique, ":1."); /* let' strip the usual prefix */
        if (!id)
                id = startswith(unique, ":"); /* the spec only requires things to start with a colon, hence
                                               * let's add a generic fallback for that. */
        if (!id)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Unique name %s has unexpected format.",
                                       unique);

        p = strjoin("run-u", id, ".", unit_type_to_string(t));
        if (!p)
                return log_oom();

        *ret = p;
        return 0;
}

typedef struct RunContext {
        sd_bus *bus;
        sd_event *event;
        PTYForward *forward;
        sd_bus_slot *match;

        /* Current state of the unit */
        char *active_state;
        bool has_job;

        /* The exit data of the unit */
        uint64_t inactive_exit_usec;
        uint64_t inactive_enter_usec;
        char *result;
        uint64_t cpu_usage_nsec;
        uint64_t ip_ingress_bytes;
        uint64_t ip_egress_bytes;
        uint64_t io_read_bytes;
        uint64_t io_write_bytes;
        uint32_t exit_code;
        uint32_t exit_status;
} RunContext;

static void run_context_free(RunContext *c) {
        assert(c);

        c->forward = pty_forward_free(c->forward);
        c->match = sd_bus_slot_unref(c->match);
        c->bus = sd_bus_unref(c->bus);
        c->event = sd_event_unref(c->event);

        free(c->active_state);
        free(c->result);
}

static void run_context_check_done(RunContext *c) {
        bool done;

        assert(c);

        if (c->match)
                done = STRPTR_IN_SET(c->active_state, "inactive", "failed") && !c->has_job;
        else
                done = true;

        if (c->forward && done) /* If the service is gone, it's time to drain the output */
                done = pty_forward_drain(c->forward);

        if (done)
                sd_event_exit(c->event, EXIT_SUCCESS);
}

static int map_job(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        bool *b = userdata;
        const char *job;
        uint32_t id;
        int r;

        r = sd_bus_message_read(m, "(uo)", &id, &job);
        if (r < 0)
                return r;

        *b = id != 0 || !streq(job, "/");
        return 0;
}

static int run_context_update(RunContext *c, const char *path) {

        static const struct bus_properties_map map[] = {
                { "ActiveState",                     "s",    NULL,    offsetof(RunContext, active_state)        },
                { "InactiveExitTimestampMonotonic",  "t",    NULL,    offsetof(RunContext, inactive_exit_usec)  },
                { "InactiveEnterTimestampMonotonic", "t",    NULL,    offsetof(RunContext, inactive_enter_usec) },
                { "Result",                          "s",    NULL,    offsetof(RunContext, result)              },
                { "ExecMainCode",                    "i",    NULL,    offsetof(RunContext, exit_code)           },
                { "ExecMainStatus",                  "i",    NULL,    offsetof(RunContext, exit_status)         },
                { "CPUUsageNSec",                    "t",    NULL,    offsetof(RunContext, cpu_usage_nsec)      },
                { "IPIngressBytes",                  "t",    NULL,    offsetof(RunContext, ip_ingress_bytes)    },
                { "IPEgressBytes",                   "t",    NULL,    offsetof(RunContext, ip_egress_bytes)     },
                { "IOReadBytes",                     "t",    NULL,    offsetof(RunContext, io_read_bytes)       },
                { "IOWriteBytes",                    "t",    NULL,    offsetof(RunContext, io_write_bytes)      },
                { "Job",                             "(uo)", map_job, offsetof(RunContext, has_job)             },
                {}
        };

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        r = bus_map_all_properties(c->bus,
                                   "org.freedesktop.systemd1",
                                   path,
                                   map,
                                   BUS_MAP_STRDUP,
                                   &error,
                                   NULL,
                                   c);
        if (r < 0) {
                sd_event_exit(c->event, EXIT_FAILURE);
                return log_error_errno(r, "Failed to query unit state: %s", bus_error_message(&error, r));
        }

        run_context_check_done(c);
        return 0;
}

static int on_properties_changed(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        RunContext *c = userdata;

        assert(m);
        assert(c);

        return run_context_update(c, sd_bus_message_get_path(m));
}

static int pty_forward_handler(PTYForward *f, int rcode, void *userdata) {
        RunContext *c = userdata;

        assert(f);

        if (rcode < 0) {
                sd_event_exit(c->event, EXIT_FAILURE);
                return log_error_errno(rcode, "Error on PTY forwarding logic: %m");
        }

        run_context_check_done(c);
        return 0;
}

static int start_transient_service(
                sd_bus *bus,
                int *retval) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        _cleanup_free_ char *service = NULL, *pty_path = NULL;
        _cleanup_close_ int master = -1;
        int r;

        assert(bus);
        assert(retval);

        if (arg_stdio == ARG_STDIO_PTY) {

                if (arg_transport == BUS_TRANSPORT_LOCAL) {
                        master = posix_openpt(O_RDWR|O_NOCTTY|O_CLOEXEC|O_NONBLOCK);
                        if (master < 0)
                                return log_error_errno(errno, "Failed to acquire pseudo tty: %m");

                        r = ptsname_malloc(master, &pty_path);
                        if (r < 0)
                                return log_error_errno(r, "Failed to determine tty name: %m");

                        if (unlockpt(master) < 0)
                                return log_error_errno(errno, "Failed to unlock tty: %m");

                } else if (arg_transport == BUS_TRANSPORT_MACHINE) {
                        _cleanup_(sd_bus_unrefp) sd_bus *system_bus = NULL;
                        _cleanup_(sd_bus_message_unrefp) sd_bus_message *pty_reply = NULL;
                        const char *s;

                        r = sd_bus_default_system(&system_bus);
                        if (r < 0)
                                return log_error_errno(r, "Failed to connect to system bus: %m");

                        r = sd_bus_call_method(system_bus,
                                               "org.freedesktop.machine1",
                                               "/org/freedesktop/machine1",
                                               "org.freedesktop.machine1.Manager",
                                               "OpenMachinePTY",
                                               &error,
                                               &pty_reply,
                                               "s", arg_host);
                        if (r < 0)
                                return log_error_errno(r, "Failed to get machine PTY: %s", bus_error_message(&error, r));

                        r = sd_bus_message_read(pty_reply, "hs", &master, &s);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        master = fcntl(master, F_DUPFD_CLOEXEC, 3);
                        if (master < 0)
                                return log_error_errno(errno, "Failed to duplicate master fd: %m");

                        pty_path = strdup(s);
                        if (!pty_path)
                                return log_oom();
                } else
                        assert_not_reached("Can't allocate tty via ssh");
        }

        /* Optionally, wait for the start job to complete. If we are supposed to read the service's stdin
         * lets skip this however, because we should start that already when the start job is running, and
         * there's little point in waiting for the start job to complete in that case anyway, as we'll wait
         * for EOF anyway, which is going to be much later. */
        if (!arg_no_block && arg_stdio == ARG_STDIO_NONE) {
                r = bus_wait_for_jobs_new(bus, &w);
                if (r < 0)
                        return log_error_errno(r, "Could not watch jobs: %m");
        }

        if (arg_unit) {
                r = unit_name_mangle_with_suffix(arg_unit, "as unit",
                                                 arg_quiet ? 0 : UNIT_NAME_MANGLE_WARN,
                                                 ".service", &service);
                if (r < 0)
                        return log_error_errno(r, "Failed to mangle unit name: %m");
        } else {
                r = make_unit_name(bus, UNIT_SERVICE, &service);
                if (r < 0)
                        return r;
        }

        r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, "StartTransientUnit");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_set_allow_interactive_authorization(m, arg_ask_password);
        if (r < 0)
                return bus_log_create_error(r);

        /* Name and mode */
        r = sd_bus_message_append(m, "ss", service, "fail");
        if (r < 0)
                return bus_log_create_error(r);

        /* Properties */
        r = sd_bus_message_open_container(m, 'a', "(sv)");
        if (r < 0)
                return bus_log_create_error(r);

        r = transient_service_set_properties(m, pty_path);
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        /* Auxiliary units */
        r = sd_bus_message_append(m, "a(sa(sv))", 0);
        if (r < 0)
                return bus_log_create_error(r);

        polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0)
                return log_error_errno(r, "Failed to start transient service unit: %s", bus_error_message(&error, r));

        if (w) {
                const char *object;

                r = sd_bus_message_read(reply, "o", &object);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = bus_wait_for_jobs_one(w, object, arg_quiet);
                if (r < 0)
                        return r;
        }

        if (!arg_quiet)
                log_info("Running as unit: %s", service);

        if (arg_wait || arg_stdio != ARG_STDIO_NONE) {
                _cleanup_(run_context_free) RunContext c = {
                        .cpu_usage_nsec = NSEC_INFINITY,
                        .ip_ingress_bytes = UINT64_MAX,
                        .ip_egress_bytes = UINT64_MAX,
                        .io_read_bytes = UINT64_MAX,
                        .io_write_bytes = UINT64_MAX,
                        .inactive_exit_usec = USEC_INFINITY,
                        .inactive_enter_usec = USEC_INFINITY,
                };
                _cleanup_free_ char *path = NULL;

                c.bus = sd_bus_ref(bus);

                r = sd_event_default(&c.event);
                if (r < 0)
                        return log_error_errno(r, "Failed to get event loop: %m");

                if (master >= 0) {
                        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGWINCH, SIGTERM, SIGINT, -1) >= 0);
                        (void) sd_event_add_signal(c.event, NULL, SIGINT, NULL, NULL);
                        (void) sd_event_add_signal(c.event, NULL, SIGTERM, NULL, NULL);

                        if (!arg_quiet)
                                log_info("Press ^] three times within 1s to disconnect TTY.");

                        r = pty_forward_new(c.event, master, PTY_FORWARD_IGNORE_INITIAL_VHANGUP, &c.forward);
                        if (r < 0)
                                return log_error_errno(r, "Failed to create PTY forwarder: %m");

                        pty_forward_set_handler(c.forward, pty_forward_handler, &c);

                        /* Make sure to process any TTY events before we process bus events */
                        (void) pty_forward_set_priority(c.forward, SD_EVENT_PRIORITY_IMPORTANT);
                }

                path = unit_dbus_path_from_name(service);
                if (!path)
                        return log_oom();

                r = sd_bus_match_signal_async(
                                bus,
                                &c.match,
                                "org.freedesktop.systemd1",
                                path,
                                "org.freedesktop.DBus.Properties",
                                "PropertiesChanged",
                                on_properties_changed, NULL, &c);
                if (r < 0)
                        return log_error_errno(r, "Failed to request properties changed signal match: %m");

                r = sd_bus_attach_event(bus, c.event, SD_EVENT_PRIORITY_NORMAL);
                if (r < 0)
                        return log_error_errno(r, "Failed to attach bus to event loop: %m");

                r = run_context_update(&c, path);
                if (r < 0)
                        return r;

                r = sd_event_loop(c.event);
                if (r < 0)
                        return log_error_errno(r, "Failed to run event loop: %m");

                if (c.forward) {
                        char last_char = 0;

                        r = pty_forward_get_last_char(c.forward, &last_char);
                        if (r >= 0 && !arg_quiet && last_char != '\n')
                                fputc('\n', stdout);
                }

                if (arg_wait && !arg_quiet) {

                        /* Explicitly destroy the PTY forwarder, so that the PTY device is usable again, with its
                         * original settings (i.e. proper line breaks), so that we can show the summary in a pretty
                         * way. */
                        c.forward = pty_forward_free(c.forward);

                        if (!isempty(c.result))
                                log_info("Finished with result: %s", strna(c.result));

                        if (c.exit_code == CLD_EXITED)
                                log_info("Main processes terminated with: code=%s/status=%i",
                                         sigchld_code_to_string(c.exit_code), c.exit_status);
                        else if (c.exit_code > 0)
                                log_info("Main processes terminated with: code=%s/status=%s",
                                         sigchld_code_to_string(c.exit_code), signal_to_string(c.exit_status));

                        if (timestamp_is_set(c.inactive_enter_usec) &&
                            timestamp_is_set(c.inactive_exit_usec) &&
                            c.inactive_enter_usec > c.inactive_exit_usec) {
                                char ts[FORMAT_TIMESPAN_MAX];
                                log_info("Service runtime: %s",
                                         format_timespan(ts, sizeof ts, c.inactive_enter_usec - c.inactive_exit_usec, USEC_PER_MSEC));
                        }

                        if (c.cpu_usage_nsec != NSEC_INFINITY) {
                                char ts[FORMAT_TIMESPAN_MAX];
                                log_info("CPU time consumed: %s",
                                         format_timespan(ts, sizeof ts, DIV_ROUND_UP(c.cpu_usage_nsec, NSEC_PER_USEC), USEC_PER_MSEC));
                        }

                        if (c.ip_ingress_bytes != UINT64_MAX) {
                                char bytes[FORMAT_BYTES_MAX];
                                log_info("IP traffic received: %s", format_bytes(bytes, sizeof bytes, c.ip_ingress_bytes));
                        }
                        if (c.ip_egress_bytes != UINT64_MAX) {
                                char bytes[FORMAT_BYTES_MAX];
                                log_info("IP traffic sent: %s", format_bytes(bytes, sizeof bytes, c.ip_egress_bytes));
                        }
                        if (c.io_read_bytes != UINT64_MAX) {
                                char bytes[FORMAT_BYTES_MAX];
                                log_info("IO bytes read: %s", format_bytes(bytes, sizeof bytes, c.io_read_bytes));
                        }
                        if (c.io_write_bytes != UINT64_MAX) {
                                char bytes[FORMAT_BYTES_MAX];
                                log_info("IO bytes written: %s", format_bytes(bytes, sizeof bytes, c.io_write_bytes));
                        }
                }

                /* Try to propagate the service's return value. But if the service defines
                 * e.g. SuccessExitStatus, honour this, and return 0 to mean "success". */
                if (streq_ptr(c.result, "success"))
                        *retval = 0;
                else if (streq_ptr(c.result, "exit-code") && c.exit_status > 0)
                        *retval = c.exit_status;
                else if (streq_ptr(c.result, "signal"))
                        *retval = EXIT_EXCEPTION;
                else
                        *retval = EXIT_FAILURE;
        }

        return 0;
}

static int acquire_invocation_id(sd_bus *bus, sd_id128_t *ret) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        const void *p;
        size_t l;
        int r;

        assert(bus);
        assert(ret);

        r = sd_bus_get_property(bus,
                                "org.freedesktop.systemd1",
                                "/org/freedesktop/systemd1/unit/self",
                                "org.freedesktop.systemd1.Unit",
                                "InvocationID",
                                &error,
                                &reply,
                                "ay");
        if (r < 0)
                return log_error_errno(r, "Failed to request invocation ID for scope: %s", bus_error_message(&error, r));

        r = sd_bus_message_read_array(reply, 'y', &p, &l);
        if (r < 0)
                return bus_log_parse_error(r);

        if (l != sizeof(sd_id128_t))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid UUID size, %zu != %zu.", l, sizeof(sd_id128_t));

        memcpy(ret, p, l);
        return 0;
}

static int start_transient_scope(sd_bus *bus) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        _cleanup_strv_free_ char **env = NULL, **user_env = NULL;
        _cleanup_free_ char *scope = NULL;
        const char *object = NULL;
        sd_id128_t invocation_id;
        int r;

        assert(bus);
        assert(!strv_isempty(arg_cmdline));

        r = bus_wait_for_jobs_new(bus, &w);
        if (r < 0)
                return log_oom();

        if (arg_unit) {
                r = unit_name_mangle_with_suffix(arg_unit, "as unit",
                                                 arg_quiet ? 0 : UNIT_NAME_MANGLE_WARN,
                                                 ".scope", &scope);
                if (r < 0)
                        return log_error_errno(r, "Failed to mangle scope name: %m");
        } else {
                r = make_unit_name(bus, UNIT_SCOPE, &scope);
                if (r < 0)
                        return r;
        }

        r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, "StartTransientUnit");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_set_allow_interactive_authorization(m, arg_ask_password);
        if (r < 0)
                return bus_log_create_error(r);

        /* Name and Mode */
        r = sd_bus_message_append(m, "ss", scope, "fail");
        if (r < 0)
                return bus_log_create_error(r);

        /* Properties */
        r = sd_bus_message_open_container(m, 'a', "(sv)");
        if (r < 0)
                return bus_log_create_error(r);

        r = transient_scope_set_properties(m);
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        /* Auxiliary units */
        r = sd_bus_message_append(m, "a(sa(sv))", 0);
        if (r < 0)
                return bus_log_create_error(r);

        polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0)
                return log_error_errno(r, "Failed to start transient scope unit: %s", bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "o", &object);
        if (r < 0)
                return bus_log_parse_error(r);

        r = bus_wait_for_jobs_one(w, object, arg_quiet);
        if (r < 0)
                return r;

        r = acquire_invocation_id(bus, &invocation_id);
        if (r < 0)
                return r;

        r = strv_extendf(&user_env, "INVOCATION_ID=" SD_ID128_FORMAT_STR, SD_ID128_FORMAT_VAL(invocation_id));
        if (r < 0)
                return log_oom();

        if (arg_nice_set) {
                if (setpriority(PRIO_PROCESS, 0, arg_nice) < 0)
                        return log_error_errno(errno, "Failed to set nice level: %m");
        }

        if (arg_exec_group) {
                gid_t gid;

                r = get_group_creds(&arg_exec_group, &gid, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve group %s: %m", arg_exec_group);

                if (setresgid(gid, gid, gid) < 0)
                        return log_error_errno(errno, "Failed to change GID to " GID_FMT ": %m", gid);
        }

        if (arg_exec_user) {
                const char *home, *shell;
                uid_t uid;
                gid_t gid;

                r = get_user_creds(&arg_exec_user, &uid, &gid, &home, &shell, USER_CREDS_CLEAN|USER_CREDS_PREFER_NSS);
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve user %s: %m", arg_exec_user);

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

        env = strv_env_merge(3, environ, user_env, arg_environment);
        if (!env)
                return log_oom();

        if (!arg_quiet)
                log_info("Running scope as unit: %s", scope);

        execvpe(arg_cmdline[0], arg_cmdline, env);

        return log_error_errno(errno, "Failed to execute: %m");
}

static int start_transient_trigger(
                sd_bus *bus,
                const char *suffix) {

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        _cleanup_free_ char *trigger = NULL, *service = NULL;
        const char *object = NULL;
        int r;

        assert(bus);

        r = bus_wait_for_jobs_new(bus, &w);
        if (r < 0)
                return log_oom();

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
                r = make_unit_name(bus, UNIT_SERVICE, &service);
                if (r < 0)
                        return r;

                r = unit_name_change_suffix(service, suffix, &trigger);
                if (r < 0)
                        return log_error_errno(r, "Failed to change unit suffix: %m");
        }

        r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, "StartTransientUnit");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_set_allow_interactive_authorization(m, arg_ask_password);
        if (r < 0)
                return bus_log_create_error(r);

        /* Name and Mode */
        r = sd_bus_message_append(m, "ss", trigger, "fail");
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
                assert_not_reached("Invalid suffix");
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

                r = transient_service_set_properties(m, NULL);
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

        polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0)
                return log_error_errno(r, "Failed to start transient %s unit: %s", suffix + 1, bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "o", &object);
        if (r < 0)
                return bus_log_parse_error(r);

        r = bus_wait_for_jobs_one(w, object, arg_quiet);
        if (r < 0)
                return r;

        if (!arg_quiet) {
                log_info("Running %s as unit: %s", suffix + 1, trigger);
                if (!strv_isempty(arg_cmdline))
                        log_info("Will run service as unit: %s", service);
        }

        return 0;
}

static int run(int argc, char* argv[]) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_free_ char *description = NULL;
        int r, retval = EXIT_SUCCESS;

        log_show_color(true);
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (!strv_isempty(arg_cmdline) &&
            arg_transport == BUS_TRANSPORT_LOCAL &&
            !strv_find_startswith(arg_property, "RootDirectory=") &&
            !strv_find_startswith(arg_property, "RootImage=")) {
                /* Patch in an absolute path to fail early for user convenience, but only when we can do it
                 * (i.e. we will be running from the same file system). This also uses the user's $PATH,
                 * while we use a fixed search path in the manager. */

                _cleanup_free_ char *command = NULL;
                r = find_executable(arg_cmdline[0], &command);
                if (r < 0)
                        return log_error_errno(r, "Failed to find executable %s: %m", arg_cmdline[0]);

                free_and_replace(arg_cmdline[0], command);
        }

        if (!arg_description) {
                description = strv_join(arg_cmdline, " ");
                if (!description)
                        return log_oom();

                if (arg_unit && isempty(description)) {
                        r = free_and_strdup(&description, arg_unit);
                        if (r < 0)
                                return log_oom();
                }

                arg_description = description;
        }

        /* If --wait is used connect via the bus, unconditionally, as ref/unref is not supported via the limited direct
         * connection */
        if (arg_wait || arg_stdio != ARG_STDIO_NONE || (arg_user && arg_transport != BUS_TRANSPORT_LOCAL))
                r = bus_connect_transport(arg_transport, arg_host, arg_user, &bus);
        else
                r = bus_connect_transport_systemd(arg_transport, arg_host, arg_user, &bus);
        if (r < 0)
                return bus_log_connect_error(r);

        if (arg_scope)
                r = start_transient_scope(bus);
        else if (arg_path_property)
                r = start_transient_trigger(bus, ".path");
        else if (arg_socket_property)
                r = start_transient_trigger(bus, ".socket");
        else if (arg_with_timer)
                r = start_transient_trigger(bus, ".timer");
        else
                r = start_transient_service(bus, &retval);
        if (r < 0)
                return r;

        return retval;
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
