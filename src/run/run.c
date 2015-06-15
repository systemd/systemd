/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

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

#include <stdio.h>
#include <getopt.h>

#include "sd-bus.h"
#include "sd-event.h"
#include "bus-util.h"
#include "event-util.h"
#include "strv.h"
#include "build.h"
#include "unit-name.h"
#include "env-util.h"
#include "path-util.h"
#include "bus-error.h"
#include "calendarspec.h"
#include "ptyfwd.h"
#include "formats-util.h"
#include "signal-util.h"

static bool arg_scope = false;
static bool arg_remain_after_exit = false;
static bool arg_no_block = false;
static const char *arg_unit = NULL;
static const char *arg_description = NULL;
static const char *arg_slice = NULL;
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
static bool arg_pty = false;
static usec_t arg_on_active = 0;
static usec_t arg_on_boot = 0;
static usec_t arg_on_startup = 0;
static usec_t arg_on_unit_active = 0;
static usec_t arg_on_unit_inactive = 0;
static char *arg_on_calendar = NULL;
static char **arg_timer_property = NULL;
static bool arg_quiet = false;

static void help(void) {
        printf("%s [OPTIONS...] {COMMAND} [ARGS...]\n\n"
               "Run the specified command in a transient scope or service or timer\n"
               "unit. If timer option is specified and unit is exist which is\n"
               "specified with --unit option then command can be omitted.\n\n"
               "  -h --help                       Show this help\n"
               "     --version                    Show package version\n"
               "     --user                       Run as user unit\n"
               "  -H --host=[USER@]HOST           Operate on remote host\n"
               "  -M --machine=CONTAINER          Operate on local container\n"
               "     --scope                      Run this as scope rather than service\n"
               "     --unit=UNIT                  Run under the specified unit name\n"
               "  -p --property=NAME=VALUE        Set unit property\n"
               "     --description=TEXT           Description for unit\n"
               "     --slice=SLICE                Run in the specified slice\n"
               "     --no-block                   Do not wait until operation finished\n"
               "  -r --remain-after-exit          Leave service around until explicitly stopped\n"
               "     --send-sighup                Send SIGHUP when terminating\n"
               "     --service-type=TYPE          Service type\n"
               "     --uid=USER                   Run as system user\n"
               "     --gid=GROUP                  Run as system group\n"
               "     --nice=NICE                  Nice level\n"
               "     --setenv=NAME=VALUE          Set environment\n"
               "  -t --pty                        Run service on pseudo tty\n"
               "  -q --quiet                      Suppress information messages during runtime\n\n"
               "Timer options:\n\n"
               "     --on-active=SECONDS          Run after SECONDS delay\n"
               "     --on-boot=SECONDS            Run SECONDS after machine was booted up\n"
               "     --on-startup=SECONDS         Run SECONDS after systemd activation\n"
               "     --on-unit-active=SECONDS     Run SECONDS after the last activation\n"
               "     --on-unit-inactive=SECONDS   Run SECONDS after the last deactivation\n"
               "     --on-calendar=SPEC           Realtime timer\n"
               "     --timer-property=NAME=VALUE  Set timer unit property\n",
               program_invocation_short_name);
}

static bool with_timer(void) {
        return arg_on_active || arg_on_boot || arg_on_startup || arg_on_unit_active || arg_on_unit_inactive || arg_on_calendar;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_USER,
                ARG_SYSTEM,
                ARG_SCOPE,
                ARG_UNIT,
                ARG_DESCRIPTION,
                ARG_SLICE,
                ARG_SEND_SIGHUP,
                ARG_EXEC_USER,
                ARG_EXEC_GROUP,
                ARG_SERVICE_TYPE,
                ARG_NICE,
                ARG_SETENV,
                ARG_TTY,
                ARG_ON_ACTIVE,
                ARG_ON_BOOT,
                ARG_ON_STARTUP,
                ARG_ON_UNIT_ACTIVE,
                ARG_ON_UNIT_INACTIVE,
                ARG_ON_CALENDAR,
                ARG_TIMER_PROPERTY,
                ARG_NO_BLOCK,
        };

        static const struct option options[] = {
                { "help",              no_argument,       NULL, 'h'                  },
                { "version",           no_argument,       NULL, ARG_VERSION          },
                { "user",              no_argument,       NULL, ARG_USER             },
                { "system",            no_argument,       NULL, ARG_SYSTEM           },
                { "scope",             no_argument,       NULL, ARG_SCOPE            },
                { "unit",              required_argument, NULL, ARG_UNIT             },
                { "description",       required_argument, NULL, ARG_DESCRIPTION      },
                { "slice",             required_argument, NULL, ARG_SLICE            },
                { "remain-after-exit", no_argument,       NULL, 'r'                  },
                { "send-sighup",       no_argument,       NULL, ARG_SEND_SIGHUP      },
                { "host",              required_argument, NULL, 'H'                  },
                { "machine",           required_argument, NULL, 'M'                  },
                { "service-type",      required_argument, NULL, ARG_SERVICE_TYPE     },
                { "uid",               required_argument, NULL, ARG_EXEC_USER        },
                { "gid",               required_argument, NULL, ARG_EXEC_GROUP       },
                { "nice",              required_argument, NULL, ARG_NICE             },
                { "setenv",            required_argument, NULL, ARG_SETENV           },
                { "property",          required_argument, NULL, 'p'                  },
                { "tty",               no_argument,       NULL, 't'                  },
                { "quiet",             no_argument,       NULL, 'q'                  },
                { "on-active",         required_argument, NULL, ARG_ON_ACTIVE        },
                { "on-boot",           required_argument, NULL, ARG_ON_BOOT          },
                { "on-startup",        required_argument, NULL, ARG_ON_STARTUP       },
                { "on-unit-active",    required_argument, NULL, ARG_ON_UNIT_ACTIVE   },
                { "on-unit-inactive",  required_argument, NULL, ARG_ON_UNIT_INACTIVE },
                { "on-calendar",       required_argument, NULL, ARG_ON_CALENDAR      },
                { "timer-property",    required_argument, NULL, ARG_TIMER_PROPERTY   },
                { "no-block",          no_argument,       NULL, ARG_NO_BLOCK         },
                {},
        };

        int r, c;
        CalendarSpec *spec = NULL;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "+hrH:M:p:tq", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case ARG_USER:
                        arg_user = true;
                        break;

                case ARG_SYSTEM:
                        arg_user = false;
                        break;

                case ARG_SCOPE:
                        arg_scope = true;
                        break;

                case ARG_UNIT:
                        arg_unit = optarg;
                        break;

                case ARG_DESCRIPTION:
                        arg_description = optarg;
                        break;

                case ARG_SLICE:
                        arg_slice = optarg;
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
                        r = safe_atoi(optarg, &arg_nice);
                        if (r < 0 || arg_nice < PRIO_MIN || arg_nice >= PRIO_MAX) {
                                log_error("Failed to parse nice value");
                                return -EINVAL;
                        }

                        arg_nice_set = true;
                        break;

                case ARG_SETENV:
                        if (strv_extend(&arg_environment, optarg) < 0)
                                return log_oom();

                        break;

                case 'p':
                        if (strv_extend(&arg_property, optarg) < 0)
                                return log_oom();

                        break;

                case 't':
                        arg_pty = true;
                        break;

                case 'q':
                        arg_quiet = true;
                        break;

                case ARG_ON_ACTIVE:

                        r = parse_sec(optarg, &arg_on_active);
                        if (r < 0) {
                                log_error("Failed to parse timer value: %s", optarg);
                                return r;
                        }

                        break;

                case ARG_ON_BOOT:

                        r = parse_sec(optarg, &arg_on_boot);
                        if (r < 0) {
                                log_error("Failed to parse timer value: %s", optarg);
                                return r;
                        }

                        break;

                case ARG_ON_STARTUP:

                        r = parse_sec(optarg, &arg_on_startup);
                        if (r < 0) {
                                log_error("Failed to parse timer value: %s", optarg);
                                return r;
                        }

                        break;

                case ARG_ON_UNIT_ACTIVE:

                        r = parse_sec(optarg, &arg_on_unit_active);
                        if (r < 0) {
                                log_error("Failed to parse timer value: %s", optarg);
                                return r;
                        }

                        break;

                case ARG_ON_UNIT_INACTIVE:

                        r = parse_sec(optarg, &arg_on_unit_inactive);
                        if (r < 0) {
                                log_error("Failed to parse timer value: %s", optarg);
                                return r;
                        }

                        break;

                case ARG_ON_CALENDAR:

                        r = calendar_spec_from_string(optarg, &spec);
                        if (r < 0) {
                                log_error("Invalid calendar spec: %s", optarg);
                                return r;
                        }
                        free(spec);
                        arg_on_calendar = optarg;
                        break;

                case ARG_TIMER_PROPERTY:

                        if (strv_extend(&arg_timer_property, optarg) < 0)
                                return log_oom();

                        break;

                case ARG_NO_BLOCK:
                        arg_no_block = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        if ((optind >= argc) && (!arg_unit || !with_timer())) {
                log_error("Command line to execute required.");
                return -EINVAL;
        }

        if (arg_user && arg_transport != BUS_TRANSPORT_LOCAL) {
                log_error("Execution in user context is not supported on non-local systems.");
                return -EINVAL;
        }

        if (arg_scope && arg_transport != BUS_TRANSPORT_LOCAL) {
                log_error("Scope execution is not supported on non-local systems.");
                return -EINVAL;
        }

        if (arg_scope && (arg_remain_after_exit || arg_service_type)) {
                log_error("--remain-after-exit and --service-type= are not supported in --scope mode.");
                return -EINVAL;
        }

        if (arg_pty && (with_timer() || arg_scope)) {
                log_error("--pty is not compatible in timer or --scope mode.");
                return -EINVAL;
        }

        if (arg_scope && with_timer()) {
                log_error("Timer options are not supported in --scope mode.");
                return -EINVAL;
        }

        if (arg_timer_property && !with_timer()) {
                log_error("--timer-property= has no effect without any other timer options.");
                return -EINVAL;
        }

        return 1;
}

static int transient_unit_set_properties(sd_bus_message *m, char **properties) {
        char **i;
        int r;

        r = sd_bus_message_append(m, "(sv)", "Description", "s", arg_description);
        if (r < 0)
                return r;

        STRV_FOREACH(i, properties) {
                r = sd_bus_message_open_container(m, 'r', "sv");
                if (r < 0)
                        return r;

                r = bus_append_unit_property_assignment(m, *i);
                if (r < 0)
                        return r;

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int transient_cgroup_set_properties(sd_bus_message *m) {
        int r;
        assert(m);

        if (!isempty(arg_slice)) {
                _cleanup_free_ char *slice;

                r = unit_name_mangle_with_suffix(arg_slice, UNIT_NAME_NOGLOB, ".slice", &slice);
                if (r < 0)
                        return r;

                r = sd_bus_message_append(m, "(sv)", "Slice", "s", slice);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int transient_kill_set_properties(sd_bus_message *m) {
        assert(m);

        if (arg_send_sighup)
                return sd_bus_message_append(m, "(sv)", "SendSIGHUP", "b", arg_send_sighup);
        else
                return 0;
}

static int transient_service_set_properties(sd_bus_message *m, char **argv, const char *pty_path) {
        int r;

        assert(m);

        r = transient_unit_set_properties(m, arg_property);
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
                        return r;
        }

        if (arg_service_type) {
                r = sd_bus_message_append(m, "(sv)", "Type", "s", arg_service_type);
                if (r < 0)
                        return r;
        }

        if (arg_exec_user) {
                r = sd_bus_message_append(m, "(sv)", "User", "s", arg_exec_user);
                if (r < 0)
                        return r;
        }

        if (arg_exec_group) {
                r = sd_bus_message_append(m, "(sv)", "Group", "s", arg_exec_group);
                if (r < 0)
                        return r;
        }

        if (arg_nice_set) {
                r = sd_bus_message_append(m, "(sv)", "Nice", "i", arg_nice);
                if (r < 0)
                        return r;
        }

        if (pty_path) {
                const char *e;

                r = sd_bus_message_append(m,
                                          "(sv)(sv)(sv)(sv)",
                                          "StandardInput", "s", "tty",
                                          "StandardOutput", "s", "tty",
                                          "StandardError", "s", "tty",
                                          "TTYPath", "s", pty_path);
                if (r < 0)
                        return r;

                e = getenv("TERM");
                if (e) {
                        char *n;

                        n = strjoina("TERM=", e);
                        r = sd_bus_message_append(m,
                                                  "(sv)",
                                                  "Environment", "as", 1, n);
                        if (r < 0)
                                return r;
                }
        }

        if (!strv_isempty(arg_environment)) {
                r = sd_bus_message_open_container(m, 'r', "sv");
                if (r < 0)
                        return r;

                r = sd_bus_message_append(m, "s", "Environment");
                if (r < 0)
                        return r;

                r = sd_bus_message_open_container(m, 'v', "as");
                if (r < 0)
                        return r;

                r = sd_bus_message_append_strv(m, arg_environment);
                if (r < 0)
                        return r;

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return r;

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return r;
        }

        /* Exec container */
        {
                r = sd_bus_message_open_container(m, 'r', "sv");
                if (r < 0)
                        return r;

                r = sd_bus_message_append(m, "s", "ExecStart");
                if (r < 0)
                        return r;

                r = sd_bus_message_open_container(m, 'v', "a(sasb)");
                if (r < 0)
                        return r;

                r = sd_bus_message_open_container(m, 'a', "(sasb)");
                if (r < 0)
                        return r;

                r = sd_bus_message_open_container(m, 'r', "sasb");
                if (r < 0)
                        return r;

                r = sd_bus_message_append(m, "s", argv[0]);
                if (r < 0)
                        return r;

                r = sd_bus_message_append_strv(m, argv);
                if (r < 0)
                        return r;

                r = sd_bus_message_append(m, "b", false);
                if (r < 0)
                        return r;

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return r;

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return r;

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return r;

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int transient_scope_set_properties(sd_bus_message *m) {
        int r;

        assert(m);

        r = transient_unit_set_properties(m, arg_property);
        if (r < 0)
                return r;

        r = transient_kill_set_properties(m);
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "(sv)", "PIDs", "au", 1, (uint32_t) getpid());
        if (r < 0)
                return r;

        return 0;
}

static int transient_timer_set_properties(sd_bus_message *m) {
        int r;

        assert(m);

        r = transient_unit_set_properties(m, arg_timer_property);
        if (r < 0)
                return r;

        if (arg_on_active) {
                r = sd_bus_message_append(m, "(sv)", "OnActiveSec", "t", arg_on_active);
                if (r < 0)
                        return r;
        }

        if (arg_on_boot) {
                r = sd_bus_message_append(m, "(sv)", "OnBootSec", "t", arg_on_boot);
                if (r < 0)
                        return r;
        }

        if (arg_on_startup) {
                r = sd_bus_message_append(m, "(sv)", "OnStartupSec", "t", arg_on_startup);
                if (r < 0)
                        return r;
        }

        if (arg_on_unit_active) {
                r = sd_bus_message_append(m, "(sv)", "OnUnitActiveSec", "t", arg_on_unit_active);
                if (r < 0)
                        return r;
        }

        if (arg_on_unit_inactive) {
                r = sd_bus_message_append(m, "(sv)", "OnUnitInactiveSec", "t", arg_on_unit_inactive);
                if (r < 0)
                        return r;
        }

        if (arg_on_calendar) {
                r = sd_bus_message_append(m, "(sv)", "OnCalendar", "s", arg_on_calendar);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int start_transient_service(
                sd_bus *bus,
                char **argv) {

        _cleanup_bus_message_unref_ sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        _cleanup_free_ char *service = NULL, *pty_path = NULL;
        _cleanup_close_ int master = -1;
        int r;

        assert(bus);
        assert(argv);

        if (arg_pty) {

                if (arg_transport == BUS_TRANSPORT_LOCAL) {
                        master = posix_openpt(O_RDWR|O_NOCTTY|O_CLOEXEC|O_NDELAY);
                        if (master < 0)
                                return log_error_errno(errno, "Failed to acquire pseudo tty: %m");

                        r = ptsname_malloc(master, &pty_path);
                        if (r < 0)
                                return log_error_errno(r, "Failed to determine tty name: %m");

                } else if (arg_transport == BUS_TRANSPORT_MACHINE) {
                        _cleanup_bus_unref_ sd_bus *system_bus = NULL;
                        const char *s;

                        r = sd_bus_open_system(&system_bus);
                        if (r < 0)
                                log_error_errno(r, "Failed to connect to system bus: %m");

                        r = sd_bus_call_method(system_bus,
                                               "org.freedesktop.machine1",
                                               "/org/freedesktop/machine1",
                                               "org.freedesktop.machine1.Manager",
                                               "OpenMachinePTY",
                                               &error,
                                               &reply,
                                               "s", arg_host);
                        if (r < 0) {
                                log_error("Failed to get machine PTY: %s", bus_error_message(&error, -r));
                                return r;
                        }

                        r = sd_bus_message_read(reply, "hs", &master, &s);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        reply = sd_bus_message_unref(reply);

                        master = fcntl(master, F_DUPFD_CLOEXEC, 3);
                        if (master < 0)
                                return log_error_errno(errno, "Failed to duplicate master fd: %m");

                        pty_path = strdup(s);
                        if (!pty_path)
                                return log_oom();
                } else
                        assert_not_reached("Can't allocate tty via ssh");

                if (unlockpt(master) < 0)
                        return log_error_errno(errno, "Failed to unlock tty: %m");
        }

        if (!arg_no_block) {
                r = bus_wait_for_jobs_new(bus, &w);
                if (r < 0)
                        return log_error_errno(r, "Could not watch jobs: %m");
        }

        if (arg_unit) {
                r = unit_name_mangle_with_suffix(arg_unit, UNIT_NAME_NOGLOB, ".service", &service);
                if (r < 0)
                        return log_error_errno(r, "Failed to mangle unit name: %m");
        } else if (asprintf(&service, "run-"PID_FMT".service", getpid()) < 0)
                return log_oom();

        r = sd_bus_message_new_method_call(
                        bus,
                        &m,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "StartTransientUnit");
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

        r = transient_service_set_properties(m, argv, pty_path);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        /* Auxiliary units */
        r = sd_bus_message_append(m, "a(sa(sv))", 0);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0) {
                log_error("Failed to start transient service unit: %s", bus_error_message(&error, -r));
                return r;
        }

        if (w) {
                const char *object;

                r = sd_bus_message_read(reply, "o", &object);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = bus_wait_for_jobs_one(w, object, arg_quiet);
                if (r < 0)
                        return r;
        }

        if (master >= 0) {
                _cleanup_(pty_forward_freep) PTYForward *forward = NULL;
                _cleanup_event_unref_ sd_event *event = NULL;
                char last_char = 0;

                r = sd_event_default(&event);
                if (r < 0)
                        return log_error_errno(r, "Failed to get event loop: %m");

                assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGWINCH, SIGTERM, SIGINT, -1) >= 0);

                (void) sd_event_add_signal(event, NULL, SIGINT, NULL, NULL);
                (void) sd_event_add_signal(event, NULL, SIGTERM, NULL, NULL);

                if (!arg_quiet)
                        log_info("Running as unit %s.\nPress ^] three times within 1s to disconnect TTY.", service);

                r = pty_forward_new(event, master, false, false, &forward);
                if (r < 0)
                        return log_error_errno(r, "Failed to create PTY forwarder: %m");

                r = sd_event_loop(event);
                if (r < 0)
                        return log_error_errno(r, "Failed to run event loop: %m");

                pty_forward_get_last_char(forward, &last_char);

                forward = pty_forward_free(forward);

                if (!arg_quiet && last_char != '\n')
                        fputc('\n', stdout);

        } else if (!arg_quiet)
                log_info("Running as unit %s.", service);

        return 0;
}

static int start_transient_scope(
                sd_bus *bus,
                char **argv) {

        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        _cleanup_strv_free_ char **env = NULL, **user_env = NULL;
        _cleanup_free_ char *scope = NULL;
        const char *object = NULL;
        int r;

        assert(bus);
        assert(argv);

        r = bus_wait_for_jobs_new(bus, &w);
        if (r < 0)
                return log_oom();

        if (arg_unit) {
                r = unit_name_mangle_with_suffix(arg_unit, UNIT_NAME_NOGLOB, ".scope", &scope);
                if (r < 0)
                        return log_error_errno(r, "Failed to mangle scope name: %m");
        } else if (asprintf(&scope, "run-"PID_FMT".scope", getpid()) < 0)
                return log_oom();

        r = sd_bus_message_new_method_call(
                        bus,
                        &m,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "StartTransientUnit");
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
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        /* Auxiliary units */
        r = sd_bus_message_append(m, "a(sa(sv))", 0);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0) {
                log_error("Failed to start transient scope unit: %s", bus_error_message(&error, -r));
                return r;
        }

        if (arg_nice_set) {
                if (setpriority(PRIO_PROCESS, 0, arg_nice) < 0)
                        return log_error_errno(errno, "Failed to set nice level: %m");
        }

        if (arg_exec_group) {
                gid_t gid;

                r = get_group_creds(&arg_exec_group, &gid);
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve group %s: %m", arg_exec_group);

                if (setresgid(gid, gid, gid) < 0)
                        return log_error_errno(errno, "Failed to change GID to " GID_FMT ": %m", gid);
        }

        if (arg_exec_user) {
                const char *home, *shell;
                uid_t uid;
                gid_t gid;

                r = get_user_creds(&arg_exec_user, &uid, &gid, &home, &shell);
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve user %s: %m", arg_exec_user);

                r = strv_extendf(&user_env, "HOME=%s", home);
                if (r < 0)
                        return log_oom();

                r = strv_extendf(&user_env, "SHELL=%s", shell);
                if (r < 0)
                        return log_oom();

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

        r = sd_bus_message_read(reply, "o", &object);
        if (r < 0)
                return bus_log_parse_error(r);

        r = bus_wait_for_jobs_one(w, object, arg_quiet);
        if (r < 0)
                return r;

        if (!arg_quiet)
                log_info("Running scope as unit %s.", scope);

        execvpe(argv[0], argv, env);

        return log_error_errno(errno, "Failed to execute: %m");
}

static int start_transient_timer(
                sd_bus *bus,
                char **argv) {

        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        _cleanup_free_ char *timer = NULL, *service = NULL;
        const char *object = NULL;
        int r;

        assert(bus);
        assert(argv);

        r = bus_wait_for_jobs_new(bus, &w);
        if (r < 0)
                return log_oom();

        if (arg_unit) {
                switch (unit_name_to_type(arg_unit)) {

                case UNIT_SERVICE:
                        service = strdup(arg_unit);
                        if (!service)
                                return log_oom();

                        r = unit_name_change_suffix(service, ".timer", &timer);
                        if (r < 0)
                                return log_error_errno(r, "Failed to change unit suffix: %m");
                        break;

                case UNIT_TIMER:
                        timer = strdup(arg_unit);
                        if (!timer)
                                return log_oom();

                        r = unit_name_change_suffix(timer, ".service", &service);
                        if (r < 0)
                                return log_error_errno(r, "Failed to change unit suffix: %m");
                        break;

                default:
                        r = unit_name_mangle_with_suffix(arg_unit, UNIT_NAME_NOGLOB, ".service", &service);
                        if (r < 0)
                                return log_error_errno(r, "Failed to mangle unit name: %m");

                        r = unit_name_mangle_with_suffix(arg_unit, UNIT_NAME_NOGLOB, ".timer", &timer);
                        if (r < 0)
                                return log_error_errno(r, "Failed to mangle unit name: %m");

                        break;
                }
        } else if ((asprintf(&service, "run-"PID_FMT".service", getpid()) < 0) ||
                   (asprintf(&timer, "run-"PID_FMT".timer", getpid()) < 0))
                return log_oom();

        r = sd_bus_message_new_method_call(
                        bus,
                        &m,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "StartTransientUnit");
        if (r < 0)
                return bus_log_create_error(r);

        /* Name and Mode */
        r = sd_bus_message_append(m, "ss", timer, "fail");
        if (r < 0)
                return bus_log_create_error(r);

        /* Properties */
        r = sd_bus_message_open_container(m, 'a', "(sv)");
        if (r < 0)
                return bus_log_create_error(r);

        r = transient_timer_set_properties(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'a', "(sa(sv))");
        if (r < 0)
                return bus_log_create_error(r);

        if (argv[0]) {
                r = sd_bus_message_open_container(m, 'r', "sa(sv)");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "s", service);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_open_container(m, 'a', "(sv)");
                if (r < 0)
                        return bus_log_create_error(r);

                r = transient_service_set_properties(m, argv, NULL);
                if (r < 0)
                        return bus_log_create_error(r);

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

        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0) {
                log_error("Failed to start transient timer unit: %s", bus_error_message(&error, -r));
                return r;
        }

        r = sd_bus_message_read(reply, "o", &object);
        if (r < 0)
                return bus_log_parse_error(r);

        r = bus_wait_for_jobs_one(w, object, arg_quiet);
        if (r < 0)
                return r;

        log_info("Running timer as unit %s.", timer);
        if (argv[0])
                log_info("Will run service as unit %s.", service);

        return 0;
}

int main(int argc, char* argv[]) {
        _cleanup_bus_close_unref_ sd_bus *bus = NULL;
        _cleanup_free_ char *description = NULL, *command = NULL;
        int r;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        if (argc > optind) {
                r = find_binary(argv[optind], arg_transport == BUS_TRANSPORT_LOCAL, &command);
                if (r < 0) {
                        log_error_errno(r, "Failed to find executable %s%s: %m",
                                        argv[optind],
                                        arg_transport == BUS_TRANSPORT_LOCAL ? "" : " on local system");
                        goto finish;
                }
                argv[optind] = command;
        }

        if (!arg_description) {
                description = strv_join(argv + optind, " ");
                if (!description) {
                        r = log_oom();
                        goto finish;
                }

                if (arg_unit && isempty(description)) {
                        free(description);
                        description = strdup(arg_unit);

                        if (!description) {
                                r = log_oom();
                                goto finish;
                        }
                }

                arg_description = description;
        }

        r = bus_open_transport_systemd(arg_transport, arg_host, arg_user, &bus);
        if (r < 0) {
                log_error_errno(r, "Failed to create bus connection: %m");
                goto finish;
        }

        if (arg_scope)
                r = start_transient_scope(bus, argv + optind);
        else if (with_timer())
                r = start_transient_timer(bus, argv + optind);
        else
                r = start_transient_service(bus, argv + optind);

finish:
        strv_free(arg_environment);
        strv_free(arg_property);
        strv_free(arg_timer_property);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
