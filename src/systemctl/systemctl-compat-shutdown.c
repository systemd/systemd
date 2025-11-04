/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "alloc-util.h"
#include "log.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "reboot-util.h"
#include "string-util.h"
#include "strv.h"
#include "systemctl.h"
#include "systemctl-compat-shutdown.h"
#include "systemctl-logind.h"
#include "time-util.h"

static int shutdown_help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("shutdown", "8", &link);
        if (r < 0)
                return log_oom();

        /* Note: if you are tempted to add new command line switches here, please do not. Let this
         * compatibility command rest in peace. Its interface is not even owned by us as much as it is by
         * sysvinit. If you add something new, add it to "systemctl halt", "systemctl reboot", "systemctl
         * poweroff" instead. */

        printf("%s [OPTIONS...] [TIME] [WALL...]\n"
               "\n%sShut down the system.%s\n"
               "\nOptions:\n"
               "     --help      Show this help\n"
               "  -H --halt      Halt the machine\n"
               "  -P --poweroff  Power-off the machine\n"
               "  -r --reboot    Reboot the machine\n"
               "  -h             Equivalent to --poweroff, overridden by --halt\n"
               "  -k             Don't halt/power-off/reboot, just send warnings\n"
               "     --no-wall   Don't send wall message before halt/power-off/reboot\n"
               "  -c             Cancel a pending shutdown\n"
               "     --show      Show pending shutdown\n"
               "\n%sThis is a compatibility interface, please use the more powerful 'systemctl halt',\n"
               "'systemctl poweroff', 'systemctl reboot' commands instead.%s\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               ansi_highlight(), ansi_normal(),
               ansi_highlight_red(), ansi_normal(),
               link);

        return 0;
}

static int parse_shutdown_time_spec(const char *t, usec_t *ret) {
        int r;

        assert(t);
        assert(ret);

        /* This parses SysV compat time spec. */

        if (streq(t, "now"))
                *ret = 0;
        else if (!strchr(t, ':')) {
                uint64_t u;

                if (safe_atou64(t, &u) < 0)
                        return -EINVAL;

                *ret = now(CLOCK_REALTIME) + USEC_PER_MINUTE * u;
        } else {
                char *e = NULL;
                long hour, minute;

                errno = 0;
                hour = strtol(t, &e, 10);
                if (errno > 0 || *e != ':' || hour < 0 || hour > 23)
                        return -EINVAL;

                minute = strtol(e+1, &e, 10);
                if (errno > 0 || *e != 0 || minute < 0 || minute > 59)
                        return -EINVAL;

                usec_t n = now(CLOCK_REALTIME);
                struct tm tm = {};

                r = localtime_or_gmtime_usec(n, /* utc= */ false, &tm);
                if (r < 0)
                        return r;

                tm.tm_hour = (int) hour;
                tm.tm_min = (int) minute;
                tm.tm_sec = 0;

                usec_t s;
                r = mktime_or_timegm_usec(&tm, /* utc= */ false, &s);
                if (r < 0)
                        return r;

                if (s <= n) {
                        /* The specified time is today, but in the past. We need to schedule it for tomorrow
                         * at the same time. Adding USEC_PER_DAY would be wrong across DST changes, so just
                         * let mktime() normalise it. */
                        int requested_hour = tm.tm_hour;
                        int requested_min = tm.tm_min;

                        tm.tm_mday++;
                        tm.tm_isdst = -1;
                        r = mktime_or_timegm_usec(&tm, /* utc= */ false, &s);
                        if (r < 0)
                                return r;

                        if (tm.tm_hour != requested_hour || tm.tm_min != requested_min) {
                                log_warning("Requested shutdown time %02d:%02d does not exist. "
                                            "Rescheduling to %02d:%02d.",
                                            requested_hour,
                                            requested_min,
                                            tm.tm_hour,
                                            tm.tm_min);
                        }
                }

                *ret = s;
        }

        return 0;
}

int shutdown_parse_argv(int argc, char *argv[]) {
        enum {
                ARG_HELP = 0x100,
                ARG_NO_WALL,
                ARG_SHOW
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, ARG_HELP    },
                { "halt",      no_argument,       NULL, 'H'         },
                { "poweroff",  no_argument,       NULL, 'P'         },
                { "reboot",    no_argument,       NULL, 'r'         },
                { "kexec",     no_argument,       NULL, 'K'         }, /* not documented extension */
                { "no-wall",   no_argument,       NULL, ARG_NO_WALL },
                { "show",      no_argument,       NULL, ARG_SHOW    },
                {}
        };

        char **wall = NULL;
        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "HPrhkKat:fFc", options, NULL)) >= 0)
                switch (c) {

                case ARG_HELP:
                        return shutdown_help();

                case 'H':
                        arg_action = ACTION_HALT;
                        break;

                case 'P':
                        arg_action = ACTION_POWEROFF;
                        break;

                case 'r':
                        if (kexec_loaded())
                                arg_action = ACTION_KEXEC;
                        else
                                arg_action = ACTION_REBOOT;
                        break;

                case 'K':
                        arg_action = ACTION_KEXEC;
                        break;

                case 'h':
                        if (arg_action != ACTION_HALT)
                                arg_action = ACTION_POWEROFF;
                        break;

                case 'k':
                        arg_dry_run = true;
                        break;

                case ARG_NO_WALL:
                        arg_no_wall = true;
                        break;

                case 'a':
                case 't': /* Note that we also ignore any passed argument to -t, not just the -t itself */
                case 'f':
                case 'F':
                        /* Compatibility nops */
                        break;

                case 'c':
                        arg_action = ACTION_CANCEL_SHUTDOWN;
                        break;

                case ARG_SHOW:
                        arg_action = ACTION_SHOW_SHUTDOWN;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (argc > optind && arg_action != ACTION_CANCEL_SHUTDOWN) {
                r = parse_shutdown_time_spec(argv[optind], &arg_when);
                if (r < 0) {
                        log_error("Failed to parse time specification: %s", argv[optind]);
                        return r;
                }
        } else
                arg_when = USEC_INFINITY; /* logind chooses on server side */

        if (argc > optind && arg_action == ACTION_CANCEL_SHUTDOWN)
                /* No time argument for shutdown cancel */
                wall = argv + optind;
        else if (argc > optind + 1)
                /* We skip the time argument */
                wall = argv + optind + 1;

        if (wall) {
                char **copy = strv_copy(wall);
                if (!copy)
                        return log_oom();
                strv_free_and_replace(arg_wall, copy);
        }

        optind = argc;

        return 1;
}
