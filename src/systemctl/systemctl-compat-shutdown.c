/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "ansi-color.h"
#include "format-table.h"
#include "help-util.h"
#include "log.h"
#include "options.h"
#include "parse-util.h"
#include "reboot-util.h"
#include "string-util.h"
#include "strv.h"
#include "systemctl.h"
#include "systemctl-compat-shutdown.h"
#include "time-util.h"

static int shutdown_help(void) {
        _cleanup_(table_unrefp) Table *options = NULL;
        int r;

        r = option_parser_get_help_table_ns("shutdown", &options);
        if (r < 0)
                return r;

        /* Note: if you are tempted to add new command line switches here, please do not. Let this
         * compatibility command rest in peace. Its interface is not even owned by us as much as it is by
         * sysvinit. If you add something new, add it to "systemctl halt", "systemctl reboot", "systemctl
         * poweroff" instead. */

        help_cmdline("[OPTIONS…] [TIME] [WALL…]");
        help_abstract("Shut down the system.");

        help_section("Options");
        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        printf("\n%sThis is a compatibility interface, please use the more powerful 'systemctl halt',\n"
               "'systemctl poweroff', 'systemctl reboot' commands instead.%s\n",
               ansi_highlight_red(), ansi_normal());

        help_man_page_reference("shutdown", "8");
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

                        if (tm.tm_hour != requested_hour || tm.tm_min != requested_min)
                                log_warning("Requested shutdown time %02d:%02d does not exist. "
                                            "Rescheduling to %02d:%02d.",
                                            requested_hour,
                                            requested_min,
                                            tm.tm_hour,
                                            tm.tm_min);
                }

                *ret = s;
        }

        return 0;
}

int shutdown_parse_argv(int argc, char *argv[], int log_level_shift) {
        int r;

        assert(argc >= 0);
        assert(argv);

        OptionParser opts = {
                argc, argv,
                .namespace = "shutdown",
                .log_level_shift = log_level_shift,
        };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_NAMESPACE("shutdown"): {}

                OPTION_LONG("help", NULL, "Show this help"):
                        return shutdown_help();

                OPTION('H', "halt", NULL, "Halt the machine"):
                        arg_action = ACTION_HALT;
                        break;

                OPTION('P', "poweroff", NULL, "Power-off the machine"):
                        arg_action = ACTION_POWEROFF;
                        break;

                OPTION('r', "reboot", NULL, "Reboot the machine"):
                        if (kexec_loaded())
                                arg_action = ACTION_KEXEC;
                        else
                                arg_action = ACTION_REBOOT;
                        break;

                OPTION_SHORT('h', NULL, "Equivalent to --poweroff, overridden by --halt"):
                        if (arg_action != ACTION_HALT)
                                arg_action = ACTION_POWEROFF;
                        break;

                OPTION_SHORT('k', NULL, "Don't halt/power-off/reboot, just send warnings"):
                        arg_dry_run = true;
                        break;

                OPTION_LONG("no-wall", NULL, "Don't send wall message before halt/power-off/reboot"):
                        arg_no_wall = true;
                        break;

                OPTION_SHORT('c', NULL, "Cancel a pending shutdown"):
                        arg_action = ACTION_CANCEL_SHUTDOWN;
                        break;

                OPTION_LONG("show", NULL, "Show pending shutdown"):
                        arg_action = ACTION_SHOW_SHUTDOWN;
                        break;

                /* Hidden compat options. */
                OPTION('K', "kexec", NULL, /* help= */ NULL):
                        arg_action = ACTION_KEXEC;
                        break;

                OPTION_SHORT('a', NULL,  /* help= */ NULL): {}   /* compatibility noops */
                OPTION_SHORT('f', NULL,  /* help= */ NULL): {}
                OPTION_SHORT('F', NULL,  /* help= */ NULL): {}
                OPTION_SHORT('t', "ARG", /* help= */ NULL):
                        break;
                }

        char **args = option_parser_get_args(&opts);
        size_t n_args = option_parser_get_n_args(&opts);

        if (n_args > 0 && arg_action != ACTION_CANCEL_SHUTDOWN) {
                r = parse_shutdown_time_spec(args[0], &arg_when);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse time specification: %s", args[0]);
        } else
                arg_when = USEC_INFINITY; /* logind chooses on server side */

        char **wall = NULL;
        if (n_args > 0 && arg_action == ACTION_CANCEL_SHUTDOWN)
                /* No time argument for shutdown cancel */
                wall = args;
        else if (n_args > 1)
                /* We skip the time argument */
                wall = args + 1;

        if (wall) {
                char **copy = strv_copy(wall);
                if (!copy)
                        return log_oom();
                strv_free_and_replace(arg_wall, copy);
        }

        return 1;
}
