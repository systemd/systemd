/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-daemon.h"

#include "ansi-color.h"
#include "format-table.h"
#include "help-util.h"
#include "log.h"
#include "options.h"
#include "process-util.h"
#include "reboot-util.h"
#include "systemctl.h"
#include "systemctl-compat-halt.h"
#include "systemctl-logind.h"
#include "systemctl-start-unit.h"
#include "systemctl-util.h"
#include "utmp-wtmp.h"

static int halt_help(void) {
        _cleanup_(table_unrefp) Table *options = NULL;
        int r;

        r = option_parser_get_help_table_ns("halt", &options);
        if (r < 0)
                return r;

        /* Note: if you are tempted to add new command line switches here, please do not. Let this
         * compatibility command rest in peace. Its interface is not even owned by us as much as it is by
         * sysvinit. If you add something new, add it to "systemctl halt", "systemctl reboot", "systemctl
         * poweroff" instead. */

        help_cmdline(arg_action == ACTION_REBOOT ? "[OPTIONS…] [ARG]" : "[OPTIONS…]");
        help_abstract(arg_action == ACTION_REBOOT   ? "Reboot the system." :
                      arg_action == ACTION_POWEROFF ? "Power off the system." :
                                                      "Halt the system.");

        help_section("Options");
        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        printf("\n%sThis is a compatibility interface, please use the more powerful 'systemctl %s' command instead.%s\n",
               ansi_highlight_red(),
               arg_action == ACTION_REBOOT   ? "reboot" :
               arg_action == ACTION_POWEROFF ? "poweroff" :
                                               "halt",
               ansi_normal());

        help_man_page_reference("halt", "8");
        return 0;
}

int halt_parse_argv(int argc, char *argv[], int log_level_shift) {
        int r;

        assert(argc >= 0);
        assert(argv);

        OptionParser opts = {
                argc, argv,
                .namespace = "halt",
                .log_level_shift = log_level_shift,
        };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_NAMESPACE("halt"): {}

                OPTION_LONG("help", NULL, "Show this help"):
                        return halt_help();

                OPTION_LONG("halt", NULL, "Halt the machine"):
                        arg_action = ACTION_HALT;
                        break;

                OPTION('p', "poweroff", NULL, "Switch off the machine"):
                        if (arg_action != ACTION_REBOOT)
                                arg_action = ACTION_POWEROFF;
                        break;

                OPTION_LONG("reboot", NULL, "Reboot the machine"):
                        arg_action = ACTION_REBOOT;
                        break;

                OPTION('f', "force", NULL, "Force immediate halt/power-off/reboot"):
                        arg_force = 2;
                        break;

                OPTION('w', "wtmp-only", NULL, "Don't halt/power-off/reboot, just write wtmp record"):
                        arg_dry_run = true;
                        break;

                OPTION('d', "no-wtmp", NULL, "Don't write wtmp record"):
                        arg_no_wtmp = true;
                        break;

                OPTION_LONG("no-wall", NULL, "Don't send wall message before halt/power-off/reboot"):
                        arg_no_wall = true;
                        break;

                /* Hidden compat-only options. */
                OPTION('n', "no-sync", NULL, /* help= */ NULL):
                        arg_no_sync = true;
                        break;

                OPTION_SHORT('i', NULL, /* help= */ NULL): {}
                OPTION_SHORT('h', NULL, /* help= */ NULL):
                        /* Compatibility nops */
                        break;
                }

        char **args = option_parser_get_args(&opts);
        size_t n_args = option_parser_get_n_args(&opts);

        if (arg_action == ACTION_REBOOT && n_args <= 1) {
                r = update_reboot_parameter_and_warn(args[0], false);
                if (r < 0)
                        return r;
        } else if (n_args > 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Too many arguments.");

        return 1;
}

int halt_main(void) {
        int r;

        if (arg_force == 0) {
                /* always try logind first */
                if (arg_when > 0)
                        r = logind_schedule_shutdown(arg_action);
                else {
                        r = logind_check_inhibitors(arg_action);
                        if (r < 0)
                                return r;

                        r = logind_reboot(arg_action);
                }
                if (r >= 0)
                        return r;
                if (IN_SET(r, -EACCES, -EOPNOTSUPP, -EINPROGRESS))
                        /* Requested operation requires auth, is not supported on the local system or already in
                         * progress */
                        return r;
                /* on all other errors, try low-level operation */

                /* In order to minimize the difference between operation with and without logind, we explicitly
                 * enable non-blocking mode for this, as logind's shutdown operations are always non-blocking. */
                arg_no_block = true;

                if (!arg_dry_run)
                        return verb_start(0, NULL, /* data= */ 0, NULL);
        }

        r = must_be_root();
        if (r < 0)
                return r;

        if (!arg_no_wtmp) {
                if (sd_booted() > 0)
                        log_debug("Not writing utmp record, assuming that systemd-update-utmp is used.");
                else {
                        r = utmp_put_shutdown();
                        if (r < 0)
                                log_warning_errno(r, "Failed to write utmp record: %m");
                }
        }

        if (arg_dry_run)
                return 0;

        r = halt_now(arg_action);
        return log_error_errno(r, "Failed to %s: %m", action_table[arg_action].verb);
}
