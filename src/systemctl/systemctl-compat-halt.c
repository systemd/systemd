/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <unistd.h>

#include "sd-daemon.h"

#include "alloc-util.h"
#include "pretty-print.h"
#include "process-util.h"
#include "reboot-util.h"
#include "systemctl-compat-halt.h"
#include "systemctl-compat-telinit.h"
#include "systemctl-logind.h"
#include "systemctl-start-unit.h"
#include "systemctl-util.h"
#include "systemctl.h"
#include "terminal-util.h"
#include "utmp-wtmp.h"

static int halt_help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("halt", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...]%s\n"
               "\n%s%s the system.%s\n"
               "\nOptions:\n"
               "     --help      Show this help\n"
               "     --halt      Halt the machine\n"
               "  -p --poweroff  Switch off the machine\n"
               "     --reboot    Reboot the machine\n"
               "  -f --force     Force immediate halt/power-off/reboot\n"
               "  -w --wtmp-only Don't halt/power-off/reboot, just write wtmp record\n"
               "  -d --no-wtmp   Don't write wtmp record\n"
               "     --no-wall   Don't send wall message before halt/power-off/reboot\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               arg_action == ACTION_REBOOT ? " [ARG]" : "",
               ansi_highlight(),
               arg_action == ACTION_REBOOT           ? "Reboot" :
                       arg_action == ACTION_POWEROFF ? "Power off" :
                                                       "Halt",
               ansi_normal(),
               link);

        return 0;
}

int halt_parse_argv(int argc, char *argv[]) {
        enum {
                ARG_HELP = 0x100,
                ARG_HALT,
                ARG_REBOOT,
                ARG_NO_WALL
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, ARG_HELP    },
                { "halt",      no_argument,       NULL, ARG_HALT    },
                { "poweroff",  no_argument,       NULL, 'p'         },
                { "reboot",    no_argument,       NULL, ARG_REBOOT  },
                { "force",     no_argument,       NULL, 'f'         },
                { "wtmp-only", no_argument,       NULL, 'w'         },
                { "no-wtmp",   no_argument,       NULL, 'd'         },
                { "no-sync",   no_argument,       NULL, 'n'         },
                { "no-wall",   no_argument,       NULL, ARG_NO_WALL },
                {}
        };

        int c, r, runlevel;

        assert(argc >= 0);
        assert(argv);

        /* called in sysvinit system as last command in shutdown/reboot so this is always forceful */
        if (utmp_get_runlevel(&runlevel, NULL) >= 0)
                if (IN_SET(runlevel, '0', '6'))
                        arg_force = 2;

        while ((c = getopt_long(argc, argv, "pfwdnih", options, NULL)) >= 0)
                switch (c) {

                case ARG_HELP:
                        return halt_help();

                case ARG_HALT:
                        arg_action = ACTION_HALT;
                        break;

                case 'p':
                        if (arg_action != ACTION_REBOOT)
                                arg_action = ACTION_POWEROFF;
                        break;

                case ARG_REBOOT:
                        arg_action = ACTION_REBOOT;
                        break;

                case 'f':
                        arg_force = 2;
                        break;

                case 'w':
                        arg_dry_run = true;
                        break;

                case 'd':
                        arg_no_wtmp = true;
                        break;

                case 'n':
                        arg_no_sync = true;
                        break;

                case ARG_NO_WALL:
                        arg_no_wall = true;
                        break;

                case 'i':
                case 'h':
                        /* Compatibility nops */
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (arg_action == ACTION_REBOOT && (argc == optind || argc == optind + 1)) {
                r = update_reboot_parameter_and_warn(argc == optind + 1 ? argv[optind] : NULL, false);
                if (r < 0)
                        return r;
        } else if (optind < argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Too many arguments.");

        return 1;
}

int halt_main(void) {
        int r;

        if (arg_force == 0) {
                /* always try logind first */
                if (arg_when > 0)
                        r = logind_schedule_shutdown();
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
                        return start_with_fallback();
        }

        if (geteuid() != 0) {
                (void) must_be_root();
                return -EPERM;
        }

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
