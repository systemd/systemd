/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <unistd.h>

#include "alloc-util.h"
#include "pretty-print.h"
#include "rlimit-util.h"
#include "systemctl-compat-telinit.h"
#include "systemctl-daemon-reload.h"
#include "systemctl-start-unit.h"
#include "systemctl-sysv-compat.h"
#include "systemctl.h"
#include "terminal-util.h"

static int telinit_help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("telinit", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] COMMAND\n\n"
               "%sSend control commands to the init daemon.%s\n"
               "\nCommands:\n"
               "  0              Power-off the machine\n"
               "  6              Reboot the machine\n"
               "  2, 3, 4, 5     Start runlevelX.target unit\n"
               "  1, s, S        Enter rescue mode\n"
               "  q, Q           Reload init daemon configuration\n"
               "  u, U           Reexecute init daemon\n"
               "\nOptions:\n"
               "     --help      Show this help\n"
               "     --no-wall   Don't send wall message before halt/power-off/reboot\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
}

int telinit_parse_argv(int argc, char *argv[]) {
        enum {
                ARG_HELP = 0x100,
                ARG_NO_WALL
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, ARG_HELP    },
                { "no-wall",   no_argument,       NULL, ARG_NO_WALL },
                {}
        };

        static const struct {
                char from;
                enum action to;
        } table[] = {
                { '0', ACTION_POWEROFF },
                { '6', ACTION_REBOOT },
                { '1', ACTION_RESCUE },
                { '2', ACTION_RUNLEVEL2 },
                { '3', ACTION_RUNLEVEL3 },
                { '4', ACTION_RUNLEVEL4 },
                { '5', ACTION_RUNLEVEL5 },
                { 's', ACTION_RESCUE },
                { 'S', ACTION_RESCUE },
                { 'q', ACTION_RELOAD },
                { 'Q', ACTION_RELOAD },
                { 'u', ACTION_REEXEC },
                { 'U', ACTION_REEXEC }
        };

        unsigned i;
        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "", options, NULL)) >= 0)
                switch (c) {

                case ARG_HELP:
                        return telinit_help();

                case ARG_NO_WALL:
                        arg_no_wall = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (optind >= argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s: required argument missing.",
                                       program_invocation_short_name);

        if (optind + 1 < argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Too many arguments.");

        if (strlen(argv[optind]) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Expected single character argument.");

        for (i = 0; i < ELEMENTSOF(table); i++)
                if (table[i].from == argv[optind][0])
                        break;

        if (i >= ELEMENTSOF(table))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Unknown command '%s'.", argv[optind]);

        arg_action = table[i].to;

        optind++;

        return 1;
}

int start_with_fallback(void) {
        int r;

        /* First, try systemd via D-Bus. */
        r = verb_start(0, NULL, NULL);
        if (r == 0)
                return 0;

#if HAVE_SYSV_COMPAT
        /* Nothing else worked, so let's try /dev/initctl */
        if (talk_initctl(action_to_runlevel()) > 0)
                return 0;
#endif

        return log_error_errno(r, "Failed to talk to init daemon: %m");
}

int reload_with_fallback(void) {

        assert(IN_SET(arg_action, ACTION_RELOAD, ACTION_REEXEC));

        /* First, try systemd via D-Bus */
        if (daemon_reload(arg_action, /* graceful= */ true) > 0)
                return 0;

        /* That didn't work, so let's try signals */
        if (kill(1, arg_action == ACTION_RELOAD ? SIGHUP : SIGTERM) < 0)
                return log_error_errno(errno, "kill() failed: %m");

        return 0;
}

int exec_telinit(char *argv[]) {
        (void) rlimit_nofile_safe();
        (void) execv(TELINIT, argv);

        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                               "Couldn't find an alternative telinit implementation to spawn.");
}
