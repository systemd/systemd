/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <getopt.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sd-messages.h"

#include "battery-util.h"
#include "build.h"
#include "errno-util.h"
#include "fd-util.h"
#include "glyph-util.h"
#include "io-util.h"
#include "log.h"
#include "main-func.h"
#include "parse-util.h"
#include "plymouth-util.h"
#include "pretty-print.h"
#include "proc-cmdline.h"
#include "socket-util.h"
#include "terminal-util.h"
#include "time-util.h"

#define BATTERY_LOW_MESSAGE \
        "Battery level critically low. Please connect your charger or the system will power off in 10 seconds."
#define BATTERY_RESTORED_MESSAGE \
        "A.C. power restored, continuing."

static bool arg_doit = true;

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-battery-check", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s\n\n"
               "%sCheck battery level to see whether there's enough charge.%s\n\n"
               "   -h --help            Show this help\n"
               "      --version         Show package version\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
}

static int plymouth_send_message(const char *mode, const char *message) {
        _cleanup_free_ char *plymouth_message = NULL;
        int c, r;

        assert(mode);
        assert(message);

        c = asprintf(&plymouth_message,
                     "C\x02%c%s%c"
                     "M\x02%c%s%c",
                     (int) strlen(mode) + 1, mode, '\x00',
                     (int) strlen(message) + 1, message, '\x00');
        if (c < 0)
                return log_oom();

        /* We set SOCK_NONBLOCK here so that we rather drop the message than wait for plymouth */
        r = plymouth_send_raw(plymouth_message, c, SOCK_NONBLOCK);
        if (r < 0)
                return log_full_errno(ERRNO_IS_NO_PLYMOUTH(r) ? LOG_DEBUG : LOG_WARNING, r,
                                      "Failed to communicate with plymouth: %m");

        return 0;
}

static int parse_argv(int argc, char * argv[]) {

        enum {
                ARG_VERSION = 0x100,
        };

        static const struct option options[] = {
                { "help",    no_argument, NULL, 'h'         },
                { "version", no_argument, NULL, ARG_VERSION },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (optind < argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s takes no argument.",
                                       program_invocation_short_name);
        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_free_ char *plymouth_message = NULL;
        _cleanup_close_ int fd = -EBADF;
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = proc_cmdline_get_bool("systemd.battery_check", PROC_CMDLINE_STRIP_RD_PREFIX|PROC_CMDLINE_TRUE_WHEN_MISSING, &arg_doit);
        if (r < 0)
                log_warning_errno(r, "Failed to parse systemd.battery_check= kernel command line option, ignoring: %m");

        if (!arg_doit) {
                log_info("Checking battery status and AC power existence is disabled by the kernel command line, skipping execution.");
                return 0;
        }

        r = battery_is_discharging_and_low();
        if (r < 0) {
                log_warning_errno(r, "Failed to check battery status, ignoring: %m");
                return 0;
        }
        if (r == 0)
                return 0;
        log_struct(LOG_EMERG,
                   LOG_MESSAGE("%s " BATTERY_LOW_MESSAGE, special_glyph(SPECIAL_GLYPH_LOW_BATTERY)),
                   "MESSAGE_ID=" SD_MESSAGE_BATTERY_LOW_WARNING_STR);

        fd = open_terminal("/dev/console", O_WRONLY|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                log_warning_errno(fd, "Failed to open console, ignoring: %m");
        else
                dprintf(fd, ANSI_HIGHLIGHT_RED "%s " BATTERY_LOW_MESSAGE ANSI_NORMAL "\n",
                        special_glyph_full(SPECIAL_GLYPH_LOW_BATTERY, /* force_utf = */ false));

        if (asprintf(&plymouth_message, "%s " BATTERY_LOW_MESSAGE,
                     special_glyph_full(SPECIAL_GLYPH_LOW_BATTERY, /* force_utf = */ true)) < 0)
                return log_oom();

        (void) plymouth_send_message("shutdown", plymouth_message);

        usleep_safe(10 * USEC_PER_SEC);

        r = battery_is_discharging_and_low();
        if (r < 0)
                return log_warning_errno(r, "Failed to check battery status, assuming not charged yet, powering off: %m");
        if (r > 0) {
                log_struct(LOG_EMERG,
                           LOG_MESSAGE("Battery level critically low, powering off."),
                           "MESSAGE_ID=" SD_MESSAGE_BATTERY_LOW_POWEROFF_STR);
                return r;
        }

        log_info(BATTERY_RESTORED_MESSAGE);
        if (fd >= 0)
                dprintf(fd, BATTERY_RESTORED_MESSAGE "\n");
        (void) plymouth_send_message("boot-up", BATTERY_RESTORED_MESSAGE);

        return 0;
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
