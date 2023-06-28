/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <getopt.h>
#include <sys/socket.h>
#include <unistd.h>

#include "battery-util.h"
#include "build.h"
#include "constants.h"
#include "errno-util.h"
#include "glyph-util.h"
#include "fd-util.h"
#include "io-util.h"
#include "log.h"
#include "main-func.h"
#include "socket-util.h"
#include "terminal-util.h"

static void help(void) {
        printf("%s\n\n"
               "Checks battery level to see whether there's enough charge.\n\n"
               "   -h --help            Show this help\n"
               "      --version         Show package version\n",
               program_invocation_short_name);
}

static void battery_check_send_plymouth_message(char *message, const char *mode) {
        assert(message);
        assert(mode);

        int r;
        static const union sockaddr_union sa = PLYMOUTH_SOCKET;
        _cleanup_close_ int fd = -EBADF;
        _cleanup_free_ char *plymouth_message = NULL;

        int c = asprintf(&plymouth_message,
                                 "C\x02%c%s%c"
                                 "M\x02%c%s%c",
                                 (int) strlen(mode) + 1, mode, '\x00',
                                 (int) strlen(message) + 1, message, '\x00');
        if (c < 0)
                return (void) log_oom();

        /* We set SOCK_NONBLOCK here so that we rather drop the
         * message than wait for plymouth */
        fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0)
                return (void) log_warning_errno(errno, "socket() failed: %m");

        if (connect(fd, &sa.sa, SOCKADDR_UN_LEN(sa.un)) < 0)
                return (void) log_full_errno(IN_SET(errno, EAGAIN, ENOENT) || ERRNO_IS_DISCONNECT(errno) ? LOG_DEBUG : LOG_WARNING, errno, "Connection to plymouth failed: %m");

        r = loop_write(fd, plymouth_message, c, /* do_poll = */ false);
        if (r < 0)
                return (void) log_full_errno(IN_SET(r, -EAGAIN, -ENOENT) || ERRNO_IS_DISCONNECT(r) ?
LOG_DEBUG : LOG_WARNING, r, "Failed to write to plymouth, ignoring: %m");
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
                        help();
                        return 0;

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
        int r;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = battery_is_discharging_and_low();
        if (r < 0) {
                log_warning_errno(r, "Failed to check battery status, ignoring: %m");
                return 0;
        }

        if (r > 0) {
                _cleanup_close_ int fd = -EBADF;
                _cleanup_free_ char *message = NULL, *plymouth_message = NULL, *ac_message = NULL;

                if (asprintf(&message, "%s Battery level critically low. Please connect your charger or the system will power off in 10 seconds.", special_glyph(SPECIAL_GLYPH_LOW_BATTERY)) < 0)
                        return log_oom();

                if (asprintf(&plymouth_message, "%s Battery level critically low. Please connect your charger or the system will power off in 10 seconds.", special_glyph_force_utf(SPECIAL_GLYPH_LOW_BATTERY)) < 0)
                        return log_oom();

                log_emergency("%s", message);

                fd = open_terminal("/dev/console", O_WRONLY|O_NOCTTY|O_CLOEXEC);
                if (fd < 0)
                        log_warning_errno(fd, "Failed to open console, ignoring: %m");
                else
                        dprintf(fd,  ANSI_HIGHLIGHT_RED "%s" ANSI_NORMAL "\n", message);

                battery_check_send_plymouth_message(plymouth_message, "shutdown");
                sleep(10);

                r = battery_is_discharging_and_low();
                if (r > 0) {
                        log_emergency("Battery level critically low, powering off.");
                        return r;
                }
                if (r < 0)
                        return log_warning_errno(r, "Failed to check battery status, ignoring: %m");

                if (asprintf(&ac_message, "A.C. power restored, continuing") < 0)
                        return log_oom();

                log_info("%s",ac_message);
                dprintf(fd, "%s\n", ac_message);
                battery_check_send_plymouth_message(ac_message, "boot-up");
        }
        return r;
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
