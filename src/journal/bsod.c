/* SPDX-License-Identifier: LPGL-2.1-or-later */

#include <errno.h>
#include <getopt.h>
#include <linux/vt.h>
#include <sys/ioctl.h>
#include <stdio.h>

#include "alloc-util.h"
#include "build.h"
#include "fd-util.h"
#include "io-util.h"
#include "log.h"
#include "main-func.h"
#include "qrcode-util.h"
#include "sd-id128.h"
#include "sd-journal.h"
#include "sysctl-util.h"
#include "terminal-util.h"

static void help(void) {
        printf("%s\n\n"
               "filters the journal to fetch the first message from the\n"
               " current boot with an emergency log level.\n\n"
               "   -h --help            Show this help\n"
               "      --version         Show package version\n",
               program_invocation_short_name);
}

static int acquire_first_emergency_log_message(char **ret) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        _cleanup_free_ char *message = NULL;

        const void *d;
        size_t l;
        sd_id128_t boot_id;
        char boot_id_filter[STRLEN("_BOOT_ID=") + SD_ID128_STRING_MAX];
        int r;

        r = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY);
        if (r < 0)
                return log_error_errno(r, "Failed to open journal: %m");

        r = sd_id128_get_boot(&boot_id);
        if (r < 0)
                return log_error_errno(r, "Failed to get boot ID: %m");

        xsprintf(boot_id_filter, "_BOOT_ID=" SD_ID128_FORMAT_STR, SD_ID128_FORMAT_VAL(boot_id));

        r = sd_journal_add_match(j, boot_id_filter, 0);
        if (r < 0)
                return log_warning_errno(r, "Failed to add boot ID filter: %m");

        r = sd_journal_add_match(j, "_UID=0", 0);
        if (r < 0)
                return log_warning_errno(r, "Failed to add User ID filter: %m");

        assert_cc(0 == LOG_EMERG);
        r = sd_journal_add_match(j, "PRIORITY=0", 0);
        if (r < 0)
                return log_warning_errno(r, "Failed to add Emergency filter: %m");

        r = sd_journal_seek_head(j);
        if (r < 0)
                return log_error_errno(r, "Failed to seek to start of jornal: %m");

        r = sd_journal_next(j);
        if (r < 0)
                return log_error_errno(r, "Failed to read next journal entry: %m");
        if (r == 0) {
                log_debug("No entries in the journal");
                return r;
        }

        r = sd_journal_get_data(j, "MESSAGE", &d, &l);
        if (r < 0)
                return log_error_errno(r, "Failed to read journal message: %m");

        message = memdup_suffix0((const char*)d + STRLEN("MESSAGE="), l - STRLEN("MESSAGE="));
        if (! message)
                return log_oom();

        *ret = TAKE_PTR(message);

        return r;
}

static int find_next_free_vt(int fd, int *ret_free_vt, int *ret_original_vt) {
        assert(fd);

        size_t i;
        struct vt_stat terminal_status;

        if (ioctl(fd, VT_GETSTATE, &terminal_status) < 0)
                return -errno;

        for (i = 0; i < sizeof(terminal_status.v_state) * 8; i++)
                if ((terminal_status.v_state & (1 << i)) == 0)
                        break;

        *ret_free_vt = i;
        *ret_original_vt = terminal_status.v_active;

        return 0;
}

static int display_emergency_message_fullscreen(char * message) {
        assert(message);
        int r, free_vt = 0, original_vt = 0;
        /* qr_code_start_row = 1, qr_code_start_column = 1*/
        char tty[STRLEN("/dev/tty") + DECIMAL_STR_MAX(int) + 1];
        _cleanup_close_ int fd = -EBADF;
        _cleanup_fclose_ FILE *stream = NULL, *out = NULL;
        char read_character_buffer = '\0';
        struct winsize w = {
                .ws_col = 80,
                .ws_row = 25,
        };

        fd = open_terminal("/dev/tty1", O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return log_error_errno(fd, "Failed to open tty1: %m");

        r = find_next_free_vt(fd, &free_vt, &original_vt);
        if (r < 0)
                return log_error_errno(r, "Failed to find a free VT: %m");

        xsprintf(tty, "/dev/tty%d", free_vt + 1);

        fd = open_terminal(tty, O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return log_error_errno(fd, "Failed to open tty: %m");

        if (ioctl(fd, TIOCGWINSZ, &w) < 0)
                log_warning_errno(errno, "Failed to fetch tty size, ignoring: %m");

        if (ioctl(fd, VT_ACTIVATE, free_vt + 1) < 0)
                return log_error_errno(errno, "Failed to activate tty: %m");

        r = loop_write(fd, ANSI_BACKGROUND_BLUE ANSI_HOME_CLEAR, strlen(ANSI_BACKGROUND_BLUE ANSI_HOME_CLEAR), /* do_poll = */ false);
        if (r < 0)
                log_warning_errno(r, "Failed to clear terminal, ignoring: %m");

        /* qr_code_start_row = w.ws_row * 3U / 4U;
        qr_code_start_column = w.ws_col * 3U / 4U; */
        r = set_terminal_cursor_position(fd, 2, 4);
        if (r < 0)
                log_warning_errno(r, "Failed to move terminal cursor position, ignoring: %m");

        r = loop_write(fd, message, strlen(message), /* do_poll = */false);
        if (r < 0)
                return log_warning_errno(r, "Failed to write emergency message to terminal: %m");

        out = fdopen(fd, "w");
        if (out == NULL)
                return log_error_errno(errno, "Failed to open output file: %m");

        r = print_qrcode(out, "Scan the code for help", (const char *) message);
        if (r < 0)
                log_warning_errno(r, "QR code could not be printed: %m");

        stream = fdopen(fd, "r");
        if (stream == NULL)
                return log_error_errno(errno, "Failed to open stream: %m");

        r = read_one_char(stream, &read_character_buffer, USEC_INFINITY, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to read character: %m");

        if (ioctl(fd, VT_ACTIVATE, original_vt) < 0)
                return log_error_errno(errno, "Failed to switch back to original VT: %m");

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
        _cleanup_free_ char *message = NULL;

        log_open();
        log_parse_environment();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = acquire_first_emergency_log_message(&message);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire first emergency log message: %m");

        if (!message) {
                log_debug("No emergency-level entries");
                return 0;
        }

        r = display_emergency_message_fullscreen(message);
        if (r < 0)
                return log_error_errno(r, "Failed to display emergency message on terminal: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
