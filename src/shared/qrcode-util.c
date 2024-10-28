/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "qrcode-util.h"

#if HAVE_QRENCODE
#include <qrencode.h>

#include "ansi-color.h"
#include "dlfcn-util.h"
#include "locale-util.h"
#include "log.h"
#include "strv.h"
#include "terminal-util.h"

#define ANSI_WHITE_ON_BLACK "\033[40;37;1m"
#define UNICODE_FULL_BLOCK       u8"█"
#define UNICODE_LOWER_HALF_BLOCK u8"▄"
#define UNICODE_UPPER_HALF_BLOCK u8"▀"

static void *qrcode_dl = NULL;

static DLSYM_PROTOTYPE(QRcode_encodeString) = NULL;
static DLSYM_PROTOTYPE(QRcode_free) = NULL;

int dlopen_qrencode(void) {
        int r;

        ELF_NOTE_DLOPEN("qrencode",
                        "Support for generating QR codes",
                        ELF_NOTE_DLOPEN_PRIORITY_SUGGESTED,
                        "libqrencode.so.4", "libqrencode.so.3");

        FOREACH_STRING(s, "libqrencode.so.4", "libqrencode.so.3") {
                r = dlopen_many_sym_or_warn(
                        &qrcode_dl, s, LOG_DEBUG,
                        DLSYM_ARG(QRcode_encodeString),
                        DLSYM_ARG(QRcode_free));
                if (r >= 0)
                        break;
        }

        return r;
}

static void print_border(FILE *output, unsigned width, unsigned row, unsigned column) {
        assert(output);
        assert(width);

        if (row != UINT_MAX && column != UINT_MAX) {
                int r, fd;

                fd = fileno(output);
                if (fd < 0)
                        return (void)log_debug_errno(errno, "Failed to get file descriptor from the file stream: %m");

                r = terminal_set_cursor_position(fd, row, column);
                if (r < 0)
                        log_warning_errno(r, "Failed to move terminal cursor position, ignoring: %m");

                /* Four rows of border */
                for (unsigned y = 0; y < 4; y += 2) {
                        fputs(ANSI_WHITE_ON_BLACK, output);

                        for (unsigned x = 0; x < 4 + width + 4; x++)
                                fputs(UNICODE_FULL_BLOCK, output);

                        fputs(ANSI_NORMAL "\n", output);
                        r = terminal_set_cursor_position(fd, row + 1, column);
                        if (r < 0)
                                log_warning_errno(r, "Failed to move terminal cursor position, ignoring: %m");
                }
        } else {
                /* Four rows of border */
                for (unsigned y = 0; y < 4; y += 2) {
                        fputs(ANSI_WHITE_ON_BLACK, output);

                        for (unsigned x = 0; x < 4 + width + 4; x++)
                                fputs(UNICODE_FULL_BLOCK, output);

                        fputs(ANSI_NORMAL "\n", output);
                }
        }
}

static void write_qrcode(FILE *output, QRcode *qr, unsigned int row, unsigned int column) {
        assert(qr);

        if (!output)
                output = stdout;

        print_border(output, qr->width, row, column);

        if (row != UINT_MAX && column != UINT_MAX) {
                /* After printing two rows of top border, we need to move the cursor down two rows before starting to print the actual QR code */
                int r, fd, move_down = 2;
                fd = fileno(output);
                if (fd < 0)
                        return (void)log_debug_errno(errno, "Failed to get file descriptor from the file stream: %m");

                r = terminal_set_cursor_position(fd, row + move_down, column);
                if (r < 0)
                        log_warning_errno(r, "Failed to move terminal cursor position, ignoring: %m");

                for (unsigned y = 0; y < (unsigned) qr->width; y += 2) {
                        const uint8_t *row1 = qr->data + qr->width * y;
                        const uint8_t *row2 = row1 + qr->width;

                        fputs(ANSI_WHITE_ON_BLACK, output);

                        for (unsigned x = 0; x < 4; x++)
                                fputs(UNICODE_FULL_BLOCK, output);

                        for (unsigned x = 0; x < (unsigned) qr->width; x++) {
                                bool a, b;

                                a = row1[x] & 1;
                                b = (y+1) < (unsigned) qr->width ? (row2[x] & 1) : false;

                                if (a && b)
                                        fputc(' ', output);
                                else if (a)
                                        fputs(UNICODE_LOWER_HALF_BLOCK, output);
                                else if (b)
                                        fputs(UNICODE_UPPER_HALF_BLOCK, output);
                                else
                                        fputs(UNICODE_FULL_BLOCK, output);
                        }

                        for (unsigned x = 0; x < 4; x++)
                                fputs(UNICODE_FULL_BLOCK, output);
                        r = terminal_set_cursor_position(fd, row + move_down, column);
                        if (r < 0)
                                log_warning_errno(r, "Failed to move terminal cursor position, ignoring: %m");
                        move_down += 1;
                        fputs(ANSI_NORMAL "\n", output);
                }

                print_border(output, qr->width, row + move_down, column);
        } else {

                for (unsigned y = 0; y < (unsigned) qr->width; y += 2) {
                        const uint8_t *row1 = qr->data + qr->width * y;
                        const uint8_t *row2 = row1 + qr->width;

                        fputs(ANSI_WHITE_ON_BLACK, output);
                        for (unsigned x = 0; x < 4; x++)
                                fputs(UNICODE_FULL_BLOCK, output);

                        for (unsigned x = 0; x < (unsigned) qr->width; x++) {
                                bool a, b;

                                a = row1[x] & 1;
                                b = (y+1) < (unsigned) qr->width ? (row2[x] & 1) : false;

                                if (a && b)
                                        fputc(' ', output);
                                else if (a)
                                        fputs(UNICODE_LOWER_HALF_BLOCK, output);
                                else if (b)
                                        fputs(UNICODE_UPPER_HALF_BLOCK, output);
                                else
                                        fputs(UNICODE_FULL_BLOCK, output);
                        }

                        for (unsigned x = 0; x < 4; x++)
                                fputs(UNICODE_FULL_BLOCK, output);
                        fputs(ANSI_NORMAL "\n", output);
                }

                print_border(output, qr->width, row, column);
        }

        fflush(output);
}

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(QRcode*, sym_QRcode_free, NULL);

int print_qrcode_full(
                FILE *out,
                const char *header,
                const char *string,
                unsigned row,
                unsigned column,
                unsigned tty_width,
                unsigned tty_height,
                bool check_tty) {

        int r;

        /* If this is not a UTF-8 system or ANSI colors aren't supported/disabled don't print any QR
         * codes */
        if (!is_locale_utf8())
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Not an UTF-8 system, cannot print qrcode");
        if (check_tty && !colors_enabled())
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Colors are disabled, cannot print qrcode");

        r = dlopen_qrencode();
        if (r < 0)
                return r;

        _cleanup_(sym_QRcode_freep) QRcode *qr =
                sym_QRcode_encodeString(string, 0, QR_ECLEVEL_L, QR_MODE_8, 1);
        if (!qr)
                return log_oom_debug();

        if (row != UINT_MAX && column != UINT_MAX) {
                unsigned qr_code_width, qr_code_height;

                int fd = fileno(out);
                if (fd < 0)
                        return log_debug_errno(errno, "Failed to get file descriptor from the file stream: %m");

                qr_code_width = qr_code_height = qr->width + 8;
                if (column + qr_code_width > tty_width)
                        column = tty_width - qr_code_width;

                /* Terminal characters are twice as high as they are wide so it's qr_code_height / 2,
                 * our QR code prints an extra new line, so we have -1 as well */
                if (row + qr_code_height > tty_height)
                        row = tty_height - (qr_code_height / 2 ) - 1;

                if (header) {
                        r = terminal_set_cursor_position(fd, row - 2, tty_width - qr_code_width - 2);
                        if (r < 0)
                                log_warning_errno(r, "Failed to move terminal cursor position, ignoring: %m");

                        fprintf(out, "%s:\n\n", header);
                }
        } else
                if (header)
                        fprintf(out, "\n%s:\n\n", header);

        write_qrcode(out, qr, row, column);
        fputc('\n', out);

        return 0;
}
#endif
