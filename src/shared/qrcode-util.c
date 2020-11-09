/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "qrcode-util.h"

#if HAVE_QRENCODE
#include <qrencode.h>

#include "dlfcn-util.h"
#include "locale-util.h"
#include "terminal-util.h"

#define ANSI_WHITE_ON_BLACK "\033[40;37;1m"

static void print_border(FILE *output, unsigned width) {
        /* Four rows of border */
        for (unsigned y = 0; y < 4; y += 2) {
                fputs(ANSI_WHITE_ON_BLACK, output);

                for (unsigned x = 0; x < 4 + width + 4; x++)
                        fputs("\342\226\210", output);

                fputs(ANSI_NORMAL "\n", output);
        }
}

static void write_qrcode(FILE *output, QRcode *qr) {
        assert(qr);

        if (!output)
                output = stdout;

        print_border(output, qr->width);

        for (unsigned y = 0; y < (unsigned) qr->width; y += 2) {
                const uint8_t *row1 = qr->data + qr->width * y;
                const uint8_t *row2 = row1 + qr->width;

                fputs(ANSI_WHITE_ON_BLACK, output);
                for (unsigned x = 0; x < 4; x++)
                        fputs("\342\226\210", output);

                for (unsigned x = 0; x < (unsigned) qr->width; x++) {
                        bool a, b;

                        a = row1[x] & 1;
                        b = (y+1) < (unsigned) qr->width ? (row2[x] & 1) : false;

                        if (a && b)
                                fputc(' ', output);
                        else if (a)
                                fputs("\342\226\204", output);
                        else if (b)
                                fputs("\342\226\200", output);
                        else
                                fputs("\342\226\210", output);
                }

                for (unsigned x = 0; x < 4; x++)
                        fputs("\342\226\210", output);
                fputs(ANSI_NORMAL "\n", output);
        }

        print_border(output, qr->width);
        fflush(output);
}

int print_qrcode(FILE *out, const char *header, const char *string) {
        QRcode* (*sym_QRcode_encodeString)(const char *string, int version, QRecLevel level, QRencodeMode hint, int casesensitive);
        void (*sym_QRcode_free)(QRcode *qrcode);
        _cleanup_(dlclosep) void *dl = NULL;
        QRcode* qr;
        int r;

        /* If this is not an UTF-8 system or ANSI colors aren't supported/disabled don't print any QR
         * codes */
        if (!is_locale_utf8() || !colors_enabled())
                return -EOPNOTSUPP;

        dl = dlopen("libqrencode.so.4", RTLD_LAZY);
        if (!dl)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "QRCODE support is not installed: %s", dlerror());

        r = dlsym_many_and_warn(
                        dl,
                        LOG_DEBUG,
                        &sym_QRcode_encodeString, "QRcode_encodeString",
                        &sym_QRcode_free, "QRcode_free",
                        NULL);
        if (r < 0)
                return r;

        qr = sym_QRcode_encodeString(string, 0, QR_ECLEVEL_L, QR_MODE_8, 0);
        if (!qr)
                return -ENOMEM;

        if (header)
                fprintf(out, "\n%s:\n\n", header);

        write_qrcode(out, qr);

        fputc('\n', out);

        sym_QRcode_free(qr);
        return 0;
}
#endif
