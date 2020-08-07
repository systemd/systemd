/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <qrencode.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "dlfcn-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "journal-qrcode.h"
#include "locale-util.h"
#include "macro.h"
#include "terminal-util.h"

#define ANSI_WHITE_ON_BLACK "\033[40;37;1m"

static void print_border(FILE *output, unsigned width) {
        unsigned x, y;

        /* Four rows of border */
        for (y = 0; y < 4; y += 2) {
                fputs(ANSI_WHITE_ON_BLACK, output);

                for (x = 0; x < 4 + width + 4; x++)
                        fputs("\342\226\210", output);

                fputs(ANSI_NORMAL "\n", output);
        }
}

int print_qr_code(
                FILE *output,
                const char *prefix_text,
                const void *seed,
                size_t seed_size,
                uint64_t start,
                uint64_t interval,
                const char *hn,
                sd_id128_t machine) {

        QRcode* (*sym_QRcode_encodeString)(const char *string, int version, QRecLevel level, QRencodeMode hint, int casesensitive);
        void (*sym_QRcode_free)(QRcode *qrcode);
        _cleanup_(dlclosep) void *dl = NULL;
        _cleanup_free_ char *url = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        size_t url_size = 0, i;
        unsigned x, y;
        QRcode* qr;
        int r;

        assert(seed);
        assert(seed_size > 0);

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

        f = open_memstream_unlocked(&url, &url_size);
        if (!f)
                return -ENOMEM;

        fputs("fss://", f);

        for (i = 0; i < seed_size; i++) {
                if (i > 0 && i % 3 == 0)
                        fputc('-', f);
                fprintf(f, "%02x", ((uint8_t*) seed)[i]);
        }

        fprintf(f, "/%"PRIx64"-%"PRIx64"?machine=" SD_ID128_FORMAT_STR,
                start,
                interval,
                SD_ID128_FORMAT_VAL(machine));

        if (hn)
                fprintf(f, ";hostname=%s", hn);

        r = fflush_and_check(f);
        if (r < 0)
                return r;

        f = safe_fclose(f);

        qr = sym_QRcode_encodeString(url, 0, QR_ECLEVEL_L, QR_MODE_8, 1);
        if (!qr)
                return -ENOMEM;

        if (prefix_text)
                fputs(prefix_text, output);

        print_border(output, qr->width);

        for (y = 0; y < (unsigned) qr->width; y += 2) {
                const uint8_t *row1, *row2;

                row1 = qr->data + qr->width * y;
                row2 = row1 + qr->width;

                fputs(ANSI_WHITE_ON_BLACK, output);
                for (x = 0; x < 4; x++)
                        fputs("\342\226\210", output);

                for (x = 0; x < (unsigned) qr->width; x ++) {
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

                for (x = 0; x < 4; x++)
                        fputs("\342\226\210", output);
                fputs(ANSI_NORMAL "\n", output);
        }

        print_border(output, qr->width);

        sym_QRcode_free(qr);
        return 0;
}
