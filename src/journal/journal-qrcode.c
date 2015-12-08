/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <assert.h>
#include <errno.h>
#include <qrencode.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "journal-qrcode.h"

#define WHITE_ON_BLACK "\033[40;37;1m"
#define NORMAL "\033[0m"

static void print_border(FILE *output, unsigned width) {
        unsigned x, y;

        /* Four rows of border */
        for (y = 0; y < 4; y += 2) {
                fputs(WHITE_ON_BLACK, output);

                for (x = 0; x < 4 + width + 4; x++)
                        fputs("\342\226\210", output);

                fputs(NORMAL "\n", output);
        }
}

int print_qr_code(
                FILE *output,
                const void *seed,
                size_t seed_size,
                uint64_t start,
                uint64_t interval,
                const char *hn,
                sd_id128_t machine) {

        FILE *f;
        char *url = NULL;
        size_t url_size = 0, i;
        QRcode* qr;
        unsigned x, y;

        assert(seed);
        assert(seed_size > 0);

        f = open_memstream(&url, &url_size);
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

        if (ferror(f)) {
                fclose(f);
                free(url);
                return -ENOMEM;
        }

        fclose(f);

        qr = QRcode_encodeString(url, 0, QR_ECLEVEL_L, QR_MODE_8, 1);
        free(url);

        if (!qr)
                return -ENOMEM;

        print_border(output, qr->width);

        for (y = 0; y < (unsigned) qr->width; y += 2) {
                const uint8_t *row1, *row2;

                row1 = qr->data + qr->width * y;
                row2 = row1 + qr->width;

                fputs(WHITE_ON_BLACK, output);
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
                fputs(NORMAL "\n", output);
        }

        print_border(output, qr->width);

        QRcode_free(qr);
        return 0;
}
