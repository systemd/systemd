#include "qrcode-util.h"
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

void write_qrcode(FILE *output, QRcode *qr) {
        unsigned x, y;

        assert(qr);

        if (!output)
                output = stdout;

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
        fflush(output);
}
