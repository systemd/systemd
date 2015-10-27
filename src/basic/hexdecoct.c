/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <ctype.h>
#include <inttypes.h>

#include "alloc-util.h"
#include "hexdecoct.h"
#include "util.h"

char octchar(int x) {
        return '0' + (x & 7);
}

int unoctchar(char c) {

        if (c >= '0' && c <= '7')
                return c - '0';

        return -EINVAL;
}

char decchar(int x) {
        return '0' + (x % 10);
}

int undecchar(char c) {

        if (c >= '0' && c <= '9')
                return c - '0';

        return -EINVAL;
}

char hexchar(int x) {
        static const char table[16] = "0123456789abcdef";

        return table[x & 15];
}

int unhexchar(char c) {

        if (c >= '0' && c <= '9')
                return c - '0';

        if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;

        if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;

        return -EINVAL;
}

char *hexmem(const void *p, size_t l) {
        char *r, *z;
        const uint8_t *x;

        z = r = malloc(l * 2 + 1);
        if (!r)
                return NULL;

        for (x = p; x < (const uint8_t*) p + l; x++) {
                *(z++) = hexchar(*x >> 4);
                *(z++) = hexchar(*x & 15);
        }

        *z = 0;
        return r;
}

int unhexmem(const char *p, size_t l, void **mem, size_t *len) {
        _cleanup_free_ uint8_t *r = NULL;
        uint8_t *z;
        const char *x;

        assert(mem);
        assert(len);
        assert(p);

        z = r = malloc((l + 1) / 2 + 1);
        if (!r)
                return -ENOMEM;

        for (x = p; x < p + l; x += 2) {
                int a, b;

                a = unhexchar(x[0]);
                if (a < 0)
                        return a;
                else if (x+1 < p + l) {
                        b = unhexchar(x[1]);
                        if (b < 0)
                                return b;
                } else
                        b = 0;

                *(z++) = (uint8_t) a << 4 | (uint8_t) b;
        }

        *z = 0;

        *mem = r;
        r = NULL;
        *len = (l + 1) / 2;

        return 0;
}

/* https://tools.ietf.org/html/rfc4648#section-6
 * Notice that base32hex differs from base32 in the alphabet it uses.
 * The distinction is that the base32hex representation preserves the
 * order of the underlying data when compared as bytestrings, this is
 * useful when representing NSEC3 hashes, as one can then verify the
 * order of hashes directly from their representation. */
char base32hexchar(int x) {
        static const char table[32] = "0123456789"
                                      "ABCDEFGHIJKLMNOPQRSTUV";

        return table[x & 31];
}

int unbase32hexchar(char c) {
        unsigned offset;

        if (c >= '0' && c <= '9')
                return c - '0';

        offset = '9' - '0' + 1;

        if (c >= 'A' && c <= 'V')
                return c - 'A' + offset;

        return -EINVAL;
}

char *base32hexmem(const void *p, size_t l, bool padding) {
        char *r, *z;
        const uint8_t *x;
        size_t len;

        if (padding)
                /* five input bytes makes eight output bytes, padding is added so we must round up */
                len = 8 * (l + 4) / 5;
        else {
                /* same, but round down as there is no padding */
                len = 8 * l / 5;

                switch (l % 5) {
                case 4:
                        len += 7;
                        break;
                case 3:
                        len += 5;
                        break;
                case 2:
                        len += 4;
                        break;
                case 1:
                        len += 2;
                        break;
                }
        }

        z = r = malloc(len + 1);
        if (!r)
                return NULL;

        for (x = p; x < (const uint8_t*) p + (l / 5) * 5; x += 5) {
                /* x[0] == XXXXXXXX; x[1] == YYYYYYYY; x[2] == ZZZZZZZZ
                   x[3] == QQQQQQQQ; x[4] == WWWWWWWW */
                *(z++) = base32hexchar(x[0] >> 3);                    /* 000XXXXX */
                *(z++) = base32hexchar((x[0] & 7) << 2 | x[1] >> 6);  /* 000XXXYY */
                *(z++) = base32hexchar((x[1] & 63) >> 1);             /* 000YYYYY */
                *(z++) = base32hexchar((x[1] & 1) << 4 | x[2] >> 4);  /* 000YZZZZ */
                *(z++) = base32hexchar((x[2] & 15) << 1 | x[3] >> 7); /* 000ZZZZQ */
                *(z++) = base32hexchar((x[3] & 127) >> 2);            /* 000QQQQQ */
                *(z++) = base32hexchar((x[3] & 3) << 3 | x[4] >> 5);  /* 000QQWWW */
                *(z++) = base32hexchar((x[4] & 31));                  /* 000WWWWW */
        }

        switch (l % 5) {
        case 4:
                *(z++) = base32hexchar(x[0] >> 3);                    /* 000XXXXX */
                *(z++) = base32hexchar((x[0] & 7) << 2 | x[1] >> 6);  /* 000XXXYY */
                *(z++) = base32hexchar((x[1] & 63) >> 1);             /* 000YYYYY */
                *(z++) = base32hexchar((x[1] & 1) << 4 | x[2] >> 4);   /* 000YZZZZ */
                *(z++) = base32hexchar((x[2] & 15) << 1 | x[3] >> 7); /* 000ZZZZQ */
                *(z++) = base32hexchar((x[3] & 127) >> 2);            /* 000QQQQQ */
                *(z++) = base32hexchar((x[3] & 3) << 3);              /* 000QQ000 */
                if (padding)
                        *(z++) = '=';

                break;

        case 3:
                *(z++) = base32hexchar(x[0] >> 3);                   /* 000XXXXX */
                *(z++) = base32hexchar((x[0] & 7) << 2 | x[1] >> 6); /* 000XXXYY */
                *(z++) = base32hexchar((x[1] & 63) >> 1);            /* 000YYYYY */
                *(z++) = base32hexchar((x[1] & 1) << 4 | x[2] >> 4); /* 000YZZZZ */
                *(z++) = base32hexchar((x[2] & 15) << 1);            /* 000ZZZZ0 */
                if (padding) {
                        *(z++) = '=';
                        *(z++) = '=';
                        *(z++) = '=';
                }

                break;

        case 2:
                *(z++) = base32hexchar(x[0] >> 3);                   /* 000XXXXX */
                *(z++) = base32hexchar((x[0] & 7) << 2 | x[1] >> 6); /* 000XXXYY */
                *(z++) = base32hexchar((x[1] & 63) >> 1);            /* 000YYYYY */
                *(z++) = base32hexchar((x[1] & 1) << 4);             /* 000Y0000 */
                if (padding) {
                        *(z++) = '=';
                        *(z++) = '=';
                        *(z++) = '=';
                        *(z++) = '=';
                }

                break;

        case 1:
                *(z++) = base32hexchar(x[0] >> 3);       /* 000XXXXX */
                *(z++) = base32hexchar((x[0] & 7) << 2); /* 000XXX00 */
                if (padding) {
                        *(z++) = '=';
                        *(z++) = '=';
                        *(z++) = '=';
                        *(z++) = '=';
                        *(z++) = '=';
                        *(z++) = '=';
                }

                break;
        }

        *z = 0;
        return r;
}

int unbase32hexmem(const char *p, size_t l, bool padding, void **mem, size_t *_len) {
        _cleanup_free_ uint8_t *r = NULL;
        int a, b, c, d, e, f, g, h;
        uint8_t *z;
        const char *x;
        size_t len;
        unsigned pad = 0;

        assert(p);

        /* padding ensures any base32hex input has input divisible by 8 */
        if (padding && l % 8 != 0)
                return -EINVAL;

        if (padding) {
                /* strip the padding */
                while (l > 0 && p[l - 1] == '=' && pad < 7) {
                        pad ++;
                        l --;
                }
        }

        /* a group of eight input bytes needs five output bytes, in case of
           padding we need to add some extra bytes */
        len = (l / 8) * 5;

        switch (l % 8) {
        case 7:
                len += 4;
                break;
        case 5:
                len += 3;
                break;
        case 4:
                len += 2;
                break;
        case 2:
                len += 1;
                break;
        case 0:
                break;
        default:
                return -EINVAL;
        }

        z = r = malloc(len + 1);
        if (!r)
                return -ENOMEM;

        for (x = p; x < p + (l / 8) * 8; x += 8) {
                /* a == 000XXXXX; b == 000YYYYY; c == 000ZZZZZ; d == 000WWWWW
                   e == 000SSSSS; f == 000QQQQQ; g == 000VVVVV; h == 000RRRRR */
                a = unbase32hexchar(x[0]);
                if (a < 0)
                        return -EINVAL;

                b = unbase32hexchar(x[1]);
                if (b < 0)
                        return -EINVAL;

                c = unbase32hexchar(x[2]);
                if (c < 0)
                        return -EINVAL;

                d = unbase32hexchar(x[3]);
                if (d < 0)
                        return -EINVAL;

                e = unbase32hexchar(x[4]);
                if (e < 0)
                        return -EINVAL;

                f = unbase32hexchar(x[5]);
                if (f < 0)
                        return -EINVAL;

                g = unbase32hexchar(x[6]);
                if (g < 0)
                        return -EINVAL;

                h = unbase32hexchar(x[7]);
                if (h < 0)
                        return -EINVAL;

                *(z++) = (uint8_t) a << 3 | (uint8_t) b >> 2;                    /* XXXXXYYY */
                *(z++) = (uint8_t) b << 6 | (uint8_t) c << 1 | (uint8_t) d >> 4; /* YYZZZZZW */
                *(z++) = (uint8_t) d << 4 | (uint8_t) e >> 1;                    /* WWWWSSSS */
                *(z++) = (uint8_t) e << 7 | (uint8_t) f << 2 | (uint8_t) g >> 3; /* SQQQQQVV */
                *(z++) = (uint8_t) g << 5 | (uint8_t) h;                         /* VVVRRRRR */
        }

        switch (l % 8) {
        case 7:
                a = unbase32hexchar(x[0]);
                if (a < 0)
                        return -EINVAL;

                b = unbase32hexchar(x[1]);
                if (b < 0)
                        return -EINVAL;

                c = unbase32hexchar(x[2]);
                if (c < 0)
                        return -EINVAL;

                d = unbase32hexchar(x[3]);
                if (d < 0)
                        return -EINVAL;

                e = unbase32hexchar(x[4]);
                if (e < 0)
                        return -EINVAL;

                f = unbase32hexchar(x[5]);
                if (f < 0)
                        return -EINVAL;

                g = unbase32hexchar(x[6]);
                if (g < 0)
                        return -EINVAL;

                /* g == 000VV000 */
                if (g & 7)
                        return -EINVAL;

                *(z++) = (uint8_t) a << 3 | (uint8_t) b >> 2;                    /* XXXXXYYY */
                *(z++) = (uint8_t) b << 6 | (uint8_t) c << 1 | (uint8_t) d >> 4; /* YYZZZZZW */
                *(z++) = (uint8_t) d << 4 | (uint8_t) e >> 1;                    /* WWWWSSSS */
                *(z++) = (uint8_t) e << 7 | (uint8_t) f << 2 | (uint8_t) g >> 3; /* SQQQQQVV */

                break;
        case 5:
                a = unbase32hexchar(x[0]);
                if (a < 0)
                        return -EINVAL;

                b = unbase32hexchar(x[1]);
                if (b < 0)
                        return -EINVAL;

                c = unbase32hexchar(x[2]);
                if (c < 0)
                        return -EINVAL;

                d = unbase32hexchar(x[3]);
                if (d < 0)
                        return -EINVAL;

                e = unbase32hexchar(x[4]);
                if (e < 0)
                        return -EINVAL;

                /* e == 000SSSS0 */
                if (e & 1)
                        return -EINVAL;

                *(z++) = (uint8_t) a << 3 | (uint8_t) b >> 2;                    /* XXXXXYYY */
                *(z++) = (uint8_t) b << 6 | (uint8_t) c << 1 | (uint8_t) d >> 4; /* YYZZZZZW */
                *(z++) = (uint8_t) d << 4 | (uint8_t) e >> 1;                    /* WWWWSSSS */

                break;
        case 4:
                a = unbase32hexchar(x[0]);
                if (a < 0)
                        return -EINVAL;

                b = unbase32hexchar(x[1]);
                if (b < 0)
                        return -EINVAL;

                c = unbase32hexchar(x[2]);
                if (c < 0)
                        return -EINVAL;

                d = unbase32hexchar(x[3]);
                if (d < 0)
                        return -EINVAL;

                /* d == 000W0000 */
                if (d & 15)
                        return -EINVAL;

                *(z++) = (uint8_t) a << 3 | (uint8_t) b >> 2;                    /* XXXXXYYY */
                *(z++) = (uint8_t) b << 6 | (uint8_t) c << 1 | (uint8_t) d >> 4; /* YYZZZZZW */

                break;
        case 2:
                a = unbase32hexchar(x[0]);
                if (a < 0)
                        return -EINVAL;

                b = unbase32hexchar(x[1]);
                if (b < 0)
                        return -EINVAL;

                /* b == 000YYY00 */
                if (b & 3)
                        return -EINVAL;

                *(z++) = (uint8_t) a << 3 | (uint8_t) b >> 2; /* XXXXXYYY */

                break;
        case 0:
                break;
        default:
                return -EINVAL;
        }

        *z = 0;

        *mem = r;
        r = NULL;
        *_len = len;

        return 0;
}

/* https://tools.ietf.org/html/rfc4648#section-4 */
char base64char(int x) {
        static const char table[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                      "abcdefghijklmnopqrstuvwxyz"
                                      "0123456789+/";
        return table[x & 63];
}

int unbase64char(char c) {
        unsigned offset;

        if (c >= 'A' && c <= 'Z')
                return c - 'A';

        offset = 'Z' - 'A' + 1;

        if (c >= 'a' && c <= 'z')
                return c - 'a' + offset;

        offset += 'z' - 'a' + 1;

        if (c >= '0' && c <= '9')
                return c - '0' + offset;

        offset += '9' - '0' + 1;

        if (c == '+')
                return offset;

        offset ++;

        if (c == '/')
                return offset;

        return -EINVAL;
}

char *base64mem(const void *p, size_t l) {
        char *r, *z;
        const uint8_t *x;

        /* three input bytes makes four output bytes, padding is added so we must round up */
        z = r = malloc(4 * (l + 2) / 3 + 1);
        if (!r)
                return NULL;

        for (x = p; x < (const uint8_t*) p + (l / 3) * 3; x += 3) {
                /* x[0] == XXXXXXXX; x[1] == YYYYYYYY; x[2] == ZZZZZZZZ */
                *(z++) = base64char(x[0] >> 2);                    /* 00XXXXXX */
                *(z++) = base64char((x[0] & 3) << 4 | x[1] >> 4);  /* 00XXYYYY */
                *(z++) = base64char((x[1] & 15) << 2 | x[2] >> 6); /* 00YYYYZZ */
                *(z++) = base64char(x[2] & 63);                    /* 00ZZZZZZ */
        }

        switch (l % 3) {
        case 2:
                *(z++) = base64char(x[0] >> 2);                   /* 00XXXXXX */
                *(z++) = base64char((x[0] & 3) << 4 | x[1] >> 4); /* 00XXYYYY */
                *(z++) = base64char((x[1] & 15) << 2);            /* 00YYYY00 */
                *(z++) = '=';

                break;
        case 1:
                *(z++) = base64char(x[0] >> 2);        /* 00XXXXXX */
                *(z++) = base64char((x[0] & 3) << 4);  /* 00XX0000 */
                *(z++) = '=';
                *(z++) = '=';

                break;
        }

        *z = 0;
        return r;
}

int unbase64mem(const char *p, size_t l, void **mem, size_t *_len) {
        _cleanup_free_ uint8_t *r = NULL;
        int a, b, c, d;
        uint8_t *z;
        const char *x;
        size_t len;

        assert(p);

        /* padding ensures any base63 input has input divisible by 4 */
        if (l % 4 != 0)
                return -EINVAL;

        /* strip the padding */
        if (l > 0 && p[l - 1] == '=')
                l --;
        if (l > 0 && p[l - 1] == '=')
                l --;

        /* a group of four input bytes needs three output bytes, in case of
           padding we need to add two or three extra bytes */
        len = (l / 4) * 3 + (l % 4 ? (l % 4) - 1 : 0);

        z = r = malloc(len + 1);
        if (!r)
                return -ENOMEM;

        for (x = p; x < p + (l / 4) * 4; x += 4) {
                /* a == 00XXXXXX; b == 00YYYYYY; c == 00ZZZZZZ; d == 00WWWWWW */
                a = unbase64char(x[0]);
                if (a < 0)
                        return -EINVAL;

                b = unbase64char(x[1]);
                if (b < 0)
                        return -EINVAL;

                c = unbase64char(x[2]);
                if (c < 0)
                        return -EINVAL;

                d = unbase64char(x[3]);
                if (d < 0)
                        return -EINVAL;

                *(z++) = (uint8_t) a << 2 | (uint8_t) b >> 4; /* XXXXXXYY */
                *(z++) = (uint8_t) b << 4 | (uint8_t) c >> 2; /* YYYYZZZZ */
                *(z++) = (uint8_t) c << 6 | (uint8_t) d;      /* ZZWWWWWW */
        }

        switch (l % 4) {
        case 3:
                a = unbase64char(x[0]);
                if (a < 0)
                        return -EINVAL;

                b = unbase64char(x[1]);
                if (b < 0)
                        return -EINVAL;

                c = unbase64char(x[2]);
                if (c < 0)
                        return -EINVAL;

                /* c == 00ZZZZ00 */
                if (c & 3)
                        return -EINVAL;

                *(z++) = (uint8_t) a << 2 | (uint8_t) b >> 4; /* XXXXXXYY */
                *(z++) = (uint8_t) b << 4 | (uint8_t) c >> 2; /* YYYYZZZZ */

                break;
        case 2:
                a = unbase64char(x[0]);
                if (a < 0)
                        return -EINVAL;

                b = unbase64char(x[1]);
                if (b < 0)
                        return -EINVAL;

                /* b == 00YY0000 */
                if (b & 15)
                        return -EINVAL;

                *(z++) = (uint8_t) a << 2 | (uint8_t) (b >> 4); /* XXXXXXYY */

                break;
        case 0:

                break;
        default:
                return -EINVAL;
        }

        *z = 0;

        *mem = r;
        r = NULL;
        *_len = len;

        return 0;
}

void hexdump(FILE *f, const void *p, size_t s) {
        const uint8_t *b = p;
        unsigned n = 0;

        assert(s == 0 || b);

        while (s > 0) {
                size_t i;

                fprintf(f, "%04x  ", n);

                for (i = 0; i < 16; i++) {

                        if (i >= s)
                                fputs("   ", f);
                        else
                                fprintf(f, "%02x ", b[i]);

                        if (i == 7)
                                fputc(' ', f);
                }

                fputc(' ', f);

                for (i = 0; i < 16; i++) {

                        if (i >= s)
                                fputc(' ', f);
                        else
                                fputc(isprint(b[i]) ? (char) b[i] : '.', f);
                }

                fputc('\n', f);

                if (s < 16)
                        break;

                n += 16;
                b += 16;
                s -= 16;
        }
}
