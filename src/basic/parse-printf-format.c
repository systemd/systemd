/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Emil Renner Berthing <systemd@esmil.dk>

  With parts from the musl C library
  Copyright 2005-2014 Rich Felker, et al.

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

#include <stddef.h>
#include <string.h>

#include "parse-printf-format.h"

static const char *consume_nonarg(const char *fmt)
{
        do {
                if (*fmt == '\0')
                        return fmt;
        } while (*fmt++ != '%');
        return fmt;
}

static const char *consume_num(const char *fmt)
{
        for (;*fmt >= '0' && *fmt <= '9'; fmt++)
                /* do nothing */;
        return fmt;
}

static const char *consume_argn(const char *fmt, size_t *arg)
{
        const char *p = fmt;
        size_t val = 0;

        if (*p < '1' || *p > '9')
                return fmt;
        do {
                val = 10*val + (*p++ - '0');
        } while (*p >= '0' && *p <= '9');

        if (*p != '$')
                return fmt;
        *arg = val;
        return p+1;
}

static const char *consume_flags(const char *fmt)
{
        while (1) {
                switch (*fmt) {
                case '#':
                case '0':
                case '-':
                case ' ':
                case '+':
                case '\'':
                case 'I':
                        fmt++;
                        continue;
                }
                return fmt;
        }
}

enum state {
        BARE,
        LPRE,
        LLPRE,
        HPRE,
        HHPRE,
        BIGLPRE,
        ZTPRE,
        JPRE,
        STOP
};

enum type {
        NONE,
        PTR,
        INT,
        UINT,
        ULLONG,
        LONG,
        ULONG,
        SHORT,
        USHORT,
        CHAR,
        UCHAR,
        LLONG,
        SIZET,
        IMAX,
        UMAX,
        PDIFF,
        UIPTR,
        DBL,
        LDBL,
        MAXTYPE
};

static const short pa_types[MAXTYPE] = {
        [NONE]   = PA_INT,
        [PTR]    = PA_POINTER,
        [INT]    = PA_INT,
        [UINT]   = PA_INT,
        [ULLONG] = PA_INT | PA_FLAG_LONG_LONG,
        [LONG]   = PA_INT | PA_FLAG_LONG,
        [ULONG]  = PA_INT | PA_FLAG_LONG,
        [SHORT]  = PA_INT | PA_FLAG_SHORT,
        [USHORT] = PA_INT | PA_FLAG_SHORT,
        [CHAR]   = PA_CHAR,
        [UCHAR]  = PA_CHAR,
        [LLONG]  = PA_INT | PA_FLAG_LONG_LONG,
        [SIZET]  = PA_INT | PA_FLAG_LONG,
        [IMAX]   = PA_INT | PA_FLAG_LONG_LONG,
        [UMAX]   = PA_INT | PA_FLAG_LONG_LONG,
        [PDIFF]  = PA_INT | PA_FLAG_LONG_LONG,
        [UIPTR]  = PA_INT | PA_FLAG_LONG,
        [DBL]    = PA_DOUBLE,
        [LDBL]   = PA_DOUBLE | PA_FLAG_LONG_DOUBLE
};

#define S(x) [(x)-'A']
#define E(x) (STOP + (x))

static const unsigned char states[]['z'-'A'+1] = {
        { /* 0: bare types */
                S('d') = E(INT), S('i') = E(INT),
                S('o') = E(UINT),S('u') = E(UINT),S('x') = E(UINT), S('X') = E(UINT),
                S('e') = E(DBL), S('f') = E(DBL), S('g') = E(DBL),  S('a') = E(DBL),
                S('E') = E(DBL), S('F') = E(DBL), S('G') = E(DBL),  S('A') = E(DBL),
                S('c') = E(CHAR),S('C') = E(INT),
                S('s') = E(PTR), S('S') = E(PTR), S('p') = E(UIPTR),S('n') = E(PTR),
                S('m') = E(NONE),
                S('l') = LPRE,   S('h') = HPRE, S('L') = BIGLPRE,
                S('z') = ZTPRE,  S('j') = JPRE, S('t') = ZTPRE
        }, { /* 1: l-prefixed */
                S('d') = E(LONG), S('i') = E(LONG),
                S('o') = E(ULONG),S('u') = E(ULONG),S('x') = E(ULONG),S('X') = E(ULONG),
                S('e') = E(DBL),  S('f') = E(DBL),  S('g') = E(DBL),  S('a') = E(DBL),
                S('E') = E(DBL),  S('F') = E(DBL),  S('G') = E(DBL),  S('A') = E(DBL),
                S('c') = E(INT),  S('s') = E(PTR),  S('n') = E(PTR),
                S('l') = LLPRE
        }, { /* 2: ll-prefixed */
                S('d') = E(LLONG), S('i') = E(LLONG),
                S('o') = E(ULLONG),S('u') = E(ULLONG),
                S('x') = E(ULLONG),S('X') = E(ULLONG),
                S('n') = E(PTR)
        }, { /* 3: h-prefixed */
                S('d') = E(SHORT), S('i') = E(SHORT),
                S('o') = E(USHORT),S('u') = E(USHORT),
                S('x') = E(USHORT),S('X') = E(USHORT),
                S('n') = E(PTR),
                S('h') = HHPRE
        }, { /* 4: hh-prefixed */
                S('d') = E(CHAR), S('i') = E(CHAR),
                S('o') = E(UCHAR),S('u') = E(UCHAR),
                S('x') = E(UCHAR),S('X') = E(UCHAR),
                S('n') = E(PTR)
        }, { /* 5: L-prefixed */
                S('e') = E(LDBL),S('f') = E(LDBL),S('g') = E(LDBL), S('a') = E(LDBL),
                S('E') = E(LDBL),S('F') = E(LDBL),S('G') = E(LDBL), S('A') = E(LDBL),
                S('n') = E(PTR)
        }, { /* 6: z- or t-prefixed (assumed to be same size) */
                S('d') = E(PDIFF),S('i') = E(PDIFF),
                S('o') = E(SIZET),S('u') = E(SIZET),
                S('x') = E(SIZET),S('X') = E(SIZET),
                S('n') = E(PTR)
        }, { /* 7: j-prefixed */
                S('d') = E(IMAX), S('i') = E(IMAX),
                S('o') = E(UMAX), S('u') = E(UMAX),
                S('x') = E(UMAX), S('X') = E(UMAX),
                S('n') = E(PTR)
        }
};

size_t parse_printf_format(const char *fmt, size_t n, int *types)
{
        size_t i = 0;
        size_t last = 0;

        memset(types, 0, n);

        while (1) {
                size_t arg;
                unsigned int state;

                fmt = consume_nonarg(fmt);
                if (*fmt == '\0')
                        break;
                if (*fmt == '%') {
                        fmt++;
                        continue;
                }
                arg = 0;
                fmt = consume_argn(fmt, &arg);
                /* flags */
                fmt = consume_flags(fmt);
                /* width */
                if (*fmt == '*') {
                        size_t warg = 0;
                        fmt = consume_argn(fmt+1, &warg);
                        if (warg == 0)
                                warg = ++i;
                        if (warg > last)
                                last = warg;
                        if (warg <= n && types[warg-1] == NONE)
                                types[warg-1] = INT;
                } else
                        fmt = consume_num(fmt);
                /* precision */
                if (*fmt == '.') {
                        fmt++;
                        if (*fmt == '*') {
                                size_t parg = 0;
                                fmt = consume_argn(fmt+1, &parg);
                                if (parg == 0)
                                        parg = ++i;
                                if (parg > last)
                                        last = parg;
                                if (parg <= n && types[parg-1] == NONE)
                                        types[parg-1] = INT;
                        } else {
                                if (*fmt == '-')
                                        fmt++;
                                fmt = consume_num(fmt);
                        }
                }
                /* length modifier and conversion specifier */
                state = BARE;
                do {
                        unsigned char c = *fmt++;

                        if (c < 'A' || c > 'z')
                                continue;
                        state = states[state]S(c);
                        if (state == 0)
                                continue;
                } while (state < STOP);

                if (state == E(NONE))
                        continue;

                if (arg == 0)
                        arg = ++i;
                if (arg > last)
                        last = arg;
                if (arg <= n)
                        types[arg-1] = state - STOP;
        }

        if (last > n)
                last = n;
        for (i = 0; i < last; i++)
                types[i] = pa_types[types[i]];

        return last;
}
