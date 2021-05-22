/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Copyright 2014 Emil Renner Berthing <systemd@esmil.dk> */

#include <limits.h>
#include <../musl/printf.h> /* This file is also compiled when built with glibc. */
#include <stdint.h>
#include <string.h>

static const char* consume_nonarg(const char *fmt) {
        do {
                if (*fmt == '\0')
                        return fmt;
        } while (*fmt++ != '%');
        return fmt;
}

static const char* consume_num(const char *fmt) {
        for (;*fmt >= '0' && *fmt <= '9'; fmt++)
                /* do nothing */;
        return fmt;
}

static const char* consume_argn(const char *fmt, size_t *arg) {
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

static const char* consume_flags(const char *fmt) {
        for (;;)
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
                default:
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
        STOP,
};

enum type {
        NONE,
        PTR,
        STR,
        WSTR,
        INT,
        LONG,
        LLONG,
        SHORT,
        IMAX,
        SIZET,
        CHAR,
        WCHAR,
        PDIFF,
        DBL,
        LDBL,
        NPTR,
        MAXTYPE,
};

static const short pa_types[MAXTYPE] = {
        [NONE]   = PA_INT,
        [PTR]    = PA_POINTER,
        [STR]    = PA_STRING,
        [WSTR]   = PA_WSTRING,
        [INT]    = PA_INT,
        [SHORT]  = PA_INT | PA_FLAG_SHORT,
        [LONG]   = PA_INT | PA_FLAG_LONG,
        [CHAR]   = PA_CHAR,
        [WCHAR]  = PA_WCHAR,
        [DBL]    = PA_DOUBLE,
        [LDBL]   = PA_DOUBLE | PA_FLAG_LONG_DOUBLE,
        [NPTR]   = PA_FLAG_PTR,
};

static int state_to_pa_type(unsigned state) {
        switch (state) {
        case LLONG:
#if LONG_MAX != LLONG_MAX
                return PA_INT | PA_FLAG_LONG_LONG;
#else
                return PA_INT | PA_FLAG_LONG;
#endif

        case IMAX:
#if LONG_MAX != LLONG_MAX
                if (sizeof(intmax_t) > sizeof(long))
                        return PA_INT | PA_FLAG_LONG_LONG;
#endif
                if (sizeof(intmax_t) > sizeof(int))
                        return PA_INT | PA_FLAG_LONG;
                return PA_INT;

        case SIZET:
#if LONG_MAX != LLONG_MAX
                if (sizeof(size_t) > sizeof(long))
                        return PA_INT | PA_FLAG_LONG_LONG;
#endif
                if (sizeof(size_t) > sizeof(int))
                        return PA_INT | PA_FLAG_LONG;
                return PA_INT;
        default:
                return pa_types[state];
        }
}

#define S(x) [(x)-'A']
#define E(x) (STOP + (x))

static const unsigned char states[]['z'-'A'+1] = {
        { /* 0: bare types */
                S('d') = E(INT),    S('i') = E(INT),
                S('o') = E(INT),    S('u') = E(INT),    S('x') = E(INT),    S('X') = E(INT),
                S('e') = E(DBL),    S('f') = E(DBL),    S('g') = E(DBL),    S('a') = E(DBL),
                S('E') = E(DBL),    S('F') = E(DBL),    S('G') = E(DBL),    S('A') = E(DBL),
                S('c') = E(CHAR),   S('C') = E(WCHAR),
                S('s') = E(STR),    S('S') = E(WSTR),   S('p') = E(PTR),
                S('n') = E(NPTR),
                S('m') = E(NONE),
                S('l') = LPRE,      S('q') = LLPRE,     S('h') = HPRE,      S('L') = BIGLPRE,
                S('z') = ZTPRE,     S('Z') = ZTPRE,     S('j') = JPRE,      S('t') = ZTPRE,
        },
        { /* 1: l-prefixed */
                S('d') = E(LONG),   S('i') = E(LONG),
                S('o') = E(LONG),   S('u') = E(LONG),   S('x') = E(LONG),   S('X') = E(LONG),
                S('e') = E(DBL),    S('f') = E(DBL),    S('g') = E(DBL),    S('a') = E(DBL),
                S('E') = E(DBL),    S('F') = E(DBL),    S('G') = E(DBL),    S('A') = E(DBL),
                S('c') = E(CHAR),   S('s') = E(STR),
                S('n') = E(NPTR),
                S('l') = LLPRE,
        },
        { /* 2: ll-prefixed */
                S('d') = E(LLONG),  S('i') = E(LLONG),
                S('o') = E(LLONG),  S('u') = E(LLONG),  S('x') = E(LLONG),  S('X') = E(LLONG),
                S('n') = E(NPTR),
        },
        { /* 3: h-prefixed */
                S('d') = E(SHORT),  S('i') = E(SHORT),
                S('o') = E(SHORT),  S('u') = E(SHORT),  S('x') = E(SHORT),  S('X') = E(SHORT),
                S('n') = E(NPTR),
                S('h') = HHPRE,
        },
        { /* 4: hh-prefixed */
                S('d') = E(CHAR),   S('i') = E(CHAR),
                S('o') = E(CHAR),   S('u') = E(CHAR),   S('x') = E(CHAR),   S('X') = E(CHAR),
                S('n') = E(NPTR),
        },
        { /* 5: L-prefixed */
                S('e') = E(LDBL),   S('f') = E(LDBL),   S('g') = E(LDBL),   S('a') = E(LDBL),
                S('E') = E(LDBL),   S('F') = E(LDBL),   S('G') = E(LDBL),   S('A') = E(LDBL),
        },
        { /* 6: z- or t-prefixed (assumed to be same size) */
                S('d') = E(SIZET),  S('i') = E(SIZET),
                S('o') = E(SIZET),  S('u') = E(SIZET),  S('x') = E(SIZET),  S('X') = E(SIZET),
                S('n') = E(NPTR),
        },
        { /* 7: j-prefixed */
                S('d') = E(IMAX),   S('i') = E(IMAX),
                S('o') = E(IMAX),   S('u') = E(IMAX),   S('x') = E(IMAX),   S('X') = E(IMAX),
                S('n') = E(NPTR),
        },
};

size_t missing_parse_printf_format(const char *fmt, size_t n, int *types) {
        size_t i = 0;
        size_t last = 0;

        memset(types, 0, n);

        for (;;) {
                size_t arg;

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
                unsigned state = BARE;
                for (;;) {
                        unsigned char c = *fmt;

                        if (c == '\0')
                                break;

                        fmt++;

                        if (c < 'A' || c > 'z')
                                break;

                        state = states[state]S(c);
                        if (state == 0 || state >= STOP)
                                break;
                }

                if (state <= STOP) /* %m or invalid format */
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
                types[i] = state_to_pa_type(types[i]);

        return last;
}
