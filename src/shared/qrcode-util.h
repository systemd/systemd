/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>

#if HAVE_QRENCODE
int dlopen_qrencode(void);

int print_qrcode_full(
                FILE *out,
                const char *header,
                const char *string,
                unsigned row,
                unsigned column,
                unsigned tty_width,
                unsigned tty_height,
                bool check_tty);
#else
static inline int print_qrcode_full(
                FILE *out,
                const char *header,
                const char *string,
                unsigned row,
                unsigned column,
                unsigned tty_width,
                unsigned tty_height,
                bool check_tty) {
        return -EOPNOTSUPP;
}
#endif

static inline int print_qrcode(FILE *out, const char *header, const char *string) {
        return print_qrcode_full(out, header, string, UINT_MAX, UINT_MAX, UINT_MAX, UINT_MAX, true);
}
