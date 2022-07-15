/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once
#include <stdio.h>
#include <errno.h>

#if HAVE_QRENCODE
int dlopen_qrencode(void);

int print_qrcode(FILE *out, const char *header, const char *string);
#else
static inline int print_qrcode(FILE *out, const char *header, const char *string) {
        return -EOPNOTSUPP;
}
#endif
