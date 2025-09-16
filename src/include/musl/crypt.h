/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <crypt.h>

static inline const char* crypt_preferred_method(void) {
        return "$6$";
}

char* crypt_ra(const char *phrase, const char *setting, void **data, int *size);
char* crypt_gensalt_ra(const char *prefix, unsigned long count, const char *rbytes, int nrbytes);
