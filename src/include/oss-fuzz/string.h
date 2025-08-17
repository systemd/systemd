/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <string.h>

#if !HAVE_STRERRORNAME_NP
/* test-errno-list does not pass with this, but oss-fuzz does not run unit tests, hence OK. */
static inline const char* strerrorname_np(int errnum) {
        return NULL;
}
#endif
