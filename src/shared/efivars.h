/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "../basic/efivars.h"   /* IWYU pragma: export */

/* These functions extend the basic efivars.h API with the variable setters, which live in the shared tier
 * because persisting writes on firmware with a file-backed variable store requires ESP discovery via
 * find-esp.c. Targets that link libshared automatically pick up this version via -Isrc/shared; targets
 * that only have src/basic on their include path fall through to the basic header. */

#if ENABLE_EFI

int efi_set_variable(const char *variable, const void *value, size_t size) _nonnull_if_nonzero_(2, 3);
int efi_set_variable_string(const char *variable, const char *value);

#else

static inline int efi_set_variable(const char *variable, const void *value, size_t size) {
        return -EOPNOTSUPP;
}

static inline int efi_set_variable_string(const char *variable, const char *p) {
        return -EOPNOTSUPP;
}

#endif
