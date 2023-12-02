/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <dlfcn.h>

#include "macro.h"

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(void*, dlclose, NULL);

int dlsym_many_or_warn_sentinel(void *dl, int log_level, ...) _sentinel_;
int dlopen_many_sym_or_warn_sentinel(void **dlp, const char *filename, int log_level, ...) _sentinel_;

#define dlsym_many_or_warn(dl, log_level, ...) \
        dlsym_many_or_warn_sentinel(dl, log_level, __VA_ARGS__, NULL)
#define dlopen_many_sym_or_warn(dlp, filename, log_level, ...) \
        dlopen_many_sym_or_warn_sentinel(dlp, filename, log_level, __VA_ARGS__, NULL)

#define DLSYM_PROTOTYPE(symbol)                 \
        extern typeof(symbol)* sym_##symbol
#define DLSYM_FUNCTION(symbol)                  \
        typeof(symbol)* sym_##symbol = NULL

/* Macro useful for putting together variable/symbol name pairs when calling dlsym_many_or_warn(). Assumes
 * that each library symbol to resolve will be placed in a variable with the "sym_" prefix, i.e. a symbol
 * "foobar" is loaded into a variable "sym_foobar". */
#define DLSYM_ARG(arg) \
        ({ assert_cc(__builtin_types_compatible_p(typeof(sym_##arg), typeof(&arg))); &sym_##arg; }), STRINGIFY(arg)

/* libbpf is a bit confused about type-safety and API compatibility. Provide a macro that can tape over that mess. Sad. */
#define DLSYM_ARG_FORCE(arg) \
        &sym_##arg, STRINGIFY(arg)

static inline void *safe_dlclose(void *p) {
        if (!p)
                return NULL;

        assert_se(dlclose(p) == 0);
        return NULL;
}
