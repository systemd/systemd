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

/* Macro useful for putting together variable/symbol name pairs when calling dlsym_many_or_warn(). Assumes
 * that each library symbol to resolve will be placed in a variable with the "sym_" prefix, i.e. a symbol
 * "foobar" is loaded into a variable "sym_foobar". */
#define DLSYM_ARG(arg) \
        &sym_##arg, STRINGIFY(arg)
