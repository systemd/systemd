/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <dlfcn.h>

#include "macro.h"

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(void*, dlclose, NULL);

int dlsym_many_and_warn(void *dl, int level, ...);

/* Macro useful for putting together variable/symbol name pairs when calling dlsym_many_and_warn(). Assumes
 * that each library symbol to resolve will be placed in a variable with the "sym_" prefix, i.e. a symbol
 * "foobar" is loaded into a variable "sym_foobar". */
#define DLSYM_ARG(arg) \
        &sym_##arg, STRINGIFY(arg)
