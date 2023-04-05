/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* Macro useful for statically assigning variables from symbols loading them via dlsym_many_or_warn(). Assumes
 * that each library symbol to resolve will be placed in a variable with the "sym_" prefix, i.e. a symbol
 * "foobar" is loaded into a variable "sym_foobar". */
#define STATIC_SYM_ARG(arg) \
        ({ assert_cc(__builtin_types_compatible_p(typeof(sym_##arg), typeof(&arg))); sym_##arg; }) = arg
