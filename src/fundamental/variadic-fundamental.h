/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro-fundamental.h"

/* Wraps variadic args in a single group. This can be passed to macros that will then expand the group into
 * all its variadic args. */
#define VA_GROUP(...) __VA_ARGS__

/* Expects 'x' to be a variadic arg list enclosed in (). Evaluates to the variadic arg list without the
 * enclosing (). Enclosing variadic args in () is useful to pass the group through multiple layers of macros
 * without needing echo layer to re-enclose it with VA_GROUP(), but it requires the final layer to extract
 * the variadic args with this macro. */
#define VA_UNPAREN(x) VA_GROUP x

/* Evaluates to nothing if no variadic args are provided, or if a single variadic arg is provided that
 * evaluates to whitespace only (or nothing). Otherwise, evaluates to 'x'. */
#define VA_IF(x, ...) __VA_OPT__(x)

/* Same as VA_IF() but negates the condition. */
#define VA_NOT(x, ...) CONCATENATE(_VA_NOT, __VA_OPT__(0))(VA_GROUP(x))
#define _VA_NOT(x) x
#define _VA_NOT0(x)

/* Combination of VA_IF() and VA_NOT(); evaluates to 'x' if there are non-empty variadic arg(s), otherwise
 * evaluates to 'y'. */
#define VA_IF_ELSE(x, y, ...) CONCATENATE(_VA_IF_ELSE, __VA_OPT__(1))(VA_GROUP(x), VA_GROUP(y))
#define _VA_IF_ELSE1(x, y) x
#define _VA_IF_ELSE(x, y) y

/* Same as VA_IF(), but evaluates to a comma. */
#define VA_COMMA(...) __VA_OPT__(,)

/* Same as VA_IF(), but evlauates to true or false. Specifically, at the preprocessor stage, this evaluates
 * to (1 - 1) for false or (1) for true. */
#define VA_EMPTY(...) (1 __VA_OPT__(- 1))

/* Evaluates to the first variadic arg. If there are no variadic args, evaluates to nothing. */
#define VA_FIRST(...) __VA_OPT__(_VA_FIRST(__VA_ARGS__))
#define _VA_FIRST(x, ...) x

/* Evaluates to the rest of the variadic args, after the first. If there is only 1 (or 0) variadic args,
 * evaluates to nothing. */
#define VA_REST(...) __VA_OPT__(_VA_REST(__VA_ARGS__))
#define _VA_REST(x, ...) __VA_ARGS__

/* Evaluates to 'macro' called with the expanded variadic args. */
#define VA_MACRO(macro, ...) macro(__VA_ARGS__)

/* This is the max number of variadic args that the macros here can handle. This should match the highest
 * entry in the _VA_0x*() list below. Unless otherwise stated, using more than VA_NARGS_MAX variadic args
 * with any of the (non-underscored) macros below will cause a compiler assertion failure. */
#define VA_NARGS_MAX (0x7f)

#define __VA_TOOM(m,s,c,t,v,...) t(c) /* too many variadic args */
#define __VA_0x7f(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x7f,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_TOOM(m,s,c,t,__VA_ARGS__))
#define __VA_0x7e(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x7e,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x7f(m,s,c,t,__VA_ARGS__))
#define __VA_0x7d(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x7d,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x7e(m,s,c,t,__VA_ARGS__))
#define __VA_0x7c(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x7c,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x7d(m,s,c,t,__VA_ARGS__))
#define __VA_0x7b(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x7b,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x7c(m,s,c,t,__VA_ARGS__))
#define __VA_0x7a(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x7a,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x7b(m,s,c,t,__VA_ARGS__))
#define __VA_0x79(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x79,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x7a(m,s,c,t,__VA_ARGS__))
#define __VA_0x78(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x78,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x79(m,s,c,t,__VA_ARGS__))
#define __VA_0x77(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x77,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x78(m,s,c,t,__VA_ARGS__))
#define __VA_0x76(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x76,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x77(m,s,c,t,__VA_ARGS__))
#define __VA_0x75(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x75,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x76(m,s,c,t,__VA_ARGS__))
#define __VA_0x74(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x74,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x75(m,s,c,t,__VA_ARGS__))
#define __VA_0x73(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x73,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x74(m,s,c,t,__VA_ARGS__))
#define __VA_0x72(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x72,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x73(m,s,c,t,__VA_ARGS__))
#define __VA_0x71(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x71,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x72(m,s,c,t,__VA_ARGS__))
#define __VA_0x70(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x70,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x71(m,s,c,t,__VA_ARGS__))
#define __VA_0x6f(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x6f,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x70(m,s,c,t,__VA_ARGS__))
#define __VA_0x6e(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x6e,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x6f(m,s,c,t,__VA_ARGS__))
#define __VA_0x6d(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x6d,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x6e(m,s,c,t,__VA_ARGS__))
#define __VA_0x6c(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x6c,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x6d(m,s,c,t,__VA_ARGS__))
#define __VA_0x6b(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x6b,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x6c(m,s,c,t,__VA_ARGS__))
#define __VA_0x6a(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x6a,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x6b(m,s,c,t,__VA_ARGS__))
#define __VA_0x69(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x69,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x6a(m,s,c,t,__VA_ARGS__))
#define __VA_0x68(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x68,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x69(m,s,c,t,__VA_ARGS__))
#define __VA_0x67(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x67,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x68(m,s,c,t,__VA_ARGS__))
#define __VA_0x66(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x66,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x67(m,s,c,t,__VA_ARGS__))
#define __VA_0x65(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x65,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x66(m,s,c,t,__VA_ARGS__))
#define __VA_0x64(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x64,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x65(m,s,c,t,__VA_ARGS__))
#define __VA_0x63(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x63,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x64(m,s,c,t,__VA_ARGS__))
#define __VA_0x62(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x62,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x63(m,s,c,t,__VA_ARGS__))
#define __VA_0x61(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x61,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x62(m,s,c,t,__VA_ARGS__))
#define __VA_0x60(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x60,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x61(m,s,c,t,__VA_ARGS__))
#define __VA_0x5f(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x5f,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x60(m,s,c,t,__VA_ARGS__))
#define __VA_0x5e(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x5e,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x5f(m,s,c,t,__VA_ARGS__))
#define __VA_0x5d(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x5d,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x5e(m,s,c,t,__VA_ARGS__))
#define __VA_0x5c(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x5c,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x5d(m,s,c,t,__VA_ARGS__))
#define __VA_0x5b(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x5b,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x5c(m,s,c,t,__VA_ARGS__))
#define __VA_0x5a(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x5a,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x5b(m,s,c,t,__VA_ARGS__))
#define __VA_0x59(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x59,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x5a(m,s,c,t,__VA_ARGS__))
#define __VA_0x58(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x58,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x59(m,s,c,t,__VA_ARGS__))
#define __VA_0x57(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x57,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x58(m,s,c,t,__VA_ARGS__))
#define __VA_0x56(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x56,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x57(m,s,c,t,__VA_ARGS__))
#define __VA_0x55(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x55,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x56(m,s,c,t,__VA_ARGS__))
#define __VA_0x54(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x54,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x55(m,s,c,t,__VA_ARGS__))
#define __VA_0x53(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x53,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x54(m,s,c,t,__VA_ARGS__))
#define __VA_0x52(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x52,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x53(m,s,c,t,__VA_ARGS__))
#define __VA_0x51(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x51,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x52(m,s,c,t,__VA_ARGS__))
#define __VA_0x50(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x50,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x51(m,s,c,t,__VA_ARGS__))
#define __VA_0x4f(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x4f,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x50(m,s,c,t,__VA_ARGS__))
#define __VA_0x4e(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x4e,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x4f(m,s,c,t,__VA_ARGS__))
#define __VA_0x4d(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x4d,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x4e(m,s,c,t,__VA_ARGS__))
#define __VA_0x4c(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x4c,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x4d(m,s,c,t,__VA_ARGS__))
#define __VA_0x4b(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x4b,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x4c(m,s,c,t,__VA_ARGS__))
#define __VA_0x4a(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x4a,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x4b(m,s,c,t,__VA_ARGS__))
#define __VA_0x49(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x49,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x4a(m,s,c,t,__VA_ARGS__))
#define __VA_0x48(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x48,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x49(m,s,c,t,__VA_ARGS__))
#define __VA_0x47(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x47,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x48(m,s,c,t,__VA_ARGS__))
#define __VA_0x46(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x46,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x47(m,s,c,t,__VA_ARGS__))
#define __VA_0x45(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x45,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x46(m,s,c,t,__VA_ARGS__))
#define __VA_0x44(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x44,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x45(m,s,c,t,__VA_ARGS__))
#define __VA_0x43(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x43,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x44(m,s,c,t,__VA_ARGS__))
#define __VA_0x42(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x42,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x43(m,s,c,t,__VA_ARGS__))
#define __VA_0x41(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x41,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x42(m,s,c,t,__VA_ARGS__))
#define __VA_0x40(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x40,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x41(m,s,c,t,__VA_ARGS__))
#define __VA_0x3f(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x3f,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x40(m,s,c,t,__VA_ARGS__))
#define __VA_0x3e(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x3e,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x3f(m,s,c,t,__VA_ARGS__))
#define __VA_0x3d(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x3d,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x3e(m,s,c,t,__VA_ARGS__))
#define __VA_0x3c(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x3c,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x3d(m,s,c,t,__VA_ARGS__))
#define __VA_0x3b(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x3b,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x3c(m,s,c,t,__VA_ARGS__))
#define __VA_0x3a(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x3a,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x3b(m,s,c,t,__VA_ARGS__))
#define __VA_0x39(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x39,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x3a(m,s,c,t,__VA_ARGS__))
#define __VA_0x38(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x38,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x39(m,s,c,t,__VA_ARGS__))
#define __VA_0x37(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x37,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x38(m,s,c,t,__VA_ARGS__))
#define __VA_0x36(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x36,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x37(m,s,c,t,__VA_ARGS__))
#define __VA_0x35(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x35,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x36(m,s,c,t,__VA_ARGS__))
#define __VA_0x34(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x34,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x35(m,s,c,t,__VA_ARGS__))
#define __VA_0x33(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x33,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x34(m,s,c,t,__VA_ARGS__))
#define __VA_0x32(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x32,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x33(m,s,c,t,__VA_ARGS__))
#define __VA_0x31(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x31,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x32(m,s,c,t,__VA_ARGS__))
#define __VA_0x30(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x30,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x31(m,s,c,t,__VA_ARGS__))
#define __VA_0x2f(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x2f,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x30(m,s,c,t,__VA_ARGS__))
#define __VA_0x2e(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x2e,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x2f(m,s,c,t,__VA_ARGS__))
#define __VA_0x2d(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x2d,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x2e(m,s,c,t,__VA_ARGS__))
#define __VA_0x2c(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x2c,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x2d(m,s,c,t,__VA_ARGS__))
#define __VA_0x2b(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x2b,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x2c(m,s,c,t,__VA_ARGS__))
#define __VA_0x2a(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x2a,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x2b(m,s,c,t,__VA_ARGS__))
#define __VA_0x29(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x29,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x2a(m,s,c,t,__VA_ARGS__))
#define __VA_0x28(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x28,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x29(m,s,c,t,__VA_ARGS__))
#define __VA_0x27(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x27,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x28(m,s,c,t,__VA_ARGS__))
#define __VA_0x26(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x26,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x27(m,s,c,t,__VA_ARGS__))
#define __VA_0x25(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x25,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x26(m,s,c,t,__VA_ARGS__))
#define __VA_0x24(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x24,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x25(m,s,c,t,__VA_ARGS__))
#define __VA_0x23(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x23,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x24(m,s,c,t,__VA_ARGS__))
#define __VA_0x22(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x22,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x23(m,s,c,t,__VA_ARGS__))
#define __VA_0x21(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x21,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x22(m,s,c,t,__VA_ARGS__))
#define __VA_0x20(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x20,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x21(m,s,c,t,__VA_ARGS__))
#define __VA_0x1f(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x1f,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x20(m,s,c,t,__VA_ARGS__))
#define __VA_0x1e(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x1e,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x1f(m,s,c,t,__VA_ARGS__))
#define __VA_0x1d(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x1d,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x1e(m,s,c,t,__VA_ARGS__))
#define __VA_0x1c(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x1c,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x1d(m,s,c,t,__VA_ARGS__))
#define __VA_0x1b(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x1b,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x1c(m,s,c,t,__VA_ARGS__))
#define __VA_0x1a(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x1a,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x1b(m,s,c,t,__VA_ARGS__))
#define __VA_0x19(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x19,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x1a(m,s,c,t,__VA_ARGS__))
#define __VA_0x18(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x18,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x19(m,s,c,t,__VA_ARGS__))
#define __VA_0x17(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x17,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x18(m,s,c,t,__VA_ARGS__))
#define __VA_0x16(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x16,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x17(m,s,c,t,__VA_ARGS__))
#define __VA_0x15(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x15,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x16(m,s,c,t,__VA_ARGS__))
#define __VA_0x14(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x14,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x15(m,s,c,t,__VA_ARGS__))
#define __VA_0x13(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x13,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x14(m,s,c,t,__VA_ARGS__))
#define __VA_0x12(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x12,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x13(m,s,c,t,__VA_ARGS__))
#define __VA_0x11(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x11,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x12(m,s,c,t,__VA_ARGS__))
#define __VA_0x10(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x10,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x11(m,s,c,t,__VA_ARGS__))
#define __VA_0x0f(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x0f,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x10(m,s,c,t,__VA_ARGS__))
#define __VA_0x0e(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x0e,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x0f(m,s,c,t,__VA_ARGS__))
#define __VA_0x0d(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x0d,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x0e(m,s,c,t,__VA_ARGS__))
#define __VA_0x0c(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x0c,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x0d(m,s,c,t,__VA_ARGS__))
#define __VA_0x0b(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x0b,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x0c(m,s,c,t,__VA_ARGS__))
#define __VA_0x0a(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x0a,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x0b(m,s,c,t,__VA_ARGS__))
#define __VA_0x09(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x09,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x0a(m,s,c,t,__VA_ARGS__))
#define __VA_0x08(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x08,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x09(m,s,c,t,__VA_ARGS__))
#define __VA_0x07(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x07,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x08(m,s,c,t,__VA_ARGS__))
#define __VA_0x06(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x06,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x07(m,s,c,t,__VA_ARGS__))
#define __VA_0x05(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x05,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x06(m,s,c,t,__VA_ARGS__))
#define __VA_0x04(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x04,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x05(m,s,c,t,__VA_ARGS__))
#define __VA_0x03(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x03,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x04(m,s,c,t,__VA_ARGS__))
#define __VA_0x02(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x02,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x03(m,s,c,t,__VA_ARGS__))
#define __VA_0x01(m,s,c,t,v,...) m(c,__VA_OPT__(1),0x01,v)__VA_OPT__(s(c,v,VA_FIRST(__VA_ARGS__)) __VA_0x02(m,s,c,t,__VA_ARGS__))
#define __VA_0x00(m,s,c,t,z) z(c)

#define VA_NARGS_TOOMANY_ERROR() _Pragma("GCC error \"Too many variadic args.\"")

/* These can be used as VA_WRAP() 'macro' parameter. */
#define VA_WRAP_MACRO_CONTEXT(c, m, i, v) c
#define VA_WRAP_MACRO_INDEX(c, m, i, v) i
#define VA_WRAP_MACRO_NONE(c, m, i, v)
#define VA_WRAP_MACRO_VALUE(c, m, i, v) v

/* These can be used as VA_WRAP() 'separator' parameter. */
#define VA_WRAP_SEPARATOR_AND(c, v, n) &&
#define VA_WRAP_SEPARATOR_COMMA(c, v, n) ,
#define VA_WRAP_SEPARATOR_COMMA_IF_PREV(c, v, n) VA_IF(VA_WRAP_SEPARATOR_COMMA(c, v, n), v)
#define VA_WRAP_SEPARATOR_COMMA_IF_NEXT(c, v, n) VA_IF(VA_WRAP_SEPARATOR_COMMA(c, v, n), n)
#define VA_WRAP_SEPARATOR_COMMA_IF_BOTH(c, v, n) VA_IF(VA_WRAP_SEPARATOR_COMMA_IF_PREV(c, v, n), n)
#define VA_WRAP_SEPARATOR_NONE(c, v, n)
#define VA_WRAP_SEPARATOR_SEMICOLON(c, v, n) ;

/* These can be used as VA_WRAP() 'context' parameter. */
#define VA_WRAP_CONTEXT_FALSE false
#define VA_WRAP_CONTEXT_NONE 0
#define VA_WRAP_CONTEXT_TRUE true

/* These can be used as VA_WRAP() 'zero' parameter. */
#define VA_WRAP_ZERO_CONTEXT(c) c
#define VA_WRAP_ZERO_ERROR(c) _Pragma("GCC error \"Zero variadic args.\"")
#define VA_WRAP_ZERO_FALSE(c) false
#define VA_WRAP_ZERO_NONE(c)
#define VA_WRAP_ZERO_TRUE(c) true
#define VA_WRAP_ZERO_VOID_0(c) VOID_0

/* These can be used as VA_WRAP() 'toomany' parameter. */
#define VA_WRAP_TOOMANY_CONTEXT(c) c
#define VA_WRAP_TOOMANY_ERROR(c) VA_NARGS_TOOMANY_ERROR()
#define VA_WRAP_TOOMANY_FALSE(c) false
#define VA_WRAP_TOOMANY_NONE(c)
#define VA_WRAP_TOOMANY_TRUE(c) true

/* Evaluates to 'x' if there are > VA_NARGS_MAX variadic args, otherwise evaluates to nothing. */
#define VA_NARGS_TOOMANY(x, ...)                                        \
        __VA_OPT__(__VA_0x01(VA_WRAP_MACRO_NONE,                        \
                             VA_WRAP_SEPARATOR_NONE,                    \
                             /* context= */ x,                          \
                             VA_WRAP_TOOMANY_CONTEXT,                   \
                             __VA_ARGS__))

/* Evaluate to one of 3 possible macro tokens, based on the number of variadic args:
 *   If there are no variadic args, evaluate to 'base_ZERO'.
 *   If there is at least one variadic arg but <= VA_NARGS_MAX, evaluate to 'base_ARGS'.
 *   If there are > VA_NARGS_MAX variadic args, evaluate to 'base_TOOMANY'.
 *
 * The 'base' value is concatenated with literal token _ZERO, _ARGS, or _TOOMANY.
 */
#define VA_NARGS_TOKEN(base, ...)                                       \
        CONCATENATE(base,                                               \
                    VA_IF_ELSE(VA_IF_ELSE(_TOOMANY,                     \
                                          _ARGS,                        \
                                          VA_NARGS_TOOMANY(1, ##__VA_ARGS__)), \
                               _ZERO,                                   \
                               ##__VA_ARGS__))

#define __VA_WRAP_ZERO(macro, separator, context, zero, toomany, ...)   \
        __VA_0x00(macro, separator, context, toomany, zero)
#define __VA_WRAP_ARGS(macro, separator, context, zero, toomany, ...)   \
        __VA_0x01(macro, separator, context, toomany, ##__VA_ARGS__)
#define __VA_WRAP_TOOMANY(macro, separator, context, zero, toomany, ...) \
        __VA_TOOM(macro, separator, context, toomany, ##__VA_ARGS__)

/* Expands to 'macro' for each variadic arg, which will be called with 4 parameters:
 *   1) the provided 'context'
 *   2) the value 1 if there more variadic args (will be empty for the last variadic arg)
 *   3) a hex iteration number (starting at 0x01)
 *   4) the variadic arg
 *
 * Each expansion of 'macro' will be separated by 'separator'. If there are no variadic args, this evaluates
 * to 'zero'. If there are too many variadic args, this evaluates to 'toomany'.
 *
 * The 'macro', 'separator', 'zero', and 'toomany' parameters must be callable macros. The VA_WRAP_*()
 * macros above may be used. */
#define VA_WRAP(macro, separator, context, zero, toomany, ...)          \
        VA_NARGS_TOKEN(__VA_WRAP, __VA_ARGS__)(macro,                   \
                                               separator,               \
                                               context,                 \
                                               zero,                    \
                                               toomany,                 \
                                               ##__VA_ARGS__)

/* Expands to list of variadic args, with any "empty" (whitespace only) args removed. This processes the list
 * twice, to remove a trailing comma if needed. */
#define VA_FILTER(...)                                          \
        VA_MACRO(VA_WRAP,                                       \
                 VA_WRAP_MACRO_VALUE,                           \
                 VA_WRAP_SEPARATOR_COMMA_IF_PREV,               \
                 VA_WRAP_CONTEXT_NONE,                          \
                 VA_WRAP_ZERO_NONE,                             \
                 VA_WRAP_TOOMANY_ERROR,                         \
                 VA_WRAP(VA_WRAP_MACRO_VALUE,                   \
                         VA_WRAP_SEPARATOR_COMMA_IF_PREV,       \
                         VA_WRAP_CONTEXT_NONE,                  \
                         VA_WRAP_ZERO_NONE,                     \
                         VA_WRAP_TOOMANY_ERROR,                 \
                         ##__VA_ARGS__))

/* Expands to a comma-separated variadic arg list containing the expansion of each group, with the correct
 * number of commas between each group; specifically, any empty group and its corresponding comma is
 * removed. This does not use VA_WRAP(), so the provided groups may use VA_WRAP(), and this also does not
 * remove empty values inside each group, this only removes the comma if an entire group is empty. These are
 * not variadic macros, so you must call the specific macro for the number of variadic arg groups you
 * have. If you have more than 4 groups, you need to add more macros here. */
#define VA_FILTER_GROUPS2(g1, g2        ) VA_GROUP(g1)VA_IF(VA_COMMA(g1), g2      ) \
                VA_GROUP(g2)
#define VA_FILTER_GROUPS3(g1, g2, g3    ) VA_GROUP(g1)VA_IF(VA_COMMA(g1), g2 g3   ) \
                VA_FILTER_GROUPS2(VA_GROUP(g2), VA_GROUP(g3))
#define VA_FILTER_GROUPS4(g1, g2, g3, g4) VA_GROUP(g1)VA_IF(VA_COMMA(g1), g2 g3 g4) \
                VA_FILTER_GROUPS3(VA_GROUP(g2), VA_GROUP(g3), VA_GROUP(g4))

/* Unfortunately, clang's implementation of __builtin_constant_p() is unreliable for actually identifying
 * constants; it reports actual variables as constant. */
#ifdef __clang__
#define ___IS_CONSTANT(x) 0
#else
#define ___IS_CONSTANT(x) __builtin_constant_p(x)
#endif

/* Evaluates (after compiler processing) to true if all variadic args are constant (or if there are no
 * variadic args). Empty args are considered constant. If there is at least one non-constant variadic arg, or
 * too many variadic args, this evaluates to false. At the preprocessing stage, this evaluates to a
 * ()-enclosed &&-separated list of expressions calling __builtin_constant_p() (unless compiling with clang;
 * see ___IS_CONSTANT()). */
#define VA_ARGS_CONSTANT(...)                                           \
        (VA_WRAP(_VA_ARG_IS_CONSTANT,                                   \
                 VA_WRAP_SEPARATOR_AND,                                 \
                 VA_WRAP_CONTEXT_NONE,                                  \
                 VA_WRAP_ZERO_TRUE,                                     \
                 VA_WRAP_TOOMANY_FALSE,                                 \
                 ##__VA_ARGS__))
#define _VA_ARG_IS_CONSTANT(c, m, i, v) (VA_IF((!___IS_CONSTANT(v))+, v) 1 == 1)

/* Evaluates (at the preprocessor stage) to the number of variadic args. */
#define VA_NARGS(...)                                                   \
        VA_WRAP(_VA_NARGS,                                              \
                VA_WRAP_SEPARATOR_NONE,                                 \
                /* context= */ 0x00,                                    \
                VA_WRAP_ZERO_CONTEXT,                                   \
                VA_WRAP_TOOMANY_ERROR,                                  \
                ##__VA_ARGS__)
#define _VA_NARGS(c, m, i, v) VA_NOT(i, m)

#define _VA_NAME_INDEX(a, b) a ## _ ## b

/* Evaluates to a variable declaration foreach variadic arg. Each variadic arg must be a type. Each variable
 * name is the concatenation of 'name' and the variadic arg index (as a hex number). */
#define VA_DECLARATIONS(name, ...)              \
        VA_WRAP(_VA_DECLARATION,                \
                VA_WRAP_SEPARATOR_SEMICOLON,    \
                /* context= */ name,            \
                VA_WRAP_ZERO_NONE,              \
                VA_WRAP_TOOMANY_ERROR,          \
                ##__VA_ARGS__)
#define _VA_DECLARATION(c, m, i, v) _unused_ v _VA_NAME_INDEX(c, i)

/* Same as VA_DECLARATIONS(), but the variadic args must be variables (or constants). Each declaration
 * uses __auto_type and is initialized to its corresponding variadic arg. */
#define VA_INITIALIZED_DECLARATIONS(name, ...)          \
        VA_WRAP(_VA_INITIALIZED_DECLARATION,            \
                VA_WRAP_SEPARATOR_SEMICOLON,            \
                /* context= */ name,                    \
                VA_WRAP_ZERO_NONE,                      \
                VA_WRAP_TOOMANY_ERROR,                  \
                ##__VA_ARGS__)
#define _VA_INITIALIZED_DECLARATION(c, m, i, v) _unused_ __auto_type _VA_NAME_INDEX(c, i) = (v)

/* Evaluates to a list of tokens by concatenating 'name' with each variadic arg index. This will produce the
 * same tokens as the variable names generated by VA_DECLARATIONS(). */
#define VA_TOKENS(name, ...)                                            \
        VA_WRAP(_VA_TOKEN,                                              \
                VA_WRAP_SEPARATOR_COMMA,                                \
                /* context= */ name,                                    \
                VA_WRAP_ZERO_NONE,                                      \
                VA_WRAP_TOOMANY_ERROR,                                  \
                ##__VA_ARGS__)
#define _VA_TOKEN(c, m, i, v) _VA_NAME_INDEX(c, i)

/* Evaluates (at the preprocessor stage) to a unique token for each variadic arg, separated by commas. This
 * is similar to VA_TOKENS() but names the tokens using the variadic arg tokens. */
#define VA_UNIQ(...)                                                    \
        VA_WRAP(_VA_UNIQ,                                               \
                VA_WRAP_SEPARATOR_COMMA,                                \
                /* context= */ UNIQ,                                    \
                VA_WRAP_ZERO_NONE,                                      \
                VA_WRAP_TOOMANY_ERROR,                                  \
                ##__VA_ARGS__)
#define _VA_UNIQ(c, m, i, v) UNIQ_T(v, c)

/* If an arg is constant, use it directly; otherwise use the tmp var we created for it. This expects to be
 * used by __VMH_VARIABLE(). */
#define _VMH_CONST_OR_NOSE_VAR(name, ...)                               \
        VA_WRAP(__VMH_CONST_OR_NOSE_VAR,                                \
                VA_WRAP_SEPARATOR_COMMA,                                \
                /* context= */ name,                                    \
                VA_WRAP_ZERO_NONE,                                      \
                VA_WRAP_TOOMANY_ERROR,                                  \
                ##__VA_ARGS__)
#define __VMH_CONST_OR_NOSE_VAR(c, m, i, v)                             \
        __builtin_choose_expr(___IS_CONSTANT(v), v, _VA_NAME_INDEX(c, i))

/* Creating tmp vars is !constant; otherwise, constant only if all nose vars are constant. */
#define __VMH_IS_CONSTANT(nose, tmp)                    \
        (VA_EMPTY(tmp) && VA_ARGS_CONSTANT(nose))

/* This will always be preprocessor-evaluated since __builtin_choose_expr() is processed by the compiler, so
 * we need to be careful to always provide the macro with the expected number of args. Also, the compiler
 * (currently) checks both choices for syntax, so this also must be syntactically correct, even if this
 * choice won't be actually used, meaning we can't actually call the macro if any tmp variables are used,
 * since the compiler will complain (undefined, wrong type, etc). So if any tmp vars are used, we replace the
 * macro with a macro that evaluates to a simple expression. */
#define __VMH_CONSTANT(macro, nose, tmp, uniq, direct)                  \
        VA_MACRO(VA_IF_ELSE(__VMH_0, macro, tmp),                       \
                 VA_FILTER_GROUPS3(VA_GROUP(nose),                      \
                                   VA_UNIQ(uniq),                       \
                                   VA_GROUP(direct)))
#define __VMH_0(...) (0)

/* This builds the token used for nose and tmp vars. */
#define __VMH_NAME(x, u) __va_macro_helper ## x ## u

/* As with __VMH_CONSTANT(), this is always preprocessor-evaluated and syntax-checked by the compiler, but we
 * don't need to do anything special, since this will always evaluate correctly for the preprocessor and will
 * always have correct syntax, even for all constant inputs. */
#define __VMH_VARIABLE(macro, u, nose, tmp, uniq, direct)               \
        ({                                                              \
                VA_INITIALIZED_DECLARATIONS(__VMH_NAME(_nose_, u), nose) \
                VA_IF(;, nose)                                          \
                VA_DECLARATIONS(__VMH_NAME(_tmp_, u), tmp)              \
                VA_IF(;, tmp)                                           \
                VA_MACRO(macro,                                         \
                         VA_FILTER_GROUPS4(_VMH_CONST_OR_NOSE_VAR(__VMH_NAME(_nose_, u), nose), \
                                           VA_TOKENS(__VMH_NAME(_tmp_, u), tmp), \
                                           VA_UNIQ(uniq),               \
                                           VA_GROUP(direct)));          \
        })

/* Calls 'macro' with a set of args based on the provided arg groups, in the order shown.
 *
 * Each arg in the 'nose' group is provided directly to the macro if the arg is constant, otherwise a
 * temporary variable, initialized to the arg value, is provided to the macro in place of the arg. All args
 * in this group must be either a variable or constant.
 *
 * Each arg in the 'tmp' group provides a temporary variable of the specified type to the macro in place of
 * the arg. All args in this group must be types.
 *
 * Each arg in the 'uniq' group provides a unique token, named based on the arg token, to the macro in
 * place of the arg. This is equivalent to UNIQ_T() for each arg.
 *
 * Each arg in the 'direct' group is provided directly to the macro.
 *
 * If all 'nose' args are constants, and the 'tmp' group is empty, this is equivalent to directly calling
 * 'macro' with the 'nose', 'uniq', and 'direct' variadic args (expanded).
 *
 * This operates mostly at the preprocessor stage, but it evaluates to __builtin_choose_expr() which is
 * handled at the compiler stage. */
#define VA_MACRO_HELPER(macro, nose, tmp, uniq, direct)                 \
        __builtin_choose_expr(__VMH_IS_CONSTANT(VA_GROUP(nose),         \
                                                VA_GROUP(tmp)),         \
                              __VMH_CONSTANT(macro,                     \
                                             VA_GROUP(nose),            \
                                             VA_GROUP(tmp),             \
                                             VA_GROUP(uniq),            \
                                             VA_GROUP(direct)),         \
                              __VMH_VARIABLE(macro,                     \
                                             UNIQ,                      \
                                             VA_GROUP(nose),            \
                                             VA_GROUP(tmp),             \
                                             VA_GROUP(uniq),            \
                                             VA_GROUP(direct)))

/* Same as VA_MACRO_HELPER() but only with 'nose' group; all variadic args are put in 'direct' group. */
#define VA_MACRO_NOSE(macro, nose, ...)                                 \
        VA_MACRO_HELPER(macro,                                          \
                        VA_GROUP(nose),                                 \
                        /* tmp=    */,                                  \
                        /* uniq=   */,                                  \
                        VA_GROUP(__VA_ARGS__))

/* Same as VA_MACRO_HELPER() but only with 'tmp' group; all variadic args are put in 'direct' group. */
#define VA_MACRO_TMP(macro, tmp, ...)                                   \
        VA_MACRO_HELPER(macro,                                          \
                        /* nose=   */,                                  \
                        VA_GROUP(tmp),                                  \
                        /* uniq=   */,                                  \
                        VA_GROUP(__VA_ARGS__))

/* Same as VA_MACRO_HELPER() but only with 'uniq' group; all variadic args are put in 'direct' group. */
#define VA_MACRO_UNIQ(macro, uniq, ...)                                 \
        VA_MACRO_HELPER(macro,                                          \
                        /* nose=   */,                                  \
                        /* tmp=    */,                                  \
                        VA_GROUP(uniq),                                 \
                        VA_GROUP(__VA_ARGS__))

/* Evaluates to a statement expression, containing 'macro' called with each variadic arg, separated by
 * semicolons. With no variadic args, the statement expression contains VOID_0. If you need a different
 * construct, use VA_WRAP() directly. */
#define VA_MACRO_FOREACH(macro, ...) VA_MACRO_FOREACH_CONTEXT(macro, /* no context */, ##__VA_ARGS__)

/* Same as VA_MACRO_FOREACH() but also provides all expanded args in the 'context' group to the macro, before
 * each variadic arg. */
#define VA_MACRO_FOREACH_CONTEXT(macro, context, ...)                   \
        ({                                                              \
                VA_WRAP(_VA_MACRO_FOREACH,                              \
                        VA_WRAP_SEPARATOR_SEMICOLON,                    \
                        (macro, context),                               \
                        VA_WRAP_ZERO_VOID_0,                            \
                        VA_WRAP_TOOMANY_ERROR,                          \
                        ##__VA_ARGS__);                                 \
        })
#define _VA_MACRO_FOREACH(c, m, i, v) __VA_MACRO_FOREACH(v, VA_UNPAREN(c))
#define __VA_MACRO_FOREACH(v, x) ___VA_MACRO_FOREACH(v, x)
#define ___VA_MACRO_FOREACH(v, macro, ...) macro(__VA_ARGS__ __VA_OPT__(,) v)
