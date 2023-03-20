/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro-fundamental.h"

/* Wraps variadic args in a single group. This can be passed to macros that will then expand the group into
 * all its variadic args. */
#define VA_GROUP(...) __VA_ARGS__

/* Evaluates to the first variadic arg. If there are no variadic args, evaluates to nothing. */
#define VA_FIRST(...) __VA_OPT__(_VA_FIRST(__VA_ARGS__))
#define _VA_FIRST(x, ...) x

/* Evaluates to the rest of the variadic args, after the first. If there is only 1 (or 0) variadic args,
 * evaluates to nothing. */
#define VA_REST(...) __VA_OPT__(_VA_REST(__VA_ARGS__))
#define _VA_REST(x, ...) __VA_ARGS__

/* Evaluates to 'x' if a single variadic arg (which is not empty or only whitespace) is provided, or if
 * multiple variadic args (even if they are all empty) are provided, otherwise evaluates to nothing. */
#define VA_IF(x, ...) __VA_OPT__(x)

/* Same as VA_IF() but negates the condition. */
#define VA_IF_NOT(x, ...) VA_IF(x, VA_NOT(__VA_ARGS__))

/* Same as VA_IF_NOT(), except this evaluates to '1'. */
//#define VA_NOT(...) VA_IF_ELSE(, 1, ##__VA_ARGS__)
#define VA_NOT(...) _VA_NOT(__VA_OPT__(1))()
#define _VA_NOT(o) __VA_NOT ## o
#define __VA_NOT1()
#define __VA_NOT() 1

/* Combination of VA_IF() and VA_IF_NOT(); evaluates to 'x' if there are non-empty variadic arg(s), otherwise
 * evaluates to 'y'. */
#define VA_IF_ELSE(x, y, ...) _VA_IF_ELSE(__VA_OPT__(1))(VA_GROUP(x), VA_GROUP(y))
#define _VA_IF_ELSE(o) __VA_IF_ELSE ## o
#define __VA_IF_ELSE1(x, y) x
#define __VA_IF_ELSE(x, y) y

/* Evaluates to ',' if x is non-empty, otherwise evalutes to nothing. */
#define VA_COMMA(...) __VA_OPT__(,)

/* Evaluates to '1' if both args are non-empty, otherwise evaluates to nothing. */
#define VA_AND(x, y) VA_NOT(VA_NOT(x) VA_NOT(y))

/* Evaluates to '1' if either arg is non-empty, otherwise evaluates to nothing. */
#define VA_OR(x, y) VA_IF(1, x y)

/* Evaluates to 'macro' called with the expanded variadic args. */
#define VA_MACRO(macro, ...) macro(__VA_ARGS__)

/* This is the max number of variadic args that the macros here can handle. This should match the highest
 * entry in the _VA_0x*() list below. Unless otherwise stated, using more than VA_NARGS_MAX variadic args
 * with any of the (non-underscored) macros below will cause a preprocessor error. */
#define VA_NARGS_MAX (0x7f)

#define __VAWTM(m,s,c,t,v,...) t(c) /* too many variadic args */
#define __VAW7f(m,s,c,t,v,...) m(c,0x7f,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAWTM(m,s,c,t,__VA_ARGS__))
#define __VAW7e(m,s,c,t,v,...) m(c,0x7e,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW7f(m,s,c,t,__VA_ARGS__))
#define __VAW7d(m,s,c,t,v,...) m(c,0x7d,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW7e(m,s,c,t,__VA_ARGS__))
#define __VAW7c(m,s,c,t,v,...) m(c,0x7c,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW7d(m,s,c,t,__VA_ARGS__))
#define __VAW7b(m,s,c,t,v,...) m(c,0x7b,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW7c(m,s,c,t,__VA_ARGS__))
#define __VAW7a(m,s,c,t,v,...) m(c,0x7a,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW7b(m,s,c,t,__VA_ARGS__))
#define __VAW79(m,s,c,t,v,...) m(c,0x79,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW7a(m,s,c,t,__VA_ARGS__))
#define __VAW78(m,s,c,t,v,...) m(c,0x78,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW79(m,s,c,t,__VA_ARGS__))
#define __VAW77(m,s,c,t,v,...) m(c,0x77,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW78(m,s,c,t,__VA_ARGS__))
#define __VAW76(m,s,c,t,v,...) m(c,0x76,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW77(m,s,c,t,__VA_ARGS__))
#define __VAW75(m,s,c,t,v,...) m(c,0x75,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW76(m,s,c,t,__VA_ARGS__))
#define __VAW74(m,s,c,t,v,...) m(c,0x74,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW75(m,s,c,t,__VA_ARGS__))
#define __VAW73(m,s,c,t,v,...) m(c,0x73,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW74(m,s,c,t,__VA_ARGS__))
#define __VAW72(m,s,c,t,v,...) m(c,0x72,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW73(m,s,c,t,__VA_ARGS__))
#define __VAW71(m,s,c,t,v,...) m(c,0x71,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW72(m,s,c,t,__VA_ARGS__))
#define __VAW70(m,s,c,t,v,...) m(c,0x70,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW71(m,s,c,t,__VA_ARGS__))
#define __VAW6f(m,s,c,t,v,...) m(c,0x6f,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW70(m,s,c,t,__VA_ARGS__))
#define __VAW6e(m,s,c,t,v,...) m(c,0x6e,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW6f(m,s,c,t,__VA_ARGS__))
#define __VAW6d(m,s,c,t,v,...) m(c,0x6d,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW6e(m,s,c,t,__VA_ARGS__))
#define __VAW6c(m,s,c,t,v,...) m(c,0x6c,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW6d(m,s,c,t,__VA_ARGS__))
#define __VAW6b(m,s,c,t,v,...) m(c,0x6b,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW6c(m,s,c,t,__VA_ARGS__))
#define __VAW6a(m,s,c,t,v,...) m(c,0x6a,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW6b(m,s,c,t,__VA_ARGS__))
#define __VAW69(m,s,c,t,v,...) m(c,0x69,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW6a(m,s,c,t,__VA_ARGS__))
#define __VAW68(m,s,c,t,v,...) m(c,0x68,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW69(m,s,c,t,__VA_ARGS__))
#define __VAW67(m,s,c,t,v,...) m(c,0x67,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW68(m,s,c,t,__VA_ARGS__))
#define __VAW66(m,s,c,t,v,...) m(c,0x66,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW67(m,s,c,t,__VA_ARGS__))
#define __VAW65(m,s,c,t,v,...) m(c,0x65,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW66(m,s,c,t,__VA_ARGS__))
#define __VAW64(m,s,c,t,v,...) m(c,0x64,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW65(m,s,c,t,__VA_ARGS__))
#define __VAW63(m,s,c,t,v,...) m(c,0x63,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW64(m,s,c,t,__VA_ARGS__))
#define __VAW62(m,s,c,t,v,...) m(c,0x62,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW63(m,s,c,t,__VA_ARGS__))
#define __VAW61(m,s,c,t,v,...) m(c,0x61,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW62(m,s,c,t,__VA_ARGS__))
#define __VAW60(m,s,c,t,v,...) m(c,0x60,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW61(m,s,c,t,__VA_ARGS__))
#define __VAW5f(m,s,c,t,v,...) m(c,0x5f,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW60(m,s,c,t,__VA_ARGS__))
#define __VAW5e(m,s,c,t,v,...) m(c,0x5e,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW5f(m,s,c,t,__VA_ARGS__))
#define __VAW5d(m,s,c,t,v,...) m(c,0x5d,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW5e(m,s,c,t,__VA_ARGS__))
#define __VAW5c(m,s,c,t,v,...) m(c,0x5c,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW5d(m,s,c,t,__VA_ARGS__))
#define __VAW5b(m,s,c,t,v,...) m(c,0x5b,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW5c(m,s,c,t,__VA_ARGS__))
#define __VAW5a(m,s,c,t,v,...) m(c,0x5a,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW5b(m,s,c,t,__VA_ARGS__))
#define __VAW59(m,s,c,t,v,...) m(c,0x59,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW5a(m,s,c,t,__VA_ARGS__))
#define __VAW58(m,s,c,t,v,...) m(c,0x58,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW59(m,s,c,t,__VA_ARGS__))
#define __VAW57(m,s,c,t,v,...) m(c,0x57,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW58(m,s,c,t,__VA_ARGS__))
#define __VAW56(m,s,c,t,v,...) m(c,0x56,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW57(m,s,c,t,__VA_ARGS__))
#define __VAW55(m,s,c,t,v,...) m(c,0x55,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW56(m,s,c,t,__VA_ARGS__))
#define __VAW54(m,s,c,t,v,...) m(c,0x54,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW55(m,s,c,t,__VA_ARGS__))
#define __VAW53(m,s,c,t,v,...) m(c,0x53,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW54(m,s,c,t,__VA_ARGS__))
#define __VAW52(m,s,c,t,v,...) m(c,0x52,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW53(m,s,c,t,__VA_ARGS__))
#define __VAW51(m,s,c,t,v,...) m(c,0x51,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW52(m,s,c,t,__VA_ARGS__))
#define __VAW50(m,s,c,t,v,...) m(c,0x50,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW51(m,s,c,t,__VA_ARGS__))
#define __VAW4f(m,s,c,t,v,...) m(c,0x4f,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW50(m,s,c,t,__VA_ARGS__))
#define __VAW4e(m,s,c,t,v,...) m(c,0x4e,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW4f(m,s,c,t,__VA_ARGS__))
#define __VAW4d(m,s,c,t,v,...) m(c,0x4d,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW4e(m,s,c,t,__VA_ARGS__))
#define __VAW4c(m,s,c,t,v,...) m(c,0x4c,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW4d(m,s,c,t,__VA_ARGS__))
#define __VAW4b(m,s,c,t,v,...) m(c,0x4b,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW4c(m,s,c,t,__VA_ARGS__))
#define __VAW4a(m,s,c,t,v,...) m(c,0x4a,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW4b(m,s,c,t,__VA_ARGS__))
#define __VAW49(m,s,c,t,v,...) m(c,0x49,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW4a(m,s,c,t,__VA_ARGS__))
#define __VAW48(m,s,c,t,v,...) m(c,0x48,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW49(m,s,c,t,__VA_ARGS__))
#define __VAW47(m,s,c,t,v,...) m(c,0x47,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW48(m,s,c,t,__VA_ARGS__))
#define __VAW46(m,s,c,t,v,...) m(c,0x46,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW47(m,s,c,t,__VA_ARGS__))
#define __VAW45(m,s,c,t,v,...) m(c,0x45,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW46(m,s,c,t,__VA_ARGS__))
#define __VAW44(m,s,c,t,v,...) m(c,0x44,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW45(m,s,c,t,__VA_ARGS__))
#define __VAW43(m,s,c,t,v,...) m(c,0x43,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW44(m,s,c,t,__VA_ARGS__))
#define __VAW42(m,s,c,t,v,...) m(c,0x42,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW43(m,s,c,t,__VA_ARGS__))
#define __VAW41(m,s,c,t,v,...) m(c,0x41,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW42(m,s,c,t,__VA_ARGS__))
#define __VAW40(m,s,c,t,v,...) m(c,0x40,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW41(m,s,c,t,__VA_ARGS__))
#define __VAW3f(m,s,c,t,v,...) m(c,0x3f,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW40(m,s,c,t,__VA_ARGS__))
#define __VAW3e(m,s,c,t,v,...) m(c,0x3e,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW3f(m,s,c,t,__VA_ARGS__))
#define __VAW3d(m,s,c,t,v,...) m(c,0x3d,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW3e(m,s,c,t,__VA_ARGS__))
#define __VAW3c(m,s,c,t,v,...) m(c,0x3c,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW3d(m,s,c,t,__VA_ARGS__))
#define __VAW3b(m,s,c,t,v,...) m(c,0x3b,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW3c(m,s,c,t,__VA_ARGS__))
#define __VAW3a(m,s,c,t,v,...) m(c,0x3a,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW3b(m,s,c,t,__VA_ARGS__))
#define __VAW39(m,s,c,t,v,...) m(c,0x39,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW3a(m,s,c,t,__VA_ARGS__))
#define __VAW38(m,s,c,t,v,...) m(c,0x38,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW39(m,s,c,t,__VA_ARGS__))
#define __VAW37(m,s,c,t,v,...) m(c,0x37,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW38(m,s,c,t,__VA_ARGS__))
#define __VAW36(m,s,c,t,v,...) m(c,0x36,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW37(m,s,c,t,__VA_ARGS__))
#define __VAW35(m,s,c,t,v,...) m(c,0x35,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW36(m,s,c,t,__VA_ARGS__))
#define __VAW34(m,s,c,t,v,...) m(c,0x34,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW35(m,s,c,t,__VA_ARGS__))
#define __VAW33(m,s,c,t,v,...) m(c,0x33,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW34(m,s,c,t,__VA_ARGS__))
#define __VAW32(m,s,c,t,v,...) m(c,0x32,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW33(m,s,c,t,__VA_ARGS__))
#define __VAW31(m,s,c,t,v,...) m(c,0x31,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW32(m,s,c,t,__VA_ARGS__))
#define __VAW30(m,s,c,t,v,...) m(c,0x30,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW31(m,s,c,t,__VA_ARGS__))
#define __VAW2f(m,s,c,t,v,...) m(c,0x2f,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW30(m,s,c,t,__VA_ARGS__))
#define __VAW2e(m,s,c,t,v,...) m(c,0x2e,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW2f(m,s,c,t,__VA_ARGS__))
#define __VAW2d(m,s,c,t,v,...) m(c,0x2d,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW2e(m,s,c,t,__VA_ARGS__))
#define __VAW2c(m,s,c,t,v,...) m(c,0x2c,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW2d(m,s,c,t,__VA_ARGS__))
#define __VAW2b(m,s,c,t,v,...) m(c,0x2b,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW2c(m,s,c,t,__VA_ARGS__))
#define __VAW2a(m,s,c,t,v,...) m(c,0x2a,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW2b(m,s,c,t,__VA_ARGS__))
#define __VAW29(m,s,c,t,v,...) m(c,0x29,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW2a(m,s,c,t,__VA_ARGS__))
#define __VAW28(m,s,c,t,v,...) m(c,0x28,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW29(m,s,c,t,__VA_ARGS__))
#define __VAW27(m,s,c,t,v,...) m(c,0x27,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW28(m,s,c,t,__VA_ARGS__))
#define __VAW26(m,s,c,t,v,...) m(c,0x26,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW27(m,s,c,t,__VA_ARGS__))
#define __VAW25(m,s,c,t,v,...) m(c,0x25,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW26(m,s,c,t,__VA_ARGS__))
#define __VAW24(m,s,c,t,v,...) m(c,0x24,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW25(m,s,c,t,__VA_ARGS__))
#define __VAW23(m,s,c,t,v,...) m(c,0x23,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW24(m,s,c,t,__VA_ARGS__))
#define __VAW22(m,s,c,t,v,...) m(c,0x22,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW23(m,s,c,t,__VA_ARGS__))
#define __VAW21(m,s,c,t,v,...) m(c,0x21,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW22(m,s,c,t,__VA_ARGS__))
#define __VAW20(m,s,c,t,v,...) m(c,0x20,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW21(m,s,c,t,__VA_ARGS__))
#define __VAW1f(m,s,c,t,v,...) m(c,0x1f,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW20(m,s,c,t,__VA_ARGS__))
#define __VAW1e(m,s,c,t,v,...) m(c,0x1e,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW1f(m,s,c,t,__VA_ARGS__))
#define __VAW1d(m,s,c,t,v,...) m(c,0x1d,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW1e(m,s,c,t,__VA_ARGS__))
#define __VAW1c(m,s,c,t,v,...) m(c,0x1c,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW1d(m,s,c,t,__VA_ARGS__))
#define __VAW1b(m,s,c,t,v,...) m(c,0x1b,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW1c(m,s,c,t,__VA_ARGS__))
#define __VAW1a(m,s,c,t,v,...) m(c,0x1a,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW1b(m,s,c,t,__VA_ARGS__))
#define __VAW19(m,s,c,t,v,...) m(c,0x19,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW1a(m,s,c,t,__VA_ARGS__))
#define __VAW18(m,s,c,t,v,...) m(c,0x18,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW19(m,s,c,t,__VA_ARGS__))
#define __VAW17(m,s,c,t,v,...) m(c,0x17,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW18(m,s,c,t,__VA_ARGS__))
#define __VAW16(m,s,c,t,v,...) m(c,0x16,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW17(m,s,c,t,__VA_ARGS__))
#define __VAW15(m,s,c,t,v,...) m(c,0x15,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW16(m,s,c,t,__VA_ARGS__))
#define __VAW14(m,s,c,t,v,...) m(c,0x14,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW15(m,s,c,t,__VA_ARGS__))
#define __VAW13(m,s,c,t,v,...) m(c,0x13,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW14(m,s,c,t,__VA_ARGS__))
#define __VAW12(m,s,c,t,v,...) m(c,0x12,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW13(m,s,c,t,__VA_ARGS__))
#define __VAW11(m,s,c,t,v,...) m(c,0x11,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW12(m,s,c,t,__VA_ARGS__))
#define __VAW10(m,s,c,t,v,...) m(c,0x10,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW11(m,s,c,t,__VA_ARGS__))
#define __VAW0f(m,s,c,t,v,...) m(c,0x0f,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW10(m,s,c,t,__VA_ARGS__))
#define __VAW0e(m,s,c,t,v,...) m(c,0x0e,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW0f(m,s,c,t,__VA_ARGS__))
#define __VAW0d(m,s,c,t,v,...) m(c,0x0d,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW0e(m,s,c,t,__VA_ARGS__))
#define __VAW0c(m,s,c,t,v,...) m(c,0x0c,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW0d(m,s,c,t,__VA_ARGS__))
#define __VAW0b(m,s,c,t,v,...) m(c,0x0b,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW0c(m,s,c,t,__VA_ARGS__))
#define __VAW0a(m,s,c,t,v,...) m(c,0x0a,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW0b(m,s,c,t,__VA_ARGS__))
#define __VAW09(m,s,c,t,v,...) m(c,0x09,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW0a(m,s,c,t,__VA_ARGS__))
#define __VAW08(m,s,c,t,v,...) m(c,0x08,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW09(m,s,c,t,__VA_ARGS__))
#define __VAW07(m,s,c,t,v,...) m(c,0x07,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW08(m,s,c,t,__VA_ARGS__))
#define __VAW06(m,s,c,t,v,...) m(c,0x06,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW07(m,s,c,t,__VA_ARGS__))
#define __VAW05(m,s,c,t,v,...) m(c,0x05,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW06(m,s,c,t,__VA_ARGS__))
#define __VAW04(m,s,c,t,v,...) m(c,0x04,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW05(m,s,c,t,__VA_ARGS__))
#define __VAW03(m,s,c,t,v,...) m(c,0x03,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW04(m,s,c,t,__VA_ARGS__))
#define __VAW02(m,s,c,t,v,...) m(c,0x02,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW03(m,s,c,t,__VA_ARGS__))
#define __VAW01(m,s,c,t,v,...) m(c,0x01,v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__) __VAW02(m,s,c,t,__VA_ARGS__))
#define __VAW00(m,s,c,t,z) z(c)

#define VA_NARGS_TOOMANY_ERROR() _Pragma("GCC error \"Too many variadic args.\"")

/* These can be used as VA_WRAP() 'macro' parameter. */
#define VA_WRAP_MACRO_CONTEXT(c, i, v, ...) c
#define VA_WRAP_MACRO_INDEX(c, i, v, ...) i
#define VA_WRAP_MACRO_LAST(c, i, v, ...) VA_IF_NOT(v, ##__VA_ARGS__)
#define VA_WRAP_MACRO_NONE(c, i, v, ...)
#define VA_WRAP_MACRO_VALUE(c, i, v, ...) v

/* These can be used as VA_WRAP() 'separator' parameter. */
#define VA_WRAP_SEPARATOR_AND(c, v, ...) &&
#define VA_WRAP_SEPARATOR_COMMA(c, v, ...) ,
#define VA_WRAP_SEPARATOR_COMMA_IF_PREV(c, v, ...) VA_COMMA(v)
#define VA_WRAP_SEPARATOR_NONE(c, v, ...)
#define VA_WRAP_SEPARATOR_SEMICOLON(c, v, ...) ;

/* These can be used as VA_WRAP() 'context' parameter. */
#define VA_WRAP_CONTEXT_FALSE false
#define VA_WRAP_CONTEXT_NONE 0
#define VA_WRAP_CONTEXT_TRUE true

/* These can be used as VA_WRAP() 'zero' parameter. */
#define VA_WRAP_ZERO_0(c) 0
#define VA_WRAP_ZERO_0x00(c) 0x00
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
        __VA_OPT__(__VAW01(VA_WRAP_MACRO_NONE,                          \
                           VA_WRAP_SEPARATOR_NONE,                      \
                           /* context= */ x,                            \
                           VA_WRAP_TOOMANY_CONTEXT,                     \
                           __VA_ARGS__))

/* Evaluates to 'x' if there are some variadic args, but not too many, otherwise evaluates to nothing. */
#define VA_NARGS_SOME(x, ...)                                           \
        VA_IF_NOT(x, VA_NARGS_ZERO(1, ##__VA_ARGS__) VA_NARGS_TOOMANY(1, ##__VA_ARGS__))

/* Evaluates to 'x' if there are no variadic args, otherwise evaluates to nothing. */
#define VA_NARGS_ZERO(x, ...) VA_IF_NOT(x, ##__VA_ARGS__)

/* Evaluates to a token based on the number of variadic args:
 *   0                       : '_ZERO'
 *   >= 1 && <= VA_NARGS_MAX : '_SOME'
 *   > VA_NARGS_MAX          : '_TOOMANY'
 */
#define _VA_NARGS_TOKEN_SUFFIX(...)                     \
        VA_NARGS_ZERO(_ZERO, ##__VA_ARGS__)             \
        VA_NARGS_SOME(_SOME, ##__VA_ARGS__)             \
        VA_NARGS_TOOMANY(_TOOMANY, ##__VA_ARGS__)

/* Evaluates to the concatenation of 'base' and the result of _VA_NARGS_TOKEN_SUFFIX(). */
#define VA_NARGS_TOKEN(base, ...)                                       \
        _VA_NARGS_TOKEN(base, _VA_NARGS_TOKEN_SUFFIX(__VA_ARGS__))
#define _VA_NARGS_TOKEN(base, suffix) __VA_NARGS_TOKEN(base, suffix)
#define __VA_NARGS_TOKEN(base, suffix) base ## suffix

#define __VA_WRAP_ZERO(macro, separator, context, zero, toomany, ...)   \
        __VAW00(macro, separator, context, toomany, zero)
#define __VA_WRAP_SOME(macro, separator, context, zero, toomany, ...)   \
        __VAW01(macro, separator, context, toomany, ##__VA_ARGS__)
#define __VA_WRAP_TOOMANY(macro, separator, context, zero, toomany, ...) \
        __VAWTM(macro, separator, context, toomany, ##__VA_ARGS__)

/* Expands to 'macro' for each variadic arg, which will be called with:
 *   1) the provided 'context'
 *   2) a hex iteration number (starting at 0x01)
 *   3) the variadic arg
 *   4...) the rest of the variadic args
 *
 * Each expansion of 'macro', except for the last, will be followed by 'separator' called with:
 *   1) the provided 'context'
 *   2) the variadic arg
 *   3...) the rest of the variadic args
 *
 * If there are no variadic args, this evaluates to 'zero' called with the single arg 'context'.
 *
 * If there are too many variadic args, this evaluates to 'toomany' called with the single arg 'context'.
 *
 * The 'macro', 'separator', 'zero', and 'toomany' parameters must be callable macros. The VA_WRAP_*()
 * macros above may be used. */
#define VA_WRAP(macro, separator, context, zero, toomany, ...)          \
        VA_NARGS_TOKEN(__VA_WRAP, ##__VA_ARGS__)(macro,                 \
                                                 separator,             \
                                                 context,               \
                                                 zero,                  \
                                                 toomany,               \
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

/* Evaluates to the number of variadic args. */
#define VA_NARGS(...)                                                   \
        VA_WRAP(_VA_NARGS,                                              \
                VA_WRAP_SEPARATOR_NONE,                                 \
                VA_WRAP_CONTEXT_NONE,                                   \
                VA_WRAP_ZERO_0x00,                                      \
                VA_WRAP_TOOMANY_ERROR,                                  \
                ##__VA_ARGS__)
#define _VA_NARGS(c, i, v, ...) VA_IF_NOT(i, ##__VA_ARGS__)

/* Evaluates to the last variadic arg. If there are no variadic args, evaluates to nothing. */
#define VA_LAST(...)                                                    \
        VA_WRAP(VA_WRAP_MACRO_LAST,                                     \
                VA_WRAP_SEPARATOR_NONE,                                 \
                VA_WRAP_CONTEXT_NONE,                                   \
                VA_WRAP_ZERO_NONE,                                      \
                VA_WRAP_TOOMANY_ERROR,                                  \
                ##__VA_ARGS__)

#define _VA_DECLARATIONS(macro, name, ...)      \
        VA_WRAP(macro,                          \
                VA_WRAP_SEPARATOR_SEMICOLON,    \
                name,                           \
                VA_WRAP_ZERO_NONE,              \
                VA_WRAP_TOOMANY_ERROR,          \
                ##__VA_ARGS__)

#define _VA_DECLARATION_TOKEN(x, y) __VA_DECLARATION_TOKEN(x, y)
#define __VA_DECLARATION_TOKEN(x, y) x ## _ ## y

/* Evaluates to a variable declaration for each variadic arg. Each variadic arg must be a type. Each variable
 * name is the concatenation of 'name', '_', and the variadic arg index (as a hex number). */
#define VA_DECLARATIONS(name, ...)                              \
        _VA_DECLARATIONS(_VA_DECLARATION, name, ##__VA_ARGS__)
#define _VA_DECLARATION(c, i, v, ...)           \
        _unused_ v _VA_DECLARATION_TOKEN(c, i)

/* Same as VA_DECLARATIONS(), but the variadic args must be variables (or constants). Each declaration
 * uses __auto_type and is initialized to its corresponding variadic arg. */
#define VA_INITIALIZED_DECLARATIONS(name, ...)                          \
        _VA_DECLARATIONS(_VA_INITIALIZED_DECLARATION, name, ##__VA_ARGS__)
#define _VA_INITIALIZED_DECLARATION(c, i, v, ...)               \
        _VA_DECLARATION(c, i, __auto_type, ##__VA_ARGS__) = (v)

/* Same as VA_INITIALIZED_DECLARATIONS(), but the temp variable is declared with const. */
#define VA_CONST_INITIALIZED_DECLARATIONS(name, ...)                    \
        _VA_DECLARATIONS(_VA_CONST_INITIALIZED_DECLARATION, name, ##__VA_ARGS__)
#define _VA_CONST_INITIALIZED_DECLARATION(c, i, v, ...)                 \
        const _VA_INITIALIZED_DECLARATION(c, i, v, ##__VA_ARGS__)

/* Evaluates to a comma-separated list of tokens by concatenating 'name' and a literal '_' with each variadic
 * arg index. This will produce the same tokens as the variable names generated by VA_DECLARATIONS(). Note
 * this does not actually evaluate any of the variadic args. */
#define VA_TOKENS(name, ...)                                            \
        VA_WRAP(_VA_TOKEN,                                              \
                VA_WRAP_SEPARATOR_COMMA,                                \
                name,                                                   \
                VA_WRAP_ZERO_NONE,                                      \
                VA_WRAP_TOOMANY_ERROR,                                  \
                ##__VA_ARGS__)
#define _VA_TOKEN(c, i, v, ...) _VA_DECLARATION_TOKEN(c, i)

/* Evaluates to a comma-separated list of unique tokens using UNIQ_T() for each variadic arg. This is similar
 * to VA_TOKENS() but uses UNIQ_T() to generate the tokens. */
#define VA_UNIQ(...)                                                    \
        VA_WRAP(_VA_UNIQ,                                               \
                VA_WRAP_SEPARATOR_COMMA,                                \
                UNIQ,                                                   \
                VA_WRAP_ZERO_NONE,                                      \
                VA_WRAP_TOOMANY_ERROR,                                  \
                ##__VA_ARGS__)
#define _VA_UNIQ(c, i, v, ...) UNIQ_T(v, c)

/* This is similar to VA_FILTER(), but we can't use VA_FILTER() because macros can't be used recursively. */
#define __VMH_GROUPS(g1, g2, g3, g4, g5)        \
        g1 VA_IF(VA_COMMA(g1), g2 g3 g4 g5)     \
        g2 VA_IF(VA_COMMA(g2), g3 g4 g5)        \
        g3 VA_IF(VA_COMMA(g3), g4 g5)           \
        g4 VA_IF(VA_COMMA(g4), g5)              \
        g5

#define __VMH_TOKEN(x, u) __va_macro_helper ## x ## u
#define __VMH_STATEMENT_EXPRESSION(macro, u, uniq, var, varinit, varconst, direct) \
        ({                                                              \
                VA_DECLARATIONS(                  __VMH_TOKEN(_var_,      u), var); \
                VA_INITIALIZED_DECLARATIONS(      __VMH_TOKEN(_varinit_,  u), varinit); \
                VA_CONST_INITIALIZED_DECLARATIONS(__VMH_TOKEN(_varconst_, u), varconst); \
                VA_MACRO(macro,                                         \
                         __VMH_GROUPS(VA_UNIQ(uniq),                    \
                                      VA_TOKENS(__VMH_TOKEN(_var_,      u), var), \
                                      VA_TOKENS(__VMH_TOKEN(_varinit_,  u), varinit), \
                                      VA_TOKENS(__VMH_TOKEN(_varconst_, u), varconst), \
                                      VA_GROUP(direct)));               \
        })

#define __VMH_EXPRESSION(macro, u, uniq, var, varinit, varconst, direct) \
        VA_MACRO(macro,                                                 \
                 __VMH_GROUPS(VA_UNIQ(uniq), VA_GROUP(direct),,,))

/* Calls 'macro' with a set of args based on the provided arg groups, in the order shown. Multiple args may
 * be provided to each group by using VA_GROUP().
 *
 * Each arg in the 'uniq' group provides a unique token, named based on the arg token, to the macro in
 * place of the arg. This is equivalent to UNIQ_T() for each arg.
 *
 * Each arg in the 'var' group provides a temporary variable of the specified type to the macro in place of
 * the arg. All args in this group must be types.
 *
 * The 'varinit' group is similar to the 'var' group, but each arg must be a variable or constant, and each
 * temporary variable is initialized to the value of the provided arg. The macro may use these args without
 * any concern for side effects.
 *
 * The 'varconst' group is similar to the 'varinit' group, but the temporary variables are also marked as
 * const. The macro should not modify args in this group.
 *
 * Each arg in the 'direct' group is provided directly to the macro. */
#define VA_MACRO_HELPER(macro, uniq, var, varinit, varconst, direct)    \
        VA_IF_ELSE(__VMH_STATEMENT_EXPRESSION,                          \
                   __VMH_EXPRESSION,                                    \
                   var varinit varconst)(macro,                         \
                                         UNIQ,                          \
                                         VA_GROUP(uniq),                \
                                         VA_GROUP(var),                 \
                                         VA_GROUP(varinit),             \
                                         VA_GROUP(varconst),            \
                                         VA_GROUP(direct))

/* Same as VA_MACRO_HELPER() but only with 'uniq' group; all variadic args are put in 'direct' group. */
#define VA_MACRO_UNIQ(macro, uniq, ...)                                 \
        VA_MACRO_HELPER(macro,                                          \
                        VA_GROUP(uniq),                                 \
                        /* var=      */,                                \
                        /* varinit=  */,                                \
                        /* varconst= */,                                \
                        VA_GROUP(__VA_ARGS__))

/* Same as VA_MACRO_HELPER() but only with 'var' group; all variadic args are put in 'direct' group. */
#define VA_MACRO_VAR(macro, var, ...)                                   \
        VA_MACRO_HELPER(macro,                                          \
                        /* uniq=     */,                                \
                        VA_GROUP(var),                                  \
                        /* varinit=  */,                                \
                        /* varconst= */,                                \
                        VA_GROUP(__VA_ARGS__))

/* Same as VA_MACRO_HELPER() but only with 'varinit' group; all variadic args are put in 'direct' group. */
#define VA_MACRO_VARINIT(macro, varinit, ...)                           \
        VA_MACRO_HELPER(macro,                                          \
                        /* uniq=     */,                                \
                        /* var=      */,                                \
                        VA_GROUP(varinit),                              \
                        /* varconst= */,                                \
                        VA_GROUP(__VA_ARGS__))

/* Same as VA_MACRO_HELPER() but only with 'varconst' group; all variadic args are put in 'direct' group. */
#define VA_MACRO_VARCONST(macro, varconst, ...)                         \
        VA_MACRO_HELPER(macro,                                          \
                        /* uniq=    */,                                 \
                        /* var=     */,                                 \
                        /* varinit= */,                                 \
                        VA_GROUP(varconst),                             \
                        VA_GROUP(__VA_ARGS__))
