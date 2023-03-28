/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* Wraps variadic args in a single group. This can be passed to macros that will then expand the group into
 * all its variadic args. */
#define VA_GROUP(...) __VA_ARGS__

/* Similar to VA_GROUP(), but encloses the variadic args in (), so they are not expanded when passed to other
 * macros. Unlike VA_GROUP(), this requires the final macro that actually uses the group contents to ungroup it
 * using VA_UNPGROUP(). */
#define VA_PGROUP(...) (__VA_ARGS__)

/* Converts a group of args protected with () into a normal VA_GROUP(). 'x' must be enclosed in (). */
#define VA_UNPGROUP(x) VA_GROUP x

/* Evaluates to 'x' if any variadic args, otherwise 'y'.
 *
 * This relies on __VA_OPT__() to determine if there are variadic args; 'any variadic args' means
 * __VA_OPT__() evaluates to its content, and 'no variadic args' means __VA_OPT__() evaluates to
 * nothing. Many of the macros here expect __VA_OPT__() to evaluate to nothing for a single all-whitespace
 * variadic arg. For example these calls are expected to be equivalent:
 *   VA_IF_ELSE(1,2)
 *   VA_IF_ELSE(1,2,)
 *   VA_IF_ELSE(1,2, )
 *   #define NONE
 *   VA_IF_ELSE(1,2,NONE)
 *   VA_IF_ELSE(1,2, NONE)
 *
 * All those calls should evaluate to 2. However, this call should evaluate to 1:
 *   VA_IF_ELSE(1,2,,)
 */
#define VA_IF_ELSE(x, y, ...) _VA_IF_ELSE_MACRO(__VA_ARGS__)(VA_GROUP(x), VA_GROUP(y))
#define _VA_IF_ELSE_MACRO(...) __VA_IF_ELSE_MACRO(__VA_OPT__(1))
#define __VA_IF_ELSE_MACRO(o) _VA_IF_ELSE ## o
#define _VA_IF_ELSE1(x, y) x
#define _VA_IF_ELSE(x, y) y

/* Evaluates to nothing if no variadic args, otherwise 'x'. */
#define VA_IF(x, ...) VA_IF_ELSE(VA_GROUP(x), /*false*/, __VA_ARGS__)

/* Same as VA_IF() but negates the condition. */
#define VA_IF_NOT(x, ...) VA_IF_ELSE(/*true*/, VA_GROUP(x), __VA_ARGS__)

/* Evaluates to token 1 if no variadic args, otherwise nothing. */
#define VA_NOT(...) VA_IF_NOT(1, __VA_ARGS__)

/* Evaluates to the first variadic arg, otherwise nothing. */
#define VA_FIRST(...) VA_IF(_VA_FIRST(__VA_ARGS__), __VA_ARGS__)
#define _VA_FIRST(x, ...) x

/* Evaluates to the rest of the variadic args, after the first, otherwise nothing. */
#define VA_REST(...) VA_IF(_VA_REST(__VA_ARGS__), __VA_ARGS__)
#define _VA_REST(x, ...) __VA_ARGS__

/* Evaluates to ',' if any variadic args, otherwise nothing. */
#define VA_COMMA(...) __VA_OPT__(,)

/* Evaluates to '1' if both args are non-empty, otherwise evaluates to nothing. */
#define VA_AND(x, y) VA_NOT(VA_NOT(x) VA_NOT(y))

/* Evaluates to '1' if either arg is non-empty, otherwise evaluates to nothing. */
#define VA_OR(x, y) VA_IF(1, x y)

/* Evaluates to 'macro' called with the expanded variadic args. */
#define VA_MACRO(macro, ...) macro(__VA_ARGS__)

/* Same as VA_MACRO() but takes a pgroup, which is expanded before passing to the macro. */
#define VA_MACRO_PGROUP(macro, pgroup) VA_MACRO(macro, VA_UNPGROUP(pgroup))

/* Evaluates to nothing. */
#define VA_NOOP(...)

/* This is the max number of variadic args that the macros here can handle. Unless otherwise stated, using
 * more than VA_NARGS_MAX variadic args with any of the (non-underscored) macros below will cause a
 * preprocessor error. */
#define VA_NARGS_MAX 0x03ff
#define __VA_REPEAT_TOOMANY_0x03ff

#define __VAI0 1
#define __VAI1 2
#define __VAI2 3
#define __VAI3 4
#define __VAI4 5
#define __VAI5 6
#define __VAI6 7
#define __VAI7 8
#define __VAI8 9
#define __VAI9 a
#define __VAIa b
#define __VAIb c
#define __VAIc d
#define __VAId e
#define __VAIe f
#define __VAIf 0

#define __VAC0 0
#define __VAC1 0
#define __VAC2 0
#define __VAC3 0
#define __VAC4 0
#define __VAC5 0
#define __VAC6 0
#define __VAC7 0
#define __VAC8 0
#define __VAC9 0
#define __VACa 0
#define __VACb 0
#define __VACc 0
#define __VACd 0
#define __VACe 0
#define __VACf 1

#define ___VAC(x, c) ____VAC(x, c)
#define ____VAC(x, c) _____VAC ## c(x)
#define _____VAC0(x) 0
#define _____VAC1(x) __VAC ## x

#define ___VAI(x, c) ____VAI(x, c)
#define ____VAI(x, c) _____VAI ## c(x)
#define _____VAI0(x) x
#define _____VAI1(x) __VAI ## x

#define ___VAC1(x1)             ___VAC(x1, 1)
#define ___VAC2(x2, x1)         ___VAC(x2, ___VAC1(x1))
#define ___VAC3(x3, x2, x1)     ___VAC(x3, ___VAC2(x2, x1))
#define ___VAC4(x4, x3, x2, x1) ___VAC(x4, ___VAC3(x3, x2, x1))

#define ___VAI1(x1)             ___VAI(x1, 1)
#define ___VAI2(x2, x1)         ___VAI(x2, ___VAC1(x1))
#define ___VAI3(x3, x2, x1)     ___VAI(x3, ___VAC2(x2, x1))
#define ___VAI4(x4, x3, x2, x1) ___VAI(x4, ___VAC3(x3, x2, x1))
#define ___VAIO(x4, x3, x2, x1) ____VAIO(___VAC4(x4, x3, x2, x1))
#define ____VAIO(c) _____VAIO(c)
#define _____VAIO(c) ______VAIO ## c()
#define ______VAIO0()
#define ______VAIO1() _Pragma("GCC error \"VA increment overflow\"")

#define __VAINC(pgroup) ___VAINC pgroup
#define ___VAINC(x4, x3, x2, x1)                \
        ___VAIO(x4, x3, x2, x1)                 \
        (___VAI4(x4, x3, x2, x1),               \
         ___VAI3(x3, x2, x1),                   \
         ___VAI2(x2, x1),                       \
         ___VAI1(x1))

#define ___VAN4(x4, x3, x2, x1) 0x ## x4 ## x3 ## x2 ## x1
#define __VAN4(pgroup) ___VAN4 pgroup
#define __VAN4_TOKEN(x, pgroup) ___VAN4_TOKEN(x, __VAN4(pgroup))
#define ___VAN4_TOKEN(x, i) ____VAN4_TOKEN(x, i)
#define ____VAN4_TOKEN(x, i) x ## i

/* If VA_NARGS_MAX is increased, more nested evaluations may be needed here. */
#define __VAE1(...) __VAE2(__VAE2(__VAE2(__VAE2(__VAE2(__VAE2(__VAE2(__VAE2(__VA_ARGS__))))))))
#define __VAE2(...) __VAE3(__VAE3(__VAE3(__VAE3(__VAE3(__VAE3(__VAE3(__VAE3(__VA_ARGS__))))))))
#define __VAE3(...) __VAE4(__VAE4(__VAE4(__VAE4(__VAE4(__VAE4(__VAE4(__VAE4(__VA_ARGS__))))))))
#define __VAE4(...) __VAE5(__VAE5(__VA_ARGS__))
#define __VAE5(...) __VA_ARGS__

#define __VA_REPEAT(m,s,c,t,...)                                \
        __VAE1(___VA_REPEAT(m,s,c,t,(0,0,0,1),__VA_ARGS__))
#define ___VA_REPEAT(m,s,c,t,i,v,...)                                   \
        m(c,__VAN4(i),v,##__VA_ARGS__)__VA_OPT__(s(c,v,__VA_ARGS__))    \
        __VA_OPT__(___VA_REPEAT_OR_TOOMANY VA_PGROUP(i) (m,s,c,t,__VAINC(i),__VA_ARGS__))
#define ___VA_REPEAT_OR_TOOMANY(i)                                      \
        VA_IF_ELSE(___VA_REPEAT, ___VA_REPEAT_TOOMANY, __VAN4_TOKEN(__VA_REPEAT_TOOMANY_, i))
#define ___VA_REPEAT_TOOMANY(m,s,c,t,i,...) t(c)

#define VA_NARGS_TOOMANY_ERROR() _Pragma("GCC error \"Too many variadic args.\"")

/* These can be used as VA_WRAP() 'macro' parameter. */
#define VA_WRAP_MACRO_CONTEXT(c, i, v, ...) c
#define VA_WRAP_MACRO_INDEX(c, i, v, ...) i
#define VA_WRAP_MACRO_LAST(c, i, v, ...) VA_IF_NOT(v, ##__VA_ARGS__)
#define VA_WRAP_MACRO_LAST_INDEX(c, i, v, ...) VA_IF_NOT(i, ##__VA_ARGS__)
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
#define VA_WRAP_ZERO_0x0000(c) 0x0000
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
        __VA_OPT__(__VA_REPEAT(VA_WRAP_MACRO_NONE,                      \
                               VA_WRAP_SEPARATOR_NONE,                  \
                               /* context= */ x,                        \
                               VA_WRAP_TOOMANY_CONTEXT,                 \
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
        zero(context)
#define __VA_WRAP_SOME(macro, separator, context, zero, toomany, ...)   \
        __VA_REPEAT(macro, separator, context, toomany, __VA_ARGS__)
#define __VA_WRAP_TOOMANY(macro, separator, context, zero, toomany, ...) \
        toomany(context)

/* Expands to 'macro' for each variadic arg, which will be called with:
 *   1) the provided 'context'
 *   2) a hex iteration number (starting at 0x0001)
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
        VA_WRAP(VA_WRAP_MACRO_LAST_INDEX,                               \
                VA_WRAP_SEPARATOR_NONE,                                 \
                VA_WRAP_CONTEXT_NONE,                                   \
                VA_WRAP_ZERO_0x0000,                                    \
                VA_WRAP_TOOMANY_ERROR,                                  \
                ##__VA_ARGS__)

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
