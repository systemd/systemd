/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* This contains macros that all help simplify the use of macros with variadic args. Also provided is a macro
 * 'helper' that helps provide some commonly used things, such as a unique variable name or temporary
 * variable.
 *
 * Some macros operate based on if there are 'any variadic args' or 'no variadic args'; this distinction is
 * based on the use of __VA_OPT__(). The description 'any variadic args' means __VA_OPT__() evaluates to its
 * content, and 'no variadic args' means __VA_OPT__() evaluates to nothing. Note that whitespace is not a
 * preprocessor token, so a single whitespace-only arg is the same as no args. For example these calls all
 * evaluate to 2:
 *   VA_IF_ELSE(1,2)
 *   VA_IF_ELSE(1,2,)
 *   VA_IF_ELSE(1,2, )
 *   #define NONE
 *   VA_IF_ELSE(1,2,NONE)
 *   VA_IF_ELSE(1,2, NONE)
 * However, this call evaluates to 1:
 *   VA_IF_ELSE(1,2,,)
 */

/* Wraps variadic args in a single group. This can be passed to macros that will then expand the group into
 * all its variadic args. */
#define VA_GROUP(...) __VA_ARGS__

/* Evaluates to 'x' if any variadic args, otherwise 'y'. */
#define VA_IF_ELSE(x, y, ...) _VA_IF_ELSE_MACRO(__VA_ARGS__)(_VA_IF_ELSE_GROUP(x), _VA_IF_ELSE_GROUP(y))
#define _VA_IF_ELSE_GROUP(...) __VA_ARGS__
#define _VA_IF_ELSE_MACRO(...) __VA_IF_ELSE_MACRO(__VA_OPT__(1))
#define __VA_IF_ELSE_MACRO(o) _VA_IF_ELSE ## o
#define _VA_IF_ELSE1(x, y) x
#define _VA_IF_ELSE(x, y) y

/* Evaluates to nothing if no variadic args, otherwise 'x'. */
#define VA_IF(x, ...) VA_IF_ELSE(_VA_IF_GROUP(x), /*false*/, __VA_ARGS__)
#define _VA_IF_GROUP(...) __VA_ARGS__

/* Same as VA_IF() but negates the condition. */
#define VA_IF_NOT(x, ...) VA_IF_ELSE(/*true*/, _VA_IF_NOT_GROUP(x), __VA_ARGS__)
#define _VA_IF_NOT_GROUP(...) __VA_ARGS__

/* Evaluates to token 1 if no variadic args, otherwise nothing. */
#define VA_NOT(...) VA_IF_NOT(1, __VA_ARGS__)

/* Evaluates to the first variadic arg, otherwise nothing. */
#define VA_FIRST(...) VA_IF(_VA_FIRST(__VA_ARGS__), __VA_ARGS__)
#define _VA_FIRST(x, ...) x

/* Evaluates to the rest of the variadic args, after the first, otherwise nothing. */
#define VA_REST(...) VA_IF(_VA_REST(__VA_ARGS__), __VA_ARGS__)
#define _VA_REST(x, ...) __VA_ARGS__

/* Evaluates to token , if any variadic args, otherwise nothing. */
#define VA_COMMA(...) __VA_OPT__(,)

/* Evaluates to token 1 if both args are non-empty (ignoring whitespace), otherwise evaluates to nothing. */
#define VA_AND(x, y) VA_NOT(VA_NOT(x) VA_NOT(y))

/* Evaluates to token 1 if either arg is non-empty (ignoring whitespace), otherwise evaluates to nothing. */
#define VA_OR(x, y) VA_IF(1, x y)

/* Evaluates to nothing. */
#define VA_NOOP(...)

/* Similar to VA_GROUP(), but encloses the variadic args in (), so they are not expanded when passed to other
 * macros. Unlike VA_GROUP(), this requires the final macro that actually uses the group contents to ungroup it
 * using VA_UNPGROUP(), or to handle the () directly. */
#define VA_PGROUP(...) (__VA_ARGS__)

/* Converts a group of args protected with () into a normal VA_GROUP(). 'x' must be a pgroup, i.e. (...). */
#define VA_UNPGROUP(x) VA_GROUP x

/* Similar to VA_FIRST(), but x is a pgroup. Evaluates to the first arg if present, otherwise nothing. */
#define VA_PGROUP_FIRST(x) VA_FIRST(VA_UNPGROUP(x))

/* Similar to VA_REST(), but x is a pgroup. Evaluates to a pgroup of the args after the first. If there are
 * no more args after the first, evaluates to an empty pgroup. */
#define VA_PGROUP_REST(x) VA_PGROUP(VA_REST(VA_UNPGROUP(x)))

/* Evaluates to token 1 if pgroup is empty, otherwise nothing. */
#define VA_PGROUP_EMPTY(x) VA_IF_NOT(1, VA_UNPGROUP(x))

/* Similar to VA_PGROUP_EMPTY() but negates the condition. */
#define VA_PGROUP_NOT_EMPTY(x) VA_NOT(VA_PGROUP_EMPTY(x))

/* Evaluates to 'macro' called with the expanded variadic args. */
#define VA_MACRO(macro, ...) macro(__VA_ARGS__)

/* Evaluates to x(__VA_ARGS__) if t is non-empty, otherwise y(__VA_ARGS__). */
#define VA_MACRO_IF_ELSE(x, y, t, ...) VA_IF_ELSE(x, y, t)(__VA_ARGS__)

/* Evaluates to m(__VA_ARGS__) if t is non-empty, otherwise nothing. */
#define VA_MACRO_IF(m, t, ...) VA_MACRO_IF_ELSE(m, VA_NOOP, t, __VA_ARGS__)

/* Evaluates to m(__VA_ARGS__) if t is empty, otherwise nothing. */
#define VA_MACRO_IF_NOT(m, t, ...) VA_MACRO_IF_ELSE(VA_NOOP, m, t, __VA_ARGS__)

/* Same as VA_MACRO() but takes a pgroup, which is unpgrouped before passing to the macro. */
#define VA_MACRO_PGROUP(macro, pgroup) VA_MACRO(macro, VA_UNPGROUP(pgroup))

/* Expands to 'macro' for each variadic arg, which will be called with:
 *   1) the provided 'context'
 *   2) a hex iteration number (starting at 0x0001)
 *   3) the variadic arg
 *   4...) the rest of the variadic args
 *
 * Each expansion of 'macro', except for the last, will be followed by 'separator' called with the same
 * parameters as 'macro'.
 *
 * If there are no variadic args, this evaluates to 'zero' called with the single arg 'context'.
 *
 * If there are too many variadic args, this evaluates to 'toomany' called with the single arg 'context'.
 *
 * The 'macro', 'separator', 'zero', and 'toomany' parameters must be callable macros. The VA_WRAP_*()
 * macros below may be used. The 'context' parameter may be anything and is not directly called. */
#define VA_WRAP(macro, separator, context, zero, toomany, ...)          \
        __VA_WRAP_RECURSE(macro, separator, context, zero, toomany, __VA_ARGS__)

/* These can be used as VA_WRAP() 'macro' parameter. */
#define VA_WRAP_MACRO_CONTEXT(c, i, v, ...) c
#define VA_WRAP_MACRO_INDEX(c, i, v, ...) i
#define VA_WRAP_MACRO_LAST(c, i, v, ...) VA_IF_NOT(v, ##__VA_ARGS__)
#define VA_WRAP_MACRO_LAST_INDEX(c, i, v, ...) VA_IF_NOT(i, ##__VA_ARGS__)
#define VA_WRAP_MACRO_NONE(c, i, v, ...)
#define VA_WRAP_MACRO_VALUE(c, i, v, ...) v

/* These can be used as VA_WRAP() 'separator' parameter. */
#define VA_WRAP_SEPARATOR_AND(c, i, v, ...) &&
#define VA_WRAP_SEPARATOR_COMMA(c, i, v, ...) ,
#define VA_WRAP_SEPARATOR_COMMA_IF_PREV(c, i, v, ...) VA_COMMA(v)
#define VA_WRAP_SEPARATOR_CONTEXT(c, i, v, ...) c
#define VA_WRAP_SEPARATOR_INDEX(c, i, v, ...) i
#define VA_WRAP_SEPARATOR_NONE(c, i, v, ...)
#define VA_WRAP_SEPARATOR_SEMICOLON(c, i, v, ...) ;

/* These can be used as VA_WRAP() 'context' parameter. Note that unlike the other parameters, 'context' is not expected to be callable. */
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
#define VA_WRAP_TOOMANY_ERROR(c) _Pragma("GCC error \"Too many variadic args.\"")
#define VA_WRAP_TOOMANY_FALSE(c) false
#define VA_WRAP_TOOMANY_NONE(c)
#define VA_WRAP_TOOMANY_TRUE(c) true

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
        v _VA_DECLARATION_TOKEN(c, i)

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

/* This is similar to VA_FILTER(), but we can't use VA_FILTER() because macros can't be used recursively, and
 * this is called from inside a VA_WRAP() (which VA_FILTER() relies on). */
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

/* Macros below are complex, internal-use-only macros and should not be used directly. They are used by the
 * macros above. */

/* Integer increment at the preprocessor stage; each macro evaluates to the next integer. Overflow is not
 * handled; f wraps to 0. */
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

/* Integer increment carryover; all macros evaluate to 0 except f, which evaluates to 1. */
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

/* Increment x based on carryover c. Requires x to be single hex digit (0-f) and carryover to be 0-1.
 * Evaluates to 0 if x == f and c == 1, otherwise x+1 if c == 1, otherwise x. */
#define ___VAI(x, c) ____VAI(x, c)
#define ____VAI(x, c) ____VAI ## c(x)
#define ____VAI0(x) x
#define ____VAI1(x) __VAI ## x

/* Carryover of x based on carryover c. Requires x to be single hex digit (0-f) and carryover to be
 * 0-1. Evaluates to 1 if x is f and c is 1, otherwise 0. */
#define ___VAC(x, c) ____VAC(x, c)
#define ____VAC(x, c) ____VAC ## c(x)
#define ____VAC0(x) 0
#define ____VAC1(x) __VAC ## x

/* Carryover of multiple digits. Each calculates the carryover of its digit, with 1 being the least
 * significant digit, and 4 being the most significant digit. */
#define ___VAC1(x1)             ___VAC(x1, 1)
#define ___VAC2(x2, x1)         ___VAC(x2, ___VAC1(x1))
#define ___VAC3(x3, x2, x1)     ___VAC(x3, ___VAC2(x2, x1))
#define ___VAC4(x4, x3, x2, x1) ___VAC(x4, ___VAC3(x3, x2, x1))

/* Increment with carryover across all digits. Each evaluate to their digit incremented if there is carryover
 * from previous digits. */
#define ___VAI1(x1)             ___VAI(x1, 1)
#define ___VAI2(x2, x1)         ___VAI(x2, ___VAC1(x1))
#define ___VAI3(x3, x2, x1)     ___VAI(x3, ___VAC2(x2, x1))
#define ___VAI4(x4, x3, x2, x1) ___VAI(x4, ___VAC3(x3, x2, x1))

/* Detect overflow. If all digits are f, this causes preprocessor error, otherwise this evaluates to
 * nothing. */
#define ___VAIO(x4, x3, x2, x1) ____VAIO(___VAC4(x4, x3, x2, x1))
#define ____VAIO(c) _____VAIO(c)
#define _____VAIO(c) ______VAIO ## c()
#define ______VAIO0()
#define ______VAIO1() _Pragma("GCC error \"VA increment overflow\"")

/* Increment a 4-digit hex number. Requires pgroup to be a 4-digit hex number pgroup, e.g. (0,1,2,3)
 * represents 0x0123. Evaluates to a 4-digit hex number pgroup that has been incremented by 1. On overflow, a
 * preprocessor error is generated. */
#define __VAINC4(pgroup) ___VAINC4 pgroup
#define ___VAINC4(x4, x3, x2, x1)               \
        ___VAIO(x4, x3, x2, x1)                 \
        (___VAI4(x4, x3, x2, x1),               \
         ___VAI3(x3, x2, x1),                   \
         ___VAI2(x2, x1),                       \
         ___VAI1(x1))

/* Convert a 4-digit hex number pgroup to a standard hex number. Requires pgroup to be a 4-digit hex number
 * pgroup. Evaluates to a standard hex number for the pgroup, e.g. (a,b,c,d) evalutes to 0xabcd. */
#define __VANUM4(pgroup) ___VANUM4 pgroup
#define ___VANUM4(x4, x3, x2, x1) 0x ## x4 ## x3 ## x2 ## x1

/* Nested repeated evaluations. This is what controls when the 'toomany' VA_WRAP() parameter is evaluated. */
#define __VA_EVAL_0x0002(...) __VA_ARGS__
#define __VA_EVAL_0x0004(...) __VA_EVAL_0x0002(__VA_EVAL_0x0002(__VA_ARGS__))
#define __VA_EVAL_0x0008(...) __VA_EVAL_0x0004(__VA_EVAL_0x0004(__VA_ARGS__))
#define __VA_EVAL_0x0010(...) __VA_EVAL_0x0008(__VA_EVAL_0x0008(__VA_ARGS__))
#define __VA_EVAL_0x0020(...) __VA_EVAL_0x0010(__VA_EVAL_0x0010(__VA_ARGS__))
#define __VA_EVAL_0x0040(...) __VA_EVAL_0x0020(__VA_EVAL_0x0020(__VA_ARGS__))
#define __VA_EVAL_0x0080(...) __VA_EVAL_0x0040(__VA_EVAL_0x0040(__VA_ARGS__))
#define __VA_EVAL_0x0100(...) __VA_EVAL_0x0080(__VA_EVAL_0x0080(__VA_ARGS__))
#define __VA_EVAL_0x0200(...) __VA_EVAL_0x0100(__VA_EVAL_0x0100(__VA_ARGS__))

/* This should match the list of macros above. */
#define __VA_EVAL_STEPS (0x0002, 0x0004, 0x0008, 0x0010, 0x0020, 0x0040, 0x0080, 0x0100, 0x0200)

/* Determine which __VA_EVAL_0x* macro to use for the given variadic args. This is a quick evaluation for the
 * preprocessor and avoids unnecessary reevaluations for complex macro expansions. Evaluates to the smallest
 * (least evaluations) __VA_EVAL_0x* macro token that can handle the number of provided variadic args. */
#define __VA_EVAL_MACRO(...) __VA_EVAL_MACRO_CHECK_EACH(__VA_EVAL_STEPS, __VA_ARGS__)

/* Re-evaluates for each step. If __VA_EVAL_STEPS is increased this may need to be increased. */
#define __VA_EVAL_MACRO_CHECK_EACH(steps, ...) __VA_EVAL_MACRO_EVAL16(__VA_EVAL_MACRO_CHECK(steps, __VA_ARGS__))
#define __VA_EVAL_MACRO_EVAL02(...) __VA_ARGS__
#define __VA_EVAL_MACRO_EVAL04(...) __VA_EVAL_MACRO_EVAL02(__VA_EVAL_MACRO_EVAL02(__VA_ARGS__))
#define __VA_EVAL_MACRO_EVAL08(...) __VA_EVAL_MACRO_EVAL04(__VA_EVAL_MACRO_EVAL04(__VA_ARGS__))
#define __VA_EVAL_MACRO_EVAL16(...) __VA_EVAL_MACRO_EVAL08(__VA_EVAL_MACRO_EVAL08(__VA_ARGS__))

/* Evaluates to the first __VA_EVAL_0x* macro name that can handle all the variadic args. If there are too
 * many variadic args for the largest macro to handle, evaluates to nothing. Note this uses the same
 * preprocessor recursion "trick" as __VA_WRAP_RECURSE() below. */
#define __VA_EVAL_MACRO_CHECK(steps, ...)                               \
        ___VA_EVAL_MACRO_CHECK                                          \
        VA_PGROUP(__VA_EVAL_MACRO_MORE(VA_PGROUP_FIRST(steps), __VA_ARGS__))(steps, __VA_ARGS__)

/* 'x' is the evaluation of __VA_EVAL_MACRO_MORE(); if it is empty, this evaluates to __VA_EVAL_MACRO_OK,
 * otherwise the tested __VA_EVAL_0x* macro cannot handle all the variadic args, and this evaluates to
 * __VA_EVAL_MACRO_NEXT. */
#define ___VA_EVAL_MACRO_CHECK(x) VA_IF_ELSE(__VA_EVAL_MACRO_NEXT, __VA_EVAL_MACRO_OK, x)

/* Move on to testing the next step (i.e. next 0x* value). */
#define __VA_EVAL_MACRO_NEXT(steps, ...) ___VA_EVAL_MACRO_NEXT(VA_PGROUP_REST(steps), __VA_ARGS__)

/* Test the next step value. If there are no more steps, evaluate to nothing. */
#define ___VA_EVAL_MACRO_NEXT(steps, ...)                               \
        VA_MACRO_IF(__VA_EVAL_MACRO_CHECK, VA_PGROUP_NOT_EMPTY(steps), steps, __VA_ARGS__)

/* The first value of 'steps' is acceptable, so evaluate to the corresponding __VA_EVAL_* macro name. */
#define __VA_EVAL_MACRO_OK(steps, ...) ___VA_EVAL_MACRO_OK(VA_PGROUP_FIRST(steps))
#define ___VA_EVAL_MACRO_OK(n) ____VA_EVAL_MACRO_OK(n)
#define ____VA_EVAL_MACRO_OK(n) __VA_EVAL_ ## n

/* Bug in Centos Stream 8 gcc preprocessor doesn't correctly handle __VA_OPT__(); work around it. Once Centos
 * Stream 8 is no longer supported, this can be dropped. */
#define __CENTOS_STREAM_8_NONE
#define __CENTOS_STREAM_8_BUG_CHECK() ___CENTOS_STREAM_8_BUG_CHECK(__CENTOS_STREAM_8_NONE)
#define ___CENTOS_STREAM_8_BUG_CHECK(...) __VA_OPT__(1)
#define __VA_EVAL_MACRO_MORE_IF_ONCE(...) __VA_OPT__(1)
#define __VA_EVAL_MACRO_MORE_IF_TWICE(...) __VA_EVAL_MACRO_MORE_IF_ONCE(__VA_ARGS__)
#define __VA_EVAL_MACRO_MORE_IF_MACRO()                 \
        VA_IF_ELSE(__VA_EVAL_MACRO_MORE_IF_TWICE,       \
                   __VA_EVAL_MACRO_MORE_IF_ONCE,        \
                   __CENTOS_STREAM_8_BUG_CHECK())
#define __VA_EVAL_MACRO_MORE_IF() __VA_EVAL_MACRO_MORE_IF_MACRO()

/* Test if the __VA_EVAL_0x* macro for hex number 'n' can handle all the variadic args. Evaluates to 1 if
 * there are remaining (unhandled) variadic args after all evaluations, otherwise nothing. */
#define __VA_EVAL_MACRO_MORE(n, ...)                                    \
        __VA_EVAL_MACRO_MORE_IF()(__VA_EVAL_MACRO_MORE_N(n)(__VA_OPT__(___VA_EVAL_MACRO_MORE(__VA_ARGS__))))
#define __VA_EVAL_MACRO_MORE_N(n) __VA_EVAL_ ## n
#define ___VA_EVAL_MACRO_MORE(v, ...) __VA_OPT__(___VA_EVAL_MACRO_MORE_NEXT VA_PGROUP()(__VA_ARGS__))
#define ___VA_EVAL_MACRO_MORE_NEXT() ___VA_EVAL_MACRO_MORE

/* Recursive macro evaluation. This is intended for use by VA_WRAP() above. This performs the actions
 * described by VA_WRAP() for each variadic arg.
 *
 * This "trick" inspired by:
 *   https://www.scs.stanford.edu/~dm/blog/va-opt.html
 *   https://github.com/pfultz2/Cloak/wiki/C-Preprocessor-tricks,-tips,-and-idioms
 *
 * This determines the number of re-evaluations required for the provided number of variadic args, then calls
 * the appropriate __VA_EVAL_0x*() macro with ___VA_WRAP_RECURSE(), providing the initial index of 0x0001. */
#define __VA_WRAP_RECURSE(macro, separator, context, zero, toomany, ...) \
        VA_IF_ELSE(__VA_WRAP_RECURSE_NONZERO,                           \
                   __VA_WRAP_RECURSE_ZERO,                              \
                   __VA_ARGS__)(macro, separator, context, zero, toomany, __VA_ARGS__)
#define __VA_WRAP_RECURSE_ZERO(macro, separator, context, zero, toomany, ...) zero(context)
#define __VA_WRAP_RECURSE_NONZERO(macro, separator, context, zero, toomany, ...) \
        __VA_WRAP_RECURSE_CHECK_TOOMANY(__VA_EVAL_MACRO(__VA_ARGS__),   \
                                        macro, separator, context, toomany, __VA_ARGS__)
#define __VA_WRAP_RECURSE_CHECK_TOOMANY(evalmacro, macro, separator, context, toomany, ...) \
        VA_IF_ELSE(__VA_WRAP_RECURSE_EVAL,                              \
                   __VA_WRAP_RECURSE_TOOMANY,                           \
                   evalmacro)(evalmacro, macro, separator, context, toomany, __VA_ARGS__)
#define __VA_WRAP_RECURSE_TOOMANY(evalmacro, macro, separator, context, toomany, ...) toomany(context)
#define __VA_WRAP_RECURSE_EVAL(evalmacro, macro, separator, context, toomany, ...) \
        evalmacro(___VA_WRAP_RECURSE(macro,                             \
                                     separator,                         \
                                     context,                           \
                                     (0,0,0,1),                         \
                                     __VA_ARGS__))

/* This is the "trick" macro, which evaluates to the current variadic arg 'value' wrapped by 'macro', and
 * then (if there are remaining variadic args) followed by 'separator' followed by the "trick"; which is
 * ___VA_WRAP_NEXT token and VA_PGROUP(). On the next re-evaluation, this (indirectly) evaluates recursively
 * to ___VA_WRAP_RECURSE(). */
#define ___VA_WRAP_RECURSE(macro, separator, context, index, value, ...) \
        ___VA_WRAP_RECURSE_CALL(macro,                                  \
                                VA_IF_ELSE(separator, VA_NOOP, __VA_ARGS__), \
                                VA_GROUP(context, __VANUM4(index), value, __VA_ARGS__)) \
        __VA_OPT__(___VA_WRAP_NEXT VA_PGROUP()(macro, separator, context, __VAINC4(index), __VA_ARGS__))
#define ___VA_WRAP_RECURSE_CALL(macro, separator, args) macro(args)separator(args)
#define ___VA_WRAP_NEXT() ___VA_WRAP_RECURSE
