/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stddef.h>

#include "log.h"
#include "string-util.h"
#include "tests.h"
#include "variadic-fundamental.h"

#define _MACRO_LOG(...) ({ log_info("%s", #__VA_ARGS__); 0; })
#define MACRO_LOG(...) _MACRO_LOG(__VA_ARGS__)

#define NONE
#define MACRO_NONE()
#define MACRO_IGNORE(...)

#define MACRO1(x, ...) (x)
#define MACRO2(x1, x2, ...) (x2)
#define MACRO_SUM12(x1, x2, ...) (x1 + x2)

#define MACRO_3ARG_SUM(x1, x2, x3) x1 + x2 + x3
#define MACRO_4ARG_SUM(x1, x2, x3, x4) x1 + x2 + x3 + x4

#define MACRO_VARG_1(x1, ...) x1
#define MACRO_VARG_2(x1, ...) MACRO_VARG_1(__VA_ARGS__)
#define MACRO_VARG_3(x1, ...) MACRO_VARG_2(__VA_ARGS__)
#define MACRO_VARG_4(x1, ...) MACRO_VARG_3(__VA_ARGS__)

#define MACRO_GROUP_VARG_1(x) MACRO_VARG_1(x)
#define MACRO_GROUP_VARG_2(x) MACRO_VARG_2(x)
#define MACRO_GROUP_VARG_3(x) MACRO_VARG_3(x)
#define MACRO_GROUP_VARG_4(x) MACRO_VARG_4(x)

#define MACRO_GROUP_3ARG_SUM(x) MACRO_3ARG_SUM(x)
#define MACRO_GROUP_4ARG_SUM(x) MACRO_4ARG_SUM(x)

#define MACRO_2GROUP_4ARG_3ARG_SUM(g1, g2) MACRO_4ARG_SUM(g1) + MACRO_3ARG_SUM(g2)
#define MACRO_2GROUP_VARG_3ARG_G2A2(g1, g2) MACRO_VARG_2(g2)
#define MACRO_2GROUP_4ARG_VARG_SUM_G1A4_G2A3(g1, g2) MACRO_VARG_4(g1) + MACRO_VARG_3(g2)

TEST(va_group) {
        assert_se(MACRO_GROUP_VARG_4(VA_GROUP(1,2,3,4)) == 4);
        assert_se(MACRO_GROUP_VARG_1(VA_GROUP(5,10,20)) == 5);
        assert_se(MACRO_GROUP_3ARG_SUM(VA_GROUP(1, 1000, -2)) == 999);
        assert_se(MACRO_GROUP_4ARG_SUM(VA_GROUP(1, 1, 1, 2)) == 5);
        assert_se(MACRO_2GROUP_4ARG_3ARG_SUM(VA_GROUP(5,6,7,8), VA_GROUP(1,1,1)) == 29);
        assert_se(MACRO_2GROUP_VARG_3ARG_G2A2(VA_GROUP(1,2,3,4,5,6,7,8,9), VA_GROUP(3,2,1)) == 2);
        assert_se(MACRO_2GROUP_4ARG_VARG_SUM_G1A4_G2A3(VA_GROUP(4,3,2,1), VA_GROUP(9,8,7,6,5,4)) == 8);
}

#define V1() 1
#define V2() 2

#define VI6E7(x) VA_IF_ELSE(6, 7, x)
#define VI8E9(x) VA_IF_ELSE(8, 9, x)

TEST(va_if_else) {
        assert_se(VA_IF_ELSE(1,2) == 2);
        assert_se(VA_IF_ELSE(1,2,) == 2);
        assert_se(VA_IF_ELSE(1,2, ) == 2);
        assert_se(VA_IF_ELSE(1,2,NONE) == 2);
        assert_se(VA_IF_ELSE(1,2, NONE) == 2);
        assert_se(VA_IF_ELSE(1,2,,) == 1);
        assert_se(VA_IF_ELSE(1, 2, ) == 2);
        assert_se(VA_IF_ELSE(1, 2,NONE ) == 2);
        assert_se(VA_IF_ELSE(1, 2, 1) == 1);
        assert_se(VA_IF_ELSE(1, 2,  "no") == 1);
        assert_se(VA_IF_ELSE(1, 2, VA_IF(1, )) == 2);
        assert_se(VA_IF_ELSE(1, 2, VA_IF(1, 1) ) == 1);
        assert_se(VA_IF_ELSE(1, 2, VA_IF_NOT(1, )) == 1);
        assert_se(VA_IF_ELSE(1, 2, VA_IF_NOT(1, 2)) == 2);
        assert_se(VA_IF_ELSE(1, 2, VA_NOT()) == 1);
        assert_se(VA_IF_ELSE(1, 2, VA_NOT(1)) == 2);
        assert_se(VA_IF_ELSE(1, 2, VA_IF_ELSE(100, 200, )) == 1);
        assert_se(VA_IF_ELSE(1, 2, VA_IF_ELSE(100, 200, 1)) == 1);
        assert_se(VA_IF_ELSE(1, 2, VA_IF_ELSE(100, , )) == 2);
        assert_se(VA_IF_ELSE(1, 2, VA_IF_ELSE(, 4 , )) == 1);
        assert_se(VA_IF_ELSE(V1, V2, 1)() == 1);
        assert_se(VA_IF_ELSE(V1, V2, )() == 2);
        assert_se(VA_IF_ELSE(VI6E7, VI8E9, )(1) == 8);
        assert_se(VA_IF_ELSE(VI6E7, VI8E9, 0)(1) == 6);
        assert_se(VA_IF_ELSE(VI6E7, VI8E9, )() == 9);
        assert_se(VA_IF_ELSE(VI6E7, VI8E9, 55)() == 7);
        assert_se(VA_IF_ELSE(VA_IF_ELSE(3, 4,  ), VA_IF_ELSE(5, 6,  ),  ) == 6);
        assert_se(VA_IF_ELSE(VA_IF_ELSE(3, 4,  ), VA_IF_ELSE(5, 6,  ), 1) == 4);
        assert_se(VA_IF_ELSE(VA_IF_ELSE(3, 4,  ), VA_IF_ELSE(5, 6, 1),  ) == 5);
        assert_se(VA_IF_ELSE(VA_IF_ELSE(3, 4,  ), VA_IF_ELSE(5, 6, 1), 1) == 4);
        assert_se(VA_IF_ELSE(VA_IF_ELSE(3, 4, 1), VA_IF_ELSE(5, 6,  ),  ) == 6);
        assert_se(VA_IF_ELSE(VA_IF_ELSE(3, 4, 1), VA_IF_ELSE(5, 6,  ), 1) == 3);
        assert_se(VA_IF_ELSE(VA_IF_ELSE(3, 4, 1), VA_IF_ELSE(5, 6, 1),  ) == 5);
        assert_se(VA_IF_ELSE(VA_IF_ELSE(3, 4, 1), VA_IF_ELSE(5, 6, 1), 1) == 3);
}

TEST(va_if) {
        assert_se(VA_IF(123,1) == 123);
        assert_se(VA_IF(1+,1) 0 == 1);
        assert_se(VA_IF(1+,0) 0 == 1);
        assert_se(VA_IF(1+,) 0 == 0);
        assert_se(VA_IF(1+,  )0 == 0);
        assert_se(VA_IF(1+, VA_IF(2+, VA_IF(3+, 4))) 0 == 1);
        assert_se(VA_IF(1+, VA_IF(2+, VA_IF(3+, ))) 0 == 0);
        assert_se(VA_IF(1+, VA_IF(, VA_IF(3+, 4))) 0 == 0);
        assert_se(streq(VA_IF("hi", VA_IF(x,1)) "", "hi"));
        assert_se(!streq(VA_IF("hi", VA_IF(x,NONE)) "", "hi"));
}

TEST(va_if_not) {
        assert_se(VA_IF_NOT(123,) == 123);
        assert_se(VA_IF_NOT(1+,1) 0 == 0);
        assert_se(VA_IF_NOT(1+,0) 0 == 0);
        assert_se(VA_IF_NOT(1+,) 0 == 1);
        assert_se(VA_IF_NOT(1+,  )0 == 1);
        assert_se(VA_IF_NOT(1+, VA_IF_NOT(2+, VA_IF_NOT(3+, 4))) 0 == 0);
        assert_se(VA_IF_NOT(1+, VA_IF_NOT(2+, VA_IF_NOT(3+, ))) 0 == 1);
        assert_se(VA_IF_NOT(1+, VA_IF_NOT(, VA_IF_NOT(3+, 4))) 0 == 1);
        assert_se(!streq(VA_IF_NOT("hi", 1) "", "hi"));
        assert_se(streq(VA_IF_NOT("hi", NONE) "", "hi"));
}

TEST(va_not) {
        assert_se(streq(STRINGIFY(VA_NOT()), "1"));
        assert_se(streq(STRINGIFY(VA_NOT(  )), "1"));
        assert_se(streq(STRINGIFY(VA_NOT(1)), ""));
        assert_se(streq(STRINGIFY(VA_NOT(0)), ""));
        assert_se(streq(STRINGIFY(VA_NOT(1,2,3)), ""));
        assert_se(streq(STRINGIFY(VA_NOT(,1,)), ""));
        assert_se(streq(STRINGIFY(VA_NOT(,1)), ""));
        assert_se(streq(STRINGIFY(VA_NOT("")), ""));
        assert_se(streq(STRINGIFY(VA_NOT("hi")), ""));
        assert_se(streq(STRINGIFY(VA_NOT(VA_NOT())), ""));
        assert_se(streq(STRINGIFY(VA_NOT(VA_NOT(2))), "1"));
        assert_se(streq(STRINGIFY(VA_NOT(VA_NOT("hi"))), "1"));
        assert_se(streq(STRINGIFY(VA_NOT(VA_NOT(VA_NOT(2)))), ""));
        assert_se(streq(STRINGIFY(VA_NOT(VA_NOT(2),VA_NOT(3))), ""));
        assert_se(streq(STRINGIFY(VA_NOT(VA_NOT(),VA_NOT(3))), ""));
        assert_se(streq(STRINGIFY(VA_NOT(VA_NOT(2),VA_NOT())), ""));
}

TEST(va_first) {
        assert_se(VA_FIRST(1,2,3) == 1);
        assert_se(VA_FIRST(1+,2+) 0 == 1);
        assert_se(VA_FIRST(1+) 0 == 1);
        assert_se(VA_FIRST() 0 == 0);
        assert_se(streq(STRINGIFY(VA_FIRST()), ""));
        assert_se(streq(STRINGIFY(VA_FIRST( )), ""));
        assert_se(streq(STRINGIFY(VA_FIRST(,)), ""));
        assert_se(streq(STRINGIFY(VA_FIRST(NONE)), ""));
        assert_se(streq(STRINGIFY(VA_FIRST( NONE )), ""));
        assert_se(streq(STRINGIFY(VA_FIRST( NONE, )), ""));
        assert_se(streq(STRINGIFY(VA_FIRST( NONE,1,3 )), ""));
}

TEST(va_rest) {
        assert_se(VA_REST(1,3) == 3);
        assert_se(VA_REST(1+,2+) 0 == 2);
        assert_se(VA_REST(1+) 0 == 0);
        assert_se(VA_REST() 0 == 0);
        assert_se(streq(STRINGIFY(VA_REST(NONE,1)), "1"));
        assert_se(streq(STRINGIFY(VA_REST(1,NONE,1)), ",1"));
        assert_se(streq(STRINGIFY(VA_REST(1,NONE)), ""));

        assert_se(VA_FIRST(VA_REST(1,2,3,4,5)) == 2);

        int ia[] = { VA_REST(1,2,3,4,5) };
        assert_se(ELEMENTSOF(ia) == 4);
        assert_se(ia[0] == 2);
        assert_se(ia[1] == 3);
        assert_se(ia[2] == 4);
        assert_se(ia[3] == 5);
}

TEST(va_comma) {
        assert_se(streq("0 , 1, 2", STRINGIFY(0 VA_COMMA(0) 1, 2)));
        assert_se(streq("0 , 1, 2", STRINGIFY(0 VA_COMMA(1) 1, 2)));
        assert_se(streq("0 1, 2", STRINGIFY(0 VA_COMMA() 1, 2)));
}

TEST(va_and) {
        assert_se(streq(STRINGIFY(VA_AND(1,2)), "1"));
        assert_se(streq(STRINGIFY(VA_AND(,2)), ""));
        assert_se(streq(STRINGIFY(VA_AND(1,)), ""));
        assert_se(streq(STRINGIFY(VA_AND(,)), ""));
        assert_se(streq(STRINGIFY(VA_AND(  ,  )), ""));
        assert_se(streq(STRINGIFY(VA_AND(1  ,  )), ""));
        assert_se(streq(STRINGIFY(VA_AND(  , 2 )), ""));
        assert_se(streq(STRINGIFY(VA_AND(  1  , 2 )), "1"));
        assert_se(streq(STRINGIFY(VA_AND("hi",2)), "1"));
        assert_se(streq(STRINGIFY(VA_AND(1,"hi")), "1"));
        assert_se(streq(STRINGIFY(VA_AND("hi","hi")), "1"));
        assert_se(streq(STRINGIFY(VA_AND(VA_AND(1,2),2)), "1"));
        assert_se(streq(STRINGIFY(VA_AND(VA_AND(1,),2)), ""));
        assert_se(streq(STRINGIFY(VA_AND(VA_AND(1,2),)), ""));
        assert_se(streq(STRINGIFY(VA_AND( VA_AND(  , 1 )  ,  VA_AND(  ,  )  )), ""));
        assert_se(streq(STRINGIFY(VA_AND( VA_AND(  ,  )  ,  VA_AND(  ,  )  )), ""));
}

TEST(va_or) {
        assert_se(streq(STRINGIFY(VA_OR(1,2)), "1"));
        assert_se(streq(STRINGIFY(VA_OR(,2)), "1"));
        assert_se(streq(STRINGIFY(VA_OR(1,)), "1"));
        assert_se(streq(STRINGIFY(VA_OR(,)), ""));
        assert_se(streq(STRINGIFY(VA_OR("hi",2)), "1"));
        assert_se(streq(STRINGIFY(VA_OR(1,"hi")), "1"));
        assert_se(streq(STRINGIFY(VA_OR("hi","hi")), "1"));
        assert_se(streq(STRINGIFY(VA_OR("hi",)), "1"));
        assert_se(streq(STRINGIFY(VA_OR(,"hi")), "1"));
        assert_se(streq(STRINGIFY(VA_OR(  ,  )), ""));
        assert_se(streq(STRINGIFY(VA_OR(VA_OR(1,),)), "1"));
        assert_se(streq(STRINGIFY(VA_OR(VA_OR(,),)), ""));
        assert_se(streq(STRINGIFY(VA_OR(VA_OR(,),2)), "1"));
        assert_se(streq(STRINGIFY(VA_OR(  VA_OR(1,)  ,  )), "1"));
        assert_se(streq(STRINGIFY(VA_OR( VA_OR(  , 1 )  ,  VA_OR(  ,  )  )), "1"));
        assert_se(streq(STRINGIFY(VA_OR( VA_OR(  ,  )  ,  VA_OR(  ,  )  )), ""));
}

TEST(va_macro) {
        assert_se(VA_MACRO(MACRO1, 3,2,1) == 3);
        assert_se(VA_MACRO(MACRO1, 4) == 4);
        assert_se(VA_MACRO(MACRO2, 4,5) == 5);
        assert_se(streq(VA_MACRO(MACRO2, 4,"hi"), "hi"));
}

#define TEST_VA_NARGS_MAX_LESS_1                                        \
        0x,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,01,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f, \
        02,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,03,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f, \
        04,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,05,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f, \
        06,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,07,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f, \
        08,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,09,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f, \
        0a,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,0b,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f, \
        0c,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,0d,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f, \
        0e,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,0f,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f, \
        1x,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,11,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f, \
        12,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,13,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f, \
        14,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,15,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f, \
        16,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,17,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f, \
        18,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,19,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f, \
        1a,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,1b,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f, \
        1c,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,1d,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f, \
        1e,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,1f,1,2,3,4,5,6,7,8,9,a,b,c,d

#define TEST_NARGS_ZST(zst, expect, ...) assert_se(zst(1+, __VA_ARGS__) 0 == expect)

TEST(va_nargs_zero) {
        assert_se(VA_NARGS_ZERO(1+) 0 == 1);

        TEST_NARGS_ZST(VA_NARGS_ZERO, 1,);
        TEST_NARGS_ZST(VA_NARGS_ZERO, 1, );
        TEST_NARGS_ZST(VA_NARGS_ZERO, 0, 1);
        TEST_NARGS_ZST(VA_NARGS_ZERO, 0, 1,2,3,4,5,6,7,8,9,"hi",10);
        TEST_NARGS_ZST(VA_NARGS_ZERO, 0, TEST_VA_NARGS_MAX_LESS_1);
        TEST_NARGS_ZST(VA_NARGS_ZERO, 0, TEST_VA_NARGS_MAX_LESS_1, 1);
        TEST_NARGS_ZST(VA_NARGS_ZERO, 0, TEST_VA_NARGS_MAX_LESS_1, 1, 2);
        TEST_NARGS_ZST(VA_NARGS_ZERO, 0, TEST_VA_NARGS_MAX_LESS_1, 1, 2, 3);
}

TEST(va_nargs_some) {
        assert_se(VA_NARGS_SOME(1+) 0 == 0);

        TEST_NARGS_ZST(VA_NARGS_SOME, 0,);
        TEST_NARGS_ZST(VA_NARGS_SOME, 0, );
        TEST_NARGS_ZST(VA_NARGS_SOME, 1, 1);
        TEST_NARGS_ZST(VA_NARGS_SOME, 1,0);
        TEST_NARGS_ZST(VA_NARGS_SOME, 1, 1,2,3,4,5,6,7,8,9,"hi",10);
        TEST_NARGS_ZST(VA_NARGS_SOME, 1, TEST_VA_NARGS_MAX_LESS_1);
        TEST_NARGS_ZST(VA_NARGS_SOME, 1, TEST_VA_NARGS_MAX_LESS_1, 1);
        TEST_NARGS_ZST(VA_NARGS_SOME, 0, TEST_VA_NARGS_MAX_LESS_1, 1, 2);
        TEST_NARGS_ZST(VA_NARGS_SOME, 0, TEST_VA_NARGS_MAX_LESS_1, 1, 2, 3);
}

TEST(va_nargs_toomany) {
        assert_se(VA_NARGS_TOOMANY(1+) 0 == 0);

        TEST_NARGS_ZST(VA_NARGS_TOOMANY, 0,);
        TEST_NARGS_ZST(VA_NARGS_TOOMANY, 0, );
        TEST_NARGS_ZST(VA_NARGS_TOOMANY, 0, 1);
        TEST_NARGS_ZST(VA_NARGS_TOOMANY, 0,0);
        TEST_NARGS_ZST(VA_NARGS_TOOMANY, 0, 1,2,3,4,5,6,7,8,9,"hi",10);
        TEST_NARGS_ZST(VA_NARGS_TOOMANY, 0, TEST_VA_NARGS_MAX_LESS_1);
        TEST_NARGS_ZST(VA_NARGS_TOOMANY, 0, TEST_VA_NARGS_MAX_LESS_1, 1);
        TEST_NARGS_ZST(VA_NARGS_TOOMANY, 1, TEST_VA_NARGS_MAX_LESS_1, 1, 2);
        TEST_NARGS_ZST(VA_NARGS_TOOMANY, 1, TEST_VA_NARGS_MAX_LESS_1, 1, 2, 3);
        TEST_NARGS_ZST(VA_NARGS_TOOMANY, 1, TEST_VA_NARGS_MAX_LESS_1, TEST_VA_NARGS_MAX_LESS_1);
}

#define TEST_NARGS_TOKENS(expect, ...)          \
        ({                                      \
                assert_se(streq(STRINGIFY(expect), STRINGIFY(VA_NARGS_TOKEN(T, ##__VA_ARGS__)))); \
        })

#define MACRO_TEST_NARGS_ZERO() 100
#define MACRO_TEST_NARGS_SOME() 101
#define MACRO_TEST_NARGS_TOOMANY() 102

TEST(va_nargs_token) {
        TEST_NARGS_TOKENS(T_ZERO);
        TEST_NARGS_TOKENS(T_ZERO,);
        TEST_NARGS_TOKENS(T_ZERO,  );
        TEST_NARGS_TOKENS(T_SOME, 1);
        TEST_NARGS_TOKENS(T_SOME, 1,2,3,4);
        TEST_NARGS_TOKENS(T_SOME, 1 , 5);
        TEST_NARGS_TOKENS(T_SOME, TEST_VA_NARGS_MAX_LESS_1);
        TEST_NARGS_TOKENS(T_SOME, TEST_VA_NARGS_MAX_LESS_1, 1);
        TEST_NARGS_TOKENS(T_TOOMANY, TEST_VA_NARGS_MAX_LESS_1, 1, 2);
        TEST_NARGS_TOKENS(T_TOOMANY, TEST_VA_NARGS_MAX_LESS_1, 1, 2, 3);
        TEST_NARGS_TOKENS(T_TOOMANY, TEST_VA_NARGS_MAX_LESS_1, TEST_VA_NARGS_MAX_LESS_1);

        assert_se(VA_NARGS_TOKEN(MACRO_TEST_NARGS)() == 100);
        assert_se(VA_NARGS_TOKEN(MACRO_TEST_NARGS,)() == 100);
        assert_se(VA_NARGS_TOKEN(MACRO_TEST_NARGS, )() == 100);
        assert_se(VA_NARGS_TOKEN(MACRO_TEST_NARGS,0)() == 101);
        assert_se(VA_NARGS_TOKEN(MACRO_TEST_NARGS,1)() == 101);
        assert_se(VA_NARGS_TOKEN(MACRO_TEST_NARGS, 0)() == 101);
        assert_se(VA_NARGS_TOKEN(MACRO_TEST_NARGS, 1)() == 101);
        assert_se(VA_NARGS_TOKEN(MACRO_TEST_NARGS, 1,2,3)() == 101);
        assert_se(VA_NARGS_TOKEN(MACRO_TEST_NARGS, TEST_VA_NARGS_MAX_LESS_1)() == 101);
        assert_se(VA_NARGS_TOKEN(MACRO_TEST_NARGS, TEST_VA_NARGS_MAX_LESS_1,1)() == 101);
        assert_se(VA_NARGS_TOKEN(MACRO_TEST_NARGS, TEST_VA_NARGS_MAX_LESS_1,1,2)() == 102);
        assert_se(VA_NARGS_TOKEN(MACRO_TEST_NARGS, TEST_VA_NARGS_MAX_LESS_1,1,2,3)() == 102);
        assert_se(VA_NARGS_TOKEN(MACRO_TEST_NARGS, TEST_VA_NARGS_MAX_LESS_1,TEST_VA_NARGS_MAX_LESS_1)() == 102);
}

#define TEST_FILTER(expected, filtered) assert_se(streq(expected, STRINGIFY(filtered)))

TEST(va_filter) {
        TEST_FILTER("0, 1, 2, 3, hi, later", VA_FILTER(0, 1, 2, 3, , , , hi, later, ));
        TEST_FILTER("", VA_FILTER(, , , , ,));
        TEST_FILTER("5", VA_FILTER(, , , , ,5));
        TEST_FILTER("4, 5", VA_FILTER(4, , , , ,5));
        TEST_FILTER("6, 7", VA_FILTER(, 6, 7, , ,));
        TEST_FILTER("\"one\", \"two\"", VA_FILTER(, "one", ,"two" , ,));
}

#define TEST_NARGS(expect, expect_token, ...)                           \
        ({                                                              \
                assert_se(VA_NARGS(__VA_ARGS__) == expect);             \
                assert_se(streq(STRINGIFY(expect_token), STRINGIFY(VA_NARGS(__VA_ARGS__)))); \
                assert_se(__builtin_constant_p(VA_NARGS(__VA_ARGS__))); \
        })

TEST(va_nargs) {
        _unused_ int i = 0;
        _unused_ const char *hi = "hello";

        TEST_NARGS(0, 0x0000);
        TEST_NARGS(0, 0x0000,);
        TEST_NARGS(0, 0x0000, );
        TEST_NARGS(1, 0x0001, 1);
        TEST_NARGS(1, 0x0001, "hello");
        TEST_NARGS(1, 0x0001, "hello");
        TEST_NARGS(1, 0x0001, i);
        TEST_NARGS(1, 0x0001, i++);
        TEST_NARGS(2, 0x0002, i, hi);
        TEST_NARGS(16, 0x0010, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

        TEST_NARGS(0x7f, 0x007f,
                   00,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                   10,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                   20,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                   30,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                   40,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                   50,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                   60,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                   70,1,2,3,4,5,6,7,8,9,a,b,c,d,e);
        TEST_NARGS(0x1fe, 0x01fe, TEST_VA_NARGS_MAX_LESS_1);
        TEST_NARGS(0x1ff, 0x01ff, TEST_VA_NARGS_MAX_LESS_1, 1);
}

TEST(va_last) {
        _unused_ int i = 0;
        _unused_ const char *hi = "hello";

        assert_se(streq(STRINGIFY(VA_LAST()), ""));
        assert_se(VA_LAST(1,2,10) == 10);
        assert_se(streq(VA_LAST("hi", "there"), "there"));
        assert_se(VA_LAST(1,2,i++) == 0);
        assert_se(i == 1);
        assert_se(VA_LAST(1,2,++i) == 2);
        assert_se(i == 2);
        assert_se(VA_LAST(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15) == 15);

        assert_se(VA_LAST(00,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                          10,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                          20,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                          30,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                          40,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                          50,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                          60,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                          70,1,2,3,4,5,6,7,8,9,a,b,c,123) == 123);
        assert_se(VA_LAST(00,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                          10,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                          20,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                          30,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                          40,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                          50,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                          60,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                          70,1,2,3,4,5,6,7,8,9,a,b,c,d,111) == 111);
        assert_se(VA_LAST(TEST_VA_NARGS_MAX_LESS_1, 321) == 321);
}

TEST(va_declarations) {
        int i = 999;
        VA_DECLARATIONS(test_decl, int, char*, uint64_t, typeof(i));

        test_decl_0x0001 = 10;
        test_decl_0x0002 = (char*)"hello";
        test_decl_0x0003 = 0xffff000000000001;
        test_decl_0x0004 = 8;
        assert_se(test_decl_0x0001 == 10);
        assert_se(__builtin_types_compatible_p(typeof(test_decl_0x0001), int));
        assert_se(streq(test_decl_0x0002, "hello"));
        assert_se(__builtin_types_compatible_p(typeof(test_decl_0x0002), char*));
        assert_se(test_decl_0x0003 == 0xffff000000000001);
        assert_se(__builtin_types_compatible_p(typeof(test_decl_0x0003), uint64_t));
        assert_se(test_decl_0x0004 == 8);
        assert_se(__builtin_types_compatible_p(typeof(test_decl_0x0004), int));

        VA_DECLARATIONS();

        VA_INITIALIZED_DECLARATIONS(test_i, test_decl_0x0003, test_decl_0x0004, i, test_decl_0x0002, test_decl_0x0001, i);

        assert_se(__builtin_types_compatible_p(typeof(test_i_0x0001), uint64_t));
        assert_se(test_i_0x0001 == 0xffff000000000001);
        test_i_0x0001--;
        assert_se(test_i_0x0001 == 0xffff000000000000);
        assert_se(test_decl_0x0003 == 0xffff000000000001);
        test_decl_0x0003 = 0xffff;
        assert_se(test_i_0x0001 == 0xffff000000000000);

        assert_se(__builtin_types_compatible_p(typeof(test_i_0x0002), int));
        assert_se(test_i_0x0002 == 8);
        test_i_0x0002--;
        assert_se(test_i_0x0002 == 7);
        assert_se(test_decl_0x0004 == 8);
        test_decl_0x0004 = 50;
        assert_se(test_i_0x0002 == 7);

        assert_se(__builtin_types_compatible_p(typeof(test_i_0x0003), int));
        assert_se(test_i_0x0003 == 999);
        test_i_0x0003--;
        assert_se(test_i_0x0003 == 998);
        assert_se(i == 999);
        i = 333;
        assert_se(test_i_0x0003 == 998);

        assert_se(__builtin_types_compatible_p(typeof(test_i_0x0004), char*));
        assert_se(streq(test_i_0x0004, "hello"));
        assert_se(streq(test_i_0x0004, test_decl_0x0002));
        test_i_0x0004 = NULL;
        assert_se(test_i_0x0004 == NULL);
        assert_se(streq(test_decl_0x0002, "hello"));

        assert_se(__builtin_types_compatible_p(typeof(test_i_0x0005), int));
        assert_se(test_i_0x0005 == 10);
        test_i_0x0005--;
        assert_se(test_i_0x0005 == 9);
        assert_se(test_decl_0x0001 == 10);
        test_decl_0x0001 = 44;
        assert_se(test_i_0x0005 == 9);

        assert_se(__builtin_types_compatible_p(typeof(test_i_0x0006), int));
        assert_se(test_i_0x0006 == 999);
        test_i_0x0006--;
        assert_se(test_i_0x0006 == 998);
        assert_se(i == 333);
        i = 222;
        assert_se(test_i_0x0006 == 998);

        VA_INITIALIZED_DECLARATIONS();
}

#define TEST_TOKENS(equal1, equal2, equal3, equal4,                     \
                    expect1, expect2, expect3, expect4,                 \
                    v1, v2, v3, v4)                                     \
        ({                                                              \
                assert_se((expect1 == v1) == equal1);                   \
                assert_se((expect2 == v2) == equal2);                   \
                assert_se((expect3 == v3) == equal3);                   \
                assert_se((expect4 == v4) == equal4);                   \
        })

TEST(va_tokens) {
        int i1 = 10, i2 = 100, i3 = 50, i4 = 99;

        VA_INITIALIZED_DECLARATIONS(test_i_, i1, i2, i3, i4);

        VA_MACRO(TEST_TOKENS, true, true, true, true, i1, i2, i3, i4, VA_TOKENS(test_i_, i1, i2, i3, i4));
        VA_MACRO(TEST_TOKENS, true, true, true, true, 10, 100, i3, 99, VA_TOKENS(test_i_, i1, i2, i3, i4));

        /* VA_TOKENS() doesn't actually use the variadic args, the tokens are based on index */
        VA_MACRO(TEST_TOKENS, true, true, true, true, i1, i2, i3, i4, VA_TOKENS(test_i_, x, x, x, x));

        VA_MACRO(TEST_TOKENS, true, false, true, false, i1, i4, i3, 1234, VA_TOKENS(test_i_, i1, i2, i3, i4));
}

#define TEST_UNIQ(x, y, z)                      \
        _unused_ int x = 10;                    \
        _unused_ const char *y = "hi";          \
        _unused_ uint64_t z = 0xffff;

TEST(va_uniq) {
        int x = 20;
        const char *y = "still me";
        uint64_t z = 0xf;

        VA_MACRO(TEST_UNIQ, VA_UNIQ(first, second, third));

        assert_se(x == 20);
        assert_se(streq(y, "still me"));
        assert_se(z == 0xf);
}

#define TEST_MACRO_SWAP(tmp, x, y)              \
        ({                                      \
                tmp = x;                        \
                x = y;                          \
                y = tmp;                        \
        })

#define TEST_MACRO_ALL(u1, u2, v1, v2, vi1, vi2, vc1, vc2, d1, d2)      \
        ({                                                              \
                int u1 = 100;                                           \
                char *u2 = (char*)"u2";                                 \
                assert_se(u1 == 100);                                   \
                assert_se(streq(u2, "u2"));                             \
                                                                        \
                v1 = d1;                                                \
                v2 = d2;                                                \
                assert_se(v1 == 30);                                    \
                assert_se(streq(v2, "d2"));                             \
                v1++;                                                   \
                v2++;                                                   \
                assert_se(v1 == 31);                                    \
                assert_se(streq(v2, "2"));                              \
                                                                        \
                assert_se(vi1 == 10);                                   \
                assert_se(streq(vi2, "vi2"));                           \
                vi1++;                                                  \
                vi2++;                                                  \
                assert_se(vi1 == 11);                                   \
                assert_se(streq(vi2, "i2"));                            \
                                                                        \
                assert_se(vc1 == 20);                                   \
                assert_se(streq(vc2, "vc2"));                           \
                                                                        \
                assert_se(d1 == 30);                                    \
                assert_se(streq(d2, "d2"));                             \
                                                                        \
                d1 = u1;                                                \
                d2 = u2;                                                \
                assert_se(d1 == 100);                                   \
                assert_se(streq(d2, "u2"));                             \
                                                                        \
                d1 + 1000;                                              \
        })

TEST(va_macro_helper) {
        int i1, i2;

        i1 = 10;
        i2 = 20;
        VA_MACRO_HELPER(TEST_MACRO_SWAP,
                        /*uniq*/,
                        int,
                        /*varinit*/,
                        /*varconst*/,
                        VA_GROUP(i1, i2));
        assert_se(i1 == 20);
        assert_se(i2 == 10);

        int vi1 = 10, vc1 = 20, d1 = 30;
        char *vi2 = (char*)"vi2", *vc2 = (char*)"vc2", *d2 = (char*)"d2";
        int all = VA_MACRO_HELPER(TEST_MACRO_ALL,
                                  VA_GROUP(u1, u2),
                                  VA_GROUP(int, char*),
                                  VA_GROUP(vi1, vi2),
                                  VA_GROUP(vc1, vc2),
                                  VA_GROUP(d1, d2));
        assert_se(all == 1100);
        assert_se(vi1 == 10);
        assert_se(streq(vi2, "vi2"));
        assert_se(vc1 == 20);
        assert_se(streq(vc2, "vc2"));
        assert_se(d1 == 100);
        assert_se(streq(d2, "u2"));
}

#define TEST_UNIQ_INT_X(_x)                     \
        ({                                      \
                int _x = 5;                     \
                _x++;                           \
        })

#define TEST_UNIQ_INT_X_Y_Z(x, y, z, v, ...)            \
        ({                                              \
                int x = v;                              \
                int y = VA_IF_ELSE(VA_FIRST(__VA_ARGS__), 100, __VA_ARGS__); \
                int z = VA_IF_ELSE(VA_FIRST(VA_REST(__VA_ARGS__)), 2000, VA_REST(__VA_ARGS__)); \
                x + y + z;                              \
        })

TEST(va_macro_uniq) {
        int x = 1, _x = 2;

        int y = VA_MACRO_UNIQ(TEST_UNIQ_INT_X, _x);
        assert_se(x == 1);
        assert_se(_x == 2);
        assert_se(y == 5);

        int z = VA_MACRO_UNIQ(TEST_UNIQ_INT_X_Y_Z, VA_GROUP(x, y, z), x);
        assert_se(x == 1);
        assert_se(_x == 2);
        assert_se(y == 5);
        assert_se(z == 2101);

        _x = VA_MACRO_UNIQ(TEST_UNIQ_INT_X_Y_Z, VA_GROUP(1, 2, z), 99);
        assert_se(x == 1);
        assert_se(_x == 2199);
        assert_se(y == 5);
        assert_se(z == 2101);

        z = VA_MACRO_UNIQ(TEST_UNIQ_INT_X_Y_Z, VA_GROUP(_X, _Y, _Z), 5, 20);
        assert_se(x == 1);
        assert_se(_x == 2199);
        assert_se(y == 5);
        assert_se(z == 2025);

        z = VA_MACRO_UNIQ(TEST_UNIQ_INT_X_Y_Z, VA_GROUP(_X, _Y, _Z), 7, 70, 5000);
        assert_se(x == 1);
        assert_se(_x == 2199);
        assert_se(y == 5);
        assert_se(z == 5077);
}

#define TEST_MACRO_INT_CHARP(x1, x2)                                    \
        ({                                                              \
                assert_se(__builtin_types_compatible_p(typeof(x1), int)); \
                assert_se(__builtin_types_compatible_p(typeof(x2), char*)); \
        })

typedef struct { int a; } structabc;

#define TEST_MACRO_INTP_STRUCTABC_INT(x1, x2, x3)                       \
        ({                                                              \
                assert_se(__builtin_types_compatible_p(typeof(x1), int*)); \
                assert_se(__builtin_types_compatible_p(typeof(x2), structabc)); \
                assert_se(__builtin_types_compatible_p(typeof(x3), int)); \
        })

#define TEST_MACRO_INT_TMP1(x)                  \
        ({                                      \
                x = 7;                          \
                x++;                            \
        })

TEST(va_macro_var) {
        int j = VA_MACRO_VAR(TEST_MACRO_INT_TMP1, int);
        assert_se(j == 7);

        assert_se(VA_MACRO_VAR(TEST_MACRO_INT_TMP1, int) == 7);

        VA_MACRO_VAR(TEST_MACRO_INT_CHARP, VA_GROUP(int, char*));
        VA_MACRO_VAR(TEST_MACRO_INTP_STRUCTABC_INT, VA_GROUP(int*, structabc, int));
}

#define MACROx7f(x01,x02,x03,x04,x05,x06,x07,x08,x09,x0a,x0b,x0c,x0d,x0e,x0f,x10, \
                 x11,x12,x13,x14,x15,x16,x17,x18,x19,x1a,x1b,x1c,x1d,x1e,x1f,x20, \
                 x21,x22,x23,x24,x25,x26,x27,x28,x29,x2a,x2b,x2c,x2d,x2e,x2f,x30, \
                 x31,x32,x33,x34,x35,x36,x37,x38,x39,x3a,x3b,x3c,x3d,x3e,x3f,x40, \
                 x41,x42,x43,x44,x45,x46,x47,x48,x49,x4a,x4b,x4c,x4d,x4e,x4f,x50, \
                 x51,x52,x53,x54,x55,x56,x57,x58,x59,x5a,x5b,x5c,x5d,x5e,x5f,x60, \
                 x61,x62,x63,x64,x65,x66,x67,x68,x69,x6a,x6b,x6c,x6d,x6e,x6f,x70, \
                 x71,x72,x73,x74,x75,x76,x77,x78,x79,x7a,x7b,x7c,x7d,x7e,x7f) x7f

#define MACRO_USE_TWICE_1L2_OR_B0(x1, x2)               \
        ({                                              \
                (x1 < x2) || (x1 == 0 && x2 == 0);      \
        })

TEST(va_macro_varinit) {
        _unused_ int i = 1, j = 0;
        _unused_ const char *hi = "hello";

        assert_se(VA_MACRO_VARINIT(MACRO1, 1) == 1);
        assert_se(VA_MACRO_VARINIT(MACRO2, VA_GROUP(1, 10)) == 10);
        assert_se(VA_MACRO_VARINIT(MACRO1, VA_GROUP(100, "hi", 1, 0, "there")) == 100);
        assert_se(VA_MACRO_VARINIT(MACRO1, hi) == hi);
        assert_se(VA_MACRO_VARINIT(MACRO1, VA_GROUP(hi, i, 1,2,3,4,hi)) == hi);
        assert_se(VA_MACRO_VARINIT(MACRO2, VA_GROUP(hi, i, 1,2,3,4,hi)) == i);
        assert_se(VA_MACRO_VARINIT(MACRO2, VA_GROUP(hi,  1,2,3,4,hi)) == 1);
        assert_se(VA_MACRO_VARINIT(MACRO_SUM12, VA_GROUP(1,10)) == 11);
        assert_se(VA_MACRO_VARINIT(MACRO_SUM12, VA_GROUP(10,1,i,hi)) == 11);

        i = 1234;
        assert_se(VA_MACRO_VARINIT(MACRO1, i) == 1234);
        assert_se(VA_MACRO_VARINIT(MACRO1, 1234) == i);

        i = 10;
        j = 20;
        assert_se(VA_MACRO_VARINIT(MACRO_USE_TWICE_1L2_OR_B0, VA_GROUP(i++, j--)) == 1);
        assert_se(i == 11);
        assert_se(j == 19);

        assert_se(VA_MACRO_VARINIT(MACRO_USE_TWICE_1L2_OR_B0, VA_GROUP(j + 5, j + 10)) == 1);
        assert_se(i == 11);
        assert_se(j == 19);

        i = 10;
        j = 0;
        assert_se(VA_MACRO_VARINIT(MACRO_USE_TWICE_1L2_OR_B0, VA_GROUP(i - 10, j)) == 1);
        assert_se(i == 10);
        assert_se(j == 0);

        assert_se(VA_MACRO_VARINIT(MACRO_USE_TWICE_1L2_OR_B0, VA_GROUP(i, j--)) == 0);
        assert_se(i == 10);
        assert_se(j == -1);

        uint64_t A=0xffffffffffffffff,B=4,C=4,D=4,E=4,F=4,G=4,H=4,I=4,J=4,K=4,L=4,M=4,N=4,O=5;
        assert_se(VA_MACRO_VARINIT(MACRO2,
                                   VA_GROUP(0,A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,
                                            1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
                                            2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
                                            3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,
                                            4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,
                                            5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
                                            6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
                                            7,7,7,7,7,7,7,7,7,7,7,7,7,7)) == 0xffffffffffffffff);

        struct { int a; float b; } last = { .a = 10, .b = 1.1, };
        assert_se(VA_MACRO_VARINIT(MACROx7f,
                                   VA_GROUP(0,A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,
                                            1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
                                            2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
                                            3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,
                                            4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,
                                            5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
                                            6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
                                            7,7,7,7,7,7,7,7,7,7,7,7,7,7,&last)) == &last);
}

TEST(va_macro_varconst) {
        _unused_ int i = 1, j = 0;
        _unused_ const char *hi = "hello";

        assert_se(VA_MACRO_VARCONST(MACRO1, 1) == 1);
        assert_se(VA_MACRO_VARCONST(MACRO2, VA_GROUP(1, 10)) == 10);
        assert_se(VA_MACRO_VARCONST(MACRO1, VA_GROUP(100, "hi", 1, 0, "there")) == 100);
        assert_se(VA_MACRO_VARCONST(MACRO1, hi) == hi);
        assert_se(VA_MACRO_VARCONST(MACRO1, VA_GROUP(hi, i, 1,2,3,4,hi)) == hi);
        assert_se(VA_MACRO_VARCONST(MACRO2, VA_GROUP(hi, i, 1,2,3,4,hi)) == i);
        assert_se(VA_MACRO_VARCONST(MACRO2, VA_GROUP(hi,  1,2,3,4,hi)) == 1);
        assert_se(VA_MACRO_VARCONST(MACRO_SUM12, VA_GROUP(1,10)) == 11);
        assert_se(VA_MACRO_VARCONST(MACRO_SUM12, VA_GROUP(10,1,i,hi)) == 11);

        i = 1234;
        assert_se(VA_MACRO_VARCONST(MACRO1, i) == 1234);
        assert_se(VA_MACRO_VARCONST(MACRO1, 1234) == i);
}

TEST(va_number) {
        assert_se(___VAN4(4,3,2,1) == 0x4321);
        assert_se(___VAN4(f,f,f,f) == 0xffff);
        assert_se(___VAN4(0,0,0,0) == 0);
        assert_se(___VAN4(0,0,0,1) == 1);
        assert_se(___VAN4(0,1,0,0) == 0x100);
        assert_se(___VAN4(1,0,0,1) == 0x1001);
        assert_se(__VAN4((1,0,0,1)) == 0x1001);
}

TEST(va_inc) {
        assert_se(__VAN4(__VAINC((1,2,3,4))) == 0x1235);
        assert_se(__VAN4(__VAINC((0,0,0,0))) == 1);
        assert_se(__VAN4(__VAINC((0,0,0,1))) == 2);
        assert_se(__VAN4(__VAINC((1,0,0,0))) == 0x1001);
        assert_se(__VAN4(__VAINC((f,f,f,e))) == 0xffff);
        assert_se(__VAN4(__VAINC((e,f,f,e))) == 0xefff);
        assert_se(__VAN4(__VAINC((e,f,e,f))) == 0xeff0);
        assert_se(__VAN4(__VAINC((d,f,f,f))) == 0xe000);
}

DEFINE_TEST_MAIN(LOG_INFO);
