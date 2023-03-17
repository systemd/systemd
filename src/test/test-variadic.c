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

#define TEST_UNPAREN(macro, group)              \
        macro(VA_UNPAREN(group))

TEST(va_unparen) {
        assert_se(TEST_UNPAREN(MACRO_GROUP_VARG_4, (1,2,3,4)) == 4);
        assert_se(TEST_UNPAREN(MACRO_GROUP_VARG_1, (5,10,20)) == 5);
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

TEST(va_not) {
        assert_se(VA_NOT(123,) == 123);
        assert_se(VA_NOT(1+,1) 0 == 0);
        assert_se(VA_NOT(1+,0) 0 == 0);
        assert_se(VA_NOT(1+,) 0 == 1);
        assert_se(VA_NOT(1+,  )0 == 1);
        assert_se(VA_NOT(1+, VA_NOT(2+, VA_NOT(3+, 4))) 0 == 0);
        assert_se(VA_NOT(1+, VA_NOT(2+, VA_NOT(3+, ))) 0 == 1);
        assert_se(VA_NOT(1+, VA_NOT(, VA_NOT(3+, 4))) 0 == 1);
        assert_se(!streq(VA_NOT("hi", 1) "", "hi"));
        assert_se(streq(VA_NOT("hi", NONE) "", "hi"));
}

#define V1() 1
#define V2() 2

#define VI6E7(x) VA_IF_ELSE(6, 7, x)
#define VI8E9(x) VA_IF_ELSE(8, 9, x)

TEST(va_if_else) {
        assert_se(VA_IF_ELSE(1, 2, ) == 2);
        assert_se(VA_IF_ELSE(1, 2,NONE ) == 2);
        assert_se(VA_IF_ELSE(1, 2, 1) == 1);
        assert_se(VA_IF_ELSE(1, 2,  "no") == 1);
        assert_se(VA_IF_ELSE(1, 2, VA_IF(1, )) == 2);
        assert_se(VA_IF_ELSE(1, 2, VA_IF(1, 1) ) == 1);
        assert_se(VA_IF_ELSE(1, 2, VA_NOT(1, )) == 1);
        assert_se(VA_IF_ELSE(1, 2, VA_NOT(1, 2)) == 2);
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

TEST(va_comma) {
        assert_se(streq("0 , 1, 2", STRINGIFY(0 VA_COMMA(0) 1, 2)));
        assert_se(streq("0 , 1, 2", STRINGIFY(0 VA_COMMA(1) 1, 2)));
        assert_se(streq("0 1, 2", STRINGIFY(0 VA_COMMA() 1, 2)));
}

TEST(va_empty) {
        assert_se(VA_EMPTY());
        assert_se(VA_EMPTY( ));
        assert_se(VA_EMPTY(     ));
        assert_se(!VA_EMPTY(0));
        assert_se(!VA_EMPTY(1));
        assert_se(!VA_EMPTY("hi"));
        assert_se(VA_EMPTY(NONE));
        assert_se(VA_EMPTY(  NONE  ));
        assert_se(VA_EMPTY(MACRO_NONE()));
        assert_se(VA_EMPTY(  MACRO_NONE()  ));
        assert_se(!VA_EMPTY( NONE, NONE ));
        assert_se(VA_EMPTY( NONE VA_COMMA(NONE) NONE ));
}

TEST(va_first) {
        assert_se(VA_FIRST(1,2,3) == 1);
        assert_se(VA_FIRST(1+,2+) 0 == 1);
        assert_se(VA_FIRST(1+) 0 == 1);
        assert_se(VA_FIRST() 0 == 0);
}

TEST(va_rest) {
        assert_se(VA_REST(1,3) == 3);
        assert_se(VA_REST(1+,2+) 0 == 2);
        assert_se(VA_REST(1+) 0 == 0);
        assert_se(VA_REST() 0 == 0);

        assert_se(VA_FIRST(VA_REST(1,2,3,4,5)) == 2);

        int ia[] = { VA_REST(1,2,3,4,5) };
        assert_se(ELEMENTSOF(ia) == 4);
        assert_se(ia[0] == 2);
        assert_se(ia[1] == 3);
        assert_se(ia[2] == 4);
        assert_se(ia[3] == 5);
}

TEST(va_macro) {
        assert_se(VA_MACRO(MACRO1, 3,2,1) == 3);
        assert_se(VA_MACRO(MACRO1, 4) == 4);
        assert_se(VA_MACRO(MACRO2, 4,5) == 5);
        assert_se(streq(VA_MACRO(MACRO2, 4,"hi"), "hi"));
}

TEST(va_nargs_toomany) {
        assert_se(VA_NARGS_TOOMANY(1+,
                                   0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                   0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                   0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                   0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                   0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                   0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                   0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                   0,1,2,3,4,5,6,7,8,9,a,b,c,d,e) 0 == 0);
        assert_se(VA_NARGS_TOOMANY(1+,
                                   0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                   0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                   0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                   0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                   0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                   0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                   0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                   0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f) 0 == 1);
        assert_se(VA_NARGS_TOOMANY(1+,
                                   0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                   0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                   0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                   0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                   0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                   0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                   0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                   0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,g) 0 == 1);
}

#define MACRO_TEST_NARGS_ZERO() 100
#define MACRO_TEST_NARGS_ARGS() 101
#define MACRO_TEST_NARGS_TOOMANY() 102

TEST(va_nargs_token) {
        assert_se(VA_NARGS_TOKEN(MACRO_TEST_NARGS)() == 100);
        assert_se(VA_NARGS_TOKEN(MACRO_TEST_NARGS,
                                 0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                 0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                 0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                 0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                 0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                 0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                 0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                 0,1,2,3,4,5,6,7,8,9,a,b,c,d,e)() == 101);
        assert_se(VA_NARGS_TOKEN(MACRO_TEST_NARGS,
                                 0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                 0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                 0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                 0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                 0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                 0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                 0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                 0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f)() == 102);
        assert_se(VA_NARGS_TOKEN(MACRO_TEST_NARGS,
                                 0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                 0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                 0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                 0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                 0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                 0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                 0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                                 0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,g)() == 102);
}

#define TEST_FILTER(expected, filtered) assert_se(streq(expected, STRINGIFY(filtered)))

TEST(va_filter) {
        TEST_FILTER("0, 1, 2, 3, hi, later", VA_FILTER(0, 1, 2, 3, , , , hi, later, ));
        TEST_FILTER("", VA_FILTER(, , , , ,));
        TEST_FILTER("5", VA_FILTER(, , , , ,5));
        TEST_FILTER("4, 5", VA_FILTER(4, , , , ,5));
        TEST_FILTER("6, 7", VA_FILTER(, 6, 7, , ,));
        TEST_FILTER("\"one\", \"two\"", VA_FILTER(, "one", ,"two" , ,));

        TEST_FILTER("1, 2, 3, \"hi\", one, 7", VA_FILTER_GROUPS4(VA_GROUP(1, 2, 3), VA_GROUP("hi", one), VA_GROUP(), 7));
        TEST_FILTER("", VA_FILTER_GROUPS4(VA_GROUP(), VA_GROUP(), VA_GROUP(      ), VA_GROUP( )));

        TEST_FILTER("", VA_FILTER_GROUPS4(, , , ));
        TEST_FILTER("z", VA_FILTER_GROUPS4(, , z , ));
        TEST_FILTER("x, y", VA_FILTER_GROUPS4(x,,,y));
}

#define TEST_ARGS_CONSTANT(expect, ...)                                 \
        ({                                                              \
                assert_se(VA_ARGS_CONSTANT(__VA_ARGS__) == expect);     \
                assert_se(__builtin_constant_p(VA_ARGS_CONSTANT(__VA_ARGS__))); \
        })

TEST(va_args_constant) {
        _unused_ int i = 0;
        _unused_ const char *hi = "hello";

        TEST_ARGS_CONSTANT(true);
        TEST_ARGS_CONSTANT(true, 1,2,3,4);
        TEST_ARGS_CONSTANT(true, "hi", "there", 5, 6);
        TEST_ARGS_CONSTANT(false, hi);
        TEST_ARGS_CONSTANT(false, i);
        TEST_ARGS_CONSTANT(false, 1, 0, i);
        TEST_ARGS_CONSTANT(false, 1, i, hi);

        TEST_ARGS_CONSTANT(true, , 1, 2, , 3);
        TEST_ARGS_CONSTANT(false, 1, , 2, 3, i);
        TEST_ARGS_CONSTANT(true, "hi",,, 0, "one", NULL, , );

        TEST_ARGS_CONSTANT(true,
                    0,1,2,3,4,5,6,7,8,9,0xa,0xb,0xc,0xd,0xe,0xf,
                   10,1,2,3,4,5,6,7,8,9,0xa,0xb,0xc,0xd,0xe,0xf,
                   20,1,2,3,4,5,6,7,8,9,0xa,0xb,0xc,0xd,0xe,0xf,
                   30,1,2,3,4,5,6,7,8,9,0xa,0xb,0xc,0xd,0xe,0xf,
                   40,1,2,3,4,5,6,7,8,9,0xa,0xb,0xc,0xd,0xe,0xf,
                   50,1,2,3,4,5,6,7,8,9,0xa,0xb,0xc,0xd,0xe,0xf,
                   60,1,2,3,4,5,6,7,8,9,0xa,0xb,0xc,0xd,0xe,0xf,
                   70,1,2,3,4,5,6,7,8,9,0xa,0xb,0xc,0xd,0xe);
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

        TEST_NARGS(0, 0x00);
        TEST_NARGS(1, 0x01, 1);
        TEST_NARGS(1, 0x01, "hello");
        TEST_NARGS(1, 0x01, "hello");
        TEST_NARGS(1, 0x01, i);
        TEST_NARGS(1, 0x01, i++);
        TEST_NARGS(2, 0x02, i, hi);
        TEST_NARGS(16, 0x10, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

        TEST_NARGS(0x7e, 0x7e,
                   00,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                   10,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                   20,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                   30,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                   40,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                   50,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                   60,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                   70,1,2,3,4,5,6,7,8,9,a,b,c,d);
        TEST_NARGS(0x7f, 0x7f,
                   00,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                   10,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                   20,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                   30,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                   40,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                   50,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                   60,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                   70,1,2,3,4,5,6,7,8,9,a,b,c,d,e);

        /* This will cause a compiler assertion failure if you uncomment it: */
        /*
        TEST_NARGS(0x80, 0x80,
                   00,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                   10,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                   20,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                   30,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                   40,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                   50,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                   60,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,
                   70,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f);
        */
}

TEST(va_declarations) {
        int i = 999;
        VA_DECLARATIONS(test_decl, int, char*, uint64_t, typeof(i));

        test_decl_0x01 = 10;
        test_decl_0x02 = (char*)"hello";
        test_decl_0x03 = 0xffff000000000001;
        test_decl_0x04 = 8;
        assert_se(test_decl_0x01 == 10);
        assert_se(__builtin_types_compatible_p(typeof(test_decl_0x01), int));
        assert_se(streq(test_decl_0x02, "hello"));
        assert_se(__builtin_types_compatible_p(typeof(test_decl_0x02), char*));
        assert_se(test_decl_0x03 == 0xffff000000000001);
        assert_se(__builtin_types_compatible_p(typeof(test_decl_0x03), uint64_t));
        assert_se(test_decl_0x04 == 8);
        assert_se(__builtin_types_compatible_p(typeof(test_decl_0x04), int));

        VA_DECLARATIONS();

        VA_INITIALIZED_DECLARATIONS(test_i, test_decl_0x03, test_decl_0x04, i, test_decl_0x02, test_decl_0x01, i);

        assert_se(__builtin_types_compatible_p(typeof(test_i_0x01), uint64_t));
        assert_se(test_i_0x01 == 0xffff000000000001);
        test_i_0x01--;
        assert_se(test_i_0x01 == 0xffff000000000000);
        assert_se(test_decl_0x03 == 0xffff000000000001);
        test_decl_0x03 = 0xffff;
        assert_se(test_i_0x01 == 0xffff000000000000);

        assert_se(__builtin_types_compatible_p(typeof(test_i_0x02), int));
        assert_se(test_i_0x02 == 8);
        test_i_0x02--;
        assert_se(test_i_0x02 == 7);
        assert_se(test_decl_0x04 == 8);
        test_decl_0x04 = 50;
        assert_se(test_i_0x02 == 7);

        assert_se(__builtin_types_compatible_p(typeof(test_i_0x03), int));
        assert_se(test_i_0x03 == 999);
        test_i_0x03--;
        assert_se(test_i_0x03 == 998);
        assert_se(i == 999);
        i = 333;
        assert_se(test_i_0x03 == 998);

        assert_se(__builtin_types_compatible_p(typeof(test_i_0x04), char*));
        assert_se(streq(test_i_0x04, "hello"));
        assert_se(streq(test_i_0x04, test_decl_0x02));
        test_i_0x04 = NULL;
        assert_se(test_i_0x04 == NULL);
        assert_se(streq(test_decl_0x02, "hello"));

        assert_se(__builtin_types_compatible_p(typeof(test_i_0x05), int));
        assert_se(test_i_0x05 == 10);
        test_i_0x05--;
        assert_se(test_i_0x05 == 9);
        assert_se(test_decl_0x01 == 10);
        test_decl_0x01 = 44;
        assert_se(test_i_0x05 == 9);

        assert_se(__builtin_types_compatible_p(typeof(test_i_0x06), int));
        assert_se(test_i_0x06 == 999);
        test_i_0x06--;
        assert_se(test_i_0x06 == 998);
        assert_se(i == 333);
        i = 222;
        assert_se(test_i_0x06 == 998);

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


#define TEST_MACRO_SWAP(tmp, x, y)              \
        ({                                      \
                tmp = x;                        \
                x = y;                          \
                y = tmp;                        \
        })

#define TEST_MACRO_ALL(n1, n2, t1, t2, u1, u2, d1, d2)  \
        ({                                              \
                assert_se(d1 == 1);                     \
                assert_se(streq(d2, "d2"));             \
                                                        \
                assert_se(n1 == 11);                    \
                assert_se(streq(n2, "n2"));             \
                n1++;                                   \
                n2++;                                   \
                assert_se(n1 == 12);                    \
                assert_se(streq(n2, "2"));              \
                                                        \
                t1 = d1;                                \
                t2 = d2;                                \
                assert_se(t1 == 1);                     \
                assert_se(streq(t2, "d2"));             \
                t1++;                                   \
                t2++;                                   \
                assert_se(t1 == 2);                     \
                assert_se(streq(t2, "2"));              \
                                                        \
                int u1 = 1111;                          \
                char *u2 = (char*)"u2";                 \
                assert_se(u1 == 1111);                  \
                assert_se(streq(u2, "u2"));             \
                                                        \
                d1 = u1;                                \
                d2 = u2;                                \
                assert_se(d1 == 1111);                  \
                assert_se(streq(d2, "u2"));             \
                                                        \
                d1;                                     \
        })

TEST(va_macro_helper) {
        int i1, i2;

        i1 = 10;
        i2 = 20;
        VA_MACRO_HELPER(TEST_MACRO_SWAP, , int, , VA_GROUP(i1, i2));
        assert_se(i1 == 20);
        assert_se(i2 == 10);

        int d1 = 1, n1 = 11;
        char *d2 = (char*)"d2", *n2 = (char*)"n2";
        int all = VA_MACRO_HELPER(TEST_MACRO_ALL, VA_GROUP(n1, n2), VA_GROUP(int, char*), VA_GROUP(u1, u2), VA_GROUP(d1, d2));
        assert_se(all == 1111);
        assert_se(d1 == 1111);
        assert_se(streq(d2, "u2"));
        assert_se(n1 == 11);
        assert_se(streq(n2, "n2"));
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

#define MACROx7e(x01,x02,x03,x04,x05,x06,x07,x08,x09,x0a,x0b,x0c,x0d,x0e,x0f,x10, \
                 x11,x12,x13,x14,x15,x16,x17,x18,x19,x1a,x1b,x1c,x1d,x1e,x1f,x20, \
                 x21,x22,x23,x24,x25,x26,x27,x28,x29,x2a,x2b,x2c,x2d,x2e,x2f,x30, \
                 x31,x32,x33,x34,x35,x36,x37,x38,x39,x3a,x3b,x3c,x3d,x3e,x3f,x40, \
                 x41,x42,x43,x44,x45,x46,x47,x48,x49,x4a,x4b,x4c,x4d,x4e,x4f,x50, \
                 x51,x52,x53,x54,x55,x56,x57,x58,x59,x5a,x5b,x5c,x5d,x5e,x5f,x60, \
                 x61,x62,x63,x64,x65,x66,x67,x68,x69,x6a,x6b,x6c,x6d,x6e,x6f,x70, \
                 x71,x72,x73,x74,x75,x76,x77,x78,x79,x7a,x7b,x7c,x7d,x7e) x7e

#define MACRO_USE_TWICE(x1, x2)                         \
        ({                                              \
                (x1 < x2) || (x1 == 0 && x2 == 0);      \
        })

#define MACRO_C1_V2(x1, x2)                                     \
        ({                                                      \
                assert_se(__builtin_constant_p(x1) == 1);       \
                assert_se(__builtin_constant_p(x2) == 0);       \
                x1;                                             \
        })

#define MACRO_V1_C2(x1, x2)                                     \
        ({                                                      \
                assert_se(__builtin_constant_p(x1) == 0);       \
                assert_se(__builtin_constant_p(x2) == 1);       \
                x1;                                             \
        })

#define TEST_VA_MACRO_NOSE(expect, constant, macro, ...)                \
        ({                                                              \
                assert_se(VA_MACRO_NOSE(macro, VA_GROUP(__VA_ARGS__)) == expect); \
                assert_se((!!__builtin_constant_p(VA_MACRO_NOSE(macro, VA_GROUP(__VA_ARGS__)))) == constant); \
        })

TEST(va_macro_nose) {
        _unused_ int i = 1, j = 0;
        _unused_ const char *hi = "hello";

        TEST_VA_MACRO_NOSE(1, true, MACRO1, 1);
        TEST_VA_MACRO_NOSE(10, true, MACRO2, 1, 10);
        TEST_VA_MACRO_NOSE(100, true, MACRO1, 100, "hi", 1, 0, "there");
        TEST_VA_MACRO_NOSE(hi, false, MACRO1, hi);
        TEST_VA_MACRO_NOSE(hi, false, MACRO1, hi, i, 1,2,3,4,hi);
        TEST_VA_MACRO_NOSE(i, false, MACRO2, hi, i, 1,2,3,4,hi);
        TEST_VA_MACRO_NOSE(1, false, MACRO2, hi, 1,2,3,4,hi);
        TEST_VA_MACRO_NOSE(11, true, MACRO_SUM12, 1,10);
        TEST_VA_MACRO_NOSE(11, false, MACRO_SUM12, 10,1,i,hi);

        TEST_VA_MACRO_NOSE(5, false, MACRO_C1_V2, 5, i);
        TEST_VA_MACRO_NOSE(i, false, MACRO_V1_C2, i, 5);

        i = 1234;
        TEST_VA_MACRO_NOSE(1234, false, MACRO1, i);
        TEST_VA_MACRO_NOSE(i, true, MACRO1, 1234);

        i = 10;
        j = 20;
        TEST_VA_MACRO_NOSE(true, false, MACRO_USE_TWICE, i++, j--);
        assert_se(i == 11);
        assert_se(j == 19);

        TEST_VA_MACRO_NOSE(true, false, MACRO_USE_TWICE, j + 5, j + 10);
        assert_se(i == 11);
        assert_se(j == 19);

        i = 10;
        j = 0;
        TEST_VA_MACRO_NOSE(true, false, MACRO_USE_TWICE, i - 10, j);
        assert_se(i == 10);
        assert_se(j == 0);

        TEST_VA_MACRO_NOSE(false, false, MACRO_USE_TWICE, i, j--);
        assert_se(i == 10);
        assert_se(j == -1);

        uint64_t A=0xffffffffffffffff,B=4,C=4,D=4,E=4,F=4,G=4,H=4,I=4,J=4,K=4,L=4,M=4,N=4,O=5;
        TEST_VA_MACRO_NOSE(0xffffffffffffffff, false, MACRO2,
                           0,A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,
                           1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
                           2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
                           3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,
                           4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,
                           5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
                           6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
                           7,7,7,7,7,7,7,7,7,7,7,7,7,7);

        struct { int a; float b; } last = { .a = 10, .b = 1.1, };
        TEST_VA_MACRO_NOSE(&last, false, MACROx7e,
                           0,A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,
                           1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
                           2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
                           3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,
                           4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,
                           5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
                           6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
                           7,7,7,7,7,7,7,7,7,7,7,7,7,&last);
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

TEST(va_macro_tmp) {
        int j = VA_MACRO_TMP(TEST_MACRO_INT_TMP1, int);
        assert_se(j == 7);

        assert_se(VA_MACRO_TMP(TEST_MACRO_INT_TMP1, int) == 7);

        VA_MACRO_TMP(TEST_MACRO_INT_CHARP, VA_GROUP(int, char*));
        VA_MACRO_TMP(TEST_MACRO_INTP_STRUCTABC_INT, VA_GROUP(int*, structabc, int));
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

#define MACRO_UNUSED_1(x) ({ x; })
#define MACRO_ADD_TO(x, y) x += y
#define MACRO_SUB_FROM(x, y) x -= y
#define MACRO_ADD_TO_SUB_FROM(x1, x2, y) ({ MACRO_ADD_TO(x1, y); MACRO_SUB_FROM(x2, y); })

TEST(va_macro_foreach) {
        int x, y;

        x = VA_MACRO_FOREACH(MACRO_UNUSED_1, 1, 2, 3, 5, 10);
        assert_se(x == 10);

        x = 1;
        VA_MACRO_FOREACH_CONTEXT(MACRO_ADD_TO, x, 1, 2);
        assert_se(x == 4);

        x = 4;
        VA_MACRO_FOREACH_CONTEXT(MACRO_SUB_FROM, x, 4, 2);
        assert_se(x == -2);

        x = 10;
        y = 100;
        VA_MACRO_FOREACH_CONTEXT(MACRO_ADD_TO_SUB_FROM, VA_GROUP(x, y), 10, 50, 8, 0);
        assert_se(x == 78);
        assert_se(y == 32);
}

DEFINE_TEST_MAIN(LOG_INFO);
