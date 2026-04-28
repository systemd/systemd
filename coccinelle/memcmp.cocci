/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Disable this transformation for iovec-util.h and the unit test */
@ depends on !(file in "src/basic/iovec-util.h")
            && !(file in "src/test/test-iovec-util.c") @
expression a, b;
@@
(
- iovec_memcmp(a, b) == 0
+ iovec_equal(a, b)
|
- iovec_memcmp(a, b) != 0
+ !iovec_equal(a, b)
|
- ASSERT_EQ(iovec_memcmp(a, b), 0)
+ ASSERT_TRUE(iovec_equal(a, b))
|
- ASSERT_NE(iovec_memcmp(a, b), 0)
+ ASSERT_FALSE(iovec_equal(a, b))
)
