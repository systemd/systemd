/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Limit the number of expressions to 6 for performance reasons */

@ is_in_assert_cc @
identifier id = assert_cc;
position p1;
expression e;
constant n0;
@@

 id(e@p1 == n0 || ...);

@@
expression e;
position p2 != is_in_assert_cc.p1;
/* Exclude JsonVariant * from the transformation, as it can't work with the
 * current version of the IN_SET macro */
typedef JsonVariant;
type T != JsonVariant*;
constant T n0, n1, n2, n3, n4, n5;
@@

(
- e@p2 == n0 || e == n1 || e == n2 || e == n3 || e == n4 || e == n5
+ IN_SET(e, n0, n1, n2, n3, n4, n5)
|
- e@p2 == n0 || e == n1 || e == n2 || e == n3 || e == n4
+ IN_SET(e, n0, n1, n2, n3, n4)
|
- e@p2 == n0 || e == n1 || e == n2 || e == n3
+ IN_SET(e, n0, n1, n2, n3)
|
- e@p2 == n0 || e == n1 || e == n2
+ IN_SET(e, n0, n1, n2)
|
- e@p2 == n0 || e == n1
+ IN_SET(e, n0, n1)
)
