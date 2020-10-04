/* Limit the number of expressions to 6 for performance reasons */
@@
expression e;
/* Exclude JsonVariant * from the transformation, as it can't work with the
 * current version of the IN_SET macro */
typedef JsonVariant;
type T != JsonVariant*;
constant T n0, n1, n2, n3, n4, n5;
@@
(
- e == n0 || e == n1 || e == n2 || e == n3 || e == n4 || e == n5
+ IN_SET(e, n0, n1, n2, n3, n4, n5)
|
- e == n0 || e == n1 || e == n2 || e == n3 || e == n4
+ IN_SET(e, n0, n1, n2, n3, n4)
|
- e == n0 || e == n1 || e == n2 || e == n3
+ IN_SET(e, n0, n1, n2, n3)
|
- e == n0 || e == n1 || e == n2
+ IN_SET(e, n0, n1, n2)
|
- e == n0 || e == n1
+ IN_SET(e, n0, n1)
)
