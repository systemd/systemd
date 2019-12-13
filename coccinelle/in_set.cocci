@@
expression e;
/* Exclude JsonVariant * from the transformation, as it can't work with the
 * current version of the IN_SET macro */
typedef JsonVariant;
type T != JsonVariant*;
constant T n0, n1, n2, n3, n4, n5, n6, n7, n8, n9;
@@

(
- e == n0 || e == n1 || e == n2 || e == n3 || e == n4 || e == n5 || e == n6 || e == n7 || e == n8 || e == n9
+ IN_SET(e, n0, n1, n2, n3, n4, n5, n6, n7, n8, n9)
|
- e == n0 || e == n1 || e == n2 || e == n3 || e == n4 || e == n5 || e == n6 || e == n7 || e == n8
+ IN_SET(e, n0, n1, n2, n3, n4, n5, n6, n7, n8)
|
- e == n0 || e == n1 || e == n2 || e == n3 || e == n4 || e == n5 || e == n6 || e == n7
+ IN_SET(e, n0, n1, n2, n3, n4, n5, n6, n7)
|
- e == n0 || e == n1 || e == n2 || e == n3 || e == n4 || e == n5 || e == n6
+ IN_SET(e, n0, n1, n2, n3, n4, n5, n6)
|
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
