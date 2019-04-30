@@
/* Disable this transformation for the securebits-util.h, as it makes
 * the expression there confusing. */
position p : script:python() { p[0].file != "src/shared/securebits-util.h" };
expression x, y;
@@
(
- ((x@p) & (y)) == (y)
+ FLAGS_SET(x, y)
|
- (x@p & (y)) == (y)
+ FLAGS_SET(x, y)
|
- ((x@p) & y) == y
+ FLAGS_SET(x, y)
)
