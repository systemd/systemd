@@
expression x, y;
@@
- ((x) & (y)) == (y)
+ FLAGS_SET(x, y)
@@
expression x, y;
@@
- (x & (y)) == (y)
+ FLAGS_SET(x, y)
@@
expression x, y;
@@
- ((x) & y) == y
+ FLAGS_SET(x, y)
