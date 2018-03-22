@@
local idexpression p;
expression q;
@@
- p = q;
- q = -1;
- return p;
+ return TAKE_FD(q);
@@
expression p, q;
@@
- p = q;
- q = -1;
+ p = TAKE_FD(q);
