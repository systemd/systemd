@@
expression p, q;
identifier r;
statement s;
@@
- if ((r = q) < p)
- s
+ r = q;
+ if (r < p)
+ s
@@
expression p, q;
identifier r;
statement s;
@@
- if ((r = q) >= p)
- s
+ r = q;
+ if (r >= p)
+ s
