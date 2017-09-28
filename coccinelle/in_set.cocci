@@
expression e;
identifier n1, n2, n3, n4, n5, n6;
statement s;
@@
- e == n1 || e == n2 || e == n3 || e == n4 || e == n5 || e == n6
+ IN_SET(e, n1, n2, n3, n4, n5, n6)
@@
expression e;
identifier n1, n2, n3, n4, n5;
statement s;
@@
- e == n1 || e == n2 || e == n3 || e == n4 || e == n5
+ IN_SET(e, n1, n2, n3, n4, n5)
@@
expression e;
identifier n1, n2, n3, n4;
statement s;
@@
- e == n1 || e == n2 || e == n3 || e == n4
+ IN_SET(e, n1, n2, n3, n4)
@@
expression e;
identifier n1, n2, n3;
statement s;
@@
- e == n1 || e == n2 || e == n3
+ IN_SET(e, n1, n2, n3)
@@
expression e;
identifier n, p;
statement s;
@@
- e == n || e == p
+ IN_SET(e, n, p)
