@@
expression q, p, n, m;
@@
- q = realloc(p, (n)*(m))
+ q = reallocarray(p, n, m)
@@
expression q, p, n, m;
@@
- q = realloc(p, n*(m))
+ q = reallocarray(p, n, m)
@@
expression q, p, n, m;
@@
- q = realloc(p, (n)*m)
+ q = reallocarray(p, n, m)
@@
expression q, p, n, m;
@@
- q = realloc(p, n*m)
+ q = reallocarray(p, n, m)
