/* SPDX-License-Identifier: LGPL-2.1-or-later */
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
