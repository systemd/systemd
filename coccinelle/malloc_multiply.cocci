/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
expression q, n, m;
@@
- q = malloc((n)*(m))
+ q = malloc_multiply(n, m)
@@
expression q, n, m;
@@
- q = malloc(n*(m))
+ q = malloc_multiply(n, m)
@@
expression q, n, m;
@@
- q = malloc((n)*m)
+ q = malloc_multiply(n, m)
@@
expression q, n, m;
@@
- q = malloc(n*m)
+ q = malloc_multiply(n, m)
