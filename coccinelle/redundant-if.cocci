/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
expression r;
@@
- if (r < 0)
-         return r;
- if (r == 0)
-         return 0;
+ if (r <= 0)
+         return r;
@@
expression r;
@@
- if (r == 0)
-         return 0;
- if (r < 0)
-         return r;
+ if (r <= 0)
+         return r;
@@
expression r;
@@
- if (r < 0)
-         return r;
- if (r == 0)
-         return r;
+ if (r <= 0)
+         return r;
@@
expression r;
@@
- if (r == 0)
-         return r;
- if (r < 0)
-         return r;
+ if (r <= 0)
+         return r;
@@
expression r;
@@
- if (r < 0)
-         return r;
- if (r > 0)
-         return r;
+ if (r != 0)
+         return r;
@@
expression r;
@@
- if (r > 0)
-         return r;
- if (r < 0)
-         return r;
+ if (r != 0)
+         return r;

@@
expression e, x;
@@
- if (e & x)
-       e &= ~x;
- else
-       e |= x;
+ e ^= x;

@@
expression e, x;
@@
- if (!(e & x))
-       e |= x;
- else
-       e &= ~x;
+ e ^= x;

@@
expression e, x;
@@
- if (e & x)
-       e ^= x;
-
+ e &= ~x;
+

@@
expression e, x;
@@
- if (e & x)
(
  e &= ~x;
)

@@
expression e, x;
@@
- if (e & ~x)
(
  e &= x;
)


@@
expression e, x;
@@
- if (e != x)
(
  e = x;
)
