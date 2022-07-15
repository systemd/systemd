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
