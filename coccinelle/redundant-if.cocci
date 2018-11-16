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
