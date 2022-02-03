/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
expression x, y;
@@
- if (x < y)
-         return -1;
- if (x > y)
-         return 1;
- return 0;
+ return CMP(x, y);
@@
expression x, y;
@@
- if (x < y)
-         return -1;
- else if (x > y)
-         return 1;
- return 0;
+ return CMP(x, y);
@@
expression x, y;
@@
- if (x < y)
-         return -1;
- else if (x > y)
-         return 1;
- else
-         return 0;
+ return CMP(x, y);
