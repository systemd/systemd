/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
expression x, y, z;
@@
- memcpy(x, y, z);
- x += z;
+ x = mempcpy(x, y, z);
@@
expression x, y, z;
@@
- memcpy_safe(x, y, z);
- x += z;
+ x = mempcpy_safe(x, y, z);
