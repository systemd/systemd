/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
expression x, y;
@@
- ((x + y - 1) / y)
+ DIV_ROUND_UP(x, y)
@@
expression x, y;
@@
- ((x + (y - 1)) / y)
+ DIV_ROUND_UP(x, y)
@@
expression x, y;
@@
- (x + y - 1) / y
+ DIV_ROUND_UP(x, y)
@@
expression x, y;
@@
- (x + (y - 1)) / y
+ DIV_ROUND_UP(x, y)
