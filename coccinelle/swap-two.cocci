/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
expression x, y, z;
@@
- z = x;
- x = y;
- y = z;
+ SWAP_TWO(x, y);
