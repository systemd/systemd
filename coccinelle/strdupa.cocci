/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
expression x;
@@
- strdupa(x)
+ strdupa_safe(x)
@@
expression x, n;
@@
- strndupa(x, n)
+ strndupa_safe(x, n)
