/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
local idexpression p;
expression q;
@@
- p = q;
- q = NULL;
- return p;
+ return TAKE_PTR(q);
@@
expression p, q;
@@
- p = q;
- q = NULL;
+ p = TAKE_PTR(q);
