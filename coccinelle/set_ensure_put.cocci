/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
local idexpression r;
expression p, k, x;
@@
- r = set_ensure_allocated(&p, k);
- if (r < 0)
-   return ...;
- r = set_put(p, x);
+ r = set_ensure_put(&p, k, x);
@@
local idexpression r;
expression p, k, x;
@@
- r = set_ensure_allocated(p, k);
- if (r < 0)
-   return ...;
- r = set_put(*p, x);
+ r = set_ensure_put(p, k, x);
