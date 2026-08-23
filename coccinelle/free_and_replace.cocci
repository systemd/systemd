/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
expression p, q;
@@
- free(p);
- p = q;
- q = NULL;
- return 0;
+ return free_and_replace(p, q);
@@
expression p, q;
@@
- free(p);
- p = q;
- q = NULL;
+ free_and_replace(p, q);
