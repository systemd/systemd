/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
expression p;
@@
- free(p);
- p = NULL;
+ p = mfree(p);
