/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
/* Avoid running this transformation on the mfree function itself */
position p : script:python() { p[0].current_element != "mfree" };
expression e;
@@
- free@p(e);
- return NULL;
+ return mfree(e);

@@
expression p;
@@
- free(p);
- p = NULL;
+ p = mfree(p);

@@
expression p;
@@
- if (p)
-          free(p);
+ free(p);

@@
expression p;
@@
- if (p)
-          mfree(p);
+ free(p);

@@
expression p;
@@
- mfree(p);
+ free(p);
