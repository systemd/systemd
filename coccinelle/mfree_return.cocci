/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
/* Avoid running this transformation on the mfree function itself */
position p : script:python() { p[0].current_element != "mfree" };
expression e;
@@
- free@p(e);
- return NULL;
+ return mfree(e);
