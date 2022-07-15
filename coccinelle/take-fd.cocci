/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
local idexpression p;
expression q;
@@
- p = q;
- q = -1;
- return p;
+ return TAKE_FD(q);

/* The ideal solution would use 'local idexpression' to avoid matching errno,
 * which is a global variable. However, 'idexpression' nor 'identifier'
 * would match, for example, "x->fd", which is considered 'expression' in
 * the SmPL grammar
 */
@@
expression p != errno;
expression q;
@@
- p = q;
- q = -1;
+ p = TAKE_FD(q);
