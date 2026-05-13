/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
expression x, y, p, l;
@@
- x[y].iov_base = p;
- x[y].iov_len = l;
- y++;
+ x[y++] = IOVEC_MAKE(p, l);
@@
expression x, p, l;
@@
- x.iov_base = p;
- x.iov_len = l;
+ x = IOVEC_MAKE(p, l);
@@
/* Don't run this transformation on iovec_done() and iovec_done_erase(),
 * since the result, albeit correct, is a bit funky. */
 position pos : script:python() { pos[0].current_element != "iovec_done" and
                                  pos[0].current_element != "iovec_done_erase" };
expression x, p, l;
@@
- x->iov_base@pos = p;
- x->iov_len = l;
+ *x = IOVEC_MAKE(p, l);
@@
expression s;
@@
- IOVEC_MAKE(s, strlen(s));
+ IOVEC_MAKE_STRING(s);
@@
expression x, y, z;
@@
- x = (struct iovec) { .iov_base = y, .iov_len = z };
+ x = IOVEC_MAKE(y, z);
