/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
expression fd;
@@
- close(fd);
- fd = -EBADF;
+ fd = safe_close(fd);
@@
expression fd;
@@
- close_nointr(fd);
- fd = -EBADF;
+ fd = safe_close(fd);
@@
expression fd;
@@
- safe_close(fd);
- fd = -EBADF;
+ fd = safe_close(fd);
