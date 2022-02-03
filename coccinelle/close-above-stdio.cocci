/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
expression fd;
@@
- if (fd > 2)
- safe_close(fd);
+ safe_close_above_stdio(fd);
@@
expression fd;
@@
- if (fd > 2)
- fd = safe_close(fd);
+ fd = safe_close_above_stdio(fd);
@@
expression fd;
@@
- if (fd >= 3)
- safe_close(fd);
+ safe_close_above_stdio(fd);
@@
expression fd;
@@
- if (fd >= 3)
- fd = safe_close(fd);
+ fd = safe_close_above_stdio(fd);
@@
expression fd;
@@
- if (fd > STDERR_FILENO)
- safe_close(fd);
+ safe_close_above_stdio(fd);
@@
expression fd;
@@
- if (fd > STDERR_FILENO)
- fd = safe_close(fd);
+ fd = safe_close_above_stdio(fd);
