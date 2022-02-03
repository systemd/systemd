/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
expression fd;
@@
- if (fd >= 0) {
- fd = safe_close(fd);
- }
+ fd = safe_close(fd);
