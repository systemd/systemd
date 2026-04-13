/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* We want to stick with dup() in test-fd-util.c */
@ depends on !(file in "src/test/test-fd-util.c") @
expression fd;
@@
- dup(fd)
+ fcntl(fd, F_DUPFD, 3)
