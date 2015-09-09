@@
expression fd;
@@
- if (fd >= 0) {
- fd = safe_close(fd);
- }
+ fd = safe_close(fd);
