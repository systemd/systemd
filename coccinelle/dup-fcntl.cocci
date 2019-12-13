@@
/* We want to stick with dup() in test-fd-util.c */
position p : script:python() { p[0].file != "src/test/test-fd-util.c" };
expression fd;
@@
- dup@p(fd)
+ fcntl(fd, F_DUPFD, 3)
