@@
expression fd;
@@
- dup(fd)
+ fcntl(fd, F_DUPFD, 3)
