/*
 * fstatfs.c
 *
 * On architectures which do fstatfs64, wrap the system call
 */

#include <sys/syscall.h>
#include <sys/vfs.h>

#ifdef __NR_fstatfs64

extern int __fstatfs64(int, size_t, struct statfs *);

int fstatfs(int fd, struct statfs *buf)
{
  return __fstatfs64(fd, sizeof *buf, buf);
}

#endif
