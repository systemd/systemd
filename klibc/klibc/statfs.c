/*
 * statfs.c
 *
 * On architectures which do statfs64, wrap the system call
 */

#include <sys/syscall.h>
#include <sys/vfs.h>

#ifdef __NR_statfs64

extern int __statfs64(const char *, size_t, struct statfs *);

int statfs(const char *path, struct statfs *buf)
{
  return __statfs64(path, sizeof *buf, buf);
}

#endif
