/*
 * sys/stat.h
 */

#ifndef _SYS_STAT_H
#define _SYS_STAT_H

#include <klibc/extern.h>
#include <sys/types.h>
#include <asm/stat.h>
#include <linux/stat.h>

__extern int stat(const char *, struct stat *);
__extern int fstat(int, struct stat *);
__extern int lstat(const char *, struct stat *);
__extern mode_t umask(mode_t);
__extern int mknod(const char *, mode_t, dev_t);
static __inline__ int mkfifo(const char *__p, mode_t __m)
{
  return mknod(__p, (__m & ~S_IFMT) | S_IFIFO, (dev_t)0);
}

#endif /* _SYS_STAT_H */
