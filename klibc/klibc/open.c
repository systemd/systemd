/*
 * open.c
 *
 * On 32-bit platforms we need to pass O_LARGEFILE to the open()
 * system call, to indicate that we're 64-bit safe.
 */

#define _KLIBC_IN_OPEN_C
#include <unistd.h>
#include <fcntl.h>

#if BITSIZE == 32 && !defined(__i386__)

extern int __open(const char *, int, mode_t);

int open(const char *pathname, int flags, mode_t mode)
{
  return __open(pathname, flags|O_LARGEFILE, mode);
}

#endif
