/*
 * getcwd.c
 *
 * The system call behaves differently than the library function.
 */

#include <unistd.h>
#include <sys/syscall.h>

extern int __getcwd(char * buf, size_t size);

char *getcwd(char *buf, size_t size)
{
  return ( __getcwd(buf, size) < 0 ) ? NULL : buf;
}

