/*
 * getcwd.c
 */

#include <unistd.h>
#include <sys/syscall.h>

#define __NR___getcwd __NR_getcwd
static inline _syscall2(int,__getcwd,char *,buf,size_t,size);

char *getcwd(char *buf, size_t size)
{
  return ( __getcwd(buf, size) < 0 ) ? NULL : buf;
}

