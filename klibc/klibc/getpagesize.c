/*
 * getpagesize.c
 */

#include <sys/syscall.h>
#include <asm/page.h>

/* Presumably there is a better way to do this... */
#ifdef __ia64__
# define __NR_getpagesize 1171
#endif

#ifdef __NR_getpagesize

_syscall0(int,getpagesize);

#else

int getpagesize(void)
{
  return PAGE_SIZE;
}

#endif


