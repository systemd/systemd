/*
 * getpriority.c
 *
 * Needs to do some post-syscall mangling to distinguish error returns...
 * but only on some platforms.  Sigh.
 */

#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/syscall.h>

#define __NR__getpriority __NR_getpriority

static inline _syscall2(int,_getpriority,int,which,int,who);

int getpriority(int which, int who)
{
#if defined(__alpha__) || defined(__ia64__)
  return _getpriority(which, who);
#else
  int rv = _getpriority(which, who);
  return ( rv < 0 ) ? rv : 20-rv;
#endif
}
