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

#if !defined(__alpha__) && !defined(__ia64__)

extern int __getpriority(int, int);

int getpriority(int which, int who)
{
  int rv = __getpriority(which, who);
  return ( rv < 0 ) ? rv : 20-rv;
}

#endif
