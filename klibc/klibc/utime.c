/*
 * utime.c
 */

#include <utime.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/syscall.h>

#ifndef __NR_utime

int utime(const char *filename, const struct utimbuf *buf)
{
  struct timeval tvp[2];

  tvp[0].tv_sec  = buf->actime;
  tvp[0].tv_usec = 0;
  tvp[1].tv_sec  = buf->modtime;
  tvp[1].tv_usec = 0;

  return utimes(filename, tvp);
}

#endif
