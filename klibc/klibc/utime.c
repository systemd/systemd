/*
 * utime.c
 */

#include <utime.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/syscall.h>

#ifdef __NR_utime

_syscall2(int,utime,const char *,filename,const struct utimbuf *,buf);

#else

static inline _syscall2(int,utimes,const char *,filename, const struct timeval *,tvp);

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
