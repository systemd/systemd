/*
 * time.c
 */

#include <time.h>
#include <sys/time.h>
#include <sys/syscall.h>

#ifdef __NR_time

_syscall1(time_t,time,time_t *,t);

#else

time_t time(time_t *t)
{
  struct timeval tv;

  gettimeofday(&tv, NULL);
  
  if ( t )
    *t = (time_t)tv.tv_sec;

  return (time_t)tv.tv_sec;
}

#endif
