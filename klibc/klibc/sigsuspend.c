/*
 * sigsuspend.c
 */

#include <signal.h>
#include <sys/syscall.h>

#ifdef __NR_sigsuspend

_syscall1(int,sigsuspend,const sigset_t *,mask);

#else

int sigsuspend(const sigset_t *mask)
{
  return rt_sigsuspend(mask, sizeof *mask);
}

#endif
