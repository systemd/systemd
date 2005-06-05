/*
 * sigsuspend.c
 */

#include <signal.h>
#include <sys/syscall.h>

#ifndef __NR_sigsuspend

__extern int __rt_sigsuspend(const sigset_t *, size_t);

int sigsuspend(const sigset_t *mask)
{
  return __rt_sigsuspend(mask, sizeof *mask);
}

#endif
