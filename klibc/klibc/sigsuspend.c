/*
 * sigsuspend.c
 */

#include <signal.h>
#include <sys/syscall.h>

#ifndef __NR_sigsuspend

int sigsuspend(const sigset_t *mask)
{
  return rt_sigsuspend(mask, sizeof *mask);
}

#endif
