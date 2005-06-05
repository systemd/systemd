/*
 * sigpending.c
 */

#include <signal.h>
#include <sys/syscall.h>

#ifndef __NR_sigpending

__extern __rt_sigpending(sigset_t *, size_t);

int sigpending(sigset_t *set)
{
  return __rt_sigpending(set, sizeof(sigset_t));
}

#endif
