/*
 * sigpending.c
 */

#include <signal.h>
#include <sys/syscall.h>

#ifdef __NR_sigpending

_syscall1(int,sigpending,sigset_t *,set);

#else

int sigpending(sigset_t *set)
{
  return rt_sigpending(set, sizeof(sigset_t));
}

#endif
