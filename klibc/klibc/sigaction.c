/*
 * sigaction.c
 */

#include <signal.h>
#include <sys/syscall.h>

#ifdef __NR_sigaction

_syscall3(int,sigaction,int,sig,const struct sigaction *,act,struct sigaction *,oact);

#else

int sigaction(int sig, const struct sigaction *act, struct sigaction *oact)
{
  return rt_sigaction(sig, act, oact, sizeof(sigset_t));
}

#endif
