/*
 * sigprocmask.c
 */

#include <signal.h>
#include <sys/syscall.h>

#ifdef __NR_sigprocmask

_syscall3(int,sigprocmask,int,how,const sigset_t *,set,sigset_t *,oset);

#else

int sigprocmask(int how, const sigset_t *set, sigset_t *oset)
{
  return rt_sigprocmask(how, set, oset, sizeof(sigset_t));
}

#endif
