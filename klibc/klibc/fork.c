/*
 * fork.c
 *
 * This is normally just a syscall stub, but at least one system
 * doesn't have sys_fork, only sys_clone...
 */

#include <sys/syscall.h>
#include <signal.h>
#include <unistd.h>

#ifdef __NR_fork

#ifdef _syscall0_forkish
_syscall0_forkish(pid_t,fork);
#else
_syscall0(pid_t,fork);
#endif

#else /* __NR_fork */

static inline _syscall2(pid_t,clone,unsigned long,flags,void *,newsp);

pid_t fork(void)
{
  return clone(SIGCHLD, 0);
}

#endif /* __NR_fork */
