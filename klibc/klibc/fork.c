/*
 * fork.c
 *
 * This is normally just a syscall stub, but at least one system
 * doesn't have sys_fork, only sys_clone...
 */

#include <sys/syscall.h>
#include <signal.h>
#include <unistd.h>
#include <sched.h>

#ifndef __NR_fork

pid_t fork(void)
{
  return __clone(SIGCHLD, 0);
}

#endif /* __NR_fork */
