/*
 * nice.c
 */

#include <unistd.h>
#include <sched.h>
#include <sys/resource.h>
#include <sys/syscall.h>

#ifdef __NR_nice

_syscall1(int,nice,int,inc);

#else

int nice(int inc)
{
  pid_t me = getpid();
  return setpriority(me, PRIO_PROCESS, getpriority(me, PRIO_PROCESS)+inc);
}

#endif
