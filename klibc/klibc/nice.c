/*
 * nice.c
 */

#include <unistd.h>
#include <sched.h>
#include <sys/resource.h>
#include <sys/syscall.h>

#ifndef __NR_nice

int nice(int inc)
{
  pid_t me = getpid();
  return setpriority(me, PRIO_PROCESS, getpriority(me, PRIO_PROCESS)+inc);
}

#endif
