/*
 * sigpending.c
 */

#include <signal.h>
#include <sys/syscall.h>

#ifndef __NR_sigpending

int sigpending(sigset_t *set)
{
  return rt_sigpending(set, sizeof(sigset_t));
}

#endif
