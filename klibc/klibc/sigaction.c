/*
 * sigaction.c
 */

#include <signal.h>
#include <sys/syscall.h>

#if !defined(__NR_sigaction)

int sigaction(int sig, const struct sigaction *act, struct sigaction *oact)
{
  return rt_sigaction(sig, act, oact, sizeof(sigset_t));
}

#endif
