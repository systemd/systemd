/*
 * signal.h
 */

#ifndef _SIGNAL_H
#define _SIGNAL_H

#include <klibc/extern.h>
#include <string.h>		/* For memset() */
#include <limits.h>		/* For LONG_BIT */
#include <sys/types.h>
#include <asm/signal.h>

#include <klibc/archsignal.h>

/* glibc seems to use sig_atomic_t as "int" pretty much on all architectures.
   Do the same, but allow the architecture to override. */
#ifdef _KLIBC_HAS_ARCH_SIG_ATOMIC_T
typedef int sig_atomic_t;
#endif

/* Some architectures don't define these */
#ifndef SA_RESETHAND
# define SA_RESETHAND SA_ONESHOT
#endif
#ifndef SA_NODEFER
# define SA_NODEFER SA_NOMASK
#endif
#ifndef NSIG
# define NSIG _NSIG
#endif

__extern const char * const sys_siglist[];

/* This assumes sigset_t is either an unsigned long or an array of such,
   and that _NSIG_BPW in the kernel is always LONG_BIT */

static __inline__ int sigemptyset(sigset_t *__set)
{
  memset(__set, 0, sizeof *__set);
  return 0;
}
static __inline__ int sigfillset(sigset_t *__set)
{
  memset(__set, ~0, sizeof *__set);
  return 0;
}
static __inline__ int sigaddset(sigset_t *__set, int __signum)
{
  unsigned long *__lset = (unsigned long *)__set;
  __lset[__signum/LONG_BIT] |= 1UL << (__signum%LONG_BIT);
  return 0;
}
static __inline__ int sigdelset(sigset_t *__set, int __signum)
{
  unsigned long *__lset = (unsigned long *)__set;
  __lset[__signum/LONG_BIT] &= ~(1UL << (__signum%LONG_BIT));
  return 0;
}
static __inline__ int sigismember(sigset_t *__set, int __signum)
{
  unsigned long *__lset = (unsigned long *)__set;
  return (int)((__lset[__signum/LONG_BIT] >> (__signum%LONG_BIT)) & 1);
}

__extern __sighandler_t __signal(int, __sighandler_t, int);
__extern __sighandler_t sysv_signal(int, __sighandler_t);
__extern __sighandler_t bsd_signal(int, __sighandler_t);
__extern int sigaction(int, const struct sigaction *, struct sigaction *);
__extern int sigprocmask(int, const sigset_t *, sigset_t *);
__extern int sigpending(sigset_t *);
__extern int sigsuspend(const sigset_t *);
__extern int rt_sigaction(int, const struct sigaction *, struct sigaction *, size_t);
__extern int rt_sigprocmask(int, const sigset_t *, sigset_t *, size_t);
__extern int rt_sigpending(sigset_t *, size_t);
__extern int rt_sigsuspend(const sigset_t *, size_t);
__extern int raise(int);
__extern int kill(pid_t, int);

#endif /* _SIGNAL_H */
