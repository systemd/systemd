/*
 * __signal.c
 */

#include <signal.h>

__sighandler_t __signal(int signum, __sighandler_t handler, int flags)
{
  struct sigaction sa;

  sa.sa_handler = handler;
  sa.sa_flags   = flags;
  sigemptyset(&sa.sa_mask);

  if ( sigaction(signum, &sa, &sa) ) {
    return (__sighandler_t)SIG_ERR;
  } else {
    return (__sighandler_t)sa.sa_handler;
  }
}

       
