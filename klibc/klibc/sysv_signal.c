/*
 * sysv_signal.c
 */

#include <signal.h>

__sighandler_t sysv_signal(int signum, __sighandler_t handler)
{
  /* Linux/SysV signal() semantics */
  return __signal(signum, handler, SA_RESETHAND);
}
