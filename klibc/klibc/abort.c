/*
 * abort.c
 */

#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

void abort(void)
{
  sigset_t set;

  sigemptyset(&set);
  sigaddset(&set, SIGABRT);
  sigprocmask(SIG_UNBLOCK, &set, NULL);
  raise(SIGABRT);
  _exit(255);			/* raise() should have killed us */
}
  
