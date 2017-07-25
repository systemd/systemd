/* Public domain. */

#include <sys/types.h>
#include <sys/wait.h>
#include "error.h"
#include "haswaitp.h"

#ifdef HASWAITPID

int wait_pid(wstat,pid) int *wstat; int pid;
{
  int r;

  do
    r = waitpid(pid,wstat,0);
  while ((r == -1) && (errno == error_intr));
  return r;
}

#else

/* XXX untested */
/* XXX breaks down with more than two children */
static int oldpid = 0;
static int oldwstat; /* defined if(oldpid) */

int wait_pid(wstat,pid) int *wstat; int pid;
{
  int r;

  if (pid == oldpid) { *wstat = oldwstat; oldpid = 0; return pid; }

  do {
    r = wait(wstat);
    if ((r != pid) && (r != -1)) { oldwstat = *wstat; oldpid = r; continue; }
  }
  while ((r == -1) && (errno == error_intr));
  return r;
}

#endif
