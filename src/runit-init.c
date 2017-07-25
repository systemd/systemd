#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <unistd.h>
#include "runit.h"
#include "strerr.h"
#include "sig.h"
#include "open.h"
#include "error.h"

#define USAGE " 0|6"
#define FATAL "init: fatal: "
/* #define WARNING "init: warning: " */

const char *progname;

void usage(void) { strerr_die4x(0, "usage: ", progname, USAGE, "\n"); }

void runit_halt () {
  if (open_trunc(STOPIT) == -1)
    strerr_die4sys(111, FATAL, "unable to create ", STOPIT, ": ");
  if (chmod(STOPIT, 0100) == -1)
    strerr_die4sys(111, FATAL, "unable to chmod ", STOPIT, ": ");
  if (chmod(REBOOT, 0) == -1)
    if (errno != error_noent)
      strerr_die4sys(111, FATAL, "unable to chmod ", REBOOT, ": ");
  kill(1, sig_cont);
  _exit(0);
}

void runit_reboot () {
  if (open_trunc(STOPIT) == -1)
    strerr_die4sys(111, FATAL, "unable to create ", STOPIT, ": ");
  if (chmod(STOPIT, 0100) == -1)
    strerr_die4sys(111, FATAL, "unable to chmod ", STOPIT, ": ");
  if (open_trunc(REBOOT) == -1)
    strerr_die4sys(111, FATAL, "unable to create ", REBOOT, ": ");
  if (chmod(REBOOT, 0100) == -1)
    strerr_die4sys(111, FATAL, "unable to chmod ", REBOOT, ": ");
  kill(1, sig_cont);
  _exit(0);
}

int main (int argc, const char * const *argv, char * const *envp) {
  const char *prog[2];

  progname =*argv++;

  if (getpid() == 1) {
    prog[1] =0;
    prog[0] ="runit";

    /* kernel is starting init, runit does the job. */
    execve(RUNIT, (char *const *)prog, envp);

    /* serious error */
    strerr_die4sys(111, FATAL, "unable to start ", prog[0], ": ");
  }

  if (! *argv || ! **argv) usage();
  switch (**argv) {
  case '0':
    runit_halt();
    break;
  case '6':
    runit_reboot();
    break;
  case '-':
    if ((*argv)[1] == 'V')
      strerr_warn1("$Id: f075d98bf7dd17c893021f9572cbb970cdad8dcf $\n", 0);
  default:
    usage();
  }
  /* not reached */
  _exit(0);
}
