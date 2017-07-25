#include <sys/types.h>
#include <sys/reboot.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include "runit.h"
#include "sig.h"
#include "strerr.h"
#include "error.h"
#include "iopause.h"
#include "coe.h"
#include "ndelay.h"
#include "wait.h"
#include "open.h"
#include "reboot_system.h"

/* #define DEBUG */

#define INFO "- runit: "
#define WARNING "- runit: warning: "
#define FATAL "- runit: fatal: "

const char * const stage[3] ={
  "/etc/runit/1",
  "/etc/runit/2",
  "/etc/runit/3" };

int selfpipe[2];
int sigc =0;
int sigi =0;

void sig_cont_handler (void) {
  sigc++;
  write(selfpipe[1], "", 1);
}
void sig_int_handler (void) {
  sigi++;
  write(selfpipe[1], "", 1);
}
void sig_child_handler (void) { write(selfpipe[1], "", 1); }

int main (int argc, const char * const *argv, char * const *envp) {
  const char * prog[2];
  int pid, pid2;
  int wstat;
  int st;
  iopause_fd x;
#ifndef IOPAUSE_POLL
  fd_set rfds;
  struct timeval t;
#endif
  char ch;
  int ttyfd;
  struct stat s;

  if (getpid() != 1) strerr_die2x(111, FATAL, "must be run as process no 1.");
  setsid();

  sig_block(sig_alarm);
  sig_block(sig_child);
  sig_catch(sig_child, sig_child_handler);
  sig_block(sig_cont);
  sig_catch(sig_cont, sig_cont_handler);
  sig_block(sig_hangup);
  sig_block(sig_int);
  sig_catch(sig_int, sig_int_handler);
  sig_block(sig_pipe);
  sig_block(sig_term);

  /* console */
  if ((ttyfd =open_write("/dev/console")) != -1) {
    dup2(ttyfd, 0); dup2(ttyfd, 1); dup2(ttyfd, 2);
    if (ttyfd > 2) close(ttyfd);
  }

  /* create selfpipe */
  while (pipe(selfpipe) == -1) {
    strerr_warn2(FATAL, "unable to create selfpipe, pausing: ", &strerr_sys);
    sleep(5);
  }
  coe(selfpipe[0]);
  coe(selfpipe[1]);
  ndelay_on(selfpipe[0]);
  ndelay_on(selfpipe[1]);

#ifdef RB_DISABLE_CAD
  /* activate ctrlaltdel handling, glibc, dietlibc */
  if (RB_DISABLE_CAD == 0) reboot_system(0);
#endif

  strerr_warn3(INFO, "$Id: 25da3b86f7bed4038b8a039d2f8e8c9bbcf0822b $",
               ": booting.", 0);

  /* runit */
  for (st =0; st < 3; st++) {
    /* if (st == 2) logwtmp("~", "reboot", ""); */
    while ((pid =fork()) == -1) {
      strerr_warn4(FATAL, "unable to fork for \"", stage[st], "\" pausing: ",
                   &strerr_sys);
      sleep(5);
    }
    if (!pid) {
      /* child */
      prog[0] =stage[st];
      prog[1] =0;

      /* stage 1 gets full control of console */
      if (st == 0) {
        if ((ttyfd =open("/dev/console", O_RDWR)) != -1) {
#ifdef TIOCSCTTY 
          ioctl(ttyfd, TIOCSCTTY, (char *)0);
#endif
          dup2(ttyfd, 0);
          if (ttyfd > 2) close(ttyfd);
        }
        else
          strerr_warn2(WARNING, "unable to open /dev/console: ", &strerr_sys);
      }
      else
        setsid();

      sig_unblock(sig_alarm);
      sig_unblock(sig_child);
      sig_uncatch(sig_child);
      sig_unblock(sig_cont);
      sig_ignore(sig_cont);
      sig_unblock(sig_hangup);
      sig_unblock(sig_int);
      sig_uncatch(sig_int);
      sig_unblock(sig_pipe);
      sig_unblock(sig_term);
            
      strerr_warn3(INFO, "enter stage: ", stage[st], 0);
      execve(*prog, (char *const *)prog, envp);
      strerr_die4sys(0, FATAL, "unable to start child: ", stage[st], ": ");
    }

    x.fd =selfpipe[0];
    x.events =IOPAUSE_READ;
    for (;;) {
      int child;

      sig_unblock(sig_child);
      sig_unblock(sig_cont);
      sig_unblock(sig_int);
#ifdef IOPAUSE_POLL
      poll(&x, 1, 14000);
#else
      t.tv_sec =14; t.tv_usec =0;
      FD_ZERO(&rfds);
      FD_SET(x.fd, &rfds);
      select(x.fd +1, &rfds, (fd_set*)0, (fd_set*)0, &t);
#endif
      sig_block(sig_cont);
      sig_block(sig_child);
      sig_block(sig_int);
      
      while (read(selfpipe[0], &ch, 1) == 1) {}
      while ((child =wait_nohang(&wstat)) > 0)
        if (child == pid) break;
      if (child == -1) {
        strerr_warn2(WARNING, "wait_nohang, pausing: ", &strerr_sys);
        sleep(5);
      }

      /* reget stderr */
      if ((ttyfd =open_write("/dev/console")) != -1) {
        dup2(ttyfd, 2);
        if (ttyfd > 2) close(ttyfd);
      }

      if (child == pid) {
        if (wait_exitcode(wstat) != 0) {
          if (wait_crashed(wstat))
            strerr_warn3(WARNING, "child crashed: ", stage[st], 0);
          else
            strerr_warn3(WARNING, "child failed: ", stage[st], 0);
          if (st == 0)
            /* this is stage 1 */
            if (wait_crashed(wstat) || (wait_exitcode(wstat) == 100)) {
              strerr_warn3(INFO, "leave stage: ", stage[st], 0);
              strerr_warn2(WARNING, "skipping stage 2...", 0);
              st++;
              break;
            }
          if (st == 1)
            /* this is stage 2 */
            if (wait_crashed(wstat) || (wait_exitcode(wstat) == 111)) {
              strerr_warn2(WARNING, "killing all processes in stage 2...", 0);
              kill(-pid, 9);
              sleep(5);
              strerr_warn2(WARNING, "restarting.", 0);
              st--;
              break;
            }
        }
        strerr_warn3(INFO, "leave stage: ", stage[st], 0);
        break;
      }
      if (child != 0) {
        /* collect terminated children */
        write(selfpipe[1], "", 1);
        continue;
      }

      /* sig? */
      if (!sigc  && !sigi) {
#ifdef DEBUG
        strerr_warn2(WARNING, "poll: ", &strerr_sys);
#endif
        continue;
      }
      if (st != 1) {
        strerr_warn2(WARNING, "signals only work in stage 2.", 0);
        sigc =sigi =0;
        continue;
      }
      if (sigi && (stat(CTRLALTDEL, &s) != -1) && (s.st_mode & S_IXUSR)) {
        strerr_warn2(INFO, "ctrl-alt-del request...", 0);
        prog[0] =CTRLALTDEL; prog[1] =0;
        while ((pid2 =fork()) == -1) {
          strerr_warn4(FATAL, "unable to fork for \"", CTRLALTDEL,
                       "\" pausing: ", &strerr_sys);
          sleep(5);
        }
        if (!pid2) {
          /* child */
          strerr_warn3(INFO, "enter stage: ", prog[0], 0);
          execve(*prog, (char *const *) prog, envp);
          strerr_die4sys(0, FATAL, "unable to start child: ", prog[0], ": ");
        }
        if (wait_pid(&wstat, pid2) == -1)
          strerr_warn2(FATAL, "wait_pid: ", &strerr_sys);
        if (wait_crashed(wstat))
          strerr_warn3(WARNING, "child crashed: ", CTRLALTDEL, 0);
        strerr_warn3(INFO, "leave stage: ", prog[0], 0);
        sigi =0;
        sigc++;
      }
      if (sigc && (stat(STOPIT, &s) != -1) && (s.st_mode & S_IXUSR)) {
        int i;
        /* unlink(STOPIT); */
        chmod(STOPIT, 0);

        /* kill stage 2 */
#ifdef DEBUG
        strerr_warn2(WARNING, "sending sigterm...", 0);
#endif
        kill(pid, sig_term);
        i =0;
        while (i < 5) {
          if ((child =wait_nohang(&wstat)) == pid) {
#ifdef DEBUG
            strerr_warn2(WARNING, "stage 2 terminated.", 0);
#endif
            pid =0;
            break;
          }
          if (child) continue;
          if (child == -1) 
            strerr_warn2(WARNING, "wait_nohang: ", &strerr_sys);
#ifdef DEBUG
          strerr_warn2(WARNING, "waiting...", 0);
#endif
          sleep(1);
          i++;
        }
        if (pid) {
          /* still there */
          strerr_warn2(WARNING,
                       "stage 2 not terminated, sending sigkill...", 0);
          kill(pid, 9);
          if (wait_pid(&wstat, pid) == -1)
            strerr_warn2(WARNING, "wait_pid: ", &strerr_sys);
        }
        sigc =0;
        strerr_warn3(INFO, "leave stage: ", stage[st], 0);

        /* enter stage 3 */
        break;
      }
      sigc =sigi =0;
#ifdef DEBUG
      strerr_warn2(WARNING, "no request.", 0);
#endif
    }
  }

  /* reget stderr */
  if ((ttyfd =open_write("/dev/console")) != -1) {
    dup2(ttyfd, 2);
    if (ttyfd > 2) close(ttyfd);
  }

#ifdef RB_AUTOBOOT
  /* fallthrough stage 3 */
  strerr_warn2(INFO, "sending KILL signal to all processes...", 0);
  kill(-1, SIGKILL);

  pid =fork();
  switch (pid) {
  case  0:
  case -1:
  if ((stat(REBOOT, &s) != -1) && (s.st_mode & S_IXUSR)) {
    strerr_warn2(INFO, "system reboot.", 0);
    sync();
    reboot_system(RB_AUTOBOOT);
  }
  else {
#ifdef RB_POWER_OFF
    strerr_warn2(INFO, "power off...", 0);
    sync();
    reboot_system(RB_POWER_OFF);
    sleep(2);
#endif
#ifdef RB_HALT_SYSTEM
    strerr_warn2(INFO, "system halt.", 0);
    sync();
    reboot_system(RB_HALT_SYSTEM);
#else
#ifdef RB_HALT
    strerr_warn2(INFO, "system halt.", 0);
    sync();
    reboot_system(RB_HALT);
#else
    strerr_warn2(INFO, "system reboot.", 0);
    sync();
    reboot_system(RB_AUTOBOOT);
#endif
#endif
  }
  if (pid == 0) _exit(0);
  break;
  default:
  sig_unblock(sig_child);
  while (wait_pid(0, pid) == -1);
  }
#endif

  for (;;) sig_pause();
  /* not reached */
  strerr_die2x(0, INFO, "exit.");
  return(0);
}
