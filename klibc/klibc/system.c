/*
 * system.c
 *
 * The system() function.  If this turns out to actually be *used*,
 * we may want to try to detect the very simple cases (no shell magic)
 * and handle them internally, instead of requiring that /bin/sh be
 * present.
 */

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

int system(const char *string)
{
  pid_t pid;
  struct sigaction ignore, old_int, old_quit;
  sigset_t masked, oldmask;
  static const char *argv[] = { "/bin/sh", "-c", NULL, NULL };
  int status;

  /* Block SIGCHLD and ignore SIGINT and SIGQUIT */
  /* Do this before the fork() to avoid races */

  ignore.sa_handler = SIG_IGN;
  sigemptyset(&ignore.sa_mask);
  ignore.sa_flags = 0;
  sigaction(SIGINT,  &ignore, &old_int);
  sigaction(SIGQUIT, &ignore, &old_quit);

  sigemptyset(&masked);
  sigaddset(&masked, SIGCHLD);
  sigprocmask(SIG_BLOCK, &masked, &oldmask);

  pid = fork();

  if ( pid < 0 )
    return -1;
  else if ( pid == 0 ) {
    sigaction(SIGINT,  &old_int, NULL);
    sigaction(SIGQUIT, &old_quit, NULL);
    sigprocmask(SIG_SETMASK, &oldmask, NULL);

    argv[2] = string;

    execve(argv[0], (char * const *)argv, (char * const *)environ);
    _exit(127);
  }

  /* else... */

  waitpid(pid, &status, 0);

  sigaction(SIGINT,  &old_int, NULL);
  sigaction(SIGQUIT, &old_quit, NULL);
  sigprocmask(SIG_SETMASK, &oldmask, NULL);

  return status;
}
