/*
 * isatty.c
 */

#include <unistd.h>
#include <termios.h>
#include <errno.h>

int isatty(int fd)
{
  int old_errno = errno;
  int istty;
  pid_t dummy;

  /* All ttys support TIOCGPGRP */
  istty = !ioctl(fd, TIOCGPGRP, &dummy);
  errno = old_errno;

  return istty;
}

