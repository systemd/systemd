/*
 * pty.c
 *
 * Basic Unix98 PTY functionality; assumes devpts
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>

char *ptsname(int fd)
{
  static char buffer[32];	/* Big enough to hold even a 64-bit pts no */
  unsigned int ptyno;

  if ( ioctl(fd, TIOCGPTN, &ptyno) )
    return NULL;
  
  snprintf(buffer, sizeof buffer, "/dev/pts/%u", ptyno);
  
  return buffer;
}

int unlockpt(int fd)
{
  int unlock = 0;

  return ioctl(fd, TIOCSPTLCK, &unlock);
}
