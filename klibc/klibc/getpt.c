/*
 * getpt.c
 *
 * GNU extension to the standard Unix98 pty suite
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>
#include <fcntl.h>
#include <sys/ioctl.h>

int getpt(void)
{
  return open("/dev/ptmx", O_RDWR|O_NOCTTY);
}
