/*
 * termios.h
 */

#ifndef _TERMIOS_H
#define _TERMIOS_H

#include <klibc/extern.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <linux/termios.h>

/* Redefine these so the magic constants == the ioctl number to use. */
#undef TCSANOW
#undef TCSADRAIN
#undef TCSAFLUSH
#define TCSANOW	   TCSETS
#define TCSADRAIN  TCSETSW
#define TCSAFLUSH  TCSETSF

static __inline__ int tcgetattr(int __fd, struct termios *__s)
{
  return ioctl(__fd, TCGETS, __s);
}

static __inline__ int tcsetattr(int __fd, int __opt, const struct termios *__s)
{
  return ioctl(__fd, __opt, (void *)__s);
}

static __inline__ int tcflow(int __fd, int __action)
{
  return ioctl(__fd, TCXONC, (void *)(intptr_t)__action);
}

static __inline__ int tcflush(int __fd, int __queue)
{
  return ioctl(__fd, TCFLSH, (void *)(intptr_t)__queue);
}

static __inline__ pid_t tcgetpgrp(int __fd)
{
  pid_t __p;
  return ioctl(__fd, TIOCGPGRP, &__p) ? (pid_t)-1 : __p;
}

static __inline__ pid_t tcgetsid(int __fd)
{
  pid_t __p;
  return ioctl(__fd, TIOCGSID, &__p) ? (pid_t)-1 : __p;
}  

static __inline__ int tcsendbreak(int __fd, int __duration)
{
  return ioctl(__fd, TCSBRKP, (void *)(uintptr_t)__duration);
}

static __inline__ int tcsetpgrp(int __fd, pid_t __p)
{
  return ioctl(__fd, TIOCSPGRP, &__p);
}

static __inline__ speed_t cfgetospeed(const struct termios *__s)
{
  return (speed_t)(__s->c_cflag & CBAUD);
}

static __inline__ speed_t cfgetispeed(const struct termios *__s)
{
  return (speed_t)(__s->c_cflag & CBAUD);
}

static __inline__ int cfsetospeed(struct termios *__s, speed_t __v)
{
  __s->c_cflag = (__s->c_cflag & ~CBAUD) | (__v & CBAUD);
  return 0;
}

static __inline__ int cfsetispeed(struct termios *__s, speed_t __v)
{
  __s->c_cflag = (__s->c_cflag & ~CBAUD) | (__v & CBAUD);
  return 0;
}

#endif /* _TERMIOS_H */
