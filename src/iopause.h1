/* Public domain. */

#ifndef IOPAUSE_H
#define IOPAUSE_H

/* sysdep: -poll */

typedef struct {
  int fd;
  short events;
  short revents;
} iopause_fd;

#define IOPAUSE_READ 1
#define IOPAUSE_WRITE 4

#include "taia.h"

extern void iopause(iopause_fd *,unsigned int,struct taia *,struct taia *);

#endif
