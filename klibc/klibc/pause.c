/*
 * pause.c
 */

#include <stddef.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/syscall.h>

#ifndef __NR_pause

int pause(void)
{
  return select(0,NULL,NULL,NULL,NULL);
}

#endif
