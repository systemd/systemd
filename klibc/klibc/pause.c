/*
 * pause.c
 */

#include <stddef.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/syscall.h>

#ifdef __NR_pause

_syscall0(int,pause);

#else

int pause(void)
{
  return select(0,NULL,NULL,NULL,NULL);
}

#endif
