/*
 * alarm.c
 */

#include <sys/time.h>
#include <sys/syscall.h>

#ifndef __NR_alarm

/* Emulate alarm() via setitimer() */

unsigned int alarm(unsigned int seconds)
{
  struct itimerval iv;

  iv.it_interval.tv_sec = iv.it_interval.tv_usec = 0;
  iv.it_value.tv_sec = seconds;
  iv.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &iv, &iv);

  return iv.it_value.tv_sec + (iv.it_value.tv_usec ? 1 : 0);
}

#endif
