/*
 * sched.h
 */

#ifndef _SCHED_H
#define _SCHED_H

#include <klibc/extern.h>

/* linux/sched.h is unusable; put the declarations we need here... */

#define SCHED_NORMAL            0
#define SCHED_FIFO              1
#define SCHED_RR                2

struct sched_param {
  int sched_priority;
};

__extern int sched_setschedule(pid_t, int, const struct sched_param *);
__extern int sched_yield(void);

#endif /* _SCHED_H */
