/*
 * sys/time.h
 */

#ifndef _SYS_TIME_H
#define _SYS_TIME_H

#include <klibc/extern.h>
#include <sys/types.h>
#include <linux/time.h>

__extern int gettimeofday(struct timeval *, struct timezone *);
__extern int settimeofday(const struct timeval *, const struct timezone *);
__extern int getitimer(int, struct itimerval *);
__extern int setitimer(int, const struct itimerval *, struct itimerval *);

#endif /* _SYS_TIME_H */
