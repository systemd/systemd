/*
 * sys/times.h
 */

#ifndef _SYS_TIMES_H
#define _SYS_TIMES_H

#include <linux/times.h>

__extern clock_t times(struct tms *);
__extern int gettimeofday(struct timeval *, struct timezone *);
__extern int settimeofday(const struct timeval *, const struct timezone *);

#endif /* _SYS_TIMES_H */
