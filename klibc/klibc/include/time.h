/*
 * time.h
 */

#ifndef _TIME_H
#define _TIME_H

#include <klibc/extern.h>
#include <sys/time.h>

__extern time_t time(time_t *);
__extern int nanosleep(const struct timespec *, struct timespec *);

#endif /* _TIME_H */
