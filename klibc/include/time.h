/*
 * time.h
 */

#ifndef _TIME_H
#define _TIME_H

#include <klibc/extern.h>
#include <sys/time.h>

__extern time_t time(time_t *);
__extern int nanosleep(const struct timespec *, struct timespec *);

/* klibc-specific but useful since we don't have floating point */
__extern char *strtotimeval(const char *str, struct timeval *tv);
__extern char *strtotimespec(const char *str, struct timespec *tv);

#endif /* _TIME_H */
