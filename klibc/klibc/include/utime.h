/*
 * utime.h
 */

#ifndef _UTIME_H
#define _UTIME_H

#include <klibc/extern.h>
#include <sys/types.h>
#include <linux/utime.h>

__extern int utime(const char *, const struct utimbuf *);

#endif /* _UTIME_H */

