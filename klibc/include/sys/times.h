/*
 * sys/times.h
 */

#ifndef _SYS_TIMES_H
#define _SYS_TIMES_H

#include <klibc/extern.h>
#include <sys/types.h>
#include <linux/times.h>

__extern clock_t times(struct tms *);

#endif /* _SYS_TIMES_H */
