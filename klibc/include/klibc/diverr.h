/*
 * klibc/diverr.h
 */

#ifndef _KLIBC_DIVERR_H
#define _KLIBC_DIVERR_H

#include <signal.h>

static __inline__ void
__divide_error(void)
{
  raise(SIGFPE);
}

#endif /* _KLIBC_DIVERR_H */
