/*
 * arch/i386/include/klibc/diverr.h
 */

#ifndef _KLIBC_DIVERR_H
#define _KLIBC_DIVERR_H

#include <signal.h>

static __inline__ void
__divide_error(void)
{
  asm volatile("divl %0" :: "rm" (0) : "eax", "edx");
}

#endif /* _KLIBC_DIVERR_H */
