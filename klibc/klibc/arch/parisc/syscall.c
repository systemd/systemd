/*
 * arch/parisc/syscall.c
 *
 * This function is called from a stub with %r20 already set up.
 * Compile this function with -ffixed-r20 so that it doesn't clobber
 * this register by mistake.
 */

#include <klibc/compiler.h>
#include <errno.h>

long __syscall_common(long a0, long a1, long a2, long a3, long a4, long a5)
{
  register unsigned long rv asm ("r28");

  asm volatile("\tble 0x100(%%sr2, %%r0)\n"
	       : "=r" (rv)
	       : "r" (a0), "r" (a1), "r" (a2), "r" (a3), "r" (a4), "r" (a5)
	       : "%r1", "%r2", "%r29", "%r31");

  if ( __unlikely(rv >= -4095UL) ) {
    errno = -rv;
    return -1L;
  } else {
    return (long)rv;
  }
}

  
