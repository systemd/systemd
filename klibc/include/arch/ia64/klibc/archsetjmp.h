/*
 * arch/ia64/include/klibc/archsetjmp.h
 *
 * Code borrowed from the FreeBSD kernel.
 *
 */

#ifndef _KLIBC_ARCHSETJMP_H
#define _KLIBC_ARCHSETJMP_H

/* User code must not depend on the internal representation of jmp_buf. */
#define _JBLEN 0x200

/* guaranteed 128-bit alignment! */
typedef char jmp_buf[_JBLEN] __attribute__ ((aligned (16)));

#endif
