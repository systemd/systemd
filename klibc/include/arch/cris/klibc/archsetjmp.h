/*
 * arch/cris/include/klibc/archsetjmp.h
 */

#ifndef _KLIBC_ARCHSETJMP_H
#define _KLIBC_ARCHSETJMP_H

struct __jmp_buf {
  unsigned long __r0;
  unsigned long __r1;
  unsigned long __r2;
  unsigned long __r3;
  unsigned long __r4;
  unsigned long __r5;
  unsigned long __r6;
  unsigned long __r7;
  unsigned long __r8;
  unsigned long __sp;
  unsigned long __srp;
};

typedef struct __jmp_buf jmp_buf[1];

#endif /* _KLIBC_ARCHSETJMP_H */
