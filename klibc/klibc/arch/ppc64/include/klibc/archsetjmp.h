/*
 * arch/ppc64/include/klibc/archsetjmp.h
 */

#ifndef _KLIBC_ARCHSETJMP_H
#define _KLIBC_ARCHSETJMP_H

struct __jmp_buf {
  unsigned long __r2;
  unsigned long __sp;
  unsigned long __lr;
  unsigned long __cr;
  unsigned long __r13;
  unsigned long __r14;
  unsigned long __r15;
  unsigned long __r16;
  unsigned long __r17;
  unsigned long __r18;
  unsigned long __r19;
  unsigned long __r20;
  unsigned long __r21;
  unsigned long __r22;
  unsigned long __r23;
  unsigned long __r24;
  unsigned long __r25;
  unsigned long __r26;
  unsigned long __r27;
  unsigned long __r28;
  unsigned long __r29;
  unsigned long __r30;
  unsigned long __r31;
};

typedef struct __jmp_buf jmp_buf[1];

#endif /* _SETJMP_H */
