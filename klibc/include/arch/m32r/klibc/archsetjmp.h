/*
 * arch/m32r/include/klibc/archsetjmp.h
 */

#ifndef _KLIBC_ARCHSETJMP_H
#define _KLIBC_ARCHSETJMP_H

struct __jmp_buf {
  unsigned long __r8;
  unsigned long __r9;
  unsigned long __r10;
  unsigned long __r11;
  unsigned long __r12;
  unsigned long __r13;
  unsigned long __r14;
  unsigned long __r15;
};

typedef struct __jmp_buf jmp_buf[1];

#endif /* _KLIBC_ARCHSETJMP_H */
