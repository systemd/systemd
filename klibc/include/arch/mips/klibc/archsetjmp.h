/*
 * arch/mips/include/klibc/archsetjmp.h
 */

#ifndef _KLIBC_ARCHSETJMP_H
#define _KLIBC_ARCHSETJMP_H

struct __jmp_buf {
  unsigned long __s0;
  unsigned long __s1;
  unsigned long __s2;
  unsigned long __s3;
  unsigned long __s4;
  unsigned long __s5;
  unsigned long __s6;
  unsigned long __s7;
  unsigned long __gp;
  unsigned long __sp;
  unsigned long __s8;
  unsigned long __ra;
  unsigned long __f20;
  unsigned long __f21;
  unsigned long __f22;
  unsigned long __f23;
  unsigned long __f24;
  unsigned long __f25;
  unsigned long __f26;
  unsigned long __f27;
  unsigned long __f28;
  unsigned long __f29;
  unsigned long __f30;
  unsigned long __f31;
  unsigned long __fcr31;
  unsigned long __unused;
} __attribute__((aligned(8)));

typedef struct __jmp_buf jmp_buf[1];

#endif /* _KLIBC_ARCHSETJMP_H */
