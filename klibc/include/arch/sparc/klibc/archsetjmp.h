/*
 * arch/sparc/include/klibc/archsetjmp.h
 */

#ifndef _KLIBC_ARCHSETJMP_H
#define _KLIBC_ARCHSETJMP_H

struct __jmp_buf {
  unsigned long __sp;
  unsigned long __fp;
  unsigned long __pc;
};

typedef struct __jmp_buf jmp_buf[1];

#endif /* _SETJMP_H */
