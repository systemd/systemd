/*
 * arch/parisc/include/klibc/archsetjmp.h
 */

#ifndef _KLIBC_ARCHSETJMP_H
#define _KLIBC_ARCHSETJMP_H

struct __jmp_buf {
  double regs[21];
};

typedef struct __jmp_buf jmp_buf[1];

#endif /* _SETJMP_H */
