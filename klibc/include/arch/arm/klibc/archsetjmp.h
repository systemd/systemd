/*
 * arch/i386/include/klibc/archsetjmp.h
 */

#ifndef _KLIBC_ARCHSETJMP_H
#define _KLIBC_ARCHSETJMP_H

struct __jmp_buf {
  unsigned int regs[10];
};

typedef struct __jmp_buf jmp_buf[1];

#endif /* _SETJMP_H */
