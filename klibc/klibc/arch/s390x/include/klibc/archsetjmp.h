/*
 * arch/s390x/include/klibc/archsetjmp.h
 */

#ifndef _KLIBC_ARCHSETJMP_H
#define _KLIBC_ARCHSETJMP_H

struct __jmp_buf {
  uint64_t __gregs[10]; /* general registers r6-r15 */
  uint64_t __fpregs[4]; /* fp registers f1, f3, f5, f7 */
};

typedef struct __jmp_buf jmp_buf[1];

#endif /* _SETJMP_H */
