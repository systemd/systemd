/*
 * arch/s390/include/klibc/archsetjmp.h
 */

#ifndef _KLIBC_ARCHSETJMP_H
#define _KLIBC_ARCHSETJMP_H

struct __jmp_buf {
  uint32_t __gregs[10]; /* general registers r6-r15 */
  uint64_t __fpregs[2]; /* fp registers f4 and f6   */
};

typedef struct __jmp_buf jmp_buf[1];

#endif /* _SETJMP_H */
