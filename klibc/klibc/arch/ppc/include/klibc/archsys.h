/*
 * arch/ppc/include/klibc/archsys.h
 *
 * Architecture-specific syscall definitions
 */

#ifndef _KLIBC_ARCHSYS_H
#define _KLIBC_ARCHSYS_H

/* PowerPC seems to lack _syscall6() in its headers */
/* This seems to work on both 32- and 64-bit ppc */

#ifndef _syscall6

#define _syscall6(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4, \
          type5,arg5,type6,arg6) \
type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5,type6 arg6) \
{ \
        unsigned long __sc_ret, __sc_err;                               \
        {                                                               \
                register unsigned long __sc_0 __asm__ ("r0");           \
                register unsigned long __sc_3 __asm__ ("r3");           \
                register unsigned long __sc_4 __asm__ ("r4");           \
                register unsigned long __sc_5 __asm__ ("r5");           \
                register unsigned long __sc_6 __asm__ ("r6");           \
                register unsigned long __sc_7 __asm__ ("r7");           \
                register unsigned long __sc_8 __asm__ ("r8");           \
                                                                        \
                __sc_3 = (unsigned long) (arg1);                        \
                __sc_4 = (unsigned long) (arg2);                        \
                __sc_5 = (unsigned long) (arg3);                        \
                __sc_6 = (unsigned long) (arg4);                        \
                __sc_7 = (unsigned long) (arg5);                        \
                __sc_8 = (unsigned long) (arg6);                        \
                __sc_0 = __NR_##name;                                   \
                __asm__ __volatile__                                    \
                        ("sc           \n\t"                            \
                         "mfcr %1      "                                \
                        : "=&r" (__sc_3), "=&r" (__sc_0)                \
                        : "0"   (__sc_3), "1"   (__sc_0),               \
                          "r"   (__sc_4),                               \
                          "r"   (__sc_5),                               \
                          "r"   (__sc_6),                               \
                          "r"   (__sc_7),                               \
                          "r"   (__sc_8)                                \
                        : __syscall_clobbers);                          \
                __sc_ret = __sc_3;                                      \
                __sc_err = __sc_0;                                      \
        }                                                               \
        __syscall_return (type);                                        \
}

#endif /* _syscall6() missing */

#endif /* _KLIBC_ARCHSYS_H */
