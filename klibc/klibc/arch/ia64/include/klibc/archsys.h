/*
 * arch/ia64/include/klibc/archsys.h
 *
 * Architecture-specific syscall definitions
 */

#ifndef _KLIBC_ARCHSYS_H
#define _KLIBC_ARCHSYS_H

#define __IA64_BREAK "break 0x100000;;\n\t"

#define _syscall0(type,name)                                            \
type                                                                    \
name (void)                                                             \
{                                                                       \
       register long _r8 asm ("r8");					\
       register long _r10 asm ("r10");                                  \
       register long _r15 asm ("r15") = __NR_##name;                    \
       long _retval;                                                    \
       __asm __volatile (__IA64_BREAK                                   \
                         : "=r" (_r8), "=r" (_r10), "=r" (_r15)         \
                         : "2" (_r15) ASM_ARGS_0                        \
                         : "memory" ASM_CLOBBERS_0);                    \
       _retval = _r8;                                                   \
       if (_r10 == -1) {                                                \
               errno = (_retval);                                       \
               _retval = -1;                                            \
       }                                                                \
       return _retval;                                                  \
}

#define _syscall1(type,name,type1,arg1)                                 \
type                                                                    \
name (type1 arg1)                                                       \
{                                                                       \
       register long _r8 asm ("r8");					\
       register long _r10 asm ("r10");                                  \
       register long _r15 asm ("r15") = __NR_##name;                    \
       long _retval;                                                    \
       LOAD_ARGS_1(arg1);                                               \
       __asm __volatile (__IA64_BREAK                                   \
                         : "=r" (_r8), "=r" (_r10), "=r" (_r15),        \
                           ASM_OUTARGS_1                                \
                         : "2" (_r15) ASM_ARGS_1                        \
                         : "memory" ASM_CLOBBERS_1);                    \
       _retval = _r8;                                                   \
       if (_r10 == -1) {                                                \
               errno = (_retval);                                       \
               _retval = -1;                                            \
       }                                                                \
       return _retval;                                                  \
}

#define _syscall2(type,name,type1,arg1,type2,arg2)                      \
type                                                                    \
name (type1 arg1, type2 arg2)                                           \
{                                                                       \
       register long _r8 asm ("r8");					\
       register long _r10 asm ("r10");                                  \
       register long _r15 asm ("r15") = __NR_##name;                    \
       long _retval;                                                    \
       LOAD_ARGS_2(arg1, arg2);                                         \
       __asm __volatile (__IA64_BREAK                                   \
                         : "=r" (_r8), "=r" (_r10), "=r" (_r15),        \
                           ASM_OUTARGS_2                                \
                         : "2" (_r15) ASM_ARGS_2                        \
                         : "memory" ASM_CLOBBERS_2);                    \
       _retval = _r8;                                                   \
       if (_r10 == -1) {                                                \
               errno = (_retval);                                       \
               _retval = -1;                                            \
       }                                                                \
       return _retval;                                                  \
}

#define _syscall3(type,name,type1,arg1,type2,arg2,type3,arg3)           \
type                                                                    \
name (type1 arg1, type2 arg2, type3 arg3)                               \
{                                                                       \
       register long _r8 asm ("r8");					\
       register long _r10 asm ("r10");                                  \
       register long _r15 asm ("r15") = __NR_##name;                    \
       long _retval;                                                    \
       LOAD_ARGS_3(arg1, arg2, arg3);                                   \
       __asm __volatile (__IA64_BREAK                                   \
                         : "=r" (_r8), "=r" (_r10), "=r" (_r15),        \
                           ASM_OUTARGS_3                                \
                         : "2" (_r15) ASM_ARGS_3                        \
                         : "memory" ASM_CLOBBERS_3);                    \
       _retval = _r8;                                                   \
       if (_r10 == -1) {                                                \
               errno = (_retval);                                       \
               _retval = -1;                                            \
       }                                                                \
       return _retval;                                                  \
}

#define _syscall4(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4) \
type                                                                    \
name (type1 arg1, type2 arg2, type3 arg3, type4 arg4)                   \
{                                                                       \
       register long _r8 asm ("r8");					\
       register long _r10 asm ("r10");                                  \
       register long _r15 asm ("r15") = __NR_##name;                    \
       long _retval;                                                    \
       LOAD_ARGS_4(arg1, arg2, arg3, arg4);                             \
       __asm __volatile (__IA64_BREAK                                   \
                         : "=r" (_r8), "=r" (_r10), "=r" (_r15),        \
                           ASM_OUTARGS_4                                \
                         : "2" (_r15) ASM_ARGS_4                        \
                         : "memory" ASM_CLOBBERS_4);                    \
       _retval = _r8;                                                   \
       if (_r10 == -1) {                                                \
               errno = (_retval);                                       \
               _retval = -1;                                            \
       }                                                                \
       return _retval;                                                  \
}

#define _syscall5(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4,type5,arg5) \
type                                                                    \
name (type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5)       \
{                                                                       \
       register long _r8 asm ("r8");					\
       register long _r10 asm ("r10");                                  \
       register long _r15 asm ("r15") = __NR_##name;                    \
       long _retval;                                                    \
       LOAD_ARGS_5(arg1, arg2, arg3, arg4, arg5);                       \
       __asm __volatile (__IA64_BREAK                                   \
                         : "=r" (_r8), "=r" (_r10), "=r" (_r15),        \
                           ASM_OUTARGS_5                                \
                         : "2" (_r15) ASM_ARGS_5                        \
                         : "memory" ASM_CLOBBERS_5);                    \
       _retval = _r8;                                                   \
       if (_r10 == -1) {                                                \
               errno = (_retval);                                       \
               _retval = -1;                                            \
       }                                                                \
       return _retval;                                                  \
}

#define _syscall6(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4,type5,arg5,type6,arg6) \
type                                                                    \
name (type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5, type6 arg6)       \
{                                                                       \
       register long _r8 asm ("r8");					\
       register long _r10 asm ("r10");                                  \
       register long _r15 asm ("r15") = __NR_##name;                    \
       long _retval;                                                    \
       LOAD_ARGS_6(arg1, arg2, arg3, arg4, arg5, arg6);                 \
       __asm __volatile (__IA64_BREAK                                   \
                         : "=r" (_r8), "=r" (_r10), "=r" (_r15),        \
                           ASM_OUTARGS_6                                \
                         : "2" (_r15) ASM_ARGS_6                        \
                         : "memory" ASM_CLOBBERS_6);                    \
       _retval = _r8;                                                   \
       if (_r10 == -1) {                                                \
               errno = (_retval);                                       \
               _retval = -1;                                            \
       }                                                                \
       return _retval;                                                  \
}
  

#define LOAD_ARGS_0()   do { } while (0)
#define LOAD_ARGS_1(out0)				\
  register long _out0 asm ("out0") = (long) (out0);	\
  LOAD_ARGS_0 ()
#define LOAD_ARGS_2(out0, out1)				\
  register long _out1 asm ("out1") = (long) (out1);	\
  LOAD_ARGS_1 (out0)
#define LOAD_ARGS_3(out0, out1, out2)			\
  register long _out2 asm ("out2") = (long) (out2);	\
  LOAD_ARGS_2 (out0, out1)
#define LOAD_ARGS_4(out0, out1, out2, out3)		\
  register long _out3 asm ("out3") = (long) (out3);	\
  LOAD_ARGS_3 (out0, out1, out2)
#define LOAD_ARGS_5(out0, out1, out2, out3, out4)	\
  register long _out4 asm ("out4") = (long) (out4);	\
  LOAD_ARGS_4 (out0, out1, out2, out3)
#define LOAD_ARGS_6(out0, out1, out2, out3, out4, out5)	\
  register long _out5 asm ("out5") = (long) (out5);	\
  LOAD_ARGS_5 (out0, out1, out2, out3, out4)

#define ASM_OUTARGS_1	"=r" (_out0)
#define ASM_OUTARGS_2	ASM_OUTARGS_1, "=r" (_out1)
#define ASM_OUTARGS_3	ASM_OUTARGS_2, "=r" (_out2)
#define ASM_OUTARGS_4	ASM_OUTARGS_3, "=r" (_out3)
#define ASM_OUTARGS_5	ASM_OUTARGS_4, "=r" (_out4)
#define ASM_OUTARGS_6	ASM_OUTARGS_5, "=r" (_out5)

#define ASM_ARGS_0
#define ASM_ARGS_1	ASM_ARGS_0, "3" (_out0)
#define ASM_ARGS_2	ASM_ARGS_1, "4" (_out1)
#define ASM_ARGS_3	ASM_ARGS_2, "5" (_out2)
#define ASM_ARGS_4	ASM_ARGS_3, "6" (_out3)
#define ASM_ARGS_5	ASM_ARGS_4, "7" (_out4)
#define ASM_ARGS_6	ASM_ARGS_5, "8" (_out5)

#define ASM_CLOBBERS_0	ASM_CLOBBERS_1, "out0"
#define ASM_CLOBBERS_1	ASM_CLOBBERS_2, "out1"
#define ASM_CLOBBERS_2	ASM_CLOBBERS_3, "out2"
#define ASM_CLOBBERS_3	ASM_CLOBBERS_4, "out3"
#define ASM_CLOBBERS_4	ASM_CLOBBERS_5, "out4"
#define ASM_CLOBBERS_5	ASM_CLOBBERS_6, "out5"
#define ASM_CLOBBERS_6	, "out6", "out7",				\
  /* Non-stacked integer registers, minus r8, r10, r15.  */		\
  "r2", "r3", "r9", "r11", "r12", "r13", "r14", "r16", "r17", "r18",	\
  "r19", "r20", "r21", "r22", "r23", "r24", "r25", "r26", "r27",	\
  "r28", "r29", "r30", "r31",						\
  /* Predicate registers.  */						\
  "p6", "p7", "p8", "p9", "p10", "p11", "p12", "p13", "p14", "p15",	\
  /* Non-rotating fp registers.  */					\
  "f6", "f7", "f8", "f9", "f10", "f11", "f12", "f13", "f14", "f15",	\
  /* Branch registers.  */						\
  "b6", "b7"

#endif /* _KLIBC_ARCHSYS_H */
