/*
 * arch/x86_64/include/klibc/archsys.h
 *
 * Architecture-specific syscall definitions
 */

#ifndef _KLIBC_ARCHSYS_H
#define _KLIBC_ARCHSYS_H

/* The x86-64 syscall headers are needlessly inefficient */

#undef _syscall0
#undef _syscall1
#undef _syscall2
#undef _syscall3
#undef _syscall4
#undef _syscall5
#undef _syscall6

#define _syscall0(type,name) \
type name (void) \
{ \
long __res; \
__asm__ volatile (__syscall \
        : "=a" (__res) \
        : "0" (__NR_##name) \
        : __syscall_clobber); \
__syscall_return(type,__res); \
}

#define _syscall1(type,name,type1,arg1) \
type name (type1 arg1) \
{ \
long __res; \
__asm__ volatile (__syscall \
        : "=a" (__res) \
        : "0" (__NR_##name),"D" (arg1) \
        : __syscall_clobber); \
__syscall_return(type,__res); \
}

#define _syscall2(type,name,type1,arg1,type2,arg2) \
type name (type1 arg1,type2 arg2) \
{ \
long __res; \
__asm__ volatile (__syscall \
        : "=a" (__res) \
        : "0" (__NR_##name),"D" (arg1),"S" (arg2) \
        : __syscall_clobber); \
__syscall_return(type,__res); \
}

#define _syscall3(type,name,type1,arg1,type2,arg2,type3,arg3) \
type name (type1 arg1,type2 arg2,type3 arg3) \
{ \
long __res; \
__asm__ volatile (__syscall \
        : "=a" (__res) \
        : "0" (__NR_##name),"D" (arg1),"S" (arg2), \
          "d" (arg3) \
        : __syscall_clobber); \
__syscall_return(type,__res); \
}

#define _syscall4(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4) \
type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4) \
{ \
long __res; \
register type4 __r10 asm("%r10") = arg4; \
__asm__ volatile (__syscall \
        : "=a" (__res) \
        : "0" (__NR_##name),"D" (arg1),"S" (arg2), \
          "d" (arg3),"r" (__r10) \
        : __syscall_clobber); \
__syscall_return(type,__res); \
}

#define _syscall5(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4, \
          type5,arg5) \
type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5) \
{ \
long __res; \
register type4 __r10 asm("%r10") = arg4; \
register type5 __r8  asm("%r8")  = arg5; \
__asm__ volatile (__syscall \
        : "=a" (__res) \
        : "0" (__NR_##name),"D" (arg1),"S" (arg2), \
          "d" (arg3),"r" (__r10),"r" (__r8) \
        : __syscall_clobber); \
__syscall_return(type,__res); \
}

#define _syscall6(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4, \
          type5,arg5,type6,arg6) \
type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5,type6 arg6) \
{ \
long __res; \
register type4 __r10 asm("%r10") = arg4; \
register type5 __r8  asm("%r8")  = arg5; \
register type6 __r9  asm("%r9")  = arg6; \
__asm__ volatile (__syscall \
        : "=a" (__res) \
        : "0" (__NR_##name),"D" (arg1),"S" (arg2), \
          "d" (arg3),"r" (__r10),"r" (__r8), "r" (__r9) \
        : __syscall_clobber); \
__syscall_return(type,__res); \
}

#endif /* _KLIBC_ARCHSYS_H */
