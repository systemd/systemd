/*
 * arch/sparc/include/klibc/archsys.h
 *
 * Architecture-specific syscall definitions
 */

#ifndef _KLIBC_ARCHSYS_H
#define _KLIBC_ARCHSYS_H

/* fork and vfork return the "other process" pid in %o0 and an
   "is child" flag in %o1... */

#define _syscall0_forkish(type,name) \
type name(void) \
{ \
register long __g1 __asm__ ("g1") = __NR_##name; \
register unsigned long __o0 __asm__ ("o0"); \
register unsigned long __o1 __asm__ ("o1"); \
__asm__ __volatile__ ("t 0x10\n\t" \
		      "bcc 1f\n\t" \
		      "mov %%o0, %0\n\t" \
		      "sub %%g0, %%o0, %0\n\t" \
		      "1:\n\t" \
		      : "=r" (__o0), "=r" (__o1)\
		      : "r" (__g1) \
		      : "cc"); \
if ((unsigned long)__o0 < (unsigned long)-255) \
    return (type)(__o0 & (__o1-1)); \
errno = (int)-__o0; \
return -1; \
}

/* SPARC seems to lack _syscall6() in its headers */

#ifndef _syscall6

#define _syscall6(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4, \
  type5,arg5,type6,arg6) \
type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5,type6 arg6) \
{ \
long __res; \
register long __g1 __asm__ ("g1") = __NR_##name; \
register long __o0 __asm__ ("o0") = (long)(arg1); \
register long __o1 __asm__ ("o1") = (long)(arg2); \
register long __o2 __asm__ ("o2") = (long)(arg3); \
register long __o3 __asm__ ("o3") = (long)(arg4); \
register long __o4 __asm__ ("o4") = (long)(arg5); \
register long __o5 __asm__ ("o5") = (long)(arg6); \
__asm__ __volatile__ ("t 0x10\n\t" \
      "bcc 1f\n\t" \
      "mov %%o0, %0\n\t" \
      "sub %%g0, %%o0, %0\n\t" \
      "1:\n\t" \
      : "=r" (__res), "=&r" (__o0) \
      : "1" (__o0), "r" (__o1), "r" (__o2), "r" (__o3), "r" (__o4), "r" (__o5), "r" (__g1) \
      : "cc"); \
if (__res < -255 || __res>=0) \
return (type) __res; \
errno = -__res; \
return (type)-1; \
}

#endif /* _syscall6 missing */

#endif /* _KLIBC_ARCHSYS_H */
