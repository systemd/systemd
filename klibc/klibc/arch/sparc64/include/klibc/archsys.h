/*
 * arch/sparc64/include/klibc/archsys.h
 *
 * Architecture-specific syscall definitions
 */

#ifndef _KLIBC_ARCHSYS_H
#define _KLIBC_ARCHSYS_H

/* The Linux 2.5.31 SPARC64 syscall macros are just plain broken */

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
  register unsigned long __g1 __asm__ ("g1") = __NR_##name; \
  register unsigned long __ret __asm__("o0"); \
  __asm__ __volatile__ ("t 0x6d\n\t" \
      "bcs,a %%xcc, 1f\n\t" \
      " st %0,%1\n\t" \
      "1:" \
      "movcs %%xcc,-1,%0\n" \
      : "=&r" (__ret), "+m" (errno) \
      : "r" (__g1) \
      : "cc"); \
  return (type) __ret; \
}

#define _syscall1(type,name,type1,arg1) \
type name (type1 arg1) \
{ \
  register unsigned long __g1 __asm__ ("g1") = __NR_##name; \
  register unsigned long __ret __asm__("o0"); \
  type1 __o0 = (arg1); \
  __asm__ __volatile__ ("t 0x6d\n\t" \
      "bcs,a %%xcc, 1f\n\t" \
      " st %0,%1\n\t" \
      "1:" \
      "movcs %%xcc,-1,%0\n" \
      : "=&r" (__ret), "+m" (errno) \
      : "0" (__o0), "r" (__g1) \
      : "cc"); \
  return (type) __ret; \
}

#define _syscall2(type,name,type1,arg1,type2,arg2) \
type name (type1 arg1,type2 arg2) \
{ \
  register unsigned long __g1 __asm__ ("g1") = __NR_##name; \
  register unsigned long __ret __asm__("o0"); \
  type1 __o0 = (arg1); \
  register type2 __o1 __asm__ ("o1") = (arg2); \
  __asm__ __volatile__ ("t 0x6d\n\t" \
      "bcs,a %%xcc, 1f\n\t" \
      " st %0,%1\n\t" \
      "1:" \
      "movcs %%xcc,-1,%0\n" \
      : "=&r" (__ret), "+m" (errno) \
      : "0" (__o0), "r" (__o1), "r" (__g1) \
      : "cc"); \
  return (type) __ret; \
}

#define _syscall3(type,name,type1,arg1,type2,arg2,type3,arg3) \
type name (type1 arg1,type2 arg2,type3 arg3) \
{ \
  register unsigned long __g1 __asm__ ("g1") = __NR_##name; \
  register unsigned long __ret __asm__("o0"); \
  type1 __o0 = (arg1); \
  register type2 __o1 __asm__ ("o1") = (arg2); \
  register type3 __o2 __asm__ ("o2") = (arg3); \
  __asm__ __volatile__ ("t 0x6d\n\t" \
      "bcs,a %%xcc, 1f\n\t" \
      " st %0,%1\n\t" \
      "1:" \
      "movcs %%xcc,-1,%0\n" \
      : "=&r" (__ret), "+m" (errno) \
      : "0" (__o0), "r" (__o1), "r" (__o2), "r" (__g1) \
      : "cc"); \
  return (type) __ret; \
}

#define _syscall4(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4) \
type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4) \
{ \
  register unsigned long __g1 __asm__ ("g1") = __NR_##name; \
  register unsigned long __ret __asm__("o0"); \
  type1 __o0 = (arg1); \
  register type2 __o1 __asm__ ("o1") = (arg2); \
  register type3 __o2 __asm__ ("o2") = (arg3); \
  register type4 __o3 __asm__ ("o3") = (arg4); \
  __asm__ __volatile__ ("t 0x6d\n\t" \
      "bcs,a %%xcc, 1f\n\t" \
      " st %0,%1\n\t" \
      "1:" \
      "movcs %%xcc,-1,%0\n" \
      : "=&r" (__ret), "+m" (errno) \
      : "0" (__o0), "r" (__o1), "r" (__o2), "r" (__o3), "r" (__g1) \
      : "cc"); \
  return (type) __ret; \
}

#define _syscall5(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4,\
  type5,arg5) \
type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5) \
{ \
  register unsigned long __g1 __asm__ ("g1") = __NR_##name; \
  register unsigned long __ret __asm__("o0"); \
  type1 __o0 = (arg1); \
  register type2 __o1 __asm__ ("o1") = (arg2); \
  register type3 __o2 __asm__ ("o2") = (arg3); \
  register type4 __o3 __asm__ ("o3") = (arg4); \
  register type5 __o4 __asm__ ("o4") = (arg5); \
  __asm__ __volatile__ ("t 0x6d\n\t" \
      "bcs,a %%xcc, 1f\n\t" \
      " st %0,%1\n\t" \
      "1:" \
      "movcs %%xcc,-1,%0\n" \
      : "=&r" (__ret), "+m" (errno) \
      : "0" (__o0), "r" (__o1), "r" (__o2), "r" (__o3), "r" (__o4), \
        "r" (__g1) \
      : "cc"); \
  return (type) __ret; \
}

#define _syscall6(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4, \
  type5,arg5,type6,arg6) \
type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5,type6 arg6) \
{ \
  register unsigned long __g1 __asm__ ("g1") = __NR_##name; \
  register unsigned long __ret __asm__("o0"); \
  type1 __o0 = (arg1); \
  register type2 __o1 __asm__ ("o1") = (arg2); \
  register type3 __o2 __asm__ ("o2") = (arg3); \
  register type4 __o3 __asm__ ("o3") = (arg4); \
  register type5 __o4 __asm__ ("o4") = (arg5); \
  register type6 __o5 __asm__ ("o5") = (arg6); \
  __asm__ __volatile__ ("t 0x6d\n\t" \
      "bcs,a %%xcc, 1f\n\t" \
      " st %0,%1\n\t" \
      "1:" \
      "movcs %%xcc,-1,%0\n" \
      : "=&r" (__ret), "+m" (errno) \
      : "0" (__o0), "r" (__o1), "r" (__o2), "r" (__o3), "r" (__o4), \
        "r" (__o5), "r" (__g1) \
      : "cc"); \
  return (type) __ret; \
}

#endif /* _KLIBC_ARCHSYS_H */
