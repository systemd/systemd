/*
 * arch/s390x/include/klibc/archsys.h
 *
 * Architecture-specific syscall definitions
 */

#ifndef _KLIBC_ARCHSYS_H
#define _KLIBC_ARCHSYS_H

/* S/390X only has five syscall parameters, and uses a structure for
   6-argument syscalls. */

#ifndef _syscall6

#define _syscall6(type,name,type1,arg1,type2,arg2,type3,arg3,\
                  type4,arg4,type5,arg5,type6,arg6)          \
type name(type1 arg1, type2 arg2, type3 arg3, type4 arg4,    \
          type5 arg5, type6 arg6) {			     \
	unsigned long  __arg[6] = {			     \
		(unsigned long) arg1, 			     \
		(unsigned long) arg2, 			     \
		(unsigned long) arg3, 			     \
		(unsigned long) arg4, 			     \
		(unsigned long) arg5,			     \
		(unsigned long) arg6 			     \
	};						     \
	register void *__argp asm("2") = &__arg;	     \
	long __res;					     \
	__asm__ __volatile__ (               	             \
                "    svc %b1\n"                              \
                "    lgr  %0,2"                              \
                : "=d" (__res)                               \
                : "i" (__NR_##name),                         \
                  "d" (__argp)				     \
		: _svc_clobber);			     \
	__syscall_return(type, __res);			     \
}

#endif /* _syscall6() missing */

#endif /* _KLIBC_ARCHSYS_H */
