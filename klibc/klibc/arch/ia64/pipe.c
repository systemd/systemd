/*
 * pipe.c
 */

#include <sys/syscall.h>
#include <klibc/archsys.h>

#define ASM_CLOBBERS ,"out2", "out3", "out4", "out5", "out6", "out7",    \
   /* Non-stacked integer registers, minus r8, r9, r10, r15.  */	\
  "r2", "r3", "r11", "r12", "r13", "r14", "r16", "r17", "r18",	        \
  "r19", "r20", "r21", "r22", "r23", "r24", "r25", "r26", "r27",	\
  "r28", "r29", "r30", "r31",						\
  /* Predicate registers.  */						\
  "p6", "p7", "p8", "p9", "p10", "p11", "p12", "p13", "p14", "p15",	\
  /* Non-rotating fp registers.  */					\
  "f6", "f7", "f8", "f9", "f10", "f11", "f12", "f13", "f14", "f15",	\
  /* Branch registers.  */						\
  "b6", "b7"

int pipe(int *filedes)
{
	register long _r8 asm("r8");
	register long _r9 asm("r9");
	register long _r10 asm("r10");
	register long _r15 asm("r15") = __NR_pipe;
	register long _out0 asm ("out0") = (long)filedes;
	long _retval;
	__asm __volatile (__IA64_BREAK
			  : "=r" (_r8), "=r" (_r10), "=r" (_r15),
			  "=r" (_out0), "=r" (_r9)
			  : "2" (_r15), "3" (_out0)
			  : "memory" ASM_CLOBBERS);
	if (_r10 == -1) {
		errno = _r8;
		_retval = -1;
	} else {
		filedes[0] = _r8;
		filedes[1] = _r9;
		_retval = 0;
	}
	return _retval;
}
