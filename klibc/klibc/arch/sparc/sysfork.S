/*
 * arch/sparc/sysfork.S
 *
 * The fork and vfork system calls are special on sparc[64]:
 * they return the "other process" pid in %o0 and the
 * "is child" flag in %o1
 *
 * Common system-call stub; %g1 already set to syscall number
 */

	.globl	__syscall_forkish
	.type	__syscall_forkish,#function
       	.align	4
__syscall_forkish:
	t	0x10
	sub	%o1, 1, %o1
	bcc,a	1f
	  and	%o0, %o1, %o0
	sethi	%hi(errno), %g4
	or	%g4, %lo(errno), %g4
	st	%o0,[%g4]
	mov	-1, %o0
1:
       	retl
	  nop
