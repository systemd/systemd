/*
 * arch/sparc64/syscall.S
 *
 * Common system-call stub; %g1 already set to syscall number
 */

	.globl	__syscall_common
	.type	__syscall_common,#function
       	.align	4
__syscall_common:
	t	0x6d
	bcc	%xcc, 1f
	  sethi	%hi(errno), %g4
	or	%g4, %lo(errno), %g4
	st	%o0,[%g4]
1:
       	retl
	  movcs	%xcc, -1, %o0
