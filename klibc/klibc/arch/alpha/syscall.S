#
# arch/alpha/syscall.S
#

#include <machine/asm.h>
	
	.text
	.align	3
	.type	__syscall_common,@function
	.ent	__syscall_common, 0
	.globl	__syscall_common
__syscall_common:
	.frame	sp,0,ra,0
	callsys
	beq	a3, 1f
	br	pv, 2f			# pv <- pc  
2:
	ldgp	gp, 0(pv)
	lda	a1, errno
	lda	v0, -1(zero)
	stl	a3, 0(a1)
1:
	ret	zero,(ra),1

	.size	__syscall_common,.-__syscall_common
	.end	__syscall_common
