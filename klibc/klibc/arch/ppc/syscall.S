/*
 * arch/ppc/syscall.S
 *
 * Common error-handling path for system calls.
 */

	.text
	.align	2
	.globl	__syscall_error
	.type	__syscall_error,@function
__syscall_error:
	lis	9,errno@ha
	stw	3,errno@l(9)
	li	3,-1
	blr
	.size	__syscall_error,.-__syscall_error
