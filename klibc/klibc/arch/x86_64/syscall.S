/*
 * arch/x86-64/syscall.S
 *
 * Common tail-handling code for system calls.
 *
 * The arguments are in the standard argument registers; the system
 * call number in %eax.
 */
	.text
	.align	4
	.globl	__syscall_common
	.type	__syscall_common,@function
__syscall_common:
	movq	%rcx,%r10		# The kernel uses %r10 istf %rcx
	syscall

	cmpq	$-4095,%rax
	jb	1f

	# Error return, must set errno
	negl	%eax
	movl	%eax,errno(%rip)	# errno is type int, so 32 bits
	orq	$-1,%rax		# orq $-1 smaller than movq $-1

1:
	ret

	.size	__syscall_common,.-__syscall_common
