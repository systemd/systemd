/*
 * arch/m32r/syscall.S
 *
 *     r7 contains the syscall number (set by stub);
 * r0..r3 contains arguments 0-3 per standard calling convention;
 * r4..r5 contains arguments 4-5, but we have to get those from
 *        the stack.
 */

	.section ".text","ax"
	.balign	4
	.globl	__syscall_common
	.type	__syscall_common,@function
__syscall_common:
	ld	r4,@sp
	ld	r5,@(4,sp)
	trap	#2
	cmpi	r0, #-4096
	bnc	1f
	jmp	r14
1:
	seth	r2,#high(errno)
	or3	r2,r2,#low(errno)
	neg	r1,r0
	st	r1,@r7
	ldi	r0,#-1
	jmp	r14

	.size	__syscall_common,.-__syscall_common
