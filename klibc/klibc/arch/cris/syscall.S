/*
 * arch/cris/syscall.S
 *
 * On cris, r9 contains the syscall number (set by generated stub);
 * r10..r13 contain arguments 0-3 per the standard calling convention,
 * and arguments 4-5 are passed in $mof and $srp; however, we have
 * to save $srp around the system call.
 */

	.section ".text","ax"
	.balign	4
	.globl	__syscall_common
	.type	__syscall_common,@function
__syscall_common:
	push	$srp
	move	[$sp+4],$mof
	move	[$sp+8],$srp
	break	13

	cmps.w	-4096,$r10
	blo	1f
	neg.d	$r10,$r11
	move.d	$r11,[errno]
	moveq	-1,$r10
1:
	pop	$srp
	ret
	nop

	.size	__syscall_common,.-__syscall_common
