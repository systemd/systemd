/*
 * arch/sh/syscall.S
 *
 * On sh, r3 contains the syscall number (set by generated stub);
 * r4..r7 contain arguments 0-3 per the standard calling convention,
 * and arguments 4-5 are passed in r0 and r1.
 *
 * The return value is in r3 rather than standard r0.
 */

	.section ".text.syscall","ax"
	.align	2
	.globl	___syscall_common
	.type	___syscall_common,@function
___syscall_common:
	mov.l	@(sp),r0
	mov.l	@(4,sp),r1
	trapa	#0x15
	mov.l	1f,r0
	cmp/hs	r0,r3
	bt/s	3f
	  neg	r3,r4
	mov.l	2f,r5
	mov.l	r4,@r5
	rts
	  mov	#-1,r0
3:
	rts
	  mov	r3,r0

	.align 2
1:	.long	-4096		/* Errno limit */
2:	.long	errno

	.size	___syscall_common,.-___syscall_common
