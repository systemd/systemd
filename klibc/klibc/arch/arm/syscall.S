/*
 * arch/arm/syscall.S
 *
 * System call common handling
 */

	.type	__syscall_common,#function
	.globl	__syscall_common
#ifndef __thumb__
	/* ARM version - this is executed after the swi */

	.align	4
__syscall_common:
        cmn     r0, #4096
        rsbcs	r2, r0, #0
        ldrcs	r3, 1f
        mvncs	r0, #0
        strcs	r2, [r3]
	ldmfd	sp!,{r4,r5,pc}
	
	.align 4	
1:
	.word	errno

#else
	/* Thumb version - must still load r4 and r5 and run swi */

	.thumb_func
	.align	2
__syscall_common:
	ldr	r4, [sp #12]
	ldr	r5, [sp #16]
	swi	0
	ldr	r1, 2f
	cmp	r0, r1
	bcc	1f
	ldr	r1, 3f
	neg	r2, r0
	mvn	r0, #0	
	str	r2, [r1]
1:
	pop	{r4,r5,r7,pc}

	.align	4
2:
	.word	#-4095
3:
	.word	errno

#endif
