#
# arch/arm/setjmp-thumb.S
#
# setjmp/longjmp for the ARM/thumb architecture
#

#
# The jmp_buf is assumed to contain the following, in order:
#		lr
#		r4
#		r5
#		r6
#		r7
#		r8
#		r9
#		r10
#		fp
#		sp
#

	.text
	.align 4
	.globl setjmp
	.type setjmp, #function
	.thumb_func
setjmp:
	mov	r3, lr
	stmia	r0!, {r3, r4, r5, r6, r7}
	mov	r3, r8
	mov	r4, r9
	mov	r5, r10
	mov	r6, fp
	mov	r7, sp
	stmia	r0!, {r3, r4, r5, r6, r7}
	mov	r0, #0
	mov	pc, lr
	.size setjmp,.-setjmp

	.text
	.align 4
	.globl longjmp
	.type longjmp, #function
	.thumb_func
longjmp:
	mov	r2, r0
	add	r0, #5*4
	ldmia	r0!, {r3, r4, r5, r6, r7}
	mov	r8, r3
	mov	r9, r4
	mov	r10, r5
	mov	fp, r6
	mov	sp, r7
	ldmia	r2!, {r3, r4, r5, r6, r7}
	mov	r0, r1
	bne	1f
	mov	r0, #1
1:	mov	pc, r3
	.size longjmp,.-longjmp
