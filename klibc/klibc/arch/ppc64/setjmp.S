#
# arch/ppc64/setjmp.S
#
# Basic setjmp/longjmp implementation
#

	.text
	.align 4

	.section ".opd","aw"
setjmp:
	.quad	.setjmp,.TOC.@tocbase,0
	.previous
	.size	setjmp,24
	.type	.setjmp,@function
	.globl	setjmp
	.globl	.setjmp
.setjmp:
	mflr	%r11			/* save return address */
	mfcr	%r12			/* save condition register */
	std	%r2,0(%r3)		/* save TOC pointer (not needed) */
	stdu	%r1,8(%r3)		/* save stack pointer */
	stdu	%r11,8(%r3)
	stdu	%r12,8(%r3)
	stdu	%r13,8(%r3)		/* save caller saved regs */
	stdu	%r14,8(%r3)
	stdu	%r15,8(%r3)
	stdu	%r16,8(%r3)
	stdu	%r17,8(%r3)
	stdu	%r18,8(%r3)
	stdu	%r19,8(%r3)
	stdu	%r20,8(%r3)
	stdu	%r21,8(%r3)
	stdu	%r22,8(%r3)
	stdu	%r23,8(%r3)
	stdu	%r24,8(%r3)
	stdu	%r25,8(%r3)
	stdu	%r26,8(%r3)
	stdu	%r27,8(%r3)
	stdu	%r28,8(%r3)
	stdu	%r29,8(%r3)
	stdu	%r30,8(%r3)
	std	%r31,8(%r3)
	li	%r3,0			/* indicate success */
	blr				/* return */

	.size .setjmp,.-.setjmp
	.section ".opd","aw"
longjmp:
	.quad	.longjmp,.TOC.@tocbase,0
	.previous
	.size	longjmp,24
	.type	.longjmp,@function
	.globl	longjmp
	.globl	.longjmp
.longjmp:
	ld	%r2,0(%r3)		/* restore TOC pointer (not needed) */
	ldu	%r1,8(%r3)		/* restore stack */
	ldu	%r11,8(%r3)
	ldu	%r12,8(%r3)
	ldu	%r13,8(%r3)		/* restore caller saved regs */
	ldu	%r14,8(%r3)
	ldu	%r15,8(%r3)
	ldu	%r16,8(%r3)
	ldu	%r17,8(%r3)
	ldu	%r18,8(%r3)
	ldu	%r19,8(%r3)
	ldu	%r20,8(%r3)
	ldu	%r21,8(%r3)
	ldu	%r22,8(%r3)
	ldu	%r23,8(%r3)
	ldu	%r24,8(%r3)
	ldu	%r25,8(%r3)
	ldu	%r26,8(%r3)
	ldu	%r27,8(%r3)
	ldu	%r28,8(%r3)
	ldu	%r29,8(%r3)
	ldu	%r30,8(%r3)
	ld	%r31,8(%r3)
	mtlr	%r11			/* restore LR */
	mtcr	%r12			/* restore CR */
	mr	%r3,%r4			/* get return value */
	blr				/* return */

	.size .longjmp,.-.longjmp
