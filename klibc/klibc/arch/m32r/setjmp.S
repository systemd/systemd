#
# arch/m32r/setjmp.S
#
# setjmp/longjmp for the M32R architecture
#

#
# The jmp_buf is assumed to contain the following, in order:
#	r8-r15
#
#	Note that r14 is the return address register and
#	r15 is the stack pointer.
#
	
	.text
	.balign 4
	.globl	setjmp
	.type	setjmp, @function
setjmp:
	st	r8, @r0
	st	r9, @+r0
	st	r10, @+r0
	st	r11, @+r0
	st	r12, @+r0
	st	r13, @+r0
	st	r14, @+r0
	st	r15, @+r0
	xor	r0, r0
	jmp	r14
	.size	setjmp,.-setjmp

	.text
	.balign 4
	.globl	longjmp
	.type	longjmp, @function
longjmp:
	ld	r8, @r0+
	ld	r9, @r0+
	ld	r10, @r0+
	ld	r11, @r0+
	ld	r12, @r0+
	ld	r13, @r0+
	ld	r14, @r0+
	ld	r15, @r0
	mv	r0, r1
	jmp	r14
	.size longjmp,.-longjmp
