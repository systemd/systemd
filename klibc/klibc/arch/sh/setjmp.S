#
# arch/sh/setjmp.S
#
# setjmp/longjmp for the SuperH architecture
#

#
# The jmp_buf is assumed to contain the following, in order:
#
#		r8
#		r9
#		r10
#		r11
#		r12
#		r13
#		r14
#		r15
#		pr
#

	.text
	.align 2

	.globl setjmp
	.type setjmp, #function

setjmp:
	add	#(9*4), r4
	sts.l	pr, @-r4
	mov.l	r15, @-r4
	mov.l	r14, @-r4
	mov.l	r13, @-r4
	mov.l	r12, @-r4
	mov.l	r11, @-r4
	mov.l	r10, @-r4
	mov.l	r9, @-r4
	mov.l	r8, @-r4
	rts
	 mov	#0, r0

	.size setjmp,.-setjmp

	.align 2
	.globl longjmp
	.type setjmp, #function

longjmp:
	mov.l	@r4+, r8
	mov.l	@r4+, r9
	mov.l	@r4+, r10
	mov.l	@r4+, r11
	mov.l	@r4+, r12
	mov.l	@r4+, r13
	mov.l	@r4+, r14
	mov.l	@r4+, r15
	lds.l	@r4+, pr
	mov	r5, r0
	tst	r0, r0
	bf	1f
	mov	#1, r0	! in case val==0
1:	rts
	 nop

	.size longjmp,.-longjmp

