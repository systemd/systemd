#
# arch/s390/setjmp.S
#
# setjmp/longjmp for the s390 architecture
#

	.text
	.align 4
	.globl setjmp
	.type setjmp, @function
setjmp:
	stm	%r6,%r15,0(%r2)		# save all general registers
	std	%f4,40(%r2)		# save fp registers f4 and f6
	std	%f6,48(%r2)
	lhi	%r2,0			# return 0
	br	%r14

	.size setjmp,.-setjmp

	.text
	.align 4
	.globl longjmp
	.type longjmp, @function
longjmp:
	lr	%r1,%r2			# jmp_buf
	lr	%r2,%r3			# return value
	ld	%f6,48(%r1)		# restore all saved registers
	ld	%f4,40(%r1)
	lm	%r6,%r15,0(%r1)
	br	%r14			# return to restored address

	.size longjmp,.-longjmp
