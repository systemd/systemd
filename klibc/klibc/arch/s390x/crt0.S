#
# arch/s390/crt0.S
#
# Does arch-specific initialization and invokes __libc_init
# with the appropriate arguments.
#
# See __static_init.c or __shared_init.c for the expected
# arguments.
#
	
	.text
	.align 4
	.type _start,@function
	.globl _start
_start:
	lgr	%r2,%r15
	lghi	%r3,0
	aghi	%r15,-160
	jg	__libc_init

	.size _start,.-_start
