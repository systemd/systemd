#
# arch/sh/crt0.S
#
# Does arch-specific initialization and invokes __libc_init
# with the appropriate arguments.
#
# See __static_init.c or __shared_init.c for the expected
# arguments.
#

	.text
	.align 2
	.type _start,#function
	.globl _start
	
_start:
	mov	r15, r4
	mov	#0, r5
	mov.l	1f, r0

	jsr	@r0
	 nop

	.align 2
1:	.long	__libc_init

	.size _start,.-_start
