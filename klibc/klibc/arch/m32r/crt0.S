#
# arch/m32r/crt0.S
#
# Does arch-specific initialization and invokes __libc_init
# with the appropriate arguments.
#
# See __static_init.c or __shared_init.c for the expected
# arguments.
#

	.text
	.balign 4
	.type	_start,@function
	.globl	_start
_start:
	/* Save the address of the ELF argument array */
	mv	r0, sp

	/* atexit() function (assume null) */
	xor	r1, r1
	
	bl	__libc_init

	.size _start, .-_start

