#
# arch/cris/crt0.S
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
	move.d	$sp,$r10	/* Address of ELF arguments */

	/* atexit() function (assume null) */
	moveq	0,$r11
	
	/* Set up a dummy stack frame to keep gcc from getting confused */
	push	$r11
	push	$r11
	jump	__libc_init

	.size _start, .-_start

