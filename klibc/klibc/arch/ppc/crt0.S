#
# arch/ppc/crt0.S
#

	.text
	.align 4
	.type _start,@function
	.globl _start
_start:
	stwu	1,-16(1)
	addi	3,1,16
	/*
	 * the SVR4abippc.pdf specifies r7 as a pointer to 
	 * a termination function pointer.
	 * It is unused on Linux.
	 */
	mr	4,7
	bl	__libc_init
	
	.size _start,.-_start
