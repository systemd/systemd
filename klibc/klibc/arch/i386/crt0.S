#
# arch/i386/crt0.S
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
	# Save the address of the ELF argument array
	movl %esp,%eax		# Address of ELF arguments
	# Set up a faux stack frame for the benefit of gdb
	xorl %ebp,%ebp
	push %ebp		# Keep gdb from getting confused
	push %ebp		# Keep gdb from getting confused
	# Push the arguments and called __libc_init()
#ifndef REGPARM
	push %edx		# atexit() function
	push %eax		# ELF array
#endif
	call __libc_init
	# If __libc_init returns, problem...	
	ud2
	hlt
	
	.size _start, .-_start

