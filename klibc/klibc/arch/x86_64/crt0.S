#
# arch/x86_64/crt0.S
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
	movq %rsp,%rdi			# Offset of the ELF data structure
	movq %rdx,%rsi			# The atexit() pointer (if any)
	call __libc_init
	# We should never get here...
	hlt
		
	.size _start,.-_start
