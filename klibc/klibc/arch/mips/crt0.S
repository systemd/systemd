#
# arch/mips/crt0.S
#
# Does arch-specific initialization and invokes __libc_init
# with the appropriate arguments.
#
# See __static_init.c or __shared_init.c for the expected
# arguments.
#

#include <machine/asm.h>

NESTED(__start, 32, sp)
	subu	sp, 32
	sw	zero, 16(sp)

	lui	gp, %hi(_gp)		# Initialize gp
	addiu	gp, gp, _gp
	
	addiu	a0, sp, 32		# Pointer to ELF entry structure
	move	a1, v0			# Kernel-provided atexit() pointer

	jal	__libc_init

	END(__start)
