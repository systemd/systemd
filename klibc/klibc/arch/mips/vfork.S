#include <asm/asm.h>
#include <asm/regdef.h>
#include <asm/unistd.h>

#define CLONE_VM	0x00000100
#define CLONE_VFORK	0x00004000
#define SIGCHLD		18

	.set noreorder
	
LEAF(vfork)
	li	a0, CLONE_VFORK | CLONE_VM | SIGCHLD
	li	a1, 0
	j	__syscall_common
	  li	v0, __NR_clone
	END(vfork)
