#include <asm/asm.h>
#include <asm/regdef.h>
#include <asm/unistd.h>

#define CLONE_VM	0x00000100
#define CLONE_VFORK	0x00004000
#define SIGCHLD		18

LEAF(vfork)
	li	a0, CLONE_VFORK | CLONE_VM | SIGCHLD
	li	a1, 0
	li	v0, __NR_clone
	syscall
	bnez	a3, 1f
	b	2f
1:	sw	v0, errno
	li	v0, -1
2:	jr	ra
	END(vfork)
