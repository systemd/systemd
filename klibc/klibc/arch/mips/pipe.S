#include <asm/asm.h>
#include <asm/regdef.h>
#include <asm/unistd.h>

LEAF(pipe)
	li	v0, __NR_pipe
	syscall
	bnez	a3, 1f
	sw	v0, (a0)
	sw	v1, (a1)
	li	v0, 0
	b	2f
1:	sw	v0, errno
	li	v0, -1
2:	jr	ra
	END(pipe)
