#include <asm/asm.h>
#include <asm/regdef.h>
#include <asm/unistd.h>

	.set noreorder
	
LEAF(__syscall_common)
	syscall
        beqz    a3, 1f
	# sw is actually two instructions; the first one goes
	# in the branch delay slot
        sw      v0, errno
        li      v0, -1
1:      jr      ra
	END(__syscall_common)
