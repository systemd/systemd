#
# arch/ia64/syscall.S
#

#include <asm/unistd.h>
	
	.text
	.align	32
	.proc	__syscall_error
	.globl	__syscall_error
__syscall_error:
	addl	r2 = @ltoffx(errno),gp
	;;
	ld8.mov	r3 = [r2],errno
	;;
	st4	[r3] = r8
	mov	r8 = -1
	br.ret.sptk.many b0
	.size	__syscall_error, .-__syscall_error
	.endp	__syscall_error
