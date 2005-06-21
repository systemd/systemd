#
# arch/i386/sigreturn.S
#

#include <asm/unistd.h>

	.text
	.align 4
	.globl __sigreturn
	.type __sigreturn,@function
__sigreturn:
	pop	%eax		# Have no idea why this is needed...
	movl	$__NR_sigreturn,%eax
	int	$0x80
	.size __sigreturn,.-__sigreturn
