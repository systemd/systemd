#
# socketcall.S
#
# On i386, the main (only?) user of socketcall(2), the memory array
# socketcall(2) needs is conveniently already assembled for us on
# the stack.  Capitalize on that to make a common socketcall stub.
#

#include <asm/unistd.h>

#ifdef __i386__

	.text
	.align 4
	.globl __socketcall_common
	.type __socketcall_common, @function

__socketcall_common:
	pushl	%ebx

	movzbl	%al,%ebx	# The socketcall number is passed in in %al
	leal	8(%esp),%ecx	# Argument pointer
	movl	$__NR_socketcall,%eax
	int	$0x80
	
	cmpl	$-4096,%eax	# Error return?
	
	popl	%ebx
	
	jb	1f
	
	negl	%eax
	movl	%eax,errno
	orl	$-1,%eax	# Return -1
1:
	ret

	.size __socketcall_common,.-__socketcall_common
	
#endif

	
