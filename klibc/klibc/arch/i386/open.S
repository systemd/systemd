/*
 * arch/i386/open.S
 *
 * Handle the open() system call - oddball due to the varadic
 * prototype, which forces the use of the cdecl calling convention,
 * and the need for O_LARGEFILE.
 */

#include <asm/unistd.h>

/* <asm/fcntl.h>, despite the name, isn't assembly-safe */
#define O_LARGEFILE     0100000
	
	.globl	open
	.type	open,@function

open:
#ifdef _REGPARM
	movl	4(%esp),%eax
	movl	8(%esp),%edx
	movl	12(%esp),%ecx
	orl	$O_LARGEFILE,%edx
#else
	orl	$O_LARGEFILE,8(%esp)
#endif
	pushl	$__NR_open
	jmp	__syscall_common

	.size	open,.-open
