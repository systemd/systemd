/*
 * arch/i386/libgcc/__negdi2.S
 *
 * 64-bit negation
 */
	
	.text
	.align 4
	.globl __negdi2
	.type __negdi2,@function
__negdi2:
#ifndef REGPARM
	movl 4(%esp),%eax
	movl 8(%esp),%edx
#endif
	negl %edx
	negl %eax
	sbbl $0,%edx
	ret

	.size __negdi2,.-__negdi2
