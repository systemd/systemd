/*
 * arch/i386/libgcc/__lshrdi3.S
 *
 * 64-bit shr
 */
	.text
	.align 4
	.globl __lshrdi3
	.type __lshrdi3,@function
__lshrdi3:
#ifndef _REGPARM
	movl  4(%esp),%eax
	movl  8(%esp),%edx
	movb  12(%esp),%cl
#endif
	cmpb  $32,%cl
	jae   1f
	
	shrdl %cl,%edx,%eax
	shrl  %cl,%edx
	ret
	
1:
	shrl  %cl,%edx
	xorl  %eax,%eax
	xchgl %edx,%eax
	ret

	.size __lshrdi3,.-__lshrdi3
