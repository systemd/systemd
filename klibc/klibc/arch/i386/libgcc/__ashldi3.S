/*
 * arch/i386/libgcc/__ashldi3.S
 *
 * 64-bit shl
 */
	.text
	.align 4
	.globl __ashldi3
	.type __ashldi3,@function
__ashldi3:
#ifndef REGPARM
	movl  4(%esp),%eax
	movl  8(%esp),%edx
	movb  12(%esp),%cl
#endif
	cmpb  $32,%cl
	jae   1f
	
	shldl %cl,%eax,%edx
	shl   %cl,%eax
	ret
	
1:
	xorl  %edx,%edx
	shl   %cl,%eax
	xchgl %edx,%eax
	ret

	.size __ashldi3,.-__ashldi3
