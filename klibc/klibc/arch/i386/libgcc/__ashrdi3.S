/*
 * arch/i386/libgcc/__ashrdi3.S
 *
 * 64-bit sar
 */
	.text
	.align 4
	.globl __ashrdi3
	.type __ashrdi3,@function
__ashrdi3:
#ifndef _REGPARM
	movl  4(%esp),%eax
	movl  8(%esp),%edx
	movb  12(%esp),%cl
#endif
	cmpb  $32,%cl
	jae   1f
	
	shrdl %cl,%edx,%eax
	sarl  %cl,%edx
	ret
	
1:
	sarl  %cl,%edx
	movl  %edx,%eax
	cdq
	ret

	.size __ashrdi3,.-__ashrdi3
