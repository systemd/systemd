/*
 * arch/i386/libgcc/__muldi3.S
 *
 * 64*64 = 64 bit unsigned multiplication
 */

	.text
	.align 4
	.globl __muldi3
	.type __muldi3,@function
__muldi3:
	push  %esi
#ifndef REGPARM
	movl  8(%esp),%eax
	movl  %eax,%esi
	movl  16(%esp),%ecx
	mull  %ecx
	imull 12(%esp),%ecx
	imull 20(%esp),%esi
	addl  %ecx,%edx
	addl  %esi,%edx
#else
	movl  %eax,%esi
	push  %edx
	mull  %ecx
	imull 8(%esp),%esi
	addl  %esi,%edx
	pop   %esi
	imull %esi,%ecx
	addl  %ecx,%edx
#endif	
	pop   %esi
	ret
	.size __muldi3,.-__muldi3
