/*
 * arch/cris/__negdi2.c
 */

/*
 * In 2's complement arithmetric, -x == (~x + 1), so
 * -{h,l} = (~{h,l} + {0,1)
 * -{h,l} = {~h,~l} + {0,1}
 * -{h,l} = {~h + cy, ~l + 1}
 * ... where cy = (l == 0)
 * -{h,l} = {~h + cy, -l}
 */

	.text
	.balign 4
	.type	__negdi2,@function
	.globl	__negdi2
__negdi2:
	neg.d	$r10,$r10
	seq	$r12
	not	$r11
	ret
	  add.d	$r12,$r11

	.size __negdi2, .-__negdi2
