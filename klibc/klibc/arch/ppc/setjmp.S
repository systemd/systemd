#
# arch/ppc/setjmp.S
#
# Basic setjmp/longjmp implementation
# This file was derived from the equivalent file in NetBSD
#

	.text
	.align 4
	.type setjmp,@function
	.globl setjmp
setjmp:
        mflr    %r11                    /* save return address */
        mfcr    %r12                    /* save condition register */
        mr      %r10,%r1                /* save stack pointer */
        mr      %r9,%r2                 /* save GPR2 (not needed) */
        stmw    %r9,0(%r3)              /* save r9..r31 */
        li      %r3,0                   /* indicate success */
        blr                             /* return */

	.size setjmp,.-setjmp

	.type longjmp,@function
	.globl longjmp
longjmp:
        lmw     %r9,0(%r3)              /* save r9..r31 */
        mtlr    %r11                    /* restore LR */
        mtcr    %r12                    /* restore CR */
        mr      %r2,%r9                 /* restore GPR2 (not needed) */
        mr      %r1,%r10                /* restore stack */
        mr      %r3,%r4                 /* get return value */
        blr                             /* return */

	.size longjmp,.-longjmp
	