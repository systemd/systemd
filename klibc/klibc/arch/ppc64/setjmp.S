#
# arch/ppc64/setjmp.S
#
# Basic setjmp/longjmp implementation
# This file was derived from the equivalent file in NetBSD
#

	.text
	.align 4

	.section ".opd","aw"
setjmp:
	.quad	.setjmp,.TOC.@tocbase,0
	.previous
	.size	setjmp,24
	.type	.setjmp,@function
	.globl	setjmp
	.globl	.setjmp
.setjmp:
        mflr    %r11                    /* save return address */
        mfcr    %r12                    /* save condition register */
        mr      %r10,%r1                /* save stack pointer */
        mr      %r9,%r2                 /* save GPR2 (not needed) */
        stmw    %r9,0(%r3)              /* save r9..r31 */
        li      %r3,0                   /* indicate success */
        blr                             /* return */

	.size .setjmp,.-.setjmp
	.section ".opd","aw"
longjmp:
	.quad	.longjmp,.TOC.@tocbase,0
	.previous
	.size	longjmp,24
	.type	.longjmp,@function
	.globl	longjmp
	.globl	.longjmp
.longjmp:
        lmw     %r9,0(%r3)              /* save r9..r31 */
        mtlr    %r11                    /* restore LR */
        mtcr    %r12                    /* restore CR */
        mr      %r2,%r9                 /* restore GPR2 (not needed) */
        mr      %r1,%r10                /* restore stack */
        mr      %r3,%r4                 /* get return value */
        blr                             /* return */

	.size .longjmp,.-.longjmp
