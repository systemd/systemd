#
# arch/alpha/crt0.S
#

	.text
	.type	__start,@function
	.ent	__start, 0
	.globl	__start
__start:
	.frame  $30, 0, $26, 0
	mov	$31, $15
	br	$29, 1f
1:	ldgp	$29, 0($29)
	.prologue 0

	lda	$16, 0($30)		# ELF data structure
	lda	$17, 0($0)		# atexit pointer
	
	jsr	$26, __libc_init
	
	.size __start,.-__start
