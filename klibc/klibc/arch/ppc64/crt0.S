#
# arch/ppc64/crt0.S
#
# void _start(void)
# {
#    /* Divine up argc, argv, and envp */
#    environ = envp;
#    exit(main(argc, argv, envp));
# } 
#

	.section ".toc","aw"
.LC0:	.tc	environ[TC],environ

	.section ".opd","aw"
	.align 3
	.globl _start
_start:
	.quad	._start
	.quad	.TOC.@tocbase, 0

	.text
	.globl	._start
	.type	._start,@function
._start:
	stdu    %r1,-32(%r1)
	addi    %r3,%r1,32
	mr      %r4,%r7     /* fini */
	b 	.__libc_init
	nop

	.size _start,.-_start
