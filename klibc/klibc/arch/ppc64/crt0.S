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
	ld	3,0(1)
	ld	4,8(1)
	ld	5,16(1)
	li	0,0
	stdu	0,-64(1)
	ld	9,.LC0@toc(2)
	std	5,0(9)
	bl	.main
	nop
	bl	.exit
	nop

	.size _start,.-_start
