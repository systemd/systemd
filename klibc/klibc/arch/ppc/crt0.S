#
# arch/ppc/crt0.S
#
# void _start(void)
# {
#    /* Divine up argc, argv, and envp */
#    environ = envp;
#    exit(main(argc, argv, envp));
# } 
#

	.text
	.align 4
	.type _start,@function
	.globl _start
_start:
	lwz	3,0(1)
	addi	4,1,4
	addi	5,1,8
	slwi	0,3,2
	add	5,5,0
	li	0,0
	stwu	0,-16(1)
	lis	9,environ@ha
	stw	5,environ@l(9)
	bl	main
	bl	exit
	
	.size _start,.-_start
