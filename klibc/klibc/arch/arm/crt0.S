#
# arch/arm/crt0.S
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
	.type _start,#function
	.globl _start

#ifdef __thumb__
	.thumb_func
#endif

_start:	mov	r0, sp
	mov	r1, #0
	bl	__libc_init

	.size _start,.-_start
