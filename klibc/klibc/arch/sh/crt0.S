#
# arch/sh/crt0.S
#
# void _start(void)
# {
#    /* Divine up argc, argv, and envp */
#    environ = envp;
#    exit(main(argc, argv, envp));
# } 
#

	.text
	.align 2
	.type _start,#function
	.globl _start
	
_start:
	mov	r15, r4
	mov	#0, r5
	mov.l	1f, r0

	jsr	@r0
	 nop

	.align 2
1:	.long	__libc_init

	.size _start,.-_start
