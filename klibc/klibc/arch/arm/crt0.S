#
# arch/arm/crt0.S
#
# void _start(void)
# {
#    __libc_init(elf_structure, atexit_ptr);
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
