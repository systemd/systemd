        .align 4

        .import $global$, data
        .import __libc_init, code
 
        .global _start
        .export _start, ENTRY
        .type _start,@function

        .proc
        .callinfo

_start: 
/* extend the stack by 64-bytes */
        ldo     64(%sp), %sp
	
/* %r25 = argc
 * %r24 = argv
 * envp = argv + (argc + 1)        
 * elfdata = (argv - 4)
 */
        ldo     -4(%r24), %r26

/* load global data */
        ldil	L%$global$, %dp
        ldo	R%$global$(%dp), %dp

/* branch to __libc_init */
        bl	__libc_init,%r2
        nop
/* break miserably if we ever return */
        iitlbp	%r0,(%r0) /* illegal instruction */
        nop
        .procend
