! This file derived from the equivalent in newlib
!
! C run time start off

! This file supports:
!
! - both 32bit pointer and 64bit pointer environments (at compile time)
! - an imposed stack bias (of 2047) (at run time)
! - medium/low and medium/anywhere code models (at run time)

! Initial stack setup:
!
!    bottom of stack (higher memory address)
! 	...
!	text of environment strings
!	text of argument strings
!	envp[envc] = 0 (4/8 bytes)
!	...
!	env[0] (4/8 bytes)
!	argv[argc] = 0 (4/8 bytes)
!	...
!	argv[0] (4/8 bytes)
!	argc (4/8 bytes)
!	register save area (64 bits by 16 registers = 128 bytes)
!	top of stack (%sp)

! Stack Bias:
!
! It is the responsibility of the o/s to set this up.
! We handle both a 0 and 2047 value for the stack bias.

! Medium/Anywhere code model support:
!
! In this model %g4 points to the start of the data segment.
! The text segment can go anywhere, but %g4 points to the *data* segment.
! It is up to the compiler/linker to get this right.
!
! Since this model is statically linked the start of the data segment
! is known at link time.  Eg:
!
!	sethi	%hh(data_start), %g1
!	sethi	%lm(data_start), %g4
!	or	%g1, %hm(data_start), %g1
!	or	%g4, %lo(data_start), %g4
!	sllx	%g1, 32, %g1
!	or	%g4, %g1, %g4
!
! FIXME: For now we just assume 0.

! FIXME: if %g1 contains a non-zero value, atexit() should be invoked
! with this value.


	.text
	.align 4
	.globl _start
	.type _start, @function
_start:
	clr	%fp

! We use %g4 even if the code model is Medium/Low (simplifies the code).

	clr	%g4			! Medium/Anywhere base reg

! If there is a stack bias in effect, account for it in %g5.  Then always
! add %g5 to stack references below.  This way the code can be used with
! or without an imposed bias.

	andcc	%sp, 1, %g5
	bz,a .LNoBias
	 nop
	mov	2047, %g5
.LNoBias:
	add	%sp, %g5, %g5

! On entry, the kernel leaves room for one register frame, but
! the C API wants more free space.  Thus, we need to drop the stack
! pointer additionally.   

#if TARGET_PTR_SIZE == 32
	sub	%sp, 32, %sp		! make room for incoming arguments
#else /* TARGET_PTR_SIZE == 64 */
	sub	%sp, 64, %sp		! make room for incoming arguments
#endif

! Set up pointers to the ELF data structure (argc, argv, ...)
! Pass as the first argument to __libc_init
#if TARGET_PTR_SIZE == 32
	add	%g5, 0x40, %o0
#else /* TARGET_PTR_SIZE == 64 */
	add	%g5, 0x80, %o0
#endif

	call	__libc_init
	 mov	%g1, %o1	! This is the "atexit" pointer;
				! pass as the second argument to __libc_init

! If __libc_init returns, something is hosed.  Try an illegal insn.
! If that does not work, the o/s is hosed more than we are.
	.long 0
