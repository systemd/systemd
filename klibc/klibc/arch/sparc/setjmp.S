!
! setjmp.S
!
! Basic setjmp/longjmp
!
! This code was based on the equivalent code in NetBSD
!

#include <machine/asm.h>
#include <machine/trap.h>

!
! The jmp_buf contains the following entries:
!   sp
!   fp
!   pc
!	
ENTRY(setjmp)
	st	%sp,[%o0+0]	! Callers stack pointer
	st	%o7,[%o0+4]	! Return pc
	st	%fp,[%o0+8]	! Frame pointer
	retl			! Return
	 clr	%o0		!  ...0

ENTRY(longjmp)
	sub	%sp, 64, %sp	! set up a local stack frame
0:
	t	ST_FLUSHWIN	! flush register windows out to memory
	!
	! We restore the saved stack pointer to %fp, then issue
	! a restore instruction which will reload the register
	! window from the stack.
	!
        ld      [%o0+4], %o7    /* restore return pc */
        ld      [%o0+0], %fp    /* and stack pointer */

        retl                    ! success, return %g6
         restore        %o1, 0, %o0
