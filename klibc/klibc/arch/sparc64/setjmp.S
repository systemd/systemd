!
! setjmp.S
!
! Basic setjmp/longjmp
!
! This code was based on the equivalent code in NetBSD
!

!
! The jmp_buf contains the following entries:
!   sp
!   fp
!   pc
!
	.text
	.align	4
	.global	setjmp
	.type	setjmp, @function
setjmp:
	stx	%sp,[%o0+0]	! Callers stack pointer
	stx	%o7,[%o0+8]	! Return pc
	stx	%fp,[%o0+16]	! Frame pointer
	retl			! Return
	 clr	%o0		!  ...0

	.size	setjmp,.-setjmp


       	.globl	longjmp
	.type	longjmp, @function	
longjmp:
	mov	%o1, %g4	! save return value
	mov	%o0, %g1	! save target
	ldx	[%g1+16],%g5	! get callers frame
1:
	cmp	%fp, %g5	! compare against desired frame
	bl,a	1b		! if below...
	 restore		! pop frame and loop
	be,a	2f		! if there...
       	 ldx	[%g1+0],%o2	! fetch return %sp

.Lbotch:
	unimp	0		! ... error ...
	
2:
       	cmp	%o2, %sp	! %sp must not decrease
	bl	.Lbotch
	 nop
	mov	%o2, %sp	! it is OK, put it in place

	ldx	[%g1+8],%o3	! fetch %pc
	jmp	%o3 + 8		! if sucess...
	 mov	%g4,%o0		!   return %g4

	.size	longjmp,.-longjmp
