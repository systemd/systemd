/*	$NetBSD: mul.S,v 1.3 1997/07/16 14:37:42 christos Exp $	*/

/*
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This software was developed by the Computer Systems Engineering group
 * at Lawrence Berkeley Laboratory under DARPA contract BG 91-66 and
 * contributed to Berkeley.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * from: Header: mul.s,v 1.5 92/06/25 13:24:03 torek Exp
 */

#include <machine/asm.h>
#if defined(LIBC_SCCS) && !defined(lint)
#if 0
	.asciz "@(#)mul.s	8.1 (Berkeley) 6/4/93"
#else
	RCSID("$NetBSD: mul.S,v 1.3 1997/07/16 14:37:42 christos Exp $")
#endif
#endif /* LIBC_SCCS and not lint */

/*
 * Signed multiply, from Appendix E of the Sparc Version 8
 * Architecture Manual.
 *
 * Returns %o0 * %o1 in %o1%o0 (i.e., %o1 holds the upper 32 bits of
 * the 64-bit product).
 *
 * This code optimizes short (less than 13-bit) multiplies.
 */

FUNC(.mul)
	mov	%o0, %y		! multiplier -> Y
	andncc	%o0, 0xfff, %g0	! test bits 12..31
	be	Lmul_shortway	! if zero, can do it the short way
	andcc	%g0, %g0, %o4	! zero the partial product and clear N and V

	/*
	 * Long multiply.  32 steps, followed by a final shift step.
	 */
	mulscc	%o4, %o1, %o4	! 1
	mulscc	%o4, %o1, %o4	! 2
	mulscc	%o4, %o1, %o4	! 3
	mulscc	%o4, %o1, %o4	! 4
	mulscc	%o4, %o1, %o4	! 5
	mulscc	%o4, %o1, %o4	! 6
	mulscc	%o4, %o1, %o4	! 7
	mulscc	%o4, %o1, %o4	! 8
	mulscc	%o4, %o1, %o4	! 9
	mulscc	%o4, %o1, %o4	! 10
	mulscc	%o4, %o1, %o4	! 11
	mulscc	%o4, %o1, %o4	! 12
	mulscc	%o4, %o1, %o4	! 13
	mulscc	%o4, %o1, %o4	! 14
	mulscc	%o4, %o1, %o4	! 15
	mulscc	%o4, %o1, %o4	! 16
	mulscc	%o4, %o1, %o4	! 17
	mulscc	%o4, %o1, %o4	! 18
	mulscc	%o4, %o1, %o4	! 19
	mulscc	%o4, %o1, %o4	! 20
	mulscc	%o4, %o1, %o4	! 21
	mulscc	%o4, %o1, %o4	! 22
	mulscc	%o4, %o1, %o4	! 23
	mulscc	%o4, %o1, %o4	! 24
	mulscc	%o4, %o1, %o4	! 25
	mulscc	%o4, %o1, %o4	! 26
	mulscc	%o4, %o1, %o4	! 27
	mulscc	%o4, %o1, %o4	! 28
	mulscc	%o4, %o1, %o4	! 29
	mulscc	%o4, %o1, %o4	! 30
	mulscc	%o4, %o1, %o4	! 31
	mulscc	%o4, %o1, %o4	! 32
	mulscc	%o4, %g0, %o4	! final shift

	! If %o0 was negative, the result is
	!	(%o0 * %o1) + (%o1 << 32))
	! We fix that here.

	tst	%o0
	bge	1f
	rd	%y, %o0

	! %o0 was indeed negative; fix upper 32 bits of result by subtracting 
	! %o1 (i.e., return %o4 - %o1 in %o1).
	retl
	sub	%o4, %o1, %o1

1:
	retl
	mov	%o4, %o1

Lmul_shortway:
	/*
	 * Short multiply.  12 steps, followed by a final shift step.
	 * The resulting bits are off by 12 and (32-12) = 20 bit positions,
	 * but there is no problem with %o0 being negative (unlike above).
	 */
	mulscc	%o4, %o1, %o4	! 1
	mulscc	%o4, %o1, %o4	! 2
	mulscc	%o4, %o1, %o4	! 3
	mulscc	%o4, %o1, %o4	! 4
	mulscc	%o4, %o1, %o4	! 5
	mulscc	%o4, %o1, %o4	! 6
	mulscc	%o4, %o1, %o4	! 7
	mulscc	%o4, %o1, %o4	! 8
	mulscc	%o4, %o1, %o4	! 9
	mulscc	%o4, %o1, %o4	! 10
	mulscc	%o4, %o1, %o4	! 11
	mulscc	%o4, %o1, %o4	! 12
	mulscc	%o4, %g0, %o4	! final shift

	/*
	 *  %o4 has 20 of the bits that should be in the low part of the
	 * result; %y has the bottom 12 (as %y's top 12).  That is:
	 *
	 *	  %o4		    %y
	 * +----------------+----------------+
	 * | -12- |   -20-  | -12- |   -20-  |
	 * +------(---------+------)---------+
	 *  --hi-- ----low-part----
	 *
	 * The upper 12 bits of %o4 should be sign-extended to form the
	 * high part of the product (i.e., highpart = %o4 >> 20).
	 */

	rd	%y, %o5
	sll	%o4, 12, %o0	! shift middle bits left 12
	srl	%o5, 20, %o5	! shift low bits right 20, zero fill at left
	or	%o5, %o0, %o0	! construct low part of result
	retl
	sra	%o4, 20, %o1	! ... and extract high part of result
