/*	$NetBSD: umul.S,v 1.3 1997/07/16 14:37:44 christos Exp $	*/

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
 * from: Header: umul.s,v 1.4 92/06/25 13:24:05 torek Exp
 */

#include <machine/asm.h>
#if defined(LIBC_SCCS) && !defined(lint)
#if 0
	.asciz "@(#)umul.s	8.1 (Berkeley) 6/4/93"
#else
	RCSID("$NetBSD: umul.S,v 1.3 1997/07/16 14:37:44 christos Exp $")
#endif
#endif /* LIBC_SCCS and not lint */

/*
 * Unsigned multiply.  Returns %o0 * %o1 in %o1%o0 (i.e., %o1 holds the
 * upper 32 bits of the 64-bit product).
 *
 * This code optimizes short (less than 13-bit) multiplies.  Short
 * multiplies require 25 instruction cycles, and long ones require
 * 45 instruction cycles.
 *
 * On return, overflow has occurred (%o1 is not zero) if and only if
 * the Z condition code is clear, allowing, e.g., the following:
 *
 *	call	.umul
 *	nop
 *	bnz	overflow	(or tnz)
 */

FUNC(.umul)
	or	%o0, %o1, %o4
	mov	%o0, %y		! multiplier -> Y
	andncc	%o4, 0xfff, %g0	! test bits 12..31 of *both* args
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


	/*
	 * Normally, with the shift-and-add approach, if both numbers are
	 * positive you get the correct result.  WIth 32-bit two's-complement
	 * numbers, -x is represented as
	 *
	 *		  x		    32
	 *	( 2  -  ------ ) mod 2  *  2
	 *		   32
	 *		  2
	 *
	 * (the `mod 2' subtracts 1 from 1.bbbb).  To avoid lots of 2^32s,
	 * we can treat this as if the radix point were just to the left
	 * of the sign bit (multiply by 2^32), and get
	 *
	 *	-x  =  (2 - x) mod 2
	 *
	 * Then, ignoring the `mod 2's for convenience:
	 *
	 *   x *  y	= xy
	 *  -x *  y	= 2y - xy
	 *   x * -y	= 2x - xy
	 *  -x * -y	= 4 - 2x - 2y + xy
	 *
	 * For signed multiplies, we subtract (x << 32) from the partial
	 * product to fix this problem for negative multipliers (see mul.s).
	 * Because of the way the shift into the partial product is calculated
	 * (N xor V), this term is automatically removed for the multiplicand,
	 * so we don't have to adjust.
	 *
	 * But for unsigned multiplies, the high order bit wasn't a sign bit,
	 * and the correction is wrong.  So for unsigned multiplies where the
	 * high order bit is one, we end up with xy - (y << 32).  To fix it
	 * we add y << 32.
	 */
	tst	%o1
	bl,a	1f		! if %o1 < 0 (high order bit = 1),
	add	%o4, %o0, %o4	! %o4 += %o0 (add y to upper half)
1:	rd	%y, %o0		! get lower half of product
	retl
	addcc	%o4, %g0, %o1	! put upper half in place and set Z for %o1==0

Lmul_shortway:
	/*
	 * Short multiply.  12 steps, followed by a final shift step.
	 * The resulting bits are off by 12 and (32-12) = 20 bit positions,
	 * but there is no problem with %o0 being negative (unlike above),
	 * and overflow is impossible (the answer is at most 24 bits long).
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
	 * %o4 has 20 of the bits that should be in the result; %y has
	 * the bottom 12 (as %y's top 12).  That is:
	 *
	 *	  %o4		    %y
	 * +----------------+----------------+
	 * | -12- |   -20-  | -12- |   -20-  |
	 * +------(---------+------)---------+
	 *	   -----result-----
	 *
	 * The 12 bits of %o4 left of the `result' area are all zero;
	 * in fact, all top 20 bits of %o4 are zero.
	 */

	rd	%y, %o5
	sll	%o4, 12, %o0	! shift middle bits left 12
	srl	%o5, 20, %o5	! shift low bits right 20
	or	%o5, %o0, %o0
	retl
	addcc	%g0, %g0, %o1	! %o1 = zero, and set Z
