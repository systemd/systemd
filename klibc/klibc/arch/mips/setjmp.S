#
# arch/mips/setjmp.S
#
# setjmp/longjmp for the MIPS architecture
#
# The jmp_buf is assumed to contain the following, in order:
#	s0..s7
#	gp
#	sp
#	s8
#	ra
#	f20..f31
#	fcr31
#

#include <machine/asm.h>
	
LEAF(setjmp)
	sw	s0,  0(a0)
	sw	s1,  4(a0)
	sw	s2,  8(a0)
	sw	s3, 12(a0)
	sw	s4, 16(a0)
	sw	s5, 20(a0)
	sw	s6, 24(a0)
	sw	s7, 28(a0)
	sw	gp, 32(a0)
	sw	sp, 36(a0)
	sw	s8, 40(a0)
	sw	ra, 44(a0)
	cfc1	t0,$31
	swc1	$f20,48(a0)
	swc1	$f21,52(a0)
	swc1	$f22,56(a0)
	swc1	$f23,60(a0)
	swc1	$f24,64(a0)
	swc1	$f25,68(a0)
	swc1	$f26,72(a0)
	swc1	$f27,76(a0)
	swc1	$f28,80(a0)
	swc1	$f29,84(a0)
	swc1	$f30,88(a0)
	swc1	$f31,92(a0)
	sw	t0,96(a0)
	move	v0,zero
	jr	ra
	
	END(setjmp)

LEAF(longjmp)
	lw	s0,  0(a0)
	lw	s1,  4(a0)
	lw	s2,  8(a0)
	lw	s3, 12(a0)
	lw	s4, 16(a0)
	lw	s5, 20(a0)
	lw	s6, 24(a0)
	lw	s7, 28(a0)
	lw	gp, 32(a0)
	lw	sp, 36(a0)
	lw	s8, 40(a0)
	lw	ra, 44(a0)
	lw	t0, 96(a0)
	lwc1	$f20,48(a0)
	lwc1	$f21,52(a0)
	lwc1	$f22,56(a0)
	lwc1	$f23,60(a0)
	lwc1	$f24,64(a0)
	lwc1	$f25,68(a0)
	lwc1	$f26,72(a0)
	lwc1	$f27,76(a0)
	lwc1	$f28,80(a0)
	lwc1	$f29,84(a0)
	lwc1	$f30,88(a0)
	lwc1	$f31,92(a0)
	ctc1	t0,$31
	move	v0,a1
	jr	ra

	END(longjmp)
	
	