/*
 * IA-64 specific setjmp/longjmp routines
 *
 * Inspired by setjmp.s from the FreeBSD kernel.
 */

#define	J_UNAT		0
#define	J_NATS		0x8
#define	J_PFS		0x10
#define	J_BSP		0x18
#define	J_RNAT		0x20
#define	J_PREDS		0x28
#define	J_LC		0x30
#define	J_R4		0x38
#define	J_R5		0x40
#define	J_R6		0x48
#define	J_R7		0x50
#define	J_SP		0x58
#define	J_F2		0x60
#define	J_F3		0x70
#define	J_F4		0x80
#define	J_F5		0x90
#define	J_F16		0xa0
#define	J_F17		0xb0
#define	J_F18		0xc0
#define	J_F19		0xd0
#define	J_F20		0xe0
#define	J_F21		0xf0
#define	J_F22		0x100
#define	J_F23		0x110
#define	J_F24		0x120
#define	J_F25		0x130
#define	J_F26		0x140
#define	J_F27		0x150
#define	J_F28		0x160
#define	J_F29		0x170
#define	J_F30		0x180
#define	J_F31		0x190
#define	J_FPSR		0x1a0
#define	J_B0		0x1a8
#define	J_B1		0x1b0
#define	J_B2		0x1b8
#define	J_B3		0x1c0
#define	J_B4		0x1c8
#define	J_B5		0x1d0
#define	J_SIGMASK	0x1d8
#define	J_SIGSET	0x1e0
#define	J_GP		0x1f0
	
// int setjmp(struct jmp_buffer *)
//
//  Setup a non-local goto.
//
// Description:
//
//  SetJump stores the current register set in the area pointed to
//  by "save".  It returns zero.  Subsequent calls to "LongJump" will
//  restore the registers and return non-zero to the same location.
//
// On entry, r32 contains the pointer to the jmp_buffer
//
	.align 32
	.global setjmp
setjmp:
    //
    //  Make sure buffer is aligned at 16byte boundary
    //
    add     r10 = -0x10,r0  ;;  // mask the lower 4 bits
    and     r32 = r32, r10;; 
    add     r32 = 0x10, r32;;   // move to next 16 byte boundary

    add     r10 = J_PREDS, r32  // skip Unats & pfs save area
    add     r11 = J_BSP, r32
    //
    //  save immediate context
    //
    mov     r2 = ar.bsp         // save backing store pointer
    mov     r3 = pr             // save predicates
    flushrs
    ;;
    //
    // save user Unat register
    //
    mov     r16 = ar.lc         // save loop count register
    mov     r14 = ar.unat       // save user Unat register

    st8     [r10] = r3, J_LC-J_PREDS
    st8     [r11] = r2, J_R4-J_BSP
    ;;
    st8     [r10] = r16, J_R5-J_LC
    st8     [r32] = r14, J_NATS // Note: Unat at the 
                                // beginning of the save area
    mov     r15 = ar.pfs
    ;;
    //
    //  save preserved general registers & NaT's
    //
    st8.spill   [r11] = r4, J_R6-J_R4
    ;;
    st8.spill   [r10] = r5, J_R7-J_R5 
    ;;
    st8.spill   [r11] = r6, J_SP-J_R6
    ;;
    st8.spill   [r10] = r7, J_F3-J_R7 
    ;;
    st8.spill   [r11] = sp, J_F2-J_SP
    ;;
    //
    // save spilled Unat and pfs registers
    //
    mov     r2 = ar.unat        // save Unat register after spill
    ;;
    st8     [r32] = r2, J_PFS-J_NATS    // save unat for spilled regs
    ;;
    st8     [r32] = r15         // save pfs
    //
    //  save floating registers 
    //
    stf.spill   [r11] = f2, J_F4-J_F2
    stf.spill   [r10] = f3, J_F5-J_F3 
    ;;
    stf.spill   [r11] = f4, J_F16-J_F4
    stf.spill   [r10] = f5, J_F17-J_F5 
    ;;
    stf.spill   [r11] = f16, J_F18-J_F16
    stf.spill   [r10] = f17, J_F19-J_F17 
    ;;
    stf.spill   [r11] = f18, J_F20-J_F18
    stf.spill   [r10] = f19, J_F21-J_F19 
    ;;
    stf.spill   [r11] = f20, J_F22-J_F20
    stf.spill   [r10] = f21, J_F23-J_F21 
    ;;
    stf.spill   [r11] = f22, J_F24-J_F22
    stf.spill   [r10] = f23, J_F25-J_F23 
    ;;
    stf.spill   [r11] = f24, J_F26-J_F24
    stf.spill   [r10] = f25, J_F27-J_F25 
    ;;
    stf.spill   [r11] = f26, J_F28-J_F26
    stf.spill   [r10] = f27, J_F29-J_F27 
    ;;
    stf.spill   [r11] = f28, J_F30-J_F28
    stf.spill   [r10] = f29, J_F31-J_F29 
    ;;
    stf.spill   [r11] = f30, J_FPSR-J_F30
    stf.spill   [r10] = f31, J_B0-J_F31     // size of f31 + fpsr
    //
    // save FPSR register & branch registers
    //
    mov     r2 = ar.fpsr    // save fpsr register
    mov     r3 = b0 
    ;;
    st8     [r11] = r2, J_B1-J_FPSR
    st8     [r10] = r3, J_B2-J_B0
    mov     r2 = b1
    mov     r3 = b2 
    ;;
    st8     [r11] = r2, J_B3-J_B1
    st8     [r10] = r3, J_B4-J_B2
    mov     r2 = b3
    mov     r3 = b4 
    ;;
    st8     [r11] = r2, J_B5-J_B3
    st8     [r10] = r3
    mov     r2 = b5 
    ;;
    st8     [r11] = r2
    ;;
    //
    // return
    //
    mov     r8 = r0         // return 0 from setjmp
    mov     ar.unat = r14   // restore unat
    br.ret.sptk b0
    .endp setjmp

//
// void longjmp(struct jmp_buffer *, int val)
//
//  Perform a non-local goto.
//
// Description:
//
//  LongJump initializes the register set to the values saved by a
//  previous 'SetJump' and jumps to the return location saved by that
//  'SetJump'.  This has the effect of unwinding the stack and returning
//  for a second time to the 'SetJump'.
//
	
	.align 32
	.global longjmp
longjmp:
    //
    //  Make sure buffer is aligned at 16byte boundary
    //
    add     r10 = -0x10,r0  ;;  // mask the lower 4 bits
    and     r32 = r32, r10;; 
    add     r32 = 0x10, r32;;   // move to next 16 byte boundary

    //
    // caching the return value as we do invala in the end
    //
    mov     r8 = r33            // return value

    //
    //  get immediate context
    //
    mov     r14 = ar.rsc        // get user RSC conf 
    add     r10 = J_PFS, r32    // get address of pfs
    add     r11 = J_NATS, r32
    ;;
    ld8     r15 = [r10], J_BSP-J_PFS    // get pfs
    ld8     r2 = [r11], J_LC-J_NATS     // get unat for spilled regs
    ;;
    mov     ar.unat = r2
    ;;
    ld8     r16 = [r10], J_PREDS-J_BSP  // get backing store pointer
    mov     ar.rsc = r0         // put RSE in enforced lazy 
    mov     ar.pfs = r15
    ;;
    
    //
    // while returning from longjmp the BSPSTORE and BSP needs to be
    // same and discard all the registers allocated after we did
    // setjmp. Also, we need to generate the RNAT register since we
    // did not flushed the RSE on setjmp.
    //
    mov     r17 = ar.bspstore   // get current BSPSTORE
    ;;
    cmp.ltu p6,p7 = r17, r16    // is it less than BSP of 
(p6)    br.spnt.few .flush_rse
    mov     r19 = ar.rnat       // get current RNAT
    ;;
    loadrs                      // invalidate dirty regs
    br.sptk.many    .restore_rnat       // restore RNAT

.flush_rse:
    flushrs
    ;;
    mov     r19 = ar.rnat       // get current RNAT
    mov     r17 = r16           // current BSPSTORE
    ;;
.restore_rnat:
    //
    // check if RNAT is saved between saved BSP and curr BSPSTORE
    //
    mov     r18 = 0x3f
    ;; 
    dep     r18 = r18,r16,3,6   // get RNAT address
    ;;
    cmp.ltu p8,p9 = r18, r17    // RNAT saved on RSE
    ;;
(p8)    ld8     r19 = [r18]     // get RNAT from RSE
    ;;
    mov     ar.bspstore = r16   // set new BSPSTORE 
    ;;
    mov     ar.rnat = r19       // restore RNAT
    mov     ar.rsc = r14        // restore RSC conf


    ld8     r3 = [r11], J_R4-J_LC       // get lc register
    ld8     r2 = [r10], J_R5-J_PREDS    // get predicates
    ;;
    mov     pr = r2, -1
    mov     ar.lc = r3
    //
    //  restore preserved general registers & NaT's
    //
    ld8.fill    r4 = [r11], J_R6-J_R4
    ;;
    ld8.fill    r5 = [r10], J_R7-J_R5 
    ld8.fill    r6 = [r11], J_SP-J_R6
    ;;
    ld8.fill    r7 = [r10], J_F2-J_R7
    ld8.fill    sp = [r11], J_F3-J_SP
    ;;
    //
    //  restore floating registers 
    //
    ldf.fill    f2 = [r10], J_F4-J_F2
    ldf.fill    f3 = [r11], J_F5-J_F3 
    ;;
    ldf.fill    f4 = [r10], J_F16-J_F4
    ldf.fill    f5 = [r11], J_F17-J_F5 
    ;;
    ldf.fill    f16 = [r10], J_F18-J_F16
    ldf.fill    f17 = [r11], J_F19-J_F17
    ;;
    ldf.fill    f18 = [r10], J_F20-J_F18
    ldf.fill    f19 = [r11], J_F21-J_F19
    ;;
    ldf.fill    f20 = [r10], J_F22-J_F20
    ldf.fill    f21 = [r11], J_F23-J_F21
    ;;
    ldf.fill    f22 = [r10], J_F24-J_F22
    ldf.fill    f23 = [r11], J_F25-J_F23 
    ;;
    ldf.fill    f24 = [r10], J_F26-J_F24
    ldf.fill    f25 = [r11], J_F27-J_F25
    ;;
    ldf.fill    f26 = [r10], J_F28-J_F26
    ldf.fill    f27 = [r11], J_F29-J_F27
    ;;
    ldf.fill    f28 = [r10], J_F30-J_F28
    ldf.fill    f29 = [r11], J_F31-J_F29 
    ;;
    ldf.fill    f30 = [r10], J_FPSR-J_F30
    ldf.fill    f31 = [r11], J_B0-J_F31 ;;

    //
    // restore branch registers and fpsr
    //
    ld8     r16 = [r10], J_B1-J_FPSR    // get fpsr
    ld8     r17 = [r11], J_B2-J_B0      // get return pointer
    ;;
    mov     ar.fpsr = r16
    mov     b0 = r17
    ld8     r2 = [r10], J_B3-J_B1
    ld8     r3 = [r11], J_B4-J_B2
    ;;
    mov     b1 = r2
    mov     b2 = r3
    ld8     r2 = [r10], J_B5-J_B3
    ld8     r3 = [r11]
    ;;
    mov     b3 = r2
    mov     b4 = r3 
    ld8     r2 = [r10]
    ld8     r21 = [r32]         // get user unat
    ;;
    mov     b5 = r2
    mov     ar.unat = r21

    //
    // invalidate ALAT
    //
    invala ;;

    br.ret.sptk b0
    .endp longjmp
