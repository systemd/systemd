/*
 * parisc specific setjmp/longjmp routines
 *
 */
        
        .text
        .align 4
        .global setjmp
        .export setjmp, code
        .proc
        .callinfo
setjmp:
        stw     %r3,0(%r26)
        stw     %r4,8(%r26)
        stw     %r5,12(%r26)
        stw     %r6,16(%r26)
        stw     %r7,20(%r26)
        stw     %r8,24(%r26)
        stw     %r9,28(%r26)
        stw     %r10,32(%r26)
        stw     %r11,36(%r26)
        stw     %r12,40(%r26)
        stw     %r13,44(%r26)
        stw     %r14,48(%r26)
        stw     %r15,52(%r26)
        stw     %r16,56(%r26)
        stw     %r17,60(%r26)
        stw     %r18,64(%r26)
        stw     %r19,68(%r26)
        stw     %r27,72(%r26)
        stw     %r30,76(%r26)
        stw     %rp,80(%r26)
        ldo     88(%r26),%r19
        fstd,ma %fr12,8(%r19)
        fstd,ma %fr13,8(%r19)
        fstd,ma %fr14,8(%r19)
        fstd,ma %fr15,8(%r19)
        fstd,ma %fr16,8(%r19)
        fstd,ma %fr17,8(%r19)
        fstd,ma %fr18,8(%r19)
        fstd,ma %fr19,8(%r19)
        fstd,ma %fr20,8(%r19)
        fstd     %fr21,0(%r19)
        bv       %r0(%rp)
        copy     %r0,%r28
	.procend

	.text
	.align 4
	.global longjmp
	.export longjmp, code
	.proc
	.callinfo
longjmp:
        ldw     0(%r26),%r3
        ldw     8(%r26),%r4
        ldw     12(%r26),%r5
        ldw     16(%r26),%r6
        ldw     20(%r26),%r7
        ldw     24(%r26),%r8
        ldw     28(%r26),%r9
        ldw     32(%r26),%r10
        ldw     36(%r26),%r11
        ldw     40(%r26),%r12
        ldw     44(%r26),%r13
        ldw     48(%r26),%r14
        ldw     52(%r26),%r15
        ldw     56(%r26),%r16
        ldw     60(%r26),%r17
        ldw     64(%r26),%r18
        ldw     68(%r26),%r19
        ldw     72(%r26),%r27
        ldw     76(%r26),%r30
        ldw     80(%r26),%rp
        ldo     88(%r26),%r20
        fldd,ma 8(%r20),%fr12
        fldd,ma 8(%r20),%fr13
        fldd,ma 8(%r20),%fr14
        fldd,ma 8(%r20),%fr15
        fldd,ma 8(%r20),%fr16
        fldd,ma 8(%r20),%fr17
        fldd,ma 8(%r20),%fr18
        fldd,ma 8(%r20),%fr19
        fldd,ma 8(%r20),%fr20
        fldd    0(%r20),%fr21
        bv      %r0(%rp)
        copy    %r25,%r28
        .procend
