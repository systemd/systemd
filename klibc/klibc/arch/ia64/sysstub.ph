# -*- perl -*-
#
# arch/ia64/sysstub.ph
#
# Script to generate system call stubs
#

sub make_sysstub($$$$$@) {
    my($outputdir, $fname, $type, $sname, $stype, @args) = @_;

    open(OUT, '>', "${outputdir}/${fname}.S");
    print OUT "#include <asm/unistd.h>\n";
    print OUT "\n";
    print OUT "\t.text\n";
    print OUT "\t.align 32\n";
    print OUT "\t.proc ${fname}\n";
    print OUT "\t.globl ${fname}\n";
    print OUT "${fname}:\n";
    print OUT "\tmov\tr15 = __NR_${sname}\n";
    print OUT "\tbreak __BREAK_SYSCALL\n";
    print OUT "\tcmp.eq p6,p0 = -1,r10\n";
    print OUT "(p6)\tbr.few __syscall_error\n";
    print OUT "\tbr.ret.sptk.many b0\n";
    print OUT "\t.size\t${fname},.-${fname}\n";
    print OUT "\t.endp\t${fname}\n";
    close(OUT);
}

1;
