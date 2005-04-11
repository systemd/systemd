# -*- perl -*-
#
# arch/s390/sysstub.ph
#
# Script to generate system call stubs
#

sub make_sysstub($$$$$@) {
    my($outputdir, $fname, $type, $sname, $stype, @args) = @_;

    open(OUT, '>', "${outputdir}/${fname}.S");
    print OUT "#include <asm/unistd.h>\n";
    print OUT "\n";
    print OUT "\t.type ${fname},\@function\n";
    print OUT "\t.globl ${fname}\n";
    print OUT "${fname}:\n";
    print OUT ".if __NR_${sname} < 256\n";
    print OUT "\tsvc __NR_${sname}\n";
    print OUT ".else\n";
    print OUT "\tlhi %r1,__NR_${sname}\n";
    print OUT "\tsvc 0\n";
    print OUT ".endif\n";
    print OUT "\tbras %r3,1f\n";
    print OUT "\t.long __syscall_common\n";
    print OUT "1:\tl %r3,0(%r3)\n";
    print OUT "\tbr %r3\n";
    print OUT "\t.size ${fname},.-${fname}\n";
    close(OUT);
}

1;
