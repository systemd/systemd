# -*- perl -*-
#
# arch/cris/sysstub.ph
#
# Script to generate system call stubs
#

sub make_sysstub($$$$$@) {
    my($outputdir, $fname, $type, $sname, $stype, @args) = @_;

    open(OUT, '>', "${outputdir}/${fname}.S");
    print OUT "#include <asm/unistd.h>\n";
    print OUT "\n";
    print OUT "\t.text\n";
    print OUT "\t.type\t${fname},\@function\n";
    print OUT "\t.globl\t${fname}\n";
    print OUT "\t.balign\t4\n";
    print OUT "${fname}:\n";
    print OUT "#if __NR_${sname} <= 31\n";
    print OUT "\t  moveq\t__NR_${sname}, \$r9\n";
    print OUT "#else\n";
    print OUT "\t  move.d\t__NR_${sname}, \$r9\n";
    print OUT "#endif\n";
    print OUT "\tjump\t__syscall_common\n";
    print OUT "\t.size ${fname},.-${fname}\n";
    close(OUT);
}

1;
