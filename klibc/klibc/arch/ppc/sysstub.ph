# -*- perl -*-
#
# arch/ppc/sysstub.ph
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
    print OUT "\tli 0,__NR_${sname}\n";
    print OUT "\tsc\n";
    print OUT "\tbnslr\n";
    print OUT "\tb __syscall_error\n";
    print OUT "\t.size ${fname},.-${fname}\n";
    close(OUT);
}

1;
