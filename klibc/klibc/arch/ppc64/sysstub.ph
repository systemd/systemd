# -*- perl -*-
#
# arch/ppc64/sysstub.ph
#
# Script to generate system call stubs
#

sub make_sysstub($$$$@) {
    my($fname, $type, $sname, $stype, @args) = @_;

    open(OUT, '>', "syscalls/${fname}.S");
    print OUT "#include <asm/unistd.h>\n";
    print OUT "\n";
    print OUT "\t.globl ${fname}\n";
    print OUT "\t.section \".opd\",\"aw\"\n";
    print OUT "\t.align 3\n";
    print OUT "${fname}:\n";
    print OUT "\t.quad .${fname},.TOC.\@tocbase,0\n";
    print OUT "\t.size ${fname},24\n";
    print OUT "\t.text\n";
    print OUT "\t.type .${fname},\@function\n";
    print OUT "\t.globl .${fname}\n";
    print OUT ".${fname}:\n";
    print OUT "\tli 0,__NR_${sname}\n";
    print OUT "\tsc\n";
    print OUT "\tmfcr 0\n";
    print OUT "\trldicl. 9,0,36,63\n";
    print OUT "\tbeqlr- 0\n";
    print OUT "\tb .__syscall_error\n";
    print OUT "\t.size .${fname},.-.${fname}\n";
    close(OUT);
}

1;
