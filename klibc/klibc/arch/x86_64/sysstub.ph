# -*- perl -*-
#
# arch/x86_64/sysstub.ph
#
# Script to generate system call stubs
#

sub make_sysstub($$$$@) {
    my($fname, $type, $sname, $stype, @args) = @_;

    open(OUT, '>', "syscalls/${fname}.S");
    print OUT "#include <asm/unistd.h>\n";
    print OUT "\n";
    print OUT "\t.type ${fname},\@function\n";
    print OUT "\t.globl ${fname}\n";
    print OUT "${fname}:\n";
    print OUT "\tmovl \$__NR_${sname},%eax\n"; # Zero-extends to 64 bits
    print OUT "\tjmp __syscall_common\n";
    print OUT "\t.size ${fname},.-${fname}\n";
    close(OUT);
}

1;
