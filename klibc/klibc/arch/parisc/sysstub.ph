# -*- perl -*-
#
# arch/parisc/sysstub.ph
#
# Script to generate system call stubs
#

sub make_sysstub($$$$@) {
    my($fname, $type, $sname, $stype, @args) = @_;

    open(OUT, '>', "syscalls/${fname}.S");
    print OUT "#include <asm/unistd.h>\n";
    print OUT "\n";
    print OUT "\t.text\n";
    print OUT "\t.align 4\n";
    print OUT "\t.import __syscall_common, code\n";
    print OUT "\t.global ${fname}\n";
    print OUT "\t.export ${fname}, code\n";
    print OUT "\t.proc\n";
    print OUT "\.callinfo\n";
    print OUT "${fname}:\n";
    print OUT "\tb\t__syscall_common\n";
    print OUT "\t  ldo\t__NR_${sname}(%r0),%r20\n";
    print OUT "\t.procend\n";
    close(OUT);
}

1;
