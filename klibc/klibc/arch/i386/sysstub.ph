# -*- perl -*-
#
# arch/i386/sysstub.ph
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

    if ( $stype eq 'varadic' ) {
	print OUT "#ifdef REGPARM\n";
	print OUT "\tmovl  4(%esp),%eax\n";
	print OUT "\tmovl  8(%esp),%edx\n";
	print OUT "\tmovl 12(%esp),%ecx\n";
	print OUT "#endif\n";
    }

    print OUT "\tpushl \$__NR_${sname}\n";
    print OUT "\tjmp __syscall_common\n";
    print OUT "\t.size ${fname},.-${fname}\n";
    close(OUT);
}

1;
