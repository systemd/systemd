# -*- perl -*-
#
# arch/mips/sysstub.ph
#
# Script to generate system call stubs
#

# On MIPS, most system calls follow the standard convention, with the
# system call number in r0 (v0), return an error value in r19 (a3) as
# well as the return value in r0 (v0).

sub make_sysstub($$$$$@) {
    my($outputdir, $fname, $type, $sname, $stype, @args) = @_;

    $stype = $stype || 'common';
    open(OUT, '>', "${outputdir}/${fname}.S");
    print OUT "#include <asm/asm.h>\n";
    print OUT "#include <asm/regdef.h>\n";
    print OUT "#include <asm/unistd.h>\n";
    print OUT "\n";
    print OUT "\t.set noreorder\n";
    print OUT "\n";
    print OUT "LEAF(${fname})\n";
    print OUT "\tj\t__syscall_${stype}\n";
    print OUT "\t  li\tv0, __NR_${sname}\n";
    print OUT "\tEND(${fname})\n";
    close(OUT);
}

1;
