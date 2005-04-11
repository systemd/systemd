# -*- perl -*-
#
# arch/arm/sysstub.ph
#
# Script to generate system call stubs
#


sub make_sysstub($$$$$@) {
    my($outputdir, $fname, $type, $sname, $stype, @args) = @_;

    open(OUT, '>', "${outputdir}/${fname}.S");
    print  OUT "#include <asm/unistd.h>\n";
	
    print  OUT "\t.text\n";
    print  OUT "\t.type\t${fname}, #function\n";
    print  OUT "\t.globl ${fname}\n";
    print  OUT "\t.align\t4\n";

    print  OUT "#ifndef __thumb__\n";

    # ARM version first
    print  OUT "${fname}:\n";
    print  OUT "\tstmfd\tsp!,{r4,r5,lr}\n";
    print  OUT "\tldr\tr4,[sp,#12]\n";
    print  OUT "\tldr\tr5,[sp,#16]\n";
    print  OUT "\tswi\t# __NR_${sname}\n";
    print  OUT "\tb\t__syscall_common\n";

    print  OUT "#else\n";

    # Thumb version
    print  OUT "\t.thumb_func\n";
    print  OUT "${fname}:\n";
    print  OUT "\tpush\t{r4,r5,r7,pc}\n";
    print  OUT "\tmov\tr7, # __NR_${sname}\n";
    print  OUT "\tb\t__syscall_common\n";
    
    print  OUT "#endif\n";

    print  OUT "\t.size\t__syscall${i},.-__syscall${i}\n";
}

1;
