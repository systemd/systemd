#!/usr/bin/perl
($arch, $file) = @ARGV;

if (!open(FILE, "< $file")) {
    print STDERR "$file: $!\n";
    exit(1);
}

while ( defined($line = <FILE>) ) {
    chomp $line;
    $line =~ s/\s*\#.*$//;	# Strip comments and trailing blanks
    next unless $line;

    if ( $line =~ /^\s*(.*)\s+([_a-zA-Z][_a-zA-Z0-9]+)\s*\((.*)\)$/ ) {
	$type = $1;
	$name = $2;
	$argv = $3;

	@args = split(/\s*\,\s*/, $argv);
	@cargs = ();

	$i = 0;
	for $arg ( @args ) {
	    push(@cargs, "$arg a".$i++);
	}
	$nargs = $i;

	if ( $arch eq 'i386' ) {
	    open(OUT, "> socketcalls/${name}.S")
		or die "$0: Cannot open socketcalls/${name}.S\n";

	    print OUT "#include <sys/socketcalls.h>\n";
	    print OUT "\n";
	    print OUT "\t.text\n";
	    print OUT "\t.align 4\n";
	    print OUT "\t.globl ${name}\n";
	    print OUT "\t.type ${name},\@function\n";
	    print OUT "${name}:\n";
	    print OUT "\tmovb \$SYS_\U${name}\E,%al\n";
	    print OUT "\tjmp __socketcall_common\n";
	    print OUT "\t.size ${name},.-${name}\n";
	} else {
	    open(OUT, "> socketcalls/${name}.c")
		or die "$0: Cannot open socketcalls/${name}.c\n";
	    print OUT "#include \"socketcommon.h\"\n\n";
	    
	    print OUT "#ifdef __NR_$name\n\n";
	    print OUT "_syscall", scalar(@args), "(", $type, ',', $name;
	    $i = 0;
	    foreach $arg ( @args ) {
		print OUT ",", $arg, ",a",$i++;
	    }
	    print OUT ");\n";
	    print OUT "\n#else\n\n";
	    
	    print OUT "$type $name (", join(', ', @cargs), ")\n";
	    print OUT "{\n";
	    print OUT "    unsigned long args[$nargs];\n";
	    for ( $i = 0 ; $i < $nargs ; $i++ ) {
		print OUT "    args[$i] = (unsigned long)a$i;\n";
	    }
	    print OUT "    return ($type) socketcall(SYS_\U${name}\E, args);\n";
	    print OUT "}\n";
	    print OUT "\n#endif\n";
	}
	close(OUT);
    } else {
	print STDERR "$file:$.: Could not parse input\n";
	exit(1);
    }
}
