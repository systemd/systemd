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

    if ( $line =~ /^\s*(\<[^\>]+\>\s+|)([^\(\<\>]+[^\@\:A-Za-z0-9_])([A-Za-z0-9_]+)(|\@[A-Za-z0-9_]+)(|\:\:[A-Za-z0-9_]+)\s*\(([^\:\)]*)\)\s*$/ ) {
	$archs = $1;
	$type  = $2;
	$sname = $3;
	$stype = $4;
	$fname = $5;
	$argv  = $6;

	$doit = 1;
	if ( $archs ne '' ) {
	    die "$0: Internal error"
		unless ( $archs =~ /^\<(|\!)([^\>\!]+)\>/ );
	    $not = $1;
	    $list = $2;

	    $doit = ($not eq '') ? 0 : 1;

	    @list = split(/,/, $list);
	    foreach  $a ( @list ) {
		if ( $a eq $arch ) {
		    $doit = ($not eq '') ? 1 : 0;
		    last;
		}
	    }
	}
	next if ( ! $doit );

	$type =~ s/\s*$//;

	$stype =~ s/^\@/_/;

	if ( $fname eq '' ) {
	    $fname = $sname;
	} else {
	    $fname =~ s/^\:\://;
	}

	@args = split(/\s*\,\s*/, $argv);

	open(OUT, "> syscalls/${fname}.c")
	    or die "$0: Cannot open syscalls/${fname}.c\n";

	if ( $fname eq "rt_sigaction") {
	    print OUT "#ifdef __x86_64__\n\n";
	    print OUT "struct sigaction;\n\n";
            print OUT "#endif\n\n"
	}

	print OUT "#include \"syscommon.h\"\n\n";
	
	if ( $fname ne $sname ) {
	    print OUT "#undef __NR_${fname}\n";
	    print OUT "#define __NR_${fname} __NR_${sname}\n\n";
	}

	print OUT "_syscall", scalar(@args), $stype, "(", $type, ',', $fname;

	$i = 0;
	foreach $arg ( @args ) {
	    print OUT ",", $arg, ",a",$i++;
	}
	print OUT ");\n";
	close(OUT);
    } else {
	print STDERR "$file:$.: Could not parse input\n";
	exit(1);
    }
}
