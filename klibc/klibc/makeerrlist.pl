#!/usr/bin/perl
#
# This creates sys_errlist from <asm/errno.h> through somewhat
# heuristic matching.  It presumes the relevant entries are of the form
# #define Exxxx <integer> /* comment */
#

use FileHandle;

%errors  = ();
%errmsg  = ();
$maxerr  = -1;
$rootdir = '../linux/include/';	# Must have trailing /

sub parse_file($) {
    my($file) = @_;
    my($fh) = new FileHandle;
    my($line, $error, $msg);
    my($kernelonly) = 0;

    $file = $rootdir.$file;

    print STDERR "opening $file\n";

    if ( !($fh->open("< ".$file)) ) {
	die "$0: cannot open $file\n";
    }

    while ( defined($line = <$fh>) ) {
	if ( $kernelonly ) {
	    if ( $line =~ /^\#\s*endif/ ) {
		$kernelonly--;
	    } elsif ( $line =~ /^\#\sif/ ) {
		$kernelonly++;
	    }
	} else {
	    if ( $line =~ /^\#\s*define\s+([A-Z0-9_]+)\s+([0-9]+)\s*\/\*\s*(.*\S)\s*\*\// ) {
		$error = $1;
		$errno = $2+0;
		$msg   = $3;
		print STDERR "$error ($errno) => \"$msg\"\n";
		$errors{$errno} = $error;
		$errmsg{$errno} = $msg;
		$maxerr = $errno if ( $errno > $maxerr );
	    } elsif ( $line =~ /^\#\s*include\s+[\<\"](.*)[\>\"]/ ) {
		parse_file($1);
	    } elsif ( $line =~ /^\#\s*ifdef\s+__KERNEL__/ ) {
		$kernelonly++;
	    }
	}
    }
    close($fh);
    print STDERR "closing $file\n";
}
	 
parse_file('linux/errno.h');

($type) = @ARGV;

if ( $type eq '-errlist' ) {
    print  "#include <errno.h>\n";
    printf "const int sys_nerr = %d;\n", $maxerr+1;
    printf "const char * const sys_errlist[%d] = {\n", $maxerr+1;
    foreach $e ( sort(keys(%errors)) ) {
	printf "  [%s] = \"%s\",\n", $errors{$e}, $errmsg{$e};
    }
    print "};\n";
} elsif ( $type eq '-errnos' ) {
    print  "#include <errno.h>\n";
    printf "const int sys_nerr = %d;\n", $maxerr+1;
    printf "const char * const sys_errlist[%d] = {\n", $maxerr+1;
    foreach $e ( sort(keys(%errors)) ) {
	printf "  [%s] = \"%s\",\n", $errors{$e}, $errors{$e};
    }
    print "};\n";
} elsif ( $type eq '-maxerr' ) {
    print $maxerr, "\n";
}

    
