#!/usr/bin/perl
#
# Combine klibc.config, klcc.in to produce a klcc script
#
# Usage: makeklcc klcc.in klibc.config perlpath
#

use File::Spec;

($klccin, $klibcconf, $perlpath) = @ARGV;

sub pathsearch($) {
    my($file) = @_;
    my(@path);
    my($p,$pp);

    if ( $file =~ /\// ) {
	return File::Spec->rel2abs($file);
    }
    
    foreach $p ( split(/\:/, $ENV{'PATH'}) ) {
	$pp = File::Spec->rel2abs(File::Spec->catpath(undef, $p, $file));
	return $pp if ( -x $pp );
    }

    return undef;
}

print "#!${perlpath}\n";

open(KLIBCCONF, '<', $klibcconf) or die "$0: cannot open $klibcconf: $!\n";
while ( defined($l = <KLIBCCONF>) ) {
    chomp $l;
    if ( $l =~ /^([^=]+)\=(.*)$/ ) {
	$n = $1;  $s = $2;

	if ( $n eq 'CC' || $n eq 'LD' || $n eq 'STRIP' ) {
	    $s1 = pathsearch($s);
	    die "$0: Cannot find $n: $s\n" unless ( defined($s1) );
	    $s = $s1;
	}

	print "\$$n = \"\Q$s\E\";\n";
	print "\@$n = qw($s);\n";
	print "\$conf{\'\L$n\E\'} = \\\$$n;\n";
    }
}
close(KLIBCCONF);

open(KLCCIN, '<', $klccin) or die "$0: cannot open $klccin: $!\n";
while ( defined($l = <KLCCIN>) ) {
    print $l;
}
close(KLCCIN);

