#!/usr/bin/perl
#
# Combine klibc.config, klcc.in to produce a klcc script
#
# Usage: makeklcc klcc.in klibc.config perlpath
#

($klccin, $klibcconf, $perlpath) = @ARGV;

print "#!${perlpath}\n";

open(KLIBCCONF, '<', $klibcconf) or die "$0: cannot open $klibcconf: $!\n";
while ( defined($l = <KLIBCCONF>) ) {
    chomp $l;
    if ( $l =~ /^([^=]+)\=(.*)$/ ) {
	$n = $1;  $s = $2;
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

