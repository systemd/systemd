#!/usr/bin/perl
#
# Combine klibc.config, klcc.in to produce a klcc script
#
# Usage: makeklcc klcc.in klibc.config perlpath
#

($klccin, $klibcconf, $perlpath) = @ARGV;

# This should probably handle quotes and escapes...
sub string2list($)
{
    my($s) = @_;

    $s =~ s/\s+/\',\'/g;
    return "(\'".$s."\')";
}

print "#!${perlpath}\n";

open(KLIBCCONF, '<', $klibcconf) or die "$0: cannot open $klibcconf: $!\n";
while ( defined($l = <KLIBCCONF>) ) {
    chomp $l;
    if ( $l =~ /=/ ) {
	print "\$$` = \"\Q$'\E\";\n";
	print "\@$` = ", string2list("$'"), ";\n";
    }
}
close(KLIBCCONF);

open(KLCCIN, '<', $klccin) or die "$0: cannot open $klccin: $!\n";
while ( defined($l = <KLCCIN>) ) {
    print $l;
}
close(KLCCIN);

