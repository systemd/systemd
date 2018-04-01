#!/usr/bin/perl -w
# -*- cperl -*-
# Copyright © 2012 Diego Elio Pettenò <flameeyes@flameeyes.eu>
# Released under the 2-clause BSD license.
#
#Example usage:
#deptree2dot > deptree.dot
#deptree2dot | dot -Tpng -o deptree.png

my $deptree = defined($ARGV[0]) ? $ARGV[0] : "/run/openrc/deptree";

open DEPTREE, $deptree or exit 1;

print "digraph deptree {\n";

my @deptree;

while(my $line = readline(DEPTREE)) {
  $line =~ /^depinfo_([0-9]+)_([a-z]+)(?:_[0-9]+)?='(.*)'\n$/;
  my $index = $1;
  my $prop = $2;
  my $value = $3; $value =~ s/[-\.:~]/_/g;

  if ( $prop eq "service" ) {
    $deptree[$index] = $value;
    printf "%s [shape=box];\n", $value;
  } else {
    my $service = $deptree[$index];

    if ( $prop eq "ineed" ) {
      printf "%s -> %s;\n", $service, $value;
    } elsif ( $prop eq "iuse" ) {
      printf "%s -> %s [color=blue];\n", $service, $value;
    } elsif ( $prop eq "ibefore" ) {
      printf "%s -> %s [style=dotted];\n", $service, $value;
    } elsif ( $prop eq "iafter" ) {
      printf "%s -> %s [style=dotted color=purple];\n", $value, $service;
    } elsif ( $prop eq "iprovide" ) {
      printf "%s -> %s [color=red];\n", $value, $service;
    }
  }
}

print "}\n";
