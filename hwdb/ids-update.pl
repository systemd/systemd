#!/usr/bin/perl

use strict;
use warnings;

my $vendor;

open(IN, "<", "usb.ids");
open(OUT, ">", "20-usb-vendor-product.hwdb");
print(OUT "# This file is part of systemd.\n" .
          "#\n" .
          "# Data imported and updated from: http://www.linux-usb.org/usb.ids\n");

while (my $line = <IN>) {
        $line =~ s/\s+$//;
        $line =~ m/^([0-9a-f]{4})\s*(.*)$/;
        if (defined $1) {
                $vendor = uc $1;
                my $text = $2;
                print(OUT "\n");
                print(OUT "usb:v" . $vendor . "*\n");
                print(OUT " ID_VENDOR_FROM_DATABASE=" . $text . "\n");
                next;
        }

        $line =~ m/^\t([0-9a-f]{4})\s*(.*)$/;
        if (defined $1) {
                my $product = uc $1;
                my $text = $2;
                print(OUT "\n");
                print(OUT "usb:v" . $vendor . "p" . $product . "*\n");
                print(OUT " ID_PRODUCT_FROM_DATABASE=" . $text . "\n");
        }
}
close(INP);
close(OUTP);


my $device;

open(IN, "<", "pci.ids");
open(OUT, ">", "20-pci-vendor-product.hwdb");
print(OUT "# This file is part of systemd.\n" .
          "#\n" .
          "# Data imported and updated from: http://pciids.sourceforge.net/v2.2/pci.ids\n");

while (my $line = <IN>) {
        $line =~ s/\s+$//;
        $line =~ m/^([0-9a-f]{4})\s*(.*)$/;
        if (defined $1) {
                $vendor = uc $1;
                my $text = $2;
                print(OUT "\n");
                print(OUT "pci:v0000" . $vendor . "*\n");
                print(OUT " ID_VENDOR_FROM_DATABASE=" . $text . "\n");
                next;
        }

        $line =~ m/^\t([0-9a-f]{4})\s*(.*)$/;
        if (defined $1) {
                $device = uc $1;
                my $text = $2;
                print(OUT "\n");
                print(OUT "pci:v0000" . $vendor . "d0000" . $device . "*\n");
                print(OUT " ID_PRODUCT_FROM_DATABASE=" . $text . "\n");
                next;
        }

        $line =~ m/^\t\t([0-9a-f]{4})\s*([0-9a-f]{4})\s*(.*)$/;
        if (defined $1) {
                my $sub_vendor = uc $1;
                my $sub_device = uc $2;
                my $text = $3;
                print(OUT "\n");
                print(OUT "pci:v0000" . $vendor . "d0000" . $device . "sv0000" . $sub_vendor . "sd0000" . $sub_device . "*\n");
                print(OUT " ID_PRODUCT_FROM_DATABASE=" . $text . "\n");
        }
}
close(INP);
close(OUTP);

open(IN, "<", "oui.txt");
open(OUT, ">", "20-OUI.hwdb");
print(OUT "# This file is part of systemd.\n" .
          "#\n" .
          "# Data imported and updated from: http://standards.ieee.org/develop/regauth/oui/oui.txt\n");

while (my $line = <IN>) {
        $line =~ s/\s+$//;
        $line =~ m/^([0-9A-F]{6})\s*\(base 16\)\s*(.*)$/;
        if (defined $1) {
                my $vendor = uc $1;
                my $text = $2;
                print(OUT "\n");
                print(OUT "OUI:" . $vendor . "\n");
                print(OUT " ID_OUI_FROM_DATABASE=" . $text . "\n");
        }
}
close(INP);
close(OUTP);
