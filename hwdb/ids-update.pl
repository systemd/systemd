#!/usr/bin/perl

use strict;
use warnings;

sub usb_vendor {
        my $vendor;

        open(IN, "<", "usb.ids");
        open(OUT, ">", "20-usb-vendor-model.hwdb");
        print(OUT "# This file is part of systemd.\n" .
                  "#\n" .
                  "# Data imported from: http://www.linux-usb.org/usb.ids\n");

        while (my $line = <IN>) {
                $line =~ s/\s+$//;
                $line =~ m/^([0-9a-f]{4})\s*(.+)$/;
                if (defined $1) {
                        $vendor = uc $1;
                        my $text = $2;
                        print(OUT "\n");
                        print(OUT "usb:v" . $vendor . "*\n");
                        print(OUT " ID_VENDOR_FROM_DATABASE=" . $text . "\n");
                        next;
                }

                $line =~ m/^\t([0-9a-f]{4})\s*(.+)$/;
                if (defined $1) {
                        my $model = uc $1;
                        my $text = $2;
                        print(OUT "\n");
                        print(OUT "usb:v" . $vendor . "p" . $model . "*\n");
                        print(OUT " ID_MODEL_FROM_DATABASE=" . $text . "\n");
                }
        }

        close(IN);
        close(OUT);
}

sub usb_classes {
        my $class;
        my $subclass;
        my $protocol;

        open(IN, "<", "usb.ids");
        open(OUT, ">", "20-usb-classes.hwdb");
        print(OUT "# This file is part of systemd.\n" .
                  "#\n" .
                  "# Data imported from: http://www.linux-usb.org/usb.ids\n");

        while (my $line = <IN>) {
                $line =~ s/\s+$//;

                $line =~ m/^C\ ([0-9a-f]{2})\s*(.+)$/;
                if (defined $1) {
                        $class = uc $1;
                        if ($class =~ m/^00$/) {
                                next;
                        }
                        my $text = $2;
                        print(OUT "\n");
                        print(OUT "usb:v*p*d*dc" . $class . "*\n");
                        print(OUT " ID_USB_CLASS_FROM_DATABASE=" . $text . "\n");
                        next;
                }

                if (not defined $class) {
                        next;
                } elsif ($line =~ m/^$/) {
                        last;
                }

                $line =~ m/^\t([0-9a-f]{2})\s*(.+)$/;
                if (defined $1) {
                        $subclass = uc $1;
                        if ($subclass =~ m/^00$/) {
                                next;
                        }
                        my $text = $2;
                        if ($text =~ m/^(\?|None|Unused)$/) {
                                next;
                        }
                        print(OUT "\n");
                        print(OUT "usb:v*p*d*dc" . $class . "dsc" . $subclass . "*\n");
                        print(OUT " ID_USB_SUBCLASS_FROM_DATABASE=" . $text . "\n");
                        next;
                }

                $line =~ m/^\t\t([0-9a-f]{2})\s*(.+)$/;
                if (defined $1) {
                        $protocol = uc $1;
                        my $text = $2;
                        if ($text =~ m/^(\?|None|Unused)$/) {
                                next;
                        }
                        print(OUT "\n");
                        print(OUT "usb:v*p*d*dc" .  $class . "dsc" . $subclass . "dp" . $protocol . "*\n");
                        print(OUT " ID_USB_PROTOCOL_FROM_DATABASE=" . $text . "\n");
                }
        }

        close(IN);
        close(OUT);
}

sub pci_vendor {
        my $vendor;
        my $device;
        my $device_text;

        open(IN, "<", "pci.ids");
        open(OUT, ">", "20-pci-vendor-model.hwdb");
        print(OUT "# This file is part of systemd.\n" .
                  "#\n" .
                  "# Data imported from: http://pci-ids.ucw.cz/v2.2/pci.ids\n");

        while (my $line = <IN>) {
                $line =~ s/\s+$//;
                $line =~ m/^([0-9a-f]{4})\s*(.+)$/;

                if (defined $1) {
                        $vendor = uc $1;
                        my $text = $2;
                        print(OUT "\n");
                        print(OUT "pci:v0000" . $vendor . "*\n");
                        print(OUT " ID_VENDOR_FROM_DATABASE=" . $text . "\n");
                        next;
                }

                $line =~ m/^\t([0-9a-f]{4})\s*(.+)$/;
                if (defined $1) {
                        $device = uc $1;
                        $device_text = $2;
                        print(OUT "\n");
                        print(OUT "pci:v0000" . $vendor . "d0000" . $device . "*\n");
                        print(OUT " ID_MODEL_FROM_DATABASE=" . $device_text . "\n");
                        next;
                }

                $line =~ m/^\t\t([0-9a-f]{4})\s*([0-9a-f]{4})\s*(.*)$/;
                if (defined $1) {
                        my $sub_vendor = uc $1;
                        my $sub_device = uc $2;
                        my $sub_text = $3;
                        $sub_text =~ s/^\Q$device_text\E\s*//;
                        $sub_text =~ s/(.+)/\ ($1)/;
                        print(OUT "\n");
                        print(OUT "pci:v0000" . $vendor . "d0000" . $device . "sv0000" . $sub_vendor . "sd0000" . $sub_device . "*\n");
                        print(OUT " ID_MODEL_FROM_DATABASE=" . $device_text . $sub_text . "\n");
                }
        }

        close(IN);
        close(OUT);
}

sub pci_classes {
        my $class;
        my $subclass;
        my $interface;

        open(IN, "<", "pci.ids");
        open(OUT, ">", "20-pci-classes.hwdb");
        print(OUT "# This file is part of systemd.\n" .
                  "#\n" .
                  "# Data imported from: http://pci-ids.ucw.cz/v2.2/pci.ids\n");

        while (my $line = <IN>) {
                $line =~ s/\s+$//;

                $line =~ m/^C\ ([0-9a-f]{2})\s*(.+)$/;
                if (defined $1) {
                        $class = uc $1;
                        my $text = $2;
                        print(OUT "\n");
                        print(OUT "pci:v*d*sv*sd*bc" . $class . "*\n");
                        print(OUT " ID_PCI_CLASS_FROM_DATABASE=" . $text . "\n");
                        next;
                }

                if (not defined $class) {
                        next;
                } elsif ($line =~ m/^$/) {
                        last;
                }

                $line =~ m/^\t([0-9a-f]{2})\s*(.+)$/;
                if (defined $1) {
                        $subclass = uc $1;
                        my $text = $2;
                        print(OUT "\n");
                        print(OUT "pci:v*d*sv*sd*bc" . $class . "sc" . $subclass . "*\n");
                        print(OUT " ID_PCI_SUBCLASS_FROM_DATABASE=" . $text . "\n");
                        next;
                }

                $line =~ m/^\t\t([0-9a-f]{2})\s*(.+)$/;
                if (defined $1) {
                        $interface = uc $1;
                        my $text = $2;
                        print(OUT "\n");
                        print(OUT "pci:v*d*sv*sd*bc" .  $class . "sc" . $subclass . "i" . $interface . "*\n");
                        print(OUT " ID_PCI_INTERFACE_FROM_DATABASE=" . $text . "\n");
                }
        }

        close(IN);
        close(OUT);
}

sub sdio_vendor {
        my $vendor;
        my $device;

        open(IN, "<", "sdio.ids");
        open(OUT, ">", "20-sdio-vendor-model.hwdb");
        print(OUT "# This file is part of systemd.\n" .
                  "#\n" .
                  "# Data imported from: hwdb/sdio.ids\n");

        while (my $line = <IN>) {
                $line =~ s/\s+$//;
                $line =~ m/^([0-9a-f]{4})\s*(.+)$/;

                if (defined $1) {
                        $vendor = uc $1;
                        my $text = $2;
                        print(OUT "\n");
                        print(OUT "sdio:c*v" . $vendor . "*\n");
                        print(OUT " ID_VENDOR_FROM_DATABASE=" . $text . "\n");
                        next;
                }

                $line =~ m/^\t([0-9a-f]{4})\s*(.+)$/;
                if (defined $1) {
                        $device = uc $1;
                        my $text = $2;
                        print(OUT "\n");
                        print(OUT "sdio:c*v" . $vendor . "d" . $device . "*\n");
                        print(OUT " ID_MODEL_FROM_DATABASE=" . $text . "\n");
                        next;
                }
        }

        close(IN);
        close(OUT);
}

sub sdio_classes {
        my $class;
        my $subclass;
        my $interface;

        open(IN, "<", "sdio.ids");
        open(OUT, ">", "20-sdio-classes.hwdb");
        print(OUT "# This file is part of systemd.\n" .
                  "#\n" .
                  "# Data imported from: hwdb/sdio.ids\n");

        while (my $line = <IN>) {
                $line =~ s/\s+$//;

                $line =~ m/^C\ ([0-9a-f]{2})\s*(.+)$/;
                if (defined $1) {
                        $class = uc $1;
                        my $text = $2;
                        print(OUT "\n");
                        print(OUT "sdio:c" . $class . "v*d*\n");
                        print(OUT " ID_SDIO_CLASS_FROM_DATABASE=" . $text . "\n");
                        next;
                }
        }

        close(IN);
        close(OUT);
}

# MAC Address Block Large/Medium/Small
# Large  MA-L 24/24 bit (OUI)
# Medium MA-M 28/20 bit (OUI prefix owned by IEEE)
# Small  MA-S 36/12 bit (OUI prefix owned by IEEE)
sub oui {
        my $prefix;
        my %ieee_prefixes = ();

        open(OUT, ">", "20-OUI.hwdb");
        print(OUT "# This file is part of systemd.\n" .
                  "#\n" .
                  "# Data imported from:\n" .
                  "#   https://services13.ieee.org/RST/standards-ra-web/rest/assignments/download/?registry=MA-L&format=txt\n" .
                  "#   https://services13.ieee.org/RST/standards-ra-web/rest/assignments/download/?registry=MA-M&format=txt\n" .
                  "#   https://services13.ieee.org/RST/standards-ra-web/rest/assignments/download/?registry=MA-S&format=txt\n");

        open(IN, "<", "ma-small.txt");
        while (my $line = <IN>) {
                $line =~ s/^ +//;
                $line =~ s/\s+$//;
                $line =~ m/^([0-9A-F]{2})-([0-9A-F]{2})-([0-9A-F]{2})\s*\(hex\)\s*.+$/;
                if (defined $1) {
                        $prefix = $1 . $2 . $3;
                        $ieee_prefixes{ $prefix } = 1;
                        next;
                }

                $line =~ m/^([0-9A-F]{3})000-\g1FFF\s*\(base 16\)\s*(.+)$/;
                if (defined $1) {
                        my $vendor = uc $1;
                        my $text = $2;

                        print(OUT "\n");
                        print(OUT "OUI:" . $prefix . $vendor . "*\n");
                        print(OUT " ID_OUI_FROM_DATABASE=" . $text . "\n");
                }
        }
        close(IN);

        open(IN, "<", "ma-medium.txt");
        while (my $line = <IN>) {
                $line =~ s/^ +//;
                $line =~ s/\s+$//;
                $line =~ m/^([0-9A-F]{2})-([0-9A-F]{2})-([0-9A-F]{2})\s*\(hex\)\s*.+$/;
                if (defined $1) {
                        $prefix = $1 . $2 . $3;
                        $ieee_prefixes{ $prefix } = 1;
                        next;
                }

                $line =~ m/^([0-9A-F])00000-\g1FFFFF\s*\(base 16\)\s*(.+)$/;
                if (defined $1) {
                        my $vendor = uc $1;
                        my $text = $2;

                        print(OUT "\n");
                        print(OUT "OUI:" . $prefix . $vendor . "*\n");
                        print(OUT " ID_OUI_FROM_DATABASE=" . $text . "\n");
                }
        }

        open(IN, "<", "ma-large.txt");
        while (my $line = <IN>) {
                $line =~ s/^ +//;
                $line =~ s/\s+$//;
                $line =~ m/^([0-9A-F]{6})\s*\(base 16\)\s*(.+)$/;
                if (defined $1) {
                        my $vendor = uc $1;
                        my $text = $2;

                        if ($text =~ m/^IEEE REGISTRATION AUTHORITY/) {
                                next;
                        }

                        # skip the IEEE owned prefixes
                        if (! exists $ieee_prefixes{ $vendor }) {
                                print(OUT "\n");
                                print(OUT "OUI:" . $vendor . "*\n");
                                print(OUT " ID_OUI_FROM_DATABASE=" . $text . "\n");
                        }
                }
        }
        close(IN);

        close(OUT);
}

usb_vendor();
usb_classes();

pci_vendor();
pci_classes();

sdio_vendor();
sdio_classes();

oui();
