#!/bin/sh -ex

cd "$1"
wget -O usb.ids 'http://www.linux-usb.org/usb.ids'
wget -O pci.ids 'http://pci-ids.ucw.cz/v2.2/pci.ids'
wget -O ma-large.txt 'http://standards.ieee.org/develop/regauth/oui/oui.txt'
wget -O ma-medium.txt 'http://standards.ieee.org/develop/regauth/oui28/mam.txt'
wget -O ma-small.txt 'http://standards.ieee.org/develop/regauth/oui36/oui36.txt'
wget -O pnp_id_registry.html 'http://www.uefi.org/uefi-pnp-export'
wget -O acpi_id_registry.html 'http://www.uefi.org/uefi-acpi-export'
./ids-update.pl
./acpi-update.py > 20-acpi-vendor.hwdb.base
patch -p0 -o- 20-acpi-vendor.hwdb.base <20-acpi-vendor.hwdb.patch >20-acpi-vendor.hwdb
