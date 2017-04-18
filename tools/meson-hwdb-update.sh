#!/bin/sh -eu

cd "$1"

curl -L -o usb.ids 'http://www.linux-usb.org/usb.ids'
curl -L -o pci.ids 'http://pci-ids.ucw.cz/v2.2/pci.ids'
curl -L -o ma-large.txt 'http://standards-oui.ieee.org/oui/oui.txt'
curl -L -o ma-medium.txt 'http://standards-oui.ieee.org/oui28/mam.txt'
curl -L -o ma-small.txt 'http://standards-oui.ieee.org/oui36/oui36.txt'
curl -L -o pnp_id_registry.html 'http://www.uefi.org/uefi-pnp-export'
curl -L -o acpi_id_registry.html 'http://www.uefi.org/uefi-acpi-export'
./ids-update.pl
./acpi-update.py > 20-acpi-vendor.hwdb.base
patch -p0 -o- 20-acpi-vendor.hwdb.base <20-acpi-vendor.hwdb.patch >20-acpi-vendor.hwdb
diff -u 20-acpi-vendor.hwdb.base 20-acpi-vendor.hwdb >20-acpi-vendor.hwdb.patch
