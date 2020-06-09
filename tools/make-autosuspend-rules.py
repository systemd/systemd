#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1+

# Generate autosuspend rules for devices that have been whitelisted (IE tested)
# by the Chromium OS team. Please keep this script in sync with:
# https://chromium.googlesource.com/chromiumos/platform2/+/master/power_manager/udev/gen_autosuspend_rules.py

import sys
import chromiumos.gen_autosuspend_rules

HWDB_FILE = """\
%(usb_entries)s\
%(pci_entries)s\
"""

if __name__ == '__main__':
    if len(sys.argv) > 1:
        sys.stdout = open(sys.argv[1], 'w')

    pci_entries = ''
    for dev_ids in chromiumos.gen_autosuspend_rules.PCI_IDS:
        vendor, device = dev_ids.split(':')

        pci_entries += ('usb:v%sp%s*\n'
                        ' ID_AUTOSUSPEND=1\n' % (vendor, device))
    usb_entries = ''
    for dev_ids in chromiumos.gen_autosuspend_rules.USB_IDS:
        vendor, device = dev_ids.split(':')

        usb_entries += ('pci:v%sp%s*\n'
                        ' ID_AUTOSUSPEND=1\n' % (vendor, device))

    print(HWDB_FILE % {'pci_entries' : pci_entries, 'usb_entries': usb_entries})
