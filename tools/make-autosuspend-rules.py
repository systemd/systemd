#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

# Generate autosuspend rules for devices that have been tested to work properly
# with autosuspend by the Chromium OS team. Based on
# https://chromium.googlesource.com/chromiumos/platform2/+/master/power_manager/udev/gen_autosuspend_rules.py

import chromiumos.gen_autosuspend_rules

print('# pci:v<00VENDOR>d<00DEVICE> (8 uppercase hexadecimal digits twice)')
for entry in chromiumos.gen_autosuspend_rules.PCI_IDS:
    vendor, device = entry.split(':')
    vendor = int(vendor, 16)
    device = int(device, 16)
    print('pci:v{:08X}d{:08X}*'.format(vendor, device))

print('# usb:v<VEND>p<PROD> (4 uppercase hexadecimal digits twice)')
for entry in chromiumos.gen_autosuspend_rules.USB_IDS:
    vendor, product = entry.split(':')
    vendor = int(vendor, 16)
    product = int(product, 16)
    print('usb:v{:04X}p{:04X}*'.format(vendor, product))

print(' ID_AUTOSUSPEND=1')
