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
    print(f'pci:v{vendor:08X}d{device:08X}*')

print('# usb:v<VEND>p<PROD> (4 uppercase hexadecimal digits twice)')
for entry in chromiumos.gen_autosuspend_rules.USB_IDS:
    vendor, product = entry.split(':')
    vendor = int(vendor, 16)
    product = int(product, 16)
    print(f'usb:v{vendor:04X}p{product:04X}*')

print(' ID_AUTOSUSPEND=1')
