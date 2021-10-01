#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# -*- coding: utf-8 -*-

# Copyright 2017 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSES/BSD-3-Clause.txt file.

"""Autosuspend udev rule generator

This script is executed at build time to generate udev rules. The
resulting rules file is installed on the device, the script itself
is not.
"""

# List of USB devices (vendorid:productid) for which it is safe to enable
# autosuspend.
USB_IDS = []

# Host Controllers and internal hubs
USB_IDS += [
    # Linux Host Controller (UHCI) (most older x86 boards)
    '1d6b:0001',
    # Linux Host Controller (EHCI) (all boards)
    '1d6b:0002',
    # Linux Host Controller (XHCI) (most newer boards)
    '1d6b:0003',
    # SMSC (Internal HSIC Hub) (most Exynos boards)
    '0424:3503',
    # Intel (Rate Matching Hub) (all x86 boards)
    '05e3:0610',
    # Intel (Internal Hub?) (peppy, falco)
    '8087:0024',
    # Genesys Logic (Internal Hub) (rambi)
    '8087:8000',
    # Microchip (Composite HID + CDC) (kefka)
    '04d8:0b28',
]

# Webcams
USB_IDS += [
    # Chicony (zgb)
    '04f2:b1d8',
    # Chicony (mario)
    '04f2:b262',
    # Chicony (stout)
    '04f2:b2fe',
    # Chicony (butterfly)
    '04f2:b35f',
    # Chicony (rambi)
    '04f2:b443',
    # Chicony (glados)
    '04f2:b552',
    # LiteOn (spring)
    '058f:b001',
    # Foxlink? (butterfly)
    '05c8:0351',
    # Foxlink? (butterfly)
    '05c8:0355',
    # Cheng Uei? (falco)
    '05c8:036e',
    # SuYin (parrot)
    '064e:d251',
    # Realtek (falco)
    '0bda:571c',
    # IMC Networks (squawks)
    '13d3:5657',
    # Sunplus (parrot)
    '1bcf:2c17',
    # (C-13HDO10B39N) (alex)
    '2232:1013',
    # (C-10HDP11538N) (lumpy)
    '2232:1017',
    # (Namuga) (link)
    '2232:1033',
    # (C-03FFM12339N) (daisy)
    '2232:1037',
    # (C-10HDO13531N) (peach)
    '2232:1056',
    # (NCM-G102) (samus)
    '2232:6001',
    # Acer (stout)
    '5986:0299',
]

# Bluetooth Host Controller
USB_IDS += [
    # Hon-hai (parrot)
    '0489:e04e',
    # Hon-hai (peppy)
    '0489:e056',
    # Hon-hai (Kahlee)
    '0489:e09f',
    # QCA6174A (delan)
    '0489:e0a2',
    # LiteOn (parrot)
    '04ca:3006',
    # LiteOn (aleena)
    '04ca:3016',
    # LiteOn (scarlet)
    '04ca:301a',
    # Realtek (blooglet)
    '0bda:b00c',
    # Atheros (stumpy, stout)
    '0cf3:3004',
    # Atheros (AR3011) (mario, alex, zgb)
    '0cf3:3005',
    # Atheros (stumyp)
    '0cf3:3007',
    # Atheros (butterfly)
    '0cf3:311e',
    # Atheros (scarlet)
    '0cf3:e300',
    # Marvell (rambi)
    '1286:2046',
    # Marvell (gru)
    '1286:204e',
    # Intel (rambi, samus)
    '8087:07dc',
    # Intel (strago, glados)
    '8087:0a2a',
    # Intel (octopus)
    '8087:0aaa',
    # Intel (hatch)
    '8087:0026',
    # Intel (atlas)
    '8087:0025',
]

# WWAN (LTE)
USB_IDS += [
    # Huawei (ME936) (kip)
    '12d1:15bb',
    # Fibocom (L850-GL) (coral, nautilus, sarien)
    '2cb7:0007',
    # Fibocom (NL668, NL652)
    '2cb7:01a0',
]

# Mass Storage
USB_IDS += [
    # Genesys (SD card reader) (lumpy, link, peppy)
    '05e3:0727',
    # Realtek (SD card reader) (mario, alex)
    '0bda:0138',
    # Realtek (SD card reader) (helios)
    '0bda:0136',
    # Realtek (SD card reader) (falco)
    '0bda:0177',
]

# Security Key
USB_IDS += [
    # Yubico.com
    '1050:0211',
    # Yubico.com (HID firmware)
    '1050:0200',
    # Google Titan key
    '18d1:5026',
]

# USB Audio devices
USB_IDS += [
    # Google USB-C to 3.5mm Digital Headphone Jack Adapter 'Mir'
    '18d1:5025',
    # Google USB-C to 3.5mm Digital Headphone Jack Adapter 'Mir' (HID only)
    '18d1:5029',
    # Google USB-C to 3.5mm Digital Headphone Jack Adapter 2018 'Condor'
    '18d1:5034',
    # Google Pixel USB-C Earbuds 'Blackbird'
    '18d1:5033',
    # Libratone Q Adapt In-Ear USB-C Earphones, Made for Google
    '03eb:2433',
    # Moshi USB-C to 3.5 mm Adapter/Charger, Made for Google
    '282b:48f0',
    # Moshi USB-C to 3.5 mm Adapter/Charger, Made for Google (HID only)
    '282b:0026',
    # AiAiAi TMA-2 C60 Cable, Made for Google
    '0572:1a08',
    # Apple USB-C to 3.5mm Headphone Jack Adapter
    '05ac:110a',
]

# List of PCI devices (vendorid:deviceid) for which it is safe to enable
# autosuspend.
PCI_IDS = []

# Intel
PCI_IDS += [
    # Host bridge
    '8086:590c',
    # i915
    '8086:591e',
    # proc_thermal
    '8086:1903',
    # SPT PCH xHCI controller
    '8086:9d2f',
    # CNP PCH xHCI controller
    '8086:9ded',
    # intel_pmc_core
    '8086:9d21',
    # i801_smbus
    '8086:9d23',
    # iwlwifi
    '8086:095a',
    # GMM
    '8086:1911',
    # Thermal
    '8086:9d31',
    # MME
    '8086:9d3a',
    # CrOS EC
    '8086:9d4b',
    # PCH SPI
    '8086:9d24',
    # SATA
    '8086:02d3',
    # RAM memory
    '8086:02ef',
    # ISA bridge
    '8086:0284',
    # Communication controller
    '8086:02e0',
    # Network controller
    '8086:02f0',
    # Serial bus controller
    '8086:02a4',
    # USB controller
    '8086:02ed',
    # Volteer xHCI controller
    '8086:a0ed',
    # Graphics
    '8086:9b41',
    # DSP
    '8086:02f9',
    # Host bridge
    '8086:9b61',
    # Host bridge
    '8086:9b71',
    # PCI Bridge
    '8086:02b0',
    # i915 (atlas)
    '8086:591c',
    # iwlwifi (atlas)
    '8086:2526',
    # i915 (kefka)
    '8086:22b1',
    # proc_thermal (kefka)
    '8086:22dc',
    # xchi_hdc (kefka)
    '8086:22b5',
    # snd_hda (kefka)
    '8086:2284',
    # pcieport (kefka)
    '8086:22c8',
    '8086:22cc',
    # lpc_ich (kefka)
    '8086:229c',
    # iosf_mbi_pci (kefka)
    '8086:2280',
]

# Samsung
PCI_IDS += [
    # NVMe KUS030205M-B001
    '144d:a806',
    # NVMe MZVLB256HAHQ
    '144d:a808',
]

# Lite-on
PCI_IDS += [
    # 3C07110288
    '14a4:9100',
]

# Seagate
PCI_IDS += [
    # ZP256CM30011
    '7089:5012',
]

# Kingston
PCI_IDS += [
    # RBUSNS8154P3128GJ3
    '2646:5008',
]

# Do not edit below this line. #################################################

UDEV_RULE = """\
ACTION!="add", GOTO="autosuspend_end"
SUBSYSTEM!="i2c|pci|usb", GOTO="autosuspend_end"

SUBSYSTEM=="i2c", GOTO="autosuspend_i2c"
SUBSYSTEM=="pci", GOTO="autosuspend_pci"
SUBSYSTEM=="usb", GOTO="autosuspend_usb"

# I2C rules
LABEL="autosuspend_i2c"
ATTR{name}=="cyapa", ATTR{power/control}="on", GOTO="autosuspend_end"
GOTO="autosuspend_end"

# PCI rules
LABEL="autosuspend_pci"
%(pci_rules)s\
GOTO="autosuspend_end"

# USB rules
LABEL="autosuspend_usb"
%(usb_rules)s\
GOTO="autosuspend_end"

# Enable autosuspend
LABEL="autosuspend_enable"
TEST=="power/control", ATTR{power/control}="auto", GOTO="autosuspend_end"

LABEL="autosuspend_end"
"""


def main():
  pci_rules = ''
  for dev_ids in PCI_IDS:
    vendor, device = dev_ids.split(':')
    pci_rules += ('ATTR{vendor}=="0x%s", ATTR{device}=="0x%s", '
                  'GOTO="autosuspend_enable"\n' % (vendor, device))

  usb_rules = ''
  for dev_ids in USB_IDS:
    vid, pid = dev_ids.split(':')
    usb_rules += ('ATTR{idVendor}=="%s", ATTR{idProduct}=="%s", '
                  'GOTO="autosuspend_enable"\n' % (vid, pid))

  print(UDEV_RULE % {'pci_rules': pci_rules, 'usb_rules': usb_rules})


if __name__ == '__main__':
  main()
