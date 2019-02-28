#!/usr/bin/env python3

# SPDX-License-Identifier: LGPL-2.1+
# Copyright © 2019 Red Hat, Inc.
# Written by Lubomir Rintel <lkundrak@v3.sk>

from sys import stdin, stdout
import re

stdin.reconfigure(encoding='latin_1')
stdout.reconfigure(encoding='latin_1')

def chop_from_the_end(vendor, wordlist):
    sep = vendor.split()
    for i in reversed(range(0, len(sep))):
        rem = False
        for word in wordlist:
            if word == sep[i].rstrip('.,'):
                rem = True
                break
        if rem:
            sep.pop(i)
        else:
            break
    return ' '.join(sep)

def chop_one_from_the_end(vendor, word):
    stripped = vendor.rstrip('., ')
    if not stripped.endswith(' ' + word):
        return vendor
    return stripped[:-len(word)].rstrip('., ')

def chop_from_the_end(vendor, wordlist):
    new = vendor
    while True:
        for word in wordlist:
            new = chop_one_from_the_end(new, word)
        if new == vendor:
            return new
        else:
            vendor = new

def fix_vendor(vendor):
    vendor = re.sub(r' /.*', '', vendor)
    vendor = re.sub(r' \([^\)]*\)', '', vendor)

    vendor = chop_from_the_end(vendor, [
        'Computer Corp',
        'AB', 'AG', 'ApS', 'a.s', 'A/S', 'ASA', 'Bhd', 'BHD',
        'b.v', 'B.V', 'BV', 'C&C', 'CGISS', 'CICT', 'Co', 'CO',
        'Co.Ltd', 'Corp', 'CORP', 'Corporation', 'DDK', 'DG',
        'd.o.o', 'Electronics.Co.,Ltd', 'Eng', 'GmbG', 'GmbH',
        'GSG', 'HF', 'ICS', 'IMC', 'inc', 'Inc', 'INC', 'IT', 'KG',
        'K.K', 'Limited', 'LLC', 'L.L.P', 'L.P', 'LSI', 'Ltd',
        'LTD', 'Ltda', 'Mfg', 'Mfy', 'MHS', 'M.I', 'MSM', 'N.V',
        'NV', 'Oy', 'PLC', 'Pte', 'PTE', 'Pty', 'PVT', 'S.A', 'SA',
        'Sdn', 'SDN', 'SE', 'Snd', 'S.p.a', 'S.p.A', 'SPA',
        's.r.l', 'S.r.l', 'S.r.L', 's.r.o', 'Tech', '(S)', '[hex]',
        '&',
    ])

    vendor = chop_from_the_end(vendor, [
        'of America',
        'of Hong Kong',
        'of Japan',
        'of North America',
        'of Taiwan',
        'of Adamov-Predmesti',
    ])

    vendor = chop_from_the_end(vendor, [
        # Phrases (with spaces) first
        'Access Systems',
        'Business Mobile Networks',
        'Communications & Multimedia',
        'Company of Japan',
        'Information and Communication Products',
        'Macao Commercial Offshore',
        'Mobile Phones',
        '(M) Son',
        'Multimedia Internet Technology',
        'Technology Group',
        'Wireless Networks',
        'Wireless Solutions',
        'Personal Systems',
        'Computer Products',
        'Info. Systems',
        'North America',
        'Electronic Components',

        'America',
        'Chips',
        'Communications',
        'Components',
        'Computers',
        'Computertechnik',
        'corp',
        'Design',
        'Electronics',
        'Enterprise',
        'Enterprises',
        'Europe',
        'Hardware',
        'Holdings',
        'Incorporated',
        'Instruments',
        'International',
        'Intl',
        'Labs',
        'Microelectronics',
        'Microsystems',
        'Multimedia',
        'Networks',
        'Norway',
        'Optical',
        'PCS',
        'Semiconductor',
        'Systems',
        'Systemtechnik',
        'Techcenter',
        'Technik',
        'Technologies',
        'Technology',
        'TECHNOLOGY',
        'Telephonics',
        'USA',
        'WCDMA',
    ])

    return vendor

def remove_phrases(product, phrases):
    for word in phrases:
        product = (' ' + product + ' ')
        product = product.replace(' ' + word + ' ', ' ')
        product = product.replace('[' + word + ' ', '[')
        product = product.lstrip(' ').rstrip(' ')
    return product

def fix_product(product):
    network_product = remove_phrases(product, [
        '100/10 MBit',
        '10/100',
        '10/100 Mbps',
        '1.0 GbE',
        '10 GbE',
        '10 Gigabit',
        '10 Mbps',
        '1/10 Gigabit',
        '150 Mbps',
        '2.5 GbE',
        '54 Mbps',
        '10/100VG',
        '10BaseT/2',
        'Attached Port',
        '+ BT',
        '"CDC Subset"',
        'CE Media Processor',
        'Controller Area Network',
        'Converged Network',
        'DEC-Tulip compatible',
        'Dish Adapter',
        'Double 108 Mbps',
        'Dual Band',
        'Dual Port',
        'Embedded UTP',
        'Ethernet Connection',
        'Ethernet Pro 100',
        'Express Module',
        'Fabric Adapter',
        'Fast Ethernet NIC',
        'Ethernet NIC',
        'Ethernet Adapter',
        'Fast Ethernet',
        'for 10GBASE-T' ,
        'for 10GbE backplane' ,
        'for 10GbE QSFP+' ,
        'for 10GbE SFP+' ,
        'for 1GbE',
        'for 20GbE backplane' ,
        'for 25GbE backplane' ,
        'for 25GbE SFP28' ,
        'for 40GbE backplane' ,
        'for 40GbE QSFP+' ,
        'G Adapter',
        'Gigabit Desktop Network',
        'Gigabit Ethernet',
        'Gigabit or',
        'Host Interface',
        'Host Virtual Interface',
        'IEEE 802.11b',
        'IEEE 802.11a/b/g',
        'IEEE 802.11g',
        'IEEE 802.11G',
        'IEEE 802.11n',
        'MAC + PHY',
        'Mini Card',
        'Mini Wireless',
        'Platform Controller Hub',
        'N Draft 11n Wireless',
        'Network Connection',
        'Network Everywhere',
        'N Wireless',
        'N+ Wireless',
        'OCT To Fast Ethernet Converter',
        'Plus Bluetooth',
        'Quad Gigabit',
        'rev 1',
        'rev 17',
        'rev 2',
        'rev A',
        'rev B',
        'rev F',
        'TO Ethernet',
        'Turbo Wireless Adapter',
        'Unified Wire',
        'Virtual media for',
        'WiFi Link',
        '+ WiMAX',
        'WiMAX/WiFi Link',
        'Wireless G',
        'Wireless G+',
        'Wireless Lan',
        'Wireless LAN',
        'Wireless Mini adapter',
        'Wireless Mini Adapter',
        'Wireless N',
        'with 1000-BASE-T interface',
        'with CX4 copper interface',
        'with Range Amplifier',
        'with SR-XFP optical interface',
        'w/ Upgradable Antenna',
        'Wireless Network',
        'Wireless PCI',
        'Wireless Cardbus',
        '802.11g+',
        '1000BaseSX',
        '1000BASE-T',
        '1000Base-ZX',
        '100/10M',
        '100baseFx',
        '100Base-MII',
        '100Base-T',
        '100BaseT4',
        '100Base-TX',
        '100BaseTX',
        '100GbE',
        '100Mbps',
        '100MBps',
        '100M',
        '10/100',
        '10/100/1000',
        '10/100/1000Base-T',
        '10/100/1000BASE-T',
        '10/100BaseT',
        '10/100baseTX',
        '10/100BaseTX',
        '10/100/BNC',
        '10/100M',
        '10/20-Gigabit',
        '10/25/40/50GbE',
        '10/40G',
        '10base-FL',
        '10BaseT',
        '10BASE-T',
        '10G',
        '10Gb',
        '10Gb/25Gb',
        '10Gb/25Gb/40Gb/50Gb',
        '10Gbase-T',
        '10GBase-T',
        '10GBASE-T',
        '10GbE',
        '10Gbps',
        '10-Giga',
        '10-Gigabit',
        '10mbps',
        '108Mbps',
        '10Mbps',
        '1/10GbE',
        '1/10-Gigabit',
        '11b/g/n',
        '11g',
        '150Mbps',
        '16Gbps/10Gbps',
        '1GbE',
        '1x2:2',
        '20GbE',
        '25Gb',
        '25GbE',
        '2x3:3',
        '3G',
        '3G/4G',
        '3x3:3',
        '40GbE',
        '4G',
        '54g',
        '54M',
        '54Mbps',
        '56k',
        '5G',
        '802.11',
        '802.11a/b/g',
        '802.11abg',
        '802.11a/b/g/n',
        '802.11abgn',
        '802.11ac',
        '802.11ad',
        '802.11a/g',
        '802.11b',
        '802.11b/g',
        '802.11bg',
        '802.11b/g/n',
        '802.11bgn',
        '802.11b/g/n-draft',
        '802.11g',
        '802.11n',
        '802.11N',
        '802.11n/b/g',
        '802.11ng',
        '802AIN',
        '802UIG-1',
        'WiMAX',
        'WIMAX',
        'CDMA',
        'LTE/UMTS/GSM',
        'webConnect',
        'HSDPA/HSUPA',
        'Wireless Modem',
        'WiMAX Connection',
        'Fast IrDA',
        '4Mbps',
        'Gig Ethernet',
        'Gigabit Module',
        'Gigabit NIC',
        'Fast',

        'RJ-45',
        'USB/Ethernet',
        'UTP',
        'UTP/Coax',
        'wifi',
        'Wi-Fi',
        'WiFi',
        'Wireless-150N',
        'Wireless-300N',
        'Wireless-G',
        'Wireless-N',
        'WLAN',
        'Dual-band',
        'Dual-Protocol',
    ])

    # Sometimes dropping these ruins a perfectly good name. We only
    # checked network devices so far.
    if network_product != product:
        network_product = network_product.rstrip(' ')
        network_product = re.sub(r' \[[^\)]*\]', '', network_product)
        network_product = re.sub(r' *\([^\)]*\)', '', network_product)
        network_product = re.sub(r' /.*', '', network_product)
        network_product = remove_phrases(network_product, [
            'multicore SoC',
            'Multi Function',
            'PC Card',
            'PCI Express',
            '2-Port',
            'USB 1.1',
            'USB 2.0',
            'adapter',
            'Adapter',
            'Micro',
            'adaptor',
            'ADSL',
            'Basic',
            'CAN-Bus',
            'card',
            'Card',
            'Cardbus',
            'CardBus',
            'CDMA',
            'CNA',
            'Composite',
            'controller',
            'Controller',
            'Copper',
            'DB',
            'Desktop',
            'device',
            'Device',
            'dongle',
            'driver',
            'EISA',
            'Enhanced',
            'ethernet.',
            'ethernet',
            'Ethernet',
            'Ethernet/RNDIS',
            'ExpressModule',
            'family',
            'Family',
            'Fast/Gigabit',
            'Fiber',
            'gigabit',
            'Gigabit',
            'G-NIC',
            'Hi-Gain',
            'Hi-Speed',
            'HSDPA',
            'HSUPA',
            'integrated',
            'Integrated',
            'interface',
            'LAN',
            'LAN+Winmodem',
            'Laptop',
            'LTE',
            'LTE/UMTS/GSM',
            'MAC',
            'Mini-Card',
            'Mini-USB',
            'misprogrammed',
            'modem',
            'Modem',
            'Modem/Networkcard',
            'Module',
            'Multimode',
            'Multithreaded',
            'Name:',
            'net',
            'network',
            'Network',
            'n/g/b',
            'NIC',
            'Notebook',
            'OEM',
            'PCI',
            'PCI64',
            'PCIe',
            'PCI-E',
            'PCI-Express',
            'PCI-X',
            'PCMCIA',
            'PDA',
            'PnP',
            'RDMA',
            'Series',
            'Server',
            'SoC',
            'Switch',
            'Technologies',
            'TOE',
            'USB',
            'USB2.0',
            'Voice',
            'v1',
            'v1.1',
            'v2',
            'V2.0',
            'v4.0',
            'v3',
            'v4',
            'miniPCI',
            'PCI-Card',
            'Cardbus',

            'wireless',
            'Wireless',
            'packet capture',
        ])
    product = network_product
    return product

for line in stdin.readlines():
    m = re.search('^([0-9a-f]{4}  )(.*)', line)
    if m:
        vendor = m[2]
        fixed_vendor = fix_vendor(vendor)
        if fixed_vendor == '':
            fixed_vendor = vendor
        stdout.write(m[1])
        stdout.write(fixed_vendor)
        stdout.write("\n")
        continue

    m = re.search('^(\t[0-9a-f]{4}  |\t\t[0-9a-f]{4} [0-9a-f]{4}  )(.*)', line)
    if m:
        product = m[2]
        fixed_product = fix_product(product)
        if fixed_product == '':
            fixed_product = product
        stdout.write(m[1])
        stdout.write(fixed_product)
        stdout.write("\n")
        continue

    stdout.write(line)
