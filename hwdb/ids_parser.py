#!/usr/bin/env python3

import re
import sys
from pyparsing import (Word, White, Literal, Regex,
                       LineEnd, SkipTo,
                       ZeroOrMore, OneOrMore, Combine, Optional, Suppress,
                       Group,
                       stringEnd, pythonStyleComment)

EOL = LineEnd().suppress()
NUM1 = Word('0123456789abcdefABCDEF', exact=1)
NUM2 = Word('0123456789abcdefABCDEF', exact=2)
NUM3 = Word('0123456789abcdefABCDEF', exact=3)
NUM4 = Word('0123456789abcdefABCDEF', exact=4)
NUM6 = Word('0123456789abcdefABCDEF', exact=6)
TAB = White('\t', exact=1).suppress()
COMMENTLINE = pythonStyleComment + EOL
EMPTYLINE = LineEnd()
text_eol = lambda name: Regex(r'[^\n]+')(name) + EOL

def klass_grammar():
    klass_line = Literal('C ').suppress() + NUM2('klass') + text_eol('text')
    subclass_line = TAB + NUM2('subclass') + text_eol('text')
    protocol_line = TAB + TAB + NUM2('protocol') + text_eol('name')
    subclass = (subclass_line('SUBCLASS') -
                ZeroOrMore(Group(protocol_line)('PROTOCOLS*')
                           ^ COMMENTLINE.suppress()))
    klass = (klass_line('KLASS') -
             ZeroOrMore(Group(subclass)('SUBCLASSES*')
                        ^ COMMENTLINE.suppress()))
    return klass

def usb_ids_grammar():
    vendor_line = NUM4('vendor') + text_eol('text')
    device_line = TAB + NUM4('device') + text_eol('text')
    vendor = (vendor_line('VENDOR') +
              ZeroOrMore(Group(device_line)('VENDOR_DEV*') ^ COMMENTLINE.suppress()))

    klass = klass_grammar()

    other_line = (Literal('AT ') ^ Literal('HID ') ^ Literal('R ')
                  ^ Literal('PHY ') ^ Literal('BIAS ') ^ Literal('HUT ')
                  ^ Literal('L ') ^ Literal('VT ') ^ Literal('HCC ')) + text_eol('text')
    other_group = (other_line - ZeroOrMore(TAB + text_eol('text')))

    commentgroup = OneOrMore(COMMENTLINE).suppress() ^ EMPTYLINE.suppress()
    grammar = OneOrMore(Group(vendor)('VENDORS*')
                        ^ Group(klass)('CLASSES*')
                        ^ other_group.suppress() ^ commentgroup) + stringEnd()

    grammar.parseWithTabs()
    return grammar

def pci_ids_grammar():
    vendor_line = NUM4('vendor') + text_eol('text')
    device_line = TAB + NUM4('device') + text_eol('text')
    subvendor_line = TAB + TAB + NUM4('a') + White(' ') + NUM4('b') + text_eol('name')

    device = (device_line('DEVICE') +
              ZeroOrMore(Group(subvendor_line)('SUBVENDORS*') ^ COMMENTLINE.suppress()))
    vendor = (vendor_line('VENDOR') +
              ZeroOrMore(Group(device)('DEVICES*') ^ COMMENTLINE.suppress()))

    klass = klass_grammar()

    commentgroup = OneOrMore(COMMENTLINE).suppress() ^ EMPTYLINE.suppress()
    grammar = OneOrMore(Group(vendor)('VENDORS*')
                        ^ Group(klass)('CLASSES*')
                        ^ commentgroup) + stringEnd()

    grammar.parseWithTabs()
    return grammar

def sdio_ids_grammar():
    vendor_line = NUM4('vendor') + text_eol('text')
    device_line = TAB + NUM4('device') + text_eol('text')
    vendor = (vendor_line('VENDOR') +
              ZeroOrMore(Group(device_line)('DEVICES*') ^ COMMENTLINE.suppress()))

    klass = klass_grammar()

    commentgroup = OneOrMore(COMMENTLINE).suppress() ^ EMPTYLINE.suppress()
    grammar = OneOrMore(Group(vendor)('VENDORS*')
                        ^ Group(klass)('CLASSES*')
                        ^ commentgroup) + stringEnd()

    grammar.parseWithTabs()
    return grammar

def oui_grammar(type):
    prefix_line = (Combine(NUM2 - Suppress('-') - NUM2 - Suppress('-') - NUM2)('prefix')
                   - Literal('(hex)') -  text_eol('text'))
    if type == 'small':
        vendor_line = (NUM3('start') - '000-' - NUM3('end') - 'FFF'
                       - Literal('(base 16)') - text_eol('text2'))
    elif type == 'medium':
        vendor_line = (NUM1('start') - '00000-' - NUM1('end') - 'FFFFF'
                       - Literal('(base 16)') - text_eol('text2'))
    else:
        assert type == 'large'
        vendor_line = (NUM6('start')
                       - Literal('(base 16)') - text_eol('text2'))

    extra_line = TAB - TAB - TAB - TAB - SkipTo(EOL)
    vendor = prefix_line + vendor_line + ZeroOrMore(extra_line) + Optional(EMPTYLINE)

    grammar = (Literal('OUI') + text_eol('header')
               + text_eol('header') + text_eol('header') + EMPTYLINE
               + OneOrMore(Group(vendor)('VENDORS*')) + stringEnd())

    grammar.parseWithTabs()
    return grammar


def header(file, *sources):
    print('''\
# This file is part of systemd.
#
# Data imported from:{}{}'''.format(' ' if len(sources) == 1 else '\n#   ',
                                    '\n#   '.join(sources)),
          file=file)

def add_item(items, key, value):
    if key in items:
        print(f'Ignoring duplicate entry: {key} = "{items[key]}", "{value}"')
    else:
        items[key] = value

def usb_vendor_model(p):
    items = {}

    for vendor_group in p.VENDORS:
        vendor = vendor_group.vendor.upper()
        text = vendor_group.text.strip()
        add_item(items, (vendor,), text)

        for vendor_dev in vendor_group.VENDOR_DEV:
            device = vendor_dev.device.upper()
            text = vendor_dev.text.strip()
            add_item(items, (vendor, device), text)

    with open('20-usb-vendor-model.hwdb', 'wt') as out:
        header(out, 'http://www.linux-usb.org/usb.ids')

        for key in sorted(items):
            if len(key) == 1:
                p, n = 'usb:v{}*', 'VENDOR'
            else:
                p, n = 'usb:v{}p{}*', 'MODEL',
            print('', p.format(*key),
                  f' ID_{n}_FROM_DATABASE={items[key]}', sep='\n', file=out)

    print(f'Wrote {out.name}')

def usb_classes(p):
    items = {}

    for klass_group in p.CLASSES:
        klass = klass_group.klass.upper()
        text = klass_group.text.strip()

        if klass != '00' and not re.match(r'(\?|None|Unused)\s*$', text):
            add_item(items, (klass,), text)

        for subclass_group in klass_group.SUBCLASSES:
            subclass = subclass_group.subclass.upper()
            text = subclass_group.text.strip()
            if subclass != '00' and not re.match(r'(\?|None|Unused)\s*$', text):
                add_item(items, (klass, subclass), text)

            for protocol_group in subclass_group.PROTOCOLS:
                protocol = protocol_group.protocol.upper()
                text = protocol_group.name.strip()
                if klass != '00' and not re.match(r'(\?|None|Unused)\s*$', text):
                    add_item(items, (klass, subclass, protocol), text)

    with open('20-usb-classes.hwdb', 'wt') as out:
        header(out, 'http://www.linux-usb.org/usb.ids')

        for key in sorted(items):
            if len(key) == 1:
                p, n = 'usb:v*p*d*dc{}*', 'CLASS'
            elif len(key) == 2:
                p, n = 'usb:v*p*d*dc{}dsc{}*', 'SUBCLASS'
            else:
                p, n = 'usb:v*p*d*dc{}dsc{}dp{}*', 'PROTOCOL'
            print('', p.format(*key),
                  f' ID_USB_{n}_FROM_DATABASE={items[key]}', sep='\n', file=out)

    print(f'Wrote {out.name}')

def pci_vendor_model(p):
    items = {}

    for vendor_group in p.VENDORS:
        vendor = vendor_group.vendor.upper()
        text = vendor_group.text.strip()
        add_item(items, (vendor,), text)

        for device_group in vendor_group.DEVICES:
            device = device_group.device.upper()
            text = device_group.text.strip()
            add_item(items, (vendor, device), text)

            for subvendor_group in device_group.SUBVENDORS:
                sub_vendor = subvendor_group.a.upper()
                sub_model = subvendor_group.b.upper()
                sub_text = subvendor_group.name.strip()
                if sub_text.startswith(text):
                    sub_text = sub_text[len(text):].lstrip()
                if sub_text:
                    sub_text = f' ({sub_text})'
                add_item(items, (vendor, device, sub_vendor, sub_model), text + sub_text)

    with open('20-pci-vendor-model.hwdb', 'wt') as out:
        header(out, 'http://pci-ids.ucw.cz/v2.2/pci.ids')

        for key in sorted(items):
            if len(key) == 1:
                p, n = 'pci:v0000{}*', 'VENDOR'
            elif len(key) == 2:
                p, n = 'pci:v0000{}d0000{}*', 'MODEL'
            else:
                p, n = 'pci:v0000{}d0000{}sv0000{}sd0000{}*', 'MODEL'
            print('', p.format(*key),
                  f' ID_{n}_FROM_DATABASE={items[key]}', sep='\n', file=out)

    print(f'Wrote {out.name}')

def pci_classes(p):
    items = {}

    for klass_group in p.CLASSES:
        klass = klass_group.klass.upper()
        text = klass_group.text.strip()
        add_item(items, (klass,), text)

        for subclass_group in klass_group.SUBCLASSES:
            subclass = subclass_group.subclass.upper()
            text = subclass_group.text.strip()
            add_item(items, (klass, subclass), text)

            for protocol_group in subclass_group.PROTOCOLS:
                protocol = protocol_group.protocol.upper()
                text = protocol_group.name.strip()
                add_item(items, (klass, subclass, protocol), text)

    with open('20-pci-classes.hwdb', 'wt') as out:
        header(out, 'http://pci-ids.ucw.cz/v2.2/pci.ids')

        for key in sorted(items):
            if len(key) == 1:
                p, n = 'pci:v*d*sv*sd*bc{}*', 'CLASS'
            elif len(key) == 2:
                p, n = 'pci:v*d*sv*sd*bc{}sc{}*', 'SUBCLASS'
            else:
                p, n = 'pci:v*d*sv*sd*bc{}sc{}i{}*', 'INTERFACE'
            print('', p.format(*key),
                  f' ID_PCI_{n}_FROM_DATABASE={items[key]}', sep='\n', file=out)

    print(f'Wrote {out.name}')

def sdio_vendor_model(p):
    items = {}

    for vendor_group in p.VENDORS:
        vendor = vendor_group.vendor.upper()
        text = vendor_group.text.strip()
        add_item(items, (vendor,), text)

        for device_group in vendor_group.DEVICES:
            device = device_group.device.upper()
            text = device_group.text.strip()
            add_item(items, (vendor, device), text)

    with open('20-sdio-vendor-model.hwdb', 'wt') as out:
        header(out, 'hwdb/sdio.ids')

        for key in sorted(items):
            if len(key) == 1:
                p, n = 'sdio:c*v{}*', 'VENDOR'
            else:
                p, n = 'sdio:c*v{}d{}*', 'MODEL'
            print('', p.format(*key),
                  f' ID_{n}_FROM_DATABASE={items[key]}', sep='\n', file=out)

    print(f'Wrote {out.name}')

def sdio_classes(p):
    items = {}

    for klass_group in p.CLASSES:
        klass = klass_group.klass.upper()
        text = klass_group.text.strip()
        add_item(items, klass, text)

    with open('20-sdio-classes.hwdb', 'wt') as out:
        header(out, 'hwdb/sdio.ids')

        for klass in sorted(items):
            print(f'',
                  f'sdio:c{klass}v*d*',
                  f' ID_SDIO_CLASS_FROM_DATABASE={items[klass]}', sep='\n', file=out)

    print(f'Wrote {out.name}')

# MAC Address Block Large/Medium/Small
# Large  MA-L 24/24 bit (OUI)
# Medium MA-M 28/20 bit (OUI prefix owned by IEEE)
# Small  MA-S 36/12 bit (OUI prefix owned by IEEE)
def oui(p1, p2, p3):
    prefixes = set()
    items = {}

    for p, check in ((p1, False), (p2, False), (p3, True)):
        for vendor_group in p.VENDORS:
            prefix = vendor_group.prefix.upper()
            if check:
                if prefix in prefixes:
                    continue
            else:
                prefixes.add(prefix)
            start = vendor_group.start.upper()
            end = vendor_group.end.upper()

            if end and start != end:
                print(f'{prefix:} {start} != {end}', file=sys.stderr)
            text = vendor_group.text.strip()

            key = prefix + start if end else prefix
            add_item(items, key, text)

    with open('20-OUI.hwdb', 'wt') as out:
        header(out,
               'https://services13.ieee.org/RST/standards-ra-web/rest/assignments/download/?registry=MA-L&format=txt',
               'https://services13.ieee.org/RST/standards-ra-web/rest/assignments/download/?registry=MA-M&format=txt',
               'https://services13.ieee.org/RST/standards-ra-web/rest/assignments/download/?registry=MA-S&format=txt')

        for pattern in sorted(items):
            print(f'',
                  f'OUI:{pattern}*',
                  f' ID_OUI_FROM_DATABASE={items[pattern]}', sep='\n', file=out)

    print(f'Wrote {out.name}')

if __name__ == '__main__':
    args = sys.argv[1:]

    if not args or 'usb' in args:
        p = usb_ids_grammar().parseFile(open('usb.ids', errors='replace'))
        usb_vendor_model(p)
        usb_classes(p)

    if not args or 'pci' in args:
        p = pci_ids_grammar().parseFile(open('pci.ids', errors='replace'))
        pci_vendor_model(p)
        pci_classes(p)

    if not args or 'sdio' in args:
        p = pci_ids_grammar().parseFile(open('sdio.ids', errors='replace'))
        sdio_vendor_model(p)
        sdio_classes(p)

    if not args or 'oui' in args:
        p = oui_grammar('small').parseFile(open('ma-small.txt'))
        p2 = oui_grammar('medium').parseFile(open('ma-medium.txt'))
        p3 = oui_grammar('large').parseFile(open('ma-large.txt'))
        oui(p, p2, p3)
