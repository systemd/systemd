#  -*- Mode: python; indent-tabs-mode: nil -*- */
#
#  This file is part of systemd.
#
#  Copyright 2012 Lennart Poettering
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.
#
#  systemd is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with systemd; If not, see <http://www.gnu.org/licenses/>.

from xml.etree.ElementTree import parse, Element, SubElement, tostring
from sys import argv, stdout

index = {}

def prettify(elem, indent = 0):
        s = "\n" + indent * "  "
        if len(elem):
                if not elem.text or not elem.text.strip():
                        elem.text = s + "  "
                for e in elem:
                        prettify(e, indent + 1)
                        if not e.tail or not e.tail.strip():
                                e.tail = s + "  "
                if not e.tail or not e.tail.strip():
                        e.tail = s
        else:
                if indent and (not elem.tail or not elem.tail.strip()):
                        elem.tail = s

for p in argv[1:]:
        t = parse(p)
        section = t.find('./refmeta/manvolnum').text
        purpose = ' '.join(t.find('./refnamediv/refpurpose').text.split())
        for f in t.findall('./refnamediv/refname'):
                index[f.text] = (p, section, purpose)

html = Element('html')

head = SubElement(html, 'head')
title = SubElement(head, 'title')
title.text = 'Manual Page Index'

body = SubElement(html, 'body')
h1 = SubElement(body, 'h1')
h1.text = 'Manual Page Index'

letter = None
for n in sorted(index.keys(), key = str.lower):
        path, section, purpose = index[n]

        if path.endswith('.xml'):
                path = path[:-4] + ".html"

        c = path.rfind('/')
        if c >= 0:
                path = path[c+1:]

        if letter is None or n[0].upper() != letter:
                letter = n[0].upper()

                h2 = SubElement(body, 'h2')
                h2.text = letter

                ul = SubElement(body, 'ul')
                ul.set('style', 'list-style-type:none')

        li = SubElement(ul, 'li')

        a = SubElement(li, 'a')
        a.set('href', path)
        a.text = n + '(' + section + ')'
        a.tail = ' -- '

        i = SubElement(li, 'i')
        i.text = purpose

hr = SubElement(body, 'hr')

p = SubElement(body, 'p')
p.text = "This index contains %s entries, referring to %i individual manual pages." % (len(index), len(argv)-1)

if hasattr(stdout, "buffer"):
	stdout = stdout.buffer
prettify(html)
stdout.write(tostring(html))
