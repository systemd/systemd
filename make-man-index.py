#!/usr/bin/env python

from xml.etree.ElementTree import parse, Element, SubElement, tostring
from sys import argv, stdout

index = {}

for p in argv[1:]:
        t = parse(p)
        section = t.find('./refmeta/manvolnum').text
        purpose = t.find('./refnamediv/refpurpose').text
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

                h2 = SubElement(body, 'h1')
                h2.text = letter

                ul = SubElement(body, 'ul')
                ul.set('style', 'list-style-type:none')

        li = SubElement(ul, 'li');

        a = SubElement(li, 'a');
        a.set('href', path)
        a.text = n + '(' + section + ')'
        a.tail = ' -- ' + purpose

stdout.write(tostring(html))
