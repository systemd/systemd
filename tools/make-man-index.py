#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import collections
import re
import sys

from xml_helper import tree, xml_parse, xml_print

MDASH = ' — ' if sys.version_info.major >= 3 else ' -- '

TEMPLATE = '''\
<refentry id="systemd.index">

  <refentryinfo>
    <title>systemd.index</title>
    <productname>systemd</productname>
  </refentryinfo>

  <refmeta>
    <refentrytitle>systemd.index</refentrytitle>
    <manvolnum>7</manvolnum>
  </refmeta>

  <refnamediv>
    <refname>systemd.index</refname>
    <refpurpose>List all manpages from the systemd project</refpurpose>
  </refnamediv>
</refentry>
'''

SUMMARY = '''\
  <refsect1>
    <title>See Also</title>
    <para>
      <citerefentry><refentrytitle>systemd.directives</refentrytitle><manvolnum>7</manvolnum></citerefentry>
    </para>

    <para id='counts' />
  </refsect1>
'''

COUNTS = '\
This index contains {count} entries, referring to {pages} individual manual pages.'


def check_id(page, t):
    page_id = t.getroot().get('id')
    if not re.search('/' + page_id + '[.]', page.translate(str.maketrans('@', '_'))):
        raise ValueError(f"id='{page_id}' is not the same as page name '{page}'")

def make_index(pages):
    index = collections.defaultdict(list)
    for p in pages:
        t = xml_parse(p)
        check_id(p, t)
        section = t.find('./refmeta/manvolnum').text
        refname = t.find('./refnamediv/refname').text
        purpose_text = ' '.join(t.find('./refnamediv/refpurpose').itertext())
        purpose = ' '.join(purpose_text.split())
        for f in t.findall('./refnamediv/refname'):
            infos = (f.text, section, purpose, refname)
            index[f.text[0].upper()].append(infos)
    return index

def add_letter(template, letter, pages):
    refsect1 = tree.SubElement(template, 'refsect1')
    title = tree.SubElement(refsect1, 'title')
    title.text = letter
    para = tree.SubElement(refsect1, 'para')
    for info in sorted(pages, key=lambda info: str.lower(info[0])):
        refname, section, purpose, _realname = info

        b = tree.SubElement(para, 'citerefentry')
        c = tree.SubElement(b, 'refentrytitle')
        c.text = refname
        d = tree.SubElement(b, 'manvolnum')
        d.text = section

        b.tail = MDASH + purpose # + ' (' + p + ')'

        tree.SubElement(para, 'sbr')

def add_summary(template, indexpages):
    count = 0
    pages = set()
    for group in indexpages:
        count += len(group)
        for info in group:
            _refname, section, _purpose, realname = info
            pages.add((realname, section))

    refsect1 = tree.fromstring(SUMMARY)
    template.append(refsect1)

    para = template.find(".//para[@id='counts']")
    para.text = COUNTS.format(count=count, pages=len(pages))

def make_page(*xml_files):
    template = tree.fromstring(TEMPLATE)
    index = make_index(xml_files)

    for letter in sorted(index):
        add_letter(template, letter, index[letter])

    add_summary(template, index.values())

    return template

if __name__ == '__main__':
    with open(sys.argv[1], 'wb') as file:
        file.write(xml_print(make_page(*sys.argv[2:])))
