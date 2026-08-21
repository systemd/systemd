#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Generates systemd.varlink(7), the index page for all Varlink interfaces documented in
man pages. Based on make-man-index.py, but lists Varlink interfaces rather than all
manual pages."""

import sys

from xml_helper import tree, xml_parse, xml_print

MDASH = ' — '

TEMPLATE = '''\
<refentry id="systemd.varlink">

  <refentryinfo>
    <title>systemd.varlink</title>
    <productname>systemd</productname>
  </refentryinfo>

  <refmeta>
    <refentrytitle>systemd.varlink</refentrytitle>
    <manvolnum>7</manvolnum>
  </refmeta>

  <refnamediv>
    <refname>systemd.varlink</refname>
    <refpurpose>List all Varlink interfaces exported by the systemd project</refpurpose>
  </refnamediv>

  <refsect1>
    <title>Description</title>

    <para>This page lists the Varlink interfaces provided by
    <citerefentry><refentrytitle>systemd</refentrytitle><manvolnum>1</manvolnum></citerefentry>-related
    components. Each interface is documented on its own manual page, which includes its full
    interface definition. The interfaces can be introspected and called with
    <citerefentry><refentrytitle>varlinkctl</refentrytitle><manvolnum>1</manvolnum></citerefentry>,
    and their methods, types and errors are indexed in
    <citerefentry><refentrytitle>systemd.directives</refentrytitle><manvolnum>7</manvolnum></citerefentry>.</para>
  </refsect1>
</refentry>
'''

SUMMARY_SEE_ALSO = '''\
  <refsect1>
    <title>See Also</title>
    <para>
      <citerefentry><refentrytitle>varlinkctl</refentrytitle><manvolnum>1</manvolnum></citerefentry>
      <citerefentry><refentrytitle>systemd.directives</refentrytitle><manvolnum>7</manvolnum></citerefentry>
      <citerefentry><refentrytitle>systemd.index</refentrytitle><manvolnum>7</manvolnum></citerefentry>
    </para>

    <para id='counts' />
  </refsect1>
'''

COUNTS = '\
This index contains {count} entries.'


def check_id(page, t):
    page_id = t.getroot().get('id')
    if not page.endswith('/' + page_id + '.xml'):
        raise ValueError(f"id='{page_id}' is not the same as page name '{page}'")


def make_index(pages):
    index = []
    for p in pages:
        t = xml_parse(p)
        check_id(p, t)
        refname = t.find('./refnamediv/refname').text
        purpose_text = ' '.join(t.find('./refnamediv/refpurpose').itertext())
        purpose = ' '.join(purpose_text.split())
        index.append((refname, purpose))
    return sorted(index)


def add_interfaces(template, interfaces):
    refsect1 = tree.SubElement(template, 'refsect1')
    title = tree.SubElement(refsect1, 'title')
    title.text = 'Interfaces'

    para = tree.SubElement(refsect1, 'para')
    for refname, purpose in interfaces:
        b = tree.SubElement(para, 'citerefentry')
        c = tree.SubElement(b, 'refentrytitle')
        c.text = refname
        d = tree.SubElement(b, 'manvolnum')
        d.text = '5'

        b.tail = MDASH + purpose

        tree.SubElement(para, 'sbr')


def add_summary(template, interfaces):
    template.append(tree.fromstring(SUMMARY_SEE_ALSO))

    para = template.find(".//para[@id='counts']")
    para.text = COUNTS.format(count=len(interfaces))


def make_page(*xml_files):
    template = tree.fromstring(TEMPLATE)
    interfaces = make_index(xml_files)

    add_interfaces(template, interfaces)
    add_summary(template, interfaces)

    return template


if __name__ == '__main__':
    with open(sys.argv[1], 'wb') as file:
        file.write(xml_print(make_page(*sys.argv[2:])))
