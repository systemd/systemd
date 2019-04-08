#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1+

import sys
import collections
import re
from xml_helper import xml_parse, xml_print, tree
from copy import deepcopy

TEMPLATE = '''\
<refentry id="systemd.directives" conditional="HAVE_PYTHON">

        <refentryinfo>
                <title>systemd.directives</title>
                <productname>systemd</productname>
        </refentryinfo>

        <refmeta>
                <refentrytitle>systemd.directives</refentrytitle>
                <manvolnum>7</manvolnum>
        </refmeta>

        <refnamediv>
                <refname>systemd.directives</refname>
                <refpurpose>Index of configuration directives</refpurpose>
        </refnamediv>

        <refsect1>
                <title>Unit directives</title>

                <para>Directives for configuring units, used in unit
                files.</para>

                <variablelist id='unit-directives' />
        </refsect1>

        <refsect1>
                <title>Options on the kernel command line</title>

                <para>Kernel boot options for configuring the behaviour of the
                systemd process.</para>

                <variablelist id='kernel-commandline-options' />
        </refsect1>

        <refsect1>
                <title>Environment variables</title>

                <para>Environment variables understood by the systemd manager
                and other programs and environment variable-compatible settings.</para>

                <variablelist id='environment-variables' />
        </refsect1>

        <refsect1>
                <title>EFI variables</title>

                <para>EFI variables understood by
                <citerefentry><refentrytitle>systemd-boot</refentrytitle><manvolnum>7</manvolnum></citerefentry>
                and other programs.</para>

                <variablelist id='efi-variables' />
        </refsect1>

        <refsect1>
                <title>UDEV directives</title>

                <para>Directives for configuring systemd units through the
                udev database.</para>

                <variablelist id='udev-directives' />
        </refsect1>

        <refsect1>
                <title>Network directives</title>

                <para>Directives for configuring network links through the
                net-setup-link udev builtin and networks through
                systemd-networkd.</para>

                <variablelist id='network-directives' />
        </refsect1>

        <refsect1>
                <title>Journal fields</title>

                <para>Fields in the journal events with a well known meaning.</para>

                <variablelist id='journal-directives' />
        </refsect1>

        <refsect1>
                <title>PAM configuration directives</title>

                <para>Directives for configuring PAM behaviour.</para>

                <variablelist id='pam-directives' />
        </refsect1>

        <refsect1>
                <title><filename>/etc/crypttab</filename> and
                <filename>/etc/fstab</filename> options</title>

                <para>Options which influence mounted filesystems and
                encrypted volumes.</para>

                <variablelist id='fstab-options' />
        </refsect1>

        <refsect1>
                <title><citerefentry><refentrytitle>systemd.nspawn</refentrytitle><manvolnum>5</manvolnum></citerefentry>
                directives</title>

                <para>Directives for configuring systemd-nspawn containers.</para>

                <variablelist id='nspawn-directives' />
        </refsect1>

        <refsect1>
                <title>Program configuration options</title>

                <para>Directives for configuring the behaviour of the
                systemd process and other tools through configuration files.</para>

                <variablelist id='config-directives' />
        </refsect1>

        <refsect1>
                <title>Command line options</title>

                <para>Command-line options accepted by programs in the
                systemd suite.</para>

                <variablelist id='options' />
        </refsect1>

        <refsect1>
                <title>Constants</title>

                <para>Various constant used and/or defined by systemd.</para>

                <variablelist id='constants' />
        </refsect1>

        <refsect1>
                <title>Miscellaneous options and directives</title>

                <para>Other configuration elements which don't fit in
                any of the above groups.</para>

                <variablelist id='miscellaneous' />
        </refsect1>

        <refsect1>
                <title>Files and directories</title>

                <para>Paths and file names referred to in the
                documentation.</para>

                <variablelist id='filenames' />
        </refsect1>

        <refsect1>
                <title>Colophon</title>
                <para id='colophon' />
        </refsect1>
</refentry>
'''

COLOPHON = '''\
This index contains {count} entries in {sections} sections,
referring to {pages} individual manual pages.
'''

def _extract_directives(directive_groups, formatting, page):
    t = xml_parse(page)
    section = t.find('./refmeta/manvolnum').text
    pagename = t.find('./refmeta/refentrytitle').text

    storopt = directive_groups['options']
    for variablelist in t.iterfind('.//variablelist'):
        klass = variablelist.attrib.get('class')
        storvar = directive_groups[klass or 'miscellaneous']
        # <option>s go in OPTIONS, unless class is specified
        for xpath, stor in (('./varlistentry/term/varname', storvar),
                            ('./varlistentry/term/option',
                             storvar if klass else storopt)):
            for name in variablelist.iterfind(xpath):
                text = re.sub(r'([= ]).*', r'\1', name.text).rstrip()
                stor[text].append((pagename, section))
                if text not in formatting:
                    # use element as formatted display
                    if name.text[-1] in '= ':
                        name.clear()
                    else:
                        name.tail = ''
                    name.text = text
                    formatting[text] = name

    storfile = directive_groups['filenames']
    for xpath, absolute_only in (('.//refsynopsisdiv//filename', False),
                                 ('.//refsynopsisdiv//command', False),
                                 ('.//filename', True)):
        for name in t.iterfind(xpath):
            if absolute_only and not (name.text and name.text.startswith('/')):
                continue
            if name.attrib.get('noindex'):
                continue
            name.tail = ''
            if name.text:
                if name.text.endswith('*'):
                    name.text = name.text[:-1]
                if not name.text.startswith('.'):
                    text = name.text.partition(' ')[0]
                    if text != name.text:
                        name.clear()
                        name.text = text
                    if text.endswith('/'):
                        text = text[:-1]
                    storfile[text].append((pagename, section))
                    if text not in formatting:
                        # use element as formatted display
                        formatting[text] = name
            else:
                text = ' '.join(name.itertext())
                storfile[text].append((pagename, section))
                formatting[text] = name

    storfile = directive_groups['constants']
    for name in t.iterfind('.//constant'):
        if name.attrib.get('noindex'):
            continue
        name.tail = ''
        if name.text.startswith('('): # a cast, strip it
            name.text = name.text.partition(' ')[2]
        storfile[name.text].append((pagename, section))
        formatting[name.text] = name

def _make_section(template, name, directives, formatting):
    varlist = template.find(".//*[@id='{}']".format(name))
    for varname, manpages in sorted(directives.items()):
        entry = tree.SubElement(varlist, 'varlistentry')
        term = tree.SubElement(entry, 'term')
        display = deepcopy(formatting[varname])
        term.append(display)

        para = tree.SubElement(tree.SubElement(entry, 'listitem'), 'para')

        b = None
        for manpage, manvolume in sorted(set(manpages)):
            if b is not None:
                b.tail = ', '
            b = tree.SubElement(para, 'citerefentry')
            c = tree.SubElement(b, 'refentrytitle')
            c.text = manpage
            c.attrib['target'] = varname
            d = tree.SubElement(b, 'manvolnum')
            d.text = manvolume
        entry.tail = '\n\n'

def _make_colophon(template, groups):
    count = 0
    pages = set()
    for group in groups:
        count += len(group)
        for pagelist in group.values():
            pages |= set(pagelist)

    para = template.find(".//para[@id='colophon']")
    para.text = COLOPHON.format(count=count,
                                sections=len(groups),
                                pages=len(pages))

def _make_page(template, directive_groups, formatting):
    """Create an XML tree from directive_groups.

    directive_groups = {
       'class': {'variable': [('manpage', 'manvolume'), ...],
                 'variable2': ...},
       ...
    }
    """
    for name, directives in directive_groups.items():
        _make_section(template, name, directives, formatting)

    _make_colophon(template, directive_groups.values())

    return template

def make_page(*xml_files):
    "Extract directives from xml_files and return XML index tree."
    template = tree.fromstring(TEMPLATE)
    names = [vl.get('id') for vl in template.iterfind('.//variablelist')]
    directive_groups = {name:collections.defaultdict(list)
                        for name in names}
    formatting = {}
    for page in xml_files:
        try:
            _extract_directives(directive_groups, formatting, page)
        except Exception:
            raise ValueError("failed to process " + page)

    return _make_page(template, directive_groups, formatting)

if __name__ == '__main__':
    with open(sys.argv[1], 'wb') as f:
        f.write(xml_print(make_page(*sys.argv[2:])))
