# -*- coding: utf-8 -*-
import sys
import collections
import xml.etree.ElementTree as tree

TEMPLATE = '''\
<refentry id="systemd.directives">

        <refentryinfo>
                <title>systemd.directives</title>
                <productname>systemd</productname>

                <authorgroup>
                        <author>
                                <contrib>Developer</contrib>
                                <firstname>Zbigniew</firstname>
                                <surname>Jędrzejewski-Szmek</surname>
                                <email>zbyszek@in.waw.pl</email>
                        </author>
                </authorgroup>
        </refentryinfo>

        <refmeta>
                <refentrytitle>systemd.directives</refentrytitle>
                <manvolnum>5</manvolnum>
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
                <title>System manager directives</title>

                <para>Directives for configuring the behaviour of the
                systemd process.</para>

                <variablelist id='systemd-directives' />
        </refsect1>

        <refsect1>
                <title>UDEV directives</title>

                <para>Directives for configuring systemd units through the
                udev database.</para>

                <variablelist id='udev-directives' />
        </refsect1>
</refentry>
'''

def _extract_directives(directive_groups, page):
    t = tree.parse(page)
    section = t.find('./refmeta/manvolnum').text
    pagename = t.find('./refmeta/refentrytitle').text
    for variablelist in t.iterfind('.//variablelist'):
        klass = variablelist.attrib.get('class') or 'unit-directives'
        stor = directive_groups[klass]
        for varname in variablelist.iterfind('./varlistentry/term/varname'):
            text = ''.join(varname.text.partition('=')[:2])
            stor[text].append((pagename, section))

def _make_section(refentry, name, directives):
    varlist = refentry.find(".//*[@id='{}']".format(name))
    for varname, manpages in sorted(directives.items()):
        entry = tree.SubElement(varlist, 'varlistentry')
        a = tree.SubElement(tree.SubElement(entry, 'term'), 'varname')
        a.text = varname
        para = tree.SubElement(tree.SubElement(entry, 'listitem'), 'para')

        b = None
        for manpage, manvolume in sorted(manpages):
                if b is not None:
                        b.tail = ', '
                b = tree.SubElement(para, 'citerefentry')
                c = tree.SubElement(b, 'refentrytitle')
                c.text = manpage
                d = tree.SubElement(b, 'manvolnum')
                d.text = manvolume
        entry.tail = '\n\n'

def _make_page(directive_groups):
    """Create an XML tree from directive_groups.

    directive_groups = {
       'class': {'variable': [('manpage', 'manvolume'), ...],
                 'variable2': ...},
       ...
    }
    """
    refentry = tree.fromstring(TEMPLATE)

    for name, directives in directive_groups.items():
            _make_section(refentry, name, directives)

    return refentry

def make_page(xml_files):
    "Extract directives from xml_files and return XML index tree."
    directive_groups = {name:collections.defaultdict(list)
                        for name in ['unit-directives',
                                     'udev-directives',
                                     'systemd-directives',
                                     ]}
    for page in xml_files:
        _extract_directives(directive_groups, page)

    return _make_page(directive_groups)

if __name__ == '__main__':
    tree.dump(make_page(sys.argv[1:]))
