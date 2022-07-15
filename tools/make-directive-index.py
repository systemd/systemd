#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import sys
import collections
import re
from xml_helper import xml_parse, xml_print, tree
from copy import deepcopy

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
        searchpath = variablelist.attrib.get('xpath','./varlistentry/term/varname')
        storvar = directive_groups[klass or 'miscellaneous']
        # <option>s go in OPTIONS, unless class is specified
        for xpath, stor in ((searchpath, storvar),
                            ('./varlistentry/term/option',
                             storvar if klass else storopt)):
            for name in variablelist.iterfind(xpath):
                text = re.sub(r'([= ]).*', r'\1', name.text).rstrip()
                if text.startswith('-'):
                    # for options, merge options with and without mandatory arg
                    text = text.partition('=')[0]
                stor[text].append((pagename, section))
                if text not in formatting:
                    # use element as formatted display
                    if name.text[-1] in "= '":
                        name.clear()
                    else:
                        name.tail = ''
                    name.text = text
                    formatting[text] = name
        extra = variablelist.attrib.get('extra-ref')
        if extra:
            stor[extra].append((pagename, section))
            if extra not in formatting:
                elt = tree.Element("varname")
                elt.text= extra
                formatting[extra] = elt

    storfile = directive_groups['filenames']
    for xpath, absolute_only in (('.//refsynopsisdiv//filename', False),
                                 ('.//refsynopsisdiv//command', False),
                                 ('.//filename', True)):
        for name in t.iterfind(xpath):
            if absolute_only and not (name.text and name.text.startswith('/')):
                continue
            if name.attrib.get('index') == 'false':
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

    for name in t.iterfind('.//constant'):
        if name.attrib.get('index') == 'false':
            continue
        name.tail = ''
        if name.text.startswith('('): # a cast, strip it
            name.text = name.text.partition(' ')[2]
        klass = name.attrib.get('class') or 'constants'
        storfile = directive_groups[klass]
        storfile[name.text].append((pagename, section))
        formatting[name.text] = name

    storfile = directive_groups['specifiers']
    for name in t.iterfind(".//table[@class='specifiers']//entry/literal"):
        if name.text[0] != '%' or name.getparent().text is not None:
            continue
        if name.attrib.get('index') == 'false':
            continue
        storfile[name.text].append((pagename, section))
        formatting[name.text] = name
    for name in t.iterfind(".//literal[@class='specifiers']"):
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

def make_page(template_path, xml_files):
    "Extract directives from xml_files and return XML index tree."
    template = xml_parse(template_path)
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
        template_path = sys.argv[2]
        xml_files = sys.argv[3:]
        xml = make_page(template_path, xml_files)
        f.write(xml_print(xml))
