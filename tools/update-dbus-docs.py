#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
# pylint: disable=superfluous-parens,consider-using-with

import argparse
import collections
import sys
import os
import subprocess
import io

try:
    from lxml import etree
except ModuleNotFoundError as e:
    etree = e

try:
    from shlex import join as shlex_join
except ImportError as e:
    shlex_join = e

try:
    from shlex import quote as shlex_quote
except ImportError as e:
    shlex_quote = e

class NoCommand(Exception):
    pass

BORING_INTERFACES = [
    'org.freedesktop.DBus.Peer',
    'org.freedesktop.DBus.Introspectable',
    'org.freedesktop.DBus.Properties',
]
RED = '\x1b[31m'
GREEN = '\x1b[32m'
YELLOW = '\x1b[33m'
RESET = '\x1b[39m'

arguments = None

def xml_parser():
    return etree.XMLParser(no_network=True,
                           remove_comments=False,
                           strip_cdata=False,
                           resolve_entities=False)

def print_method(declarations, elem, *, prefix, file, is_signal=False):
    name = elem.get('name')
    klass = 'signal' if is_signal else 'method'
    declarations[klass].append(name)

    # @org.freedesktop.systemd1.Privileged("true")
    # SetShowStatus(in  s mode);

    for anno in elem.findall('./annotation'):
        anno_name = anno.get('name')
        anno_value = anno.get('value')
        print(f'''{prefix}@{anno_name}("{anno_value}")''', file=file)

    print(f'''{prefix}{name}(''', file=file, end='')
    lead = ',\n' + prefix + ' ' * len(name) + ' '

    for num, arg in enumerate(elem.findall('./arg')):
        argname = arg.get('name')

        if argname is None:
            if arguments.print_errors:
                print(f'method {name}: argument {num+1} has no name', file=sys.stderr)
            argname = 'UNNAMED'

        argtype = arg.get('type')
        if not is_signal:
            direction = arg.get('direction')
            print(f'''{lead if num > 0 else ''}{direction:3} {argtype} {argname}''', file=file, end='')
        else:
            print(f'''{lead if num > 0 else ''}{argtype} {argname}''', file=file, end='')

    print(');', file=file)

ACCESS_MAP = {
    'read' : 'readonly',
    'write' : 'readwrite',
}

def value_ellipsis(prop_type):
    if prop_type == 's':
        return "'...'"
    if prop_type[0] == 'a':
        inner = value_ellipsis(prop_type[1:])
        return f"[{inner}{', ...' if inner != '...' else ''}]"
    return '...'

def print_property(declarations, elem, *, prefix, file):
    prop_name = elem.get('name')
    prop_type = elem.get('type')
    prop_access = elem.get('access')

    declarations['property'].append(prop_name)

    # @org.freedesktop.DBus.Property.EmitsChangedSignal("false")
    # @org.freedesktop.systemd1.Privileged("true")
    # readwrite b EnableWallMessages = false;

    for anno in elem.findall('./annotation'):
        anno_name = anno.get('name')
        anno_value = anno.get('value')
        print(f'''{prefix}@{anno_name}("{anno_value}")''', file=file)

    prop_access = ACCESS_MAP.get(prop_access, prop_access)
    print(f'''{prefix}{prop_access} {prop_type} {prop_name} = {value_ellipsis(prop_type)};''', file=file)

def print_interface(iface, *, prefix, file, print_boring, only_interface, declarations):
    name = iface.get('name')

    is_boring = (name in BORING_INTERFACES or
                 only_interface is not None and name != only_interface)

    if is_boring and print_boring:
        print(f'''{prefix}interface {name} {{ ... }};''', file=file)

    elif not is_boring and not print_boring:
        print(f'''{prefix}interface {name} {{''', file=file)
        prefix2 = prefix + '  '

        for num, elem in enumerate(iface.findall('./method')):
            if num == 0:
                print(f'''{prefix2}methods:''', file=file)
            print_method(declarations, elem, prefix=prefix2 + '  ', file=file)

        for num, elem in enumerate(iface.findall('./signal')):
            if num == 0:
                print(f'''{prefix2}signals:''', file=file)
            print_method(declarations, elem, prefix=prefix2 + '  ', file=file, is_signal=True)

        for num, elem in enumerate(iface.findall('./property')):
            if num == 0:
                print(f'''{prefix2}properties:''', file=file)
            print_property(declarations, elem, prefix=prefix2 + '  ', file=file)

        print(f'''{prefix}}};''', file=file)

def check_documented(document, declarations, stats, interface, missing_version):
    missing = []

    sections = document.findall("refsect1")
    history_section = document.find("refsect1[title = 'History']")
    if history_section is not None:
        sections.remove(history_section)

    for klass, items in declarations.items():
        stats['total'] += len(items)

        for item in items:
            if klass in ('method', 'signal'):
                elem = 'function'
                item_repr = f'{item}()'

                # Find all functions/signals in <function> elements that are not
                # suffixed with '()' and fix them
                for section in sections:
                    element = section.find(f".//{elem}[. = '{item}']")
                    if element is not None:
                        element.text = item_repr

            elif klass == 'property':
                elem = 'varname'
                item_repr = item
            else:
                assert False, (klass, item)

            predicate = f".//{elem}[. = '{item_repr}']"
            if not any(section.find(predicate) is not None for section in sections):
                if arguments.print_errors:
                    print(f'{klass} {item} is not documented :(')
                missing.append((klass, item))

            if history_section is None or history_section.find(predicate) is None:
                missing_version.append(f"{interface}.{item_repr}")

    stats['missing'] += len(missing)

    return missing

def xml_to_text(destination, xml, *, only_interface=None):
    file = io.StringIO()

    declarations = collections.defaultdict(list)
    interfaces = []

    print(f'''node {destination} {{''', file=file)

    for print_boring in [False, True]:
        for iface in xml.findall('./interface'):
            print_interface(iface, prefix='  ', file=file,
                            print_boring=print_boring,
                            only_interface=only_interface,
                            declarations=declarations)
            name = iface.get('name')
            if not name in BORING_INTERFACES:
                interfaces.append(name)

    print('''};''', file=file)

    return file.getvalue(), declarations, interfaces

def subst_output(document, programlisting, stats, missing_version):
    executable = programlisting.get('executable', None)
    if executable is None:
        # Not our thing
        return
    executable = programlisting.get('executable')
    node = programlisting.get('node')
    interface = programlisting.get('interface')

    argv = [f'{arguments.build_dir}/{executable}', f'--bus-introspect={interface}']
    if isinstance(shlex_join, Exception):
        print(f'COMMAND: {" ".join(shlex_quote(arg) for arg in argv)}')
    else:
        print(f'COMMAND: {shlex_join(argv)}')

    try:
        out = subprocess.check_output(argv, universal_newlines=True)
    except FileNotFoundError:
        print(f'{executable} not found, ignoring', file=sys.stderr)
        return

    xml = etree.fromstring(out, parser=xml_parser())

    new_text, declarations, interfaces = xml_to_text(node, xml, only_interface=interface)
    programlisting.text = '\n' + new_text

    if declarations:
        missing = check_documented(document, declarations, stats, interface, missing_version)
        parent = programlisting.getparent()

        # delete old comments
        for child in parent:
            if child.tag is etree.Comment and 'Autogenerated' in child.text:
                parent.remove(child)
            if child.tag is etree.Comment and 'not documented' in child.text:
                parent.remove(child)
            if child.tag == "variablelist" and child.attrib.get("generated", False) == "True":
                parent.remove(child)

        # insert pointer for systemd-directives generation
        the_tail = programlisting.tail #tail is erased by addnext, so save it here.
        prev_element = etree.Comment("Autogenerated cross-references for systemd.directives, do not edit")
        programlisting.addnext(prev_element)
        programlisting.tail = the_tail

        for interface in interfaces:
            variablelist = etree.Element("variablelist")
            variablelist.attrib['class'] = 'dbus-interface'
            variablelist.attrib['generated'] = 'True'
            variablelist.attrib['extra-ref'] = interface

            prev_element.addnext(variablelist)
            prev_element.tail = the_tail
            prev_element = variablelist

        for decl_type,decl_list in declarations.items():
            for declaration in decl_list:
                variablelist = etree.Element("variablelist")
                variablelist.attrib['class'] = 'dbus-'+decl_type
                variablelist.attrib['generated'] = 'True'
                if decl_type in ('method', 'signal'):
                    variablelist.attrib['extra-ref'] = declaration + '()'
                else:
                    variablelist.attrib['extra-ref'] = declaration

                prev_element.addnext(variablelist)
                prev_element.tail = the_tail
                prev_element = variablelist

        last_element = etree.Comment("End of Autogenerated section")
        prev_element.addnext(last_element)
        prev_element.tail = the_tail
        last_element.tail = the_tail

        # insert comments for undocumented items
        for item in reversed(missing):
            comment = etree.Comment(f'{item[0]} {item[1]} is not documented!')
            comment.tail = programlisting.tail
            parent.insert(parent.index(programlisting) + 1, comment)

def process(page, missing_version):
    src = open(page).read()
    xml = etree.fromstring(src, parser=xml_parser())

    # print('parsing {}'.format(name), file=sys.stderr)
    if xml.tag != 'refentry':
        return None

    stats = collections.Counter()

    pls = xml.findall('.//programlisting')
    for pl in pls:
        subst_output(xml, pl, stats, missing_version)

    out_text = etree.tostring(xml, encoding='unicode')
    # massage format to avoid some lxml whitespace handling idiosyncrasies
    # https://bugs.launchpad.net/lxml/+bug/526799
    out_text = (src[:src.find('<refentryinfo')] +
                out_text[out_text.find('<refentryinfo'):] +
                '\n')

    if not arguments.test:
        with open(page, 'w') as out:
            out.write(out_text)

    return { "stats" : stats, "modified" : out_text != src }

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--test', action='store_true',
                   help='only verify that everything is up2date')
    p.add_argument('--build-dir', default='build')
    p.add_argument('pages', nargs='+')
    opts = p.parse_args()
    opts.print_errors = not opts.test
    return opts

def main():
    # pylint: disable=global-statement
    global arguments
    arguments = parse_args()

    for item in (etree, shlex_quote):
        if isinstance(item, Exception):
            print(item, file=sys.stderr)
            sys.exit(77 if arguments.test else 1)

    if not os.path.exists(f'{arguments.build_dir}/systemd'):
        sys.exit(f"{arguments.build_dir}/systemd doesn't exist. Use --build-dir=.")

    missing_version = []
    stats = {page.split('/')[-1] : process(page, missing_version) for page in arguments.pages}

    ignore_list = open(os.path.join(os.path.dirname(__file__), 'dbus_ignorelist')).read().split()
    missing_version = [x for x in missing_version if x not in ignore_list]

    for missing in missing_version:
        print(f"{RED}Missing version information for {missing}{RESET}")

    if missing_version:
        sys.exit(1)

    # Let's print all statistics at the end
    mlen = max(len(page) for page in stats)
    total = sum((item['stats'] for item in stats.values()), collections.Counter())
    total = 'total', { "stats" : total, "modified" : False }
    modified = []
    classification = 'OUTDATED' if arguments.test else 'MODIFIED'
    for page, info in sorted(stats.items()) + [total]:
        m = info['stats']['missing']
        t = info['stats']['total']
        p = page + ':'
        c = classification if info['modified'] else ''
        if c:
            modified.append(page)
        color = RED if m > t/2 else (YELLOW if m else GREEN)
        print(f'{color}{p:{mlen + 1}} {t - m}/{t} {c}{RESET}')

    if arguments.test and modified:
        sys.exit(f'Outdated pages: {", ".join(modified)}\n'
                 f'Hint: ninja -C {arguments.build_dir} update-dbus-docs')

if __name__ == '__main__':
    main()
