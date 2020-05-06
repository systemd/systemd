#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1+

import collections
import sys
import os
import shlex
import subprocess
import io
from lxml import etree

PARSER = etree.XMLParser(no_network=True,
                         remove_comments=False,
                         strip_cdata=False,
                         resolve_entities=False)

PRINT_ERRORS = True

class NoCommand(Exception):
    pass

BORING_INTERFACES = [
    'org.freedesktop.DBus.Peer',
    'org.freedesktop.DBus.Introspectable',
    'org.freedesktop.DBus.Properties',
]

def print_method(declarations, elem, *, prefix, file, is_signal=False):
    name = elem.get('name')
    klass = 'signal' if is_signal else 'method'
    declarations[klass].append(name)

    print(f'''{prefix}{name}(''', file=file, end='')
    lead = ',\n' + prefix + ' ' * len(name) + ' '

    for num, arg in enumerate(elem.findall('./arg')):
        argname = arg.get('name')

        if argname is None:
            if PRINT_ERRORS:
                print(f'method {name}: argument {num+1} has no name', file=sys.stderr)
            argname = 'UNNAMED'

        type = arg.get('type')
        if not is_signal:
            direction = arg.get('direction')
            print(f'''{lead if num > 0 else ''}{direction:3} {type} {argname}''', file=file, end='')
        else:
            print(f'''{lead if num > 0 else ''}{type} {argname}''', file=file, end='')

    print(f');', file=file)

ACCESS_MAP = {
    'read' : 'readonly',
    'write' : 'readwrite',
}

def value_ellipsis(type):
    if type == 's':
        return "'...'";
    if type[0] == 'a':
        inner = value_ellipsis(type[1:])
        return f"[{inner}{', ...' if inner != '...' else ''}]";
    return '...'

def print_property(declarations, elem, *, prefix, file):
    name = elem.get('name')
    type = elem.get('type')
    access = elem.get('access')

    declarations['property'].append(name)

    # @org.freedesktop.DBus.Property.EmitsChangedSignal("false")
    # @org.freedesktop.systemd1.Privileged("true")
    # readwrite b EnableWallMessages = false;

    for anno in elem.findall('./annotation'):
        anno_name = anno.get('name')
        anno_value = anno.get('value')
        print(f'''{prefix}@{anno_name}("{anno_value}")''', file=file)

    access = ACCESS_MAP.get(access, access)
    print(f'''{prefix}{access} {type} {name} = {value_ellipsis(type)};''', file=file)

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

def document_has_elem_with_text(document, elem, item_repr):
    predicate = f".//{elem}" # [text() = 'foo'] doesn't seem supported :(
    for loc in document.findall(predicate):
        if loc.text == item_repr:
            return True
    else:
        return False

def check_documented(document, declarations):
    missing = []
    for klass, items in declarations.items():
        for item in items:
            if klass == 'method':
                elem = 'function'
                item_repr = f'{item}()'
            elif klass == 'signal':
                elem = 'function'
                item_repr = item
            elif klass == 'property':
                elem = 'varname'
                item_repr = item
            else:
                assert False, (klass, item)

            if not document_has_elem_with_text(document, elem, item_repr):
                if PRINT_ERRORS:
                    print(f'{klass} {item} is not documented :(')
                missing.append((klass, item))

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

    print(f'''}};''', file=file)

    return file.getvalue(), declarations, interfaces

def subst_output(document, programlisting):
    executable = programlisting.get('executable', None)
    if executable is None:
        # Not our thing
        return
    executable = programlisting.get('executable')
    node = programlisting.get('node')
    interface = programlisting.get('interface')

    argv = [f'{build_dir}/{executable}', f'--bus-introspect={interface}']
    print(f'COMMAND: {shlex.join(argv)}')

    try:
        out = subprocess.check_output(argv, text=True)
    except FileNotFoundError:
        print(f'{executable} not found, ignoring', file=sys.stderr)
        return

    xml = etree.fromstring(out, parser=PARSER)

    new_text, declarations, interfaces = xml_to_text(node, xml, only_interface=interface)
    programlisting.text = '\n' + new_text + '    '

    if declarations:
        missing = check_documented(document, declarations)
        parent = programlisting.getparent()

        # delete old comments
        for child in parent:
            if (child.tag == etree.Comment
                and 'Autogenerated' in child.text):
                parent.remove(child)
            if (child.tag == etree.Comment
                and 'not documented' in child.text):
                parent.remove(child)
            if (child.tag == "variablelist"
                and child.attrib.get("generated",False) == "True"):
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
                if decl_type == 'method' :
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

def process(page):
    src = open(page).read()
    xml = etree.fromstring(src, parser=PARSER)

    # print('parsing {}'.format(name), file=sys.stderr)
    if xml.tag != 'refentry':
        return

    pls = xml.findall('.//programlisting')
    for pl in pls:
        subst_output(xml, pl)

    out_text = etree.tostring(xml, encoding='unicode')
    # massage format to avoid some lxml whitespace handling idiosyncrasies
    # https://bugs.launchpad.net/lxml/+bug/526799
    out_text = (src[:src.find('<refentryinfo')] +
                out_text[out_text.find('<refentryinfo'):] +
                '\n')

    with open(page, 'w') as out:
        out.write(out_text)

if __name__ == '__main__':
    pages = sys.argv[1:]

    if pages[0].startswith('--build-dir='):
        build_dir = pages[0].partition('=')[2]
        pages = pages[1:]
    else:
        build_dir = 'build'

    if not os.path.exists(f'{build_dir}/systemd'):
        exit(f"{build_dir}/systemd doesn't exist. Use --build-dir=.")

    for page in pages:
        process(page)
