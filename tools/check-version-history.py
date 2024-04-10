#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import sys

try:
    import lxml.etree as tree
except ImportError as e:
    print(str(e), file=sys.stderr)
    sys.exit(77)

_parser = tree.XMLParser(resolve_entities=False)
tree.set_default_parser(_parser)


def find_undocumented_functions(pages, ignorelist):
    undocumented = []
    for page in pages:
        filename = os.path.basename(page)
        pagetree = tree.parse(page)

        assert pagetree.getroot().tag == "refentry"

        hist_section = pagetree.find("refsect1[title='History']")
        for func in pagetree.findall("//funcprototype/funcdef/function"):
            path = f"/refsynopsisdiv/funcsynopsis/funcprototype/funcdef/function[.='{func.text}']"
            assert pagetree.findall(path) == [func]

            if (
                hist_section is None
                or hist_section.find(f"para/function[.='{func.text}()']") is None
            ):
                if func.text not in ignorelist:
                    undocumented.append((filename, func.text))
    return undocumented


def construct_path(element):
    tag = element.tag

    if tag == "refentry":
        return ""

    predicate = ""
    if tag == "varlistentry":
        text = "".join(element.find("term").itertext())
        predicate = f'[term="{text}"]'
    elif tag.startswith("refsect"):
        text = "".join(element.find("title").itertext())
        predicate = f'[title="{text}"]'
    elif tag == "variablelist":
        varlists = element.getparent().findall(tag)
        if len(varlists) > 1:
            predicate = f"[{varlists.index(element)+1}]"

    return construct_path(element.getparent()) + "/" + tag + predicate


def find_undocumented_commands(pages, ignorelist):
    undocumented = []
    for page in pages:
        filename = os.path.basename(page)

        pagetree = tree.parse(page)
        if pagetree.getroot().tag != "refentry":
            continue

        for varlistentry in pagetree.findall("*//variablelist/varlistentry"):
            path = construct_path(varlistentry)

            assert pagetree.findall(path) == [varlistentry]

            listitem = varlistentry.find("listitem")
            parent = listitem if listitem is not None else varlistentry

            rev = parent.getchildren()[-1]
            if rev.get("href") != "version-info.xml":
                if (filename, path) not in ignorelist:
                    undocumented.append((filename, path))
    return undocumented


def process_pages(pages):
    command_pages = []
    function_pages = []

    for page in pages:
        filename = os.path.basename(page)
        if filename.startswith("org.freedesktop."):  # dbus
            continue

        if (
            filename.startswith("sd_")
            or filename.startswith("sd-")
            or filename.startswith("udev_")
        ):
            function_pages.append(page)
            continue

        command_pages.append(page)

    undocumented_commands = find_undocumented_commands(
        command_pages, command_ignorelist
    )
    undocumented_functions = find_undocumented_functions(
        function_pages, function_ignorelist
    )

    return undocumented_commands, undocumented_functions


if __name__ == "__main__":
    with open(os.path.join(os.path.dirname(__file__), "command_ignorelist")) as f:
        command_ignorelist = []
        for l in f.read().splitlines():
            if l.startswith("#"):
                continue
            fname, path = l.split(" ", 1)
            path = path.replace("\\n", "\n")
            command_ignorelist.append((fname, path))
    with open(os.path.join(os.path.dirname(__file__), "function_ignorelist")) as f:
        function_ignorelist = f.read().splitlines()

    undocumented_commands, undocumented_functions = process_pages(sys.argv[1:])

    if undocumented_commands or undocumented_functions:
        for filename, func in undocumented_functions:
            print(
                f"Function {func}() in {filename} isn't documented in the History section."
            )
        for filename, path in undocumented_commands:
            print(filename, path, "is undocumented")
        if undocumented_commands:
            print(
                "Hint: if you reorganized this part of the documentation, "
                "please update tools/commands_ignorelist."
            )

        sys.exit(1)
