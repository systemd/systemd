#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
import argparse
import logging
import re
from typing import Iterator  # XXX deprecated in python3.9
from pathlib import Path

try:
    from lxml import etree
except ImportError:
    etree = None
import jinja2

logger = logging.getLogger(Path(__file__).stem)


def extract_properties(
    xml: str,
    *,
    xpath: str = "//refsect1//variablelist/varlistentry/term/varname",
) -> Iterator[str]:
    """extract properties from the specified XML file"""
    yield f"# {re.sub('.*/man/', 'man/', xml)}"

    if not etree:
        logger.warning(
            "lxml is not available, cannot generate completion for properties"
        )
        return
    try:
        tree = etree.parse(xml)
    except SyntaxError as e:
        logger.error(e)
        return

    root = tree.getroot()
    varnames = root.xpath(xpath)
    for v in varnames:
        m = re.search(r"^([A-Za-z]+=).*", v.text)
        if m:
            yield m.group(1)


def main():
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i",
        "--input",
        help="template file for shell completion; "
        "if not specified, print extracted properties to OUTPUT",
        type=argparse.FileType(),
    )
    parser.add_argument(
        "-o",
        "--output",
        help="defaults to stdout",
        type=argparse.FileType("w"),
        default="-",
    )
    parser.add_argument(
        "property_file",
        nargs="+",
        help="file(s) from which properties are extracted, "
        "e.g. ../man/systemd.resource-control.xml",
    )
    args = parser.parse_args()

    properties = "\n".join("\n".join(extract_properties(x)) for x in args.property_file)

    if args.input:
        with args.input as f:
            txt = f.read()
        template = jinja2.Template(txt)
        txt = template.render(properties=properties)
    else:
        logger.info(f"--input not specified, print properties to {args.output.name}")
        txt = properties

    with args.output as f:
        f.write(txt + "\n")


if __name__ == "__main__":
    main()
