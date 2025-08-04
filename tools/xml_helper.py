#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

from lxml import etree as tree


class CustomResolver(tree.Resolver):
    def resolve(self, url, _id, context):
        if 'custom-entities.ent' in url:
            return self.resolve_filename('man/custom-entities.ent', context)
        if 'ethtool-link-mode' in url:
            return self.resolve_filename('src/shared/ethtool-link-mode.xml', context)
        if 'bpf-delegate' in url:
            return self.resolve_filename('src/core/bpf-delegate.xml', context)

        return None

_parser = tree.XMLParser()
# pylint: disable=no-member
_parser.resolvers.add(CustomResolver())

def xml_parse(page):
    doc = tree.parse(page, _parser)
    doc.xinclude()
    return doc

def xml_print(xml):
    return tree.tostring(xml, pretty_print=True, encoding='utf-8')
