#!/usr/bin/python3
#  -*- Mode: python; coding: utf-8; indent-tabs-mode: nil -*- */
#
#  This file is part of systemd.
#
#  Copyright 2016 Zbigniew Jędrzejewski-Szmek
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.
#
#  systemd is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with systemd; If not, see <http://www.gnu.org/licenses/>.

import functools
import glob
import string
import sys
import os

try:
    from pyparsing import (Word, White, Literal, ParserElement, Regex,
                           LineStart, LineEnd,
                           ZeroOrMore, OneOrMore, Combine, Or, Optional, Suppress, Group,
                           nums, alphanums, printables,
                           stringEnd, pythonStyleComment,
                           ParseBaseException)
except ImportError:
    print('pyparsing is not available')
    sys.exit(77)

try:
    from evdev.ecodes import ecodes
except ImportError:
    ecodes = None
    print('WARNING: evdev is not available')

EOL = LineEnd().suppress()
EMPTYLINE = LineStart() + LineEnd()
COMMENTLINE = pythonStyleComment + EOL
INTEGER = Word(nums)
REAL = Combine((INTEGER + Optional('.' + Optional(INTEGER))) ^ ('.' + INTEGER))
UDEV_TAG = Word(string.ascii_uppercase, alphanums + '_')

TYPES = {'mouse':    ('usb', 'bluetooth', 'ps2', '*'),
         'evdev':    ('name', 'atkbd', 'input'),
         'touchpad': ('i8042', 'rmi', 'bluetooth', 'usb'),
         'keyboard': ('name', ),
         }

@functools.lru_cache()
def hwdb_grammar():
    ParserElement.setDefaultWhitespaceChars('')

    prefix = Or(category + ':' + Or(conn) + ':'
                for category, conn in TYPES.items())
    matchline = Combine(prefix + Word(printables + ' ' + '®')) + EOL
    propertyline = (White(' ', exact=1).suppress() +
                    Combine(UDEV_TAG - '=' - Word(alphanums + '_=:@*.! ') - Optional(pythonStyleComment)) +
                    EOL)
    propertycomment = White(' ', exact=1) + pythonStyleComment + EOL

    group = (OneOrMore(matchline('MATCHES*') ^ COMMENTLINE.suppress()) -
             OneOrMore(propertyline('PROPERTIES*') ^ propertycomment.suppress()) -
             (EMPTYLINE ^ stringEnd()).suppress() )
    commentgroup = OneOrMore(COMMENTLINE).suppress() - EMPTYLINE.suppress()

    grammar = OneOrMore(group('GROUPS*') ^ commentgroup) + stringEnd()

    return grammar

@functools.lru_cache()
def property_grammar():
    ParserElement.setDefaultWhitespaceChars(' ')

    setting = Optional('*')('DEFAULT') + INTEGER('DPI') + Suppress('@') + INTEGER('HZ')
    props = (('MOUSE_DPI', Group(OneOrMore(setting('SETTINGS*')))),
             ('MOUSE_WHEEL_CLICK_ANGLE', INTEGER),
             ('MOUSE_WHEEL_CLICK_ANGLE_HORIZONTAL', INTEGER),
             ('ID_INPUT_TRACKBALL', Literal('1')),
             ('POINTINGSTICK_SENSITIVITY', INTEGER),
             ('POINTINGSTICK_CONST_ACCEL', REAL),
             ('ID_INPUT_TOUCHPAD_INTEGRATION', Or(('internal', 'external'))),
    )
    fixed_props = [Literal(name)('NAME') - Suppress('=') - val('VALUE')
                   for name, val in props]
    kbd_props = [Regex(r'KEYBOARD_KEY_[0-9a-f]+')('NAME')
                 - Suppress('=') -
                 ('!' ^ (Optional('!') - Word(alphanums + '_')))('VALUE')
                 ]
    abs_props = [Regex(r'EVDEV_ABS_[0-9a-f]{2}')('NAME')
                 - Suppress('=') -
                 Word(nums + ':')('VALUE')
                 ]

    grammar = Or(fixed_props + kbd_props + abs_props)

    return grammar

ERROR = False
def error(fmt, *args, **kwargs):
    global ERROR
    ERROR = True
    print(fmt.format(*args, **kwargs))

def convert_properties(group):
    matches = [m[0] for m in group.MATCHES]
    props = [p[0] for p in group.PROPERTIES]
    return matches, props

def parse(fname):
    grammar = hwdb_grammar()
    try:
        parsed = grammar.parseFile(fname)
    except ParseBaseException as e:
        error('Cannot parse {}: {}', fname, e)
        return []
    return [convert_properties(g) for g in parsed.GROUPS]

def check_match_uniqueness(groups):
    matches = sum((group[0] for group in groups), [])
    matches.sort()
    prev = None
    for match in matches:
        if match == prev:
            error('Match {!r} is duplicated', match)
        prev = match

def check_one_default(prop, settings):
    defaults = [s for s in settings if s.DEFAULT]
    if len(defaults) > 1:
        error('More than one star entry: {!r}', prop)

def check_one_keycode(prop, value):
    if value != '!' and ecodes is not None:
        key = 'KEY_' + value.upper()
        if key not in ecodes:
            error('Keycode {} unknown', key)

def check_properties(groups):
    grammar = property_grammar()
    for matches, props in groups:
        prop_names = set()
        for prop in props:
            # print('--', prop)
            prop = prop.partition('#')[0].rstrip()
            try:
                parsed = grammar.parseString(prop)
            except ParseBaseException as e:
                error('Failed to parse: {!r}', prop)
                continue
            # print('{!r}'.format(parsed))
            if parsed.NAME in prop_names:
                error('Property {} is duplicated', parsed.NAME)
            prop_names.add(parsed.NAME)
            if parsed.NAME == 'MOUSE_DPI':
                check_one_default(prop, parsed.VALUE.SETTINGS)
            elif parsed.NAME.startswith('KEYBOARD_KEY_'):
                check_one_keycode(prop, parsed.VALUE)

def print_summary(fname, groups):
    print('{}: {} match groups, {} matches, {} properties'
          .format(fname,
                  len(groups),
                  sum(len(matches) for matches, props in groups),
                  sum(len(props) for matches, props in groups),
          ))

if __name__ == '__main__':
    args = sys.argv[1:] or glob.glob(os.path.dirname(sys.argv[0]) + '/[67]0-*.hwdb')

    for fname in args:
        groups = parse(fname)
        print_summary(fname, groups)
        check_match_uniqueness(groups)
        check_properties(groups)

    sys.exit(ERROR)
