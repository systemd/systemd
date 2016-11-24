#!/usr/bin/python3
# -*- Mode: python; coding: utf-8; indent-tabs-mode: nil -*- */
#
# This file is part of systemd. It is distrubuted under the MIT license, see
# below.
#
# Copyright 2016 Zbigniew Jędrzejewski-Szmek
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

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

try:
    from functools import lru_cache
except ImportError:
    # don't do caching on old python
    lru_cache = lambda: (lambda f: f)

EOL = LineEnd().suppress()
EMPTYLINE = LineEnd()
COMMENTLINE = pythonStyleComment + EOL
INTEGER = Word(nums)
REAL = Combine((INTEGER + Optional('.' + Optional(INTEGER))) ^ ('.' + INTEGER))
UDEV_TAG = Word(string.ascii_uppercase, alphanums + '_')

TYPES = {'mouse':    ('usb', 'bluetooth', 'ps2', '*'),
         'evdev':    ('name', 'atkbd', 'input'),
         'touchpad': ('i8042', 'rmi', 'bluetooth', 'usb'),
         'keyboard': ('name', ),
         }

@lru_cache()
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

@lru_cache()
def property_grammar():
    ParserElement.setDefaultWhitespaceChars(' ')

    setting = Optional('*')('DEFAULT') + INTEGER('DPI') + Suppress('@') + INTEGER('HZ')
    props = (('MOUSE_DPI', Group(OneOrMore(setting('SETTINGS*')))),
             ('MOUSE_WHEEL_CLICK_ANGLE', INTEGER),
             ('MOUSE_WHEEL_CLICK_ANGLE_HORIZONTAL', INTEGER),
             ('MOUSE_WHEEL_CLICK_COUNT', INTEGER),
             ('MOUSE_WHEEL_CLICK_COUNT_HORIZONTAL', INTEGER),
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
        with open(fname, 'r', encoding='UTF-8') as f:
            parsed = grammar.parseFile(f)
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
