#!/usr/bin/env python3
#  SPDX-License-Identifier: LGPL-2.1+
#
#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.

import sys
import subprocess

EX_DATAERR = 65 # from sysexits.h

exe = sys.argv[1]

def test_invalid_line(line):
    print('Running {} on {!r}'.format(exe, line))
    c = subprocess.run([exe, '--create', '-'],
                       input=line, stdout=subprocess.PIPE, universal_newlines=True)
    assert c.returncode == EX_DATAERR, c

if __name__ == '__main__':
    test_invalid_line('asdfa')
    test_invalid_line('f "open quote')
    test_invalid_line('f closed quote""')
    test_invalid_line('Y /unknown/letter')
    test_invalid_line('w non/absolute/path')
    test_invalid_line('s') # s is for short
    test_invalid_line('f!! /too/many/bangs')
    test_invalid_line('f++ /too/many/plusses')
    test_invalid_line('f+!+ /too/many/plusses')
    test_invalid_line('f!+! /too/many/bangs')
    #test_invalid_line('w /unresolved/argument - - - - "%Y"')
    #test_invalid_line('w /unresolved/argument/sandwich - - - - "%v%Y%v"')
    #test_invalid_line('w /unresolved/filename/%Y - - - - "whatever"')
    #test_invalid_line('w /unresolved/filename/sandwich/%v%Y%v - - - - "whatever"')
    test_invalid_line('w - - - - - "no file specfied"')
    test_invalid_line('C - - - - - "no file specfied"')
    test_invalid_line('C non/absolute/path - - - - -')
    test_invalid_line('b - - - - - -')
    test_invalid_line('b 1234 - - - - -')
    test_invalid_line('c - - - - - -')
    test_invalid_line('c 1234 - - - - -')
    test_invalid_line('t - - -')
    test_invalid_line('T - - -')
    test_invalid_line('a - - -')
    test_invalid_line('A - - -')
    test_invalid_line('h - - -')
    test_invalid_line('H - - -')
