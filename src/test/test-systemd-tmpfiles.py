#!/usr/bin/env python3
#  SPDX-License-Identifier: LGPL-2.1+
#
#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.

import os
import sys
import subprocess

EX_DATAERR = 65 # from sysexits.h

exe = sys.argv[1]

def test_line(line, *, user, returncode=EX_DATAERR):
    args = ['--user'] if user else []
    print('Running {} {} on {!r}'.format(exe, ' '.join(args), line))
    c = subprocess.run([exe, '--create', *args, '-'],
                       input=line, stdout=subprocess.PIPE, universal_newlines=True)
    assert c.returncode == returncode, c

def test_invalids(*, user):
    test_line('asdfa', user=user)
    test_line('f "open quote', user=user)
    test_line('f closed quote""', user=user)
    test_line('Y /unknown/letter', user=user)
    test_line('w non/absolute/path', user=user)
    test_line('s', user=user) # s is for short
    test_line('f!! /too/many/bangs', user=user)
    test_line('f++ /too/many/plusses', user=user)
    test_line('f+!+ /too/many/plusses', user=user)
    test_line('f!+! /too/many/bangs', user=user)
    test_line('w /unresolved/argument - - - - "%Y"', user=user)
    test_line('w /unresolved/argument/sandwich - - - - "%v%Y%v"', user=user)
    test_line('w /unresolved/filename/%Y - - - - "whatever"', user=user)
    test_line('w /unresolved/filename/sandwich/%v%Y%v - - - - "whatever"', user=user)
    test_line('w - - - - - "no file specfied"', user=user)
    test_line('C - - - - - "no file specfied"', user=user)
    test_line('C non/absolute/path - - - - -', user=user)
    test_line('b - - - - - -', user=user)
    test_line('b 1234 - - - - -', user=user)
    test_line('c - - - - - -', user=user)
    test_line('c 1234 - - - - -', user=user)
    test_line('t - - -', user=user)
    test_line('T - - -', user=user)
    test_line('a - - -', user=user)
    test_line('A - - -', user=user)
    test_line('h - - -', user=user)
    test_line('H - - -', user=user)

def test_unitialized_t():
    if os.getuid() == 0:
        return

    try:
        del os.environ['XDG_RUNTIME_DIR']
    except KeyError:
        pass
    test_line('w /foo - - - - "specifier for --user %t"', user=True, returncode=0)

if __name__ == '__main__':
    test_invalids(user=False)
    test_invalids(user=True)
    test_unitialized_t()
