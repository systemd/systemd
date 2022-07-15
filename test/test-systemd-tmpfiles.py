#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# systemd is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.

import os
import sys
import socket
import subprocess
import tempfile
import pwd
import grp

try:
    from systemd import id128
except ImportError:
    id128 = None

EX_DATAERR = 65 # from sysexits.h
EXIT_TEST_SKIP = 77

try:
    subprocess.run
except AttributeError:
    sys.exit(EXIT_TEST_SKIP)

exe_with_args = sys.argv[1:]

def test_line(line, *, user, returncode=EX_DATAERR, extra={}):
    args = ['--user'] if user else []
    print('Running {} on {!r}'.format(' '.join(exe_with_args + args), line))
    c = subprocess.run(exe_with_args + ['--create', '-'] + args,
                       input=line, stdout=subprocess.PIPE, universal_newlines=True,
                       **extra)
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
    test_line('f== /too/many/equals', user=user)
    test_line('w /unresolved/argument - - - - "%Y"', user=user)
    test_line('w /unresolved/argument/sandwich - - - - "%v%Y%v"', user=user)
    test_line('w /unresolved/filename/%Y - - - - "whatever"', user=user)
    test_line('w /unresolved/filename/sandwich/%v%Y%v - - - - "whatever"', user=user)
    test_line('w - - - - - "no file specified"', user=user)
    test_line('C - - - - - "no file specified"', user=user)
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

def test_uninitialized_t():
    if os.getuid() == 0:
        return

    test_line('w /foo - - - - "specifier for --user %t"',
              user=True, returncode=0, extra={'env':{}})

def test_content(line, expected, *, user, extra={}, subpath='/arg', path_cb=None):
    d = tempfile.TemporaryDirectory(prefix='test-systemd-tmpfiles.')
    if path_cb is not None:
        path_cb(d.name, subpath)
    arg = d.name + subpath
    spec = line.format(arg)
    test_line(spec, user=user, returncode=0, extra=extra)
    content = open(arg).read()
    print('expect: {!r}\nactual: {!r}'.format(expected, content))
    assert content == expected

def test_valid_specifiers(*, user):
    test_content('f {} - - - - two words', 'two words', user=user)
    if id128:
        try:
            test_content('f {} - - - - %m', '{}'.format(id128.get_machine().hex), user=user)
        except AssertionError as e:
            print(e)
            print('/etc/machine-id: {!r}'.format(open('/etc/machine-id').read()))
            print('/proc/cmdline: {!r}'.format(open('/proc/cmdline').read()))
            print('skipping')
        test_content('f {} - - - - %b', '{}'.format(id128.get_boot().hex), user=user)
    test_content('f {} - - - - %H', '{}'.format(socket.gethostname()), user=user)
    test_content('f {} - - - - %v', '{}'.format(os.uname().release), user=user)
    test_content('f {} - - - - %U', '{}'.format(os.getuid() if user else 0), user=user)
    test_content('f {} - - - - %G', '{}'.format(os.getgid() if user else 0), user=user)

    puser = pwd.getpwuid(os.getuid() if user else 0)
    test_content('f {} - - - - %u', '{}'.format(puser.pw_name), user=user)

    pgroup = grp.getgrgid(os.getgid() if user else 0)
    test_content('f {} - - - - %g', '{}'.format(pgroup.gr_name), user=user)

    # Note that %h is the only specifier in which we look the environment,
    # because we check $HOME. Should we even be doing that?
    home = os.path.expanduser("~")
    test_content('f {} - - - - %h', '{}'.format(home), user=user)

    xdg_runtime_dir = os.getenv('XDG_RUNTIME_DIR')
    if xdg_runtime_dir is not None or not user:
        test_content('f {} - - - - %t',
                     xdg_runtime_dir if user else '/run',
                     user=user)

    xdg_config_home = os.getenv('XDG_CONFIG_HOME')
    if xdg_config_home is not None or not user:
        test_content('f {} - - - - %S',
                     xdg_config_home if user else '/var/lib',
                     user=user)

    xdg_cache_home = os.getenv('XDG_CACHE_HOME')
    if xdg_cache_home is not None or not user:
        test_content('f {} - - - - %C',
                     xdg_cache_home if user else '/var/cache',
                     user=user)

    if xdg_config_home is not None or not user:
        test_content('f {} - - - - %L',
                     xdg_config_home + '/log' if user else '/var/log',
                     user=user)

    test_content('f {} - - - - %%', '%', user=user)

def mkfifo(parent, subpath):
    os.makedirs(parent, mode=0o755, exist_ok=True)
    first_component = subpath.split('/')[1]
    path = parent + '/' + first_component
    print('path: {}'.format(path))
    os.mkfifo(path)

def mkdir(parent, subpath):
    first_component = subpath.split('/')[1]
    path = parent + '/' + first_component
    os.makedirs(path, mode=0o755, exist_ok=True)
    os.symlink(path, path + '/self', target_is_directory=True)

def symlink(parent, subpath):
    link_path = parent + '/link-target'
    os.makedirs(parent, mode=0o755, exist_ok=True)
    with open(link_path, 'wb') as f:
        f.write(b'target')
    first_component = subpath.split('/')[1]
    path = parent + '/' + first_component
    os.symlink(link_path, path, target_is_directory=True)

def file(parent, subpath):
    content = 'file-' + subpath.split('/')[1]
    path = parent + subpath
    os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
    with open(path, 'wb') as f:
        f.write(content.encode())

def valid_symlink(parent, subpath):
    target = 'link-target'
    link_path = parent + target
    os.makedirs(link_path, mode=0o755, exist_ok=True)
    first_component = subpath.split('/')[1]
    path = parent + '/' + first_component
    os.symlink(target, path, target_is_directory=True)

def test_hard_cleanup(*, user):
    type_cbs = [None, file, mkdir, symlink]
    if 'mkfifo' in dir(os):
        type_cbs.append(mkfifo)

    for type_cb in type_cbs:
        for subpath in ['/shallow', '/deep/1/2']:
            label = '{}-{}'.format('None' if type_cb is None else type_cb.__name__, subpath.split('/')[1])
            test_content('f= {} - - - - ' + label, label, user=user, subpath=subpath, path_cb=type_cb)

    # Test the case that a valid symlink is in the path.
    label = 'valid_symlink-deep'
    test_content('f= {} - - - - ' + label, label, user=user, subpath='/deep/1/2', path_cb=valid_symlink)

if __name__ == '__main__':
    test_invalids(user=False)
    test_invalids(user=True)
    test_uninitialized_t()

    test_valid_specifiers(user=False)
    test_valid_specifiers(user=True)

    test_hard_cleanup(user=False)
    test_hard_cleanup(user=True)
