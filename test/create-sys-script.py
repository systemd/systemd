#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

OUTFILE_HEADER = """#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# create-sys-script.py
#
# © 2017 Canonical Ltd.
# Author: Dan Streetman <dan.streetman@canonical.com>
"""

# Use this only to (re-)create the test/sys-script.py script,
# after adding or modifying anything in the test/sys/ directory


import os, sys
import stat
import tempfile
import filecmp
import subprocess

OUTFILE_MODE = 0o775

OUTFILE_FUNCS = r"""
import os, sys
import shutil

def d(path, mode):
    os.mkdir(path, mode)

def l(path, src):
    os.symlink(src, path)

def f(path, mode, contents):
    with open(path, "wb") as f:
        f.write(contents)
    os.chmod(path, mode)
"""

OUTFILE_MAIN = """
if len(sys.argv) < 2:
    exit("Usage: {} <target dir>".format(sys.argv[0]))

if not os.path.isdir(sys.argv[1]):
    exit("Target dir {} not found".format(sys.argv[1]))

os.chdir(sys.argv[1])

if os.path.exists('sys'):
    shutil.rmtree('sys')
"""


def handle_dir(outfile, path):
    m = os.lstat(path).st_mode & 0o777
    outfile.write(f"d('{path}', {m:#o})\n")


def handle_link(outfile, path):
    src = os.readlink(path)
    outfile.write(f"l('{path}', '{src}')\n")


def escape_single_quotes(b):
    # remove the b'' wrapping each line repr
    r = repr(b)[2:-1]
    # python escapes all ' only if there are ' and " in the string
    if '"' not in r:
        r = r.replace("'", r"\'")
    # return line with all ' escaped
    return r


def handle_file(outfile, path):
    m = os.lstat(path).st_mode & 0o777
    with open(path, "rb") as f:
        b = f.read()
    if b.count(b"\n") > 1:
        r = "\n".join( escape_single_quotes(l) for l in b.split(b"\n") )
        r = f"b'''{r}'''"
    else:
        r = repr(b)
    outfile.write(f"f('{path}', {m:#o}, {r})\n")


def process_sysdir(outfile):
    for (dirpath, dirnames, filenames) in os.walk('sys'):
        handle_dir(outfile, dirpath)
        for d in dirnames:
            path = os.path.join(dirpath, d)
            if stat.S_ISLNK(os.lstat(path).st_mode):
                handle_link(outfile, path)
        for f in filenames:
            path = os.path.join(dirpath, f)
            mode = os.lstat(path).st_mode
            if stat.S_ISLNK(mode):
                handle_link(outfile, path)
            elif stat.S_ISREG(mode):
                handle_file(outfile, path)


def verify_dir(tmpd, path_a):
    path_b = os.path.join(tmpd, path_a)
    mode_a = os.lstat(path_a).st_mode
    mode_b = os.lstat(path_b).st_mode
    if not stat.S_ISDIR(mode_b):
        raise Exception("Not directory")
    if (mode_a & 0o777) != (mode_b & 0o777):
        raise Exception("Permissions mismatch")


def verify_link(tmpd, path_a):
    path_b = os.path.join(tmpd, path_a)
    if not stat.S_ISLNK(os.lstat(path_b).st_mode):
        raise Exception("Not symlink")
    if os.readlink(path_a) != os.readlink(path_b):
        raise Exception("Symlink dest mismatch")


def verify_file(tmpd, path_a):
    path_b = os.path.join(tmpd, path_a)
    mode_a = os.lstat(path_a).st_mode
    mode_b = os.lstat(path_b).st_mode
    if not stat.S_ISREG(mode_b):
        raise Exception("Not file")
    if (mode_a & 0o777) != (mode_b & 0o777):
        raise Exception("Permissions mismatch")
    if not filecmp.cmp(path_a, path_b, shallow=False):
        raise Exception("File contents mismatch")


def verify_script(tmpd):
    any = False
    for (dirpath, dirnames, filenames) in os.walk("sys"):
        any = True
        try:
            path = dirpath
            verify_dir(tmpd, path)
            for d in dirnames:
                path = os.path.join(dirpath, d)
                if stat.S_ISLNK(os.lstat(path).st_mode):
                    verify_link(tmpd, path)
                for f in filenames:
                    path = os.path.join(dirpath, f)
                    mode = os.lstat(path).st_mode
                    if stat.S_ISLNK(mode):
                        verify_link(tmpd, path)
                    elif stat.S_ISREG(mode):
                        verify_file(tmpd, path)
        except Exception:
            print(f'FAIL on "{path}"', file=sys.stderr)
            raise
    if not any:
        exit('Nothing found!')

if __name__ == "__main__":
    if len(sys.argv) < 2:
        exit('Usage: create-sys-script.py /path/to/test/')

    outfile = os.path.abspath(os.path.dirname(sys.argv[0]) + '/sys-script.py')
    print(f'Creating {outfile} using contents of {sys.argv[1]}/sys')

    os.chdir(sys.argv[1])

    with open(outfile, "w") as f:
        os.chmod(outfile, OUTFILE_MODE)
        f.write(OUTFILE_HEADER.replace(os.path.basename(sys.argv[0]),
                                       os.path.basename(outfile)))
        f.write(OUTFILE_FUNCS)
        f.write(OUTFILE_MAIN)
        process_sysdir(f)

    with tempfile.TemporaryDirectory() as tmpd:
        print(f'Recreating sys/ using {outfile} at {tmpd}')
        subprocess.check_call([outfile, tmpd])
        verify_script(tmpd)

    print(f'Verification successful, {outfile} is correct')
