#!/usr/bin/env python3
# SPDX-License-Identifier: MIT-0

"""

Proof-of-concept systemd environment generator that makes sure that bin dirs
are always after matching sbin dirs in the path.
(Changes /sbin:/bin:/foo/bar to /bin:/sbin:/foo/bar.)

This generator shows how to override the configuration possibly created by
earlier generators. It would be easier to write in bash, but let's have it
in Python just to prove that we can, and to serve as a template for more
interesting generators.

"""

import os
import pathlib

def rearrange_bin_sbin(path):
    """Make sure any pair of …/bin, …/sbin directories is in this order

    >>> rearrange_bin_sbin('/bin:/sbin:/usr/sbin:/usr/bin')
    '/bin:/sbin:/usr/bin:/usr/sbin'
    """
    items = [pathlib.Path(p) for p in path.split(':')]
    for i in range(len(items)):
        if 'sbin' in items[i].parts:
            ind = items[i].parts.index('sbin')
            bin = pathlib.Path(*items[i].parts[:ind], 'bin', *items[i].parts[ind+1:])
            if bin in items[i+1:]:
                j = i + 1 + items[i+1:].index(bin)
                items[i], items[j] = items[j], items[i]
    return ':'.join(p.as_posix() for p in items)

if __name__ == '__main__':
    path = os.environ['PATH'] # This should be always set.
                              # If it is not, we will just crash, which is OK too.
    new = rearrange_bin_sbin(path)
    if new != path:
        print('PATH={}'.format(new))
