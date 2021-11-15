#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import sys


def filter_fsname(name):
    # File system magics are sometimes not unique, because file systems got new
    # revisions or got renamed. Let's prefer newer over older here, and thus
    # ignore the old names. Specifically:
    #
    # → cgroupfs took over the magic of cpuset
    # → devtmpfs is not a file system of its own, but just a "named superblock" of tmpfs
    # → ext4 is the newest revision of ext2 + ext3
    # → fuseblk is closely related to fuse, so close that they share a single magic, but the latter is more common
    # → gfs2 is the newest revision of gfs
    # → vfat is the newest revision of msdos
    # → ncpfs (not ncp) was the last name of the netware `file_system_type` name before it was removed in 2018
    # → nfs4 is the newest revision of nfs
    # → orangefs is the new name of pvfs2
    # → smb3 is an alias for cifs

    return name in (
        "cpuset",
        "devtmpfs",
        "ext2",
        "ext3",
        "fuseblk",
        "gfs",
        "msdos",
        "ncp",
        "nfs",
        "pvfs2",
        "smb3",
    )


gperf_file = sys.argv[1]
keywords_section = False

for line in open(gperf_file):
    if line[0] == "#":
        continue

    if keywords_section:
        name, ids = line.split(",", 1)

        name = name.strip()
        if filter_fsname(name):
            continue

        ids = ids.strip()
        assert ids[0] == "{"
        assert ids[-1] == "}"
        ids = ids[1:-1]

        for id in ids.split(","):
            print(f"case (statfs_f_type_t) {id.strip()}:")

        print(f'        return "{name}";')

    if line.startswith("%%"):
        keywords_section = True
