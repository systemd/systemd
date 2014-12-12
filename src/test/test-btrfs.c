/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdlib.h>

#include "log.h"
#include "btrfs-util.h"
#include "fileio.h"

int main(int argc, char *argv[]) {
        int r;

        r = btrfs_subvol_make("/xxxtest");
        if (r < 0)
                log_error_errno(r, "Failed to make subvolume: %m");

        r = write_string_file("/xxxtest/afile", "ljsadhfljasdkfhlkjdsfha");
        if (r < 0)
                log_error_errno(r, "Failed to write file: %m");

        r = btrfs_subvol_snapshot("/xxxtest", "/xxxtest2", false, false);
        if (r < 0)
                log_error_errno(r, "Failed to make snapshot: %m");

        r = btrfs_subvol_snapshot("/xxxtest", "/xxxtest3", true, false);
        if (r < 0)
                log_error_errno(r, "Failed to make snapshot: %m");

        r = btrfs_subvol_remove("/xxxtest");
        if (r < 0)
                log_error_errno(r, "Failed to remove subvolume: %m");

        r = btrfs_subvol_remove("/xxxtest2");
        if (r < 0)
                log_error_errno(r, "Failed to remove subvolume: %m");

        r = btrfs_subvol_remove("/xxxtest3");
        if (r < 0)
                log_error_errno(r, "Failed to remove subvolume: %m");

        r = btrfs_subvol_snapshot("/etc", "/etc2", true, true);
        if (r < 0)
                log_error_errno(r, "Failed to make snapshot: %m");

        r = btrfs_subvol_remove("/etc2");
        if (r < 0)
                log_error_errno(r, "Failed to remove subvolume: %m");

        return 0;
}
