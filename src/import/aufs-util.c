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

#include <ftw.h>

#include "aufs-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "util.h"

static int nftw_cb(
                const char *fpath,
                const struct stat *sb,
                int flag,
                struct FTW *ftwbuf) {

        const char *fn, *original;
        char *p;
        int r;

        fn = fpath + ftwbuf->base;

        /* We remove all whiteout files, and all whiteouts */

        original = startswith(fn, ".wh.");
        if (!original)
                return FTW_CONTINUE;

        log_debug("Removing whiteout indicator %s.", fpath);
        r = rm_rf(fpath, REMOVE_ROOT|REMOVE_PHYSICAL);
        if (r < 0)
                return FTW_STOP;

        if (!startswith(fn, ".wh..wh.")) {

                p = alloca(ftwbuf->base + strlen(original));
                strcpy(mempcpy(p, fpath, ftwbuf->base), original);

                log_debug("Removing deleted file %s.", p);
                r = rm_rf(p, REMOVE_ROOT|REMOVE_PHYSICAL);
                if (r < 0)
                        return FTW_STOP;
        }

        return FTW_CONTINUE;
}

int aufs_resolve(const char *path) {
        int r;

        errno = 0;
        r = nftw(path, nftw_cb, 64, FTW_MOUNT|FTW_PHYS|FTW_ACTIONRETVAL);
        if (r == FTW_STOP)
                return errno ? -errno : -EIO;

        return 0;
}
