/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#include "set.h"
#include "util.h"
#include "macro.h"
#include "fdset.h"

#define MAKE_SET(s) ((Set*) s)
#define MAKE_FDSET(s) ((FDSet*) s)

/* Make sure we can distuingish fd 0 and NULL */
#define FD_TO_PTR(fd) INT_TO_PTR((fd)+1)
#define PTR_TO_FD(p) (PTR_TO_INT(p)-1)

FDSet *fdset_new(void) {
        return MAKE_FDSET(set_new(trivial_hash_func, trivial_compare_func));
}

void fdset_free(FDSet *s) {
        void *p;

        while ((p = set_steal_first(MAKE_SET(s)))) {
                /* Valgrind's fd might have ended up in this set here,
                 * due to fdset_new_fill(). We'll ignore all failures
                 * here, so that the EBADFD that valgrind will return
                 * us on close() doesn't influence us */

                log_warning("Closing left-over fd %i", PTR_TO_FD(p));
                close_nointr(PTR_TO_FD(p));
        }

        set_free(MAKE_SET(s));
}

int fdset_put(FDSet *s, int fd) {
        assert(s);
        assert(fd >= 0);

        return set_put(MAKE_SET(s), FD_TO_PTR(fd));
}

int fdset_put_dup(FDSet *s, int fd) {
        int copy, r;

        assert(s);
        assert(fd >= 0);

        if ((copy = fcntl(fd, F_DUPFD_CLOEXEC, 3)) < 0)
                return -errno;

        if ((r = fdset_put(s, copy)) < 0) {
                close_nointr_nofail(copy);
                return r;
        }

        return copy;
}

bool fdset_contains(FDSet *s, int fd) {
        assert(s);
        assert(fd >= 0);

        return !!set_get(MAKE_SET(s), FD_TO_PTR(fd));
}

int fdset_remove(FDSet *s, int fd) {
        assert(s);
        assert(fd >= 0);

        return set_remove(MAKE_SET(s), FD_TO_PTR(fd)) ? fd : -ENOENT;
}

int fdset_new_fill(FDSet **_s) {
        DIR *d;
        struct dirent *de;
        int r = 0;
        FDSet *s;

        assert(_s);

        /* Creates an fdsets and fills in all currently open file
         * descriptors. */

        if (!(d = opendir("/proc/self/fd")))
                return -errno;

        if (!(s = fdset_new())) {
                r = -ENOMEM;
                goto finish;
        }

        while ((de = readdir(d))) {
                int fd = -1;

                if (ignore_file(de->d_name))
                        continue;

                if ((r = safe_atoi(de->d_name, &fd)) < 0)
                        goto finish;

                if (fd < 3)
                        continue;

                if (fd == dirfd(d))
                        continue;

                if ((r = fdset_put(s, fd)) < 0)
                        goto finish;
        }

        r = 0;
        *_s = s;
        s = NULL;

finish:
        closedir(d);

        /* We won't close the fds here! */
        if (s)
                set_free(MAKE_SET(s));

        return r;
}

int fdset_cloexec(FDSet *fds, bool b) {
        Iterator i;
        void *p;
        int r;

        assert(fds);

        SET_FOREACH(p, MAKE_SET(fds), i)
                if ((r = fd_cloexec(PTR_TO_FD(p), b)) < 0)
                        return r;

        return 0;
}
