/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2015 Endocode AG

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

#include "journal-dir.h"
#include "macro.h"
#include "util.h"

static int journal_directory_new_steal(char *path, int fd, JournalDirectory **dir) {
        JournalDirectory *d;

        assert(path);
        assert(fd >= 0);
        assert(dir);

        d = new0(JournalDirectory, 1);
        if (!d)
                return -ENOMEM;
        d->path = path;
        d->fd = fd;
        d->n_ref = 1;
        *dir = d;
        return 0;
}

int journal_directory_open(const char *path, JournalDirectory **dir)
{
        _cleanup_free_ char *p = NULL;
        _cleanup_close_ int fd = -1;
        int r;

        assert(path);
        assert(dir);

        fd = open(path, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
        if (fd < 0)
                return -errno;

        p = strdup(path);
        if (!p)
                return -ENOMEM;

        r = journal_directory_new_steal(p, fd, dir);
        if (r < 0)
                return r;
        p = NULL;
        fd = -1;
        return 0;
}

int journal_directory_new(const char *path, int fd, JournalDirectory **dir)
{
        _cleanup_free_ char *p = NULL;
        _cleanup_close_ int dfd = -1;
        int r;

        assert(path);
        assert(fd >= 0);
        assert(dir);

        dfd = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (dfd < 0)
                return -errno;

        p = strdup(path);
        if (!p)
                return -ENOMEM;

        r = journal_directory_new_steal(p, dfd, dir);
        if (r < 0)
                return r;
        p = NULL;
        dfd = -1;
        return 0;
}

JournalDirectory *journal_directory_ref(JournalDirectory *dir)
{
        assert(dir);
        assert(dir->n_ref > 0);

        dir->n_ref ++;
        return dir;
}

JournalDirectory *journal_directory_unref(JournalDirectory *dir)
{
        if (dir) {
                PROTECT_ERRNO;

                assert(dir->n_ref > 0);

                dir->n_ref --;
                if (!dir->n_ref) {
                        safe_close(dir->fd);
                        free(dir->path);
                        free(dir);
                }
        }

        return NULL;
}

int journal_directory_opendir(JournalDirectory *dir, DIR **de)
{
        int fd;
        DIR* d;

        assert(dir);
        assert(de);

        fd = fcntl(dir->fd, F_DUPFD_CLOEXEC, 3);
        if (fd < 0)
                return -errno;

        d = fdopendir(fd);
        if (!d) {
                safe_close(fd);
                return -errno;
        }

        *de = d;
        return 0;
}
