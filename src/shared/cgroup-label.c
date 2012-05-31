/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ftw.h>

#include "cgroup-util.h"
#include "log.h"
#include "set.h"
#include "macro.h"
#include "util.h"
#include "mkdir.h"

int cg_create(const char *controller, const char *path) {
        char *fs;
        int r;

        assert(controller);
        assert(path);

        r = cg_get_path_and_check(controller, path, NULL, &fs);
        if (r < 0)
                return r;

        r = mkdir_parents_label(fs, 0755);

        if (r >= 0) {
                if (mkdir(fs, 0755) >= 0)
                        r = 1;
                else if (errno == EEXIST)
                        r = 0;
                else
                        r = -errno;
        }

        free(fs);

        return r;
}

int cg_create_and_attach(const char *controller, const char *path, pid_t pid) {
        int r, q;

        assert(controller);
        assert(path);
        assert(pid >= 0);

        if ((r = cg_create(controller, path)) < 0)
                return r;

        if ((q = cg_attach(controller, path, pid)) < 0)
                return q;

        /* This does not remove the cgroup on failure */

        return r;
}
