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
#include <sys/mount.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sched.h>
#include <sys/syscall.h>
#include <limits.h>
#include <linux/fs.h>

#include "strv.h"
#include "util.h"
#include "path-util.h"
#include "namespace.h"
#include "missing.h"
#include "execute.h"

typedef enum MountMode {
        /* This is ordered by priority! */
        INACCESSIBLE,
        READONLY,
        PRIVATE_TMP,
        PRIVATE_VAR_TMP,
        READWRITE
} MountMode;

typedef struct BindMount {
        const char *path;
        MountMode mode;
        bool done;
} BindMount;

static int append_mounts(BindMount **p, char **strv, MountMode mode) {
        char **i;

        STRV_FOREACH(i, strv) {

                if (!path_is_absolute(*i))
                        return -EINVAL;

                (*p)->path = *i;
                (*p)->mode = mode;
                (*p)++;
        }

        return 0;
}

static int mount_path_compare(const void *a, const void *b) {
        const BindMount *p = a, *q = b;

        if (path_equal(p->path, q->path)) {

                /* If the paths are equal, check the mode */
                if (p->mode < q->mode)
                        return -1;

                if (p->mode > q->mode)
                        return 1;

                return 0;
        }

        /* If the paths are not equal, then order prefixes first */
        if (path_startswith(p->path, q->path))
                return 1;

        if (path_startswith(q->path, p->path))
                return -1;

        return 0;
}

static void drop_duplicates(BindMount *m, unsigned *n) {
        BindMount *f, *t, *previous;

        assert(m);
        assert(n);

        for (f = m, t = m, previous = NULL; f < m+*n; f++) {

                /* The first one wins */
                if (previous && path_equal(f->path, previous->path))
                        continue;

                t->path = f->path;
                t->mode = f->mode;

                previous = t;

                t++;
        }

        *n = t - m;
}

static int apply_mount(
                BindMount *m,
                const char *tmp_dir,
                const char *var_tmp_dir) {

        const char *what;
        int r;

        assert(m);

        switch (m->mode) {

        case INACCESSIBLE:
                what = "/run/systemd/inaccessible";
                break;

        case READONLY:
        case READWRITE:
                what = m->path;
                break;

        case PRIVATE_TMP:
                what = tmp_dir;
                break;

        case PRIVATE_VAR_TMP:
                what = var_tmp_dir;
                break;

        default:
                assert_not_reached("Unknown mode");
        }

        assert(what);

        r = mount(what, m->path, NULL, MS_BIND|MS_REC, NULL);
        if (r >= 0)
                log_debug("Successfully mounted %s to %s", what, m->path);

        return r;
}

static int make_read_only(BindMount *m) {
        int r;

        assert(m);

        if (m->mode != INACCESSIBLE && m->mode != READONLY)
                return 0;

        r = mount(NULL, m->path, NULL, MS_BIND|MS_REMOUNT|MS_RDONLY|MS_REC, NULL);
        if (r < 0)
                return -errno;

        return 0;
}

int setup_tmpdirs(char **tmp_dir,
                  char **var_tmp_dir) {
        int r = 0;
        char tmp_dir_template[] = "/tmp/systemd-private-XXXXXX",
             var_tmp_dir_template[] = "/var/tmp/systemd-private-XXXXXX";

        assert(tmp_dir);
        assert(var_tmp_dir);

        r = create_tmp_dir(tmp_dir_template, tmp_dir);
        if (r < 0)
                return r;

        r = create_tmp_dir(var_tmp_dir_template, var_tmp_dir);
        if (r == 0)
                return 0;

        /* failure */
        rmdir(*tmp_dir);
        rmdir(tmp_dir_template);
        free(*tmp_dir);
        *tmp_dir = NULL;

        return r;
}

int setup_namespace(char** read_write_dirs,
                    char** read_only_dirs,
                    char** inaccessible_dirs,
                    char* tmp_dir,
                    char* var_tmp_dir,
                    bool private_tmp,
                    unsigned mount_flags) {

        unsigned n = strv_length(read_write_dirs) +
                     strv_length(read_only_dirs) +
                     strv_length(inaccessible_dirs) +
                     (private_tmp ? 2 : 0);
        BindMount *m, *mounts;
        int r = 0;

        if (!mount_flags)
                mount_flags = MS_SHARED;

        if (unshare(CLONE_NEWNS) < 0)
                return -errno;

        m = mounts = (BindMount *) alloca(n * sizeof(BindMount));
        if ((r = append_mounts(&m, read_write_dirs, READWRITE)) < 0 ||
                (r = append_mounts(&m, read_only_dirs, READONLY)) < 0 ||
                (r = append_mounts(&m, inaccessible_dirs, INACCESSIBLE)) < 0)
                return r;

        if (private_tmp) {
                m->path = "/tmp";
                m->mode = PRIVATE_TMP;
                m++;

                m->path = "/var/tmp";
                m->mode = PRIVATE_VAR_TMP;
                m++;
        }

        assert(mounts + n == m);

        qsort(mounts, n, sizeof(BindMount), mount_path_compare);
        drop_duplicates(mounts, &n);

        /* Remount / as SLAVE so that nothing now mounted in the namespace
           shows up in the parent */
        if (mount(NULL, "/", NULL, MS_SLAVE|MS_REC, NULL) < 0)
                return -errno;

        for (m = mounts; m < mounts + n; ++m) {
                r = apply_mount(m, tmp_dir, var_tmp_dir);
                if (r < 0)
                        goto undo_mounts;
        }

        for (m = mounts; m < mounts + n; ++m) {
                r = make_read_only(m);
                if (r < 0)
                        goto undo_mounts;
        }

        /* Remount / as the desired mode */
        if (mount(NULL, "/", NULL, mount_flags | MS_REC, NULL) < 0) {
                r = -errno;
                goto undo_mounts;
        }

        return 0;

undo_mounts:
        for (m = mounts; m < mounts + n; ++m) {
                if (m->done)
                        umount2(m->path, MNT_DETACH);
        }

        return r;
}
