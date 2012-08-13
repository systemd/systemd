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

typedef enum PathMode {
        /* This is ordered by priority! */
        INACCESSIBLE,
        READONLY,
        PRIVATE_TMP,
        PRIVATE_VAR_TMP,
        READWRITE
} PathMode;

typedef struct Path {
        const char *path;
        PathMode mode;
        bool done;
} Path;

static int append_paths(Path **p, char **strv, PathMode mode) {
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

static int path_compare(const void *a, const void *b) {
        const Path *p = a, *q = b;

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

static void drop_duplicates(Path *p, unsigned *n, bool *need_inaccessible) {
        Path *f, *t, *previous;

        assert(p);
        assert(n);
        assert(need_inaccessible);

        for (f = p, t = p, previous = NULL; f < p+*n; f++) {

                /* The first one wins */
                if (previous && path_equal(f->path, previous->path))
                        continue;

                t->path = f->path;
                t->mode = f->mode;

                if (t->mode == INACCESSIBLE)
                        *need_inaccessible = true;

                previous = t;

                t++;
        }

        *n = t - p;
}

static int apply_mount(
                Path *p,
                const char *tmp_dir,
                const char *var_tmp_dir,
                const char *inaccessible_dir) {

        const char *what;
        int r;

        assert(p);

        switch (p->mode) {

        case INACCESSIBLE:
                what = inaccessible_dir;
                break;

        case READONLY:
        case READWRITE:
                what = p->path;
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

        r = mount(what, p->path, NULL, MS_BIND|MS_REC, NULL);
        if (r >= 0)
                log_debug("Successfully mounted %s to %s", what, p->path);

        return r;
}

static int make_read_only(Path *p) {
        int r;

        assert(p);

        if (p->mode != INACCESSIBLE && p->mode != READONLY)
                return 0;

        r = mount(NULL, p->path, NULL, MS_BIND|MS_REMOUNT|MS_RDONLY|MS_REC, NULL);
        if (r < 0)
                return -errno;

        return 0;
}

int setup_namespace(
                char **writable,
                char **readable,
                char **inaccessible,
                bool private_tmp,
                unsigned long flags) {

        char
                tmp_dir[] = "/tmp/systemd-private-XXXXXX",
                var_tmp_dir[] = "/var/tmp/systemd-private-XXXXXX",
                inaccessible_dir[] = "/tmp/systemd-inaccessible-XXXXXX";

        Path *paths, *p;
        unsigned n;
        bool need_inaccessible = false;
        bool remove_tmp = false, remove_var_tmp = false, remove_inaccessible = false;
        int r;

        if (!flags)
                flags = MS_SHARED;

        n =
                strv_length(writable) +
                strv_length(readable) +
                strv_length(inaccessible) +
                (private_tmp ? 2 : 0);

        p = paths = alloca(sizeof(Path) * n);
        if ((r = append_paths(&p, writable, READWRITE)) < 0 ||
            (r = append_paths(&p, readable, READONLY)) < 0 ||
            (r = append_paths(&p, inaccessible, INACCESSIBLE)) < 0)
                goto fail;

        if (private_tmp) {
                p->path = "/tmp";
                p->mode = PRIVATE_TMP;
                p++;

                p->path = "/var/tmp";
                p->mode = PRIVATE_VAR_TMP;
                p++;
        }

        assert(paths + n == p);

        qsort(paths, n, sizeof(Path), path_compare);
        drop_duplicates(paths, &n, &need_inaccessible);

        if (need_inaccessible) {
                mode_t u;
                char *d;

                u = umask(0777);
                d = mkdtemp(inaccessible_dir);
                umask(u);

                if (!d) {
                        r = -errno;
                        goto fail;
                }

                remove_inaccessible = true;
        }

        if (private_tmp) {
                mode_t u;
                char *d;

                u = umask(0000);
                d = mkdtemp(tmp_dir);
                umask(u);

                if (!d) {
                        r = -errno;
                        goto fail;
                }

                remove_tmp = true;

                u = umask(0000);
                d = mkdtemp(var_tmp_dir);
                umask(u);

                if (!d) {
                        r = -errno;
                        goto fail;
                }

                remove_var_tmp = true;

                if (chmod(tmp_dir, 0777 + S_ISVTX) < 0) {
                        r = -errno;
                        goto fail;
                }

                if (chmod(var_tmp_dir, 0777 + S_ISVTX) < 0) {
                        r = -errno;
                        goto fail;
                }
        }

        if (unshare(CLONE_NEWNS) < 0) {
                r = -errno;
                goto fail;
        }

        /* Remount / as SLAVE so that nothing now mounted in the namespace
           shows up in the parent */
        if (mount(NULL, "/", NULL, MS_SLAVE|MS_REC, NULL) < 0) {
                r = -errno;
                goto fail;
        }

        for (p = paths; p < paths + n; p++) {
                r = apply_mount(p, tmp_dir, var_tmp_dir, inaccessible_dir);
                if (r < 0)
                        goto undo_mounts;
        }

        for (p = paths; p < paths + n; p++) {
                r = make_read_only(p);
                if (r < 0)
                        goto undo_mounts;
        }

        /* Remount / as the desired mode */
        if (mount(NULL, "/", NULL, flags|MS_REC, NULL) < 0) {
                r = -errno;
                goto undo_mounts;
        }

        return 0;

undo_mounts:
        for (p = paths; p < paths + n; p++)
                if (p->done)
                        umount2(p->path, MNT_DETACH);

fail:
        if (remove_inaccessible)
                rmdir(inaccessible_dir);

        if (remove_tmp)
                rmdir(tmp_dir);

        if (remove_var_tmp)
                rmdir(var_tmp_dir);

        return r;
}
