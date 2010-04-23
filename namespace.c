/*-*- Mode: C; c-basic-offset: 8 -*-*/

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
#include <sys/mount.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sched.h>
#include <sys/syscall.h>
#include <limits.h>

#include "strv.h"
#include "util.h"
#include "namespace.h"
#include "missing.h"

typedef enum PathMode {
        /* This is ordered by priority! */
        INACCESSIBLE,
        READONLY,
        PRIVATE,
        READWRITE
} PathMode;

typedef struct Path {
        const char *path;
        PathMode mode;
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

static void drop_duplicates(Path *p, unsigned *n, bool *need_inaccessible, bool *need_private) {
        Path *f, *t, *previous;

        assert(p);
        assert(n);
        assert(need_inaccessible);
        assert(need_private);

        for (f = p, t = p, previous = NULL; f < p+*n; f++) {

                if (previous && path_equal(f->path, previous->path))
                        continue;

                t->path = f->path;
                t->mode = f->mode;

                if (t->mode == PRIVATE)
                        *need_private = true;

                if (t->mode == INACCESSIBLE)
                        *need_inaccessible = true;

                previous = t;

                t++;
        }

        *n = t - p;
}

static int apply_mount(Path *p, const char *root_dir, const char *inaccessible_dir, const char *private_dir, unsigned long flags) {
        const char *what;
        char *where;
        int r;

        assert(p);
        assert(root_dir);
        assert(inaccessible_dir);
        assert(private_dir);

        if (!(where = strappend(root_dir, p->path)))
                return -ENOMEM;

        switch (p->mode) {

        case INACCESSIBLE:
                what = inaccessible_dir;
                flags |= MS_RDONLY;
                break;

        case READONLY:
                flags |= MS_RDONLY;
                /* Fall through */

        case READWRITE:
                what = p->path;
                break;

        case PRIVATE:
                what = private_dir;
                break;
        }

        if ((r = mount(what, where, NULL, MS_BIND|MS_REC, NULL)) >= 0) {
                log_debug("Successfully mounted %s to %s", what, where);

                /* The bind mount will always inherit the original
                 * flags. If we want to set any flag we need
                 * to do so in a second indepdant step. */
                if (flags)
                        r = mount(NULL, where, NULL, MS_REMOUNT|MS_BIND|MS_REC|flags, NULL);

                /* Avoid expontial growth of trees */
                if (r >= 0 && path_equal(p->path, "/"))
                        r = mount(NULL, where, NULL, MS_REMOUNT|MS_BIND|MS_UNBINDABLE|flags, NULL);

                if (r < 0) {
                        r = -errno;
                        umount2(where, MNT_DETACH);
                }
        }

        free(where);
        return r;
}

int setup_namespace(
                char **writable,
                char **readable,
                char **inaccessible,
                bool private_tmp,
                unsigned long flags) {

        char
                tmp_dir[] = "/tmp/systemd-namespace-XXXXXX",
                root_dir[] = "/tmp/systemd-namespace-XXXXXX/root",
                old_root_dir[] = "/tmp/systemd-namespace-XXXXXX/root/tmp/old-root-XXXXXX",
                inaccessible_dir[] = "/tmp/systemd-namespace-XXXXXX/inaccessible",
                private_dir[] = "/tmp/systemd-namespace-XXXXXX/private";

        Path *paths, *p;
        unsigned n;
        bool need_private = false, need_inaccessible = false;
        bool remove_tmp = false, remove_root = false, remove_old_root = false, remove_inaccessible = false, remove_private = false;
        int r;
        const char *t;

        n =
                strv_length(writable) +
                strv_length(readable) +
                strv_length(inaccessible) +
                (private_tmp ? 2 : 1);

        if (!(paths = new(Path, n)))
                return -ENOMEM;

        p = paths;
        if ((r = append_paths(&p, writable, READWRITE)) < 0 ||
            (r = append_paths(&p, readable, READONLY)) < 0 ||
            (r = append_paths(&p, inaccessible, INACCESSIBLE)) < 0)
                goto fail;

        if (private_tmp) {
                p->path = "/tmp";
                p->mode = PRIVATE;
                p++;
        }

        p->path = "/";
        p->mode = READWRITE;
        p++;

        assert(paths + n == p);

        qsort(paths, n, sizeof(Path), path_compare);
        drop_duplicates(paths, &n, &need_inaccessible, &need_private);

        if (!mkdtemp(tmp_dir)) {
                r = -errno;
                goto fail;
        }
        remove_tmp = true;

        memcpy(root_dir, tmp_dir, sizeof(tmp_dir)-1);
        if (mkdir(root_dir, 0777) < 0) {
                r = -errno;
                goto fail;
        }
        remove_root = true;

        if (need_inaccessible) {
                memcpy(inaccessible_dir, tmp_dir, sizeof(tmp_dir)-1);
                if (mkdir(inaccessible_dir, 0) < 0) {
                        r = -errno;
                        goto fail;
                }
                remove_inaccessible = true;
        }

        if (need_private) {
                memcpy(private_dir, tmp_dir, sizeof(tmp_dir)-1);
                if (mkdir(private_dir, 0777 + S_ISVTX) < 0) {
                        r = -errno;
                        goto fail;
                }
                remove_private = true;
        }

        if (unshare(CLONE_NEWNS) < 0) {
                r = -errno;
                goto fail;
        }

        /* We assume that by default mount events from us won't be
         * propagated to the root namespace. */

        for (p = paths; p < paths + n; p++)
                if ((r = apply_mount(p, root_dir, inaccessible_dir, private_dir, flags)) < 0)
                        goto undo_mounts;

        memcpy(old_root_dir, tmp_dir, sizeof(tmp_dir)-1);
        if (!mkdtemp(old_root_dir)) {
                r = -errno;
                goto undo_mounts;
        }
        remove_old_root = true;

        if (chdir(root_dir) < 0) {
                r = -errno;
                goto undo_mounts;
        }

        if (pivot_root(root_dir, old_root_dir) < 0) {
                r = -errno;
                goto undo_mounts;
        }

        t = old_root_dir + sizeof(root_dir) - 1;
        if (umount2(t, MNT_DETACH) < 0)
                /* At this point it's too late to turn anything back,
                 * since we are already in the new root. */
                return -errno;

        if (rmdir(t) < 0)
                return -errno;

        return 0;

undo_mounts:

        for (p--; p >= paths; p--) {
                char full_path[PATH_MAX];

                snprintf(full_path, sizeof(full_path), "%s%s", root_dir, p->path);
                char_array_0(full_path);

                umount2(full_path, MNT_DETACH);
        }

fail:
        if (remove_old_root)
                rmdir(old_root_dir);

        if (remove_inaccessible)
                rmdir(inaccessible_dir);

        if (remove_private)
                rmdir(private_dir);

        if (remove_root)
                rmdir(root_dir);

        if (remove_tmp)
                rmdir(tmp_dir);

             free(paths);

        return r;
}
