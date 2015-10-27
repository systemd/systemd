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

#include <string.h>
#include <sys/mount.h>
#include <sys/statvfs.h>

#include "alloc-util.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "mount-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "set.h"
#include "stdio-util.h"
#include "string-util.h"
#include "util.h"

static int fd_fdinfo_mnt_id(int fd, const char *filename, int flags, int *mnt_id) {
        char path[strlen("/proc/self/fdinfo/") + DECIMAL_STR_MAX(int)];
        _cleanup_free_ char *fdinfo = NULL;
        _cleanup_close_ int subfd = -1;
        char *p;
        int r;

        if ((flags & AT_EMPTY_PATH) && isempty(filename))
                xsprintf(path, "/proc/self/fdinfo/%i", fd);
        else {
                subfd = openat(fd, filename, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_PATH);
                if (subfd < 0)
                        return -errno;

                xsprintf(path, "/proc/self/fdinfo/%i", subfd);
        }

        r = read_full_file(path, &fdinfo, NULL);
        if (r == -ENOENT) /* The fdinfo directory is a relatively new addition */
                return -EOPNOTSUPP;
        if (r < 0)
                return -errno;

        p = startswith(fdinfo, "mnt_id:");
        if (!p) {
                p = strstr(fdinfo, "\nmnt_id:");
                if (!p) /* The mnt_id field is a relatively new addition */
                        return -EOPNOTSUPP;

                p += 8;
        }

        p += strspn(p, WHITESPACE);
        p[strcspn(p, WHITESPACE)] = 0;

        return safe_atoi(p, mnt_id);
}


int fd_is_mount_point(int fd, const char *filename, int flags) {
        union file_handle_union h = FILE_HANDLE_INIT, h_parent = FILE_HANDLE_INIT;
        int mount_id = -1, mount_id_parent = -1;
        bool nosupp = false, check_st_dev = true;
        struct stat a, b;
        int r;

        assert(fd >= 0);
        assert(filename);

        /* First we will try the name_to_handle_at() syscall, which
         * tells us the mount id and an opaque file "handle". It is
         * not supported everywhere though (kernel compile-time
         * option, not all file systems are hooked up). If it works
         * the mount id is usually good enough to tell us whether
         * something is a mount point.
         *
         * If that didn't work we will try to read the mount id from
         * /proc/self/fdinfo/<fd>. This is almost as good as
         * name_to_handle_at(), however, does not return the
         * opaque file handle. The opaque file handle is pretty useful
         * to detect the root directory, which we should always
         * consider a mount point. Hence we use this only as
         * fallback. Exporting the mnt_id in fdinfo is a pretty recent
         * kernel addition.
         *
         * As last fallback we do traditional fstat() based st_dev
         * comparisons. This is how things were traditionally done,
         * but unionfs breaks breaks this since it exposes file
         * systems with a variety of st_dev reported. Also, btrfs
         * subvolumes have different st_dev, even though they aren't
         * real mounts of their own. */

        r = name_to_handle_at(fd, filename, &h.handle, &mount_id, flags);
        if (r < 0) {
                if (errno == ENOSYS)
                        /* This kernel does not support name_to_handle_at()
                         * fall back to simpler logic. */
                        goto fallback_fdinfo;
                else if (errno == EOPNOTSUPP)
                        /* This kernel or file system does not support
                         * name_to_handle_at(), hence let's see if the
                         * upper fs supports it (in which case it is a
                         * mount point), otherwise fallback to the
                         * traditional stat() logic */
                        nosupp = true;
                else
                        return -errno;
        }

        r = name_to_handle_at(fd, "", &h_parent.handle, &mount_id_parent, AT_EMPTY_PATH);
        if (r < 0) {
                if (errno == EOPNOTSUPP) {
                        if (nosupp)
                                /* Neither parent nor child do name_to_handle_at()?
                                   We have no choice but to fall back. */
                                goto fallback_fdinfo;
                        else
                                /* The parent can't do name_to_handle_at() but the
                                 * directory we are interested in can?
                                 * If so, it must be a mount point. */
                                return 1;
                } else
                        return -errno;
        }

        /* The parent can do name_to_handle_at() but the
         * directory we are interested in can't? If so, it
         * must be a mount point. */
        if (nosupp)
                return 1;

        /* If the file handle for the directory we are
         * interested in and its parent are identical, we
         * assume this is the root directory, which is a mount
         * point. */

        if (h.handle.handle_bytes == h_parent.handle.handle_bytes &&
            h.handle.handle_type == h_parent.handle.handle_type &&
            memcmp(h.handle.f_handle, h_parent.handle.f_handle, h.handle.handle_bytes) == 0)
                return 1;

        return mount_id != mount_id_parent;

fallback_fdinfo:
        r = fd_fdinfo_mnt_id(fd, filename, flags, &mount_id);
        if (r == -EOPNOTSUPP)
                goto fallback_fstat;
        if (r < 0)
                return r;

        r = fd_fdinfo_mnt_id(fd, "", AT_EMPTY_PATH, &mount_id_parent);
        if (r < 0)
                return r;

        if (mount_id != mount_id_parent)
                return 1;

        /* Hmm, so, the mount ids are the same. This leaves one
         * special case though for the root file system. For that,
         * let's see if the parent directory has the same inode as we
         * are interested in. Hence, let's also do fstat() checks now,
         * too, but avoid the st_dev comparisons, since they aren't
         * that useful on unionfs mounts. */
        check_st_dev = false;

fallback_fstat:
        /* yay for fstatat() taking a different set of flags than the other
         * _at() above */
        if (flags & AT_SYMLINK_FOLLOW)
                flags &= ~AT_SYMLINK_FOLLOW;
        else
                flags |= AT_SYMLINK_NOFOLLOW;
        if (fstatat(fd, filename, &a, flags) < 0)
                return -errno;

        if (fstatat(fd, "", &b, AT_EMPTY_PATH) < 0)
                return -errno;

        /* A directory with same device and inode as its parent? Must
         * be the root directory */
        if (a.st_dev == b.st_dev &&
            a.st_ino == b.st_ino)
                return 1;

        return check_st_dev && (a.st_dev != b.st_dev);
}

/* flags can be AT_SYMLINK_FOLLOW or 0 */
int path_is_mount_point(const char *t, int flags) {
        _cleanup_close_ int fd = -1;
        _cleanup_free_ char *canonical = NULL, *parent = NULL;

        assert(t);

        if (path_equal(t, "/"))
                return 1;

        /* we need to resolve symlinks manually, we can't just rely on
         * fd_is_mount_point() to do that for us; if we have a structure like
         * /bin -> /usr/bin/ and /usr is a mount point, then the parent that we
         * look at needs to be /usr, not /. */
        if (flags & AT_SYMLINK_FOLLOW) {
                canonical = canonicalize_file_name(t);
                if (!canonical)
                        return -errno;

                t = canonical;
        }

        parent = dirname_malloc(t);
        if (!parent)
                return -ENOMEM;

        fd = openat(AT_FDCWD, parent, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC|O_PATH);
        if (fd < 0)
                return -errno;

        return fd_is_mount_point(fd, basename(t), flags);
}

int umount_recursive(const char *prefix, int flags) {
        bool again;
        int n = 0, r;

        /* Try to umount everything recursively below a
         * directory. Also, take care of stacked mounts, and keep
         * unmounting them until they are gone. */

        do {
                _cleanup_fclose_ FILE *proc_self_mountinfo = NULL;

                again = false;
                r = 0;

                proc_self_mountinfo = fopen("/proc/self/mountinfo", "re");
                if (!proc_self_mountinfo)
                        return -errno;

                for (;;) {
                        _cleanup_free_ char *path = NULL, *p = NULL;
                        int k;

                        k = fscanf(proc_self_mountinfo,
                                   "%*s "       /* (1) mount id */
                                   "%*s "       /* (2) parent id */
                                   "%*s "       /* (3) major:minor */
                                   "%*s "       /* (4) root */
                                   "%ms "       /* (5) mount point */
                                   "%*s"        /* (6) mount options */
                                   "%*[^-]"     /* (7) optional fields */
                                   "- "         /* (8) separator */
                                   "%*s "       /* (9) file system type */
                                   "%*s"        /* (10) mount source */
                                   "%*s"        /* (11) mount options 2 */
                                   "%*[^\n]",   /* some rubbish at the end */
                                   &path);
                        if (k != 1) {
                                if (k == EOF)
                                        break;

                                continue;
                        }

                        r = cunescape(path, UNESCAPE_RELAX, &p);
                        if (r < 0)
                                return r;

                        if (!path_startswith(p, prefix))
                                continue;

                        if (umount2(p, flags) < 0) {
                                r = -errno;
                                continue;
                        }

                        again = true;
                        n++;

                        break;
                }

        } while (again);

        return r ? r : n;
}

static int get_mount_flags(const char *path, unsigned long *flags) {
        struct statvfs buf;

        if (statvfs(path, &buf) < 0)
                return -errno;
        *flags = buf.f_flag;
        return 0;
}

int bind_remount_recursive(const char *prefix, bool ro) {
        _cleanup_set_free_free_ Set *done = NULL;
        _cleanup_free_ char *cleaned = NULL;
        int r;

        /* Recursively remount a directory (and all its submounts)
         * read-only or read-write. If the directory is already
         * mounted, we reuse the mount and simply mark it
         * MS_BIND|MS_RDONLY (or remove the MS_RDONLY for read-write
         * operation). If it isn't we first make it one. Afterwards we
         * apply MS_BIND|MS_RDONLY (or remove MS_RDONLY) to all
         * submounts we can access, too. When mounts are stacked on
         * the same mount point we only care for each individual
         * "top-level" mount on each point, as we cannot
         * influence/access the underlying mounts anyway. We do not
         * have any effect on future submounts that might get
         * propagated, they migt be writable. This includes future
         * submounts that have been triggered via autofs. */

        cleaned = strdup(prefix);
        if (!cleaned)
                return -ENOMEM;

        path_kill_slashes(cleaned);

        done = set_new(&string_hash_ops);
        if (!done)
                return -ENOMEM;

        for (;;) {
                _cleanup_fclose_ FILE *proc_self_mountinfo = NULL;
                _cleanup_set_free_free_ Set *todo = NULL;
                bool top_autofs = false;
                char *x;
                unsigned long orig_flags;

                todo = set_new(&string_hash_ops);
                if (!todo)
                        return -ENOMEM;

                proc_self_mountinfo = fopen("/proc/self/mountinfo", "re");
                if (!proc_self_mountinfo)
                        return -errno;

                for (;;) {
                        _cleanup_free_ char *path = NULL, *p = NULL, *type = NULL;
                        int k;

                        k = fscanf(proc_self_mountinfo,
                                   "%*s "       /* (1) mount id */
                                   "%*s "       /* (2) parent id */
                                   "%*s "       /* (3) major:minor */
                                   "%*s "       /* (4) root */
                                   "%ms "       /* (5) mount point */
                                   "%*s"        /* (6) mount options (superblock) */
                                   "%*[^-]"     /* (7) optional fields */
                                   "- "         /* (8) separator */
                                   "%ms "       /* (9) file system type */
                                   "%*s"        /* (10) mount source */
                                   "%*s"        /* (11) mount options (bind mount) */
                                   "%*[^\n]",   /* some rubbish at the end */
                                   &path,
                                   &type);
                        if (k != 2) {
                                if (k == EOF)
                                        break;

                                continue;
                        }

                        r = cunescape(path, UNESCAPE_RELAX, &p);
                        if (r < 0)
                                return r;

                        /* Let's ignore autofs mounts.  If they aren't
                         * triggered yet, we want to avoid triggering
                         * them, as we don't make any guarantees for
                         * future submounts anyway.  If they are
                         * already triggered, then we will find
                         * another entry for this. */
                        if (streq(type, "autofs")) {
                                top_autofs = top_autofs || path_equal(cleaned, p);
                                continue;
                        }

                        if (path_startswith(p, cleaned) &&
                            !set_contains(done, p)) {

                                r = set_consume(todo, p);
                                p = NULL;

                                if (r == -EEXIST)
                                        continue;
                                if (r < 0)
                                        return r;
                        }
                }

                /* If we have no submounts to process anymore and if
                 * the root is either already done, or an autofs, we
                 * are done */
                if (set_isempty(todo) &&
                    (top_autofs || set_contains(done, cleaned)))
                        return 0;

                if (!set_contains(done, cleaned) &&
                    !set_contains(todo, cleaned)) {
                        /* The prefix directory itself is not yet a
                         * mount, make it one. */
                        if (mount(cleaned, cleaned, NULL, MS_BIND|MS_REC, NULL) < 0)
                                return -errno;

                        orig_flags = 0;
                        (void) get_mount_flags(cleaned, &orig_flags);
                        orig_flags &= ~MS_RDONLY;

                        if (mount(NULL, prefix, NULL, orig_flags|MS_BIND|MS_REMOUNT|(ro ? MS_RDONLY : 0), NULL) < 0)
                                return -errno;

                        x = strdup(cleaned);
                        if (!x)
                                return -ENOMEM;

                        r = set_consume(done, x);
                        if (r < 0)
                                return r;
                }

                while ((x = set_steal_first(todo))) {

                        r = set_consume(done, x);
                        if (r == -EEXIST || r == 0)
                                continue;
                        if (r < 0)
                                return r;

                        /* Try to reuse the original flag set, but
                         * don't care for errors, in case of
                         * obstructed mounts */
                        orig_flags = 0;
                        (void) get_mount_flags(x, &orig_flags);
                        orig_flags &= ~MS_RDONLY;

                        if (mount(NULL, x, NULL, orig_flags|MS_BIND|MS_REMOUNT|(ro ? MS_RDONLY : 0), NULL) < 0) {

                                /* Deal with mount points that are
                                 * obstructed by a later mount */

                                if (errno != ENOENT)
                                        return -errno;
                        }

                }
        }
}

int mount_move_root(const char *path) {
        assert(path);

        if (chdir(path) < 0)
                return -errno;

        if (mount(path, "/", NULL, MS_MOVE, NULL) < 0)
                return -errno;

        if (chroot(".") < 0)
                return -errno;

        if (chdir("/") < 0)
                return -errno;

        return 0;
}

bool fstype_is_network(const char *fstype) {
        static const char table[] =
                "afs\0"
                "cifs\0"
                "smbfs\0"
                "sshfs\0"
                "ncpfs\0"
                "ncp\0"
                "nfs\0"
                "nfs4\0"
                "gfs\0"
                "gfs2\0"
                "glusterfs\0";

        const char *x;

        x = startswith(fstype, "fuse.");
        if (x)
                fstype = x;

        return nulstr_contains(table, fstype);
}

int repeat_unmount(const char *path, int flags) {
        bool done = false;

        assert(path);

        /* If there are multiple mounts on a mount point, this
         * removes them all */

        for (;;) {
                if (umount2(path, flags) < 0) {

                        if (errno == EINVAL)
                                return done;

                        return -errno;
                }

                done = true;
        }
}
