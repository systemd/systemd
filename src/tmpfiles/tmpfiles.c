/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering, Kay Sievers

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

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <limits.h>
#include <dirent.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <getopt.h>
#include <stdbool.h>
#include <time.h>
#include <sys/types.h>
#include <sys/param.h>
#include <glob.h>
#include <fnmatch.h>
#include <sys/capability.h>

#include "log.h"
#include "util.h"
#include "macro.h"
#include "missing.h"
#include "mkdir.h"
#include "path-util.h"
#include "strv.h"
#include "label.h"
#include "set.h"
#include "conf-files.h"
#include "capability.h"
#include "specifier.h"
#include "build.h"
#include "copy.h"

/* This reads all files listed in /etc/tmpfiles.d/?*.conf and creates
 * them in the file system. This is intended to be used to create
 * properly owned directories beneath /tmp, /var/tmp, /run, which are
 * volatile and hence need to be recreated on bootup. */

typedef enum ItemType {
        /* These ones take file names */
        CREATE_FILE = 'f',
        TRUNCATE_FILE = 'F',
        CREATE_DIRECTORY = 'd',
        TRUNCATE_DIRECTORY = 'D',
        CREATE_FIFO = 'p',
        CREATE_SYMLINK = 'L',
        CREATE_CHAR_DEVICE = 'c',
        CREATE_BLOCK_DEVICE = 'b',
        COPY_FILES = 'C',

        /* These ones take globs */
        WRITE_FILE = 'w',
        IGNORE_PATH = 'x',
        IGNORE_DIRECTORY_PATH = 'X',
        REMOVE_PATH = 'r',
        RECURSIVE_REMOVE_PATH = 'R',
        ADJUST_MODE = 'm', /* legacy, 'z' is identical to this */
        RELABEL_PATH = 'z',
        RECURSIVE_RELABEL_PATH = 'Z',
} ItemType;

typedef struct Item {
        ItemType type;

        char *path;
        char *argument;
        uid_t uid;
        gid_t gid;
        mode_t mode;
        usec_t age;

        dev_t major_minor;

        bool uid_set:1;
        bool gid_set:1;
        bool mode_set:1;
        bool age_set:1;
        bool mask_perms:1;

        bool keep_first_level:1;

        bool force:1;

        bool done:1;
} Item;

static bool arg_create = false;
static bool arg_clean = false;
static bool arg_remove = false;
static bool arg_boot = false;

static char **arg_include_prefixes = NULL;
static char **arg_exclude_prefixes = NULL;
static char *arg_root = NULL;

static const char conf_file_dirs[] =
        "/etc/tmpfiles.d\0"
        "/run/tmpfiles.d\0"
        "/usr/local/lib/tmpfiles.d\0"
        "/usr/lib/tmpfiles.d\0"
#ifdef HAVE_SPLIT_USR
        "/lib/tmpfiles.d\0"
#endif
        ;

#define MAX_DEPTH 256

static Hashmap *items = NULL, *globs = NULL;
static Set *unix_sockets = NULL;

static bool needs_glob(ItemType t) {
        return IN_SET(t,
                      WRITE_FILE,
                      IGNORE_PATH,
                      IGNORE_DIRECTORY_PATH,
                      REMOVE_PATH,
                      RECURSIVE_REMOVE_PATH,
                      ADJUST_MODE,
                      RELABEL_PATH,
                      RECURSIVE_RELABEL_PATH);
}

static struct Item* find_glob(Hashmap *h, const char *match) {
        Item *j;
        Iterator i;

        HASHMAP_FOREACH(j, h, i)
                if (fnmatch(j->path, match, FNM_PATHNAME|FNM_PERIOD) == 0)
                        return j;

        return NULL;
}

static void load_unix_sockets(void) {
        _cleanup_fclose_ FILE *f = NULL;
        char line[LINE_MAX];

        if (unix_sockets)
                return;

        /* We maintain a cache of the sockets we found in
         * /proc/net/unix to speed things up a little. */

        unix_sockets = set_new(string_hash_func, string_compare_func);
        if (!unix_sockets)
                return;

        f = fopen("/proc/net/unix", "re");
        if (!f)
                return;

        /* Skip header */
        if (!fgets(line, sizeof(line), f))
                goto fail;

        for (;;) {
                char *p, *s;
                int k;

                if (!fgets(line, sizeof(line), f))
                        break;

                truncate_nl(line);

                p = strchr(line, ':');
                if (!p)
                        continue;

                if (strlen(p) < 37)
                        continue;

                p += 37;
                p += strspn(p, WHITESPACE);
                p += strcspn(p, WHITESPACE); /* skip one more word */
                p += strspn(p, WHITESPACE);

                if (*p != '/')
                        continue;

                s = strdup(p);
                if (!s)
                        goto fail;

                path_kill_slashes(s);

                k = set_consume(unix_sockets, s);
                if (k < 0 && k != -EEXIST)
                        goto fail;
        }

        return;

fail:
        set_free_free(unix_sockets);
        unix_sockets = NULL;
}

static bool unix_socket_alive(const char *fn) {
        assert(fn);

        load_unix_sockets();

        if (unix_sockets)
                return !!set_get(unix_sockets, (char*) fn);

        /* We don't know, so assume yes */
        return true;
}

static int dir_is_mount_point(DIR *d, const char *subdir) {

        union file_handle_union h = {
                .handle.handle_bytes = MAX_HANDLE_SZ
        };

        int mount_id_parent, mount_id;
        int r_p, r;

        r_p = name_to_handle_at(dirfd(d), ".", &h.handle, &mount_id_parent, 0);
        if (r_p < 0)
                r_p = -errno;

        h.handle.handle_bytes = MAX_HANDLE_SZ;
        r = name_to_handle_at(dirfd(d), subdir, &h.handle, &mount_id, 0);
        if (r < 0)
                r = -errno;

        /* got no handle; make no assumptions, return error */
        if (r_p < 0 && r < 0)
                return r_p;

        /* got both handles; if they differ, it is a mount point */
        if (r_p >= 0 && r >= 0)
                return mount_id_parent != mount_id;

        /* got only one handle; assume different mount points if one
         * of both queries was not supported by the filesystem */
        if (r_p == -ENOSYS || r_p == -ENOTSUP || r == -ENOSYS || r == -ENOTSUP)
                return true;

        /* return error */
        if (r_p < 0)
                return r_p;
        return r;
}

static int dir_cleanup(
                Item *i,
                const char *p,
                DIR *d,
                const struct stat *ds,
                usec_t cutoff,
                dev_t rootdev,
                bool mountpoint,
                int maxdepth,
                bool keep_this_level) {

        struct dirent *dent;
        struct timespec times[2];
        bool deleted = false;
        int r = 0;

        while ((dent = readdir(d))) {
                struct stat s;
                usec_t age;
                _cleanup_free_ char *sub_path = NULL;

                if (streq(dent->d_name, ".") ||
                    streq(dent->d_name, ".."))
                        continue;

                if (fstatat(dirfd(d), dent->d_name, &s, AT_SYMLINK_NOFOLLOW) < 0) {
                        if (errno == ENOENT)
                                continue;

                        /* FUSE, NFS mounts, SELinux might return EACCES */
                        if (errno == EACCES)
                                log_debug("stat(%s/%s) failed: %m", p, dent->d_name);
                        else
                                log_error("stat(%s/%s) failed: %m", p, dent->d_name);
                        r = -errno;
                        continue;
                }

                /* Stay on the same filesystem */
                if (s.st_dev != rootdev)
                        continue;

                /* Try to detect bind mounts of the same filesystem instance; they
                 * do not differ in device major/minors. This type of query is not
                 * supported on all kernels or filesystem types though. */
                if (S_ISDIR(s.st_mode) && dir_is_mount_point(d, dent->d_name) > 0)
                        continue;

                /* Do not delete read-only files owned by root */
                if (s.st_uid == 0 && !(s.st_mode & S_IWUSR))
                        continue;

                sub_path = strjoin(p, "/", dent->d_name, NULL);
                if (!sub_path) {
                        r = log_oom();
                        goto finish;
                }

                /* Is there an item configured for this path? */
                if (hashmap_get(items, sub_path))
                        continue;

                if (find_glob(globs, sub_path))
                        continue;

                if (S_ISDIR(s.st_mode)) {

                        if (mountpoint &&
                            streq(dent->d_name, "lost+found") &&
                            s.st_uid == 0)
                                continue;

                        if (maxdepth <= 0)
                                log_warning("Reached max depth on %s.", sub_path);
                        else {
                                _cleanup_closedir_ DIR *sub_dir;
                                int q;

                                sub_dir = xopendirat(dirfd(d), dent->d_name, O_NOFOLLOW|O_NOATIME);
                                if (!sub_dir) {
                                        if (errno != ENOENT) {
                                                log_error("opendir(%s/%s) failed: %m", p, dent->d_name);
                                                r = -errno;
                                        }

                                        continue;
                                }

                                q = dir_cleanup(i, sub_path, sub_dir, &s, cutoff, rootdev, false, maxdepth-1, false);
                                if (q < 0)
                                        r = q;
                        }

                        /* Note: if you are wondering why we don't
                         * support the sticky bit for excluding
                         * directories from cleaning like we do it for
                         * other file system objects: well, the sticky
                         * bit already has a meaning for directories,
                         * so we don't want to overload that. */

                        if (keep_this_level)
                                continue;

                        /* Ignore ctime, we change it when deleting */
                        age = MAX(timespec_load(&s.st_mtim),
                                  timespec_load(&s.st_atim));
                        if (age >= cutoff)
                                continue;

                        if (i->type != IGNORE_DIRECTORY_PATH || !streq(dent->d_name, p)) {
                                log_debug("rmdir '%s'", sub_path);

                                if (unlinkat(dirfd(d), dent->d_name, AT_REMOVEDIR) < 0) {
                                        if (errno != ENOENT && errno != ENOTEMPTY) {
                                                log_error("rmdir(%s): %m", sub_path);
                                                r = -errno;
                                        }
                                }
                        }

                } else {
                        /* Skip files for which the sticky bit is
                         * set. These are semantics we define, and are
                         * unknown elsewhere. See XDG_RUNTIME_DIR
                         * specification for details. */
                        if (s.st_mode & S_ISVTX)
                                continue;

                        if (mountpoint && S_ISREG(s.st_mode)) {
                                if (streq(dent->d_name, ".journal") &&
                                    s.st_uid == 0)
                                        continue;

                                if (streq(dent->d_name, "aquota.user") ||
                                    streq(dent->d_name, "aquota.group"))
                                        continue;
                        }

                        /* Ignore sockets that are listed in /proc/net/unix */
                        if (S_ISSOCK(s.st_mode) && unix_socket_alive(sub_path))
                                continue;

                        /* Ignore device nodes */
                        if (S_ISCHR(s.st_mode) || S_ISBLK(s.st_mode))
                                continue;

                        /* Keep files on this level around if this is
                         * requested */
                        if (keep_this_level)
                                continue;

                        age = MAX3(timespec_load(&s.st_mtim),
                                   timespec_load(&s.st_atim),
                                   timespec_load(&s.st_ctim));

                        if (age >= cutoff)
                                continue;

                        log_debug("unlink '%s'", sub_path);

                        if (unlinkat(dirfd(d), dent->d_name, 0) < 0) {
                                if (errno != ENOENT) {
                                        log_error("unlink(%s): %m", sub_path);
                                        r = -errno;
                                }
                        }

                        deleted = true;
                }
        }

finish:
        if (deleted) {
                /* Restore original directory timestamps */
                times[0] = ds->st_atim;
                times[1] = ds->st_mtim;

                if (futimens(dirfd(d), times) < 0)
                        log_error("utimensat(%s): %m", p);
        }

        return r;
}

static int item_set_perms(Item *i, const char *path) {
        assert(i);
        assert(path);

        /* not using i->path directly because it may be a glob */
        if (i->mode_set) {
                mode_t m = i->mode;

                if (i->mask_perms) {
                        struct stat st;

                        if (stat(path, &st) >= 0) {
                                if (!(st.st_mode & 0111))
                                        m &= ~0111;
                                if (!(st.st_mode & 0222))
                                        m &= ~0222;
                                if (!(st.st_mode & 0444))
                                        m &= ~0444;
                                if (!S_ISDIR(st.st_mode))
                                        m &= ~07000; /* remove sticky/sgid/suid bit, unless directory */
                        }
                }

                if (chmod(path, m) < 0) {
                        log_error("chmod(%s) failed: %m", path);
                        return -errno;
                }
        }

        if (i->uid_set || i->gid_set)
                if (chown(path,
                          i->uid_set ? i->uid : (uid_t) -1,
                          i->gid_set ? i->gid : (gid_t) -1) < 0) {

                        log_error("chown(%s) failed: %m", path);
                        return -errno;
                }

        return label_fix(path, false, false);
}

static int write_one_file(Item *i, const char *path) {
        _cleanup_close_ int fd = -1;
        int flags, r = 0;
        struct stat st;

        assert(i);
        assert(path);

        flags = i->type == CREATE_FILE ? O_CREAT|O_APPEND|O_NOFOLLOW :
                i->type == TRUNCATE_FILE ? O_CREAT|O_TRUNC|O_NOFOLLOW : 0;

        RUN_WITH_UMASK(0000) {
                label_context_set(path, S_IFREG);
                fd = open(path, flags|O_NDELAY|O_CLOEXEC|O_WRONLY|O_NOCTTY, i->mode);
                label_context_clear();
        }

        if (fd < 0) {
                if (i->type == WRITE_FILE && errno == ENOENT)
                        return 0;

                log_error("Failed to create file %s: %m", path);
                return -errno;
        }

        if (i->argument) {
                _cleanup_free_ char *unescaped;
                ssize_t n;
                size_t l;

                unescaped = cunescape(i->argument);
                if (!unescaped)
                        return log_oom();

                l = strlen(unescaped);
                n = write(fd, unescaped, l);

                if (n < 0 || (size_t) n < l) {
                        log_error("Failed to write file %s: %s", path, n < 0 ? strerror(-n) : "Short write");
                        return n < 0 ? n : -EIO;
                }
        }

        fd = safe_close(fd);

        if (stat(path, &st) < 0) {
                log_error("stat(%s) failed: %m", path);
                return -errno;
        }

        if (!S_ISREG(st.st_mode)) {
                log_error("%s is not a file.", path);
                return -EEXIST;
        }

        r = item_set_perms(i, path);
        if (r < 0)
                return r;

        return 0;
}

static int item_set_perms_children(Item *i, const char *path) {
        _cleanup_closedir_ DIR *d;
        int r = 0;

        assert(i);
        assert(path);

        /* This returns the first error we run into, but nevertheless
         * tries to go on */

        d = opendir(path);
        if (!d)
                return errno == ENOENT || errno == ENOTDIR ? 0 : -errno;

        for (;;) {
                _cleanup_free_ char *p = NULL;
                struct dirent *de;
                int q;

                errno = 0;
                de = readdir(d);
                if (!de) {
                        if (errno != 0 && r == 0)
                                r = -errno;

                        break;
                }

                if (streq(de->d_name, ".") || streq(de->d_name, ".."))
                        continue;

                p = strjoin(path, "/", de->d_name, NULL);
                if (!p)
                        return -ENOMEM;

                q = item_set_perms(i, p);
                if (q < 0 && q != -ENOENT && r == 0)
                        r = q;

                if (IN_SET(de->d_type, DT_UNKNOWN, DT_DIR)) {
                        q = item_set_perms_children(i, p);
                        if (q < 0 && r == 0)
                                r = q;
                }
        }

        return r;
}

static int item_set_perms_recursive(Item *i, const char *path) {
        int r, q;

        assert(i);
        assert(path);

        r = item_set_perms(i, path);
        if (r < 0)
                return r;

        q = item_set_perms_children(i, path);
        if (q < 0 && r == 0)
                r = q;

        return r;
}

static int glob_item(Item *i, int (*action)(Item *, const char *)) {
        _cleanup_globfree_ glob_t g = {};
        int r = 0, k;
        char **fn;

        errno = 0;
        k = glob(i->path, GLOB_NOSORT|GLOB_BRACE, NULL, &g);
        if (k != 0 && k != GLOB_NOMATCH) {
                if (errno == 0)
                        errno = EIO;

                log_error("glob(%s) failed: %m", i->path);
                return -errno;
        }

        STRV_FOREACH(fn, g.gl_pathv) {
                k = action(i, *fn);
                if (k < 0 && r == 0)
                        r = k;
        }

        return r;
}

static int create_item(Item *i) {
        struct stat st;
        int r = 0;

        assert(i);

        switch (i->type) {

        case IGNORE_PATH:
        case IGNORE_DIRECTORY_PATH:
        case REMOVE_PATH:
        case RECURSIVE_REMOVE_PATH:
                return 0;

        case CREATE_FILE:
        case TRUNCATE_FILE:
                r = write_one_file(i, i->path);
                if (r < 0)
                        return r;
                break;

        case COPY_FILES:
                r = copy_tree(i->argument, i->path, false);
                if (r < 0) {
                        struct stat a, b;

                        if (r != -EEXIST) {
                                log_error("Failed to copy files to %s: %s", i->path, strerror(-r));
                                return -r;
                        }

                        if (stat(i->argument, &a) < 0) {
                                log_error("stat(%s) failed: %m", i->argument);
                                return -errno;
                        }

                        if (stat(i->path, &b) < 0) {
                                log_error("stat(%s) failed: %m", i->path);
                                return -errno;
                        }

                        if ((a.st_mode ^ b.st_mode) & S_IFMT) {
                                log_debug("Can't copy to %s, file exists already and is of different type", i->path);
                                return 0;
                        }
                }

                r = item_set_perms(i, i->path);
                if (r < 0)
                        return r;

                break;

        case WRITE_FILE:
                r = glob_item(i, write_one_file);
                if (r < 0)
                        return r;

                break;

        case TRUNCATE_DIRECTORY:
        case CREATE_DIRECTORY:

                RUN_WITH_UMASK(0000) {
                        mkdir_parents_label(i->path, 0755);
                        r = mkdir_label(i->path, i->mode);
                }

                if (r < 0) {
                        if (r != -EEXIST) {
                                log_error("Failed to create directory %s: %s", i->path, strerror(-r));
                                return r;
                        }

                        if (stat(i->path, &st) < 0) {
                                log_error("stat(%s) failed: %m", i->path);
                                return -errno;
                        }

                        if (!S_ISDIR(st.st_mode)) {
                                log_debug("%s already exists and is not a directory.", i->path);
                                return 0;
                        }
                }

                r = item_set_perms(i, i->path);
                if (r < 0)
                        return r;

                break;

        case CREATE_FIFO:

                RUN_WITH_UMASK(0000) {
                        label_context_set(i->path, S_IFIFO);
                        r = mkfifo(i->path, i->mode);
                        label_context_clear();
                }

                if (r < 0) {
                        if (errno != EEXIST) {
                                log_error("Failed to create fifo %s: %m", i->path);
                                return -errno;
                        }

                        if (stat(i->path, &st) < 0) {
                                log_error("stat(%s) failed: %m", i->path);
                                return -errno;
                        }

                        if (!S_ISFIFO(st.st_mode)) {

                                if (i->force) {

                                        RUN_WITH_UMASK(0000) {
                                                label_context_set(i->path, S_IFIFO);
                                                r = mkfifo_atomic(i->path, i->mode);
                                                label_context_clear();
                                        }

                                        if (r < 0) {
                                                log_error("Failed to create fifo %s: %s", i->path, strerror(-r));
                                                return r;
                                        }
                                } else {
                                        log_debug("%s is not a fifo.", i->path);
                                        return 0;
                                }
                        }
                }

                r = item_set_perms(i, i->path);
                if (r < 0)
                        return r;

                break;

        case CREATE_SYMLINK:

                label_context_set(i->path, S_IFLNK);
                r = symlink(i->argument, i->path);
                label_context_clear();

                if (r < 0) {
                        _cleanup_free_ char *x = NULL;

                        if (errno != EEXIST) {
                                log_error("symlink(%s, %s) failed: %m", i->argument, i->path);
                                return -errno;
                        }

                        r = readlink_malloc(i->path, &x);
                        if (r < 0 || !streq(i->argument, x)) {

                                if (i->force) {
                                        label_context_set(i->path, S_IFLNK);
                                        r = symlink_atomic(i->argument, i->path);
                                        label_context_clear();

                                        if (r < 0) {
                                                log_error("symlink(%s, %s) failed: %s", i->argument, i->path, strerror(-r));
                                                return r;
                                        }
                                } else {
                                        log_debug("%s is not a symlink or does not point to the correct path.", i->path);
                                        return 0;
                                }
                        }
                }

                break;

        case CREATE_BLOCK_DEVICE:
        case CREATE_CHAR_DEVICE: {
                mode_t file_type;

                if (have_effective_cap(CAP_MKNOD) == 0) {
                        /* In a container we lack CAP_MKNOD. We
                        shouldn't attempt to create the device node in
                        that case to avoid noise, and we don't support
                        virtualized devices in containers anyway. */

                        log_debug("We lack CAP_MKNOD, skipping creation of device node %s.", i->path);
                        return 0;
                }

                file_type = i->type == CREATE_BLOCK_DEVICE ? S_IFBLK : S_IFCHR;

                RUN_WITH_UMASK(0000) {
                        label_context_set(i->path, file_type);
                        r = mknod(i->path, i->mode | file_type, i->major_minor);
                        label_context_clear();
                }

                if (r < 0) {
                        if (errno == EPERM) {
                                log_debug("We lack permissions, possibly because of cgroup configuration; "
                                          "skipping creation of device node %s.", i->path);
                                return 0;
                        }

                        if (errno != EEXIST) {
                                log_error("Failed to create device node %s: %m", i->path);
                                return -errno;
                        }

                        if (stat(i->path, &st) < 0) {
                                log_error("stat(%s) failed: %m", i->path);
                                return -errno;
                        }

                        if ((st.st_mode & S_IFMT) != file_type) {

                                if (i->force) {

                                        RUN_WITH_UMASK(0000) {
                                                label_context_set(i->path, file_type);
                                                r = mknod_atomic(i->path, i->mode | file_type, i->major_minor);
                                                label_context_clear();
                                        }

                                        if (r < 0) {
                                                log_error("Failed to create device node %s: %s", i->path, strerror(-r));
                                                return r;
                                        }
                                } else {
                                        log_debug("%s is not a device node.", i->path);
                                        return 0;
                                }
                        }
                }

                r = item_set_perms(i, i->path);
                if (r < 0)
                        return r;

                break;
        }

        case ADJUST_MODE:
        case RELABEL_PATH:

                r = glob_item(i, item_set_perms);
                if (r < 0)
                        return r;
                break;

        case RECURSIVE_RELABEL_PATH:

                r = glob_item(i, item_set_perms_recursive);
                if (r < 0)
                        return r;

                break;
        }

        log_debug("%s created successfully.", i->path);

        return 0;
}

static int remove_item_instance(Item *i, const char *instance) {
        int r;

        assert(i);

        switch (i->type) {

        case CREATE_FILE:
        case TRUNCATE_FILE:
        case CREATE_DIRECTORY:
        case CREATE_FIFO:
        case CREATE_SYMLINK:
        case CREATE_BLOCK_DEVICE:
        case CREATE_CHAR_DEVICE:
        case IGNORE_PATH:
        case IGNORE_DIRECTORY_PATH:
        case ADJUST_MODE:
        case RELABEL_PATH:
        case RECURSIVE_RELABEL_PATH:
        case WRITE_FILE:
        case COPY_FILES:
                break;

        case REMOVE_PATH:
                if (remove(instance) < 0 && errno != ENOENT) {
                        log_error("remove(%s): %m", instance);
                        return -errno;
                }

                break;

        case TRUNCATE_DIRECTORY:
        case RECURSIVE_REMOVE_PATH:
                /* FIXME: we probably should use dir_cleanup() here
                 * instead of rm_rf() so that 'x' is honoured. */
                r = rm_rf_dangerous(instance, false, i->type == RECURSIVE_REMOVE_PATH, false);
                if (r < 0 && r != -ENOENT) {
                        log_error("rm_rf(%s): %s", instance, strerror(-r));
                        return r;
                }

                break;
        }

        return 0;
}

static int remove_item(Item *i) {
        int r = 0;

        assert(i);

        switch (i->type) {

        case CREATE_FILE:
        case TRUNCATE_FILE:
        case CREATE_DIRECTORY:
        case CREATE_FIFO:
        case CREATE_SYMLINK:
        case CREATE_CHAR_DEVICE:
        case CREATE_BLOCK_DEVICE:
        case IGNORE_PATH:
        case IGNORE_DIRECTORY_PATH:
        case ADJUST_MODE:
        case RELABEL_PATH:
        case RECURSIVE_RELABEL_PATH:
        case WRITE_FILE:
        case COPY_FILES:
                break;

        case REMOVE_PATH:
        case TRUNCATE_DIRECTORY:
        case RECURSIVE_REMOVE_PATH:
                r = glob_item(i, remove_item_instance);
                break;
        }

        return r;
}

static int clean_item_instance(Item *i, const char* instance) {
        _cleanup_closedir_ DIR *d = NULL;
        struct stat s, ps;
        bool mountpoint;
        int r;
        usec_t cutoff, n;

        assert(i);

        if (!i->age_set)
                return 0;

        n = now(CLOCK_REALTIME);
        if (n < i->age)
                return 0;

        cutoff = n - i->age;

        d = opendir(instance);
        if (!d) {
                if (errno == ENOENT || errno == ENOTDIR)
                        return 0;

                log_error("Failed to open directory %s: %m", i->path);
                return -errno;
        }

        if (fstat(dirfd(d), &s) < 0) {
                log_error("stat(%s) failed: %m", i->path);
                return -errno;
        }

        if (!S_ISDIR(s.st_mode)) {
                log_error("%s is not a directory.", i->path);
                return -ENOTDIR;
        }

        if (fstatat(dirfd(d), "..", &ps, AT_SYMLINK_NOFOLLOW) != 0) {
                log_error("stat(%s/..) failed: %m", i->path);
                return -errno;
        }

        mountpoint = s.st_dev != ps.st_dev ||
                     (s.st_dev == ps.st_dev && s.st_ino == ps.st_ino);

        r = dir_cleanup(i, instance, d, &s, cutoff, s.st_dev, mountpoint,
                        MAX_DEPTH, i->keep_first_level);
        return r;
}

static int clean_item(Item *i) {
        int r = 0;

        assert(i);

        switch (i->type) {
        case CREATE_DIRECTORY:
        case TRUNCATE_DIRECTORY:
        case IGNORE_PATH:
        case COPY_FILES:
                clean_item_instance(i, i->path);
                break;
        case IGNORE_DIRECTORY_PATH:
                r = glob_item(i, clean_item_instance);
                break;
        default:
                break;
        }

        return r;
}

static int process_item(Item *i) {
        int r, q, p;
        char prefix[PATH_MAX];

        assert(i);

        if (i->done)
                return 0;

        i->done = true;

        PATH_FOREACH_PREFIX(prefix, i->path) {
                Item *j;

                j = hashmap_get(items, prefix);
                if (j)
                        process_item(j);
        }

        r = arg_create ? create_item(i) : 0;
        q = arg_remove ? remove_item(i) : 0;
        p = arg_clean ? clean_item(i) : 0;

        if (r < 0)
                return r;

        if (q < 0)
                return q;

        return p;
}

static void item_free(Item *i) {

        if (!i)
                return;

        free(i->path);
        free(i->argument);
        free(i);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Item*, item_free);

static bool item_equal(Item *a, Item *b) {
        assert(a);
        assert(b);

        if (!streq_ptr(a->path, b->path))
                return false;

        if (a->type != b->type)
                return false;

        if (a->uid_set != b->uid_set ||
            (a->uid_set && a->uid != b->uid))
            return false;

        if (a->gid_set != b->gid_set ||
            (a->gid_set && a->gid != b->gid))
            return false;

        if (a->mode_set != b->mode_set ||
            (a->mode_set && a->mode != b->mode))
            return false;

        if (a->age_set != b->age_set ||
            (a->age_set && a->age != b->age))
            return false;

        if ((a->type == CREATE_FILE ||
             a->type == TRUNCATE_FILE ||
             a->type == WRITE_FILE ||
             a->type == CREATE_SYMLINK ||
             a->type == COPY_FILES) &&
            !streq_ptr(a->argument, b->argument))
                return false;

        if ((a->type == CREATE_CHAR_DEVICE ||
             a->type == CREATE_BLOCK_DEVICE) &&
            a->major_minor != b->major_minor)
                return false;

        return true;
}

static bool should_include_path(const char *path) {
        char **prefix;

        STRV_FOREACH(prefix, arg_exclude_prefixes)
                if (path_startswith(path, *prefix))
                        return false;

        STRV_FOREACH(prefix, arg_include_prefixes)
                if (path_startswith(path, *prefix))
                        return true;

        /* no matches, so we should include this path only if we
         * have no whitelist at all */
        return strv_length(arg_include_prefixes) == 0;
}

static int parse_line(const char *fname, unsigned line, const char *buffer) {

        static const Specifier specifier_table[] = {
                { 'm', specifier_machine_id, NULL },
                { 'b', specifier_boot_id, NULL },
                { 'H', specifier_host_name, NULL },
                { 'v', specifier_kernel_release, NULL },
                {}
        };

        _cleanup_free_ char *action = NULL, *mode = NULL, *user = NULL, *group = NULL, *age = NULL, *path = NULL;
        _cleanup_(item_freep) Item *i = NULL;
        Item *existing;
        char type;
        Hashmap *h;
        int r, n = -1;

        assert(fname);
        assert(line >= 1);
        assert(buffer);

        r = sscanf(buffer,
                   "%ms %ms %ms %ms %ms %ms %n",
                   &action,
                   &path,
                   &mode,
                   &user,
                   &group,
                   &age,
                   &n);
        if (r < 2) {
                log_error("[%s:%u] Syntax error.", fname, line);
                return -EIO;
        }

        if (isempty(action)) {
                log_error("[%s:%u] Command too short '%s'.", fname, line, action);
                return -EINVAL;
        }

        if (strlen(action) > 1 && !in_charset(action+1, "!+")) {
                log_error("[%s:%u] Unknown modifiers in command '%s'", fname, line, action);
                return -EINVAL;
        }

        if (strchr(action+1, '!') && !arg_boot)
                return 0;

        type = action[0];

        i = new0(Item, 1);
        if (!i)
                return log_oom();

        i->force = !!strchr(action+1, '+');

        r = specifier_printf(path, specifier_table, NULL, &i->path);
        if (r < 0) {
                log_error("[%s:%u] Failed to replace specifiers: %s", fname, line, path);
                return r;
        }

        if (n >= 0)  {
                n += strspn(buffer+n, WHITESPACE);
                if (buffer[n] != 0 && (buffer[n] != '-' || buffer[n+1] != 0)) {
                        i->argument = unquote(buffer+n, "\"");
                        if (!i->argument)
                                return log_oom();
                }
        }

        switch (type) {

        case CREATE_FILE:
        case TRUNCATE_FILE:
        case CREATE_DIRECTORY:
        case TRUNCATE_DIRECTORY:
        case CREATE_FIFO:
        case IGNORE_PATH:
        case IGNORE_DIRECTORY_PATH:
        case REMOVE_PATH:
        case RECURSIVE_REMOVE_PATH:
        case ADJUST_MODE:
        case RELABEL_PATH:
        case RECURSIVE_RELABEL_PATH:
                break;

        case CREATE_SYMLINK:
                if (!i->argument) {
                        i->argument = strappend("/usr/share/factory", i->path);
                        if (!i->argument)
                                return log_oom();
                }
                break;

        case WRITE_FILE:
                if (!i->argument) {
                        log_error("[%s:%u] Write file requires argument.", fname, line);
                        return -EBADMSG;
                }
                break;

        case COPY_FILES:
                if (!i->argument) {
                        i->argument = strappend("/usr/share/factory", i->path);
                        if (!i->argument)
                                return log_oom();
                }

                if (!path_is_absolute(i->argument)) {
                        log_error("[%s:%u] Source path is not absolute.", fname, line);
                        return -EBADMSG;
                }

                path_kill_slashes(i->argument);
                break;

        case CREATE_CHAR_DEVICE:
        case CREATE_BLOCK_DEVICE: {
                unsigned major, minor;

                if (!i->argument) {
                        log_error("[%s:%u] Device file requires argument.", fname, line);
                        return -EBADMSG;
                }

                if (sscanf(i->argument, "%u:%u", &major, &minor) != 2) {
                        log_error("[%s:%u] Can't parse device file major/minor '%s'.", fname, line, i->argument);
                        return -EBADMSG;
                }

                i->major_minor = makedev(major, minor);
                break;
        }

        default:
                log_error("[%s:%u] Unknown command type '%c'.", fname, line, type);
                return -EBADMSG;
        }

        i->type = type;

        if (!path_is_absolute(i->path)) {
                log_error("[%s:%u] Path '%s' not absolute.", fname, line, i->path);
                return -EBADMSG;
        }

        path_kill_slashes(i->path);

        if (!should_include_path(i->path))
                return 0;

        if (arg_root) {
                char *p;

                p = strappend(arg_root, i->path);
                if (!p)
                        return log_oom();

                free(i->path);
                i->path = p;
        }

        if (user && !streq(user, "-")) {
                const char *u = user;

                r = get_user_creds(&u, &i->uid, NULL, NULL, NULL);
                if (r < 0) {
                        log_error("[%s:%u] Unknown user '%s'.", fname, line, user);
                        return r;
                }

                i->uid_set = true;
        }

        if (group && !streq(group, "-")) {
                const char *g = group;

                r = get_group_creds(&g, &i->gid);
                if (r < 0) {
                        log_error("[%s:%u] Unknown group '%s'.", fname, line, group);
                        return r;
                }

                i->gid_set = true;
        }

        if (mode && !streq(mode, "-")) {
                const char *mm = mode;
                unsigned m;

                if (*mm == '~') {
                        i->mask_perms = true;
                        mm++;
                }

                if (sscanf(mm, "%o", &m) != 1) {
                        log_error("[%s:%u] Invalid mode '%s'.", fname, line, mode);
                        return -ENOENT;
                }

                i->mode = m;
                i->mode_set = true;
        } else
                i->mode =
                        i->type == CREATE_DIRECTORY ||
                        i->type == TRUNCATE_DIRECTORY ? 0755 : 0644;

        if (age && !streq(age, "-")) {
                const char *a = age;

                if (*a == '~') {
                        i->keep_first_level = true;
                        a++;
                }

                if (parse_sec(a, &i->age) < 0) {
                        log_error("[%s:%u] Invalid age '%s'.", fname, line, age);
                        return -EBADMSG;
                }

                i->age_set = true;
        }

        h = needs_glob(i->type) ? globs : items;

        existing = hashmap_get(h, i->path);
        if (existing) {

                /* Two identical items are fine */
                if (!item_equal(existing, i))
                        log_warning("Two or more conflicting lines for %s configured, ignoring.", i->path);

                return 0;
        }

        r = hashmap_put(h, i->path, i);
        if (r < 0) {
                log_error("Failed to insert item %s: %s", i->path, strerror(-r));
                return r;
        }

        i = NULL; /* avoid cleanup */

        return 0;
}

static int help(void) {

        printf("%s [OPTIONS...] [CONFIGURATION FILE...]\n\n"
               "Creates, deletes and cleans up volatile and temporary files and directories.\n\n"
               "  -h --help                 Show this help\n"
               "     --version              Show package version\n"
               "     --create               Create marked files/directories\n"
               "     --clean                Clean up marked directories\n"
               "     --remove               Remove marked files/directories\n"
               "     --boot                 Execute actions only safe at boot\n"
               "     --prefix=PATH          Only apply rules that apply to paths with the specified prefix\n"
               "     --exclude-prefix=PATH  Ignore rules that apply to paths with the specified prefix\n"
               "     --root=PATH            Operate on an alternate filesystem root\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_CREATE,
                ARG_CLEAN,
                ARG_REMOVE,
                ARG_BOOT,
                ARG_PREFIX,
                ARG_EXCLUDE_PREFIX,
                ARG_ROOT,
        };

        static const struct option options[] = {
                { "help",           no_argument,         NULL, 'h'                },
                { "version",        no_argument,         NULL, ARG_VERSION        },
                { "create",         no_argument,         NULL, ARG_CREATE         },
                { "clean",          no_argument,         NULL, ARG_CLEAN          },
                { "remove",         no_argument,         NULL, ARG_REMOVE         },
                { "boot",           no_argument,         NULL, ARG_BOOT           },
                { "prefix",         required_argument,   NULL, ARG_PREFIX         },
                { "exclude-prefix", required_argument,   NULL, ARG_EXCLUDE_PREFIX },
                { "root",           required_argument,   NULL, ARG_ROOT           },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case ARG_CREATE:
                        arg_create = true;
                        break;

                case ARG_CLEAN:
                        arg_clean = true;
                        break;

                case ARG_REMOVE:
                        arg_remove = true;
                        break;

                case ARG_BOOT:
                        arg_boot = true;
                        break;

                case ARG_PREFIX:
                        if (strv_push(&arg_include_prefixes, optarg) < 0)
                                return log_oom();
                        break;

                case ARG_EXCLUDE_PREFIX:
                        if (strv_push(&arg_exclude_prefixes, optarg) < 0)
                                return log_oom();
                        break;

                case ARG_ROOT:
                        free(arg_root);
                        arg_root = path_make_absolute_cwd(optarg);
                        if (!arg_root)
                                return log_oom();

                        path_kill_slashes(arg_root);
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }
        }

        if (!arg_clean && !arg_create && !arg_remove) {
                log_error("You need to specify at least one of --clean, --create or --remove.");
                return -EINVAL;
        }

        return 1;
}

static int read_config_file(const char *fn, bool ignore_enoent) {
        _cleanup_fclose_ FILE *f = NULL;
        char line[LINE_MAX];
        Iterator iterator;
        unsigned v = 0;
        Item *i;
        int r;

        assert(fn);

        r = search_and_fopen_nulstr(fn, "re", arg_root, conf_file_dirs, &f);
        if (r < 0) {
                if (ignore_enoent && r == -ENOENT)
                        return 0;

                log_error("Failed to open '%s', ignoring: %s", fn, strerror(-r));
                return r;
        }

        FOREACH_LINE(line, f, break) {
                char *l;
                int k;

                v++;

                l = strstrip(line);
                if (*l == '#' || *l == 0)
                        continue;

                k = parse_line(fn, v, l);
                if (k < 0 && r == 0)
                        r = k;
        }

        /* we have to determine age parameter for each entry of type X */
        HASHMAP_FOREACH(i, globs, iterator) {
                Iterator iter;
                Item *j, *candidate_item = NULL;

                if (i->type != IGNORE_DIRECTORY_PATH)
                        continue;

                HASHMAP_FOREACH(j, items, iter) {
                        if (j->type != CREATE_DIRECTORY && j->type != TRUNCATE_DIRECTORY)
                                continue;

                        if (path_equal(j->path, i->path)) {
                                candidate_item = j;
                                break;
                        }

                        if ((!candidate_item && path_startswith(i->path, j->path)) ||
                            (candidate_item && path_startswith(j->path, candidate_item->path) && (fnmatch(i->path, j->path, FNM_PATHNAME | FNM_PERIOD) == 0)))
                                candidate_item = j;
                }

                if (candidate_item) {
                        i->age = candidate_item->age;
                        i->age_set = true;
                }
        }

        if (ferror(f)) {
                log_error("Failed to read from file %s: %m", fn);
                if (r == 0)
                        r = -EIO;
        }

        return r;
}

int main(int argc, char *argv[]) {
        int r, k;
        Item *i;
        Iterator iterator;

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        label_init(NULL);

        items = hashmap_new(string_hash_func, string_compare_func);
        globs = hashmap_new(string_hash_func, string_compare_func);

        if (!items || !globs) {
                r = log_oom();
                goto finish;
        }

        r = 0;

        if (optind < argc) {
                int j;

                for (j = optind; j < argc; j++) {
                        k = read_config_file(argv[j], false);
                        if (k < 0 && r == 0)
                                r = k;
                }

        } else {
                _cleanup_strv_free_ char **files = NULL;
                char **f;

                r = conf_files_list_nulstr(&files, ".conf", arg_root, conf_file_dirs);
                if (r < 0) {
                        log_error("Failed to enumerate tmpfiles.d files: %s", strerror(-r));
                        goto finish;
                }

                STRV_FOREACH(f, files) {
                        k = read_config_file(*f, true);
                        if (k < 0 && r == 0)
                                r = k;
                }
        }

        HASHMAP_FOREACH(i, globs, iterator)
                process_item(i);

        HASHMAP_FOREACH(i, items, iterator)
                process_item(i);

finish:
        while ((i = hashmap_steal_first(items)))
                item_free(i);

        while ((i = hashmap_steal_first(globs)))
                item_free(i);

        hashmap_free(items);
        hashmap_free(globs);

        free(arg_include_prefixes);
        free(arg_exclude_prefixes);
        free(arg_root);

        set_free_free(unix_sockets);

        label_finish();

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
