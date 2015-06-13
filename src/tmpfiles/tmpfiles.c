/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering, Kay Sievers
  Copyright 2015 Zbigniew Jędrzejewski-Szmek

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
#include <limits.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <getopt.h>
#include <stdbool.h>
#include <time.h>
#include <glob.h>
#include <fnmatch.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <linux/fs.h>

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
#include "rm-rf.h"
#include "selinux-util.h"
#include "btrfs-util.h"
#include "acl-util.h"
#include "formats-util.h"

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
        CREATE_SUBVOLUME = 'v',
        CREATE_FIFO = 'p',
        CREATE_SYMLINK = 'L',
        CREATE_CHAR_DEVICE = 'c',
        CREATE_BLOCK_DEVICE = 'b',
        COPY_FILES = 'C',

        /* These ones take globs */
        WRITE_FILE = 'w',
        SET_XATTR = 't',
        RECURSIVE_SET_XATTR = 'T',
        SET_ACL = 'a',
        RECURSIVE_SET_ACL = 'A',
        SET_ATTRIBUTE = 'h',
        RECURSIVE_SET_ATTRIBUTE = 'H',
        IGNORE_PATH = 'x',
        IGNORE_DIRECTORY_PATH = 'X',
        REMOVE_PATH = 'r',
        RECURSIVE_REMOVE_PATH = 'R',
        RELABEL_PATH = 'z',
        RECURSIVE_RELABEL_PATH = 'Z',
        ADJUST_MODE = 'm', /* legacy, 'z' is identical to this */
} ItemType;

typedef struct Item {
        ItemType type;

        char *path;
        char *argument;
        char **xattrs;
#ifdef HAVE_ACL
        acl_t acl_access;
        acl_t acl_default;
#endif
        uid_t uid;
        gid_t gid;
        mode_t mode;
        usec_t age;

        dev_t major_minor;
        unsigned attribute_value;
        unsigned attribute_mask;

        bool uid_set:1;
        bool gid_set:1;
        bool mode_set:1;
        bool age_set:1;
        bool mask_perms:1;
        bool attribute_set:1;

        bool keep_first_level:1;

        bool force:1;

        bool done:1;
} Item;

typedef struct ItemArray {
        Item *items;
        size_t count;
        size_t size;
} ItemArray;

static bool arg_create = false;
static bool arg_clean = false;
static bool arg_remove = false;
static bool arg_boot = false;

static char **arg_include_prefixes = NULL;
static char **arg_exclude_prefixes = NULL;
static char *arg_root = NULL;

static const char conf_file_dirs[] = CONF_DIRS_NULSTR("tmpfiles");

#define MAX_DEPTH 256

static OrderedHashmap *items = NULL, *globs = NULL;
static Set *unix_sockets = NULL;

static const Specifier specifier_table[] = {
        { 'm', specifier_machine_id, NULL },
        { 'b', specifier_boot_id, NULL },
        { 'H', specifier_host_name, NULL },
        { 'v', specifier_kernel_release, NULL },
        {}
};

static bool needs_glob(ItemType t) {
        return IN_SET(t,
                      WRITE_FILE,
                      IGNORE_PATH,
                      IGNORE_DIRECTORY_PATH,
                      REMOVE_PATH,
                      RECURSIVE_REMOVE_PATH,
                      ADJUST_MODE,
                      RELABEL_PATH,
                      RECURSIVE_RELABEL_PATH,
                      SET_XATTR,
                      RECURSIVE_SET_XATTR,
                      SET_ACL,
                      RECURSIVE_SET_ACL,
                      SET_ATTRIBUTE,
                      RECURSIVE_SET_ATTRIBUTE);
}

static bool takes_ownership(ItemType t) {
        return IN_SET(t,
                      CREATE_FILE,
                      TRUNCATE_FILE,
                      CREATE_DIRECTORY,
                      TRUNCATE_DIRECTORY,
                      CREATE_SUBVOLUME,
                      CREATE_FIFO,
                      CREATE_SYMLINK,
                      CREATE_CHAR_DEVICE,
                      CREATE_BLOCK_DEVICE,
                      COPY_FILES,
                      WRITE_FILE,
                      IGNORE_PATH,
                      IGNORE_DIRECTORY_PATH,
                      REMOVE_PATH,
                      RECURSIVE_REMOVE_PATH);
}

static struct Item* find_glob(OrderedHashmap *h, const char *match) {
        ItemArray *j;
        Iterator i;

        ORDERED_HASHMAP_FOREACH(j, h, i) {
                unsigned n;

                for (n = 0; n < j->count; n++) {
                        Item *item = j->items + n;

                        if (fnmatch(item->path, match, FNM_PATHNAME|FNM_PERIOD) == 0)
                                return item;
                }
        }

        return NULL;
}

static void load_unix_sockets(void) {
        _cleanup_fclose_ FILE *f = NULL;
        char line[LINE_MAX];

        if (unix_sockets)
                return;

        /* We maintain a cache of the sockets we found in
         * /proc/net/unix to speed things up a little. */

        unix_sockets = set_new(&string_hash_ops);
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

        union file_handle_union h = FILE_HANDLE_INIT;
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
        if (r_p == -ENOSYS || r_p == -EOPNOTSUPP || r == -ENOSYS || r == -EOPNOTSUPP)
                return true;

        /* return error */
        if (r_p < 0)
                return r_p;
        return r;
}

static DIR* xopendirat_nomod(int dirfd, const char *path) {
        DIR *dir;

        dir = xopendirat(dirfd, path, O_NOFOLLOW|O_NOATIME);
        if (dir)
                return dir;

        log_debug_errno(errno, "Cannot open %sdirectory \"%s\": %m", dirfd == AT_FDCWD ? "" : "sub", path);
        if (errno != EPERM)
                return NULL;

        dir = xopendirat(dirfd, path, O_NOFOLLOW);
        if (!dir)
                log_debug_errno(errno, "Cannot open %sdirectory \"%s\": %m", dirfd == AT_FDCWD ? "" : "sub", path);

        return dir;
}

static DIR* opendir_nomod(const char *path) {
        return xopendirat_nomod(AT_FDCWD, path);
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

                if (STR_IN_SET(dent->d_name, ".", ".."))
                        continue;

                if (fstatat(dirfd(d), dent->d_name, &s, AT_SYMLINK_NOFOLLOW) < 0) {
                        if (errno == ENOENT)
                                continue;

                        /* FUSE, NFS mounts, SELinux might return EACCES */
                        if (errno == EACCES)
                                log_debug_errno(errno, "stat(%s/%s) failed: %m", p, dent->d_name);
                        else
                                log_error_errno(errno, "stat(%s/%s) failed: %m", p, dent->d_name);
                        r = -errno;
                        continue;
                }

                /* Stay on the same filesystem */
                if (s.st_dev != rootdev) {
                        log_debug("Ignoring \"%s/%s\": different filesystem.", p, dent->d_name);
                        continue;
                }

                /* Try to detect bind mounts of the same filesystem instance; they
                 * do not differ in device major/minors. This type of query is not
                 * supported on all kernels or filesystem types though. */
                if (S_ISDIR(s.st_mode) && dir_is_mount_point(d, dent->d_name) > 0) {
                        log_debug("Ignoring \"%s/%s\": different mount of the same filesystem.",
                                  p, dent->d_name);
                        continue;
                }

                /* Do not delete read-only files owned by root */
                if (s.st_uid == 0 && !(s.st_mode & S_IWUSR)) {
                        log_debug("Ignoring \"%s/%s\": read-only and owner by root.", p, dent->d_name);
                        continue;
                }

                sub_path = strjoin(p, "/", dent->d_name, NULL);
                if (!sub_path) {
                        r = log_oom();
                        goto finish;
                }

                /* Is there an item configured for this path? */
                if (ordered_hashmap_get(items, sub_path)) {
                        log_debug("Ignoring \"%s\": a separate entry exists.", sub_path);
                        continue;
                }

                if (find_glob(globs, sub_path)) {
                        log_debug("Ignoring \"%s\": a separate glob exists.", sub_path);
                        continue;
                }

                if (S_ISDIR(s.st_mode)) {

                        if (mountpoint &&
                            streq(dent->d_name, "lost+found") &&
                            s.st_uid == 0) {
                                log_debug("Ignoring \"%s\".", sub_path);
                                continue;
                        }

                        if (maxdepth <= 0)
                                log_warning("Reached max depth on \"%s\".", sub_path);
                        else {
                                _cleanup_closedir_ DIR *sub_dir;
                                int q;

                                sub_dir = xopendirat_nomod(dirfd(d), dent->d_name);
                                if (!sub_dir) {
                                        if (errno != ENOENT)
                                                r = log_error_errno(errno, "opendir(%s) failed: %m", sub_path);

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

                        if (keep_this_level) {
                                log_debug("Keeping \"%s\".", sub_path);
                                continue;
                        }

                        /* Ignore ctime, we change it when deleting */
                        age = timespec_load(&s.st_mtim);
                        if (age >= cutoff) {
                                char a[FORMAT_TIMESTAMP_MAX];
                                /* Follows spelling in stat(1). */
                                log_debug("Directory \"%s\": modify time %s is too new.",
                                          sub_path,
                                          format_timestamp_us(a, sizeof(a), age));
                                continue;
                        }

                        age = timespec_load(&s.st_atim);
                        if (age >= cutoff) {
                                char a[FORMAT_TIMESTAMP_MAX];
                                log_debug("Directory \"%s\": access time %s is too new.",
                                          sub_path,
                                          format_timestamp_us(a, sizeof(a), age));
                                continue;
                        }

                        log_debug("Removing directory \"%s\".", sub_path);
                        if (unlinkat(dirfd(d), dent->d_name, AT_REMOVEDIR) < 0)
                                if (errno != ENOENT && errno != ENOTEMPTY) {
                                        log_error_errno(errno, "rmdir(%s): %m", sub_path);
                                        r = -errno;
                                }

                } else {
                        /* Skip files for which the sticky bit is
                         * set. These are semantics we define, and are
                         * unknown elsewhere. See XDG_RUNTIME_DIR
                         * specification for details. */
                        if (s.st_mode & S_ISVTX) {
                                log_debug("Skipping \"%s\": sticky bit set.", sub_path);
                                continue;
                        }

                        if (mountpoint && S_ISREG(s.st_mode))
                                if (s.st_uid == 0 && STR_IN_SET(dent->d_name,
                                                                ".journal",
                                                                "aquota.user",
                                                                "aquota.group")) {
                                        log_debug("Skipping \"%s\".", sub_path);
                                        continue;
                                }

                        /* Ignore sockets that are listed in /proc/net/unix */
                        if (S_ISSOCK(s.st_mode) && unix_socket_alive(sub_path)) {
                                log_debug("Skipping \"%s\": live socket.", sub_path);
                                continue;
                        }

                        /* Ignore device nodes */
                        if (S_ISCHR(s.st_mode) || S_ISBLK(s.st_mode)) {
                                log_debug("Skipping \"%s\": a device.", sub_path);
                                continue;
                        }

                        /* Keep files on this level around if this is
                         * requested */
                        if (keep_this_level) {
                                log_debug("Keeping \"%s\".", sub_path);
                                continue;
                        }

                        age = timespec_load(&s.st_mtim);
                        if (age >= cutoff) {
                                char a[FORMAT_TIMESTAMP_MAX];
                                /* Follows spelling in stat(1). */
                                log_debug("File \"%s\": modify time %s is too new.",
                                          sub_path,
                                          format_timestamp_us(a, sizeof(a), age));
                                continue;
                        }

                        age = timespec_load(&s.st_atim);
                        if (age >= cutoff) {
                                char a[FORMAT_TIMESTAMP_MAX];
                                log_debug("File \"%s\": access time %s is too new.",
                                          sub_path,
                                          format_timestamp_us(a, sizeof(a), age));
                                continue;
                        }

                        age = timespec_load(&s.st_ctim);
                        if (age >= cutoff) {
                                char a[FORMAT_TIMESTAMP_MAX];
                                log_debug("File \"%s\": change time %s is too new.",
                                          sub_path,
                                          format_timestamp_us(a, sizeof(a), age));
                                continue;
                        }

                        log_debug("unlink \"%s\"", sub_path);

                        if (unlinkat(dirfd(d), dent->d_name, 0) < 0)
                                if (errno != ENOENT)
                                        r = log_error_errno(errno, "unlink(%s): %m", sub_path);

                        deleted = true;
                }
        }

finish:
        if (deleted) {
                usec_t age1, age2;
                char a[FORMAT_TIMESTAMP_MAX], b[FORMAT_TIMESTAMP_MAX];

                /* Restore original directory timestamps */
                times[0] = ds->st_atim;
                times[1] = ds->st_mtim;

                age1 = timespec_load(&ds->st_atim);
                age2 = timespec_load(&ds->st_mtim);
                log_debug("Restoring access and modification time on \"%s\": %s, %s",
                          p,
                          format_timestamp_us(a, sizeof(a), age1),
                          format_timestamp_us(b, sizeof(b), age2));
                if (futimens(dirfd(d), times) < 0)
                        log_error_errno(errno, "utimensat(%s): %m", p);
        }

        return r;
}

static int path_set_perms(Item *i, const char *path) {
        _cleanup_close_ int fd = -1;
        struct stat st;

        assert(i);
        assert(path);

        /* We open the file with O_PATH here, to make the operation
         * somewhat atomic. Also there's unfortunately no fchmodat()
         * with AT_SYMLINK_NOFOLLOW, hence we emulate it here via
         * O_PATH. */

        fd = open(path, O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_PATH|O_NOATIME);
        if (fd < 0)
                return log_error_errno(errno, "Adjusting owner and mode for %s failed: %m", path);

        if (fstatat(fd, "", &st, AT_EMPTY_PATH) < 0)
                return log_error_errno(errno, "Failed to fstat() file %s: %m", path);

        if (S_ISLNK(st.st_mode))
                log_debug("Skipping mode an owner fix for symlink %s.", path);
        else {
                char fn[strlen("/proc/self/fd/") + DECIMAL_STR_MAX(int)];
                xsprintf(fn, "/proc/self/fd/%i", fd);

                /* not using i->path directly because it may be a glob */
                if (i->mode_set) {
                        mode_t m = i->mode;

                        if (i->mask_perms) {
                                if (!(st.st_mode & 0111))
                                        m &= ~0111;
                                if (!(st.st_mode & 0222))
                                m &= ~0222;
                                if (!(st.st_mode & 0444))
                                        m &= ~0444;
                                if (!S_ISDIR(st.st_mode))
                                        m &= ~07000; /* remove sticky/sgid/suid bit, unless directory */
                        }

                        if (m == (st.st_mode & 07777))
                                log_debug("\"%s\" has right mode %o", path, st.st_mode);
                        else {
                                log_debug("chmod \"%s\" to mode %o", path, m);
                                if (chmod(fn, m) < 0)
                                        return log_error_errno(errno, "chmod(%s) failed: %m", path);
                        }
                }

                if ((i->uid != st.st_uid || i->gid != st.st_gid) &&
                    (i->uid_set || i->gid_set)) {
                        log_debug("chown \"%s\" to "UID_FMT"."GID_FMT,
                                  path,
                                  i->uid_set ? i->uid : UID_INVALID,
                                  i->gid_set ? i->gid : GID_INVALID);
                        if (chown(fn,
                                  i->uid_set ? i->uid : UID_INVALID,
                                  i->gid_set ? i->gid : GID_INVALID) < 0)
                        return log_error_errno(errno, "chown(%s) failed: %m", path);
                }
        }

        fd = safe_close(fd);

        return label_fix(path, false, false);
}

static int parse_xattrs_from_arg(Item *i) {
        const char *p;
        int r;

        assert(i);
        assert(i->argument);

        p = i->argument;

        for (;;) {
                _cleanup_free_ char *name = NULL, *value = NULL, *xattr = NULL, *xattr_replaced = NULL;

                r = unquote_first_word(&p, &xattr, UNQUOTE_CUNESCAPE);
                if (r < 0)
                        log_warning_errno(r, "Failed to parse extended attribute '%s', ignoring: %m", p);
                if (r <= 0)
                        break;

                r = specifier_printf(xattr, specifier_table, NULL, &xattr_replaced);
                if (r < 0)
                        return log_error_errno(r, "Failed to replace specifiers in extended attribute '%s': %m", xattr);

                r = split_pair(xattr_replaced, "=", &name, &value);
                if (r < 0) {
                        log_warning_errno(r, "Failed to parse extended attribute, ignoring: %s", xattr);
                        continue;
                }

                if (isempty(name) || isempty(value)) {
                        log_warning("Malformed extended attribute found, ignoring: %s", xattr);
                        continue;
                }

                if (strv_push_pair(&i->xattrs, name, value) < 0)
                        return log_oom();

                name = value = NULL;
        }

        return 0;
}

static int path_set_xattrs(Item *i, const char *path) {
        char **name, **value;

        assert(i);
        assert(path);

        STRV_FOREACH_PAIR(name, value, i->xattrs) {
                int n;

                n = strlen(*value);
                log_debug("Setting extended attribute '%s=%s' on %s.", *name, *value, path);
                if (lsetxattr(path, *name, *value, n, 0) < 0) {
                        log_error("Setting extended attribute %s=%s on %s failed: %m", *name, *value, path);
                        return -errno;
                }
        }
        return 0;
}

static int parse_acls_from_arg(Item *item) {
#ifdef HAVE_ACL
        int r;

        assert(item);

        /* If force (= modify) is set, we will not modify the acl
         * afterwards, so the mask can be added now if necessary. */

        r = parse_acl(item->argument, &item->acl_access, &item->acl_default, !item->force);
        if (r < 0)
                log_warning_errno(r, "Failed to parse ACL \"%s\": %m. Ignoring", item->argument);
#else
        log_warning_errno(ENOSYS, "ACLs are not supported. Ignoring");
#endif

        return 0;
}

#ifdef HAVE_ACL
static int path_set_acl(const char *path, const char *pretty, acl_type_t type, acl_t acl, bool modify) {
        _cleanup_(acl_free_charpp) char *t = NULL;
        _cleanup_(acl_freep) acl_t dup = NULL;
        int r;

        /* Returns 0 for success, positive error if already warned,
         * negative error otherwise. */

        if (modify) {
                r = acls_for_file(path, type, acl, &dup);
                if (r < 0)
                        return r;

                r = calc_acl_mask_if_needed(&dup);
                if (r < 0)
                        return r;
        } else {
                dup = acl_dup(acl);
                if (!dup)
                        return -errno;

                /* the mask was already added earlier if needed */
        }

        r = add_base_acls_if_needed(&dup, path);
        if (r < 0)
                return r;

        t = acl_to_any_text(dup, NULL, ',', TEXT_ABBREVIATE);
        log_debug("Setting %s ACL %s on %s.",
                  type == ACL_TYPE_ACCESS ? "access" : "default",
                  strna(t), pretty);

        r = acl_set_file(path, type, dup);
        if (r < 0)
                /* Return positive to indicate we already warned */
                return -log_error_errno(errno,
                                        "Setting %s ACL \"%s\" on %s failed: %m",
                                        type == ACL_TYPE_ACCESS ? "access" : "default",
                                        strna(t), pretty);

        return 0;
}
#endif

static int path_set_acls(Item *item, const char *path) {
        int r = 0;
#ifdef HAVE_ACL
        char fn[strlen("/proc/self/fd/") + DECIMAL_STR_MAX(int)];
        _cleanup_close_ int fd = -1;
        struct stat st;

        assert(item);
        assert(path);

        fd = open(path, O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_PATH|O_NOATIME);
        if (fd < 0)
                return log_error_errno(errno, "Adjusting ACL of %s failed: %m", path);

        if (fstatat(fd, "", &st, AT_EMPTY_PATH) < 0)
                return log_error_errno(errno, "Failed to fstat() file %s: %m", path);

        if (S_ISLNK(st.st_mode)) {
                log_debug("Skipping ACL fix for symlink %s.", path);
                return 0;
        }

        xsprintf(fn, "/proc/self/fd/%i", fd);

        if (item->acl_access)
                r = path_set_acl(fn, path, ACL_TYPE_ACCESS, item->acl_access, item->force);

        if (r == 0 && item->acl_default)
                r = path_set_acl(fn, path, ACL_TYPE_DEFAULT, item->acl_default, item->force);

        if (r > 0)
                return -r; /* already warned */
        else if (r == -EOPNOTSUPP) {
                log_debug_errno(r, "ACLs not supported by file system at %s", path);
                return 0;
        } else if (r < 0)
                log_error_errno(r, "ACL operation on \"%s\" failed: %m", path);
#endif
        return r;
}

#define ATTRIBUTES_ALL                          \
        (FS_NOATIME_FL      |                   \
         FS_SYNC_FL         |                   \
         FS_DIRSYNC_FL      |                   \
         FS_APPEND_FL       |                   \
         FS_COMPR_FL        |                   \
         FS_NODUMP_FL       |                   \
         FS_EXTENT_FL       |                   \
         FS_IMMUTABLE_FL    |                   \
         FS_JOURNAL_DATA_FL |                   \
         FS_SECRM_FL        |                   \
         FS_UNRM_FL         |                   \
         FS_NOTAIL_FL       |                   \
         FS_TOPDIR_FL       |                   \
         FS_NOCOW_FL)

static int parse_attribute_from_arg(Item *item) {

        static const struct {
                char character;
                unsigned value;
        } attributes[] = {
                { 'A', FS_NOATIME_FL },      /* do not update atime */
                { 'S', FS_SYNC_FL },         /* Synchronous updates */
                { 'D', FS_DIRSYNC_FL },      /* dirsync behaviour (directories only) */
                { 'a', FS_APPEND_FL },       /* writes to file may only append */
                { 'c', FS_COMPR_FL },        /* Compress file */
                { 'd', FS_NODUMP_FL },       /* do not dump file */
                { 'e', FS_EXTENT_FL },       /* Top of directory hierarchies*/
                { 'i', FS_IMMUTABLE_FL },    /* Immutable file */
                { 'j', FS_JOURNAL_DATA_FL }, /* Reserved for ext3 */
                { 's', FS_SECRM_FL },        /* Secure deletion */
                { 'u', FS_UNRM_FL },         /* Undelete */
                { 't', FS_NOTAIL_FL },       /* file tail should not be merged */
                { 'T', FS_TOPDIR_FL },       /* Top of directory hierarchies*/
                { 'C', FS_NOCOW_FL },        /* Do not cow file */
        };

        enum {
                MODE_ADD,
                MODE_DEL,
                MODE_SET
        } mode = MODE_ADD;

        unsigned value = 0, mask = 0;
        const char *p;

        assert(item);

        p = item->argument;
        if (p) {
                if (*p == '+') {
                        mode = MODE_ADD;
                        p++;
                } else if (*p == '-') {
                        mode = MODE_DEL;
                        p++;
                } else  if (*p == '=') {
                        mode = MODE_SET;
                        p++;
                }
        }

        if (isempty(p) && mode != MODE_SET) {
                log_error("Setting file attribute on '%s' needs an attribute specification.", item->path);
                return -EINVAL;
        }

        for (; p && *p ; p++) {
                unsigned i, v;

                for (i = 0; i < ELEMENTSOF(attributes); i++)
                        if (*p == attributes[i].character)
                                break;

                if (i >= ELEMENTSOF(attributes)) {
                        log_error("Unknown file attribute '%c' on '%s'.", *p, item->path);
                        return -EINVAL;
                }

                v = attributes[i].value;

                if (mode == MODE_ADD || mode == MODE_SET)
                        value |= v;
                else
                        value &= ~v;

                mask |= v;
        }

        if (mode == MODE_SET)
                mask |= ATTRIBUTES_ALL;

        assert(mask != 0);

        item->attribute_mask = mask;
        item->attribute_value = value;
        item->attribute_set = true;

        return 0;
}

static int path_set_attribute(Item *item, const char *path) {
        _cleanup_close_ int fd = -1;
        struct stat st;
        unsigned f;
        int r;

        if (!item->attribute_set || item->attribute_mask == 0)
                return 0;

        fd = open(path, O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_NOATIME|O_NOFOLLOW);
        if (fd < 0) {
                if (errno == ELOOP)
                        return log_error_errno(errno, "Skipping file attributes adjustment on symlink %s.", path);

                return log_error_errno(errno, "Cannot open '%s': %m", path);
        }

        if (fstat(fd, &st) < 0)
                return log_error_errno(errno, "Cannot stat '%s': %m", path);

        /* Issuing the file attribute ioctls on device nodes is not
         * safe, as that will be delivered to the drivers, not the
         * file system containing the device node. */
        if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)) {
                log_error("Setting file flags is only supported on regular files and directories, cannot set on '%s'.", path);
                return -EINVAL;
        }

        f = item->attribute_value & item->attribute_mask;

        /* Mask away directory-specific flags */
        if (!S_ISDIR(st.st_mode))
                f &= ~FS_DIRSYNC_FL;

        r = chattr_fd(fd, f, item->attribute_mask);
        if (r < 0)
                return log_error_errno(r,
                        "Cannot set file attribute for '%s', value=0x%08x, mask=0x%08x: %m",
                        path, item->attribute_value, item->attribute_mask);

        return 0;
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
                mac_selinux_create_file_prepare(path, S_IFREG);
                fd = open(path, flags|O_NDELAY|O_CLOEXEC|O_WRONLY|O_NOCTTY, i->mode);
                mac_selinux_create_file_clear();
        }

        if (fd < 0) {
                if (i->type == WRITE_FILE && errno == ENOENT) {
                        log_debug_errno(errno, "Not writing \"%s\": %m", path);
                        return 0;
                }

                r = -errno;
                if (!i->argument && errno == EROFS && stat(path, &st) == 0 &&
                    (i->type == CREATE_FILE || st.st_size == 0))
                        goto check_mode;

                return log_error_errno(r, "Failed to create file %s: %m", path);
        }

        if (i->argument) {
                _cleanup_free_ char *unescaped = NULL, *replaced = NULL;

                log_debug("%s to \"%s\".", i->type == CREATE_FILE ? "Appending" : "Writing", path);

                r = cunescape(i->argument, 0, &unescaped);
                if (r < 0)
                        return log_error_errno(r, "Failed to unescape parameter to write: %s", i->argument);

                r = specifier_printf(unescaped, specifier_table, NULL, &replaced);
                if (r < 0)
                        return log_error_errno(r, "Failed to replace specifiers in parameter to write '%s': %m", unescaped);

                r = loop_write(fd, replaced, strlen(replaced), false);
                if (r < 0)
                        return log_error_errno(r, "Failed to write file \"%s\": %m", path);
        } else
                log_debug("\"%s\" has been created.", path);

        fd = safe_close(fd);

        if (stat(path, &st) < 0)
                return log_error_errno(errno, "stat(%s) failed: %m", path);

 check_mode:
        if (!S_ISREG(st.st_mode)) {
                log_error("%s is not a file.", path);
                return -EEXIST;
        }

        r = path_set_perms(i, path);
        if (r < 0)
                return r;

        return 0;
}

typedef int (*action_t)(Item *, const char *);

static int item_do_children(Item *i, const char *path, action_t action) {
        _cleanup_closedir_ DIR *d;
        int r = 0;

        assert(i);
        assert(path);

        /* This returns the first error we run into, but nevertheless
         * tries to go on */

        d = opendir_nomod(path);
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

                if (STR_IN_SET(de->d_name, ".", ".."))
                        continue;

                p = strjoin(path, "/", de->d_name, NULL);
                if (!p)
                        return -ENOMEM;

                q = action(i, p);
                if (q < 0 && q != -ENOENT && r == 0)
                        r = q;

                if (IN_SET(de->d_type, DT_UNKNOWN, DT_DIR)) {
                        q = item_do_children(i, p, action);
                        if (q < 0 && r == 0)
                                r = q;
                }
        }

        return r;
}

static int glob_item(Item *i, action_t action, bool recursive) {
        _cleanup_globfree_ glob_t g = {
                .gl_closedir = (void (*)(void *)) closedir,
                .gl_readdir = (struct dirent *(*)(void *)) readdir,
                .gl_opendir = (void *(*)(const char *)) opendir_nomod,
                .gl_lstat = lstat,
                .gl_stat = stat,
        };
        int r = 0, k;
        char **fn;

        errno = 0;
        k = glob(i->path, GLOB_NOSORT|GLOB_BRACE|GLOB_ALTDIRFUNC, NULL, &g);
        if (k != 0 && k != GLOB_NOMATCH)
                return log_error_errno(errno ?: EIO, "glob(%s) failed: %m", i->path);

        STRV_FOREACH(fn, g.gl_pathv) {
                k = action(i, *fn);
                if (k < 0 && r == 0)
                        r = k;

                if (recursive) {
                        k = item_do_children(i, *fn, action);
                        if (k < 0 && r == 0)
                                r = k;
                }
        }

        return r;
}

typedef enum {
        CREATION_NORMAL,
        CREATION_EXISTING,
        CREATION_FORCE,
        _CREATION_MODE_MAX,
        _CREATION_MODE_INVALID = -1
} CreationMode;

static const char *creation_mode_verb_table[_CREATION_MODE_MAX] = {
        [CREATION_NORMAL] = "Created",
        [CREATION_EXISTING] = "Found existing",
        [CREATION_FORCE] = "Created replacement",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(creation_mode_verb, CreationMode);

static int create_item(Item *i) {
        _cleanup_free_ char *resolved = NULL;
        struct stat st;
        int r = 0;
        CreationMode creation;

        assert(i);

        log_debug("Running create action for entry %c %s", (char) i->type, i->path);

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

        case COPY_FILES: {
                r = specifier_printf(i->argument, specifier_table, NULL, &resolved);
                if (r < 0)
                        return log_error_errno(r, "Failed to substitute specifiers in copy source %s: %m", i->argument);

                log_debug("Copying tree \"%s\" to \"%s\".", resolved, i->path);
                r = copy_tree(resolved, i->path, false);

                if (r == -EROFS && stat(i->path, &st) == 0)
                        r = -EEXIST;

                if (r < 0) {
                        struct stat a, b;

                        if (r != -EEXIST)
                                return log_error_errno(r, "Failed to copy files to %s: %m", i->path);

                        if (stat(resolved, &a) < 0)
                                return log_error_errno(errno, "stat(%s) failed: %m", resolved);

                        if (stat(i->path, &b) < 0)
                                return log_error_errno(errno, "stat(%s) failed: %m", i->path);

                        if ((a.st_mode ^ b.st_mode) & S_IFMT) {
                                log_debug("Can't copy to %s, file exists already and is of different type", i->path);
                                return 0;
                        }
                }

                r = path_set_perms(i, i->path);
                if (r < 0)
                        return r;

                break;

        case WRITE_FILE:
                r = glob_item(i, write_one_file, false);
                if (r < 0)
                        return r;

                break;

        case CREATE_DIRECTORY:
        case TRUNCATE_DIRECTORY:
        case CREATE_SUBVOLUME:

                RUN_WITH_UMASK(0000)
                        mkdir_parents_label(i->path, 0755);

                if (i->type == CREATE_SUBVOLUME)
                        RUN_WITH_UMASK((~i->mode) & 0777) {
                                r = btrfs_subvol_make(i->path);
                                log_debug_errno(r, "Creating subvolume \"%s\": %m", i->path);
                        }
                else
                        r = 0;

                if (IN_SET(i->type, CREATE_DIRECTORY, TRUNCATE_DIRECTORY) || r == -ENOTTY)
                        RUN_WITH_UMASK(0000)
                                r = mkdir_label(i->path, i->mode);

                if (r < 0) {
                        int k;

                        if (r != -EEXIST && r != -EROFS)
                                return log_error_errno(r, "Failed to create directory or subvolume \"%s\": %m", i->path);

                        k = is_dir(i->path, false);
                        if (k == -ENOENT && r == -EROFS)
                                return log_error_errno(r, "%s does not exist and cannot be created as the file system is read-only.", i->path);
                        if (k < 0)
                                return log_error_errno(k, "Failed to check if %s exists: %m", i->path);
                        if (!k) {
                                log_warning("\"%s\" already exists and is not a directory.", i->path);
                                return 0;
                        }

                        creation = CREATION_EXISTING;
                } else
                        creation = CREATION_NORMAL;

                log_debug("%s directory \"%s\".", creation_mode_verb_to_string(creation), i->path);

                r = path_set_perms(i, i->path);
                if (r < 0)
                        return r;

                break;

        case CREATE_FIFO:

                RUN_WITH_UMASK(0000) {
                        mac_selinux_create_file_prepare(i->path, S_IFIFO);
                        r = mkfifo(i->path, i->mode);
                        mac_selinux_create_file_clear();
                }

                if (r < 0) {
                        if (errno != EEXIST)
                                return log_error_errno(errno, "Failed to create fifo %s: %m", i->path);

                        if (lstat(i->path, &st) < 0)
                                return log_error_errno(errno, "stat(%s) failed: %m", i->path);

                        if (!S_ISFIFO(st.st_mode)) {

                                if (i->force) {
                                        RUN_WITH_UMASK(0000) {
                                                mac_selinux_create_file_prepare(i->path, S_IFIFO);
                                                r = mkfifo_atomic(i->path, i->mode);
                                                mac_selinux_create_file_clear();
                                        }

                                        if (r < 0)
                                                return log_error_errno(r, "Failed to create fifo %s: %m", i->path);
                                        creation = CREATION_FORCE;
                                } else {
                                        log_warning("\"%s\" already exists and is not a fifo.", i->path);
                                        return 0;
                                }
                        } else
                                creation = CREATION_EXISTING;
                } else
                        creation = CREATION_NORMAL;
                log_debug("%s fifo \"%s\".", creation_mode_verb_to_string(creation), i->path);

                r = path_set_perms(i, i->path);
                if (r < 0)
                        return r;

                break;
        }

        case CREATE_SYMLINK: {
                r = specifier_printf(i->argument, specifier_table, NULL, &resolved);
                if (r < 0)
                        return log_error_errno(r, "Failed to substitute specifiers in symlink target %s: %m", i->argument);

                mac_selinux_create_file_prepare(i->path, S_IFLNK);
                r = symlink(resolved, i->path);
                mac_selinux_create_file_clear();

                if (r < 0) {
                        _cleanup_free_ char *x = NULL;

                        if (errno != EEXIST)
                                return log_error_errno(errno, "symlink(%s, %s) failed: %m", resolved, i->path);

                        r = readlink_malloc(i->path, &x);
                        if (r < 0 || !streq(resolved, x)) {

                                if (i->force) {
                                        mac_selinux_create_file_prepare(i->path, S_IFLNK);
                                        r = symlink_atomic(resolved, i->path);
                                        mac_selinux_create_file_clear();

                                        if (r < 0)
                                                return log_error_errno(r, "symlink(%s, %s) failed: %m", resolved, i->path);

                                        creation = CREATION_FORCE;
                                } else {
                                        log_debug("\"%s\" is not a symlink or does not point to the correct path.", i->path);
                                        return 0;
                                }
                        } else
                                creation = CREATION_EXISTING;
                } else

                        creation = CREATION_NORMAL;
                log_debug("%s symlink \"%s\".", creation_mode_verb_to_string(creation), i->path);
                break;
        }

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
                        mac_selinux_create_file_prepare(i->path, file_type);
                        r = mknod(i->path, i->mode | file_type, i->major_minor);
                        mac_selinux_create_file_clear();
                }

                if (r < 0) {
                        if (errno == EPERM) {
                                log_debug("We lack permissions, possibly because of cgroup configuration; "
                                          "skipping creation of device node %s.", i->path);
                                return 0;
                        }

                        if (errno != EEXIST)
                                return log_error_errno(errno, "Failed to create device node %s: %m", i->path);

                        if (lstat(i->path, &st) < 0)
                                return log_error_errno(errno, "stat(%s) failed: %m", i->path);

                        if ((st.st_mode & S_IFMT) != file_type) {

                                if (i->force) {

                                        RUN_WITH_UMASK(0000) {
                                                mac_selinux_create_file_prepare(i->path, file_type);
                                                r = mknod_atomic(i->path, i->mode | file_type, i->major_minor);
                                                mac_selinux_create_file_clear();
                                        }

                                        if (r < 0)
                                                return log_error_errno(r, "Failed to create device node \"%s\": %m", i->path);
                                        creation = CREATION_FORCE;
                                } else {
                                        log_debug("%s is not a device node.", i->path);
                                        return 0;
                                }
                        } else
                                creation = CREATION_EXISTING;
                } else
                        creation = CREATION_NORMAL;

                log_debug("%s %s device node \"%s\" %u:%u.",
                          creation_mode_verb_to_string(creation),
                          i->type == CREATE_BLOCK_DEVICE ? "block" : "char",
                          i->path, major(i->mode), minor(i->mode));

                r = path_set_perms(i, i->path);
                if (r < 0)
                        return r;

                break;
        }

        case ADJUST_MODE:
        case RELABEL_PATH:
                r = glob_item(i, path_set_perms, false);
                if (r < 0)
                        return r;
                break;

        case RECURSIVE_RELABEL_PATH:
                r = glob_item(i, path_set_perms, true);
                if (r < 0)
                        return r;
                break;

        case SET_XATTR:
                r = glob_item(i, path_set_xattrs, false);
                if (r < 0)
                        return r;
                break;

        case RECURSIVE_SET_XATTR:
                r = glob_item(i, path_set_xattrs, true);
                if (r < 0)
                        return r;
                break;

        case SET_ACL:
                r = glob_item(i, path_set_acls, false);
                if (r < 0)
                        return r;
                break;

        case RECURSIVE_SET_ACL:
                r = glob_item(i, path_set_acls, true);
                if (r < 0)
                        return r;
                break;

        case SET_ATTRIBUTE:
                r = glob_item(i, path_set_attribute, false);
                if (r < 0)
                        return r;
                break;

        case RECURSIVE_SET_ATTRIBUTE:
                r = glob_item(i, path_set_attribute, true);
                if (r < 0)
                        return r;
                break;
        }

        return 0;
}

static int remove_item_instance(Item *i, const char *instance) {
        int r;

        assert(i);

        switch (i->type) {

        case REMOVE_PATH:
                if (remove(instance) < 0 && errno != ENOENT)
                        return log_error_errno(errno, "rm(%s): %m", instance);

                break;

        case TRUNCATE_DIRECTORY:
        case RECURSIVE_REMOVE_PATH:
                /* FIXME: we probably should use dir_cleanup() here
                 * instead of rm_rf() so that 'x' is honoured. */
                log_debug("rm -rf \"%s\"", instance);
                r = rm_rf(instance, (i->type == RECURSIVE_REMOVE_PATH ? REMOVE_ROOT|REMOVE_SUBVOLUME : 0) | REMOVE_PHYSICAL);
                if (r < 0 && r != -ENOENT)
                        return log_error_errno(r, "rm_rf(%s): %m", instance);

                break;

        default:
                assert_not_reached("wut?");
        }

        return 0;
}

static int remove_item(Item *i) {
        int r = 0;

        assert(i);

        log_debug("Running remove action for entry %c %s", (char) i->type, i->path);

        switch (i->type) {

        case CREATE_FILE:
        case TRUNCATE_FILE:
        case CREATE_DIRECTORY:
        case CREATE_SUBVOLUME:
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
        case SET_XATTR:
        case RECURSIVE_SET_XATTR:
        case SET_ACL:
        case RECURSIVE_SET_ACL:
        case SET_ATTRIBUTE:
        case RECURSIVE_SET_ATTRIBUTE:
                break;

        case REMOVE_PATH:
        case TRUNCATE_DIRECTORY:
        case RECURSIVE_REMOVE_PATH:
                r = glob_item(i, remove_item_instance, false);
                break;
        }

        return r;
}

static int clean_item_instance(Item *i, const char* instance) {
        _cleanup_closedir_ DIR *d = NULL;
        struct stat s, ps;
        bool mountpoint;
        usec_t cutoff, n;
        char timestamp[FORMAT_TIMESTAMP_MAX];

        assert(i);

        if (!i->age_set)
                return 0;

        n = now(CLOCK_REALTIME);
        if (n < i->age)
                return 0;

        cutoff = n - i->age;

        d = opendir_nomod(instance);
        if (!d) {
                if (errno == ENOENT || errno == ENOTDIR) {
                        log_debug_errno(errno, "Directory \"%s\": %m", instance);
                        return 0;
                }

                log_error_errno(errno, "Failed to open directory %s: %m", instance);
                return -errno;
        }

        if (fstat(dirfd(d), &s) < 0)
                return log_error_errno(errno, "stat(%s) failed: %m", i->path);

        if (!S_ISDIR(s.st_mode)) {
                log_error("%s is not a directory.", i->path);
                return -ENOTDIR;
        }

        if (fstatat(dirfd(d), "..", &ps, AT_SYMLINK_NOFOLLOW) != 0)
                return log_error_errno(errno, "stat(%s/..) failed: %m", i->path);

        mountpoint = s.st_dev != ps.st_dev ||
                     (s.st_dev == ps.st_dev && s.st_ino == ps.st_ino);

        log_debug("Cleanup threshold for %s \"%s\" is %s",
                  mountpoint ? "mount point" : "directory",
                  instance,
                  format_timestamp_us(timestamp, sizeof(timestamp), cutoff));

        return dir_cleanup(i, instance, d, &s, cutoff, s.st_dev, mountpoint,
                           MAX_DEPTH, i->keep_first_level);
}

static int clean_item(Item *i) {
        int r = 0;

        assert(i);

        log_debug("Running clean action for entry %c %s", (char) i->type, i->path);

        switch (i->type) {
        case CREATE_DIRECTORY:
        case CREATE_SUBVOLUME:
        case TRUNCATE_DIRECTORY:
        case IGNORE_PATH:
        case COPY_FILES:
                clean_item_instance(i, i->path);
                break;
        case IGNORE_DIRECTORY_PATH:
                r = glob_item(i, clean_item_instance, false);
                break;
        default:
                break;
        }

        return r;
}

static int process_item_array(ItemArray *array);

static int process_item(Item *i) {
        int r, q, p, t = 0;
        _cleanup_free_ char *prefix = NULL;

        assert(i);

        if (i->done)
                return 0;

        i->done = true;

        prefix = malloc(strlen(i->path) + 1);
        if (!prefix)
                return log_oom();

        PATH_FOREACH_PREFIX(prefix, i->path) {
                ItemArray *j;

                j = ordered_hashmap_get(items, prefix);
                if (j) {
                        int s;

                        s = process_item_array(j);
                        if (s < 0 && t == 0)
                                t = s;
                }
        }

        r = arg_create ? create_item(i) : 0;
        q = arg_remove ? remove_item(i) : 0;
        p = arg_clean ? clean_item(i) : 0;

        return t < 0 ? t :
                r < 0 ? r :
                q < 0 ? q :
                p;
}

static int process_item_array(ItemArray *array) {
        unsigned n;
        int r = 0, k;

        assert(array);

        for (n = 0; n < array->count; n++) {
                k = process_item(array->items + n);
                if (k < 0 && r == 0)
                        r = k;
        }

        return r;
}

static void item_free_contents(Item *i) {
        assert(i);
        free(i->path);
        free(i->argument);
        strv_free(i->xattrs);

#ifdef HAVE_ACL
        acl_free(i->acl_access);
        acl_free(i->acl_default);
#endif
}

static void item_array_free(ItemArray *a) {
        unsigned n;

        if (!a)
                return;

        for (n = 0; n < a->count; n++)
                item_free_contents(a->items + n);
        free(a->items);
        free(a);
}

static int item_compare(const void *a, const void *b) {
        const Item *x = a, *y = b;

        /* Make sure that the ownership taking item is put first, so
         * that we first create the node, and then can adjust it */

        if (takes_ownership(x->type) && !takes_ownership(y->type))
                return -1;
        if (!takes_ownership(x->type) && takes_ownership(y->type))
                return 1;

        return (int) x->type - (int) y->type;
}

static bool item_compatible(Item *a, Item *b) {
        assert(a);
        assert(b);
        assert(streq(a->path, b->path));

        if (takes_ownership(a->type) && takes_ownership(b->type))
                /* check if the items are the same */
                return  streq_ptr(a->argument, b->argument) &&

                        a->uid_set == b->uid_set &&
                        a->uid == b->uid &&

                        a->gid_set == b->gid_set &&
                        a->gid == b->gid &&

                        a->mode_set == b->mode_set &&
                        a->mode == b->mode &&

                        a->age_set == b->age_set &&
                        a->age == b->age &&

                        a->mask_perms == b->mask_perms &&

                        a->keep_first_level == b->keep_first_level &&

                        a->major_minor == b->major_minor;

        return true;
}

static bool should_include_path(const char *path) {
        char **prefix;

        STRV_FOREACH(prefix, arg_exclude_prefixes)
                if (path_startswith(path, *prefix)) {
                        log_debug("Entry \"%s\" matches exclude prefix \"%s\", skipping.",
                                  path, *prefix);
                        return false;
                }

        STRV_FOREACH(prefix, arg_include_prefixes)
                if (path_startswith(path, *prefix)) {
                        log_debug("Entry \"%s\" matches include prefix \"%s\".", path, *prefix);
                        return true;
                }

        /* no matches, so we should include this path only if we
         * have no whitelist at all */
        if (strv_length(arg_include_prefixes) == 0)
                return true;

        log_debug("Entry \"%s\" does not match any include prefix, skipping.", path);
        return false;
}

static int parse_line(const char *fname, unsigned line, const char *buffer) {

        _cleanup_free_ char *action = NULL, *mode = NULL, *user = NULL, *group = NULL, *age = NULL, *path = NULL;
        _cleanup_(item_free_contents) Item i = {};
        ItemArray *existing;
        OrderedHashmap *h;
        int r, pos;
        bool force = false, boot = false;

        assert(fname);
        assert(line >= 1);
        assert(buffer);

        r = unquote_many_words(
                        &buffer,
                        0,
                        &action,
                        &path,
                        &mode,
                        &user,
                        &group,
                        &age,
                        NULL);
        if (r < 0)
                return log_error_errno(r, "[%s:%u] Failed to parse line: %m", fname, line);
        else if (r < 2) {
                log_error("[%s:%u] Syntax error.", fname, line);
                return -EIO;
        }

        if (!isempty(buffer) && !streq(buffer, "-")) {
                i.argument = strdup(buffer);
                if (!i.argument)
                        return log_oom();
        }

        if (isempty(action)) {
                log_error("[%s:%u] Command too short '%s'.", fname, line, action);
                return -EINVAL;
        }

        for (pos = 1; action[pos]; pos++) {
                if (action[pos] == '!' && !boot)
                        boot = true;
                else if (action[pos] == '+' && !force)
                        force = true;
                else {
                        log_error("[%s:%u] Unknown modifiers in command '%s'",
                                  fname, line, action);
                        return -EINVAL;
                }
        }

        if (boot && !arg_boot) {
                log_debug("Ignoring entry %s \"%s\" because --boot is not specified.",
                          action, path);
                return 0;
        }

        i.type = action[0];
        i.force = force;

        r = specifier_printf(path, specifier_table, NULL, &i.path);
        if (r < 0) {
                log_error("[%s:%u] Failed to replace specifiers: %s", fname, line, path);
                return r;
        }

        switch (i.type) {

        case CREATE_DIRECTORY:
        case CREATE_SUBVOLUME:
        case TRUNCATE_DIRECTORY:
        case CREATE_FIFO:
        case IGNORE_PATH:
        case IGNORE_DIRECTORY_PATH:
        case REMOVE_PATH:
        case RECURSIVE_REMOVE_PATH:
        case ADJUST_MODE:
        case RELABEL_PATH:
        case RECURSIVE_RELABEL_PATH:
                if (i.argument)
                        log_warning("[%s:%u] %c lines don't take argument fields, ignoring.", fname, line, i.type);

                break;

        case CREATE_FILE:
        case TRUNCATE_FILE:
                break;

        case CREATE_SYMLINK:
                if (!i.argument) {
                        i.argument = strappend("/usr/share/factory/", i.path);
                        if (!i.argument)
                                return log_oom();
                }
                break;

        case WRITE_FILE:
                if (!i.argument) {
                        log_error("[%s:%u] Write file requires argument.", fname, line);
                        return -EBADMSG;
                }
                break;

        case COPY_FILES:
                if (!i.argument) {
                        i.argument = strappend("/usr/share/factory/", i.path);
                        if (!i.argument)
                                return log_oom();
                } else if (!path_is_absolute(i.argument)) {
                        log_error("[%s:%u] Source path is not absolute.", fname, line);
                        return -EBADMSG;
                }

                path_kill_slashes(i.argument);
                break;

        case CREATE_CHAR_DEVICE:
        case CREATE_BLOCK_DEVICE: {
                unsigned major, minor;

                if (!i.argument) {
                        log_error("[%s:%u] Device file requires argument.", fname, line);
                        return -EBADMSG;
                }

                if (sscanf(i.argument, "%u:%u", &major, &minor) != 2) {
                        log_error("[%s:%u] Can't parse device file major/minor '%s'.", fname, line, i.argument);
                        return -EBADMSG;
                }

                i.major_minor = makedev(major, minor);
                break;
        }

        case SET_XATTR:
        case RECURSIVE_SET_XATTR:
                if (!i.argument) {
                        log_error("[%s:%u] Set extended attribute requires argument.", fname, line);
                        return -EBADMSG;
                }
                r = parse_xattrs_from_arg(&i);
                if (r < 0)
                        return r;
                break;

        case SET_ACL:
        case RECURSIVE_SET_ACL:
                if (!i.argument) {
                        log_error("[%s:%u] Set ACLs requires argument.", fname, line);
                        return -EBADMSG;
                }
                r = parse_acls_from_arg(&i);
                if (r < 0)
                        return r;
                break;

        case SET_ATTRIBUTE:
        case RECURSIVE_SET_ATTRIBUTE:
                if (!i.argument) {
                        log_error("[%s:%u] Set file attribute requires argument.", fname, line);
                        return -EBADMSG;
                }
                r = parse_attribute_from_arg(&i);
                if (r < 0)
                        return r;
                break;

        default:
                log_error("[%s:%u] Unknown command type '%c'.", fname, line, (char) i.type);
                return -EBADMSG;
        }

        if (!path_is_absolute(i.path)) {
                log_error("[%s:%u] Path '%s' not absolute.", fname, line, i.path);
                return -EBADMSG;
        }

        path_kill_slashes(i.path);

        if (!should_include_path(i.path))
                return 0;

        if (arg_root) {
                char *p;

                p = prefix_root(arg_root, i.path);
                if (!p)
                        return log_oom();

                free(i.path);
                i.path = p;
        }

        if (!isempty(user) && !streq(user, "-")) {
                const char *u = user;

                r = get_user_creds(&u, &i.uid, NULL, NULL, NULL);
                if (r < 0) {
                        log_error("[%s:%u] Unknown user '%s'.", fname, line, user);
                        return r;
                }

                i.uid_set = true;
        }

        if (!isempty(group) && !streq(group, "-")) {
                const char *g = group;

                r = get_group_creds(&g, &i.gid);
                if (r < 0) {
                        log_error("[%s:%u] Unknown group '%s'.", fname, line, group);
                        return r;
                }

                i.gid_set = true;
        }

        if (!isempty(mode) && !streq(mode, "-")) {
                const char *mm = mode;
                unsigned m;

                if (*mm == '~') {
                        i.mask_perms = true;
                        mm++;
                }

                if (parse_mode(mm, &m) < 0) {
                        log_error("[%s:%u] Invalid mode '%s'.", fname, line, mode);
                        return -EBADMSG;
                }

                i.mode = m;
                i.mode_set = true;
        } else
                i.mode = IN_SET(i.type, CREATE_DIRECTORY, CREATE_SUBVOLUME, TRUNCATE_DIRECTORY)
                        ? 0755 : 0644;

        if (!isempty(age) && !streq(age, "-")) {
                const char *a = age;

                if (*a == '~') {
                        i.keep_first_level = true;
                        a++;
                }

                if (parse_sec(a, &i.age) < 0) {
                        log_error("[%s:%u] Invalid age '%s'.", fname, line, age);
                        return -EBADMSG;
                }

                i.age_set = true;
        }

        h = needs_glob(i.type) ? globs : items;

        existing = ordered_hashmap_get(h, i.path);
        if (existing) {
                unsigned n;

                for (n = 0; n < existing->count; n++) {
                        if (!item_compatible(existing->items + n, &i)) {
                                log_warning("[%s:%u] Duplicate line for path \"%s\", ignoring.",
                                            fname, line, i.path);
                                return 0;
                        }
                }
        } else {
                existing = new0(ItemArray, 1);
                r = ordered_hashmap_put(h, i.path, existing);
                if (r < 0)
                        return log_oom();
        }

        if (!GREEDY_REALLOC(existing->items, existing->size, existing->count + 1))
                return log_oom();

        memcpy(existing->items + existing->count++, &i, sizeof(i));

        /* Sort item array, to enforce stable ordering of application */
        qsort_safe(existing->items, existing->count, sizeof(Item), item_compare);

        zero(i);
        return 0;
}

static void help(void) {
        printf("%s [OPTIONS...] [CONFIGURATION FILE...]\n\n"
               "Creates, deletes and cleans up volatile and temporary files and directories.\n\n"
               "  -h --help                 Show this help\n"
               "     --version              Show package version\n"
               "     --create               Create marked files/directories\n"
               "     --clean                Clean up marked directories\n"
               "     --remove               Remove marked files/directories\n"
               "     --boot                 Execute actions only safe at boot\n"
               "     --prefix=PATH          Only apply rules with the specified prefix\n"
               "     --exclude-prefix=PATH  Ignore rules with the specified prefix\n"
               "     --root=PATH            Operate on an alternate filesystem root\n",
               program_invocation_short_name);
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

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        help();
                        return 0;

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
                if (ignore_enoent && r == -ENOENT) {
                        log_debug_errno(r, "Failed to open \"%s\": %m", fn);
                        return 0;
                }

                return log_error_errno(r, "Failed to open '%s', ignoring: %m", fn);
        }
        log_debug("Reading config file \"%s\".", fn);

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
        ORDERED_HASHMAP_FOREACH(i, globs, iterator) {
                Iterator iter;
                Item *j, *candidate_item = NULL;

                if (i->type != IGNORE_DIRECTORY_PATH)
                        continue;

                ORDERED_HASHMAP_FOREACH(j, items, iter) {
                        if (j->type != CREATE_DIRECTORY && j->type != TRUNCATE_DIRECTORY && j->type != CREATE_SUBVOLUME)
                                continue;

                        if (path_equal(j->path, i->path)) {
                                candidate_item = j;
                                break;
                        }

                        if ((!candidate_item && path_startswith(i->path, j->path)) ||
                            (candidate_item && path_startswith(j->path, candidate_item->path) && (fnmatch(i->path, j->path, FNM_PATHNAME | FNM_PERIOD) == 0)))
                                candidate_item = j;
                }

                if (candidate_item && candidate_item->age_set) {
                        i->age = candidate_item->age;
                        i->age_set = true;
                }
        }

        if (ferror(f)) {
                log_error_errno(errno, "Failed to read from file %s: %m", fn);
                if (r == 0)
                        r = -EIO;
        }

        return r;
}

int main(int argc, char *argv[]) {
        int r, k;
        ItemArray *a;
        Iterator iterator;

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        mac_selinux_init(NULL);

        items = ordered_hashmap_new(&string_hash_ops);
        globs = ordered_hashmap_new(&string_hash_ops);

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
                        log_error_errno(r, "Failed to enumerate tmpfiles.d files: %m");
                        goto finish;
                }

                STRV_FOREACH(f, files) {
                        k = read_config_file(*f, true);
                        if (k < 0 && r == 0)
                                r = k;
                }
        }

        /* The non-globbing ones usually create things, hence we apply
         * them first */
        ORDERED_HASHMAP_FOREACH(a, items, iterator) {
                k = process_item_array(a);
                if (k < 0 && r == 0)
                        r = k;
        }

        /* The globbing ones usually alter things, hence we apply them
         * second. */
        ORDERED_HASHMAP_FOREACH(a, globs, iterator) {
                k = process_item_array(a);
                if (k < 0 && r == 0)
                        r = k;
        }

finish:
        while ((a = ordered_hashmap_steal_first(items)))
                item_array_free(a);

        while ((a = ordered_hashmap_steal_first(globs)))
                item_array_free(a);

        ordered_hashmap_free(items);
        ordered_hashmap_free(globs);

        free(arg_include_prefixes);
        free(arg_exclude_prefixes);
        free(arg_root);

        set_free_free(unix_sockets);

        mac_selinux_finish();

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
