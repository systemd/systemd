/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering

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

#include <sys/mount.h>
#include <linux/magic.h>

#include "alloc-util.h"
#include "cgroup-util.h"
#include "escape.h"
#include "fs-util.h"
#include "label.h"
#include "mkdir.h"
#include "mount-util.h"
#include "nspawn-mount.h"
#include "parse-util.h"
#include "path-util.h"
#include "rm-rf.h"
#include "set.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"
#include "util.h"

CustomMount* custom_mount_add(CustomMount **l, unsigned *n, CustomMountType t) {
        CustomMount *c, *ret;

        assert(l);
        assert(n);
        assert(t >= 0);
        assert(t < _CUSTOM_MOUNT_TYPE_MAX);

        c = realloc(*l, (*n + 1) * sizeof(CustomMount));
        if (!c)
                return NULL;

        *l = c;
        ret = *l + *n;
        (*n)++;

        *ret = (CustomMount) { .type = t };

        return ret;
}

void custom_mount_free_all(CustomMount *l, unsigned n) {
        unsigned i;

        for (i = 0; i < n; i++) {
                CustomMount *m = l + i;

                free(m->source);
                free(m->destination);
                free(m->options);

                if (m->work_dir) {
                        (void) rm_rf(m->work_dir, REMOVE_ROOT|REMOVE_PHYSICAL);
                        free(m->work_dir);
                }

                strv_free(m->lower);
        }

        free(l);
}

int custom_mount_compare(const void *a, const void *b) {
        const CustomMount *x = a, *y = b;
        int r;

        r = path_compare(x->destination, y->destination);
        if (r != 0)
                return r;

        if (x->type < y->type)
                return -1;
        if (x->type > y->type)
                return 1;

        return 0;
}

int bind_mount_parse(CustomMount **l, unsigned *n, const char *s, bool read_only) {
        _cleanup_free_ char *source = NULL, *destination = NULL, *opts = NULL;
        const char *p = s;
        CustomMount *m;
        int r;

        assert(l);
        assert(n);

        r = extract_many_words(&p, ":", EXTRACT_DONT_COALESCE_SEPARATORS, &source, &destination, NULL);
        if (r < 0)
                return r;
        if (r == 0)
                return -EINVAL;

        if (r == 1) {
                destination = strdup(source);
                if (!destination)
                        return -ENOMEM;
        }

        if (r == 2 && !isempty(p)) {
                opts = strdup(p);
                if (!opts)
                        return -ENOMEM;
        }

        if (!path_is_absolute(source))
                return -EINVAL;

        if (!path_is_absolute(destination))
                return -EINVAL;

        m = custom_mount_add(l, n, CUSTOM_MOUNT_BIND);
        if (!m)
                return log_oom();

        m->source = source;
        m->destination = destination;
        m->read_only = read_only;
        m->options = opts;

        source = destination = opts = NULL;
        return 0;
}

int tmpfs_mount_parse(CustomMount **l, unsigned *n, const char *s) {
        _cleanup_free_ char *path = NULL, *opts = NULL;
        const char *p = s;
        CustomMount *m;
        int r;

        assert(l);
        assert(n);
        assert(s);

        r = extract_first_word(&p, &path, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
        if (r < 0)
                return r;
        if (r == 0)
                return -EINVAL;

        if (isempty(p))
                opts = strdup("mode=0755");
        else
                opts = strdup(p);
        if (!opts)
                return -ENOMEM;

        if (!path_is_absolute(path))
                return -EINVAL;

        m = custom_mount_add(l, n, CUSTOM_MOUNT_TMPFS);
        if (!m)
                return -ENOMEM;

        m->destination = path;
        m->options = opts;

        path = opts = NULL;
        return 0;
}

static int tmpfs_patch_options(
                const char *options,
                bool userns, uid_t uid_shift, uid_t uid_range,
                const char *selinux_apifs_context,
                char **ret) {

        char *buf = NULL;

        if (userns && uid_shift != 0) {
                assert(uid_shift != UID_INVALID);

                if (options)
                        (void) asprintf(&buf, "%s,uid=" UID_FMT ",gid=" UID_FMT, options, uid_shift, uid_shift);
                else
                        (void) asprintf(&buf, "uid=" UID_FMT ",gid=" UID_FMT, uid_shift, uid_shift);
                if (!buf)
                        return -ENOMEM;

                options = buf;
        }

#ifdef HAVE_SELINUX
        if (selinux_apifs_context) {
                char *t;

                if (options)
                        t = strjoin(options, ",context=\"", selinux_apifs_context, "\"", NULL);
                else
                        t = strjoin("context=\"", selinux_apifs_context, "\"", NULL);
                if (!t) {
                        free(buf);
                        return -ENOMEM;
                }

                free(buf);
                buf = t;
        }
#endif

        *ret = buf;
        return !!buf;
}

int mount_sysfs(const char *dest) {
        const char *full, *top, *x;
        int r;

        top = prefix_roota(dest, "/sys");
        r = path_check_fstype(top, SYSFS_MAGIC);
        if (r < 0)
                return log_error_errno(r, "Failed to determine filesystem type of %s: %m", top);
        /* /sys might already be mounted as sysfs by the outer child in the
         * !netns case. In this case, it's all good. Don't touch it because we
         * don't have the right to do so, see https://github.com/systemd/systemd/issues/1555.
         */
        if (r > 0)
                return 0;

        full = prefix_roota(top, "/full");

        (void) mkdir(full, 0755);

        if (mount("sysfs", full, "sysfs", MS_RDONLY|MS_NOSUID|MS_NOEXEC|MS_NODEV, NULL) < 0)
                return log_error_errno(errno, "Failed to mount sysfs to %s: %m", full);

        FOREACH_STRING(x, "block", "bus", "class", "dev", "devices", "kernel") {
                _cleanup_free_ char *from = NULL, *to = NULL;

                from = prefix_root(full, x);
                if (!from)
                        return log_oom();

                to = prefix_root(top, x);
                if (!to)
                        return log_oom();

                (void) mkdir(to, 0755);

                if (mount(from, to, NULL, MS_BIND, NULL) < 0)
                        return log_error_errno(errno, "Failed to mount /sys/%s into place: %m", x);

                if (mount(NULL, to, NULL, MS_BIND|MS_RDONLY|MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_REMOUNT, NULL) < 0)
                        return log_error_errno(errno, "Failed to mount /sys/%s read-only: %m", x);
        }

        if (umount(full) < 0)
                return log_error_errno(errno, "Failed to unmount %s: %m", full);

        if (rmdir(full) < 0)
                return log_error_errno(errno, "Failed to remove %s: %m", full);

        x = prefix_roota(top, "/fs/kdbus");
        (void) mkdir(x, 0755);

        if (mount(NULL, top, NULL, MS_BIND|MS_RDONLY|MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_REMOUNT, NULL) < 0)
                return log_error_errno(errno, "Failed to make %s read-only: %m", top);

        return 0;
}

int mount_all(const char *dest,
              bool use_userns, bool in_userns,
              bool use_netns,
              uid_t uid_shift, uid_t uid_range,
              const char *selinux_apifs_context) {

        typedef struct MountPoint {
                const char *what;
                const char *where;
                const char *type;
                const char *options;
                unsigned long flags;
                bool fatal;
                bool in_userns;
                bool use_netns;
        } MountPoint;

        static const MountPoint mount_table[] = {
                { "proc",      "/proc",          "proc",   NULL,        MS_NOSUID|MS_NOEXEC|MS_NODEV,                              true,  true, false  },
                { "/proc/sys", "/proc/sys",      NULL,     NULL,        MS_BIND,                                                   true,  true, false  },   /* Bind mount first */
                { NULL,        "/proc/sys",      NULL,     NULL,        MS_BIND|MS_RDONLY|MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_REMOUNT, true,  true, false  },   /* Then, make it r/o */
                { "tmpfs",     "/sys",           "tmpfs",  "mode=755",  MS_NOSUID|MS_NOEXEC|MS_NODEV,                              true,  false, true },
                { "sysfs",     "/sys",           "sysfs",  NULL,        MS_RDONLY|MS_NOSUID|MS_NOEXEC|MS_NODEV,                    true,  false, false },
                { "tmpfs",     "/dev",           "tmpfs",  "mode=755",  MS_NOSUID|MS_STRICTATIME,                                  true,  false, false },
                { "tmpfs",     "/dev/shm",       "tmpfs",  "mode=1777", MS_NOSUID|MS_NODEV|MS_STRICTATIME,                         true,  false, false },
                { "tmpfs",     "/run",           "tmpfs",  "mode=755",  MS_NOSUID|MS_NODEV|MS_STRICTATIME,                         true,  false, false },
                { "tmpfs",     "/tmp",           "tmpfs",  "mode=1777", MS_STRICTATIME,                                            true,  false, false },
#ifdef HAVE_SELINUX
                { "/sys/fs/selinux", "/sys/fs/selinux", NULL, NULL,     MS_BIND,                                                   false, false, false },  /* Bind mount first */
                { NULL,              "/sys/fs/selinux", NULL, NULL,     MS_BIND|MS_RDONLY|MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_REMOUNT, false, false, false },  /* Then, make it r/o */
#endif
        };

        unsigned k;
        int r;

        for (k = 0; k < ELEMENTSOF(mount_table); k++) {
                _cleanup_free_ char *where = NULL, *options = NULL;
                const char *o;

                if (in_userns != mount_table[k].in_userns)
                        continue;

                if (!use_netns && mount_table[k].use_netns)
                        continue;

                where = prefix_root(dest, mount_table[k].where);
                if (!where)
                        return log_oom();

                r = path_is_mount_point(where, AT_SYMLINK_FOLLOW);
                if (r < 0 && r != -ENOENT)
                        return log_error_errno(r, "Failed to detect whether %s is a mount point: %m", where);

                /* Skip this entry if it is not a remount. */
                if (mount_table[k].what && r > 0)
                        continue;

                r = mkdir_p(where, 0755);
                if (r < 0) {
                        if (mount_table[k].fatal)
                                return log_error_errno(r, "Failed to create directory %s: %m", where);

                        log_warning_errno(r, "Failed to create directory %s: %m", where);
                        continue;
                }

                o = mount_table[k].options;
                if (streq_ptr(mount_table[k].type, "tmpfs")) {
                        r = tmpfs_patch_options(o, use_userns, uid_shift, uid_range, selinux_apifs_context, &options);
                        if (r < 0)
                                return log_oom();
                        if (r > 0)
                                o = options;
                }

                if (mount(mount_table[k].what,
                          where,
                          mount_table[k].type,
                          mount_table[k].flags,
                          o) < 0) {

                        if (mount_table[k].fatal)
                                return log_error_errno(errno, "mount(%s) failed: %m", where);

                        log_warning_errno(errno, "mount(%s) failed, ignoring: %m", where);
                }
        }

        return 0;
}

static int parse_mount_bind_options(const char *options, unsigned long *mount_flags, char **mount_opts) {
        const char *p = options;
        unsigned long flags = *mount_flags;
        char *opts = NULL;

        assert(options);

        for (;;) {
                _cleanup_free_ char *word = NULL;
                int r = extract_first_word(&p, &word, ",", 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract mount option: %m");
                if (r == 0)
                        break;

                if (streq(word, "rbind"))
                        flags |= MS_REC;
                else if (streq(word, "norbind"))
                        flags &= ~MS_REC;
                else {
                        log_error("Invalid bind mount option: %s", word);
                        return -EINVAL;
                }
        }

        *mount_flags = flags;
        /* in the future mount_opts will hold string options for mount(2) */
        *mount_opts = opts;

        return 0;
}

static int mount_bind(const char *dest, CustomMount *m) {
        struct stat source_st, dest_st;
        const char *where;
        unsigned long mount_flags = MS_BIND | MS_REC;
        _cleanup_free_ char *mount_opts = NULL;
        int r;

        assert(m);

        if (m->options) {
                r = parse_mount_bind_options(m->options, &mount_flags, &mount_opts);
                if (r < 0)
                        return r;
        }

        if (stat(m->source, &source_st) < 0)
                return log_error_errno(errno, "Failed to stat %s: %m", m->source);

        where = prefix_roota(dest, m->destination);

        if (stat(where, &dest_st) >= 0) {
                if (S_ISDIR(source_st.st_mode) && !S_ISDIR(dest_st.st_mode)) {
                        log_error("Cannot bind mount directory %s on file %s.", m->source, where);
                        return -EINVAL;
                }

                if (!S_ISDIR(source_st.st_mode) && S_ISDIR(dest_st.st_mode)) {
                        log_error("Cannot bind mount file %s on directory %s.", m->source, where);
                        return -EINVAL;
                }

        } else if (errno == ENOENT) {
                r = mkdir_parents_label(where, 0755);
                if (r < 0)
                        return log_error_errno(r, "Failed to make parents of %s: %m", where);
        } else {
                return log_error_errno(errno, "Failed to stat %s: %m", where);
        }

        /* Create the mount point. Any non-directory file can be
         * mounted on any non-directory file (regular, fifo, socket,
         * char, block).
         */
        if (S_ISDIR(source_st.st_mode))
                r = mkdir_label(where, 0755);
        else
                r = touch(where);
        if (r < 0 && r != -EEXIST)
                return log_error_errno(r, "Failed to create mount point %s: %m", where);

        if (mount(m->source, where, NULL, mount_flags, mount_opts) < 0)
                return log_error_errno(errno, "mount(%s) failed: %m", where);

        if (m->read_only) {
                r = bind_remount_recursive(where, true);
                if (r < 0)
                        return log_error_errno(r, "Read-only bind mount failed: %m");
        }

        return 0;
}

static int mount_tmpfs(
                const char *dest,
                CustomMount *m,
                bool userns, uid_t uid_shift, uid_t uid_range,
                const char *selinux_apifs_context) {

        const char *where, *options;
        _cleanup_free_ char *buf = NULL;
        int r;

        assert(dest);
        assert(m);

        where = prefix_roota(dest, m->destination);

        r = mkdir_p_label(where, 0755);
        if (r < 0 && r != -EEXIST)
                return log_error_errno(r, "Creating mount point for tmpfs %s failed: %m", where);

        r = tmpfs_patch_options(m->options, userns, uid_shift, uid_range, selinux_apifs_context, &buf);
        if (r < 0)
                return log_oom();
        options = r > 0 ? buf : m->options;

        if (mount("tmpfs", where, "tmpfs", MS_NODEV|MS_STRICTATIME, options) < 0)
                return log_error_errno(errno, "tmpfs mount to %s failed: %m", where);

        return 0;
}

static char *joined_and_escaped_lower_dirs(char * const *lower) {
        _cleanup_strv_free_ char **sv = NULL;

        sv = strv_copy(lower);
        if (!sv)
                return NULL;

        strv_reverse(sv);

        if (!strv_shell_escape(sv, ",:"))
                return NULL;

        return strv_join(sv, ":");
}

static int mount_overlay(const char *dest, CustomMount *m) {
        _cleanup_free_ char *lower = NULL;
        const char *where, *options;
        int r;

        assert(dest);
        assert(m);

        where = prefix_roota(dest, m->destination);

        r = mkdir_label(where, 0755);
        if (r < 0 && r != -EEXIST)
                return log_error_errno(r, "Creating mount point for overlay %s failed: %m", where);

        (void) mkdir_p_label(m->source, 0755);

        lower = joined_and_escaped_lower_dirs(m->lower);
        if (!lower)
                return log_oom();

        if (m->read_only) {
                _cleanup_free_ char *escaped_source = NULL;

                escaped_source = shell_escape(m->source, ",:");
                if (!escaped_source)
                        return log_oom();

                options = strjoina("lowerdir=", escaped_source, ":", lower);
        } else {
                _cleanup_free_ char *escaped_source = NULL, *escaped_work_dir = NULL;

                assert(m->work_dir);
                (void) mkdir_label(m->work_dir, 0700);

                escaped_source = shell_escape(m->source, ",:");
                if (!escaped_source)
                        return log_oom();
                escaped_work_dir = shell_escape(m->work_dir, ",:");
                if (!escaped_work_dir)
                        return log_oom();

                options = strjoina("lowerdir=", lower, ",upperdir=", escaped_source, ",workdir=", escaped_work_dir);
        }

        if (mount("overlay", where, "overlay", m->read_only ? MS_RDONLY : 0, options) < 0)
                return log_error_errno(errno, "overlay mount to %s failed: %m", where);

        return 0;
}

int mount_custom(
                const char *dest,
                CustomMount *mounts, unsigned n,
                bool userns, uid_t uid_shift, uid_t uid_range,
                const char *selinux_apifs_context) {

        unsigned i;
        int r;

        assert(dest);

        for (i = 0; i < n; i++) {
                CustomMount *m = mounts + i;

                switch (m->type) {

                case CUSTOM_MOUNT_BIND:
                        r = mount_bind(dest, m);
                        break;

                case CUSTOM_MOUNT_TMPFS:
                        r = mount_tmpfs(dest, m, userns, uid_shift, uid_range, selinux_apifs_context);
                        break;

                case CUSTOM_MOUNT_OVERLAY:
                        r = mount_overlay(dest, m);
                        break;

                default:
                        assert_not_reached("Unknown custom mount type");
                }

                if (r < 0)
                        return r;
        }

        return 0;
}

static int mount_legacy_cgroup_hierarchy(const char *dest, const char *controller, const char *hierarchy, bool read_only) {
        char *to;
        int r;

        to = strjoina(strempty(dest), "/sys/fs/cgroup/", hierarchy);

        r = path_is_mount_point(to, 0);
        if (r < 0 && r != -ENOENT)
                return log_error_errno(r, "Failed to determine if %s is mounted already: %m", to);
        if (r > 0)
                return 0;

        mkdir_p(to, 0755);

        /* The superblock mount options of the mount point need to be
         * identical to the hosts', and hence writable... */
        if (mount("cgroup", to, "cgroup", MS_NOSUID|MS_NOEXEC|MS_NODEV, controller) < 0)
                return log_error_errno(errno, "Failed to mount to %s: %m", to);

        /* ... hence let's only make the bind mount read-only, not the
         * superblock. */
        if (read_only) {
                if (mount(NULL, to, NULL, MS_BIND|MS_REMOUNT|MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_RDONLY, NULL) < 0)
                        return log_error_errno(errno, "Failed to remount %s read-only: %m", to);
        }
        return 1;
}

static int mount_legacy_cgroups(
                const char *dest,
                bool userns, uid_t uid_shift, uid_t uid_range,
                const char *selinux_apifs_context) {

        _cleanup_set_free_free_ Set *controllers = NULL;
        const char *cgroup_root;
        int r;

        cgroup_root = prefix_roota(dest, "/sys/fs/cgroup");

        (void) mkdir_p(cgroup_root, 0755);

        /* Mount a tmpfs to /sys/fs/cgroup if it's not mounted there yet. */
        r = path_is_mount_point(cgroup_root, AT_SYMLINK_FOLLOW);
        if (r < 0)
                return log_error_errno(r, "Failed to determine if /sys/fs/cgroup is already mounted: %m");
        if (r == 0) {
                _cleanup_free_ char *options = NULL;

                r = tmpfs_patch_options("mode=755", userns, uid_shift, uid_range, selinux_apifs_context, &options);
                if (r < 0)
                        return log_oom();

                if (mount("tmpfs", cgroup_root, "tmpfs", MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_STRICTATIME, options) < 0)
                        return log_error_errno(errno, "Failed to mount /sys/fs/cgroup: %m");
        }

        if (cg_unified() > 0)
                goto skip_controllers;

        controllers = set_new(&string_hash_ops);
        if (!controllers)
                return log_oom();

        r = cg_kernel_controllers(controllers);
        if (r < 0)
                return log_error_errno(r, "Failed to determine cgroup controllers: %m");

        for (;;) {
                _cleanup_free_ char *controller = NULL, *origin = NULL, *combined = NULL;

                controller = set_steal_first(controllers);
                if (!controller)
                        break;

                origin = prefix_root("/sys/fs/cgroup/", controller);
                if (!origin)
                        return log_oom();

                r = readlink_malloc(origin, &combined);
                if (r == -EINVAL) {
                        /* Not a symbolic link, but directly a single cgroup hierarchy */

                        r = mount_legacy_cgroup_hierarchy(dest, controller, controller, true);
                        if (r < 0)
                                return r;

                } else if (r < 0)
                        return log_error_errno(r, "Failed to read link %s: %m", origin);
                else {
                        _cleanup_free_ char *target = NULL;

                        target = prefix_root(dest, origin);
                        if (!target)
                                return log_oom();

                        /* A symbolic link, a combination of controllers in one hierarchy */

                        if (!filename_is_valid(combined)) {
                                log_warning("Ignoring invalid combined hierarchy %s.", combined);
                                continue;
                        }

                        r = mount_legacy_cgroup_hierarchy(dest, combined, combined, true);
                        if (r < 0)
                                return r;

                        r = symlink_idempotent(combined, target);
                        if (r == -EINVAL) {
                                log_error("Invalid existing symlink for combined hierarchy");
                                return r;
                        }
                        if (r < 0)
                                return log_error_errno(r, "Failed to create symlink for combined hierarchy: %m");
                }
        }

skip_controllers:
        r = mount_legacy_cgroup_hierarchy(dest, "none,name=systemd,xattr", "systemd", false);
        if (r < 0)
                return r;

        if (mount(NULL, cgroup_root, NULL, MS_REMOUNT|MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_STRICTATIME|MS_RDONLY, "mode=755") < 0)
                return log_error_errno(errno, "Failed to remount %s read-only: %m", cgroup_root);

        return 0;
}

static int mount_unified_cgroups(const char *dest) {
        const char *p;
        int r;

        assert(dest);

        p = prefix_roota(dest, "/sys/fs/cgroup");

        (void) mkdir_p(p, 0755);

        r = path_is_mount_point(p, AT_SYMLINK_FOLLOW);
        if (r < 0)
                return log_error_errno(r, "Failed to determine if %s is mounted already: %m", p);
        if (r > 0) {
                p = prefix_roota(dest, "/sys/fs/cgroup/cgroup.procs");
                if (access(p, F_OK) >= 0)
                        return 0;
                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to determine if mount point %s contains the unified cgroup hierarchy: %m", p);

                log_error("%s is already mounted but not a unified cgroup hierarchy. Refusing.", p);
                return -EINVAL;
        }

        if (mount("cgroup", p, "cgroup", MS_NOSUID|MS_NOEXEC|MS_NODEV, "__DEVEL__sane_behavior") < 0)
                return log_error_errno(errno, "Failed to mount unified cgroup hierarchy to %s: %m", p);

        return 0;
}

int mount_cgroups(
                const char *dest,
                bool unified_requested,
                bool userns, uid_t uid_shift, uid_t uid_range,
                const char *selinux_apifs_context) {

        if (unified_requested)
                return mount_unified_cgroups(dest);
        else
                return mount_legacy_cgroups(dest, userns, uid_shift, uid_range, selinux_apifs_context);
}

int mount_systemd_cgroup_writable(
                const char *dest,
                bool unified_requested) {

        _cleanup_free_ char *own_cgroup_path = NULL;
        const char *systemd_root, *systemd_own;
        int r;

        assert(dest);

        r = cg_pid_get_path(NULL, 0, &own_cgroup_path);
        if (r < 0)
                return log_error_errno(r, "Failed to determine our own cgroup path: %m");

        /* If we are living in the top-level, then there's nothing to do... */
        if (path_equal(own_cgroup_path, "/"))
                return 0;

        if (unified_requested) {
                systemd_own = strjoina(dest, "/sys/fs/cgroup", own_cgroup_path);
                systemd_root = prefix_roota(dest, "/sys/fs/cgroup");
        } else {
                systemd_own = strjoina(dest, "/sys/fs/cgroup/systemd", own_cgroup_path);
                systemd_root = prefix_roota(dest, "/sys/fs/cgroup/systemd");
        }

        /* Make our own cgroup a (writable) bind mount */
        if (mount(systemd_own, systemd_own,  NULL, MS_BIND, NULL) < 0)
                return log_error_errno(errno, "Failed to turn %s into a bind mount: %m", own_cgroup_path);

        /* And then remount the systemd cgroup root read-only */
        if (mount(NULL, systemd_root, NULL, MS_BIND|MS_REMOUNT|MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_RDONLY, NULL) < 0)
                return log_error_errno(errno, "Failed to mount cgroup root read-only: %m");

        return 0;
}

int setup_volatile_state(
                const char *directory,
                VolatileMode mode,
                bool userns, uid_t uid_shift, uid_t uid_range,
                const char *selinux_apifs_context) {

        _cleanup_free_ char *buf = NULL;
        const char *p, *options;
        int r;

        assert(directory);

        if (mode != VOLATILE_STATE)
                return 0;

        /* --volatile=state means we simply overmount /var
           with a tmpfs, and the rest read-only. */

        r = bind_remount_recursive(directory, true);
        if (r < 0)
                return log_error_errno(r, "Failed to remount %s read-only: %m", directory);

        p = prefix_roota(directory, "/var");
        r = mkdir(p, 0755);
        if (r < 0 && errno != EEXIST)
                return log_error_errno(errno, "Failed to create %s: %m", directory);

        options = "mode=755";
        r = tmpfs_patch_options(options, userns, uid_shift, uid_range, selinux_apifs_context, &buf);
        if (r < 0)
                return log_oom();
        if (r > 0)
                options = buf;

        if (mount("tmpfs", p, "tmpfs", MS_STRICTATIME, options) < 0)
                return log_error_errno(errno, "Failed to mount tmpfs to /var: %m");

        return 0;
}

int setup_volatile(
                const char *directory,
                VolatileMode mode,
                bool userns, uid_t uid_shift, uid_t uid_range,
                const char *selinux_apifs_context) {

        bool tmpfs_mounted = false, bind_mounted = false;
        char template[] = "/tmp/nspawn-volatile-XXXXXX";
        _cleanup_free_ char *buf = NULL;
        const char *f, *t, *options;
        int r;

        assert(directory);

        if (mode != VOLATILE_YES)
                return 0;

        /* --volatile=yes means we mount a tmpfs to the root dir, and
           the original /usr to use inside it, and that read-only. */

        if (!mkdtemp(template))
                return log_error_errno(errno, "Failed to create temporary directory: %m");

        options = "mode=755";
        r = tmpfs_patch_options(options, userns, uid_shift, uid_range, selinux_apifs_context, &buf);
        if (r < 0)
                return log_oom();
        if (r > 0)
                options = buf;

        if (mount("tmpfs", template, "tmpfs", MS_STRICTATIME, options) < 0) {
                r = log_error_errno(errno, "Failed to mount tmpfs for root directory: %m");
                goto fail;
        }

        tmpfs_mounted = true;

        f = prefix_roota(directory, "/usr");
        t = prefix_roota(template, "/usr");

        r = mkdir(t, 0755);
        if (r < 0 && errno != EEXIST) {
                r = log_error_errno(errno, "Failed to create %s: %m", t);
                goto fail;
        }

        if (mount(f, t, NULL, MS_BIND|MS_REC, NULL) < 0) {
                r = log_error_errno(errno, "Failed to create /usr bind mount: %m");
                goto fail;
        }

        bind_mounted = true;

        r = bind_remount_recursive(t, true);
        if (r < 0) {
                log_error_errno(r, "Failed to remount %s read-only: %m", t);
                goto fail;
        }

        if (mount(template, directory, NULL, MS_MOVE, NULL) < 0) {
                r = log_error_errno(errno, "Failed to move root mount: %m");
                goto fail;
        }

        (void) rmdir(template);

        return 0;

fail:
        if (bind_mounted)
                (void) umount(t);

        if (tmpfs_mounted)
                (void) umount(template);
        (void) rmdir(template);
        return r;
}

VolatileMode volatile_mode_from_string(const char *s) {
        int b;

        if (isempty(s))
                return _VOLATILE_MODE_INVALID;

        b = parse_boolean(s);
        if (b > 0)
                return VOLATILE_YES;
        if (b == 0)
                return VOLATILE_NO;

        if (streq(s, "state"))
                return VOLATILE_STATE;

        return _VOLATILE_MODE_INVALID;
}
