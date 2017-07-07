/* SPDX-License-Identifier: LGPL-2.1+ */

#include <sys/mount.h>
#include <linux/magic.h>

#include "alloc-util.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
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

CustomMount* custom_mount_add(CustomMount **l, size_t *n, CustomMountType t) {
        CustomMount *c, *ret;

        assert(l);
        assert(n);
        assert(t >= 0);
        assert(t < _CUSTOM_MOUNT_TYPE_MAX);

        c = reallocarray(*l, *n + 1, sizeof(CustomMount));
        if (!c)
                return NULL;

        *l = c;
        ret = *l + *n;
        (*n)++;

        *ret = (CustomMount) { .type = t };

        return ret;
}

void custom_mount_free_all(CustomMount *l, size_t n) {
        size_t i;

        for (i = 0; i < n; i++) {
                CustomMount *m = l + i;

                free(m->source);
                free(m->destination);
                free(m->options);

                if (m->work_dir) {
                        (void) rm_rf(m->work_dir, REMOVE_ROOT|REMOVE_PHYSICAL);
                        free(m->work_dir);
                }

                if (m->rm_rf_tmpdir) {
                        (void) rm_rf(m->rm_rf_tmpdir, REMOVE_ROOT|REMOVE_PHYSICAL);
                        free(m->rm_rf_tmpdir);
                }

                strv_free(m->lower);
        }

        free(l);
}

static int custom_mount_compare(const void *a, const void *b) {
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

static bool source_path_is_valid(const char *p) {
        assert(p);

        if (*p == '+')
                p++;

        return path_is_absolute(p);
}

static char *resolve_source_path(const char *dest, const char *source) {

        if (!source)
                return NULL;

        if (source[0] == '+')
                return prefix_root(dest, source + 1);

        return strdup(source);
}

int custom_mount_prepare_all(const char *dest, CustomMount *l, size_t n) {
        size_t i;
        int r;

        /* Prepare all custom mounts. This will make source we know all temporary directories. This is called in the
         * parent process, so that we know the temporary directories to remove on exit before we fork off the
         * children. */

        assert(l || n == 0);

        /* Order the custom mounts, and make sure we have a working directory */
        qsort_safe(l, n, sizeof(CustomMount), custom_mount_compare);

        for (i = 0; i < n; i++) {
                CustomMount *m = l + i;

                if (m->source) {
                        char *s;

                        s = resolve_source_path(dest, m->source);
                        if (!s)
                                return log_oom();

                        free_and_replace(m->source, s);
                } else {
                        /* No source specified? In that case, use a throw-away temporary directory in /var/tmp */

                        m->rm_rf_tmpdir = strdup("/var/tmp/nspawn-temp-XXXXXX");
                        if (!m->rm_rf_tmpdir)
                                return log_oom();

                        if (!mkdtemp(m->rm_rf_tmpdir)) {
                                m->rm_rf_tmpdir = mfree(m->rm_rf_tmpdir);
                                return log_error_errno(errno, "Failed to acquire temporary directory: %m");
                        }

                        m->source = strjoin(m->rm_rf_tmpdir, "/src");
                        if (!m->source)
                                return log_oom();

                        if (mkdir(m->source, 0755) < 0)
                                return log_error_errno(errno, "Failed to create %s: %m", m->source);
                }

                if (m->type == CUSTOM_MOUNT_OVERLAY) {
                        char **j;

                        STRV_FOREACH(j, m->lower) {
                                char *s;

                                s = resolve_source_path(dest, *j);
                                if (!s)
                                        return log_oom();

                                free_and_replace(*j, s);
                        }

                        if (m->work_dir) {
                                char *s;

                                s = resolve_source_path(dest, m->work_dir);
                                if (!s)
                                        return log_oom();

                                free_and_replace(m->work_dir, s);
                        } else {
                                assert(m->source);

                                r = tempfn_random(m->source, NULL, &m->work_dir);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to acquire working directory: %m");
                        }

                        (void) mkdir_label(m->work_dir, 0700);
                }
        }

        return 0;
}

int bind_mount_parse(CustomMount **l, size_t *n, const char *s, bool read_only) {
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
                destination = strdup(source[0] == '+' ? source+1 : source);
                if (!destination)
                        return -ENOMEM;
        }
        if (r == 2 && !isempty(p)) {
                opts = strdup(p);
                if (!opts)
                        return -ENOMEM;
        }

        if (isempty(source))
                source = NULL;
        else if (!source_path_is_valid(source))
                return -EINVAL;

        if (!path_is_absolute(destination))
                return -EINVAL;

        m = custom_mount_add(l, n, CUSTOM_MOUNT_BIND);
        if (!m)
                return -ENOMEM;

        m->source = source;
        m->destination = destination;
        m->read_only = read_only;
        m->options = opts;

        source = destination = opts = NULL;
        return 0;
}

int tmpfs_mount_parse(CustomMount **l, size_t *n, const char *s) {
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

        m->destination = TAKE_PTR(path);
        m->options = TAKE_PTR(opts);

        return 0;
}

int overlay_mount_parse(CustomMount **l, size_t *n, const char *s, bool read_only) {
        _cleanup_free_ char *upper = NULL, *destination = NULL;
        _cleanup_strv_free_ char **lower = NULL;
        CustomMount *m;
        int k;

        k = strv_split_extract(&lower, s, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
        if (k < 0)
                return k;
        if (k < 2)
                return -EADDRNOTAVAIL;
        if (k == 2) {
                /* If two parameters are specified, the first one is the lower, the second one the upper directory. And
                 * we'll also define the destination mount point the same as the upper. */

                if (!source_path_is_valid(lower[0]) ||
                    !source_path_is_valid(lower[1]))
                        return -EINVAL;

                upper = TAKE_PTR(lower[1]);

                destination = strdup(upper[0] == '+' ? upper+1 : upper); /* take the destination without "+" prefix */
                if (!destination)
                        return -ENOMEM;
        } else {
                char **i;

                /* If more than two parameters are specified, the last one is the destination, the second to last one
                 * the "upper", and all before that the "lower" directories. */

                destination = lower[k - 1];
                upper = TAKE_PTR(lower[k - 2]);

                STRV_FOREACH(i, lower)
                        if (!source_path_is_valid(*i))
                                return -EINVAL;

                /* If the upper directory is unspecified, then let's create it automatically as a throw-away directory
                 * in /var/tmp */
                if (isempty(upper))
                        upper = NULL;
                else if (!source_path_is_valid(upper))
                        return -EINVAL;

                if (!path_is_absolute(destination))
                        return -EINVAL;
        }

        m = custom_mount_add(l, n, CUSTOM_MOUNT_OVERLAY);
        if (!m)
                return -ENOMEM;

        m->destination = TAKE_PTR(destination);
        m->source = TAKE_PTR(upper);
        m->lower = TAKE_PTR(lower);
        m->read_only = read_only;

        return 0;
}

static int tmpfs_patch_options(
                const char *options,
                bool userns,
                uid_t uid_shift, uid_t uid_range,
                bool patch_ids,
                const char *selinux_apifs_context,
                char **ret) {

        char *buf = NULL;

        if ((userns && uid_shift != 0) || patch_ids) {
                assert(uid_shift != UID_INVALID);

                if (asprintf(&buf, "%s%suid=" UID_FMT ",gid=" UID_FMT,
                             strempty(options), options ? "," : "",
                             uid_shift, uid_shift) < 0)
                        return -ENOMEM;

                options = buf;
        }

#if HAVE_SELINUX
        if (selinux_apifs_context) {
                char *t;

                t = strjoin(strempty(options), options ? "," : "",
                            "context=\"", selinux_apifs_context, "\"");
                free(buf);
                if (!t)
                        return -ENOMEM;

                buf = t;
        }
#endif

        if (!buf && options) {
                buf = strdup(options);
                if (!buf)
                        return -ENOMEM;
        }
        *ret = buf;

        return !!buf;
}

int mount_sysfs(const char *dest, MountSettingsMask mount_settings) {
        const char *full, *top, *x;
        int r;
        unsigned long extra_flags = 0;

        top = prefix_roota(dest, "/sys");
        r = path_is_fs_type(top, SYSFS_MAGIC);
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

        if (mount_settings & MOUNT_APPLY_APIVFS_RO)
                extra_flags |= MS_RDONLY;

        r = mount_verbose(LOG_ERR, "sysfs", full, "sysfs",
                          MS_NOSUID|MS_NOEXEC|MS_NODEV|extra_flags, NULL);
        if (r < 0)
                return r;

        FOREACH_STRING(x, "block", "bus", "class", "dev", "devices", "kernel") {
                _cleanup_free_ char *from = NULL, *to = NULL;

                from = prefix_root(full, x);
                if (!from)
                        return log_oom();

                to = prefix_root(top, x);
                if (!to)
                        return log_oom();

                (void) mkdir(to, 0755);

                r = mount_verbose(LOG_ERR, from, to, NULL, MS_BIND, NULL);
                if (r < 0)
                        return r;

                r = mount_verbose(LOG_ERR, NULL, to, NULL,
                                  MS_BIND|MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_REMOUNT|extra_flags, NULL);
                if (r < 0)
                        return r;
        }

        r = umount_verbose(full);
        if (r < 0)
                return r;

        if (rmdir(full) < 0)
                return log_error_errno(errno, "Failed to remove %s: %m", full);

        /* Create mountpoint for cgroups. Otherwise we are not allowed since we
         * remount /sys read-only.
         */
        if (cg_ns_supported()) {
                x = prefix_roota(top, "/fs/cgroup");
                (void) mkdir_p(x, 0755);
        }

        return mount_verbose(LOG_ERR, NULL, top, NULL,
                             MS_BIND|MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_REMOUNT|extra_flags, NULL);
}

static int mkdir_userns(const char *path, mode_t mode, uid_t uid_shift) {
        int r;

        assert(path);

        r = mkdir_errno_wrapper(path, mode);
        if (r < 0 && r != -EEXIST)
                return r;

        if (uid_shift == UID_INVALID)
                return 0;

        if (lchown(path, uid_shift, uid_shift) < 0)
                return -errno;

        return 0;
}

static int mkdir_userns_p(const char *prefix, const char *path, mode_t mode, uid_t uid_shift) {
        const char *p, *e;
        int r;

        assert(path);

        if (prefix && !path_startswith(path, prefix))
                return -ENOTDIR;

        /* create every parent directory in the path, except the last component */
        p = path + strspn(path, "/");
        for (;;) {
                char t[strlen(path) + 1];

                e = p + strcspn(p, "/");
                p = e + strspn(e, "/");

                /* Is this the last component? If so, then we're done */
                if (*p == 0)
                        break;

                memcpy(t, path, e - path);
                t[e-path] = 0;

                if (prefix && path_startswith(prefix, t))
                        continue;

                r = mkdir_userns(t, mode, uid_shift);
                if (r < 0)
                        return r;
        }

        return mkdir_userns(path, mode, uid_shift);
}

int mount_all(const char *dest,
              MountSettingsMask mount_settings,
              uid_t uid_shift, uid_t uid_range,
              const char *selinux_apifs_context) {

#define PROC_INACCESSIBLE(path)                                         \
        { NULL, (path), NULL, NULL, MS_BIND,                            \
          MOUNT_IN_USERNS|MOUNT_APPLY_APIVFS_RO|MOUNT_INACCESSIBLE_REG }, /* Bind mount first ... */ \
        { NULL, (path), NULL, NULL, MS_BIND|MS_RDONLY|MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_REMOUNT, \
          MOUNT_IN_USERNS|MOUNT_APPLY_APIVFS_RO } /* Then, make it r/o */

#define PROC_READ_ONLY(path)                                            \
        { (path), (path), NULL, NULL, MS_BIND,                          \
          MOUNT_IN_USERNS|MOUNT_APPLY_APIVFS_RO }, /* Bind mount first ... */ \
        { NULL,   (path), NULL, NULL, MS_BIND|MS_RDONLY|MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_REMOUNT, \
          MOUNT_IN_USERNS|MOUNT_APPLY_APIVFS_RO } /* Then, make it r/o */

        typedef struct MountPoint {
                const char *what;
                const char *where;
                const char *type;
                const char *options;
                unsigned long flags;
                MountSettingsMask mount_settings;
        } MountPoint;

        static const MountPoint mount_table[] = {
                /* First we list inner child mounts (i.e. mounts applied *after* entering user namespacing) */
                { "proc",            "/proc",           "proc",  NULL,        MS_NOSUID|MS_NOEXEC|MS_NODEV,
                  MOUNT_FATAL|MOUNT_IN_USERNS },

                { "/proc/sys",       "/proc/sys",       NULL,    NULL,        MS_BIND,
                  MOUNT_FATAL|MOUNT_IN_USERNS|MOUNT_APPLY_APIVFS_RO },                          /* Bind mount first ... */

                { "/proc/sys/net",   "/proc/sys/net",   NULL,    NULL,        MS_BIND,
                  MOUNT_FATAL|MOUNT_IN_USERNS|MOUNT_APPLY_APIVFS_RO|MOUNT_APPLY_APIVFS_NETNS }, /* (except for this) */

                { NULL,              "/proc/sys",       NULL,    NULL,        MS_BIND|MS_RDONLY|MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_REMOUNT,
                  MOUNT_FATAL|MOUNT_IN_USERNS|MOUNT_APPLY_APIVFS_RO },                          /* ... then, make it r/o */

                /* Make these files inaccessible to container payloads: they potentially leak information about kernel
                 * internals or the host's execution environment to the container */
                PROC_INACCESSIBLE("/proc/kallsyms"),
                PROC_INACCESSIBLE("/proc/kcore"),
                PROC_INACCESSIBLE("/proc/keys"),
                PROC_INACCESSIBLE("/proc/sysrq-trigger"),
                PROC_INACCESSIBLE("/proc/timer_list"),

                /* Make these directories read-only to container payloads: they show hardware information, and in some
                 * cases contain tunables the container really shouldn't have access to. */
                PROC_READ_ONLY("/proc/acpi"),
                PROC_READ_ONLY("/proc/apm"),
                PROC_READ_ONLY("/proc/asound"),
                PROC_READ_ONLY("/proc/bus"),
                PROC_READ_ONLY("/proc/fs"),
                PROC_READ_ONLY("/proc/irq"),
                PROC_READ_ONLY("/proc/scsi"),

                /* Then we list outer child mounts (i.e. mounts applied *before* entering user namespacing) */
                { "tmpfs",           "/tmp",            "tmpfs", "mode=1777", MS_NOSUID|MS_NODEV|MS_STRICTATIME,
                  MOUNT_FATAL },
                { "tmpfs",           "/sys",            "tmpfs", "mode=755",  MS_NOSUID|MS_NOEXEC|MS_NODEV,
                  MOUNT_FATAL|MOUNT_APPLY_APIVFS_NETNS },
                { "sysfs",           "/sys",            "sysfs", NULL,        MS_RDONLY|MS_NOSUID|MS_NOEXEC|MS_NODEV,
                  MOUNT_FATAL|MOUNT_APPLY_APIVFS_RO },    /* skipped if above was mounted */
                { "sysfs",           "/sys",            "sysfs", NULL,        MS_NOSUID|MS_NOEXEC|MS_NODEV,
                  MOUNT_FATAL },                          /* skipped if above was mounted */
                { "tmpfs",           "/dev",            "tmpfs", "mode=755",  MS_NOSUID|MS_STRICTATIME,
                  MOUNT_FATAL },
                { "tmpfs",           "/dev/shm",        "tmpfs", "mode=1777", MS_NOSUID|MS_NODEV|MS_STRICTATIME,
                  MOUNT_FATAL },
                { "tmpfs",           "/run",            "tmpfs", "mode=755",  MS_NOSUID|MS_NODEV|MS_STRICTATIME,
                  MOUNT_FATAL },

#if HAVE_SELINUX
                { "/sys/fs/selinux", "/sys/fs/selinux", NULL,    NULL,        MS_BIND,
                  0 },  /* Bind mount first */
                { NULL,              "/sys/fs/selinux", NULL,    NULL,        MS_BIND|MS_RDONLY|MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_REMOUNT,
                  0 },  /* Then, make it r/o */
#endif
        };

        _cleanup_(unlink_and_freep) char *inaccessible = NULL;
        bool use_userns = (mount_settings & MOUNT_USE_USERNS);
        bool netns = (mount_settings & MOUNT_APPLY_APIVFS_NETNS);
        bool ro = (mount_settings & MOUNT_APPLY_APIVFS_RO);
        bool in_userns = (mount_settings & MOUNT_IN_USERNS);
        size_t k;
        int r;

        for (k = 0; k < ELEMENTSOF(mount_table); k++) {
                _cleanup_free_ char *where = NULL, *options = NULL;
                const char *o, *what;
                bool fatal = (mount_table[k].mount_settings & MOUNT_FATAL);

                if (in_userns != (bool)(mount_table[k].mount_settings & MOUNT_IN_USERNS))
                        continue;

                if (!netns && (bool)(mount_table[k].mount_settings & MOUNT_APPLY_APIVFS_NETNS))
                        continue;

                if (!ro && (bool)(mount_table[k].mount_settings & MOUNT_APPLY_APIVFS_RO))
                        continue;

                r = chase_symlinks(mount_table[k].where, dest, CHASE_NONEXISTENT|CHASE_PREFIX_ROOT, &where);
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve %s/%s: %m", dest, mount_table[k].where);

                if (mount_table[k].mount_settings & MOUNT_INACCESSIBLE_REG) {

                        if (!inaccessible) {
                                _cleanup_free_ char *np = NULL;

                                r = tempfn_random_child(NULL, "inaccessible", &np);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to generate inaccessible file node path: %m");

                                r = touch_file(np, false, USEC_INFINITY, UID_INVALID, GID_INVALID, 0000);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to create inaccessible file node '%s': %m", np);

                                inaccessible = TAKE_PTR(np);
                        }

                        what = inaccessible;
                } else
                        what = mount_table[k].what;

                r = path_is_mount_point(where, NULL, 0);
                if (r < 0 && r != -ENOENT)
                        return log_error_errno(r, "Failed to detect whether %s is a mount point: %m", where);

                /* Skip this entry if it is not a remount. */
                if (what && r > 0)
                        continue;

                r = mkdir_userns_p(dest, where, 0755, (use_userns && !in_userns) ? uid_shift : UID_INVALID);
                if (r < 0 && r != -EEXIST) {
                        if (fatal && r != -EROFS)
                                return log_error_errno(r, "Failed to create directory %s: %m", where);

                        log_debug_errno(r, "Failed to create directory %s: %m", where);
                        /* If we failed mkdir() or chown() due to the root
                         * directory being read only, attempt to mount this fs
                         * anyway and let mount_verbose log any errors */
                        if (r != -EROFS)
                                continue;
                }

                o = mount_table[k].options;
                if (streq_ptr(mount_table[k].type, "tmpfs")) {
                        if (in_userns)
                                r = tmpfs_patch_options(o, use_userns, 0, uid_range, true, selinux_apifs_context, &options);
                        else
                                r = tmpfs_patch_options(o, use_userns, uid_shift, uid_range, false, selinux_apifs_context, &options);
                        if (r < 0)
                                return log_oom();
                        if (r > 0)
                                o = options;
                }

                r = mount_verbose(fatal ? LOG_ERR : LOG_DEBUG,
                                  what,
                                  where,
                                  mount_table[k].type,
                                  mount_table[k].flags,
                                  o);
                if (r < 0 && fatal)
                        return r;
        }

        return 0;
}

static int mount_bind(const char *dest, CustomMount *m) {

        _cleanup_free_ char *where = NULL;
        struct stat source_st, dest_st;
        int r;

        assert(dest);
        assert(m);

        if (stat(m->source, &source_st) < 0)
                return log_error_errno(errno, "Failed to stat %s: %m", m->source);

        r = chase_symlinks(m->destination, dest, CHASE_PREFIX_ROOT|CHASE_NONEXISTENT, &where);
        if (r < 0)
                return log_error_errno(r, "Failed to resolve %s/%s: %m", dest, m->destination);
        if (r > 0) { /* Path exists already? */

                if (stat(where, &dest_st) < 0)
                        return log_error_errno(errno, "Failed to stat %s: %m", where);

                if (S_ISDIR(source_st.st_mode) && !S_ISDIR(dest_st.st_mode)) {
                        log_error("Cannot bind mount directory %s on file %s.", m->source, where);
                        return -EINVAL;
                }

                if (!S_ISDIR(source_st.st_mode) && S_ISDIR(dest_st.st_mode)) {
                        log_error("Cannot bind mount file %s on directory %s.", m->source, where);
                        return -EINVAL;
                }

        } else { /* Path doesn't exist yet? */
                r = mkdir_parents_label(where, 0755);
                if (r < 0)
                        return log_error_errno(r, "Failed to make parents of %s: %m", where);

                /* Create the mount point. Any non-directory file can be
                * mounted on any non-directory file (regular, fifo, socket,
                * char, block).
                */
                if (S_ISDIR(source_st.st_mode))
                        r = mkdir_label(where, 0755);
                else
                        r = touch(where);
                if (r < 0)
                        return log_error_errno(r, "Failed to create mount point %s: %m", where);

        }

        r = mount_verbose(LOG_ERR, m->source, where, NULL, MS_BIND | MS_REC, m->options);
        if (r < 0)
                return r;

        if (m->read_only) {
                r = bind_remount_recursive(where, true, NULL);
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

        const char *options;
        _cleanup_free_ char *buf = NULL, *where = NULL;
        int r;

        assert(dest);
        assert(m);

        r = chase_symlinks(m->destination, dest, CHASE_PREFIX_ROOT|CHASE_NONEXISTENT, &where);
        if (r < 0)
                return log_error_errno(r, "Failed to resolve %s/%s: %m", dest, m->destination);
        if (r == 0) { /* Doesn't exist yet? */
                r = mkdir_p_label(where, 0755);
                if (r < 0)
                        return log_error_errno(r, "Creating mount point for tmpfs %s failed: %m", where);
        }

        r = tmpfs_patch_options(m->options, userns, uid_shift, uid_range, false, selinux_apifs_context, &buf);
        if (r < 0)
                return log_oom();
        options = r > 0 ? buf : m->options;

        return mount_verbose(LOG_ERR, "tmpfs", where, "tmpfs", MS_NODEV|MS_STRICTATIME, options);
}

static char *joined_and_escaped_lower_dirs(char **lower) {
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

        _cleanup_free_ char *lower = NULL, *where = NULL, *escaped_source = NULL;
        const char *options;
        int r;

        assert(dest);
        assert(m);

        r = chase_symlinks(m->destination, dest, CHASE_PREFIX_ROOT|CHASE_NONEXISTENT, &where);
        if (r < 0)
                return log_error_errno(r, "Failed to resolve %s/%s: %m", dest, m->destination);
        if (r == 0) { /* Doesn't exist yet? */
                r = mkdir_label(where, 0755);
                if (r < 0)
                        return log_error_errno(r, "Creating mount point for overlay %s failed: %m", where);
        }

        (void) mkdir_p_label(m->source, 0755);

        lower = joined_and_escaped_lower_dirs(m->lower);
        if (!lower)
                return log_oom();

        escaped_source = shell_escape(m->source, ",:");
        if (!escaped_source)
                return log_oom();

        if (m->read_only)
                options = strjoina("lowerdir=", escaped_source, ":", lower);
        else {
                _cleanup_free_ char *escaped_work_dir = NULL;

                escaped_work_dir = shell_escape(m->work_dir, ",:");
                if (!escaped_work_dir)
                        return log_oom();

                options = strjoina("lowerdir=", lower, ",upperdir=", escaped_source, ",workdir=", escaped_work_dir);
        }

        return mount_verbose(LOG_ERR, "overlay", where, "overlay", m->read_only ? MS_RDONLY : 0, options);
}

int mount_custom(
                const char *dest,
                CustomMount *mounts, size_t n,
                bool userns, uid_t uid_shift, uid_t uid_range,
                const char *selinux_apifs_context) {

        size_t i;
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

/* Retrieve existing subsystems. This function is called in a new cgroup
 * namespace.
 */
static int get_process_controllers(Set **ret) {
        _cleanup_set_free_free_ Set *controllers = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(ret);

        controllers = set_new(&string_hash_ops);
        if (!controllers)
                return -ENOMEM;

        f = fopen("/proc/self/cgroup", "re");
        if (!f)
                return errno == ENOENT ? -ESRCH : -errno;

        for (;;) {
                _cleanup_free_ char *line = NULL;
                char *e, *l;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                l = strchr(line, ':');
                if (!l)
                        continue;

                l++;
                e = strchr(l, ':');
                if (!e)
                        continue;

                *e = 0;

                if (STR_IN_SET(l, "", "name=systemd", "name=unified"))
                        continue;

                r = set_put_strdup(controllers, l);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(controllers);

        return 0;
}

static int mount_legacy_cgroup_hierarchy(
                const char *dest,
                const char *controller,
                const char *hierarchy,
                bool read_only) {

        const char *to, *fstype, *opts;
        int r;

        to = strjoina(strempty(dest), "/sys/fs/cgroup/", hierarchy);

        r = path_is_mount_point(to, dest, 0);
        if (r < 0 && r != -ENOENT)
                return log_error_errno(r, "Failed to determine if %s is mounted already: %m", to);
        if (r > 0)
                return 0;

        mkdir_p(to, 0755);

        /* The superblock mount options of the mount point need to be
         * identical to the hosts', and hence writable... */
        if (streq(controller, SYSTEMD_CGROUP_CONTROLLER_HYBRID)) {
                fstype = "cgroup2";
                opts = NULL;
        } else if (streq(controller, SYSTEMD_CGROUP_CONTROLLER_LEGACY)) {
                fstype = "cgroup";
                opts = "none,name=systemd,xattr";
        } else {
                fstype = "cgroup";
                opts = controller;
        }

        r = mount_verbose(LOG_ERR, "cgroup", to, fstype, MS_NOSUID|MS_NOEXEC|MS_NODEV, opts);
        if (r < 0)
                return r;

        /* ... hence let's only make the bind mount read-only, not the superblock. */
        if (read_only) {
                r = mount_verbose(LOG_ERR, NULL, to, NULL,
                                  MS_BIND|MS_REMOUNT|MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_RDONLY, NULL);
                if (r < 0)
                        return r;
        }

        return 1;
}

/* Mount a legacy cgroup hierarchy when cgroup namespaces are supported. */
static int mount_legacy_cgns_supported(
                const char *dest,
                CGroupUnified unified_requested,
                bool userns,
                uid_t uid_shift,
                uid_t uid_range,
                const char *selinux_apifs_context) {

        _cleanup_set_free_free_ Set *controllers = NULL;
        const char *cgroup_root = "/sys/fs/cgroup", *c;
        int r;

        (void) mkdir_p(cgroup_root, 0755);

        /* Mount a tmpfs to /sys/fs/cgroup if it's not mounted there yet. */
        r = path_is_mount_point(cgroup_root, dest, AT_SYMLINK_FOLLOW);
        if (r < 0)
                return log_error_errno(r, "Failed to determine if /sys/fs/cgroup is already mounted: %m");
        if (r == 0) {
                _cleanup_free_ char *options = NULL;

                /* When cgroup namespaces are enabled and user namespaces are
                 * used then the mount of the cgroupfs is done *inside* the new
                 * user namespace. We're root in the new user namespace and the
                 * kernel will happily translate our uid/gid to the correct
                 * uid/gid as seen from e.g. /proc/1/mountinfo. So we simply
                 * pass uid 0 and not uid_shift to tmpfs_patch_options().
                 */
                r = tmpfs_patch_options("mode=755", userns, 0, uid_range, true, selinux_apifs_context, &options);
                if (r < 0)
                        return log_oom();

                r = mount_verbose(LOG_ERR, "tmpfs", cgroup_root, "tmpfs",
                                  MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_STRICTATIME, options);
                if (r < 0)
                        return r;
        }

        r = cg_all_unified();
        if (r < 0)
                return r;
        if (r > 0)
                goto skip_controllers;

        r = get_process_controllers(&controllers);
        if (r < 0)
                return log_error_errno(r, "Failed to determine cgroup controllers: %m");

        for (;;) {
                _cleanup_free_ const char *controller = NULL;

                controller = set_steal_first(controllers);
                if (!controller)
                        break;

                r = mount_legacy_cgroup_hierarchy("", controller, controller, !userns);
                if (r < 0)
                        return r;

                /* When multiple hierarchies are co-mounted, make their
                 * constituting individual hierarchies a symlink to the
                 * co-mount.
                 */
                c = controller;
                for (;;) {
                        _cleanup_free_ char *target = NULL, *tok = NULL;

                        r = extract_first_word(&c, &tok, ",", 0);
                        if (r < 0)
                                return log_error_errno(r, "Failed to extract co-mounted cgroup controller: %m");
                        if (r == 0)
                                break;

                        if (streq(controller, tok))
                                break;

                        target = prefix_root("/sys/fs/cgroup/", tok);
                        if (!target)
                                return log_oom();

                        r = symlink_idempotent(controller, target);
                        if (r == -EINVAL)
                                return log_error_errno(r, "Invalid existing symlink for combined hierarchy: %m");
                        if (r < 0)
                                return log_error_errno(r, "Failed to create symlink for combined hierarchy: %m");
                }
        }

skip_controllers:
        if (unified_requested >= CGROUP_UNIFIED_SYSTEMD) {
                r = mount_legacy_cgroup_hierarchy("", SYSTEMD_CGROUP_CONTROLLER_HYBRID, "unified", false);
                if (r < 0)
                        return r;
        }

        r = mount_legacy_cgroup_hierarchy("", SYSTEMD_CGROUP_CONTROLLER_LEGACY, "systemd", false);
        if (r < 0)
                return r;

        if (!userns)
                return mount_verbose(LOG_ERR, NULL, cgroup_root, NULL,
                                     MS_REMOUNT|MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_STRICTATIME|MS_RDONLY, "mode=755");

        return 0;
}

/* Mount legacy cgroup hierarchy when cgroup namespaces are unsupported. */
static int mount_legacy_cgns_unsupported(
                const char *dest,
                CGroupUnified unified_requested,
                bool userns,
                uid_t uid_shift,
                uid_t uid_range,
                const char *selinux_apifs_context) {

        _cleanup_set_free_free_ Set *controllers = NULL;
        const char *cgroup_root;
        int r;

        cgroup_root = prefix_roota(dest, "/sys/fs/cgroup");

        (void) mkdir_p(cgroup_root, 0755);

        /* Mount a tmpfs to /sys/fs/cgroup if it's not mounted there yet. */
        r = path_is_mount_point(cgroup_root, dest, AT_SYMLINK_FOLLOW);
        if (r < 0)
                return log_error_errno(r, "Failed to determine if /sys/fs/cgroup is already mounted: %m");
        if (r == 0) {
                _cleanup_free_ char *options = NULL;

                r = tmpfs_patch_options("mode=755", userns, uid_shift, uid_range, false, selinux_apifs_context, &options);
                if (r < 0)
                        return log_oom();

                r = mount_verbose(LOG_ERR, "tmpfs", cgroup_root, "tmpfs",
                                  MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_STRICTATIME, options);
                if (r < 0)
                        return r;
        }

        r = cg_all_unified();
        if (r < 0)
                return r;
        if (r > 0)
                goto skip_controllers;

        r = cg_kernel_controllers(&controllers);
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
                        if (r == -EINVAL)
                                return log_error_errno(r, "Invalid existing symlink for combined hierarchy: %m");
                        if (r < 0)
                                return log_error_errno(r, "Failed to create symlink for combined hierarchy: %m");
                }
        }

skip_controllers:
        if (unified_requested >= CGROUP_UNIFIED_SYSTEMD) {
                r = mount_legacy_cgroup_hierarchy(dest, SYSTEMD_CGROUP_CONTROLLER_HYBRID, "unified", false);
                if (r < 0)
                        return r;
        }

        r = mount_legacy_cgroup_hierarchy(dest, SYSTEMD_CGROUP_CONTROLLER_LEGACY, "systemd", false);
        if (r < 0)
                return r;

        return mount_verbose(LOG_ERR, NULL, cgroup_root, NULL,
                             MS_REMOUNT|MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_STRICTATIME|MS_RDONLY, "mode=755");
}

static int mount_unified_cgroups(const char *dest) {
        const char *p;
        int r;

        assert(dest);

        p = prefix_roota(dest, "/sys/fs/cgroup");

        (void) mkdir_p(p, 0755);

        r = path_is_mount_point(p, dest, AT_SYMLINK_FOLLOW);
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

        return mount_verbose(LOG_ERR, "cgroup", p, "cgroup2", MS_NOSUID|MS_NOEXEC|MS_NODEV, NULL);
}

int mount_cgroups(
                const char *dest,
                CGroupUnified unified_requested,
                bool userns,
                uid_t uid_shift,
                uid_t uid_range,
                const char *selinux_apifs_context,
                bool use_cgns) {

        if (unified_requested >= CGROUP_UNIFIED_ALL)
                return mount_unified_cgroups(dest);
        if (use_cgns)
                return mount_legacy_cgns_supported(dest, unified_requested, userns, uid_shift, uid_range, selinux_apifs_context);

        return mount_legacy_cgns_unsupported(dest, unified_requested, userns, uid_shift, uid_range, selinux_apifs_context);
}

static int mount_systemd_cgroup_writable_one(const char *root, const char *own) {
        int r;

        assert(root);
        assert(own);

        /* Make our own cgroup a (writable) bind mount */
        r = mount_verbose(LOG_ERR, own, own, NULL, MS_BIND, NULL);
        if (r < 0)
                return r;

        /* And then remount the systemd cgroup root read-only */
        return mount_verbose(LOG_ERR, NULL, root, NULL,
                             MS_BIND|MS_REMOUNT|MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_RDONLY, NULL);
}

int mount_systemd_cgroup_writable(
                const char *dest,
                CGroupUnified unified_requested) {

        _cleanup_free_ char *own_cgroup_path = NULL;
        const char *root, *own;
        int r;

        assert(dest);

        r = cg_pid_get_path(NULL, 0, &own_cgroup_path);
        if (r < 0)
                return log_error_errno(r, "Failed to determine our own cgroup path: %m");

        /* If we are living in the top-level, then there's nothing to do... */
        if (path_equal(own_cgroup_path, "/"))
                return 0;

        if (unified_requested >= CGROUP_UNIFIED_ALL) {

                root = prefix_roota(dest, "/sys/fs/cgroup");
                own = strjoina(root, own_cgroup_path);

        } else {

                if (unified_requested >= CGROUP_UNIFIED_SYSTEMD) {
                        root = prefix_roota(dest, "/sys/fs/cgroup/unified");
                        own = strjoina(root, own_cgroup_path);

                        r = mount_systemd_cgroup_writable_one(root, own);
                        if (r < 0)
                                return r;
                }

                root = prefix_roota(dest, "/sys/fs/cgroup/systemd");
                own = strjoina(root, own_cgroup_path);
        }

        return mount_systemd_cgroup_writable_one(root, own);
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

        r = bind_remount_recursive(directory, true, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to remount %s read-only: %m", directory);

        p = prefix_roota(directory, "/var");
        r = mkdir(p, 0755);
        if (r < 0 && errno != EEXIST)
                return log_error_errno(errno, "Failed to create %s: %m", directory);

        options = "mode=755";
        r = tmpfs_patch_options(options, userns, uid_shift, uid_range, false, selinux_apifs_context, &buf);
        if (r < 0)
                return log_oom();
        if (r > 0)
                options = buf;

        return mount_verbose(LOG_ERR, "tmpfs", p, "tmpfs", MS_STRICTATIME, options);
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
        r = tmpfs_patch_options(options, userns, uid_shift, uid_range, false, selinux_apifs_context, &buf);
        if (r < 0)
                return log_oom();
        if (r > 0)
                options = buf;

        r = mount_verbose(LOG_ERR, "tmpfs", template, "tmpfs", MS_STRICTATIME, options);
        if (r < 0)
                goto fail;

        tmpfs_mounted = true;

        f = prefix_roota(directory, "/usr");
        t = prefix_roota(template, "/usr");

        r = mkdir(t, 0755);
        if (r < 0 && errno != EEXIST) {
                r = log_error_errno(errno, "Failed to create %s: %m", t);
                goto fail;
        }

        r = mount_verbose(LOG_ERR, f, t, NULL, MS_BIND|MS_REC, NULL);
        if (r < 0)
                goto fail;

        bind_mounted = true;

        r = bind_remount_recursive(t, true, NULL);
        if (r < 0) {
                log_error_errno(r, "Failed to remount %s read-only: %m", t);
                goto fail;
        }

        r = mount_verbose(LOG_ERR, template, directory, NULL, MS_MOVE, NULL);
        if (r < 0)
                goto fail;

        (void) rmdir(template);

        return 0;

fail:
        if (bind_mounted)
                (void) umount_verbose(t);

        if (tmpfs_mounted)
                (void) umount_verbose(template);
        (void) rmdir(template);
        return r;
}

/* Expects *pivot_root_new and *pivot_root_old to be initialised to allocated memory or NULL. */
int pivot_root_parse(char **pivot_root_new, char **pivot_root_old, const char *s) {
        _cleanup_free_ char *root_new = NULL, *root_old = NULL;
        const char *p = s;
        int r;

        assert(pivot_root_new);
        assert(pivot_root_old);

        r = extract_first_word(&p, &root_new, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
        if (r < 0)
                return r;
        if (r == 0)
                return -EINVAL;

        if (isempty(p))
                root_old = NULL;
        else {
                root_old = strdup(p);
                if (!root_old)
                        return -ENOMEM;
        }

        if (!path_is_absolute(root_new))
                return -EINVAL;
        if (root_old && !path_is_absolute(root_old))
                return -EINVAL;

        free_and_replace(*pivot_root_new, root_new);
        free_and_replace(*pivot_root_old, root_old);

        return 0;
}

int setup_pivot_root(const char *directory, const char *pivot_root_new, const char *pivot_root_old) {
        _cleanup_free_ char *directory_pivot_root_new = NULL;
        _cleanup_free_ char *pivot_tmp_pivot_root_old = NULL;
        char pivot_tmp[] = "/tmp/nspawn-pivot-XXXXXX";
        bool remove_pivot_tmp = false;
        int r;

        assert(directory);

        if (!pivot_root_new)
                return 0;

        /* Pivot pivot_root_new to / and the existing / to pivot_root_old.
         * If pivot_root_old is NULL, the existing / disappears.
         * This requires a temporary directory, pivot_tmp, which is
         * not a child of either.
         *
         * This is typically used for OSTree-style containers, where
         * the root partition contains several sysroots which could be
         * run. Normally, one would be chosen by the bootloader and
         * pivoted to / by initramfs.
         *
         * For example, for an OSTree deployment, pivot_root_new
         * would be: /ostree/deploy/$os/deploy/$checksum. Note that this
         * code doesn’t do the /var mount which OSTree expects: use
         * --bind +/sysroot/ostree/deploy/$os/var:/var for that.
         *
         * So in the OSTree case, we’ll end up with something like:
         *  - directory = /tmp/nspawn-root-123456
         *  - pivot_root_new = /ostree/deploy/os/deploy/123abc
         *  - pivot_root_old = /sysroot
         *  - directory_pivot_root_new =
         *       /tmp/nspawn-root-123456/ostree/deploy/os/deploy/123abc
         *  - pivot_tmp = /tmp/nspawn-pivot-123456
         *  - pivot_tmp_pivot_root_old = /tmp/nspawn-pivot-123456/sysroot
         *
         * Requires all file systems at directory and below to be mounted
         * MS_PRIVATE or MS_SLAVE so they can be moved.
         */
        directory_pivot_root_new = prefix_root(directory, pivot_root_new);

        /* Remount directory_pivot_root_new to make it movable. */
        r = mount_verbose(LOG_ERR, directory_pivot_root_new, directory_pivot_root_new, NULL, MS_BIND, NULL);
        if (r < 0)
                goto done;

        if (pivot_root_old) {
                if (!mkdtemp(pivot_tmp)) {
                        r = log_error_errno(errno, "Failed to create temporary directory: %m");
                        goto done;
                }

                remove_pivot_tmp = true;
                pivot_tmp_pivot_root_old = prefix_root(pivot_tmp, pivot_root_old);

                r = mount_verbose(LOG_ERR, directory_pivot_root_new, pivot_tmp, NULL, MS_MOVE, NULL);
                if (r < 0)
                        goto done;

                r = mount_verbose(LOG_ERR, directory, pivot_tmp_pivot_root_old, NULL, MS_MOVE, NULL);
                if (r < 0)
                        goto done;

                r = mount_verbose(LOG_ERR, pivot_tmp, directory, NULL, MS_MOVE, NULL);
                if (r < 0)
                        goto done;
        } else {
                r = mount_verbose(LOG_ERR, directory_pivot_root_new, directory, NULL, MS_MOVE, NULL);
                if (r < 0)
                        goto done;
        }

done:
        if (remove_pivot_tmp)
                (void) rmdir(pivot_tmp);

        return r;
}
