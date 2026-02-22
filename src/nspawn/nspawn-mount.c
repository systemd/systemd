/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/magic.h>
#include <sched.h>
#include <sys/mount.h>
#include <unistd.h>

#include "alloc-util.h"
#include "chase.h"
#include "errno-util.h"
#include "escape.h"
#include "extract-word.h"
#include "fd-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "log.h"
#include "mkdir-label.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "namespace-util.h"
#include "nspawn-mount.h"
#include "path-util.h"
#include "rm-rf.h"
#include "sort-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "user-util.h"

CustomMount* custom_mount_add(CustomMount **l, size_t *n, CustomMountType t) {
        CustomMount *ret;

        assert(l);
        assert(n);
        assert(t >= 0);
        assert(t < _CUSTOM_MOUNT_TYPE_MAX);

        if (!GREEDY_REALLOC(*l, *n + 1))
                return NULL;

        ret = *l + *n;
        (*n)++;

        *ret = (CustomMount) {
                .type = t,
                .destination_uid = UID_INVALID,
        };

        return ret;
}

void custom_mount_free_all(CustomMount *l, size_t n) {
        FOREACH_ARRAY(m, l, n) {
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
                free(m->type_argument);
        }

        free(l);
}

static int custom_mount_compare(const CustomMount *a, const CustomMount *b) {
        int r;

        r = path_compare(a->destination, b->destination);
        if (r != 0)
                return r;

        return CMP(a->type, b->type);
}

static int source_path_parse(const char *p, char **ret) {
        assert(p);
        assert(ret);

        if (isempty(p))
                return -EINVAL;

        if (*p == '+') {
                if (!path_is_absolute(p + 1))
                        return -EINVAL;

                char *s = strdup(p);
                if (!s)
                        return -ENOMEM;

                *ret = TAKE_PTR(s);
                return 0;
        }

        return path_make_absolute_cwd(p, ret);
}

static int source_path_parse_nullable(const char *p, char **ret) {
        assert(p);
        assert(ret);

        if (isempty(p)) {
                *ret = NULL;
                return 0;
        }

        return source_path_parse(p, ret);
}

static char *resolve_source_path(const char *dest, const char *source) {
        if (!source)
                return NULL;

        if (source[0] == '+')
                return path_join(dest, source + 1);

        return strdup(source);
}

static int allocate_temporary_source(CustomMount *m) {
        int r;

        assert(m);
        assert(!m->source);
        assert(!m->rm_rf_tmpdir);

        r = mkdtemp_malloc("/var/tmp/nspawn-temp-XXXXXX", &m->rm_rf_tmpdir);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire temporary directory: %m");

        m->source = path_join(m->rm_rf_tmpdir, "src");
        if (!m->source)
                return log_oom();

        if (mkdir(m->source, 0755) < 0)
                return log_error_errno(errno, "Failed to create %s: %m", m->source);

        return 0;
}

int custom_mount_prepare_all(const char *dest, CustomMount *l, size_t n) {
        int r;

        /* Prepare all custom mounts. This will make sure we know all temporary directories. This is called in the
         * parent process, so that we know the temporary directories to remove on exit before we fork off the
         * children. */

        assert(l || n == 0);

        /* Order the custom mounts, and make sure we have a working directory */
        typesafe_qsort(l, n, custom_mount_compare);

        FOREACH_ARRAY(m, l, n) {
                /* /proc we mount in the inner child, i.e. when we acquired CLONE_NEWPID. All other mounts we mount
                 * already in the outer child, so that the mounts are already established before CLONE_NEWPID and in
                 * particular CLONE_NEWUSER. This also means any custom mounts below /proc also need to be mounted in
                 * the inner child, not the outer one. Determine this here. */
                m->in_userns = path_startswith(m->destination, "/proc");

                if (m->type == CUSTOM_MOUNT_BIND) {
                        if (m->source) {
                                char *s;

                                s = resolve_source_path(dest, m->source);
                                if (!s)
                                        return log_oom();

                                free_and_replace(m->source, s);
                        } else {
                                /* No source specified? In that case, use a throw-away temporary directory in /var/tmp */

                                r = allocate_temporary_source(m);
                                if (r < 0)
                                        return r;
                        }
                }

                if (m->type == CUSTOM_MOUNT_OVERLAY) {
                        STRV_FOREACH(j, m->lower) {
                                char *s;

                                s = resolve_source_path(dest, *j);
                                if (!s)
                                        return log_oom();

                                free_and_replace(*j, s);
                        }

                        if (m->source) {
                                char *s;

                                s = resolve_source_path(dest, m->source);
                                if (!s)
                                        return log_oom();

                                free_and_replace(m->source, s);
                        } else {
                                r = allocate_temporary_source(m);
                                if (r < 0)
                                        return r;
                        }

                        if (m->work_dir) {
                                char *s;

                                s = resolve_source_path(dest, m->work_dir);
                                if (!s)
                                        return log_oom();

                                free_and_replace(m->work_dir, s);
                        } else {
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
        _cleanup_free_ char *source = NULL, *destination = NULL, *opts = NULL, *p = NULL;
        CustomMount *m;
        int r;

        assert(l);
        assert(n);

        r = extract_many_words(&s, ":", EXTRACT_DONT_COALESCE_SEPARATORS, &source, &destination);
        if (r < 0)
                return r;
        if (r == 0)
                return -EINVAL;
        if (r == 1) {
                destination = strdup(source[0] == '+' ? source+1 : source);
                if (!destination)
                        return -ENOMEM;
        }
        if (r == 2 && !isempty(s)) {
                opts = strdup(s);
                if (!opts)
                        return -ENOMEM;
        }

        r = source_path_parse_nullable(source, &p);
        if (r < 0)
                return r;

        if (!path_is_absolute(destination))
                return -EINVAL;

        m = custom_mount_add(l, n, CUSTOM_MOUNT_BIND);
        if (!m)
                return -ENOMEM;

        m->source = TAKE_PTR(p);
        m->destination = TAKE_PTR(destination);
        m->read_only = read_only;
        m->options = TAKE_PTR(opts);

        return 0;
}

int tmpfs_mount_parse(CustomMount **l, size_t *n, const char *s) {
        _cleanup_free_ char *path = NULL, *opts = NULL;
        const char *p = ASSERT_PTR(s);
        CustomMount *m;
        int r;

        assert(l);
        assert(n);

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
        int r, k;

        k = strv_split_full(&lower, s, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
        if (k < 0)
                return k;
        if (k < 2)
                return -EADDRNOTAVAIL;
        if (k == 2) {
                _cleanup_free_ char *p = NULL;

                /* If two parameters are specified, the first one is the lower, the second one the upper directory. And
                 * we'll also define the destination mount point the same as the upper. */

                r = source_path_parse(lower[0], &p);
                if (r < 0)
                        return r;

                free_and_replace(lower[0], p);

                r = source_path_parse(lower[1], &p);
                if (r < 0)
                        return r;

                free_and_replace(lower[1], p);

                upper = TAKE_PTR(lower[1]);

                destination = strdup(upper[0] == '+' ? upper+1 : upper); /* take the destination without "+" prefix */
                if (!destination)
                        return -ENOMEM;
        } else {
                _cleanup_free_ char *p = NULL;

                /* If more than two parameters are specified, the last one is the destination, the second to last one
                 * the "upper", and all before that the "lower" directories. */

                destination = lower[k - 1];
                upper = TAKE_PTR(lower[k - 2]);

                STRV_FOREACH(i, lower) {
                        r = source_path_parse(*i, &p);
                        if (r < 0)
                                return r;

                        free_and_replace(*i, p);
                }

                /* If the upper directory is unspecified, then let's create it automatically as a throw-away directory
                 * in /var/tmp */
                r = source_path_parse_nullable(upper, &p);
                if (r < 0)
                        return r;

                free_and_replace(upper, p);

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

int inaccessible_mount_parse(CustomMount **l, size_t *n, const char *s) {
        _cleanup_free_ char *path = NULL;
        CustomMount *m;

        assert(l);
        assert(n);
        assert(s);

        if (!path_is_absolute(s))
                return -EINVAL;

        path = strdup(s);
        if (!path)
                return -ENOMEM;

        m = custom_mount_add(l, n, CUSTOM_MOUNT_INACCESSIBLE);
        if (!m)
                return -ENOMEM;

        m->destination = TAKE_PTR(path);
        return 0;
}

int tmpfs_patch_options(
                const char *options,
                uid_t uid_shift,
                const char *selinux_apifs_context,
                char **ret) {

        _cleanup_free_ char *buf = NULL;

        assert(ret);

        if (options) {
                buf = strdup(options);
                if (!buf)
                        return -ENOMEM;
        }

        if (uid_shift != UID_INVALID)
                if (strextendf_with_separator(&buf, ",", "uid=" UID_FMT ",gid=" UID_FMT, uid_shift, uid_shift) < 0)
                        return -ENOMEM;

#if HAVE_SELINUX
        if (selinux_apifs_context)
                if (strextendf_with_separator(&buf, ",", "context=\"%s\"", selinux_apifs_context) < 0)
                        return -ENOMEM;
#endif

        *ret = TAKE_PTR(buf);
        return !!*ret;
}

int mount_sysfs(const char *dest, MountSettingsMask mount_settings) {
        _cleanup_free_ char *top = NULL, *full = NULL;;
        unsigned long extra_flags = 0;
        int r;

        top = path_join(dest, "/sys");
        if (!top)
                return log_oom();

        r = path_is_mount_point(top);
        if (r < 0)
                return log_error_errno(r, "Failed to determine if '%s' is a mountpoint: %m", top);
        if (r == 0) {
                /* If this is not a mount point yet, then mount a tmpfs there */
                r = mount_nofollow_verbose(LOG_ERR, "tmpfs", top, "tmpfs", MS_NOSUID|MS_NOEXEC|MS_NODEV, "mode=0555" TMPFS_LIMITS_SYS);
                if (r < 0)
                        return r;
        } else {
                r = path_is_fs_type(top, SYSFS_MAGIC);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine filesystem type of %s: %m", top);

                /* /sys/ might already be mounted as sysfs by the outer child in the !netns case. In this case, it's
                 * all good. Don't touch it because we don't have the right to do so, see
                 * https://github.com/systemd/systemd/issues/1555.
                 */
                if (r > 0)
                        return 0;
        }

        full = path_join(top, "/full");
        if (!full)
                return log_oom();

        if (mkdir(full, 0755) < 0 && errno != EEXIST)
                return log_error_errno(errno, "Failed to create directory '%s': %m", full);

        if (FLAGS_SET(mount_settings, MOUNT_APPLY_APIVFS_RO))
                extra_flags |= MS_RDONLY;

        r = mount_nofollow_verbose(LOG_ERR, "sysfs", full, "sysfs",
                                   MS_NOSUID|MS_NOEXEC|MS_NODEV|extra_flags, NULL);
        if (r < 0)
                return r;

        FOREACH_STRING(x, "block", "bus", "class", "dev", "devices", "kernel") {
                _cleanup_free_ char *from = NULL, *to = NULL;

                from = path_join(full, x);
                if (!from)
                        return log_oom();

                to = path_join(top, x);
                if (!to)
                        return log_oom();

                (void) mkdir(to, 0755);

                r = mount_nofollow_verbose(LOG_ERR, from, to, NULL, MS_BIND, NULL);
                if (r < 0)
                        return r;

                r = mount_nofollow_verbose(LOG_ERR, NULL, to, NULL,
                                           MS_BIND|MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_REMOUNT|extra_flags, NULL);
                if (r < 0)
                        return r;
        }

        r = umount_verbose(LOG_ERR, full, UMOUNT_NOFOLLOW);
        if (r < 0)
                return r;

        if (rmdir(full) < 0)
                return log_error_errno(errno, "Failed to remove %s: %m", full);

        /* Create mountpoints. Otherwise we are not allowed since we remount /sys/ read-only. */
        FOREACH_STRING(p, "/fs/cgroup", "/fs/bpf") {
                _cleanup_free_ char *x = path_join(top, p);
                if (!x)
                        return log_oom();

                (void) mkdir_p(x, 0755);
        }

        return mount_nofollow_verbose(LOG_ERR, NULL, top, NULL,
                                      MS_BIND|MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_REMOUNT|extra_flags, NULL);
}

#define PROC_DEFAULT_MOUNT_FLAGS (MS_NOSUID|MS_NOEXEC|MS_NODEV)
#define SYS_DEFAULT_MOUNT_FLAGS  (MS_RDONLY|MS_NOSUID|MS_NOEXEC|MS_NODEV)

int mount_all(const char *dest,
              MountSettingsMask mount_settings,
              uid_t uid_shift,
              const char *selinux_apifs_context) {

#define PROC_INACCESSIBLE_REG(path)                                     \
        { "/run/systemd/inaccessible/reg", (path), NULL, NULL, MS_BIND, \
          MOUNT_IN_USERNS|MOUNT_APPLY_APIVFS_RO }, /* Bind mount first ... */ \
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
                /* First we list inner child mounts (i.e. mounts applied *after* entering user namespacing when we are privileged) */
                { "proc",            "/proc",           "proc",  NULL,        PROC_DEFAULT_MOUNT_FLAGS,
                  MOUNT_FATAL|MOUNT_IN_USERNS|MOUNT_MKDIR|MOUNT_FOLLOW_SYMLINKS }, /* we follow symlinks here since not following them requires /proc/ already being mounted, which we don't have here. */

                { "/proc/sys",       "/proc/sys",       NULL,    NULL,        MS_BIND,
                  MOUNT_FATAL|MOUNT_IN_USERNS|MOUNT_APPLY_APIVFS_RO },                          /* Bind mount first ... */

                { "/proc/sys/net",   "/proc/sys/net",   NULL,    NULL,        MS_BIND,
                  MOUNT_FATAL|MOUNT_IN_USERNS|MOUNT_APPLY_APIVFS_RO|MOUNT_APPLY_APIVFS_NETNS }, /* (except for this) */

                { NULL,              "/proc/sys",       NULL,    NULL,        MS_BIND|MS_RDONLY|MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_REMOUNT,
                  MOUNT_FATAL|MOUNT_IN_USERNS|MOUNT_APPLY_APIVFS_RO },                          /* ... then, make it r/o */

                /* Make these files inaccessible to container payloads: they potentially leak information about kernel
                 * internals or the host's execution environment to the container */
                PROC_INACCESSIBLE_REG("/proc/kallsyms"),
                PROC_INACCESSIBLE_REG("/proc/kcore"),
                PROC_INACCESSIBLE_REG("/proc/keys"),
                PROC_INACCESSIBLE_REG("/proc/sysrq-trigger"),
                PROC_INACCESSIBLE_REG("/proc/timer_list"),

                /* Make these directories read-only to container payloads: they show hardware information, and in some
                 * cases contain tunables the container really shouldn't have access to. */
                PROC_READ_ONLY("/proc/acpi"),
                PROC_READ_ONLY("/proc/apm"),
                PROC_READ_ONLY("/proc/asound"),
                PROC_READ_ONLY("/proc/bus"),
                PROC_READ_ONLY("/proc/fs"),
                PROC_READ_ONLY("/proc/irq"),
                PROC_READ_ONLY("/proc/scsi"),

                { "mqueue",                 "/dev/mqueue",                  "mqueue", NULL,                            MS_NOSUID|MS_NOEXEC|MS_NODEV,
                  MOUNT_IN_USERNS|MOUNT_MKDIR },

                /* Then we list outer child mounts (i.e. mounts applied *before* entering user namespacing when we are privileged) */
                { "tmpfs",                  "/tmp",                         "tmpfs", "mode=01777" NESTED_TMPFS_LIMITS, MS_NOSUID|MS_NODEV|MS_STRICTATIME,
                  MOUNT_FATAL|MOUNT_APPLY_TMPFS_TMP|MOUNT_MKDIR|MOUNT_USRQUOTA_GRACEFUL },
                { "tmpfs",                  "/sys",                         "tmpfs", "mode=0555" TMPFS_LIMITS_SYS,     MS_NOSUID|MS_NOEXEC|MS_NODEV,
                  MOUNT_FATAL|MOUNT_APPLY_APIVFS_NETNS|MOUNT_MKDIR|MOUNT_UNMANAGED },
                { "sysfs",                  "/sys",                         "sysfs", NULL,                             SYS_DEFAULT_MOUNT_FLAGS,
                  MOUNT_FATAL|MOUNT_APPLY_APIVFS_RO|MOUNT_MKDIR|MOUNT_UNMANAGED },    /* skipped if above was mounted */
                { "sysfs",                  "/sys",                         "sysfs", NULL,                             MS_NOSUID|MS_NOEXEC|MS_NODEV,
                  MOUNT_FATAL|MOUNT_MKDIR|MOUNT_UNMANAGED },                          /* skipped if above was mounted */
                { "tmpfs",                  "/dev",                         "tmpfs", "mode=0755" TMPFS_LIMITS_PRIVATE_DEV, MS_NOSUID|MS_STRICTATIME,
                  MOUNT_FATAL|MOUNT_MKDIR },
                { "tmpfs",                  "/dev/shm",                     "tmpfs", "mode=01777" NESTED_TMPFS_LIMITS, MS_NOSUID|MS_NODEV|MS_STRICTATIME,
                  MOUNT_FATAL|MOUNT_MKDIR|MOUNT_USRQUOTA_GRACEFUL },
                { "tmpfs",                  "/run",                         "tmpfs", "mode=0755" TMPFS_LIMITS_RUN,     MS_NOSUID|MS_NODEV|MS_STRICTATIME,
                  MOUNT_FATAL|MOUNT_MKDIR },
                { "/run/host",              "/run/host",                    NULL,    NULL,                             MS_BIND,
                  MOUNT_FATAL|MOUNT_MKDIR|MOUNT_PREFIX_ROOT }, /* Prepare this so that we can make it read-only when we are done */
                { "/etc/os-release",        "/run/host/os-release",         NULL,    NULL,                             MS_BIND,
                  MOUNT_TOUCH }, /* As per kernel interface requirements, bind mount first (creating mount points) and make read-only later */
                { "/usr/lib/os-release",    "/run/host/os-release",         NULL,    NULL,                             MS_BIND,
                  MOUNT_FATAL }, /* If /etc/os-release doesn't exist use the version in /usr/lib as fallback */
                { NULL,                     "/run/host/os-release",         NULL,    NULL,                             MS_BIND|MS_RDONLY|MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_REMOUNT,
                  MOUNT_FATAL },
                { NULL,                     "/run/host/os-release",         NULL,    NULL,                             MS_PRIVATE,
                  MOUNT_FATAL },  /* Turn off propagation (we only want that for the mount propagation tunnel dir) */
                { NULL,                     "/run/host",                    NULL,    NULL,                             MS_BIND|MS_RDONLY|MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_REMOUNT,
                  MOUNT_FATAL|MOUNT_IN_USERNS },
#if HAVE_SELINUX
                { "/sys/fs/selinux",        "/sys/fs/selinux",              NULL,    NULL,                             MS_BIND,
                  MOUNT_MKDIR|MOUNT_PRIVILEGED },  /* Bind mount first (mkdir/chown the mount point in case /sys/ is mounted as minimal skeleton tmpfs) */
                { NULL,                     "/sys/fs/selinux",              NULL,    NULL,                             MS_BIND|MS_RDONLY|MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_REMOUNT,
                  MOUNT_UNMANAGED|MOUNT_PRIVILEGED },  /* Then, make it r/o (don't mkdir/chown the mount point here, the previous entry already did that) */
                { NULL,                     "/sys/fs/selinux",              NULL,    NULL,                             MS_PRIVATE,
                  MOUNT_UNMANAGED|MOUNT_PRIVILEGED },  /* Turn off propagation (we only want that for the mount propagation tunnel dir) */
#endif
        };

        bool use_userns = FLAGS_SET(mount_settings, MOUNT_USE_USERNS);
        bool netns = FLAGS_SET(mount_settings, MOUNT_APPLY_APIVFS_NETNS);
        bool ro = FLAGS_SET(mount_settings, MOUNT_APPLY_APIVFS_RO);
        bool in_userns = FLAGS_SET(mount_settings, MOUNT_IN_USERNS);
        bool tmpfs_tmp = FLAGS_SET(mount_settings, MOUNT_APPLY_TMPFS_TMP);
        bool unmanaged = FLAGS_SET(mount_settings, MOUNT_UNMANAGED);
        bool privileged = FLAGS_SET(mount_settings, MOUNT_PRIVILEGED);
        int r;

        FOREACH_ELEMENT(m, mount_table) {
                _cleanup_free_ char *where = NULL, *options = NULL, *prefixed = NULL;
                bool fatal = FLAGS_SET(m->mount_settings, MOUNT_FATAL);
                const char *o;

                /* If we are in managed user namespace mode but the entry is marked for mount outside of
                 * managed user namespace mode, and to be mounted outside the user namespace, then skip it */
                if (!unmanaged && FLAGS_SET(m->mount_settings, MOUNT_UNMANAGED) && !FLAGS_SET(m->mount_settings, MOUNT_IN_USERNS))
                        continue;

                if (in_userns != FLAGS_SET(m->mount_settings, MOUNT_IN_USERNS))
                        continue;

                if (!netns && FLAGS_SET(m->mount_settings, MOUNT_APPLY_APIVFS_NETNS))
                        continue;

                if (!ro && FLAGS_SET(m->mount_settings, MOUNT_APPLY_APIVFS_RO))
                        continue;

                if (!tmpfs_tmp && FLAGS_SET(m->mount_settings, MOUNT_APPLY_TMPFS_TMP))
                        continue;

                if (!privileged && FLAGS_SET(m->mount_settings, MOUNT_PRIVILEGED))
                        continue;

                r = chase(m->where, dest, CHASE_NONEXISTENT|CHASE_PREFIX_ROOT, &where, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve %s%s: %m", strempty(dest), m->where);

                /* Skip this entry if it is not a remount. */
                if (m->what) {
                        r = path_is_mount_point(where);
                        if (r < 0 && r != -ENOENT)
                                return log_error_errno(r, "Failed to detect whether %s is a mount point: %m", where);
                        if (r > 0)
                                continue;
                }

                if ((m->mount_settings & (MOUNT_MKDIR|MOUNT_TOUCH)) != 0) {
                        uid_t u = (use_userns && !in_userns) ? uid_shift : UID_INVALID;

                        if (FLAGS_SET(m->mount_settings, MOUNT_TOUCH))
                                r = mkdir_parents_safe(dest, where, 0755, u, u, 0);
                        else
                                r = mkdir_p_safe(dest, where, 0755, u, u, 0);
                        if (r < 0 && r != -EEXIST) {
                                if (fatal && r != -EROFS)
                                        return log_error_errno(r, "Failed to create directory %s: %m", where);

                                log_debug_errno(r, "Failed to create directory %s: %m", where);

                                /* If mkdir() or chown() failed due to the root directory being read only,
                                 * attempt to mount this fs anyway and let mount_verbose log any errors */
                                if (r != -EROFS)
                                        continue;
                        }
                }

                if (FLAGS_SET(m->mount_settings, MOUNT_TOUCH)) {
                        r = touch(where);
                        if (r < 0 && r != -EEXIST) {
                                if (fatal && r != -EROFS)
                                        return log_error_errno(r, "Failed to create file %s: %m", where);

                                log_debug_errno(r, "Failed to create file %s: %m", where);
                                if (r != -EROFS)
                                        continue;
                        }
                }

                o = m->options;
                if (streq_ptr(m->type, "tmpfs")) {
                        r = tmpfs_patch_options(o, in_userns ? 0 : uid_shift, selinux_apifs_context, &options);
                        if (r < 0)
                                return log_oom();
                        if (r > 0)
                                o = options;
                }

                if (FLAGS_SET(m->mount_settings, MOUNT_USRQUOTA_GRACEFUL)) {
                        r = mount_option_supported(m->type, /* key= */ "usrquota", /* value= */ NULL);
                        if (r < 0)
                                log_warning_errno(r, "Failed to determine if '%s' supports 'usrquota', assuming it doesn't: %m", m->type);
                        else if (r == 0)
                                log_debug("Kernel doesn't support 'usrquota' on '%s', not including in mount options for '%s'.", m->type, m->where);
                        else {
                                _cleanup_free_ char *joined = NULL;

                                if (!strextend_with_separator(&joined, ",", o ?: POINTER_MAX, "usrquota"))
                                        return log_oom();

                                free_and_replace(options, joined);
                                o = options;
                        }
                }

                if (FLAGS_SET(m->mount_settings, MOUNT_PREFIX_ROOT)) {
                        /* Optionally prefix the mount source with the root dir. This is useful in bind
                         * mounts to be created within the container image before we transition into it. Note
                         * that MOUNT_IN_USERNS is run after we transitioned hence prefixing is not necessary
                         * for those. */
                        r = chase(m->what, dest, CHASE_PREFIX_ROOT, &prefixed, NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to resolve %s%s: %m", strempty(dest), m->what);
                }

                r = mount_verbose_full(
                                fatal ? LOG_ERR : LOG_DEBUG,
                                prefixed ?: m->what,
                                where,
                                m->type,
                                m->flags,
                                o,
                                FLAGS_SET(m->mount_settings, MOUNT_FOLLOW_SYMLINKS));
                if (r < 0 && fatal)
                        return r;
        }

        return 0;
}

static int parse_mount_bind_options(const char *options, unsigned long *open_tree_flags, char **mount_opts, RemountIdmapping *idmapping) {
        unsigned long flags = *open_tree_flags;
        char *opts = NULL;
        RemountIdmapping new_idmapping = *idmapping;
        int r;

        assert(options);

        for (;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&options, &word, ",", 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract mount option: %m");
                if (r == 0)
                        break;

                if (streq(word, "rbind"))
                        flags |= AT_RECURSIVE;
                else if (streq(word, "norbind"))
                        flags &= ~AT_RECURSIVE;
                else if (streq(word, "idmap"))
                        new_idmapping = REMOUNT_IDMAPPING_HOST_ROOT;
                else if (streq(word, "noidmap"))
                        new_idmapping = REMOUNT_IDMAPPING_NONE;
                else if (streq(word, "rootidmap"))
                        new_idmapping = REMOUNT_IDMAPPING_HOST_OWNER;
                else if (streq(word, "owneridmap"))
                        new_idmapping = REMOUNT_IDMAPPING_HOST_OWNER_TO_TARGET_OWNER;
                else
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Invalid bind mount option: %s", word);
        }

        *open_tree_flags = flags;
        *idmapping = new_idmapping;
        /* in the future mount_opts will hold string options for mount(2) */
        *mount_opts = opts;

        return 0;
}

static int mount_bind(const char *dest, CustomMount *m, uid_t uid_shift, uid_t uid_range) {
        _cleanup_free_ char *mount_opts = NULL, *where = NULL;
        unsigned long open_tree_flags = OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_RECURSIVE;
        struct stat source_st, dest_st;
        uid_t dest_uid = UID_INVALID;
        int r;
        RemountIdmapping idmapping = REMOUNT_IDMAPPING_NONE;

        assert(dest);
        assert(m);

        if (m->options) {
                r = parse_mount_bind_options(m->options, &open_tree_flags, &mount_opts, &idmapping);
                if (r < 0)
                        return r;
        }

        /* ID remapping cannot be done if user namespaces are not in use (uid_shift is UID_INVALID).
         * Fail if idmapping was explicitly requested in this state. Otherwise, treat UID_INVALID
         * as 0 for ownership operations. */
        if (idmapping != REMOUNT_IDMAPPING_NONE && !uid_is_valid(uid_shift))
                return log_error_errno(
                                SYNTHETIC_ERRNO(EINVAL),
                                "ID remapping requested for %s, but user namespacing is not enabled.",
                                m->source);

        uid_t chown_uid = uid_is_valid(uid_shift) ? uid_shift : 0;

        /* If this is a bind mount from a temporary sources change ownership of the source to the container's
         * root UID. Otherwise it would always show up as "nobody" if user namespacing is used. */
        if (m->rm_rf_tmpdir && chown(m->source, chown_uid, chown_uid) < 0)
                return log_error_errno(errno, "Failed to chown %s: %m", m->source);

        /* UID/GIDs of idmapped mounts are always resolved in the caller's user namespace. In other
         * words, they're not nested. If we're doing an idmapped mount from a bind mount that's
         * already idmapped itself, the old idmap is replaced with the new one. This means that the
         * source uid which we put in the idmap userns has to be the uid of mount source in the
         * caller's userns *without* any mount idmapping in place. To get that uid, we clone the
         * mount source tree and clear any existing idmapping and temporarily mount that tree over
         * the mount source before we stat the mount source to figure out the source uid. */
        _cleanup_close_ int fd_clone =
                idmapping == REMOUNT_IDMAPPING_NONE ?
                RET_NERRNO(open_tree(
                        AT_FDCWD,
                        m->source,
                        open_tree_flags)) :
                open_tree_try_drop_idmap(
                        AT_FDCWD,
                        m->source,
                        open_tree_flags);
        if (fd_clone < 0)
                return log_error_errno(errno, "Failed to clone %s: %m", m->source);

        if (fstat(fd_clone, &source_st) < 0)
                return log_error_errno(errno, "Failed to stat %s: %m", m->source);

        r = chase(m->destination, dest, CHASE_PREFIX_ROOT|CHASE_NONEXISTENT, &where, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to resolve %s/%s: %m", dest, m->destination);
        if (r > 0) { /* Path exists already? */

                if (stat(where, &dest_st) < 0)
                        return log_error_errno(errno, "Failed to stat %s: %m", where);

                dest_uid = uid_is_valid(m->destination_uid) ? chown_uid + m->destination_uid : dest_st.st_uid;

                if (S_ISDIR(source_st.st_mode) && !S_ISDIR(dest_st.st_mode))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Cannot bind mount directory %s on file %s.",
                                               m->source, where);

                if (!S_ISDIR(source_st.st_mode) && S_ISDIR(dest_st.st_mode))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Cannot bind mount file %s on directory %s.",
                                               m->source, where);

        } else { /* Path doesn't exist yet? */
                r = mkdir_parents_safe_label(dest, where, 0755, chown_uid, chown_uid, MKDIR_IGNORE_EXISTING);
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

                if (chown(where, chown_uid, chown_uid) < 0)
                        return log_error_errno(errno, "Failed to chown %s: %m", where);

                dest_uid = chown_uid + (uid_is_valid(m->destination_uid) ? m->destination_uid : 0);
        }

        if (move_mount(fd_clone, "", AT_FDCWD, where, MOVE_MOUNT_F_EMPTY_PATH) < 0)
                return log_error_errno(errno, "Failed to mount %s to %s: %m", m->source, where);

        fd_clone = safe_close(fd_clone);

        if (m->read_only) {
                r = bind_remount_recursive(where, MS_RDONLY, MS_RDONLY, NULL);
                if (r < 0)
                        return log_error_errno(r, "Read-only bind mount failed: %m");
        }

        if (idmapping != REMOUNT_IDMAPPING_NONE) {
                r = remount_idmap(STRV_MAKE(where), uid_shift, uid_range, source_st.st_uid, dest_uid, idmapping);
                if (r < 0)
                        return log_error_errno(r, "Failed to map ids for bind mount %s: %m", where);
        }

        return 0;
}

static int mount_tmpfs(const char *dest, CustomMount *m, uid_t uid_shift, const char *selinux_apifs_context) {
        const char *options;
        _cleanup_free_ char *buf = NULL, *where = NULL;
        int r;

        assert(dest);
        assert(m);

        r = chase(m->destination, dest, CHASE_PREFIX_ROOT|CHASE_NONEXISTENT, &where, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to resolve %s/%s: %m", dest, m->destination);
        if (r == 0) { /* Doesn't exist yet? */
                r = mkdir_p_label(where, 0755);
                if (r < 0)
                        return log_error_errno(r, "Creating mount point for tmpfs %s failed: %m", where);
        }

        r = tmpfs_patch_options(m->options, uid_shift == 0 ? UID_INVALID : uid_shift, selinux_apifs_context, &buf);
        if (r < 0)
                return log_oom();
        options = r > 0 ? buf : m->options;

        return mount_nofollow_verbose(LOG_ERR, "tmpfs", where, "tmpfs", MS_NODEV|MS_STRICTATIME, options);
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

        r = chase(m->destination, dest, CHASE_PREFIX_ROOT|CHASE_NONEXISTENT, &where, NULL);
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

        return mount_nofollow_verbose(LOG_ERR, "overlay", where, "overlay", m->read_only ? MS_RDONLY : 0, options);
}

static int mount_inaccessible(const char *dest, CustomMount *m) {
        _cleanup_free_ char *where = NULL, *source = NULL;
        struct stat st;
        int r;

        assert(dest);
        assert(m);

        r = chase_and_stat(m->destination, dest, CHASE_PREFIX_ROOT, &where, &st);
        if (r < 0) {
                log_full_errno(m->graceful ? LOG_DEBUG : LOG_ERR, r, "Failed to resolve %s/%s: %m", dest, m->destination);
                return m->graceful ? 0 : r;
        }

        r = mode_to_inaccessible_node(NULL, st.st_mode, &source);
        if (r < 0)
                return m->graceful ? 0 : r;

        r = mount_nofollow_verbose(m->graceful ? LOG_DEBUG : LOG_ERR, source, where, NULL, MS_BIND, NULL);
        if (r < 0)
                return m->graceful ? 0 : r;

        r = mount_nofollow_verbose(m->graceful ? LOG_DEBUG : LOG_ERR, NULL, where, NULL, MS_BIND|MS_RDONLY|MS_REMOUNT, NULL);
        if (r < 0) {
                (void) umount_verbose(m->graceful ? LOG_DEBUG : LOG_ERR, where, UMOUNT_NOFOLLOW);
                return m->graceful ? 0 : r;
        }

        return 0;
}

static int mount_arbitrary(const char *dest, CustomMount *m) {
        _cleanup_free_ char *where = NULL;
        int r;

        assert(dest);
        assert(m);

        r = chase(m->destination, dest, CHASE_PREFIX_ROOT|CHASE_NONEXISTENT, &where, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to resolve %s/%s: %m", dest, m->destination);
        if (r == 0) { /* Doesn't exist yet? */
                r = mkdir_p_label(where, 0755);
                if (r < 0)
                        return log_error_errno(r, "Creating mount point for mount %s failed: %m", where);
        }

        return mount_nofollow_verbose(LOG_ERR, m->source, where, m->type_argument, 0, m->options);
}

int mount_custom(
                const char *dest,
                CustomMount *mounts, size_t n,
                uid_t uid_shift,
                uid_t uid_range,
                const char *selinux_apifs_context,
                MountSettingsMask mount_settings) {
        int r;

        assert(dest);

        FOREACH_ARRAY(m, mounts, n) {
                if (FLAGS_SET(mount_settings, MOUNT_IN_USERNS) != m->in_userns)
                        continue;

                if (FLAGS_SET(mount_settings, MOUNT_ROOT_ONLY) && !path_equal(m->destination, "/"))
                        continue;

                if (FLAGS_SET(mount_settings, MOUNT_NON_ROOT_ONLY) && path_equal(m->destination, "/"))
                        continue;

                switch (m->type) {

                case CUSTOM_MOUNT_BIND:
                        r = mount_bind(dest, m, uid_shift, uid_range);
                        break;

                case CUSTOM_MOUNT_TMPFS:
                        r = mount_tmpfs(dest, m, uid_shift, selinux_apifs_context);
                        break;

                case CUSTOM_MOUNT_OVERLAY:
                        r = mount_overlay(dest, m);
                        break;

                case CUSTOM_MOUNT_INACCESSIBLE:
                        r = mount_inaccessible(dest, m);
                        break;

                case CUSTOM_MOUNT_ARBITRARY:
                        r = mount_arbitrary(dest, m);
                        break;

                default:
                        assert_not_reached();
                }

                if (r < 0)
                        return r;
        }

        return 0;
}

bool has_custom_root_mount(const CustomMount *mounts, size_t n) {
        FOREACH_ARRAY(m, mounts, n)
                if (path_equal(m->destination, "/"))
                        return true;

        return false;
}

static int setup_volatile_state(const char *directory) {
        int r;

        assert(directory);

        /* --volatile=state means we simply overmount /var with a tmpfs, and the rest read-only. */

        /* First, remount the root directory. */
        r = bind_remount_recursive(directory, MS_RDONLY, MS_RDONLY, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to remount %s read-only: %m", directory);

        return 0;
}

static int setup_volatile_state_after_remount_idmap(const char *directory, uid_t uid_shift, const char *selinux_apifs_context) {
        _cleanup_free_ char *buf = NULL;
        int r;

        assert(directory);

        /* Then, after remount_idmap(), overmount /var/ with a tmpfs. */

        _cleanup_free_ char *p = path_join(directory, "/var");
        if (!p)
                return log_oom();

        r = mkdir(p, 0755);
        if (r < 0 && errno != EEXIST)
                return log_error_errno(errno, "Failed to create %s: %m", directory);

        const char *options = "mode=0755" TMPFS_LIMITS_VOLATILE_STATE;
        r = tmpfs_patch_options(options, uid_shift == 0 ? UID_INVALID : uid_shift, selinux_apifs_context, &buf);
        if (r < 0)
                return log_oom();
        if (r > 0)
                options = buf;

        return mount_nofollow_verbose(LOG_ERR, "tmpfs", p, "tmpfs", MS_STRICTATIME, options);
}

static int setup_volatile_yes(const char *directory, uid_t uid_shift, const char *selinux_apifs_context) {
        bool tmpfs_mounted = false, bind_mounted = false;
        _cleanup_(rmdir_and_freep) char *template = NULL;
        _cleanup_free_ char *buf = NULL, *bindir = NULL, *f = NULL, *t = NULL;
        struct stat st;
        int r;

        assert(directory);

        /* --volatile=yes means we mount a tmpfs to the root dir, and the original /usr to use inside it, and
         * that read-only. Before we start setting this up let's validate if the image has the /usr merge
         * implemented, and let's output a friendly log message if it hasn't. */

        bindir = path_join(directory, "/bin");
        if (!bindir)
                return log_oom();
        if (lstat(bindir, &st) < 0) {
                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to stat /bin directory below image: %m");

                /* ENOENT is fine, just means the image is probably just a naked /usr and we can create the
                 * rest. */
        } else if (S_ISDIR(st.st_mode))
                return log_error_errno(SYNTHETIC_ERRNO(EISDIR),
                                       "Sorry, --volatile=yes mode is not supported with OS images that have not merged /bin/, /sbin/, /lib/, /lib64/ into /usr/. "
                                       "Please work with your distribution and help them adopt the merged /usr scheme.");
        else if (!S_ISLNK(st.st_mode))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Error starting image: if --volatile=yes is used /bin must be a symlink (for merged /usr support) or non-existent (in which case a symlink is created automatically).");

        r = mkdtemp_malloc("/tmp/nspawn-volatile-XXXXXX", &template);
        if (r < 0)
                return log_error_errno(r, "Failed to create temporary directory: %m");

        const char *options = "mode=0755" TMPFS_LIMITS_ROOTFS;
        r = tmpfs_patch_options(options, uid_shift == 0 ? UID_INVALID : uid_shift, selinux_apifs_context, &buf);
        if (r < 0)
                goto fail;
        if (r > 0)
                options = buf;

        r = mount_nofollow_verbose(LOG_ERR, "tmpfs", template, "tmpfs", MS_STRICTATIME, options);
        if (r < 0)
                goto fail;

        tmpfs_mounted = true;

        f = path_join(directory, "/usr");
        if (!f) {
                r = log_oom();
                goto fail;
        }

        t = path_join(template, "/usr");
        if (!t) {
                r = log_oom();
                goto fail;
        }

        r = mkdir(t, 0755);
        if (r < 0 && errno != EEXIST) {
                r = log_error_errno(errno, "Failed to create %s: %m", t);
                goto fail;
        }

        r = mount_nofollow_verbose(LOG_ERR, f, t, NULL, MS_BIND|MS_REC, NULL);
        if (r < 0)
                goto fail;

        bind_mounted = true;

        r = bind_remount_recursive(t, MS_RDONLY, MS_RDONLY, NULL);
        if (r < 0) {
                log_error_errno(r, "Failed to remount %s read-only: %m", t);
                goto fail;
        }

        r = mount_nofollow_verbose(LOG_ERR, template, directory, NULL, MS_MOVE, NULL);
        if (r < 0)
                goto fail;

        (void) rmdir(template);

        return 0;

fail:
        if (bind_mounted)
                (void) umount_verbose(LOG_ERR, t, UMOUNT_NOFOLLOW);

        if (tmpfs_mounted)
                (void) umount_verbose(LOG_ERR, template, UMOUNT_NOFOLLOW);

        return r;
}

static int setup_volatile_overlay(const char *directory, uid_t uid_shift, const char *selinux_apifs_context) {
        _cleanup_free_ char *buf = NULL, *escaped_directory = NULL, *escaped_upper = NULL, *escaped_work = NULL;
        _cleanup_(rmdir_and_freep) char *template = NULL;
        const char *upper, *work, *options;
        bool tmpfs_mounted = false;
        int r;

        assert(directory);

        /* --volatile=overlay means we mount an overlayfs to the root dir. */

        r = mkdtemp_malloc("/tmp/nspawn-volatile-XXXXXX", &template);
        if (r < 0)
                return log_error_errno(r, "Failed to create temporary directory: %m");

        options = "mode=0755" TMPFS_LIMITS_ROOTFS;
        r = tmpfs_patch_options(options, uid_shift == 0 ? UID_INVALID : uid_shift, selinux_apifs_context, &buf);
        if (r < 0)
                goto finish;
        if (r > 0)
                options = buf;

        r = mount_nofollow_verbose(LOG_ERR, "tmpfs", template, "tmpfs", MS_STRICTATIME, options);
        if (r < 0)
                goto finish;

        tmpfs_mounted = true;

        upper = strjoina(template, "/upper");
        work = strjoina(template, "/work");

        if (mkdir(upper, 0755) < 0) {
                r = log_error_errno(errno, "Failed to create %s: %m", upper);
                goto finish;
        }
        if (mkdir(work, 0755) < 0) {
                r = log_error_errno(errno, "Failed to create %s: %m", work);
                goto finish;
        }

        /* And now, let's overmount the root dir with an overlayfs that uses the root dir as lower dir. It's kinda nice
         * that the kernel allows us to do that without going through some mount point rearrangements. */

        escaped_directory = shell_escape(directory, ",:");
        escaped_upper = shell_escape(upper, ",:");
        escaped_work = shell_escape(work, ",:");
        if (!escaped_directory || !escaped_upper || !escaped_work) {
                r = -ENOMEM;
                goto finish;
        }

        options = strjoina("lowerdir=", escaped_directory, ",upperdir=", escaped_upper, ",workdir=", escaped_work);
        r = mount_nofollow_verbose(LOG_ERR, "overlay", directory, "overlay", 0, options);

finish:
        if (tmpfs_mounted)
                (void) umount_verbose(LOG_ERR, template, UMOUNT_NOFOLLOW);

        return r;
}

int setup_volatile_mode(
                const char *directory,
                VolatileMode mode,
                uid_t uid_shift,
                const char *selinux_apifs_context) {

        switch (mode) {

        case VOLATILE_YES:
                return setup_volatile_yes(directory, uid_shift, selinux_apifs_context);

        case VOLATILE_STATE:
                return setup_volatile_state(directory);

        case VOLATILE_OVERLAY:
                return setup_volatile_overlay(directory, uid_shift, selinux_apifs_context);

        default:
                return 0;
        }
}

int setup_volatile_mode_after_remount_idmap(
                const char *directory,
                VolatileMode mode,
                uid_t uid_shift,
                const char *selinux_apifs_context) {

        switch (mode) {

        case VOLATILE_STATE:
                return setup_volatile_state_after_remount_idmap(directory, uid_shift, selinux_apifs_context);

        default:
                return 0;
        }
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
        _cleanup_(rmdir_and_freep) char *pivot_tmp = NULL;
        int r;

        assert(directory);

        if (!pivot_root_new)
                return 0;

        /* Pivot pivot_root_new to / and the existing / to pivot_root_old.
         * If pivot_root_old is NULL, the existing / disappears.
         * This requires a temporary directory, pivot_tmp, which is
         * not a child of either.
         *
         * This is typically used for OSTree-style containers, where the root partition contains several
         * sysroots which could be run. Normally, one would be chosen by the bootloader and pivoted to / by
         * initrd.
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
        directory_pivot_root_new = path_join(directory, pivot_root_new);
        if (!directory_pivot_root_new)
                return log_oom();

        /* Remount directory_pivot_root_new to make it movable. */
        r = mount_nofollow_verbose(LOG_ERR, directory_pivot_root_new, directory_pivot_root_new, NULL, MS_BIND, NULL);
        if (r < 0)
                return r;

        if (pivot_root_old) {
                r = mkdtemp_malloc("/tmp/nspawn-pivot-XXXXXX", &pivot_tmp);
                if (r < 0)
                        return log_error_errno(r, "Failed to create temporary directory: %m");

                pivot_tmp_pivot_root_old = path_join(pivot_tmp, pivot_root_old);
                if (!pivot_tmp_pivot_root_old)
                        return log_oom();

                r = mount_nofollow_verbose(LOG_ERR, directory_pivot_root_new, pivot_tmp, NULL, MS_MOVE, NULL);
                if (r < 0)
                        return r;

                r = mount_nofollow_verbose(LOG_ERR, directory, pivot_tmp_pivot_root_old, NULL, MS_MOVE, NULL);
                if (r < 0)
                        return r;

                r = mount_nofollow_verbose(LOG_ERR, pivot_tmp, directory, NULL, MS_MOVE, NULL);
        } else
                r = mount_nofollow_verbose(LOG_ERR, directory_pivot_root_new, directory, NULL, MS_MOVE, NULL);

        if (r < 0)
                return r;

        return 0;
}

#define NSPAWN_PRIVATE_FULLY_VISIBLE_PROCFS "/run/host/proc"
#define NSPAWN_PRIVATE_FULLY_VISIBLE_SYSFS "/run/host/sys"

int pin_fully_visible_api_fs(void) {
        int r;

        log_debug("Pinning fully visible API FS");

        (void) mkdir_p(NSPAWN_PRIVATE_FULLY_VISIBLE_PROCFS, 0755);
        (void) mkdir_p(NSPAWN_PRIVATE_FULLY_VISIBLE_SYSFS, 0755);

        r = mount_follow_verbose(LOG_ERR, "proc", NSPAWN_PRIVATE_FULLY_VISIBLE_PROCFS, "proc", PROC_DEFAULT_MOUNT_FLAGS, NULL);
        if (r < 0)
                return r;

        r = mount_follow_verbose(LOG_ERR, "sysfs", NSPAWN_PRIVATE_FULLY_VISIBLE_SYSFS, "sysfs", SYS_DEFAULT_MOUNT_FLAGS, NULL);
        if (r < 0)
                return r;

        return 0;
}

static int do_wipe_fully_visible_api_fs(void) {
        if (umount2(NSPAWN_PRIVATE_FULLY_VISIBLE_PROCFS, MNT_DETACH) < 0)
                return log_error_errno(errno, "Failed to unmount temporary proc: %m");

        if (rmdir(NSPAWN_PRIVATE_FULLY_VISIBLE_PROCFS) < 0)
                return log_error_errno(errno, "Failed to remove temporary proc mountpoint: %m");

        if (umount2(NSPAWN_PRIVATE_FULLY_VISIBLE_SYSFS, MNT_DETACH) < 0)
                return log_error_errno(errno, "Failed to unmount temporary sys: %m");

        if (rmdir(NSPAWN_PRIVATE_FULLY_VISIBLE_SYSFS) < 0)
                return log_error_errno(errno, "Failed to remove temporary sys mountpoint: %m");

        return 0;
}

int wipe_fully_visible_api_fs(int mntns_fd) {
        _cleanup_close_ int orig_mntns_fd = -EBADF;
        int r;

        log_debug("Wiping fully visible API FS");

        orig_mntns_fd = namespace_open_by_type(NAMESPACE_MOUNT);
        if (orig_mntns_fd < 0)
                return log_error_errno(orig_mntns_fd, "Failed to pin originating mount namespace: %m");

        if (setns(mntns_fd, CLONE_NEWNS) < 0)
                return log_error_errno(errno, "Failed to enter mount namespace: %m");

        r = do_wipe_fully_visible_api_fs();

        if (setns(orig_mntns_fd, CLONE_NEWNS) < 0)
                return log_error_errno(errno, "Failed to enter original mount namespace: %m");

        return r;
}
