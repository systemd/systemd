/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/magic.h>
#include <unistd.h>

#include "cgroup-setup.h"
#include "cgroup-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "log.h"
#include "mkdir.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "recurse-dir.h"
#include "set.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "user-util.h"

int cg_weight_parse(const char *s, uint64_t *ret) {
        uint64_t u;
        int r;

        assert(s);
        assert(ret);

        if (isempty(s)) {
                *ret = CGROUP_WEIGHT_INVALID;
                return 0;
        }

        r = safe_atou64(s, &u);
        if (r < 0)
                return r;

        if (u < CGROUP_WEIGHT_MIN || u > CGROUP_WEIGHT_MAX)
                return -ERANGE;

        *ret = u;
        return 0;
}

int cg_cpu_weight_parse(const char *s, uint64_t *ret) {
        assert(s);
        assert(ret);

        if (streq(s, "idle"))
                return *ret = CGROUP_WEIGHT_IDLE;

        return cg_weight_parse(s, ret);
}

static int trim_cb(
                RecurseDirEvent event,
                const char *path,
                int dir_fd,
                int inode_fd,
                const struct dirent *de,
                const struct statx *sx,
                void *userdata) {

        /* Failures to delete inner cgroup we ignore (but debug log in case error code is unexpected) */
        if (event == RECURSE_DIR_LEAVE &&
            de->d_type == DT_DIR &&
            unlinkat(dir_fd, de->d_name, AT_REMOVEDIR) < 0 &&
            !IN_SET(errno, ENOENT, ENOTEMPTY, EBUSY))
                log_debug_errno(errno, "Failed to trim inner cgroup %s, ignoring: %m", path);

        return RECURSE_DIR_CONTINUE;
}

int cg_trim(const char *path, bool delete_root) {
        _cleanup_free_ char *fs = NULL;
        int r;

        r = cg_get_path(path, /* suffix = */ NULL, &fs);
        if (r < 0)
                return r;

        r = recurse_dir_at(
                        AT_FDCWD,
                        fs,
                        /* statx_mask = */ 0,
                        /* n_depth_max = */ UINT_MAX,
                        RECURSE_DIR_ENSURE_TYPE,
                        trim_cb,
                        /* userdata = */ NULL);
        if (r == -ENOENT) /* non-existing is the ultimate trimming, hence no error */
                r = 0;
        else if (r < 0)
                log_debug_errno(r, "Failed to trim subcgroups of '%s': %m", path);

        /* If we shall delete the top-level cgroup, then propagate the failure to do so (except if it is
         * already gone anyway). Also, let's debug log about this failure, except if the error code is an
         * expected one. */
        if (delete_root && !empty_or_root(path) &&
            rmdir(fs) < 0 && errno != ENOENT) {
                if (!IN_SET(errno, ENOTEMPTY, EBUSY))
                        log_debug_errno(errno, "Failed to trim cgroup '%s': %m", path);
                RET_GATHER(r, -errno);
        }

        return r;
}

/* Create a cgroup in the hierarchy of controller.
 * Returns 0 if the group already existed, 1 on success, negative otherwise.
 */
int cg_create(const char *path) {
        _cleanup_free_ char *fs = NULL;
        int r;

        r = cg_get_path(path, /* suffix = */ NULL, &fs);
        if (r < 0)
                return r;

        r = mkdir_parents(fs, 0755);
        if (r < 0)
                return r;

        r = RET_NERRNO(mkdir(fs, 0755));
        if (r == -EEXIST)
                return 0;
        if (r < 0)
                return r;

        return 1;
}

int cg_attach(const char *path, pid_t pid) {
        _cleanup_free_ char *fs = NULL;
        char c[DECIMAL_STR_MAX(pid_t) + 2];
        int r;

        assert(path);
        assert(pid >= 0);

        r = cg_get_path(path, "cgroup.procs", &fs);
        if (r < 0)
                return r;

        if (pid == 0)
                pid = getpid_cached();

        xsprintf(c, PID_FMT "\n", pid);

        r = write_string_file(fs, c, WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r == -EOPNOTSUPP && cg_is_threaded(path) > 0)
                /* When the threaded mode is used, we cannot read/write the file. Let's return recognizable error. */
                return -EUCLEAN;
        if (r < 0)
                return r;

        return 0;
}

int cg_fd_attach(int fd, pid_t pid) {
        char c[DECIMAL_STR_MAX(pid_t) + 2];

        assert(fd >= 0);
        assert(pid >= 0);

        if (pid == 0)
                pid = getpid_cached();

        xsprintf(c, PID_FMT "\n", pid);

        return write_string_file_at(fd, "cgroup.procs", c, WRITE_STRING_FILE_DISABLE_BUFFER);
}

int cg_create_and_attach(const char *path, pid_t pid) {
        int r, q;

        /* This does not remove the cgroup on failure */

        assert(pid >= 0);

        r = cg_create(path);
        if (r < 0)
                return r;

        q = cg_attach(path, pid);
        if (q < 0)
                return q;

        return r;
}

int cg_set_access(
                const char *path,
                uid_t uid,
                gid_t gid) {

        static const struct {
                const char *name;
                bool fatal;
        } attributes[] = {
                { "cgroup.procs",           true  },
                { "cgroup.subtree_control", true  },
                { "cgroup.threads",         false },
                { "memory.oom.group",       false },
                { "memory.reclaim",         false },
        };

        _cleanup_free_ char *fs = NULL;
        int r;

        assert(path);

        if (uid == UID_INVALID && gid == GID_INVALID)
                return 0;

        /* Configure access to the cgroup itself */
        r = cg_get_path(path, /* suffix = */ NULL, &fs);
        if (r < 0)
                return r;

        r = chmod_and_chown(fs, 0755, uid, gid);
        if (r < 0)
                return r;

        /* Configure access to the cgroup's attributes */
        FOREACH_ELEMENT(i, attributes) {
                _cleanup_free_ char *a = path_join(fs, i->name);
                if (!a)
                        return -ENOMEM;

                r = chmod_and_chown(a, 0644, uid, gid);
                if (r < 0) {
                        if (i->fatal)
                                return r;

                        log_debug_errno(r, "Failed to set access on cgroup %s, ignoring: %m", a);
                }
        }

        return 0;
}

struct access_callback_data {
        uid_t uid;
        gid_t gid;
        int error;
};

static int access_callback(
                RecurseDirEvent event,
                const char *path,
                int dir_fd,
                int inode_fd,
                const struct dirent *de,
                const struct statx *sx,
                void *userdata) {

        if (!IN_SET(event, RECURSE_DIR_ENTER, RECURSE_DIR_ENTRY))
                return RECURSE_DIR_CONTINUE;

        struct access_callback_data *d = ASSERT_PTR(userdata);

        assert(path);
        assert(inode_fd >= 0);

        if (fchownat(inode_fd, "", d->uid, d->gid, AT_EMPTY_PATH) < 0)
                RET_GATHER(d->error, log_debug_errno(errno, "Failed to change ownership of '%s', ignoring: %m", path));

        return RECURSE_DIR_CONTINUE;
}

int cg_set_access_recursive(
                const char *path,
                uid_t uid,
                gid_t gid) {

        _cleanup_close_ int fd = -EBADF;
        _cleanup_free_ char *fs = NULL;
        int r;

        assert(path);

        /* A recursive version of cg_set_access(). But note that this one changes ownership of *all* files,
         * not just the allowlist that cg_set_access() uses. Use cg_set_access() on the cgroup you want to
         * delegate, and cg_set_access_recursive() for any subcgroups you might want to create below it. */

        if (!uid_is_valid(uid) && !gid_is_valid(gid))
                return 0;

        r = cg_get_path(path, /* suffix = */ NULL, &fs);
        if (r < 0)
                return r;

        fd = open(fs, O_DIRECTORY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        struct access_callback_data d = {
                .uid = uid,
                .gid = gid,
        };

        r = recurse_dir(fd,
                        fs,
                        /* statx_mask= */ 0,
                        /* n_depth_max= */ UINT_MAX,
                        RECURSE_DIR_SAME_MOUNT|RECURSE_DIR_INODE_FD|RECURSE_DIR_TOPLEVEL,
                        access_callback,
                        &d);
        if (r < 0)
                return r;

        assert(d.error <= 0);
        return d.error;
}

int cg_migrate(
                const char *from,
                const char *to,
                CGroupFlags flags) {

        _cleanup_set_free_ Set *s = NULL;
        bool done;
        int r, ret = 0;

        assert(from);
        assert(to);

        do {
                _cleanup_fclose_ FILE *f = NULL;
                pid_t pid;

                done = true;

                r = cg_enumerate_processes(from, &f);
                if (r < 0)
                        return RET_GATHER(ret, r);

                while ((r = cg_read_pid(f, &pid, flags)) > 0) {
                        /* Throw an error if unmappable PIDs are in output, we can't migrate those. */
                        if (pid == 0)
                                return -EREMOTE;

                        /* This might do weird stuff if we aren't a single-threaded program. However, we
                         * luckily know we are. */
                        if (FLAGS_SET(flags, CGROUP_IGNORE_SELF) && pid == getpid_cached())
                                continue;

                        if (set_contains(s, PID_TO_PTR(pid)))
                                continue;

                        if (pid_is_kernel_thread(pid) > 0)
                                continue;

                        r = cg_attach(to, pid);
                        if (r < 0) {
                                if (r != -ESRCH)
                                        RET_GATHER(ret, r);
                        } else if (ret == 0)
                                ret = 1;

                        done = false;

                        r = set_ensure_put(&s, /* hash_ops = */ NULL, PID_TO_PTR(pid));
                        if (r < 0)
                                return RET_GATHER(ret, r);
                }
                if (r == -ENODEV)
                        continue;
                if (r < 0)
                        return RET_GATHER(ret, r);
        } while (!done);

        return ret;
}

int cg_enable(
                CGroupMask supported,
                CGroupMask mask,
                const char *p,
                CGroupMask *ret_result_mask) {

        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *fs = NULL;
        CGroupController c;
        CGroupMask ret = 0;
        int r;

        assert(p);

        if (supported == 0) {
                if (ret_result_mask)
                        *ret_result_mask = 0;
                return 0;
        }

        r = cg_get_path(p, "cgroup.subtree_control", &fs);
        if (r < 0)
                return r;

        for (c = 0; c < _CGROUP_CONTROLLER_MAX; c++) {
                CGroupMask bit = CGROUP_CONTROLLER_TO_MASK(c);
                const char *n;

                if (!FLAGS_SET(CGROUP_MASK_V2, bit))
                        continue;

                if (!FLAGS_SET(supported, bit))
                        continue;

                n = cgroup_controller_to_string(c);
                {
                        char s[1 + strlen(n) + 1];

                        s[0] = FLAGS_SET(mask, bit) ? '+' : '-';
                        strcpy(s + 1, n);

                        if (!f) {
                                f = fopen(fs, "we");
                                if (!f)
                                        return log_debug_errno(errno, "Failed to open cgroup.subtree_control file of %s: %m", p);
                        }

                        r = write_string_stream(f, s, WRITE_STRING_FILE_DISABLE_BUFFER);
                        if (r < 0) {
                                log_debug_errno(r, "Failed to %s controller %s for %s (%s): %m",
                                                FLAGS_SET(mask, bit) ? "enable" : "disable", n, p, fs);
                                clearerr(f);

                                /* If we can't turn off a controller, leave it on in the reported resulting mask. This
                                 * happens for example when we attempt to turn off a controller up in the tree that is
                                 * used down in the tree. */
                                if (!FLAGS_SET(mask, bit) && r == -EBUSY) /* You might wonder why we check for EBUSY
                                                                           * only here, and not follow the same logic
                                                                           * for other errors such as EINVAL or
                                                                           * EOPNOTSUPP or anything else. That's
                                                                           * because EBUSY indicates that the
                                                                           * controllers is currently enabled and
                                                                           * cannot be disabled because something down
                                                                           * the hierarchy is still using it. Any other
                                                                           * error most likely means something like "I
                                                                           * never heard of this controller" or
                                                                           * similar. In the former case it's hence
                                                                           * safe to assume the controller is still on
                                                                           * after the failed operation, while in the
                                                                           * latter case it's safer to assume the
                                                                           * controller is unknown and hence certainly
                                                                           * not enabled. */
                                        ret |= bit;
                        } else {
                                /* Otherwise, if we managed to turn on a controller, set the bit reflecting that. */
                                if (FLAGS_SET(mask, bit))
                                        ret |= bit;
                        }
                }
        }

        /* Let's return the precise set of controllers now enabled for the cgroup. */
        if (ret_result_mask)
                *ret_result_mask = ret;

        return 0;
}

int cg_has_legacy(void) {
        struct statfs fs;

        /* Checks if any legacy controller/hierarchy is mounted. */

        if (statfs("/sys/fs/cgroup/", &fs) < 0) {
                if (errno == ENOENT) /* sysfs not mounted? */
                        return false;

                return log_error_errno(errno, "Failed to statfs /sys/fs/cgroup/: %m");
        }

        if (is_fs_type(&fs, CGROUP2_SUPER_MAGIC) ||
            is_fs_type(&fs, SYSFS_MAGIC)) /* not mounted yet */
                return false;

        if (is_fs_type(&fs, TMPFS_MAGIC)) {
                log_info("Found tmpfs on /sys/fs/cgroup/, assuming legacy hierarchy.");
                return true;
        }

        return log_error_errno(SYNTHETIC_ERRNO(ENOMEDIUM),
                               "Unknown filesystem type %llx mounted on /sys/fs/cgroup/.",
                               (unsigned long long) fs.f_type);
}

int cg_is_ready(void) {
        struct statfs fs;

        if (statfs("/sys/fs/cgroup/", &fs) < 0) {
                if (errno == ENOENT) /* sysfs not mounted? */
                        return false;

                return log_debug_errno(errno, "Failed to statfs /sys/fs/cgroup/: %m");
        }

        return is_fs_type(&fs, CGROUP2_SUPER_MAGIC);
}
