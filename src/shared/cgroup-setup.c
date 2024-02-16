/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "cgroup-setup.h"
#include "cgroup-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "missing_threads.h"
#include "mkdir.h"
#include "parse-util.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "recurse-dir.h"
#include "stdio-util.h"
#include "string-util.h"
#include "user-util.h"
#include "virt.h"

static int cg_any_controller_used_for_v1(void) {
        _cleanup_free_ char *buf = NULL;
        _cleanup_strv_free_ char **lines = NULL;
        int r;

        r = read_full_virtual_file("/proc/cgroups", &buf, NULL);
        if (r < 0)
                return log_debug_errno(r, "Could not read /proc/cgroups, ignoring: %m");

        r = strv_split_newlines_full(&lines, buf, 0);
        if (r < 0)
                return r;

        /* The intention of this is to check if the fully unified cgroup tree setup is possible, meaning all
         * enabled kernel cgroup controllers are currently not in use by cgroup1.  For reference:
         * https://systemd.io/CGROUP_DELEGATION/#three-different-tree-setups-
         *
         * Note that this is typically only useful to check inside a container where we don't know what
         * cgroup tree setup is in use by the host; if the host is using legacy or hybrid, we can't use
         * unified since some or all controllers would be missing. This is not the best way to detect this,
         * as whatever container manager created our container should have mounted /sys/fs/cgroup
         * appropriately, but in case that wasn't done, we try to detect if it's possible for us to use
         * unified cgroups. */
        STRV_FOREACH(line, lines) {
                _cleanup_free_ char *name = NULL, *hierarchy_id = NULL, *num = NULL, *enabled = NULL;

                /* Skip header line */
                if (startswith(*line, "#"))
                        continue;

                const char *p = *line;
                r = extract_many_words(&p, NULL, 0, &name, &hierarchy_id, &num, &enabled, NULL);
                if (r < 0)
                        return log_debug_errno(r, "Error parsing /proc/cgroups line, ignoring: %m");
                else if (r < 4) {
                        log_debug("Invalid /proc/cgroups line, ignoring.");
                        continue;
                }

                /* Ignore disabled controllers. */
                if (streq(enabled, "0"))
                        continue;

                /* Ignore controllers we don't care about. */
                if (cgroup_controller_from_string(name) < 0)
                        continue;

                /* Since the unified cgroup doesn't use multiple hierarchies, if any controller has a
                 * non-zero hierarchy_id that means it's in use already in a legacy (or hybrid) cgroup v1
                 * hierarchy, and can't be used in a unified cgroup. */
                if (!streq(hierarchy_id, "0")) {
                        log_debug("Cgroup controller %s in use by legacy v1 hierarchy.", name);
                        return 1;
                }
        }

        return 0;
}

bool cg_is_unified_wanted(void) {
        static thread_local int wanted = -1;
        bool b;
        const bool is_default = DEFAULT_HIERARCHY == CGROUP_UNIFIED_ALL;
        _cleanup_free_ char *c = NULL;
        int r;

        /* If we have a cached value, return that. */
        if (wanted >= 0)
                return wanted;

        /* If the hierarchy is already mounted, then follow whatever was chosen for it. */
        r = cg_unified_cached(true);
        if (r >= 0)
                return (wanted = r >= CGROUP_UNIFIED_ALL);

        /* If we were explicitly passed systemd.unified_cgroup_hierarchy, respect that. */
        r = proc_cmdline_get_bool("systemd.unified_cgroup_hierarchy", /* flags = */ 0, &b);
        if (r > 0)
                return (wanted = b);

        /* If we passed cgroup_no_v1=all with no other instructions, it seems highly unlikely that we want to
         * use hybrid or legacy hierarchy. */
        r = proc_cmdline_get_key("cgroup_no_v1", 0, &c);
        if (r > 0 && streq_ptr(c, "all"))
                return (wanted = true);

        /* If any controller is in use as v1, don't use unified. */
        if (cg_any_controller_used_for_v1() > 0)
                return (wanted = false);

        return (wanted = is_default);
}

bool cg_is_legacy_wanted(void) {
        static thread_local int wanted = -1;

        /* If we have a cached value, return that. */
        if (wanted >= 0)
                return wanted;

        /* Check if we have cgroup v2 already mounted. */
        if (cg_unified_cached(true) == CGROUP_UNIFIED_ALL)
                return (wanted = false);

        /* Otherwise, assume that at least partial legacy is wanted,
         * since cgroup v2 should already be mounted at this point. */
        return (wanted = true);
}

bool cg_is_hybrid_wanted(void) {
        static thread_local int wanted = -1;
        int r;
        bool b;
        const bool is_default = DEFAULT_HIERARCHY >= CGROUP_UNIFIED_SYSTEMD;
        /* We default to true if the default is "hybrid", obviously, but also when the default is "unified",
         * because if we get called, it means that unified hierarchy was not mounted. */

        /* If we have a cached value, return that. */
        if (wanted >= 0)
                return wanted;

        /* If the hierarchy is already mounted, then follow whatever was chosen for it. */
        if (cg_unified_cached(true) == CGROUP_UNIFIED_ALL)
                return (wanted = false);

        /* Otherwise, let's see what the kernel command line has to say.  Since checking is expensive, cache
         * a non-error result. */
        r = proc_cmdline_get_bool("systemd.legacy_systemd_cgroup_controller", /* flags = */ 0, &b);

        /* The meaning of the kernel option is reversed wrt. to the return value of this function, hence the
         * negation. */
        return (wanted = r > 0 ? !b : is_default);
}

int cg_weight_parse(const char *s, uint64_t *ret) {
        uint64_t u;
        int r;

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
        if (streq_ptr(s, "idle"))
                return *ret = CGROUP_WEIGHT_IDLE;
        return cg_weight_parse(s, ret);
}

int cg_cpu_shares_parse(const char *s, uint64_t *ret) {
        uint64_t u;
        int r;

        if (isempty(s)) {
                *ret = CGROUP_CPU_SHARES_INVALID;
                return 0;
        }

        r = safe_atou64(s, &u);
        if (r < 0)
                return r;

        if (u < CGROUP_CPU_SHARES_MIN || u > CGROUP_CPU_SHARES_MAX)
                return -ERANGE;

        *ret = u;
        return 0;
}

int cg_blkio_weight_parse(const char *s, uint64_t *ret) {
        uint64_t u;
        int r;

        if (isempty(s)) {
                *ret = CGROUP_BLKIO_WEIGHT_INVALID;
                return 0;
        }

        r = safe_atou64(s, &u);
        if (r < 0)
                return r;

        if (u < CGROUP_BLKIO_WEIGHT_MIN || u > CGROUP_BLKIO_WEIGHT_MAX)
                return -ERANGE;

        *ret = u;
        return 0;
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

int cg_trim(const char *controller, const char *path, bool delete_root) {
        _cleanup_free_ char *fs = NULL;
        int r, q;

        assert(path);
        assert(controller);

        r = cg_get_path(controller, path, NULL, &fs);
        if (r < 0)
                return r;

        r = recurse_dir_at(
                        AT_FDCWD,
                        fs,
                        /* statx_mask= */ 0,
                        /* n_depth_max= */ UINT_MAX,
                        RECURSE_DIR_ENSURE_TYPE,
                        trim_cb,
                        NULL);
        if (r == -ENOENT) /* non-existing is the ultimate trimming, hence no error */
                r = 0;
        else if (r < 0)
                log_debug_errno(r, "Failed to iterate through cgroup %s: %m", path);

        /* If we shall delete the top-level cgroup, then propagate the failure to do so (except if it is
         * already gone anyway). Also, let's debug log about this failure, except if the error code is an
         * expected one. */
        if (delete_root && !empty_or_root(path) &&
            rmdir(fs) < 0 && errno != ENOENT) {
                if (!IN_SET(errno, ENOTEMPTY, EBUSY))
                        log_debug_errno(errno, "Failed to trim cgroup %s: %m", path);
                if (r >= 0)
                        r = -errno;
        }

        q = cg_hybrid_unified();
        if (q < 0)
                return q;
        if (q > 0 && streq(controller, SYSTEMD_CGROUP_CONTROLLER))
                (void) cg_trim(SYSTEMD_CGROUP_CONTROLLER_LEGACY, path, delete_root);

        return r;
}

/* Create a cgroup in the hierarchy of controller.
 * Returns 0 if the group already existed, 1 on success, negative otherwise.
 */
int cg_create(const char *controller, const char *path) {
        _cleanup_free_ char *fs = NULL;
        int r;

        r = cg_get_path_and_check(controller, path, NULL, &fs);
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

        r = cg_hybrid_unified();
        if (r < 0)
                return r;

        if (r > 0 && streq(controller, SYSTEMD_CGROUP_CONTROLLER)) {
                r = cg_create(SYSTEMD_CGROUP_CONTROLLER_LEGACY, path);
                if (r < 0)
                        log_warning_errno(r, "Failed to create compat systemd cgroup %s: %m", path);
        }

        return 1;
}

int cg_create_and_attach(const char *controller, const char *path, pid_t pid) {
        int r, q;

        assert(pid >= 0);

        r = cg_create(controller, path);
        if (r < 0)
                return r;

        q = cg_attach(controller, path, pid);
        if (q < 0)
                return q;

        /* This does not remove the cgroup on failure */
        return r;
}

int cg_attach(const char *controller, const char *path, pid_t pid) {
        _cleanup_free_ char *fs = NULL;
        char c[DECIMAL_STR_MAX(pid_t) + 2];
        int r;

        assert(path);
        assert(pid >= 0);

        r = cg_get_path_and_check(controller, path, "cgroup.procs", &fs);
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

        r = cg_hybrid_unified();
        if (r < 0)
                return r;

        if (r > 0 && streq(controller, SYSTEMD_CGROUP_CONTROLLER)) {
                r = cg_attach(SYSTEMD_CGROUP_CONTROLLER_LEGACY, path, pid);
                if (r < 0)
                        log_warning_errno(r, "Failed to attach "PID_FMT" to compat systemd cgroup %s: %m", pid, path);
        }

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

int cg_attach_fallback(const char *controller, const char *path, pid_t pid) {
        int r;

        assert(controller);
        assert(path);
        assert(pid >= 0);

        r = cg_attach(controller, path, pid);
        if (r < 0) {
                char prefix[strlen(path) + 1];

                /* This didn't work? Then let's try all prefixes of
                 * the destination */

                PATH_FOREACH_PREFIX(prefix, path) {
                        int q;

                        q = cg_attach(controller, prefix, pid);
                        if (q >= 0)
                                return q;
                }
        }

        return r;
}

int cg_set_access(
                const char *controller,
                const char *path,
                uid_t uid,
                gid_t gid) {

        struct Attribute {
                const char *name;
                bool fatal;
        };

        /* cgroup v1, aka legacy/non-unified */
        static const struct Attribute legacy_attributes[] = {
                { "cgroup.procs",           true  },
                { "tasks",                  false },
                { "cgroup.clone_children",  false },
                {},
        };

        /* cgroup v2, aka unified */
        static const struct Attribute unified_attributes[] = {
                { "cgroup.procs",           true  },
                { "cgroup.subtree_control", true  },
                { "cgroup.threads",         false },
                { "memory.oom.group",       false },
                { "memory.reclaim",         false },
                {},
        };

        static const struct Attribute* const attributes[] = {
                [false] = legacy_attributes,
                [true]  = unified_attributes,
        };

        _cleanup_free_ char *fs = NULL;
        const struct Attribute *i;
        int r, unified;

        assert(path);

        if (uid == UID_INVALID && gid == GID_INVALID)
                return 0;

        unified = cg_unified_controller(controller);
        if (unified < 0)
                return unified;

        /* Configure access to the cgroup itself */
        r = cg_get_path(controller, path, NULL, &fs);
        if (r < 0)
                return r;

        r = chmod_and_chown(fs, 0755, uid, gid);
        if (r < 0)
                return r;

        /* Configure access to the cgroup's attributes */
        for (i = attributes[unified]; i->name; i++) {
                fs = mfree(fs);

                r = cg_get_path(controller, path, i->name, &fs);
                if (r < 0)
                        return r;

                r = chmod_and_chown(fs, 0644, uid, gid);
                if (r < 0) {
                        if (i->fatal)
                                return r;

                        log_debug_errno(r, "Failed to set access on cgroup %s, ignoring: %m", fs);
                }
        }

        if (streq(controller, SYSTEMD_CGROUP_CONTROLLER)) {
                r = cg_hybrid_unified();
                if (r < 0)
                        return r;
                if (r > 0) {
                        /* Always propagate access mode from unified to legacy controller */
                        r = cg_set_access(SYSTEMD_CGROUP_CONTROLLER_LEGACY, path, uid, gid);
                        if (r < 0)
                                log_debug_errno(r, "Failed to set access on compatibility systemd cgroup %s, ignoring: %m", path);
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

        struct access_callback_data *d = ASSERT_PTR(userdata);

        if (!IN_SET(event, RECURSE_DIR_ENTER, RECURSE_DIR_ENTRY))
                return RECURSE_DIR_CONTINUE;

        assert(inode_fd >= 0);

        /* fchown() doesn't support O_PATH fds, hence we use the /proc/self/fd/ trick */
        if (chown(FORMAT_PROC_FD_PATH(inode_fd), d->uid, d->gid) < 0) {
                log_debug_errno(errno, "Failed to change ownership of '%s', ignoring: %m", ASSERT_PTR(path));

                if (d->error == 0) /* Return last error to caller */
                        d->error = errno;
        }

        return RECURSE_DIR_CONTINUE;
}

int cg_set_access_recursive(
                const char *controller,
                const char *path,
                uid_t uid,
                gid_t gid) {

        _cleanup_close_ int fd = -EBADF;
        _cleanup_free_ char *fs = NULL;
        int r;

        /* A recursive version of cg_set_access(). But note that this one changes ownership of *all* files,
         * not just the allowlist that cg_set_access() uses. Use cg_set_access() on the cgroup you want to
         * delegate, and cg_set_access_recursive() for any subcrgoups you might want to create below it. */

        if (!uid_is_valid(uid) && !gid_is_valid(gid))
                return 0;

        r = cg_get_path(controller, path, NULL, &fs);
        if (r < 0)
                return r;

        fd = open(fs, O_DIRECTORY|O_CLOEXEC|O_RDONLY);
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

        return -d.error;
}

int cg_migrate(
                const char *cfrom,
                const char *pfrom,
                const char *cto,
                const char *pto,
                CGroupFlags flags) {

        bool done = false;
        _cleanup_set_free_ Set *s = NULL;
        int r, ret = 0;
        pid_t my_pid;

        assert(cfrom);
        assert(pfrom);
        assert(cto);
        assert(pto);

        s = set_new(NULL);
        if (!s)
                return -ENOMEM;

        my_pid = getpid_cached();

        do {
                _cleanup_fclose_ FILE *f = NULL;
                pid_t pid = 0;
                done = true;

                r = cg_enumerate_processes(cfrom, pfrom, &f);
                if (r < 0) {
                        if (ret >= 0 && r != -ENOENT)
                                return r;

                        return ret;
                }

                while ((r = cg_read_pid(f, &pid)) > 0) {

                        /* This might do weird stuff if we aren't a
                         * single-threaded program. However, we
                         * luckily know we are not */
                        if ((flags & CGROUP_IGNORE_SELF) && pid == my_pid)
                                continue;

                        if (set_get(s, PID_TO_PTR(pid)) == PID_TO_PTR(pid))
                                continue;

                        /* Ignore kernel threads. Since they can only
                         * exist in the root cgroup, we only check for
                         * them there. */
                        if (cfrom &&
                            empty_or_root(pfrom) &&
                            pid_is_kernel_thread(pid) > 0)
                                continue;

                        r = cg_attach(cto, pto, pid);
                        if (r < 0) {
                                if (ret >= 0 && r != -ESRCH)
                                        ret = r;
                        } else if (ret == 0)
                                ret = 1;

                        done = false;

                        r = set_put(s, PID_TO_PTR(pid));
                        if (r < 0) {
                                if (ret >= 0)
                                        return r;

                                return ret;
                        }
                }

                if (r < 0) {
                        if (ret >= 0)
                                return r;

                        return ret;
                }
        } while (!done);

        return ret;
}

int cg_migrate_recursive(
                const char *cfrom,
                const char *pfrom,
                const char *cto,
                const char *pto,
                CGroupFlags flags) {

        _cleanup_closedir_ DIR *d = NULL;
        int r, ret = 0;
        char *fn;

        assert(cfrom);
        assert(pfrom);
        assert(cto);
        assert(pto);

        ret = cg_migrate(cfrom, pfrom, cto, pto, flags);

        r = cg_enumerate_subgroups(cfrom, pfrom, &d);
        if (r < 0) {
                if (ret >= 0 && r != -ENOENT)
                        return r;

                return ret;
        }

        while ((r = cg_read_subgroup(d, &fn)) > 0) {
                _cleanup_free_ char *p = NULL;

                p = path_join(empty_to_root(pfrom), fn);
                free(fn);
                if (!p)
                        return -ENOMEM;

                r = cg_migrate_recursive(cfrom, p, cto, pto, flags);
                if (r != 0 && ret >= 0)
                        ret = r;
        }

        if (r < 0 && ret >= 0)
                ret = r;

        if (flags & CGROUP_REMOVE) {
                r = cg_rmdir(cfrom, pfrom);
                if (r < 0 && ret >= 0 && !IN_SET(r, -ENOENT, -EBUSY))
                        return r;
        }

        return ret;
}

int cg_migrate_recursive_fallback(
                const char *cfrom,
                const char *pfrom,
                const char *cto,
                const char *pto,
                CGroupFlags flags) {

        int r;

        assert(cfrom);
        assert(pfrom);
        assert(cto);
        assert(pto);

        r = cg_migrate_recursive(cfrom, pfrom, cto, pto, flags);
        if (r < 0) {
                char prefix[strlen(pto) + 1];

                /* This didn't work? Then let's try all prefixes of the destination */

                PATH_FOREACH_PREFIX(prefix, pto) {
                        int q;

                        q = cg_migrate_recursive(cfrom, pfrom, cto, prefix, flags);
                        if (q >= 0)
                                return q;
                }
        }

        return r;
}

int cg_create_everywhere(CGroupMask supported, CGroupMask mask, const char *path) {
        CGroupController c;
        CGroupMask done;
        bool created;
        int r;

        /* This one will create a cgroup in our private tree, but also
         * duplicate it in the trees specified in mask, and remove it
         * in all others.
         *
         * Returns 0 if the group already existed in the systemd hierarchy,
         * 1 on success, negative otherwise.
         */

        /* First create the cgroup in our own hierarchy. */
        r = cg_create(SYSTEMD_CGROUP_CONTROLLER, path);
        if (r < 0)
                return r;
        created = r;

        /* If we are in the unified hierarchy, we are done now */
        r = cg_all_unified();
        if (r < 0)
                return r;
        if (r > 0)
                return created;

        supported &= CGROUP_MASK_V1;
        mask = CGROUP_MASK_EXTEND_JOINED(mask);
        done = 0;

        /* Otherwise, do the same in the other hierarchies */
        for (c = 0; c < _CGROUP_CONTROLLER_MAX; c++) {
                CGroupMask bit = CGROUP_CONTROLLER_TO_MASK(c);
                const char *n;

                if (!FLAGS_SET(supported, bit))
                        continue;

                if (FLAGS_SET(done, bit))
                        continue;

                n = cgroup_controller_to_string(c);
                if (FLAGS_SET(mask, bit))
                        (void) cg_create(n, path);

                done |= CGROUP_MASK_EXTEND_JOINED(bit);
        }

        return created;
}

int cg_attach_everywhere(CGroupMask supported, const char *path, pid_t pid, cg_migrate_callback_t path_callback, void *userdata) {
        int r;

        r = cg_attach(SYSTEMD_CGROUP_CONTROLLER, path, pid);
        if (r < 0)
                return r;

        r = cg_all_unified();
        if (r < 0)
                return r;
        if (r > 0)
                return 0;

        supported &= CGROUP_MASK_V1;
        CGroupMask done = 0;

        for (CGroupController c = 0; c < _CGROUP_CONTROLLER_MAX; c++) {
                CGroupMask bit = CGROUP_CONTROLLER_TO_MASK(c);
                const char *p = NULL;

                if (!FLAGS_SET(supported, bit))
                        continue;

                if (FLAGS_SET(done, bit))
                        continue;

                if (path_callback)
                        p = path_callback(bit, userdata);
                if (!p)
                        p = path;

                (void) cg_attach_fallback(cgroup_controller_to_string(c), p, pid);
                done |= CGROUP_MASK_EXTEND_JOINED(bit);
        }

        return 0;
}

int cg_migrate_v1_controllers(CGroupMask supported, CGroupMask mask, const char *from, cg_migrate_callback_t to_callback, void *userdata) {
        CGroupController c;
        CGroupMask done;
        int r = 0, q;

        assert(to_callback);

        supported &= CGROUP_MASK_V1;
        mask = CGROUP_MASK_EXTEND_JOINED(mask);
        done = 0;

        for (c = 0; c < _CGROUP_CONTROLLER_MAX; c++) {
                CGroupMask bit = CGROUP_CONTROLLER_TO_MASK(c);
                const char *to = NULL;

                if (!FLAGS_SET(supported, bit))
                        continue;

                if (FLAGS_SET(done, bit))
                        continue;

                if (!FLAGS_SET(mask, bit))
                        continue;

                to = to_callback(bit, userdata);

                /* Remember first error and try continuing */
                q = cg_migrate_recursive_fallback(SYSTEMD_CGROUP_CONTROLLER, from, cgroup_controller_to_string(c), to, 0);
                r = (r < 0) ? r : q;

                done |= CGROUP_MASK_EXTEND_JOINED(bit);
        }

        return r;
}

int cg_trim_everywhere(CGroupMask supported, const char *path, bool delete_root) {
        int r, q;

        r = cg_trim(SYSTEMD_CGROUP_CONTROLLER, path, delete_root);
        if (r < 0)
                return r;

        q = cg_all_unified();
        if (q < 0)
                return q;
        if (q > 0)
                return r;

        return cg_trim_v1_controllers(supported, _CGROUP_MASK_ALL, path, delete_root);
}

int cg_trim_v1_controllers(CGroupMask supported, CGroupMask mask, const char *path, bool delete_root) {
        CGroupController c;
        CGroupMask done;
        int r = 0, q;

        supported &= CGROUP_MASK_V1;
        mask = CGROUP_MASK_EXTEND_JOINED(mask);
        done = 0;

        for (c = 0; c < _CGROUP_CONTROLLER_MAX; c++) {
                CGroupMask bit = CGROUP_CONTROLLER_TO_MASK(c);

                if (!FLAGS_SET(supported, bit))
                        continue;

                if (FLAGS_SET(done, bit))
                        continue;

                if (FLAGS_SET(mask, bit)) {
                        /* Remember first error and try continuing */
                        q = cg_trim(cgroup_controller_to_string(c), path, delete_root);
                        r = (r < 0) ? r : q;
                }
                done |= CGROUP_MASK_EXTEND_JOINED(bit);
        }

        return r;
}

int cg_enable_everywhere(
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

        r = cg_all_unified();
        if (r < 0)
                return r;
        if (r == 0) {
                /* On the legacy hierarchy there's no concept of "enabling" controllers in cgroups defined. Let's claim
                 * complete success right away. (If you wonder why we return the full mask here, rather than zero: the
                 * caller tends to use the returned mask later on to compare if all controllers where properly joined,
                 * and if not requeues realization. This use is the primary purpose of the return value, hence let's
                 * minimize surprises here and reduce triggers for re-realization by always saying we fully
                 * succeeded.) */
                if (ret_result_mask)
                        *ret_result_mask = mask & supported & CGROUP_MASK_V2; /* If you wonder why we mask this with
                                                                               * CGROUP_MASK_V2: The 'supported' mask
                                                                               * might contain pure-V1 or BPF
                                                                               * controllers, and we never want to
                                                                               * claim that we could enable those with
                                                                               * cgroup.subtree_control */
                return 0;
        }

        r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, p, "cgroup.subtree_control", &fs);
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
