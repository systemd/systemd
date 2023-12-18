/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "missing_fs.h"

#include "alloc-util.h"
#include "cgroup-util.h"
#include "constants.h"
#include "dirent-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "log.h"
#include "login-util.h"
#include "macro.h"
#include "missing_magic.h"
#include "missing_threads.h"
#include "mkdir.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "set.h"
#include "special.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "unit-name.h"
#include "user-util.h"
#include "xattr-util.h"

int cg_path_open(const char *controller, const char *path) {
        _cleanup_free_ char *fs = NULL;
        int r;

        r = cg_get_path(controller, path, /* item=*/ NULL, &fs);
        if (r < 0)
                return r;

        return RET_NERRNO(open(fs, O_DIRECTORY|O_CLOEXEC));
}

int cg_cgroupid_open(int cgroupfs_fd, uint64_t id) {
        _cleanup_close_ int fsfd = -EBADF;

        if (cgroupfs_fd < 0) {
                fsfd = open("/sys/fs/cgroup", O_CLOEXEC|O_DIRECTORY);
                if (fsfd < 0)
                        return -errno;

                cgroupfs_fd = fsfd;
        }

        cg_file_handle fh = CG_FILE_HANDLE_INIT;
        CG_FILE_HANDLE_CGROUPID(fh) = id;

        int fd;
        fd = open_by_handle_at(cgroupfs_fd, &fh.file_handle, O_DIRECTORY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        return fd;
}

static int cg_enumerate_items(const char *controller, const char *path, FILE **ret, const char *item) {
        _cleanup_free_ char *fs = NULL;
        FILE *f;
        int r;

        assert(ret);

        r = cg_get_path(controller, path, item, &fs);
        if (r < 0)
                return r;

        f = fopen(fs, "re");
        if (!f)
                return -errno;

        *ret = f;
        return 0;
}

int cg_enumerate_processes(const char *controller, const char *path, FILE **ret) {
        return cg_enumerate_items(controller, path, ret, "cgroup.procs");
}

int cg_read_pid(FILE *f, pid_t *ret) {
        unsigned long ul;

        /* Note that the cgroup.procs might contain duplicates! See cgroups.txt for details. */

        assert(f);
        assert(ret);

        errno = 0;
        if (fscanf(f, "%lu", &ul) != 1) {

                if (feof(f)) {
                        *ret = 0;
                        return 0;
                }

                return errno_or_else(EIO);
        }

        if (ul <= 0)
                return -EIO;
        if (ul > PID_T_MAX)
                return -EIO;

        *ret = (pid_t) ul;
        return 1;
}

int cg_read_pidref(FILE *f, PidRef *ret) {
        int r;

        assert(f);
        assert(ret);

        for (;;) {
                pid_t pid;

                r = cg_read_pid(f, &pid);
                if (r < 0)
                        return r;
                if (r == 0) {
                        *ret = PIDREF_NULL;
                        return 0;
                }

                r = pidref_set_pid(ret, pid);
                if (r >= 0)
                        return 1;
                if (r != -ESRCH)
                        return r;

                /* ESRCH → gone by now? just skip over it, read the next */
        }
}

int cg_read_event(
                const char *controller,
                const char *path,
                const char *event,
                char **ret) {

        _cleanup_free_ char *events = NULL, *content = NULL;
        int r;

        r = cg_get_path(controller, path, "cgroup.events", &events);
        if (r < 0)
                return r;

        r = read_full_virtual_file(events, &content, NULL);
        if (r < 0)
                return r;

        for (const char *p = content;;) {
                _cleanup_free_ char *line = NULL, *key = NULL, *val = NULL;
                const char *q;

                r = extract_first_word(&p, &line, "\n", 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -ENOENT;

                q = line;
                r = extract_first_word(&q, &key, " ", 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -EINVAL;

                if (!streq(key, event))
                        continue;

                val = strdup(q);
                if (!val)
                        return -ENOMEM;

                *ret = TAKE_PTR(val);
                return 0;
        }
}

bool cg_ns_supported(void) {
        static thread_local int enabled = -1;

        if (enabled >= 0)
                return enabled;

        if (access("/proc/self/ns/cgroup", F_OK) < 0) {
                if (errno != ENOENT)
                        log_debug_errno(errno, "Failed to check whether /proc/self/ns/cgroup is available, assuming not: %m");
                enabled = false;
        } else
                enabled = true;

        return enabled;
}

bool cg_freezer_supported(void) {
        static thread_local int supported = -1;

        if (supported >= 0)
                return supported;

        supported = cg_all_unified() > 0 && access("/sys/fs/cgroup/init.scope/cgroup.freeze", F_OK) == 0;

        return supported;
}

bool cg_kill_supported(void) {
        static thread_local int supported = -1;

        if (supported >= 0)
                return supported;

        if (cg_all_unified() <= 0)
                supported = false;
        else if (access("/sys/fs/cgroup/init.scope/cgroup.kill", F_OK) < 0) {
                if (errno != ENOENT)
                        log_debug_errno(errno, "Failed to check if cgroup.kill is available, assuming not: %m");
                supported = false;
        } else
                supported = true;

        return supported;
}

int cg_enumerate_subgroups(const char *controller, const char *path, DIR **ret) {
        _cleanup_free_ char *fs = NULL;
        DIR *d;
        int r;

        assert(ret);

        /* This is not recursive! */

        r = cg_get_path(controller, path, NULL, &fs);
        if (r < 0)
                return r;

        d = opendir(fs);
        if (!d)
                return -errno;

        *ret = d;
        return 0;
}

int cg_read_subgroup(DIR *d, char **ret) {
        assert(d);
        assert(ret);

        FOREACH_DIRENT_ALL(de, d, return -errno) {
                char *b;

                if (de->d_type != DT_DIR)
                        continue;

                if (dot_or_dot_dot(de->d_name))
                        continue;

                b = strdup(de->d_name);
                if (!b)
                        return -ENOMEM;

                *ret = b;
                return 1;
        }

        *ret = NULL;
        return 0;
}

int cg_rmdir(const char *controller, const char *path) {
        _cleanup_free_ char *p = NULL;
        int r;

        r = cg_get_path(controller, path, NULL, &p);
        if (r < 0)
                return r;

        r = rmdir(p);
        if (r < 0 && errno != ENOENT)
                return -errno;

        r = cg_hybrid_unified();
        if (r <= 0)
                return r;

        if (streq(controller, SYSTEMD_CGROUP_CONTROLLER)) {
                r = cg_rmdir(SYSTEMD_CGROUP_CONTROLLER_LEGACY, path);
                if (r < 0)
                        log_warning_errno(r, "Failed to remove compat systemd cgroup %s: %m", path);
        }

        return 0;
}

static int cg_kill_items(
                const char *path,
                int sig,
                CGroupFlags flags,
                Set *s,
                cg_kill_log_func_t log_kill,
                void *userdata,
                const char *item) {

        _cleanup_set_free_ Set *allocated_set = NULL;
        bool done = false;
        int r, ret = 0, ret_log_kill = 0;

        assert(sig >= 0);

         /* Don't send SIGCONT twice. Also, SIGKILL always works even when process is suspended, hence don't send
          * SIGCONT on SIGKILL. */
        if (IN_SET(sig, SIGCONT, SIGKILL))
                flags &= ~CGROUP_SIGCONT;

        /* This goes through the tasks list and kills them all. This
         * is repeated until no further processes are added to the
         * tasks list, to properly handle forking processes */

        if (!s) {
                s = allocated_set = set_new(NULL);
                if (!s)
                        return -ENOMEM;
        }

        do {
                _cleanup_fclose_ FILE *f = NULL;
                done = true;

                r = cg_enumerate_items(SYSTEMD_CGROUP_CONTROLLER, path, &f, item);
                if (r == -ENOENT)
                        break;
                if (r < 0)
                        return RET_GATHER(ret, r);

                for (;;) {
                        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;

                        r = cg_read_pidref(f, &pidref);
                        if (r < 0)
                                return RET_GATHER(ret, r);
                        if (r == 0)
                                break;

                        if ((flags & CGROUP_IGNORE_SELF) && pidref_is_self(&pidref))
                                continue;

                        if (set_get(s, PID_TO_PTR(pidref.pid)) == PID_TO_PTR(pidref.pid))
                                continue;

                        if (log_kill)
                                ret_log_kill = log_kill(&pidref, sig, userdata);

                        /* If we haven't killed this process yet, kill it */
                        r = pidref_kill(&pidref, sig);
                        if (r < 0 && r != -ESRCH)
                                RET_GATHER(ret, r);
                        if (r >= 0) {
                                if (flags & CGROUP_SIGCONT)
                                        (void) pidref_kill(&pidref, SIGCONT);

                                if (ret == 0) {
                                        if (log_kill)
                                                ret = ret_log_kill;
                                        else
                                                ret = 1;
                                }
                        }

                        done = false;

                        r = set_put(s, PID_TO_PTR(pidref.pid));
                        if (r < 0)
                                return RET_GATHER(ret, r);
                }

                /* To avoid racing against processes which fork quicker than we can kill them, we repeat this
                 * until no new pids need to be killed. */

        } while (!done);

        return ret;
}

int cg_kill(
                const char *path,
                int sig,
                CGroupFlags flags,
                Set *s,
                cg_kill_log_func_t log_kill,
                void *userdata) {

        int r, ret;

        r = cg_kill_items(path, sig, flags, s, log_kill, userdata, "cgroup.procs");
        if (r < 0 || sig != SIGKILL)
                return r;

        ret = r;

        /* Only in case of killing with SIGKILL and when using cgroupsv2, kill remaining threads manually as
           a workaround for kernel bug. It was fixed in 5.2-rc5 (c03cd7738a83), backported to 4.19.66
           (4340d175b898) and 4.14.138 (feb6b123b7dd). */
        r = cg_unified_controller(SYSTEMD_CGROUP_CONTROLLER);
        if (r < 0)
                return r;
        if (r == 0)
                return ret;

        r = cg_kill_items(path, sig, flags, s, log_kill, userdata, "cgroup.threads");
        if (r < 0)
                return r;

        return r > 0 || ret > 0;
}

int cg_kill_kernel_sigkill(const char *path) {
        /* Kills the cgroup at `path` directly by writing to its cgroup.kill file.  This sends SIGKILL to all
         * processes in the cgroup and has the advantage of being completely atomic, unlike cg_kill_items(). */

        _cleanup_free_ char *killfile = NULL;
        int r;

        assert(path);

        if (!cg_kill_supported())
                return -EOPNOTSUPP;

        r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, path, "cgroup.kill", &killfile);
        if (r < 0)
                return r;

        r = write_string_file(killfile, "1", WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                return r;

        return 0;
}

int cg_kill_recursive(
                const char *path,
                int sig,
                CGroupFlags flags,
                Set *s,
                cg_kill_log_func_t log_kill,
                void *userdata) {

        int r, ret;

        assert(path);
        assert(sig >= 0);

        if (sig == SIGKILL && cg_kill_supported() &&
            !FLAGS_SET(flags, CGROUP_IGNORE_SELF) && !s && !log_kill)
                /* ignore CGROUP_SIGCONT, since this is a no-op alongside SIGKILL */
                ret = cg_kill_kernel_sigkill(path);
        else {
                _cleanup_set_free_ Set *allocated_set = NULL;
                _cleanup_closedir_ DIR *d = NULL;

                if (!s) {
                        s = allocated_set = set_new(NULL);
                        if (!s)
                                return -ENOMEM;
                }

                ret = cg_kill(path, sig, flags, s, log_kill, userdata);

                r = cg_enumerate_subgroups(SYSTEMD_CGROUP_CONTROLLER, path, &d);
                if (r < 0) {
                        if (r != -ENOENT)
                                RET_GATHER(ret, r);

                        return ret;
                }

                for (;;) {
                        _cleanup_free_ char *fn = NULL, *p = NULL;

                        r = cg_read_subgroup(d, &fn);
                        if (r < 0) {
                                RET_GATHER(ret, r);
                                break;
                        }
                        if (r == 0)
                                break;

                        p = path_join(empty_to_root(path), fn);
                        if (!p)
                                return -ENOMEM;

                        r = cg_kill_recursive(p, sig, flags, s, log_kill, userdata);
                        if (r != 0 && ret >= 0)
                                ret = r;
                }
        }

        if (FLAGS_SET(flags, CGROUP_REMOVE)) {
                r = cg_rmdir(SYSTEMD_CGROUP_CONTROLLER, path);
                if (!IN_SET(r, -ENOENT, -EBUSY))
                        RET_GATHER(ret, r);
        }

        return ret;
}

static const char *controller_to_dirname(const char *controller) {
        assert(controller);

        /* Converts a controller name to the directory name below /sys/fs/cgroup/ we want to mount it
         * to. Effectively, this just cuts off the name= prefixed used for named hierarchies, if it is
         * specified. */

        if (streq(controller, SYSTEMD_CGROUP_CONTROLLER)) {
                if (cg_hybrid_unified() > 0)
                        controller = SYSTEMD_CGROUP_CONTROLLER_HYBRID;
                else
                        controller = SYSTEMD_CGROUP_CONTROLLER_LEGACY;
        }

        return startswith(controller, "name=") ?: controller;
}

static int join_path_legacy(const char *controller, const char *path, const char *suffix, char **ret) {
        const char *dn;
        char *t = NULL;

        assert(ret);
        assert(controller);

        dn = controller_to_dirname(controller);

        if (isempty(path) && isempty(suffix))
                t = path_join("/sys/fs/cgroup", dn);
        else if (isempty(path))
                t = path_join("/sys/fs/cgroup", dn, suffix);
        else if (isempty(suffix))
                t = path_join("/sys/fs/cgroup", dn, path);
        else
                t = path_join("/sys/fs/cgroup", dn, path, suffix);
        if (!t)
                return -ENOMEM;

        *ret = t;
        return 0;
}

static int join_path_unified(const char *path, const char *suffix, char **ret) {
        char *t;

        assert(ret);

        if (isempty(path) && isempty(suffix))
                t = strdup("/sys/fs/cgroup");
        else if (isempty(path))
                t = path_join("/sys/fs/cgroup", suffix);
        else if (isempty(suffix))
                t = path_join("/sys/fs/cgroup", path);
        else
                t = path_join("/sys/fs/cgroup", path, suffix);
        if (!t)
                return -ENOMEM;

        *ret = t;
        return 0;
}

int cg_get_path(const char *controller, const char *path, const char *suffix, char **ret) {
        int r;

        assert(ret);

        if (!controller) {
                char *t;

                /* If no controller is specified, we return the path *below* the controllers, without any
                 * prefix. */

                if (isempty(path) && isempty(suffix))
                        return -EINVAL;

                if (isempty(suffix))
                        t = strdup(path);
                else if (isempty(path))
                        t = strdup(suffix);
                else
                        t = path_join(path, suffix);
                if (!t)
                        return -ENOMEM;

                *ret = path_simplify(t);
                return 0;
        }

        if (!cg_controller_is_valid(controller))
                return -EINVAL;

        r = cg_all_unified();
        if (r < 0)
                return r;
        if (r > 0)
                r = join_path_unified(path, suffix, ret);
        else
                r = join_path_legacy(controller, path, suffix, ret);
        if (r < 0)
                return r;

        path_simplify(*ret);
        return 0;
}

static int controller_is_v1_accessible(const char *root, const char *controller) {
        const char *cpath, *dn;

        assert(controller);

        dn = controller_to_dirname(controller);

        /* If root if specified, we check that:
         * - possible subcgroup is created at root,
         * - we can modify the hierarchy. */

        cpath = strjoina("/sys/fs/cgroup/", dn, root, root ? "/cgroup.procs" : NULL);
        return laccess(cpath, root ? W_OK : F_OK);
}

int cg_get_path_and_check(const char *controller, const char *path, const char *suffix, char **ret) {
        int r;

        assert(controller);
        assert(ret);

        if (!cg_controller_is_valid(controller))
                return -EINVAL;

        r = cg_all_unified();
        if (r < 0)
                return r;
        if (r > 0) {
                /* In the unified hierarchy all controllers are considered accessible,
                 * except for the named hierarchies */
                if (startswith(controller, "name="))
                        return -EOPNOTSUPP;
        } else {
                /* Check if the specified controller is actually accessible */
                r = controller_is_v1_accessible(NULL, controller);
                if (r < 0)
                        return r;
        }

        return cg_get_path(controller, path, suffix, ret);
}

int cg_set_xattr(const char *path, const char *name, const void *value, size_t size, int flags) {
        _cleanup_free_ char *fs = NULL;
        int r;

        assert(path);
        assert(name);
        assert(value || size <= 0);

        r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, path, NULL, &fs);
        if (r < 0)
                return r;

        return RET_NERRNO(setxattr(fs, name, value, size, flags));
}

int cg_get_xattr(const char *path, const char *name, void *value, size_t size) {
        _cleanup_free_ char *fs = NULL;
        ssize_t n;
        int r;

        assert(path);
        assert(name);

        r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, path, NULL, &fs);
        if (r < 0)
                return r;

        n = getxattr(fs, name, value, size);
        if (n < 0)
                return -errno;

        return (int) n;
}

int cg_get_xattr_malloc(const char *path, const char *name, char **ret) {
        _cleanup_free_ char *fs = NULL;
        int r;

        assert(path);
        assert(name);

        r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, path, NULL, &fs);
        if (r < 0)
                return r;

        return lgetxattr_malloc(fs, name, ret);
}

int cg_get_xattr_bool(const char *path, const char *name) {
        _cleanup_free_ char *fs = NULL;
        int r;

        assert(path);
        assert(name);

        r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, path, NULL, &fs);
        if (r < 0)
                return r;

        return getxattr_at_bool(AT_FDCWD, fs, name, /* flags= */ 0);
}

int cg_remove_xattr(const char *path, const char *name) {
        _cleanup_free_ char *fs = NULL;
        int r;

        assert(path);
        assert(name);

        r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, path, NULL, &fs);
        if (r < 0)
                return r;

        return RET_NERRNO(removexattr(fs, name));
}

int cg_pid_get_path(const char *controller, pid_t pid, char **ret_path) {
        _cleanup_fclose_ FILE *f = NULL;
        const char *fs, *controller_str = NULL;  /* avoid false maybe-uninitialized warning */
        int unified, r;

        assert(pid >= 0);
        assert(ret_path);

        if (controller) {
                if (!cg_controller_is_valid(controller))
                        return -EINVAL;
        } else
                controller = SYSTEMD_CGROUP_CONTROLLER;

        unified = cg_unified_controller(controller);
        if (unified < 0)
                return unified;
        if (unified == 0) {
                if (streq(controller, SYSTEMD_CGROUP_CONTROLLER))
                        controller_str = SYSTEMD_CGROUP_CONTROLLER_LEGACY;
                else
                        controller_str = controller;
        }

        fs = procfs_file_alloca(pid, "cgroup");
        r = fopen_unlocked(fs, "re", &f);
        if (r == -ENOENT)
                return -ESRCH;
        if (r < 0)
                return r;

        for (;;) {
                _cleanup_free_ char *line = NULL;
                char *e;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -ENODATA;

                if (unified) {
                        e = startswith(line, "0:");
                        if (!e)
                                continue;

                        e = strchr(e, ':');
                        if (!e)
                                continue;
                } else {
                        char *l;

                        l = strchr(line, ':');
                        if (!l)
                                continue;

                        l++;
                        e = strchr(l, ':');
                        if (!e)
                                continue;
                        *e = 0;

                        assert(controller_str);
                        r = string_contains_word(l, ",", controller_str);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                continue;
                }

                char *path = strdup(e + 1);
                if (!path)
                        return -ENOMEM;

                /* Truncate suffix indicating the process is a zombie */
                e = endswith(path, " (deleted)");
                if (e)
                        *e = 0;

                *ret_path = path;
                return 0;
        }
}

int cg_pidref_get_path(const char *controller, const PidRef *pidref, char **ret_path) {
        _cleanup_free_ char *path = NULL;
        int r;

        assert(ret_path);

        if (!pidref_is_set(pidref))
                return -ESRCH;

        r = cg_pid_get_path(controller, pidref->pid, &path);
        if (r < 0)
                return r;

        /* Before we return the path, make sure the procfs entry for this pid still matches the pidref */
        r = pidref_verify(pidref);
        if (r < 0)
                return r;

        *ret_path = TAKE_PTR(path);
        return 0;
}

int cg_install_release_agent(const char *controller, const char *agent) {
        _cleanup_free_ char *fs = NULL, *contents = NULL;
        const char *sc;
        int r;

        assert(agent);

        r = cg_unified_controller(controller);
        if (r < 0)
                return r;
        if (r > 0) /* doesn't apply to unified hierarchy */
                return -EOPNOTSUPP;

        r = cg_get_path(controller, NULL, "release_agent", &fs);
        if (r < 0)
                return r;

        r = read_one_line_file(fs, &contents);
        if (r < 0)
                return r;

        sc = strstrip(contents);
        if (isempty(sc)) {
                r = write_string_file(fs, agent, WRITE_STRING_FILE_DISABLE_BUFFER);
                if (r < 0)
                        return r;
        } else if (!path_equal(sc, agent))
                return -EEXIST;

        fs = mfree(fs);
        r = cg_get_path(controller, NULL, "notify_on_release", &fs);
        if (r < 0)
                return r;

        contents = mfree(contents);
        r = read_one_line_file(fs, &contents);
        if (r < 0)
                return r;

        sc = strstrip(contents);
        if (streq(sc, "0")) {
                r = write_string_file(fs, "1", WRITE_STRING_FILE_DISABLE_BUFFER);
                if (r < 0)
                        return r;

                return 1;
        }

        if (!streq(sc, "1"))
                return -EIO;

        return 0;
}

int cg_uninstall_release_agent(const char *controller) {
        _cleanup_free_ char *fs = NULL;
        int r;

        r = cg_unified_controller(controller);
        if (r < 0)
                return r;
        if (r > 0) /* Doesn't apply to unified hierarchy */
                return -EOPNOTSUPP;

        r = cg_get_path(controller, NULL, "notify_on_release", &fs);
        if (r < 0)
                return r;

        r = write_string_file(fs, "0", WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                return r;

        fs = mfree(fs);

        r = cg_get_path(controller, NULL, "release_agent", &fs);
        if (r < 0)
                return r;

        r = write_string_file(fs, "", WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                return r;

        return 0;
}

int cg_is_empty(const char *controller, const char *path) {
        _cleanup_fclose_ FILE *f = NULL;
        pid_t pid;
        int r;

        assert(path);

        r = cg_enumerate_processes(controller, path, &f);
        if (r == -ENOENT)
                return true;
        if (r < 0)
                return r;

        r = cg_read_pid(f, &pid);
        if (r < 0)
                return r;

        return r == 0;
}

int cg_is_empty_recursive(const char *controller, const char *path) {
        int r;

        assert(path);

        /* The root cgroup is always populated */
        if (controller && empty_or_root(path))
                return false;

        r = cg_unified_controller(controller);
        if (r < 0)
                return r;
        if (r > 0) {
                _cleanup_free_ char *t = NULL;

                /* On the unified hierarchy we can check empty state
                 * via the "populated" attribute of "cgroup.events". */

                r = cg_read_event(controller, path, "populated", &t);
                if (r == -ENOENT)
                        return true;
                if (r < 0)
                        return r;

                return streq(t, "0");
        } else {
                _cleanup_closedir_ DIR *d = NULL;
                char *fn;

                r = cg_is_empty(controller, path);
                if (r <= 0)
                        return r;

                r = cg_enumerate_subgroups(controller, path, &d);
                if (r == -ENOENT)
                        return true;
                if (r < 0)
                        return r;

                while ((r = cg_read_subgroup(d, &fn)) > 0) {
                        _cleanup_free_ char *p = NULL;

                        p = path_join(path, fn);
                        free(fn);
                        if (!p)
                                return -ENOMEM;

                        r = cg_is_empty_recursive(controller, p);
                        if (r <= 0)
                                return r;
                }
                if (r < 0)
                        return r;

                return true;
        }
}

int cg_split_spec(const char *spec, char **ret_controller, char **ret_path) {
        _cleanup_free_ char *controller = NULL, *path = NULL;
        int r;

        assert(spec);

        if (*spec == '/') {
                if (!path_is_normalized(spec))
                        return -EINVAL;

                if (ret_path) {
                        r = path_simplify_alloc(spec, &path);
                        if (r < 0)
                                return r;
                }

        } else {
                const char *e;

                e = strchr(spec, ':');
                if (e) {
                        controller = strndup(spec, e-spec);
                        if (!controller)
                                return -ENOMEM;
                        if (!cg_controller_is_valid(controller))
                                return -EINVAL;

                        if (!isempty(e + 1)) {
                                path = strdup(e+1);
                                if (!path)
                                        return -ENOMEM;

                                if (!path_is_normalized(path) ||
                                    !path_is_absolute(path))
                                        return -EINVAL;

                                path_simplify(path);
                        }

                } else {
                        if (!cg_controller_is_valid(spec))
                                return -EINVAL;

                        if (ret_controller) {
                                controller = strdup(spec);
                                if (!controller)
                                        return -ENOMEM;
                        }
                }
        }

        if (ret_controller)
                *ret_controller = TAKE_PTR(controller);
        if (ret_path)
                *ret_path = TAKE_PTR(path);
        return 0;
}

int cg_mangle_path(const char *path, char **ret) {
        _cleanup_free_ char *c = NULL, *p = NULL;
        int r;

        assert(path);
        assert(ret);

        /* First, check if it already is a filesystem path */
        if (path_startswith(path, "/sys/fs/cgroup"))
                return path_simplify_alloc(path, ret);

        /* Otherwise, treat it as cg spec */
        r = cg_split_spec(path, &c, &p);
        if (r < 0)
                return r;

        return cg_get_path(c ?: SYSTEMD_CGROUP_CONTROLLER, p ?: "/", NULL, ret);
}

int cg_get_root_path(char **ret_path) {
        char *p, *e;
        int r;

        assert(ret_path);

        r = cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER, 1, &p);
        if (r < 0)
                return r;

        e = endswith(p, "/" SPECIAL_INIT_SCOPE);
        if (!e)
                e = endswith(p, "/" SPECIAL_SYSTEM_SLICE); /* legacy */
        if (!e)
                e = endswith(p, "/system"); /* even more legacy */
        if (e)
                *e = 0;

        *ret_path = p;
        return 0;
}

int cg_shift_path(const char *cgroup, const char *root, const char **ret_shifted) {
        _cleanup_free_ char *rt = NULL;
        char *p;
        int r;

        assert(cgroup);
        assert(ret_shifted);

        if (!root) {
                /* If the root was specified let's use that, otherwise
                 * let's determine it from PID 1 */

                r = cg_get_root_path(&rt);
                if (r < 0)
                        return r;

                root = rt;
        }

        p = path_startswith(cgroup, root);
        if (p && p > cgroup)
                *ret_shifted = p - 1;
        else
                *ret_shifted = cgroup;

        return 0;
}

int cg_pid_get_path_shifted(pid_t pid, const char *root, char **ret_cgroup) {
        _cleanup_free_ char *raw = NULL;
        const char *c;
        int r;

        assert(pid >= 0);
        assert(ret_cgroup);

        r = cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER, pid, &raw);
        if (r < 0)
                return r;

        r = cg_shift_path(raw, root, &c);
        if (r < 0)
                return r;

        if (c == raw)
                *ret_cgroup = TAKE_PTR(raw);
        else {
                char *n;

                n = strdup(c);
                if (!n)
                        return -ENOMEM;

                *ret_cgroup = n;
        }

        return 0;
}

int cg_path_decode_unit(const char *cgroup, char **ret_unit) {
        char *c, *s;
        size_t n;

        assert(cgroup);
        assert(ret_unit);

        n = strcspn(cgroup, "/");
        if (n < 3)
                return -ENXIO;

        c = strndupa_safe(cgroup, n);
        c = cg_unescape(c);

        if (!unit_name_is_valid(c, UNIT_NAME_PLAIN|UNIT_NAME_INSTANCE))
                return -ENXIO;

        s = strdup(c);
        if (!s)
                return -ENOMEM;

        *ret_unit = s;
        return 0;
}

static bool valid_slice_name(const char *p, size_t n) {

        if (!p)
                return false;

        if (n < STRLEN("x.slice"))
                return false;

        if (memcmp(p + n - 6, ".slice", 6) == 0) {
                char buf[n+1], *c;

                memcpy(buf, p, n);
                buf[n] = 0;

                c = cg_unescape(buf);

                return unit_name_is_valid(c, UNIT_NAME_PLAIN);
        }

        return false;
}

static const char *skip_slices(const char *p) {
        assert(p);

        /* Skips over all slice assignments */

        for (;;) {
                size_t n;

                p += strspn(p, "/");

                n = strcspn(p, "/");
                if (!valid_slice_name(p, n))
                        return p;

                p += n;
        }
}

int cg_path_get_unit(const char *path, char **ret) {
        _cleanup_free_ char *unit = NULL;
        const char *e;
        int r;

        assert(path);
        assert(ret);

        e = skip_slices(path);

        r = cg_path_decode_unit(e, &unit);
        if (r < 0)
                return r;

        /* We skipped over the slices, don't accept any now */
        if (endswith(unit, ".slice"))
                return -ENXIO;

        *ret = TAKE_PTR(unit);
        return 0;
}

int cg_path_get_unit_path(const char *path, char **ret) {
        _cleanup_free_ char *path_copy = NULL;
        char *unit_name;

        assert(path);
        assert(ret);

        path_copy = strdup(path);
        if (!path_copy)
                return -ENOMEM;

        unit_name = (char *)skip_slices(path_copy);
        unit_name[strcspn(unit_name, "/")] = 0;

        if (!unit_name_is_valid(cg_unescape(unit_name), UNIT_NAME_PLAIN|UNIT_NAME_INSTANCE))
                return -ENXIO;

        *ret = TAKE_PTR(path_copy);

        return 0;
}

int cg_pid_get_unit(pid_t pid, char **ret_unit) {
        _cleanup_free_ char *cgroup = NULL;
        int r;

        assert(ret_unit);

        r = cg_pid_get_path_shifted(pid, NULL, &cgroup);
        if (r < 0)
                return r;

        return cg_path_get_unit(cgroup, ret_unit);
}

int cg_pidref_get_unit(const PidRef *pidref, char **ret) {
        _cleanup_free_ char *unit = NULL;
        int r;

        assert(ret);

        if (!pidref_is_set(pidref))
                return -ESRCH;

        r = cg_pid_get_unit(pidref->pid, &unit);
        if (r < 0)
                return r;

        r = pidref_verify(pidref);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(unit);
        return 0;
}

/**
 * Skip session-*.scope, but require it to be there.
 */
static const char *skip_session(const char *p) {
        size_t n;

        if (isempty(p))
                return NULL;

        p += strspn(p, "/");

        n = strcspn(p, "/");
        if (n < STRLEN("session-x.scope"))
                return NULL;

        if (memcmp(p, "session-", 8) == 0 && memcmp(p + n - 6, ".scope", 6) == 0) {
                char buf[n - 8 - 6 + 1];

                memcpy(buf, p + 8, n - 8 - 6);
                buf[n - 8 - 6] = 0;

                /* Note that session scopes never need unescaping,
                 * since they cannot conflict with the kernel's own
                 * names, hence we don't need to call cg_unescape()
                 * here. */

                if (!session_id_valid(buf))
                        return NULL;

                p += n;
                p += strspn(p, "/");
                return p;
        }

        return NULL;
}

/**
 * Skip user@*.service, but require it to be there.
 */
static const char *skip_user_manager(const char *p) {
        size_t n;

        if (isempty(p))
                return NULL;

        p += strspn(p, "/");

        n = strcspn(p, "/");
        if (n < STRLEN("user@x.service"))
                return NULL;

        if (memcmp(p, "user@", 5) == 0 && memcmp(p + n - 8, ".service", 8) == 0) {
                char buf[n - 5 - 8 + 1];

                memcpy(buf, p + 5, n - 5 - 8);
                buf[n - 5 - 8] = 0;

                /* Note that user manager services never need unescaping,
                 * since they cannot conflict with the kernel's own
                 * names, hence we don't need to call cg_unescape()
                 * here. */

                if (parse_uid(buf, NULL) < 0)
                        return NULL;

                p += n;
                p += strspn(p, "/");

                return p;
        }

        return NULL;
}

static const char *skip_user_prefix(const char *path) {
        const char *e, *t;

        assert(path);

        /* Skip slices, if there are any */
        e = skip_slices(path);

        /* Skip the user manager, if it's in the path now... */
        t = skip_user_manager(e);
        if (t)
                return t;

        /* Alternatively skip the user session if it is in the path... */
        return skip_session(e);
}

int cg_path_get_user_unit(const char *path, char **ret) {
        const char *t;

        assert(path);
        assert(ret);

        t = skip_user_prefix(path);
        if (!t)
                return -ENXIO;

        /* And from here on it looks pretty much the same as for a system unit, hence let's use the same
         * parser. */
        return cg_path_get_unit(t, ret);
}

int cg_pid_get_user_unit(pid_t pid, char **ret_unit) {
        _cleanup_free_ char *cgroup = NULL;
        int r;

        assert(ret_unit);

        r = cg_pid_get_path_shifted(pid, NULL, &cgroup);
        if (r < 0)
                return r;

        return cg_path_get_user_unit(cgroup, ret_unit);
}

int cg_path_get_machine_name(const char *path, char **ret_machine) {
        _cleanup_free_ char *u = NULL;
        const char *sl;
        int r;

        r = cg_path_get_unit(path, &u);
        if (r < 0)
                return r;

        sl = strjoina("/run/systemd/machines/unit:", u);
        return readlink_malloc(sl, ret_machine);
}

int cg_pid_get_machine_name(pid_t pid, char **ret_machine) {
        _cleanup_free_ char *cgroup = NULL;
        int r;

        assert(ret_machine);

        r = cg_pid_get_path_shifted(pid, NULL, &cgroup);
        if (r < 0)
                return r;

        return cg_path_get_machine_name(cgroup, ret_machine);
}

int cg_path_get_cgroupid(const char *path, uint64_t *ret) {
        cg_file_handle fh = CG_FILE_HANDLE_INIT;
        int mnt_id = -1;

        assert(path);
        assert(ret);

        /* This is cgroupfs so we know the size of the handle, thus no need to loop around like
         * name_to_handle_at_loop() does in mountpoint-util.c */
        if (name_to_handle_at(AT_FDCWD, path, &fh.file_handle, &mnt_id, 0) < 0)
                return -errno;

        *ret = CG_FILE_HANDLE_CGROUPID(fh);
        return 0;
}

int cg_fd_get_cgroupid(int fd, uint64_t *ret) {
        cg_file_handle fh = CG_FILE_HANDLE_INIT;
        int mnt_id = -1;

        assert(fd >= 0);
        assert(ret);

        if (name_to_handle_at(fd, "", &fh.file_handle, &mnt_id, AT_EMPTY_PATH) < 0)
                return -errno;

        *ret = CG_FILE_HANDLE_CGROUPID(fh);
        return 0;
}

int cg_path_get_session(const char *path, char **ret_session) {
        _cleanup_free_ char *unit = NULL;
        char *start, *end;
        int r;

        assert(path);

        r = cg_path_get_unit(path, &unit);
        if (r < 0)
                return r;

        start = startswith(unit, "session-");
        if (!start)
                return -ENXIO;
        end = endswith(start, ".scope");
        if (!end)
                return -ENXIO;

        *end = 0;
        if (!session_id_valid(start))
                return -ENXIO;

        if (ret_session) {
                char *rr;

                rr = strdup(start);
                if (!rr)
                        return -ENOMEM;

                *ret_session = rr;
        }

        return 0;
}

int cg_pid_get_session(pid_t pid, char **ret_session) {
        _cleanup_free_ char *cgroup = NULL;
        int r;

        r = cg_pid_get_path_shifted(pid, NULL, &cgroup);
        if (r < 0)
                return r;

        return cg_path_get_session(cgroup, ret_session);
}

int cg_path_get_owner_uid(const char *path, uid_t *ret_uid) {
        _cleanup_free_ char *slice = NULL;
        char *start, *end;
        int r;

        assert(path);

        r = cg_path_get_slice(path, &slice);
        if (r < 0)
                return r;

        start = startswith(slice, "user-");
        if (!start)
                return -ENXIO;

        end = endswith(start, ".slice");
        if (!end)
                return -ENXIO;

        *end = 0;
        if (parse_uid(start, ret_uid) < 0)
                return -ENXIO;

        return 0;
}

int cg_pid_get_owner_uid(pid_t pid, uid_t *ret_uid) {
        _cleanup_free_ char *cgroup = NULL;
        int r;

        r = cg_pid_get_path_shifted(pid, NULL, &cgroup);
        if (r < 0)
                return r;

        return cg_path_get_owner_uid(cgroup, ret_uid);
}

int cg_path_get_slice(const char *p, char **ret_slice) {
        const char *e = NULL;

        assert(p);
        assert(ret_slice);

        /* Finds the right-most slice unit from the beginning, but
         * stops before we come to the first non-slice unit. */

        for (;;) {
                size_t n;

                p += strspn(p, "/");

                n = strcspn(p, "/");
                if (!valid_slice_name(p, n)) {

                        if (!e) {
                                char *s;

                                s = strdup(SPECIAL_ROOT_SLICE);
                                if (!s)
                                        return -ENOMEM;

                                *ret_slice = s;
                                return 0;
                        }

                        return cg_path_decode_unit(e, ret_slice);
                }

                e = p;
                p += n;
        }
}

int cg_pid_get_slice(pid_t pid, char **ret_slice) {
        _cleanup_free_ char *cgroup = NULL;
        int r;

        assert(ret_slice);

        r = cg_pid_get_path_shifted(pid, NULL, &cgroup);
        if (r < 0)
                return r;

        return cg_path_get_slice(cgroup, ret_slice);
}

int cg_path_get_user_slice(const char *p, char **ret_slice) {
        const char *t;
        assert(p);
        assert(ret_slice);

        t = skip_user_prefix(p);
        if (!t)
                return -ENXIO;

        /* And now it looks pretty much the same as for a system slice, so let's just use the same parser
         * from here on. */
        return cg_path_get_slice(t, ret_slice);
}

int cg_pid_get_user_slice(pid_t pid, char **ret_slice) {
        _cleanup_free_ char *cgroup = NULL;
        int r;

        assert(ret_slice);

        r = cg_pid_get_path_shifted(pid, NULL, &cgroup);
        if (r < 0)
                return r;

        return cg_path_get_user_slice(cgroup, ret_slice);
}

bool cg_needs_escape(const char *p) {

        /* Checks if the specified path is a valid cgroup name by our rules, or if it must be escaped. Note
         * that we consider escaped cgroup names invalid here, as they need to be escaped a second time if
         * they shall be used. Also note that various names cannot be made valid by escaping even if we
         * return true here (because too long, or contain the forbidden character "/"). */

        if (!filename_is_valid(p))
                return true;

        if (IN_SET(p[0], '_', '.'))
                return true;

        if (STR_IN_SET(p, "notify_on_release", "release_agent", "tasks"))
                return true;

        if (startswith(p, "cgroup."))
                return true;

        for (CGroupController c = 0; c < _CGROUP_CONTROLLER_MAX; c++) {
                const char *q;

                q = startswith(p, cgroup_controller_to_string(c));
                if (!q)
                        continue;

                if (q[0] == '.')
                        return true;
        }

        return false;
}

int cg_escape(const char *p, char **ret) {
        _cleanup_free_ char *n = NULL;

        /* This implements very minimal escaping for names to be used as file names in the cgroup tree: any
         * name which might conflict with a kernel name or is prefixed with '_' is prefixed with a '_'. That
         * way, when reading cgroup names it is sufficient to remove a single prefixing underscore if there
         * is one. */

        /* The return value of this function (unlike cg_unescape()) needs free()! */

        if (cg_needs_escape(p)) {
                n = strjoin("_", p);
                if (!n)
                        return -ENOMEM;

                if (!filename_is_valid(n)) /* became invalid due to the prefixing? Or contained things like a slash that cannot be fixed by prefixing? */
                        return -EINVAL;
        } else {
                n = strdup(p);
                if (!n)
                        return -ENOMEM;
        }

        *ret = TAKE_PTR(n);
        return 0;
}

char *cg_unescape(const char *p) {
        assert(p);

        /* The return value of this function (unlike cg_escape())
         * doesn't need free()! */

        if (p[0] == '_')
                return (char*) p+1;

        return (char*) p;
}

#define CONTROLLER_VALID                        \
        DIGITS LETTERS                          \
        "_"

bool cg_controller_is_valid(const char *p) {
        const char *t, *s;

        if (!p)
                return false;

        if (streq(p, SYSTEMD_CGROUP_CONTROLLER))
                return true;

        s = startswith(p, "name=");
        if (s)
                p = s;

        if (IN_SET(*p, 0, '_'))
                return false;

        for (t = p; *t; t++)
                if (!strchr(CONTROLLER_VALID, *t))
                        return false;

        if (t - p > NAME_MAX)
                return false;

        return true;
}

int cg_slice_to_path(const char *unit, char **ret) {
        _cleanup_free_ char *p = NULL, *s = NULL, *e = NULL;
        const char *dash;
        int r;

        assert(unit);
        assert(ret);

        if (streq(unit, SPECIAL_ROOT_SLICE)) {
                char *x;

                x = strdup("");
                if (!x)
                        return -ENOMEM;
                *ret = x;
                return 0;
        }

        if (!unit_name_is_valid(unit, UNIT_NAME_PLAIN))
                return -EINVAL;

        if (!endswith(unit, ".slice"))
                return -EINVAL;

        r = unit_name_to_prefix(unit, &p);
        if (r < 0)
                return r;

        dash = strchr(p, '-');

        /* Don't allow initial dashes */
        if (dash == p)
                return -EINVAL;

        while (dash) {
                _cleanup_free_ char *escaped = NULL;
                char n[dash - p + sizeof(".slice")];

#if HAS_FEATURE_MEMORY_SANITIZER
                /* msan doesn't instrument stpncpy, so it thinks
                 * n is later used uninitialized:
                 * https://github.com/google/sanitizers/issues/926
                 */
                zero(n);
#endif

                /* Don't allow trailing or double dashes */
                if (IN_SET(dash[1], 0, '-'))
                        return -EINVAL;

                strcpy(stpncpy(n, p, dash - p), ".slice");
                if (!unit_name_is_valid(n, UNIT_NAME_PLAIN))
                        return -EINVAL;

                r = cg_escape(n, &escaped);
                if (r < 0)
                        return r;

                if (!strextend(&s, escaped, "/"))
                        return -ENOMEM;

                dash = strchr(dash+1, '-');
        }

        r = cg_escape(unit, &e);
        if (r < 0)
                return r;

        if (!strextend(&s, e))
                return -ENOMEM;

        *ret = TAKE_PTR(s);
        return 0;
}

int cg_is_threaded(const char *path) {
        _cleanup_free_ char *fs = NULL, *contents = NULL;
        _cleanup_strv_free_ char **v = NULL;
        int r;

        r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, path, "cgroup.type", &fs);
        if (r < 0)
                return r;

        r = read_full_virtual_file(fs, &contents, NULL);
        if (r == -ENOENT)
                return false; /* Assume no. */
        if (r < 0)
                return r;

        v = strv_split(contents, NULL);
        if (!v)
                return -ENOMEM;

        /* If the cgroup is in the threaded mode, it contains "threaded".
         * If one of the parents or siblings is in the threaded mode, it may contain "invalid". */
        return strv_contains(v, "threaded") || strv_contains(v, "invalid");
}

int cg_set_attribute(const char *controller, const char *path, const char *attribute, const char *value) {
        _cleanup_free_ char *p = NULL;
        int r;

        r = cg_get_path(controller, path, attribute, &p);
        if (r < 0)
                return r;

        return write_string_file(p, value, WRITE_STRING_FILE_DISABLE_BUFFER);
}

int cg_get_attribute(const char *controller, const char *path, const char *attribute, char **ret) {
        _cleanup_free_ char *p = NULL;
        int r;

        r = cg_get_path(controller, path, attribute, &p);
        if (r < 0)
                return r;

        return read_one_line_file(p, ret);
}

int cg_get_attribute_as_uint64(const char *controller, const char *path, const char *attribute, uint64_t *ret) {
        _cleanup_free_ char *value = NULL;
        uint64_t v;
        int r;

        assert(ret);

        r = cg_get_attribute(controller, path, attribute, &value);
        if (r == -ENOENT)
                return -ENODATA;
        if (r < 0)
                return r;

        if (streq(value, "max")) {
                *ret = CGROUP_LIMIT_MAX;
                return 0;
        }

        r = safe_atou64(value, &v);
        if (r < 0)
                return r;

        *ret = v;
        return 0;
}

int cg_get_attribute_as_bool(const char *controller, const char *path, const char *attribute, bool *ret) {
        _cleanup_free_ char *value = NULL;
        int r;

        assert(ret);

        r = cg_get_attribute(controller, path, attribute, &value);
        if (r == -ENOENT)
                return -ENODATA;
        if (r < 0)
                return r;

        r = parse_boolean(value);
        if (r < 0)
                return r;

        *ret = r;
        return 0;
}

int cg_get_owner(const char *path, uid_t *ret_uid) {
        _cleanup_free_ char *f = NULL;
        struct stat stats;
        int r;

        assert(ret_uid);

        r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, path, NULL, &f);
        if (r < 0)
                return r;

        if (stat(f, &stats) < 0)
                return -errno;

        r = stat_verify_directory(&stats);
        if (r < 0)
                return r;

        *ret_uid = stats.st_uid;
        return 0;
}

int cg_get_keyed_attribute_full(
                const char *controller,
                const char *path,
                const char *attribute,
                char **keys,
                char **ret_values,
                CGroupKeyMode mode) {

        _cleanup_free_ char *filename = NULL, *contents = NULL;
        const char *p;
        size_t n, i, n_done = 0;
        char **v;
        int r;

        /* Reads one or more fields of a cgroup v2 keyed attribute file. The 'keys' parameter should be an strv with
         * all keys to retrieve. The 'ret_values' parameter should be passed as string size with the same number of
         * entries as 'keys'. On success each entry will be set to the value of the matching key.
         *
         * If the attribute file doesn't exist at all returns ENOENT, if any key is not found returns ENXIO. If mode
         * is set to GG_KEY_MODE_GRACEFUL we ignore missing keys and return those that were parsed successfully. */

        r = cg_get_path(controller, path, attribute, &filename);
        if (r < 0)
                return r;

        r = read_full_file(filename, &contents, NULL);
        if (r < 0)
                return r;

        n = strv_length(keys);
        if (n == 0) /* No keys to retrieve? That's easy, we are done then */
                return 0;

        /* Let's build this up in a temporary array for now in order not to clobber the return parameter on failure */
        v = newa0(char*, n);

        for (p = contents; *p;) {
                const char *w = NULL;

                for (i = 0; i < n; i++)
                        if (!v[i]) {
                                w = first_word(p, keys[i]);
                                if (w)
                                        break;
                        }

                if (w) {
                        size_t l;

                        l = strcspn(w, NEWLINE);
                        v[i] = strndup(w, l);
                        if (!v[i]) {
                                r = -ENOMEM;
                                goto fail;
                        }

                        n_done++;
                        if (n_done >= n)
                                goto done;

                        p = w + l;
                } else
                        p += strcspn(p, NEWLINE);

                p += strspn(p, NEWLINE);
        }

        if (mode & CG_KEY_MODE_GRACEFUL)
                goto done;

        r = -ENXIO;

fail:
        free_many_charp(v, n);
        return r;

done:
        memcpy(ret_values, v, sizeof(char*) * n);
        if (mode & CG_KEY_MODE_GRACEFUL)
                return n_done;

        return 0;
}

int cg_mask_to_string(CGroupMask mask, char **ret) {
        _cleanup_free_ char *s = NULL;
        bool space = false;
        CGroupController c;
        size_t n = 0;

        assert(ret);

        if (mask == 0) {
                *ret = NULL;
                return 0;
        }

        for (c = 0; c < _CGROUP_CONTROLLER_MAX; c++) {
                const char *k;
                size_t l;

                if (!FLAGS_SET(mask, CGROUP_CONTROLLER_TO_MASK(c)))
                        continue;

                k = cgroup_controller_to_string(c);
                l = strlen(k);

                if (!GREEDY_REALLOC(s, n + space + l + 1))
                        return -ENOMEM;

                if (space)
                        s[n] = ' ';
                memcpy(s + n + space, k, l);
                n += space + l;

                space = true;
        }

        assert(s);

        s[n] = 0;
        *ret = TAKE_PTR(s);

        return 0;
}

int cg_mask_from_string(const char *value, CGroupMask *ret) {
        CGroupMask m = 0;

        assert(ret);
        assert(value);

        for (;;) {
                _cleanup_free_ char *n = NULL;
                CGroupController v;
                int r;

                r = extract_first_word(&value, &n, NULL, 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                v = cgroup_controller_from_string(n);
                if (v < 0)
                        continue;

                m |= CGROUP_CONTROLLER_TO_MASK(v);
        }

        *ret = m;
        return 0;
}

int cg_mask_supported_subtree(const char *root, CGroupMask *ret) {
        CGroupMask mask;
        int r;

        /* Determines the mask of supported cgroup controllers. Only includes controllers we can make sense of and that
         * are actually accessible. Only covers real controllers, i.e. not the CGROUP_CONTROLLER_BPF_xyz
         * pseudo-controllers. */

        r = cg_all_unified();
        if (r < 0)
                return r;
        if (r > 0) {
                _cleanup_free_ char *controllers = NULL, *path = NULL;

                /* In the unified hierarchy we can read the supported and accessible controllers from
                 * the top-level cgroup attribute */

                r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, root, "cgroup.controllers", &path);
                if (r < 0)
                        return r;

                r = read_one_line_file(path, &controllers);
                if (r < 0)
                        return r;

                r = cg_mask_from_string(controllers, &mask);
                if (r < 0)
                        return r;

                /* Mask controllers that are not supported in unified hierarchy. */
                mask &= CGROUP_MASK_V2;

        } else {
                CGroupController c;

                /* In the legacy hierarchy, we check which hierarchies are accessible. */

                mask = 0;
                for (c = 0; c < _CGROUP_CONTROLLER_MAX; c++) {
                        CGroupMask bit = CGROUP_CONTROLLER_TO_MASK(c);
                        const char *n;

                        if (!FLAGS_SET(CGROUP_MASK_V1, bit))
                                continue;

                        n = cgroup_controller_to_string(c);
                        if (controller_is_v1_accessible(root, n) >= 0)
                                mask |= bit;
                }
        }

        *ret = mask;
        return 0;
}

int cg_mask_supported(CGroupMask *ret) {
        _cleanup_free_ char *root = NULL;
        int r;

        r = cg_get_root_path(&root);
        if (r < 0)
                return r;

        return cg_mask_supported_subtree(root, ret);
}

int cg_kernel_controllers(Set **ret) {
        _cleanup_set_free_ Set *controllers = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(ret);

        /* Determines the full list of kernel-known controllers. Might include controllers we don't actually support
         * and controllers that aren't currently accessible (because not mounted). This does not include "name="
         * pseudo-controllers. */

        r = fopen_unlocked("/proc/cgroups", "re", &f);
        if (r == -ENOENT) {
                *ret = NULL;
                return 0;
        }
        if (r < 0)
                return r;

        /* Ignore the header line */
        (void) read_line(f, SIZE_MAX, NULL);

        for (;;) {
                _cleanup_free_ char *controller = NULL;
                int enabled = 0;

                if (fscanf(f, "%ms %*i %*i %i", &controller, &enabled) != 2) {

                        if (ferror(f))
                                return -errno;

                        if (feof(f))
                                break;

                        return -EBADMSG;
                }

                if (!enabled)
                        continue;

                if (!cg_controller_is_valid(controller))
                        return -EBADMSG;

                r = set_ensure_consume(&controllers, &string_hash_ops_free, TAKE_PTR(controller));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(controllers);

        return 0;
}

/* The hybrid mode was initially implemented in v232 and simply mounted cgroup2 on
 * /sys/fs/cgroup/systemd. This unfortunately broke other tools (such as docker) which expected the v1
 * "name=systemd" hierarchy on /sys/fs/cgroup/systemd. From v233 and on, the hybrid mode mounts v2 on
 * /sys/fs/cgroup/unified and maintains "name=systemd" hierarchy on /sys/fs/cgroup/systemd for compatibility
 * with other tools.
 *
 * To keep live upgrade working, we detect and support v232 layout. When v232 layout is detected, to keep
 * cgroup v2 process management but disable the compat dual layout, we return true on
 * cg_unified_controller(SYSTEMD_CGROUP_CONTROLLER) and false on cg_hybrid_unified().
 */
static thread_local bool unified_systemd_v232;

int cg_unified_cached(bool flush) {
        static thread_local CGroupUnified unified_cache = CGROUP_UNIFIED_UNKNOWN;

        struct statfs fs;

        /* Checks if we support the unified hierarchy. Returns an
         * error when the cgroup hierarchies aren't mounted yet or we
         * have any other trouble determining if the unified hierarchy
         * is supported. */

        if (flush)
                unified_cache = CGROUP_UNIFIED_UNKNOWN;
        else if (unified_cache >= CGROUP_UNIFIED_NONE)
                return unified_cache;

        if (statfs("/sys/fs/cgroup/", &fs) < 0)
                return log_debug_errno(errno, "statfs(\"/sys/fs/cgroup/\") failed: %m");

        if (F_TYPE_EQUAL(fs.f_type, CGROUP2_SUPER_MAGIC)) {
                log_debug("Found cgroup2 on /sys/fs/cgroup/, full unified hierarchy");
                unified_cache = CGROUP_UNIFIED_ALL;
        } else if (F_TYPE_EQUAL(fs.f_type, TMPFS_MAGIC)) {
                if (statfs("/sys/fs/cgroup/unified/", &fs) == 0 &&
                    F_TYPE_EQUAL(fs.f_type, CGROUP2_SUPER_MAGIC)) {
                        log_debug("Found cgroup2 on /sys/fs/cgroup/unified, unified hierarchy for systemd controller");
                        unified_cache = CGROUP_UNIFIED_SYSTEMD;
                        unified_systemd_v232 = false;
                } else {
                        if (statfs("/sys/fs/cgroup/systemd/", &fs) < 0) {
                                if (errno == ENOENT) {
                                        /* Some other software may have set up /sys/fs/cgroup in a configuration we do not recognize. */
                                        log_debug_errno(errno, "Unsupported cgroupsv1 setup detected: name=systemd hierarchy not found.");
                                        return -ENOMEDIUM;
                                }
                                return log_debug_errno(errno, "statfs(\"/sys/fs/cgroup/systemd\" failed: %m");
                        }

                        if (F_TYPE_EQUAL(fs.f_type, CGROUP2_SUPER_MAGIC)) {
                                log_debug("Found cgroup2 on /sys/fs/cgroup/systemd, unified hierarchy for systemd controller (v232 variant)");
                                unified_cache = CGROUP_UNIFIED_SYSTEMD;
                                unified_systemd_v232 = true;
                        } else if (F_TYPE_EQUAL(fs.f_type, CGROUP_SUPER_MAGIC)) {
                                log_debug("Found cgroup on /sys/fs/cgroup/systemd, legacy hierarchy");
                                unified_cache = CGROUP_UNIFIED_NONE;
                        } else {
                                log_debug("Unexpected filesystem type %llx mounted on /sys/fs/cgroup/systemd, assuming legacy hierarchy",
                                          (unsigned long long) fs.f_type);
                                unified_cache = CGROUP_UNIFIED_NONE;
                        }
                }
        } else if (F_TYPE_EQUAL(fs.f_type, SYSFS_MAGIC)) {
                return log_debug_errno(SYNTHETIC_ERRNO(ENOMEDIUM),
                                       "No filesystem is currently mounted on /sys/fs/cgroup.");
        } else
                return log_debug_errno(SYNTHETIC_ERRNO(ENOMEDIUM),
                                       "Unknown filesystem type %llx mounted on /sys/fs/cgroup.",
                                       (unsigned long long)fs.f_type);

        return unified_cache;
}

int cg_unified_controller(const char *controller) {
        int r;

        r = cg_unified_cached(false);
        if (r < 0)
                return r;

        if (r == CGROUP_UNIFIED_NONE)
                return false;

        if (r >= CGROUP_UNIFIED_ALL)
                return true;

        return streq_ptr(controller, SYSTEMD_CGROUP_CONTROLLER);
}

int cg_all_unified(void) {
        int r;

        r = cg_unified_cached(false);
        if (r < 0)
                return r;

        return r >= CGROUP_UNIFIED_ALL;
}

int cg_hybrid_unified(void) {
        int r;

        r = cg_unified_cached(false);
        if (r < 0)
                return r;

        return r == CGROUP_UNIFIED_SYSTEMD && !unified_systemd_v232;
}

int cg_is_delegated(const char *path) {
        int r;

        assert(path);

        r = cg_get_xattr_bool(path, "trusted.delegate");
        if (!ERRNO_IS_NEG_XATTR_ABSENT(r))
                return r;

        /* If the trusted xattr isn't set (preferred), then check the untrusted one. Under the assumption
         * that whoever is trusted enough to own the cgroup, is also trusted enough to decide if it is
         * delegated or not this should be safe. */
        r = cg_get_xattr_bool(path, "user.delegate");
        return ERRNO_IS_NEG_XATTR_ABSENT(r) ? false : r;
}

int cg_is_delegated_fd(int fd) {
        int r;

        assert(fd >= 0);

        r = getxattr_at_bool(fd, /* path= */ NULL, "trusted.delegate", /* flags= */ 0);
        if (!ERRNO_IS_NEG_XATTR_ABSENT(r))
                return r;

        r = getxattr_at_bool(fd, /* path= */ NULL, "user.delegate", /* flags= */ 0);
        return ERRNO_IS_NEG_XATTR_ABSENT(r) ? false : r;
}

int cg_has_coredump_receive(const char *path) {
        int r;

        assert(path);

        r = cg_get_xattr_bool(path, "user.coredump_receive");
        if (ERRNO_IS_NEG_XATTR_ABSENT(r))
                return false;

        return r;
}

const uint64_t cgroup_io_limit_defaults[_CGROUP_IO_LIMIT_TYPE_MAX] = {
        [CGROUP_IO_RBPS_MAX]    = CGROUP_LIMIT_MAX,
        [CGROUP_IO_WBPS_MAX]    = CGROUP_LIMIT_MAX,
        [CGROUP_IO_RIOPS_MAX]   = CGROUP_LIMIT_MAX,
        [CGROUP_IO_WIOPS_MAX]   = CGROUP_LIMIT_MAX,
};

static const char* const cgroup_io_limit_type_table[_CGROUP_IO_LIMIT_TYPE_MAX] = {
        [CGROUP_IO_RBPS_MAX]    = "IOReadBandwidthMax",
        [CGROUP_IO_WBPS_MAX]    = "IOWriteBandwidthMax",
        [CGROUP_IO_RIOPS_MAX]   = "IOReadIOPSMax",
        [CGROUP_IO_WIOPS_MAX]   = "IOWriteIOPSMax",
};

DEFINE_STRING_TABLE_LOOKUP(cgroup_io_limit_type, CGroupIOLimitType);

bool is_cgroup_fs(const struct statfs *s) {
        return is_fs_type(s, CGROUP_SUPER_MAGIC) ||
               is_fs_type(s, CGROUP2_SUPER_MAGIC);
}

bool fd_is_cgroup_fs(int fd) {
        struct statfs s;

        if (fstatfs(fd, &s) < 0)
                return -errno;

        return is_cgroup_fs(&s);
}

static const char *const cgroup_controller_table[_CGROUP_CONTROLLER_MAX] = {
        [CGROUP_CONTROLLER_CPU] = "cpu",
        [CGROUP_CONTROLLER_CPUACCT] = "cpuacct",
        [CGROUP_CONTROLLER_CPUSET] = "cpuset",
        [CGROUP_CONTROLLER_IO] = "io",
        [CGROUP_CONTROLLER_BLKIO] = "blkio",
        [CGROUP_CONTROLLER_MEMORY] = "memory",
        [CGROUP_CONTROLLER_DEVICES] = "devices",
        [CGROUP_CONTROLLER_PIDS] = "pids",
        [CGROUP_CONTROLLER_BPF_FIREWALL] = "bpf-firewall",
        [CGROUP_CONTROLLER_BPF_DEVICES] = "bpf-devices",
        [CGROUP_CONTROLLER_BPF_FOREIGN] = "bpf-foreign",
        [CGROUP_CONTROLLER_BPF_SOCKET_BIND] = "bpf-socket-bind",
        [CGROUP_CONTROLLER_BPF_RESTRICT_NETWORK_INTERFACES] = "bpf-restrict-network-interfaces",
};

DEFINE_STRING_TABLE_LOOKUP(cgroup_controller, CGroupController);

CGroupMask get_cpu_accounting_mask(void) {
        static CGroupMask needed_mask = (CGroupMask) -1;

        /* On kernel ≥4.15 with unified hierarchy, cpu.stat's usage_usec is
         * provided externally from the CPU controller, which means we don't
         * need to enable the CPU controller just to get metrics. This is good,
         * because enabling the CPU controller comes at a minor performance
         * hit, especially when it's propagated deep into large hierarchies.
         * There's also no separate CPU accounting controller available within
         * a unified hierarchy.
         *
         * This combination of factors results in the desired cgroup mask to
         * enable for CPU accounting varying as follows:
         *
         *                   ╔═════════════════════╤═════════════════════╗
         *                   ║     Linux ≥4.15     │     Linux <4.15     ║
         *   ╔═══════════════╬═════════════════════╪═════════════════════╣
         *   ║ Unified       ║ nothing             │ CGROUP_MASK_CPU     ║
         *   ╟───────────────╫─────────────────────┼─────────────────────╢
         *   ║ Hybrid/Legacy ║ CGROUP_MASK_CPUACCT │ CGROUP_MASK_CPUACCT ║
         *   ╚═══════════════╩═════════════════════╧═════════════════════╝
         *
         * We check kernel version here instead of manually checking whether
         * cpu.stat is present for every cgroup, as that check in itself would
         * already be fairly expensive.
         *
         * Kernels where this patch has been backported will therefore have the
         * CPU controller enabled unnecessarily. This is more expensive than
         * necessary, but harmless. ☺️
         */

        if (needed_mask == (CGroupMask) -1) {
                if (cg_all_unified()) {
                        struct utsname u;
                        assert_se(uname(&u) >= 0);

                        if (strverscmp_improved(u.release, "4.15") < 0)
                                needed_mask = CGROUP_MASK_CPU;
                        else
                                needed_mask = 0;
                } else
                        needed_mask = CGROUP_MASK_CPUACCT;
        }

        return needed_mask;
}

bool cpu_accounting_is_cheap(void) {
        return get_cpu_accounting_mask() == 0;
}

static const char* const managed_oom_mode_table[_MANAGED_OOM_MODE_MAX] = {
        [MANAGED_OOM_AUTO] = "auto",
        [MANAGED_OOM_KILL] = "kill",
};

DEFINE_STRING_TABLE_LOOKUP(managed_oom_mode, ManagedOOMMode);

static const char* const managed_oom_preference_table[_MANAGED_OOM_PREFERENCE_MAX] = {
        [MANAGED_OOM_PREFERENCE_NONE] = "none",
        [MANAGED_OOM_PREFERENCE_AVOID] = "avoid",
        [MANAGED_OOM_PREFERENCE_OMIT] = "omit",
};

DEFINE_STRING_TABLE_LOOKUP(managed_oom_preference, ManagedOOMPreference);
