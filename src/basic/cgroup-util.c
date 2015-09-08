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

#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ftw.h>

#include "set.h"
#include "macro.h"
#include "util.h"
#include "formats-util.h"
#include "process-util.h"
#include "path-util.h"
#include "unit-name.h"
#include "fileio.h"
#include "special.h"
#include "mkdir.h"
#include "login-util.h"
#include "cgroup-util.h"

int cg_enumerate_processes(const char *controller, const char *path, FILE **_f) {
        _cleanup_free_ char *fs = NULL;
        FILE *f;
        int r;

        assert(_f);

        r = cg_get_path(controller, path, "cgroup.procs", &fs);
        if (r < 0)
                return r;

        f = fopen(fs, "re");
        if (!f)
                return -errno;

        *_f = f;
        return 0;
}

int cg_read_pid(FILE *f, pid_t *_pid) {
        unsigned long ul;

        /* Note that the cgroup.procs might contain duplicates! See
         * cgroups.txt for details. */

        assert(f);
        assert(_pid);

        errno = 0;
        if (fscanf(f, "%lu", &ul) != 1) {

                if (feof(f))
                        return 0;

                return errno ? -errno : -EIO;
        }

        if (ul <= 0)
                return -EIO;

        *_pid = (pid_t) ul;
        return 1;
}

int cg_enumerate_subgroups(const char *controller, const char *path, DIR **_d) {
        _cleanup_free_ char *fs = NULL;
        int r;
        DIR *d;

        assert(_d);

        /* This is not recursive! */

        r = cg_get_path(controller, path, NULL, &fs);
        if (r < 0)
                return r;

        d = opendir(fs);
        if (!d)
                return -errno;

        *_d = d;
        return 0;
}

int cg_read_subgroup(DIR *d, char **fn) {
        struct dirent *de;

        assert(d);
        assert(fn);

        FOREACH_DIRENT_ALL(de, d, return -errno) {
                char *b;

                if (de->d_type != DT_DIR)
                        continue;

                if (streq(de->d_name, ".") ||
                    streq(de->d_name, ".."))
                        continue;

                b = strdup(de->d_name);
                if (!b)
                        return -ENOMEM;

                *fn = b;
                return 1;
        }

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

        return 0;
}

int cg_kill(const char *controller, const char *path, int sig, bool sigcont, bool ignore_self, Set *s) {
        _cleanup_set_free_ Set *allocated_set = NULL;
        bool done = false;
        int r, ret = 0;
        pid_t my_pid;

        assert(sig >= 0);

        /* This goes through the tasks list and kills them all. This
         * is repeated until no further processes are added to the
         * tasks list, to properly handle forking processes */

        if (!s) {
                s = allocated_set = set_new(NULL);
                if (!s)
                        return -ENOMEM;
        }

        my_pid = getpid();

        do {
                _cleanup_fclose_ FILE *f = NULL;
                pid_t pid = 0;
                done = true;

                r = cg_enumerate_processes(controller, path, &f);
                if (r < 0) {
                        if (ret >= 0 && r != -ENOENT)
                                return r;

                        return ret;
                }

                while ((r = cg_read_pid(f, &pid)) > 0) {

                        if (ignore_self && pid == my_pid)
                                continue;

                        if (set_get(s, PID_TO_PTR(pid)) == PID_TO_PTR(pid))
                                continue;

                        /* If we haven't killed this process yet, kill
                         * it */
                        if (kill(pid, sig) < 0) {
                                if (ret >= 0 && errno != ESRCH)
                                        ret = -errno;
                        } else {
                                if (sigcont && sig != SIGKILL)
                                        (void) kill(pid, SIGCONT);

                                if (ret == 0)
                                        ret = 1;
                        }

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

                /* To avoid racing against processes which fork
                 * quicker than we can kill them we repeat this until
                 * no new pids need to be killed. */

        } while (!done);

        return ret;
}

int cg_kill_recursive(const char *controller, const char *path, int sig, bool sigcont, bool ignore_self, bool rem, Set *s) {
        _cleanup_set_free_ Set *allocated_set = NULL;
        _cleanup_closedir_ DIR *d = NULL;
        int r, ret;
        char *fn;

        assert(path);
        assert(sig >= 0);

        if (!s) {
                s = allocated_set = set_new(NULL);
                if (!s)
                        return -ENOMEM;
        }

        ret = cg_kill(controller, path, sig, sigcont, ignore_self, s);

        r = cg_enumerate_subgroups(controller, path, &d);
        if (r < 0) {
                if (ret >= 0 && r != -ENOENT)
                        return r;

                return ret;
        }

        while ((r = cg_read_subgroup(d, &fn)) > 0) {
                _cleanup_free_ char *p = NULL;

                p = strjoin(path, "/", fn, NULL);
                free(fn);
                if (!p)
                        return -ENOMEM;

                r = cg_kill_recursive(controller, p, sig, sigcont, ignore_self, rem, s);
                if (r != 0 && ret >= 0)
                        ret = r;
        }

        if (ret >= 0 && r < 0)
                ret = r;

        if (rem) {
                r = cg_rmdir(controller, path);
                if (r < 0 && ret >= 0 && r != -ENOENT && r != -EBUSY)
                        return r;
        }

        return ret;
}

int cg_migrate(const char *cfrom, const char *pfrom, const char *cto, const char *pto, bool ignore_self) {
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

        my_pid = getpid();

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
                        if (ignore_self && pid == my_pid)
                                continue;

                        if (set_get(s, PID_TO_PTR(pid)) == PID_TO_PTR(pid))
                                continue;

                        /* Ignore kernel threads. Since they can only
                         * exist in the root cgroup, we only check for
                         * them there. */
                        if (cfrom &&
                            (isempty(pfrom) || path_equal(pfrom, "/")) &&
                            is_kernel_thread(pid) > 0)
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
                bool ignore_self,
                bool rem) {

        _cleanup_closedir_ DIR *d = NULL;
        int r, ret = 0;
        char *fn;

        assert(cfrom);
        assert(pfrom);
        assert(cto);
        assert(pto);

        ret = cg_migrate(cfrom, pfrom, cto, pto, ignore_self);

        r = cg_enumerate_subgroups(cfrom, pfrom, &d);
        if (r < 0) {
                if (ret >= 0 && r != -ENOENT)
                        return r;

                return ret;
        }

        while ((r = cg_read_subgroup(d, &fn)) > 0) {
                _cleanup_free_ char *p = NULL;

                p = strjoin(pfrom, "/", fn, NULL);
                free(fn);
                if (!p)
                        return -ENOMEM;

                r = cg_migrate_recursive(cfrom, p, cto, pto, ignore_self, rem);
                if (r != 0 && ret >= 0)
                        ret = r;
        }

        if (r < 0 && ret >= 0)
                ret = r;

        if (rem) {
                r = cg_rmdir(cfrom, pfrom);
                if (r < 0 && ret >= 0 && r != -ENOENT && r != -EBUSY)
                        return r;
        }

        return ret;
}

int cg_migrate_recursive_fallback(
                const char *cfrom,
                const char *pfrom,
                const char *cto,
                const char *pto,
                bool ignore_self,
                bool rem) {

        int r;

        assert(cfrom);
        assert(pfrom);
        assert(cto);
        assert(pto);

        r = cg_migrate_recursive(cfrom, pfrom, cto, pto, ignore_self, rem);
        if (r < 0) {
                char prefix[strlen(pto) + 1];

                /* This didn't work? Then let's try all prefixes of the destination */

                PATH_FOREACH_PREFIX(prefix, pto) {
                        int q;

                        q = cg_migrate_recursive(cfrom, pfrom, cto, prefix, ignore_self, rem);
                        if (q >= 0)
                                return q;
                }
        }

        return r;
}

static const char *controller_to_dirname(const char *controller) {
        const char *e;

        assert(controller);

        /* Converts a controller name to the directory name below
         * /sys/fs/cgroup/ we want to mount it to. Effectively, this
         * just cuts off the name= prefixed used for named
         * hierarchies, if it is specified. */

        e = startswith(controller, "name=");
        if (e)
                return e;

        return controller;
}

static int join_path_legacy(const char *controller, const char *path, const char *suffix, char **fs) {
        const char *dn;
        char *t = NULL;

        assert(fs);
        assert(controller);

        dn = controller_to_dirname(controller);

        if (isempty(path) && isempty(suffix))
                t = strappend("/sys/fs/cgroup/", dn);
        else if (isempty(path))
                t = strjoin("/sys/fs/cgroup/", dn, "/", suffix, NULL);
        else if (isempty(suffix))
                t = strjoin("/sys/fs/cgroup/", dn, "/", path, NULL);
        else
                t = strjoin("/sys/fs/cgroup/", dn, "/", path, "/", suffix, NULL);
        if (!t)
                return -ENOMEM;

        *fs = t;
        return 0;
}

static int join_path_unified(const char *path, const char *suffix, char **fs) {
        char *t;

        assert(fs);

        if (isempty(path) && isempty(suffix))
                t = strdup("/sys/fs/cgroup");
        else if (isempty(path))
                t = strappend("/sys/fs/cgroup/", suffix);
        else if (isempty(suffix))
                t = strappend("/sys/fs/cgroup/", path);
        else
                t = strjoin("/sys/fs/cgroup/", path, "/", suffix, NULL);
        if (!t)
                return -ENOMEM;

        *fs = t;
        return 0;
}

int cg_get_path(const char *controller, const char *path, const char *suffix, char **fs) {
        int unified, r;

        assert(fs);

        if (!controller) {
                char *t;

                /* If no controller is specified, we return the path
                 * *below* the controllers, without any prefix. */

                if (!path && !suffix)
                        return -EINVAL;

                if (!suffix)
                        t = strdup(path);
                else if (!path)
                        t = strdup(suffix);
                else
                        t = strjoin(path, "/", suffix, NULL);
                if (!t)
                        return -ENOMEM;

                *fs = path_kill_slashes(t);
                return 0;
        }

        if (!cg_controller_is_valid(controller))
                return -EINVAL;

        unified = cg_unified();
        if (unified < 0)
                return unified;

        if (unified > 0)
                r = join_path_unified(path, suffix, fs);
        else
                r = join_path_legacy(controller, path, suffix, fs);
        if (r < 0)
                return r;

        path_kill_slashes(*fs);
        return 0;
}

static int controller_is_accessible(const char *controller) {
        int unified;

        assert(controller);

        /* Checks whether a specific controller is accessible,
         * i.e. its hierarchy mounted. In the unified hierarchy all
         * controllers are considered accessible, except for the named
         * hierarchies */

        if (!cg_controller_is_valid(controller))
                return -EINVAL;

        unified = cg_unified();
        if (unified < 0)
                return unified;
        if (unified > 0) {
                /* We don't support named hierarchies if we are using
                 * the unified hierarchy. */

                if (streq(controller, SYSTEMD_CGROUP_CONTROLLER))
                        return 0;

                if (startswith(controller, "name="))
                        return -EOPNOTSUPP;

        } else {
                const char *cc, *dn;

                dn = controller_to_dirname(controller);
                cc = strjoina("/sys/fs/cgroup/", dn);

                if (laccess(cc, F_OK) < 0)
                        return -errno;
        }

        return 0;
}

int cg_get_path_and_check(const char *controller, const char *path, const char *suffix, char **fs) {
        int r;

        assert(controller);
        assert(fs);

        /* Check if the specified controller is actually accessible */
        r = controller_is_accessible(controller);
        if (r < 0)
                return r;

        return cg_get_path(controller, path, suffix, fs);
}

static int trim_cb(const char *path, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
        assert(path);
        assert(sb);
        assert(ftwbuf);

        if (typeflag != FTW_DP)
                return 0;

        if (ftwbuf->level < 1)
                return 0;

        (void) rmdir(path);
        return 0;
}

int cg_trim(const char *controller, const char *path, bool delete_root) {
        _cleanup_free_ char *fs = NULL;
        int r = 0;

        assert(path);

        r = cg_get_path(controller, path, NULL, &fs);
        if (r < 0)
                return r;

        errno = 0;
        if (nftw(fs, trim_cb, 64, FTW_DEPTH|FTW_MOUNT|FTW_PHYS) != 0) {
                if (errno == ENOENT)
                        r = 0;
                else if (errno != 0)
                        r = -errno;
                else
                        r = -EIO;
        }

        if (delete_root) {
                if (rmdir(fs) < 0 && errno != ENOENT)
                        return -errno;
        }

        return r;
}

int cg_create(const char *controller, const char *path) {
        _cleanup_free_ char *fs = NULL;
        int r;

        r = cg_get_path_and_check(controller, path, NULL, &fs);
        if (r < 0)
                return r;

        r = mkdir_parents(fs, 0755);
        if (r < 0)
                return r;

        if (mkdir(fs, 0755) < 0) {

                if (errno == EEXIST)
                        return 0;

                return -errno;
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
                pid = getpid();

        snprintf(c, sizeof(c), PID_FMT"\n", pid);

        return write_string_file(fs, c, 0);
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

int cg_set_group_access(
                const char *controller,
                const char *path,
                mode_t mode,
                uid_t uid,
                gid_t gid) {

        _cleanup_free_ char *fs = NULL;
        int r;

        if (mode == MODE_INVALID && uid == UID_INVALID && gid == GID_INVALID)
                return 0;

        if (mode != MODE_INVALID)
                mode &= 0777;

        r = cg_get_path(controller, path, NULL, &fs);
        if (r < 0)
                return r;

        return chmod_and_chown(fs, mode, uid, gid);
}

int cg_set_task_access(
                const char *controller,
                const char *path,
                mode_t mode,
                uid_t uid,
                gid_t gid) {

        _cleanup_free_ char *fs = NULL, *procs = NULL;
        int r, unified;

        assert(path);

        if (mode == MODE_INVALID && uid == UID_INVALID && gid == GID_INVALID)
                return 0;

        if (mode != MODE_INVALID)
                mode &= 0666;

        r = cg_get_path(controller, path, "cgroup.procs", &fs);
        if (r < 0)
                return r;

        r = chmod_and_chown(fs, mode, uid, gid);
        if (r < 0)
                return r;

        unified = cg_unified();
        if (unified < 0)
                return unified;
        if (unified)
                return 0;

        /* Compatibility, Always keep values for "tasks" in sync with
         * "cgroup.procs" */
        if (cg_get_path(controller, path, "tasks", &procs) >= 0)
                (void) chmod_and_chown(procs, mode, uid, gid);

        return 0;
}

int cg_pid_get_path(const char *controller, pid_t pid, char **path) {
        _cleanup_fclose_ FILE *f = NULL;
        char line[LINE_MAX];
        const char *fs;
        size_t cs = 0;
        int unified;

        assert(path);
        assert(pid >= 0);

        unified = cg_unified();
        if (unified < 0)
                return unified;
        if (unified == 0) {
                if (controller) {
                        if (!cg_controller_is_valid(controller))
                                return -EINVAL;
                } else
                        controller = SYSTEMD_CGROUP_CONTROLLER;

                cs = strlen(controller);
        }

        fs = procfs_file_alloca(pid, "cgroup");
        f = fopen(fs, "re");
        if (!f)
                return errno == ENOENT ? -ESRCH : -errno;

        FOREACH_LINE(line, f, return -errno) {
                char *e, *p;

                truncate_nl(line);

                if (unified) {
                        e = startswith(line, "0:");
                        if (!e)
                                continue;

                        e = strchr(e, ':');
                        if (!e)
                                continue;
                } else {
                        char *l;
                        size_t k;
                        const char *word, *state;
                        bool found = false;

                        l = strchr(line, ':');
                        if (!l)
                                continue;

                        l++;
                        e = strchr(l, ':');
                        if (!e)
                                continue;

                        *e = 0;
                        FOREACH_WORD_SEPARATOR(word, k, l, ",", state) {
                                if (k == cs && memcmp(word, controller, cs) == 0) {
                                        found = true;
                                        break;
                                }
                        }

                        if (!found)
                                continue;
                }

                p = strdup(e + 1);
                if (!p)
                        return -ENOMEM;

                *path = p;
                return 0;
        }

        return -ENODATA;
}

int cg_install_release_agent(const char *controller, const char *agent) {
        _cleanup_free_ char *fs = NULL, *contents = NULL;
        const char *sc;
        int r, unified;

        assert(agent);

        unified = cg_unified();
        if (unified < 0)
                return unified;
        if (unified) /* doesn't apply to unified hierarchy */
                return -EOPNOTSUPP;

        r = cg_get_path(controller, NULL, "release_agent", &fs);
        if (r < 0)
                return r;

        r = read_one_line_file(fs, &contents);
        if (r < 0)
                return r;

        sc = strstrip(contents);
        if (isempty(sc)) {
                r = write_string_file(fs, agent, 0);
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
                r = write_string_file(fs, "1", 0);
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
        int r, unified;

        unified = cg_unified();
        if (unified < 0)
                return unified;
        if (unified) /* Doesn't apply to unified hierarchy */
                return -EOPNOTSUPP;

        r = cg_get_path(controller, NULL, "notify_on_release", &fs);
        if (r < 0)
                return r;

        r = write_string_file(fs, "0", 0);
        if (r < 0)
                return r;

        fs = mfree(fs);

        r = cg_get_path(controller, NULL, "release_agent", &fs);
        if (r < 0)
                return r;

        r = write_string_file(fs, "", 0);
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
                return 1;
        if (r < 0)
                return r;

        r = cg_read_pid(f, &pid);
        if (r < 0)
                return r;

        return r == 0;
}

int cg_is_empty_recursive(const char *controller, const char *path) {
        int unified, r;

        assert(path);

        /* The root cgroup is always populated */
        if (controller && (isempty(path) || path_equal(path, "/")))
                return false;

        unified = cg_unified();
        if (unified < 0)
                return unified;

        if (unified > 0) {
                _cleanup_free_ char *populated = NULL, *t = NULL;

                /* On the unified hierarchy we can check empty state
                 * via the "cgroup.populated" attribute. */

                r = cg_get_path(controller, path, "cgroup.populated", &populated);
                if (r < 0)
                        return r;

                r = read_one_line_file(populated, &t);
                if (r == -ENOENT)
                        return 1;
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
                        return 1;
                if (r < 0)
                        return r;

                while ((r = cg_read_subgroup(d, &fn)) > 0) {
                        _cleanup_free_ char *p = NULL;

                        p = strjoin(path, "/", fn, NULL);
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

int cg_split_spec(const char *spec, char **controller, char **path) {
        char *t = NULL, *u = NULL;
        const char *e;

        assert(spec);

        if (*spec == '/') {
                if (!path_is_safe(spec))
                        return -EINVAL;

                if (path) {
                        t = strdup(spec);
                        if (!t)
                                return -ENOMEM;

                        *path = path_kill_slashes(t);
                }

                if (controller)
                        *controller = NULL;

                return 0;
        }

        e = strchr(spec, ':');
        if (!e) {
                if (!cg_controller_is_valid(spec))
                        return -EINVAL;

                if (controller) {
                        t = strdup(spec);
                        if (!t)
                                return -ENOMEM;

                        *controller = t;
                }

                if (path)
                        *path = NULL;

                return 0;
        }

        t = strndup(spec, e-spec);
        if (!t)
                return -ENOMEM;
        if (!cg_controller_is_valid(t)) {
                free(t);
                return -EINVAL;
        }

        if (isempty(e+1))
                u = NULL;
        else {
                u = strdup(e+1);
                if (!u) {
                        free(t);
                        return -ENOMEM;
                }

                if (!path_is_safe(u) ||
                    !path_is_absolute(u)) {
                        free(t);
                        free(u);
                        return -EINVAL;
                }

                path_kill_slashes(u);
        }

        if (controller)
                *controller = t;
        else
                free(t);

        if (path)
                *path = u;
        else
                free(u);

        return 0;
}

int cg_mangle_path(const char *path, char **result) {
        _cleanup_free_ char *c = NULL, *p = NULL;
        char *t;
        int r;

        assert(path);
        assert(result);

        /* First, check if it already is a filesystem path */
        if (path_startswith(path, "/sys/fs/cgroup")) {

                t = strdup(path);
                if (!t)
                        return -ENOMEM;

                *result = path_kill_slashes(t);
                return 0;
        }

        /* Otherwise, treat it as cg spec */
        r = cg_split_spec(path, &c, &p);
        if (r < 0)
                return r;

        return cg_get_path(c ?: SYSTEMD_CGROUP_CONTROLLER, p ?: "/", NULL, result);
}

int cg_get_root_path(char **path) {
        char *p, *e;
        int r;

        assert(path);

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

        *path = p;
        return 0;
}

int cg_shift_path(const char *cgroup, const char *root, const char **shifted) {
        _cleanup_free_ char *rt = NULL;
        char *p;
        int r;

        assert(cgroup);
        assert(shifted);

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
                *shifted = p - 1;
        else
                *shifted = cgroup;

        return 0;
}

int cg_pid_get_path_shifted(pid_t pid, const char *root, char **cgroup) {
        _cleanup_free_ char *raw = NULL;
        const char *c;
        int r;

        assert(pid >= 0);
        assert(cgroup);

        r = cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER, pid, &raw);
        if (r < 0)
                return r;

        r = cg_shift_path(raw, root, &c);
        if (r < 0)
                return r;

        if (c == raw) {
                *cgroup = raw;
                raw = NULL;
        } else {
                char *n;

                n = strdup(c);
                if (!n)
                        return -ENOMEM;

                *cgroup = n;
        }

        return 0;
}

int cg_path_decode_unit(const char *cgroup, char **unit){
        char *c, *s;
        size_t n;

        assert(cgroup);
        assert(unit);

        n = strcspn(cgroup, "/");
        if (n < 3)
                return -ENXIO;

        c = strndupa(cgroup, n);
        c = cg_unescape(c);

        if (!unit_name_is_valid(c, UNIT_NAME_PLAIN|UNIT_NAME_INSTANCE))
                return -ENXIO;

        s = strdup(c);
        if (!s)
                return -ENOMEM;

        *unit = s;
        return 0;
}

static bool valid_slice_name(const char *p, size_t n) {

        if (!p)
                return false;

        if (n < strlen("x.slice"))
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
        const char *e;
        char *unit;
        int r;

        assert(path);
        assert(ret);

        e = skip_slices(path);

        r = cg_path_decode_unit(e, &unit);
        if (r < 0)
                return r;

        /* We skipped over the slices, don't accept any now */
        if (endswith(unit, ".slice")) {
                free(unit);
                return -ENXIO;
        }

        *ret = unit;
        return 0;
}

int cg_pid_get_unit(pid_t pid, char **unit) {
        _cleanup_free_ char *cgroup = NULL;
        int r;

        assert(unit);

        r = cg_pid_get_path_shifted(pid, NULL, &cgroup);
        if (r < 0)
                return r;

        return cg_path_get_unit(cgroup, unit);
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
        if (n < strlen("session-x.scope"))
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
                        return false;

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
        if (n < strlen("user@x.service"))
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

        /* And from here on it looks pretty much the same as for a
         * system unit, hence let's use the same parser from here
         * on. */
        return cg_path_get_unit(t, ret);
}

int cg_pid_get_user_unit(pid_t pid, char **unit) {
        _cleanup_free_ char *cgroup = NULL;
        int r;

        assert(unit);

        r = cg_pid_get_path_shifted(pid, NULL, &cgroup);
        if (r < 0)
                return r;

        return cg_path_get_user_unit(cgroup, unit);
}

int cg_path_get_machine_name(const char *path, char **machine) {
        _cleanup_free_ char *u = NULL;
        const char *sl;
        int r;

        r = cg_path_get_unit(path, &u);
        if (r < 0)
                return r;

        sl = strjoina("/run/systemd/machines/unit:", u);
        return readlink_malloc(sl, machine);
}

int cg_pid_get_machine_name(pid_t pid, char **machine) {
        _cleanup_free_ char *cgroup = NULL;
        int r;

        assert(machine);

        r = cg_pid_get_path_shifted(pid, NULL, &cgroup);
        if (r < 0)
                return r;

        return cg_path_get_machine_name(cgroup, machine);
}

int cg_path_get_session(const char *path, char **session) {
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

        if (session) {
                char *rr;

                rr = strdup(start);
                if (!rr)
                        return -ENOMEM;

                *session = rr;
        }

        return 0;
}

int cg_pid_get_session(pid_t pid, char **session) {
        _cleanup_free_ char *cgroup = NULL;
        int r;

        r = cg_pid_get_path_shifted(pid, NULL, &cgroup);
        if (r < 0)
                return r;

        return cg_path_get_session(cgroup, session);
}

int cg_path_get_owner_uid(const char *path, uid_t *uid) {
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
        if (parse_uid(start, uid) < 0)
                return -ENXIO;

        return 0;
}

int cg_pid_get_owner_uid(pid_t pid, uid_t *uid) {
        _cleanup_free_ char *cgroup = NULL;
        int r;

        r = cg_pid_get_path_shifted(pid, NULL, &cgroup);
        if (r < 0)
                return r;

        return cg_path_get_owner_uid(cgroup, uid);
}

int cg_path_get_slice(const char *p, char **slice) {
        const char *e = NULL;

        assert(p);
        assert(slice);

        /* Finds the right-most slice unit from the beginning, but
         * stops before we come to the first non-slice unit. */

        for (;;) {
                size_t n;

                p += strspn(p, "/");

                n = strcspn(p, "/");
                if (!valid_slice_name(p, n)) {

                        if (!e) {
                                char *s;

                                s = strdup("-.slice");
                                if (!s)
                                        return -ENOMEM;

                                *slice = s;
                                return 0;
                        }

                        return cg_path_decode_unit(e, slice);
                }

                e = p;
                p += n;
        }
}

int cg_pid_get_slice(pid_t pid, char **slice) {
        _cleanup_free_ char *cgroup = NULL;
        int r;

        assert(slice);

        r = cg_pid_get_path_shifted(pid, NULL, &cgroup);
        if (r < 0)
                return r;

        return cg_path_get_slice(cgroup, slice);
}

int cg_path_get_user_slice(const char *p, char **slice) {
        const char *t;
        assert(p);
        assert(slice);

        t = skip_user_prefix(p);
        if (!t)
                return -ENXIO;

        /* And now it looks pretty much the same as for a system
         * slice, so let's just use the same parser from here on. */
        return cg_path_get_slice(t, slice);
}

int cg_pid_get_user_slice(pid_t pid, char **slice) {
        _cleanup_free_ char *cgroup = NULL;
        int r;

        assert(slice);

        r = cg_pid_get_path_shifted(pid, NULL, &cgroup);
        if (r < 0)
                return r;

        return cg_path_get_user_slice(cgroup, slice);
}

char *cg_escape(const char *p) {
        bool need_prefix = false;

        /* This implements very minimal escaping for names to be used
         * as file names in the cgroup tree: any name which might
         * conflict with a kernel name or is prefixed with '_' is
         * prefixed with a '_'. That way, when reading cgroup names it
         * is sufficient to remove a single prefixing underscore if
         * there is one. */

        /* The return value of this function (unlike cg_unescape())
         * needs free()! */

        if (p[0] == 0 ||
            p[0] == '_' ||
            p[0] == '.' ||
            streq(p, "notify_on_release") ||
            streq(p, "release_agent") ||
            streq(p, "tasks") ||
            startswith(p, "cgroup."))
                need_prefix = true;
        else {
                const char *dot;

                dot = strrchr(p, '.');
                if (dot) {
                        CGroupController c;
                        size_t l = dot - p;

                        for (c = 0; c < _CGROUP_CONTROLLER_MAX; c++) {
                                const char *n;

                                n = cgroup_controller_to_string(c);

                                if (l != strlen(n))
                                        continue;

                                if (memcmp(p, n, l) != 0)
                                        continue;

                                need_prefix = true;
                                break;
                        }
                }
        }

        if (need_prefix)
                return strappend("_", p);

        return strdup(p);
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

        s = startswith(p, "name=");
        if (s)
                p = s;

        if (*p == 0 || *p == '_')
                return false;

        for (t = p; *t; t++)
                if (!strchr(CONTROLLER_VALID, *t))
                        return false;

        if (t - p > FILENAME_MAX)
                return false;

        return true;
}

int cg_slice_to_path(const char *unit, char **ret) {
        _cleanup_free_ char *p = NULL, *s = NULL, *e = NULL;
        const char *dash;
        int r;

        assert(unit);
        assert(ret);

        if (streq(unit, "-.slice")) {
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

                /* Don't allow trailing or double dashes */
                if (dash[1] == 0 || dash[1] == '-')
                        return -EINVAL;

                strcpy(stpncpy(n, p, dash - p), ".slice");
                if (!unit_name_is_valid(n, UNIT_NAME_PLAIN))
                        return -EINVAL;

                escaped = cg_escape(n);
                if (!escaped)
                        return -ENOMEM;

                if (!strextend(&s, escaped, "/", NULL))
                        return -ENOMEM;

                dash = strchr(dash+1, '-');
        }

        e = cg_escape(unit);
        if (!e)
                return -ENOMEM;

        if (!strextend(&s, e, NULL))
                return -ENOMEM;

        *ret = s;
        s = NULL;

        return 0;
}

int cg_set_attribute(const char *controller, const char *path, const char *attribute, const char *value) {
        _cleanup_free_ char *p = NULL;
        int r;

        r = cg_get_path(controller, path, attribute, &p);
        if (r < 0)
                return r;

        return write_string_file(p, value, 0);
}

int cg_get_attribute(const char *controller, const char *path, const char *attribute, char **ret) {
        _cleanup_free_ char *p = NULL;
        int r;

        r = cg_get_path(controller, path, attribute, &p);
        if (r < 0)
                return r;

        return read_one_line_file(p, ret);
}

int cg_create_everywhere(CGroupMask supported, CGroupMask mask, const char *path) {
        CGroupController c;
        int r, unified;

        /* This one will create a cgroup in our private tree, but also
         * duplicate it in the trees specified in mask, and remove it
         * in all others */

        /* First create the cgroup in our own hierarchy. */
        r = cg_create(SYSTEMD_CGROUP_CONTROLLER, path);
        if (r < 0)
                return r;

        /* If we are in the unified hierarchy, we are done now */
        unified = cg_unified();
        if (unified < 0)
                return unified;
        if (unified > 0)
                return 0;

        /* Otherwise, do the same in the other hierarchies */
        for (c = 0; c < _CGROUP_CONTROLLER_MAX; c++) {
                CGroupMask bit = CGROUP_CONTROLLER_TO_MASK(c);
                const char *n;

                n = cgroup_controller_to_string(c);

                if (mask & bit)
                        (void) cg_create(n, path);
                else if (supported & bit)
                        (void) cg_trim(n, path, true);
        }

        return 0;
}

int cg_attach_everywhere(CGroupMask supported, const char *path, pid_t pid, cg_migrate_callback_t path_callback, void *userdata) {
        CGroupController c;
        int r, unified;

        r = cg_attach(SYSTEMD_CGROUP_CONTROLLER, path, pid);
        if (r < 0)
                return r;

        unified = cg_unified();
        if (unified < 0)
                return unified;
        if (unified > 0)
                return 0;

        for (c = 0; c < _CGROUP_CONTROLLER_MAX; c++) {
                CGroupMask bit = CGROUP_CONTROLLER_TO_MASK(c);
                const char *p = NULL;

                if (!(supported & bit))
                        continue;

                if (path_callback)
                        p = path_callback(bit, userdata);

                if (!p)
                        p = path;

                (void) cg_attach_fallback(cgroup_controller_to_string(c), p, pid);
        }

        return 0;
}

int cg_attach_many_everywhere(CGroupMask supported, const char *path, Set* pids, cg_migrate_callback_t path_callback, void *userdata) {
        Iterator i;
        void *pidp;
        int r = 0;

        SET_FOREACH(pidp, pids, i) {
                pid_t pid = PTR_TO_PID(pidp);
                int q;

                q = cg_attach_everywhere(supported, path, pid, path_callback, userdata);
                if (q < 0 && r >= 0)
                        r = q;
        }

        return r;
}

int cg_migrate_everywhere(CGroupMask supported, const char *from, const char *to, cg_migrate_callback_t to_callback, void *userdata) {
        CGroupController c;
        int r = 0, unified;

        if (!path_equal(from, to))  {
                r = cg_migrate_recursive(SYSTEMD_CGROUP_CONTROLLER, from, SYSTEMD_CGROUP_CONTROLLER, to, false, true);
                if (r < 0)
                        return r;
        }

        unified = cg_unified();
        if (unified < 0)
                return unified;
        if (unified > 0)
                return r;

        for (c = 0; c < _CGROUP_CONTROLLER_MAX; c++) {
                CGroupMask bit = CGROUP_CONTROLLER_TO_MASK(c);
                const char *p = NULL;

                if (!(supported & bit))
                        continue;

                if (to_callback)
                        p = to_callback(bit, userdata);

                if (!p)
                        p = to;

                (void) cg_migrate_recursive_fallback(SYSTEMD_CGROUP_CONTROLLER, to, cgroup_controller_to_string(c), p, false, false);
        }

        return 0;
}

int cg_trim_everywhere(CGroupMask supported, const char *path, bool delete_root) {
        CGroupController c;
        int r, unified;

        r = cg_trim(SYSTEMD_CGROUP_CONTROLLER, path, delete_root);
        if (r < 0)
                return r;

        unified = cg_unified();
        if (unified < 0)
                return unified;
        if (unified > 0)
                return r;

        for (c = 0; c < _CGROUP_CONTROLLER_MAX; c++) {
                CGroupMask bit = CGROUP_CONTROLLER_TO_MASK(c);

                if (!(supported & bit))
                        continue;

                (void) cg_trim(cgroup_controller_to_string(c), path, delete_root);
        }

        return 0;
}

int cg_mask_supported(CGroupMask *ret) {
        CGroupMask mask = 0;
        int r, unified;

        /* Determines the mask of supported cgroup controllers. Only
         * includes controllers we can make sense of and that are
         * actually accessible. */

        unified = cg_unified();
        if (unified < 0)
                return unified;
        if (unified > 0) {
                _cleanup_free_ char *root = NULL, *controllers = NULL, *path = NULL;
                const char *c;

                /* In the unified hierarchy we can read the supported
                 * and accessible controllers from a the top-level
                 * cgroup attribute */

                r = cg_get_root_path(&root);
                if (r < 0)
                        return r;

                r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, root, "cgroup.controllers", &path);
                if (r < 0)
                        return r;

                r = read_one_line_file(path, &controllers);
                if (r < 0)
                        return r;

                c = controllers;
                for (;;) {
                        _cleanup_free_ char *n = NULL;
                        CGroupController v;

                        r = extract_first_word(&c, &n, NULL, 0);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                break;

                        v = cgroup_controller_from_string(n);
                        if (v < 0)
                                continue;

                        mask |= CGROUP_CONTROLLER_TO_MASK(v);
                }

                /* Currently, we only support the memory controller in
                 * the unified hierarchy, mask everything else off. */
                mask &= CGROUP_MASK_MEMORY;

        } else {
                CGroupController c;

                /* In the legacy hierarchy, we check whether which
                 * hierarchies are mounted. */

                for (c = 0; c < _CGROUP_CONTROLLER_MAX; c++) {
                        const char *n;

                        n = cgroup_controller_to_string(c);
                        if (controller_is_accessible(n) >= 0)
                                mask |= CGROUP_CONTROLLER_TO_MASK(c);
                }
        }

        *ret = mask;
        return 0;
}

int cg_kernel_controllers(Set *controllers) {
        _cleanup_fclose_ FILE *f = NULL;
        char buf[LINE_MAX];
        int r;

        assert(controllers);

        /* Determines the full list of kernel-known controllers. Might
         * include controllers we don't actually support, arbitrary
         * named hierarchies and controllers that aren't currently
         * accessible (because not mounted). */

        f = fopen("/proc/cgroups", "re");
        if (!f) {
                if (errno == ENOENT)
                        return 0;
                return -errno;
        }

        /* Ignore the header line */
        (void) fgets(buf, sizeof(buf), f);

        for (;;) {
                char *controller;
                int enabled = 0;

                errno = 0;
                if (fscanf(f, "%ms %*i %*i %i", &controller, &enabled) != 2) {

                        if (feof(f))
                                break;

                        if (ferror(f) && errno != 0)
                                return -errno;

                        return -EBADMSG;
                }

                if (!enabled) {
                        free(controller);
                        continue;
                }

                if (!cg_controller_is_valid(controller)) {
                        free(controller);
                        return -EBADMSG;
                }

                r = set_consume(controllers, controller);
                if (r < 0)
                        return r;
        }

        return 0;
}

static thread_local int unified_cache = -1;

int cg_unified(void) {
        struct statfs fs;

        /* Checks if we support the unified hierarchy. Returns an
         * error when the cgroup hierarchies aren't mounted yet or we
         * have any other trouble determining if the unified hierarchy
         * is supported. */

        if (unified_cache >= 0)
                return unified_cache;

        if (statfs("/sys/fs/cgroup/", &fs) < 0)
                return -errno;

        if (F_TYPE_EQUAL(fs.f_type, CGROUP_SUPER_MAGIC))
                unified_cache = true;
        else if (F_TYPE_EQUAL(fs.f_type, TMPFS_MAGIC))
                unified_cache = false;
        else
                return -ENOEXEC;

        return unified_cache;
}

void cg_unified_flush(void) {
        unified_cache = -1;
}

int cg_enable_everywhere(CGroupMask supported, CGroupMask mask, const char *p) {
        _cleanup_free_ char *fs = NULL;
        CGroupController c;
        int r, unified;

        assert(p);

        if (supported == 0)
                return 0;

        unified = cg_unified();
        if (unified < 0)
                return unified;
        if (!unified) /* on the legacy hiearchy there's no joining of controllers defined */
                return 0;

        r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, p, "cgroup.subtree_control", &fs);
        if (r < 0)
                return r;

        for (c = 0; c < _CGROUP_CONTROLLER_MAX; c++) {
                CGroupMask bit = CGROUP_CONTROLLER_TO_MASK(c);
                const char *n;

                if (!(supported & bit))
                        continue;

                n = cgroup_controller_to_string(c);
                {
                        char s[1 + strlen(n) + 1];

                        s[0] = mask & bit ? '+' : '-';
                        strcpy(s + 1, n);

                        r = write_string_file(fs, s, 0);
                        if (r < 0)
                                log_debug_errno(r, "Failed to enable controller %s for %s (%s): %m", n, p, fs);
                }
        }

        return 0;
}

bool cg_is_unified_wanted(void) {
        static thread_local int wanted = -1;
        int r, unified;

        /* If the hierarchy is already mounted, then follow whatever
         * was chosen for it. */
        unified = cg_unified();
        if (unified >= 0)
                return unified;

        /* Otherwise, let's see what the kernel command line has to
         * say. Since checking that is expensive, let's cache the
         * result. */
        if (wanted >= 0)
                return wanted;

        r = get_proc_cmdline_key("systemd.unified_cgroup_hierarchy", NULL);
        if (r > 0)
                return (wanted = true);
        else {
                _cleanup_free_ char *value = NULL;

                r = get_proc_cmdline_key("systemd.unified_cgroup_hierarchy=", &value);
                if (r < 0)
                        return false;
                if (r == 0)
                        return (wanted = false);

                return (wanted = parse_boolean(value) > 0);
        }
}

bool cg_is_legacy_wanted(void) {
        return !cg_is_unified_wanted();
}

static const char *cgroup_controller_table[_CGROUP_CONTROLLER_MAX] = {
        [CGROUP_CONTROLLER_CPU] = "cpu",
        [CGROUP_CONTROLLER_CPUACCT] = "cpuacct",
        [CGROUP_CONTROLLER_BLKIO] = "blkio",
        [CGROUP_CONTROLLER_MEMORY] = "memory",
        [CGROUP_CONTROLLER_DEVICE] = "devices",
};

DEFINE_STRING_TABLE_LOOKUP(cgroup_controller, CGroupController);
