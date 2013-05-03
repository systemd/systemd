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

#include "cgroup-util.h"
#include "log.h"
#include "set.h"
#include "macro.h"
#include "util.h"
#include "path-util.h"
#include "strv.h"
#include "unit-name.h"
#include "fileio.h"

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

int cg_enumerate_tasks(const char *controller, const char *path, FILE **_f) {
        _cleanup_free_ char *fs = NULL;
        FILE *f;
        int r;

        assert(_f);

        r = cg_get_path(controller, path, "tasks", &fs);
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

        FOREACH_DIRENT(de, d, return -errno) {
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

int cg_rmdir(const char *controller, const char *path, bool honour_sticky) {
        _cleanup_free_ char *p = NULL;
        int r;

        r = cg_get_path(controller, path, NULL, &p);
        if (r < 0)
                return r;

        if (honour_sticky) {
                char *tasks;

                /* If the sticky bit is set don't remove the directory */

                tasks = strappend(p, "/tasks");
                if (!tasks)
                        return -ENOMEM;

                r = file_is_priv_sticky(tasks);
                free(tasks);

                if (r > 0)
                        return 0;
        }

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
                s = allocated_set = set_new(trivial_hash_func, trivial_compare_func);
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

                        if (set_get(s, LONG_TO_PTR(pid)) == LONG_TO_PTR(pid))
                                continue;

                        /* If we haven't killed this process yet, kill
                         * it */
                        if (kill(pid, sig) < 0) {
                                if (ret >= 0 && errno != ESRCH)
                                        ret = -errno;
                        } else if (ret == 0) {

                                if (sigcont)
                                        kill(pid, SIGCONT);

                                ret = 1;
                        }

                        done = false;

                        r = set_put(s, LONG_TO_PTR(pid));
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
        int r, ret = 0;
        char *fn;

        assert(path);
        assert(sig >= 0);

        if (!s) {
                s = allocated_set = set_new(trivial_hash_func, trivial_compare_func);
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
                if (ret >= 0 && r != 0)
                        ret = r;
        }

        if (ret >= 0 && r < 0)
                ret = r;

        if (rem) {
                r = cg_rmdir(controller, path, true);
                if (r < 0 && ret >= 0 && r != -ENOENT && r != -EBUSY)
                        return r;
        }

        return ret;
}

int cg_kill_recursive_and_wait(const char *controller, const char *path, bool rem) {
        unsigned i;

        assert(path);

        /* This safely kills all processes; first it sends a SIGTERM,
         * then checks 8 times after 200ms whether the group is now
         * empty, then kills everything that is left with SIGKILL and
         * finally checks 5 times after 200ms each whether the group
         * is finally empty. */

        for (i = 0; i < 15; i++) {
                int sig, r;

                if (i <= 0)
                        sig = SIGTERM;
                else if (i == 9)
                        sig = SIGKILL;
                else
                        sig = 0;

                r = cg_kill_recursive(controller, path, sig, true, true, rem, NULL);
                if (r <= 0)
                        return r;

                usleep(200 * USEC_PER_MSEC);
        }

        return 0;
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

        s = set_new(trivial_hash_func, trivial_compare_func);
        if (!s)
                return -ENOMEM;

        my_pid = getpid();

        do {
                _cleanup_fclose_ FILE *f = NULL;
                pid_t pid = 0;
                done = true;

                r = cg_enumerate_tasks(cfrom, pfrom, &f);
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

                        if (set_get(s, LONG_TO_PTR(pid)) == LONG_TO_PTR(pid))
                                continue;

                        r = cg_attach(cto, pto, pid);
                        if (r < 0) {
                                if (ret >= 0 && r != -ESRCH)
                                        ret = r;
                        } else if (ret == 0)
                                ret = 1;

                        done = false;

                        r = set_put(s, LONG_TO_PTR(pid));
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

int cg_migrate_recursive(const char *cfrom, const char *pfrom, const char *cto, const char *pto, bool ignore_self, bool rem) {
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
                if (!p) {
                        if (ret >= 0)
                                return -ENOMEM;

                        return ret;
                }

                r = cg_migrate_recursive(cfrom, p, cto, pto, ignore_self, rem);
                if (r != 0 && ret >= 0)
                        ret = r;
        }

        if (r < 0 && ret >= 0)
                ret = r;

        if (rem) {
                r = cg_rmdir(cfrom, pfrom, true);
                if (r < 0 && ret >= 0 && r != -ENOENT && r != -EBUSY)
                        return r;
        }

        return ret;
}

static const char *normalize_controller(const char *controller) {

        assert(controller);

        if (streq(controller, SYSTEMD_CGROUP_CONTROLLER))
                return "systemd";
        else if (startswith(controller, "name="))
                return controller + 5;
        else
                return controller;
}

static int join_path(const char *controller, const char *path, const char *suffix, char **fs) {
        char *t = NULL;

        if (controller) {
                if (path && suffix)
                        t = strjoin("/sys/fs/cgroup/", controller, "/", path, "/", suffix, NULL);
                else if (path)
                        t = strjoin("/sys/fs/cgroup/", controller, "/", path, NULL);
                else if (suffix)
                        t = strjoin("/sys/fs/cgroup/", controller, "/", suffix, NULL);
                else
                        t = strappend("/sys/fs/cgroup/", controller);
        } else {
                if (path && suffix)
                        t = strjoin(path, "/", suffix, NULL);
                else if (path)
                        t = strdup(path);
                else
                        return -EINVAL;
        }

        if (!t)
                return -ENOMEM;

        path_kill_slashes(t);

        *fs = t;
        return 0;
}

int cg_get_path(const char *controller, const char *path, const char *suffix, char **fs) {
        const char *p;
        static __thread bool good = false;

        assert(fs);

        if (controller && !cg_controller_is_valid(controller, true))
                return -EINVAL;

        if (_unlikely_(!good)) {
                int r;

                r = path_is_mount_point("/sys/fs/cgroup", false);
                if (r <= 0)
                        return r < 0 ? r : -ENOENT;

                /* Cache this to save a few stat()s */
                good = true;
        }

        p = controller ? normalize_controller(controller) : NULL;

        return join_path(p, path, suffix, fs);
}

static int check_hierarchy(const char *p) {
        char *cc;

        assert(p);

        /* Check if this controller actually really exists */
        cc = alloca(sizeof("/sys/fs/cgroup/") + strlen(p));
        strcpy(stpcpy(cc, "/sys/fs/cgroup/"), p);
        if (access(cc, F_OK) < 0)
                return -errno;

        return 0;
}

int cg_get_path_and_check(const char *controller, const char *path, const char *suffix, char **fs) {
        const char *p;
        int r;

        assert(fs);

        if (!cg_controller_is_valid(controller, true))
                return -EINVAL;

        /* Normalize the controller syntax */
        p = normalize_controller(controller);

        /* Check if this controller actually really exists */
        r = check_hierarchy(p);
        if (r < 0)
                return r;

        return join_path(p, path, suffix, fs);
}

static int trim_cb(const char *path, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
        char *p;
        bool is_sticky;

        if (typeflag != FTW_DP)
                return 0;

        if (ftwbuf->level < 1)
                return 0;

        p = strappend(path, "/tasks");
        if (!p) {
                errno = ENOMEM;
                return 1;
        }

        is_sticky = file_is_priv_sticky(p) > 0;
        free(p);

        if (is_sticky)
                return 0;

        rmdir(path);
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
        if (nftw(fs, trim_cb, 64, FTW_DEPTH|FTW_MOUNT|FTW_PHYS) != 0)
                r = errno ? -errno : -EIO;

        if (delete_root) {
                bool is_sticky;
                char *p;

                p = strappend(fs, "/tasks");
                if (!p)
                        return -ENOMEM;

                is_sticky = file_is_priv_sticky(p) > 0;
                free(p);

                if (!is_sticky)
                        if (rmdir(fs) < 0 && errno != ENOENT && r == 0)
                                return -errno;
        }

        return r;
}

int cg_delete(const char *controller, const char *path) {
        _cleanup_free_ char *parent = NULL;
        int r;

        assert(path);

        r = path_get_parent(path, &parent);
        if (r < 0)
                return r;

        r = cg_migrate_recursive(controller, path, controller, parent, false, true);
        return r == -ENOENT ? 0 : r;
}

int cg_attach(const char *controller, const char *path, pid_t pid) {
        _cleanup_free_ char *fs = NULL;
        char c[DECIMAL_STR_MAX(pid_t) + 2];
        int r;

        assert(path);
        assert(pid >= 0);

        r = cg_get_path_and_check(controller, path, "tasks", &fs);
        if (r < 0)
                return r;

        if (pid == 0)
                pid = getpid();

        snprintf(c, sizeof(c), "%lu\n", (unsigned long) pid);

        return write_string_file(fs, c);
}

int cg_set_group_access(
                const char *controller,
                const char *path,
                mode_t mode,
                uid_t uid,
                gid_t gid) {

        _cleanup_free_ char *fs = NULL;
        int r;

        assert(path);

        if (mode != (mode_t) -1)
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
                gid_t gid,
                int sticky) {

        _cleanup_free_ char *fs = NULL, *procs = NULL;
        int r;

        assert(path);

        if (mode == (mode_t) -1 && uid == (uid_t) -1 && gid == (gid_t) -1 && sticky < 0)
                return 0;

        if (mode != (mode_t) -1)
                mode &= 0666;

        r = cg_get_path(controller, path, "tasks", &fs);
        if (r < 0)
                return r;

        if (sticky >= 0 && mode != (mode_t) -1)
                /* Both mode and sticky param are passed */
                mode |= (sticky ? S_ISVTX : 0);
        else if ((sticky >= 0 && mode == (mode_t) -1) ||
                 (mode != (mode_t) -1 && sticky < 0)) {
                struct stat st;

                /* Only one param is passed, hence read the current
                 * mode from the file itself */

                r = lstat(fs, &st);
                if (r < 0)
                        return -errno;

                if (mode == (mode_t) -1)
                        /* No mode set, we just shall set the sticky bit */
                        mode = (st.st_mode & ~S_ISVTX) | (sticky ? S_ISVTX : 0);
                else
                        /* Only mode set, leave sticky bit untouched */
                        mode = (st.st_mode & ~0777) | mode;
        }

        r = chmod_and_chown(fs, mode, uid, gid);
        if (r < 0)
                return r;

        /* Always keep values for "cgroup.procs" in sync with "tasks" */
        r = cg_get_path(controller, path, "cgroup.procs", &procs);
        if (r < 0)
                return r;

        return chmod_and_chown(procs, mode, uid, gid);
}

int cg_pid_get_path(const char *controller, pid_t pid, char **path) {
        _cleanup_fclose_ FILE *f = NULL;
        char line[LINE_MAX];
        const char *fs;
        size_t cs;

        assert(path);
        assert(pid >= 0);

        if (controller) {
                if (!cg_controller_is_valid(controller, true))
                        return -EINVAL;

                controller = normalize_controller(controller);
        } else
                controller = SYSTEMD_CGROUP_CONTROLLER;

        if (pid == 0)
                fs = "/proc/self/cgroup";
        else
                fs = procfs_file_alloca(pid, "cgroup");

        f = fopen(fs, "re");
        if (!f)
                return errno == ENOENT ? -ESRCH : -errno;

        cs = strlen(controller);

        FOREACH_LINE(line, f, return -errno) {
                char *l, *p, *w, *e;
                size_t k;
                char *state;
                bool found = false;

                truncate_nl(line);

                l = strchr(line, ':');
                if (!l)
                        continue;

                l++;
                e = strchr(l, ':');
                if (!e)
                        continue;

                *e = 0;

                FOREACH_WORD_SEPARATOR(w, k, l, ",", state) {

                        if (k == cs && memcmp(w, controller, cs) == 0) {
                                found = true;
                                break;
                        }

                        if (k == 5 + cs &&
                            memcmp(w, "name=", 5) == 0 &&
                            memcmp(w+5, controller, cs) == 0) {
                                found = true;
                                break;
                        }
                }

                if (!found)
                        continue;

                p = strdup(e + 1);
                if (!p)
                        return -ENOMEM;

                *path = p;
                return 0;
        }

        return -ENOENT;
}

int cg_install_release_agent(const char *controller, const char *agent) {
        _cleanup_free_ char *fs = NULL, *contents = NULL;
        char *sc;
        int r;

        assert(agent);

        r = cg_get_path(controller, NULL, "release_agent", &fs);
        if (r < 0)
                return r;

        r = read_one_line_file(fs, &contents);
        if (r < 0)
                return r;

        sc = strstrip(contents);
        if (sc[0] == 0) {
                r = write_string_file(fs, agent);
                if (r < 0)
                        return r;
        } else if (!streq(sc, agent))
                return -EEXIST;

        free(fs);
        fs = NULL;
        r = cg_get_path(controller, NULL, "notify_on_release", &fs);
        if (r < 0)
                return r;

        free(contents);
        contents = NULL;
        r = read_one_line_file(fs, &contents);
        if (r < 0)
                return r;

        sc = strstrip(contents);
        if (streq(sc, "0")) {
                r = write_string_file(fs, "1");
                if (r < 0)
                        return r;

                return 1;
        }

        if (!streq(sc, "1"))
                return -EIO;

        return 0;
}

int cg_is_empty(const char *controller, const char *path, bool ignore_self) {
        _cleanup_fclose_ FILE *f = NULL;
        pid_t pid = 0, self_pid;
        bool found = false;
        int r;

        assert(path);

        r = cg_enumerate_tasks(controller, path, &f);
        if (r < 0)
                return r == -ENOENT ? 1 : r;

        self_pid = getpid();

        while ((r = cg_read_pid(f, &pid)) > 0) {

                if (ignore_self && pid == self_pid)
                        continue;

                found = true;
                break;
        }

        if (r < 0)
                return r;

        return !found;
}

int cg_is_empty_by_spec(const char *spec, bool ignore_self) {
        _cleanup_free_ char *controller = NULL, *path = NULL;
        int r;

        assert(spec);

        r = cg_split_spec(spec, &controller, &path);
        if (r < 0)
                return r;

        return cg_is_empty(controller, path, ignore_self);
}

int cg_is_empty_recursive(const char *controller, const char *path, bool ignore_self) {
        _cleanup_closedir_ DIR *d = NULL;
        char *fn;
        int r;

        assert(path);

        r = cg_is_empty(controller, path, ignore_self);
        if (r <= 0)
                return r;

        r = cg_enumerate_subgroups(controller, path, &d);
        if (r < 0)
                return r == -ENOENT ? 1 : r;

        while ((r = cg_read_subgroup(d, &fn)) > 0) {
                _cleanup_free_ char *p = NULL;

                p = strjoin(path, "/", fn, NULL);
                free(fn);
                if (!p)
                        return -ENOMEM;

                r = cg_is_empty_recursive(controller, p, ignore_self);
                if (r <= 0)
                        return r;
        }

        if (r < 0)
                return r;

        return 1;
}

int cg_split_spec(const char *spec, char **controller, char **path) {
        const char *e;
        char *t = NULL, *u = NULL;
        _cleanup_free_ char *v = NULL;

        assert(spec);

        if (*spec == '/') {
                if (!path_is_safe(spec))
                        return -EINVAL;

                if (path) {
                        t = strdup(spec);
                        if (!t)
                                return -ENOMEM;

                        path_kill_slashes(t);
                        *path = t;
                }

                if (controller)
                        *controller = NULL;

                return 0;
        }

        e = strchr(spec, ':');
        if (!e) {
                if (!cg_controller_is_valid(spec, true))
                        return -EINVAL;

                if (controller) {
                        t = strdup(normalize_controller(spec));
                        if (!t)
                                return -ENOMEM;

                        *controller = t;
                }

                if (path)
                        *path = NULL;

                return 0;
        }

        v = strndup(spec, e-spec);
        if (!v)
                return -ENOMEM;
        t = strdup(normalize_controller(v));
        if (!t)
                return -ENOMEM;
        if (!cg_controller_is_valid(t, true)) {
                free(t);
                return -EINVAL;
        }

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

int cg_join_spec(const char *controller, const char *path, char **spec) {
        char *s;

        assert(path);

        if (!controller)
                controller = "systemd";
        else {
                if (!cg_controller_is_valid(controller, true))
                        return -EINVAL;

                controller = normalize_controller(controller);
        }

        if (!path_is_absolute(path))
                return -EINVAL;

        s = strjoin(controller, ":", path, NULL);
        if (!s)
                return -ENOMEM;

        path_kill_slashes(s + strlen(controller) + 1);

        *spec = s;
        return 0;
}

int cg_mangle_path(const char *path, char **result) {
        _cleanup_free_ char *c = NULL, *p = NULL;
        char *t;
        int r;

        assert(path);
        assert(result);

        /* First check if it already is a filesystem path */
        if (path_startswith(path, "/sys/fs/cgroup")) {

                t = strdup(path);
                if (!t)
                        return -ENOMEM;

                path_kill_slashes(t);
                *result = t;
                return 0;
        }

        /* Otherwise treat it as cg spec */
        r = cg_split_spec(path, &c, &p);
        if (r < 0)
                return r;

        return cg_get_path(c ? c : SYSTEMD_CGROUP_CONTROLLER, p ? p : "/", NULL, result);
}

int cg_get_system_path(char **path) {
        char *p;
        int r;

        assert(path);

        r = cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER, 1, &p);
        if (r < 0) {
                p = strdup("/system");
                if (!p)
                        return -ENOMEM;
        }

        if (endswith(p, "/system"))
                *path = p;
        else {
                char *q;

                q = strappend(p, "/system");
                free(p);
                if (!q)
                        return -ENOMEM;

                *path = q;
        }

        return 0;
}

int cg_get_root_path(char **path) {
        char *root, *e;
        int r;

        assert(path);

        r = cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER, 1, &root);
        if (r < 0)
                return r;

        e = endswith(root, "/system");
        if (e == root)
                e[1] = 0;
        else if (e)
                *e = 0;

        *path = root;
        return 0;
}

int cg_get_user_path(char **path) {
        _cleanup_free_ char *root = NULL;
        char *p;

        assert(path);

        /* Figure out the place to put user cgroups below. We use the
         * same as PID 1 has but with the "/system" suffix replaced by
         * "/user" */

        if (cg_get_root_path(&root) < 0 || streq(root, "/"))
                p = strdup("/user");
        else
                p = strappend(root, "/user");

        if (!p)
                return -ENOMEM;

        *path = p;
        return 0;
}

int cg_get_machine_path(const char *machine, char **path) {
        _cleanup_free_ char *root = NULL, *escaped = NULL;
        char *p;

        assert(path);

        if (machine) {
                const char *name = strappenda(machine, ".nspawn");

                escaped = cg_escape(name);
                if (!escaped)
                        return -ENOMEM;
        }

        p = strjoin(cg_get_root_path(&root) >= 0 && !streq(root, "/") ? root : "",
                    "/machine", machine ? "/" : "", machine ? escaped : "", NULL);
        if (!p)
                return -ENOMEM;

        *path = p;
        return 0;
}

char **cg_shorten_controllers(char **controllers) {
        char **f, **t;

        if (!controllers)
                return controllers;

        for (f = controllers, t = controllers; *f; f++) {
                const char *p;
                int r;

                p = normalize_controller(*f);

                if (streq(p, "systemd")) {
                        free(*f);
                        continue;
                }

                if (!cg_controller_is_valid(p, true)) {
                        log_warning("Controller %s is not valid, removing from controllers list.", p);
                        free(*f);
                        continue;
                }

                r = check_hierarchy(p);
                if (r < 0) {
                        log_debug("Controller %s is not available, removing from controllers list.", p);
                        free(*f);
                        continue;
                }

                *(t++) = *f;
        }

        *t = NULL;
        return strv_uniq(controllers);
}

int cg_pid_get_path_shifted(pid_t pid, char **root, char **cgroup) {
        _cleanup_free_ char *cg_root = NULL;
        char *cg_process, *p;
        int r;

        r = cg_get_root_path(&cg_root);
        if (r < 0)
                return r;

        r = cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER, pid, &cg_process);
        if (r < 0)
                return r;

        p = path_startswith(cg_process, cg_root);
        if (p)
                p--;
        else
                p = cg_process;

        if (cgroup) {
                char* c;

                c = strdup(p);
                if (!c) {
                        free(cg_process);
                        return -ENOMEM;
                }

                *cgroup = c;
        }

        if (root) {
                cg_process[p-cg_process] = 0;
                *root = cg_process;
        } else
                free(cg_process);

        return 0;
}

int cg_path_decode_unit(const char *cgroup, char **unit){
        char *p, *e, *c, *s, *k;

        assert(cgroup);
        assert(unit);

        e = strchrnul(cgroup, '/');
        c = strndupa(cgroup, e - cgroup);
        c = cg_unescape(c);

        /* Could this be a valid unit name? */
        if (!unit_name_is_valid(c, true))
                return -EINVAL;

        if (!unit_name_is_template(c))
                s = strdup(c);
        else {
                if (*e != '/')
                        return -EINVAL;

                e += strspn(e, "/");

                p = strchrnul(e, '/');
                k = strndupa(e, p - e);
                k = cg_unescape(k);

                if (!unit_name_is_valid(k, false))
                        return -EINVAL;

                s = strdup(k);
        }

        if (!s)
                return -ENOMEM;

        *unit = s;
        return 0;
}

int cg_path_get_unit(const char *path, char **unit) {
        const char *e;

        assert(path);
        assert(unit);

        e = path_startswith(path, "/system/");
        if (!e)
                return -ENOENT;

        return cg_path_decode_unit(e, unit);
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

_pure_ static const char *skip_label(const char *e) {
        assert(e);

        e = strchr(e, '/');
        if (!e)
                return NULL;

        e += strspn(e, "/");
        return e;
}

int cg_path_get_user_unit(const char *path, char **unit) {
        const char *e;

        assert(path);
        assert(unit);

        /* We always have to parse the path from the beginning as unit
         * cgroups might have arbitrary child cgroups and we shouldn't get
         * confused by those */

        e = path_startswith(path, "/user/");
        if (!e)
                return -ENOENT;

        /* Skip the user name */
        e = skip_label(e);
        if (!e)
                return -ENOENT;

        /* Skip the session ID */
        e = skip_label(e);
        if (!e)
                return -ENOENT;

        /* Skip the systemd cgroup */
        e = skip_label(e);
        if (!e)
                return -ENOENT;

        return cg_path_decode_unit(e, unit);
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
        const char *e, *n;
        char *s, *r;

        assert(path);
        assert(machine);

        e = path_startswith(path, "/machine/");
        if (!e)
                return -ENOENT;

        n = strchrnul(e, '/');
        if (e == n)
                return -ENOENT;

        s = strndupa(e, n - e);

        r = strdup(cg_unescape(s));
        if (!r)
                return -ENOMEM;

        *machine = r;
        return 0;
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
        const char *e, *n;
        char *s;

        assert(path);
        assert(session);

        e = path_startswith(path, "/user/");
        if (!e)
                return -ENOENT;

        /* Skip the user name */
        e = skip_label(e);
        if (!e)
                return -ENOENT;

        n = strchrnul(e, '/');
        if (n - e < 8)
                return -ENOENT;
        if (memcmp(n - 8, ".session", 8) != 0)
                return -ENOENT;

        s = strndup(e, n - e - 8);
        if (!s)
                return -ENOMEM;

        *session = s;
        return 0;
}

int cg_pid_get_session(pid_t pid, char **session) {
        _cleanup_free_ char *cgroup = NULL;
        int r;

        assert(session);

        r = cg_pid_get_path_shifted(pid, NULL, &cgroup);
        if (r < 0)
                return r;

        return cg_path_get_session(cgroup, session);
}

int cg_path_get_owner_uid(const char *path, uid_t *uid) {
        const char *e, *n;
        char *s;

        assert(path);
        assert(uid);

        e = path_startswith(path, "/user/");
        if (!e)
                return -ENOENT;

        n = strchrnul(e, '/');
        if (n - e < 5)
                return -ENOENT;
        if (memcmp(n - 5, ".user", 5) != 0)
                return -ENOENT;

        s = strndupa(e, n - e - 5);
        if (!s)
                return -ENOMEM;

        return parse_uid(s, uid);
}

int cg_pid_get_owner_uid(pid_t pid, uid_t *uid) {
        _cleanup_free_ char *cgroup = NULL;
        int r;

        assert(uid);

        r = cg_pid_get_path_shifted(pid, NULL, &cgroup);
        if (r < 0)
                return r;

        return cg_path_get_owner_uid(cgroup, uid);
}

int cg_controller_from_attr(const char *attr, char **controller) {
        const char *dot;
        char *c;

        assert(attr);
        assert(controller);

        if (!filename_is_safe(attr))
                return -EINVAL;

        dot = strchr(attr, '.');
        if (!dot) {
                *controller = NULL;
                return 0;
        }

        c = strndup(attr, dot - attr);
        if (!c)
                return -ENOMEM;

        if (!cg_controller_is_valid(c, false)) {
                free(c);
                return -EINVAL;
        }

        *controller = c;
        return 1;
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
            streq(p, "tasks"))
                need_prefix = true;
        else {
                const char *dot;

                dot = strrchr(p, '.');
                if (dot) {

                        if (dot - p == 6 && memcmp(p, "cgroup", 6) == 0)
                                need_prefix = true;
                        else {
                                char *n;

                                n = strndupa(p, dot - p);

                                if (check_hierarchy(n) >= 0)
                                        need_prefix = true;
                        }
                }
        }

        if (need_prefix)
                return strappend("_", p);
        else
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
        "0123456789"                            \
        "abcdefghijklmnopqrstuvwxyz"            \
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"            \
        "_"

bool cg_controller_is_valid(const char *p, bool allow_named) {
        const char *t, *s;

        if (!p)
                return false;

        if (allow_named) {
                s = startswith(p, "name=");
                if (s)
                        p = s;
        }

        if (*p == 0 || *p == '_')
                return false;

        for (t = p; *t; t++)
                if (!strchr(CONTROLLER_VALID, *t))
                        return false;

        if (t - p > FILENAME_MAX)
                return false;

        return true;
}
