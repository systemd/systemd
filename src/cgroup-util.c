/*-*- Mode: C; c-basic-offset: 8 -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>

#include <libcgroup.h>

#include "cgroup-util.h"
#include "log.h"
#include "set.h"
#include "macro.h"
#include "util.h"

int cg_translate_error(int error, int _errno) {

        switch (error) {

        case ECGROUPNOTCOMPILED:
        case ECGROUPNOTMOUNTED:
        case ECGROUPNOTEXIST:
        case ECGROUPNOTCREATED:
                return -ENOENT;

        case ECGINVAL:
                return -EINVAL;

        case ECGROUPNOTALLOWED:
                return -EPERM;

        case ECGOTHER:
                return -_errno;
        }

        return -EIO;
}

static struct cgroup* cg_new(const char *controller, const char *path) {
        struct cgroup *cgroup;

        assert(path);
        assert(controller);

        if (!(cgroup = cgroup_new_cgroup(path)))
                return NULL;

        if (!cgroup_add_controller(cgroup, controller)) {
                cgroup_free(&cgroup);
                return NULL;
        }

        return cgroup;
}

int cg_kill(const char *controller, const char *path, int sig, bool ignore_self) {
        bool killed = false, done = false;
        Set *s;
        pid_t my_pid;
        int r, ret = 0;

        assert(controller);
        assert(path);
        assert(sig >= 0);

        /* This goes through the tasks list and kills them all. This
         * is repeated until no further processes are added to the
         * tasks list, to properly handle forking processes */

        if (!(s = set_new(trivial_hash_func, trivial_compare_func)))
                return -ENOMEM;

        my_pid = getpid();

        do {
                void *iterator = NULL;
                pid_t pid = 0;

                done = true;

                r = cgroup_get_task_begin(path, controller, &iterator, &pid);
                while (r == 0) {

                        if (pid == my_pid && ignore_self)
                                goto next;

                        if (set_get(s, INT_TO_PTR(pid)) == INT_TO_PTR(pid))
                                goto next;

                        /* If we haven't killed this process yet, kill
                         * it */

                        if (kill(pid, sig) < 0 && errno != ESRCH) {
                                if (ret == 0)
                                        ret = -errno;
                        }

                        killed = true;
                        done = false;

                        if ((r = set_put(s, INT_TO_PTR(pid))) < 0)
                                goto loop_exit;

                next:
                        r = cgroup_get_task_next(&iterator, &pid);
                }

                if (r == 0 || r == ECGEOF)
                        r = 0;
                else if (r == ECGOTHER && errno == ENOENT)
                        r = -ESRCH;
                else
                        r = cg_translate_error(r, errno);

        loop_exit:
                assert_se(cgroup_get_task_end(&iterator) == 0);

                /* To avoid racing against processes which fork
                 * quicker than we can kill them we repeat this until
                 * no new pids need to be killed. */

        } while (!done && r >= 0);

        set_free(s);

        if (ret < 0)
                return ret;

        if (r < 0)
                return r;

        return !!killed;
}

int cg_kill_recursive(const char *controller, const char *path, int sig, bool ignore_self) {
        struct cgroup_file_info info;
        int level = 0, r, ret = 0;
        void *iterator = NULL;
        bool killed = false;

        assert(path);
        assert(controller);
        assert(sig >= 0);

        zero(info);

        r = cgroup_walk_tree_begin(controller, path, 0, &iterator, &info, &level);
        while (r == 0) {
                int k;
                char *p;

                if (info.type != CGROUP_FILE_TYPE_DIR)
                        goto next;

                if (asprintf(&p, "%s/%s", path, info.path) < 0) {
                        ret = -ENOMEM;
                        break;
                }

                k = cg_kill(controller, p, sig, ignore_self);
                free(p);

                if (k < 0) {
                        if (ret == 0)
                                ret = k;
                } else if (k > 0)
                        killed = true;

        next:

                r = cgroup_walk_tree_next(0, &iterator, &info, level);
        }

        if (ret == 0) {
                if (r == 0 || r == ECGEOF)
                        ret = !!killed;
                else if (r == ECGOTHER && errno == ENOENT)
                        ret = -ESRCH;
                else
                        ret = cg_translate_error(r, errno);
        }

        assert_se(cgroup_walk_tree_end(&iterator) == 0);

        return ret;
}

int cg_kill_recursive_and_wait(const char *controller, const char *path) {
        unsigned i;

        assert(path);
        assert(controller);

        /* This safely kills all processes; first it sends a SIGTERM,
         * then checks 8 times after 50ms whether the group is
         * now empty, and finally kills everything that is left with
         * SIGKILL */

        for (i = 0; i < 10; i++) {
int sig, r;

                if (i <= 0)
                        sig = SIGTERM;
                else if (i >= 9)
                        sig = SIGKILL;
                else
                        sig = 0;

                if ((r = cg_kill_recursive(controller, path, sig, true)) <= 0)
                        return r;

                usleep(50 * USEC_PER_MSEC);
        }

        return 0;
}

int cg_migrate(const char *controller, const char *from, const char *to, bool ignore_self) {
        bool migrated = false, done = false;
        struct cgroup *dest;
        int r, ret = 0;
        pid_t my_pid;

        assert(controller);
        assert(from);
        assert(to);

        if (!(dest = cg_new(controller, to)))
                return -ENOMEM;

        my_pid = getpid();

        do {
                void *iterator = NULL;
                pid_t pid = 0;

                done = true;

                r = cgroup_get_task_begin(from, controller, &iterator, &pid);
                while (r == 0) {

                        if (pid == my_pid && ignore_self)
                                goto next;

                        if ((r = cgroup_attach_task_pid(dest, pid)) != 0) {
                                if (ret == 0)
                                        r = cg_translate_error(r, errno);
                        }

                        migrated = true;
                        done = false;

                next:

                        r = cgroup_get_task_next(&iterator, &pid);
                }

                if (r == 0 || r == ECGEOF)
                        r = 0;
                else if (r == ECGOTHER && errno == ENOENT)
                        r = -ESRCH;
                else
                        r = cg_translate_error(r, errno);

                assert_se(cgroup_get_task_end(&iterator) == 0);

        } while (!done && r >= 0);

        cgroup_free(&dest);

        if (ret < 0)
                return ret;

        if (r < 0)
                return r;

        return !!migrated;
}

int cg_migrate_recursive(const char *controller, const char *from, const char *to, bool ignore_self) {
        struct cgroup_file_info info;
        int level = 0, r, ret = 0;
        void *iterator = NULL;
        bool migrated = false;

        assert(controller);
        assert(from);
        assert(to);

        zero(info);

        r = cgroup_walk_tree_begin(controller, from, 0, &iterator, &info, &level);
        while (r == 0) {
                int k;
                char *p;

                if (info.type != CGROUP_FILE_TYPE_DIR)
                        goto next;

                if (asprintf(&p, "%s/%s", from, info.path) < 0) {
                        ret = -ENOMEM;
                        break;
                }

                k = cg_migrate(controller, p, to, ignore_self);
                free(p);

                if (k < 0) {
                        if (ret == 0)
                                ret = k;
                } else if (k > 0)
                        migrated = true;

        next:
                r = cgroup_walk_tree_next(0, &iterator, &info, level);
        }

        if (ret == 0) {
                if (r == 0 || r == ECGEOF)
                        r = !!migrated;
                else if (r == ECGOTHER && errno == ENOENT)
                        r = -ESRCH;
                else
                        r = cg_translate_error(r, errno);
        }

        assert_se(cgroup_walk_tree_end(&iterator) == 0);

        return ret;
}

int cg_get_path(const char *controller, const char *path, const char *suffix, char **fs) {
        char *mp;
        int r;

        assert(controller);
        assert(path);

        if ((r = cgroup_get_subsys_mount_point(controller, &mp)) != 0)
                return cg_translate_error(r, errno);

        if (suffix)
                r = asprintf(fs, "%s/%s/%s", mp, path, suffix);
        else
                r = asprintf(fs, "%s/%s", mp, path);

        free(mp);

        return r < 0 ? -ENOMEM : 0;
}

int cg_trim(const char *controller, const char *path, bool delete_root) {
        char *fs;
        int r;

        assert(controller);
        assert(path);

        if ((r = cg_get_path(controller, path, NULL, &fs)) < 0)
                return r;

        r = rm_rf(fs, true, delete_root);
        free(fs);

        return r;
}

int cg_delete(const char *controller, const char *path) {
        struct cgroup *cg;
        int r;

        assert(controller);
        assert(path);

        if (!(cg = cg_new(controller, path)))
                return -ENOMEM;

        if ((r = cgroup_delete_cgroup_ext(cg, CGFLAG_DELETE_RECURSIVE|CGFLAG_DELETE_IGNORE_MIGRATION)) != 0) {
                r = cg_translate_error(r, errno);
                goto finish;
        }

        r = 0;

finish:
        cgroup_free(&cg);

        return r;
}

int cg_create(const char *controller, const char *path) {
        struct cgroup *cg;
        int r;

        assert(controller);
        assert(path);

        if (!(cg = cg_new(controller, path)))
                return -ENOMEM;

        if ((r = cgroup_create_cgroup(cg, 1)) != 0) {
                r = cg_translate_error(r, errno);
                goto finish;
        }

        r = 0;

finish:
        cgroup_free(&cg);

        return r;
}

int cg_attach(const char *controller, const char *path, pid_t pid) {
        struct cgroup *cg;
        int r;

        assert(controller);
        assert(path);
        assert(pid >= 0);

        if (!(cg = cg_new(controller, path)))
                return -ENOMEM;

        if (pid == 0)
                pid = getpid();

        if ((r = cgroup_attach_task_pid(cg, pid))) {
                r = cg_translate_error(r, errno);
                goto finish;
        }

        r = 0;

finish:
        cgroup_free(&cg);

        return r;
}

int cg_create_and_attach(const char *controller, const char *path, pid_t pid) {
        struct cgroup *cg;
        int r;

        assert(controller);
        assert(path);
        assert(pid >= 0);

        if (!(cg = cg_new(controller, path)))
                return -ENOMEM;

        if ((r = cgroup_create_cgroup(cg, 1)) != 0) {
                r = cg_translate_error(r, errno);
                goto finish;
        }

        if (pid == 0)
                pid = getpid();

        if ((r = cgroup_attach_task_pid(cg, pid))) {
                r = cg_translate_error(r, errno);
                goto finish;
        }

        r = 0;

finish:
        cgroup_free(&cg);

        return r;
}

int cg_set_group_access(const char *controller, const char *path, mode_t mode, uid_t uid, gid_t gid) {
        char *fs;
        int r;

        assert(controller);
        assert(path);

        if ((r = cg_get_path(controller, path, NULL, &fs)) < 0)
                return r;

        r = chmod_and_chown(fs, mode, uid, gid);
        free(fs);

        return r;
}

int cg_set_task_access(const char *controller, const char *path, mode_t mode, uid_t uid, gid_t gid) {
        char *fs;
        int r;

        assert(controller);
        assert(path);

        if ((r = cg_get_path(controller, path, "tasks", &fs)) < 0)
                return r;

        r = chmod_and_chown(fs, mode, uid, gid);
        free(fs);

        return r;
}

int cg_get_by_pid(const char *controller, pid_t pid, char **path) {
        int r;
        char *p = NULL;

        assert(controller);
        assert(pid > 0);
        assert(path);

        if ((r = cgroup_get_current_controller_path(pid, controller, &p)) != 0)
                return cg_translate_error(r, errno);

        assert(p);

        *path = p;
        return 0;
}

int cg_install_release_agent(const char *controller, const char *agent) {
        char *mp = NULL, *path = NULL, *contents = NULL, *line = NULL, *sc;
        int r;

        assert(controller);
        assert(agent);

        if ((r = cgroup_get_subsys_mount_point(controller, &mp)) != 0)
                return cg_translate_error(r, errno);

        if (asprintf(&path, "%s/release_agent", mp) < 0) {
                r = -ENOMEM;
                goto finish;
        }

        if ((r = read_one_line_file(path, &contents)) < 0)
                goto finish;

        sc = strstrip(contents);

        if (sc[0] == 0) {

                if (asprintf(&line, "%s\n", agent) < 0) {
                        r = -ENOMEM;
                        goto finish;
                }

                if ((r = write_one_line_file(path, line)) < 0)
                        goto finish;

        } else if (!streq(sc, agent)) {
                r = -EEXIST;
                goto finish;
        }

        free(path);
        path = NULL;
        if (asprintf(&path, "%s/notify_on_release", mp) < 0) {
                r = -ENOMEM;
                goto finish;
        }

        free(contents);
        contents = NULL;
        if ((r = read_one_line_file(path, &contents)) < 0)
                goto finish;

        sc = strstrip(contents);

        if (streq(sc, "0")) {
                if ((r = write_one_line_file(path, "1\n")) < 0)
                        goto finish;
        } else if (!streq(sc, "1")) {
                r = -EIO;
                goto finish;
        }

        r = 0;

finish:
        free(mp);
        free(path);
        free(contents);
        free(line);

        return r;
}

int cg_is_empty(const char *controller, const char *path, bool ignore_self) {
        void *iterator = NULL;
        pid_t pid = 0;
        int r;

        assert(controller);
        assert(path);

        r = cgroup_get_task_begin(path, controller, &iterator, &pid);
        while (r == 0) {

                if (ignore_self&& pid == getpid())
                        goto next;

                break;

        next:
                r = cgroup_get_task_next(&iterator, &pid);
        }


        if (r == ECGEOF)
                r = 1;
        else if (r != 0)
                r = cg_translate_error(r, errno);
        else
                r = 0;

        assert_se(cgroup_get_task_end(&iterator) == 0);

        return r;
}

int cg_is_empty_recursive(const char *controller, const char *path, bool ignore_self) {
        struct cgroup_file_info info;
        int level = 0, r, ret = 0;
        void *iterator = NULL;
        bool empty = true;

        assert(controller);
        assert(path);

        zero(info);

        r = cgroup_walk_tree_begin(controller, path, 0, &iterator, &info, &level);
        while (r == 0) {
                int k;
                char *p;

                if (info.type != CGROUP_FILE_TYPE_DIR)
                        goto next;

                if (asprintf(&p, "%s/%s", path, info.path) < 0) {
                        ret = -ENOMEM;
                        break;
                }

                k = cg_is_empty(controller, p, ignore_self);
                free(p);

                if (k < 0) {
                        ret = k;
                        break;
                } else if (k == 0) {
                        empty = false;
                        break;
                }

        next:
                r = cgroup_walk_tree_next(0, &iterator, &info, level);
        }

        if (ret == 0) {
                if (r == 0 || r == ECGEOF)
                        ret = !!empty;
                else if (r == ECGOTHER && errno == ENOENT)
                        ret = -ESRCH;
                else
                        ret = cg_translate_error(r, errno);
        }

        assert_se(cgroup_walk_tree_end(&iterator) == 0);

        return ret;
}
