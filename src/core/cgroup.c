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
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/mount.h>
#include <fcntl.h>

#include "cgroup.h"
#include "cgroup-util.h"
#include "log.h"
#include "strv.h"
#include "path-util.h"

int cgroup_bonding_realize(CGroupBonding *b) {
        int r;

        assert(b);
        assert(b->path);
        assert(b->controller);

        r = cg_create(b->controller, b->path, NULL);
        if (r < 0) {
                log_warning("Failed to create cgroup %s:%s: %s", b->controller, b->path, strerror(-r));
                return r;
        }

        b->realized = true;

        return 0;
}

int cgroup_bonding_realize_list(CGroupBonding *first) {
        CGroupBonding *b;
        int r;

        LIST_FOREACH(by_unit, b, first)
                if ((r = cgroup_bonding_realize(b)) < 0 && b->essential)
                        return r;

        return 0;
}

void cgroup_bonding_free(CGroupBonding *b, bool trim) {
        assert(b);

        if (b->unit) {
                CGroupBonding *f;

                LIST_REMOVE(CGroupBonding, by_unit, b->unit->cgroup_bondings, b);

                if (streq(b->controller, SYSTEMD_CGROUP_CONTROLLER)) {
                        assert_se(f = hashmap_get(b->unit->manager->cgroup_bondings, b->path));
                        LIST_REMOVE(CGroupBonding, by_path, f, b);

                        if (f)
                                hashmap_replace(b->unit->manager->cgroup_bondings, b->path, f);
                        else
                                hashmap_remove(b->unit->manager->cgroup_bondings, b->path);
                }
        }

        if (b->realized && b->ours && trim)
                cg_trim(b->controller, b->path, false);

        free(b->controller);
        free(b->path);
        free(b);
}

void cgroup_bonding_free_list(CGroupBonding *first, bool remove_or_trim) {
        CGroupBonding *b, *n;

        LIST_FOREACH_SAFE(by_unit, b, n, first)
                cgroup_bonding_free(b, remove_or_trim);
}

void cgroup_bonding_trim(CGroupBonding *b, bool delete_root) {
        assert(b);

        if (b->realized && b->ours)
                cg_trim(b->controller, b->path, delete_root);
}

void cgroup_bonding_trim_list(CGroupBonding *first, bool delete_root) {
        CGroupBonding *b;

        LIST_FOREACH(by_unit, b, first)
                cgroup_bonding_trim(b, delete_root);
}

int cgroup_bonding_install(CGroupBonding *b, pid_t pid, const char *cgroup_suffix) {
        _cleanup_free_ char *p = NULL;
        const char *path;
        int r;

        assert(b);
        assert(pid >= 0);

        if (cgroup_suffix) {
                p = strjoin(b->path, "/", cgroup_suffix, NULL);
                if (!p)
                        return -ENOMEM;

                path = p;
        } else
                path = b->path;

        r = cg_create_and_attach(b->controller, path, pid);
        if (r < 0)
                return r;

        b->realized = true;
        return 0;
}

int cgroup_bonding_install_list(CGroupBonding *first, pid_t pid, const char *cgroup_suffix) {
        CGroupBonding *b;
        int r;

        LIST_FOREACH(by_unit, b, first) {
                r = cgroup_bonding_install(b, pid, cgroup_suffix);
                if (r < 0 && b->essential)
                        return r;
        }

        return 0;
}

int cgroup_bonding_migrate(CGroupBonding *b, CGroupBonding *list) {
        CGroupBonding *q;
        int ret = 0;

        LIST_FOREACH(by_unit, q, list) {
                int r;

                if (q == b)
                        continue;

                if (!q->ours)
                        continue;

                r = cg_migrate_recursive(q->controller, q->path, b->controller, b->path, true, false);
                if (r < 0 && ret == 0)
                        ret = r;
        }

        return ret;
}

int cgroup_bonding_migrate_to(CGroupBonding *b, const char *target, bool rem) {
        assert(b);
        assert(target);

        return cg_migrate_recursive(b->controller, b->path, b->controller, target, true, rem);
}

int cgroup_bonding_set_group_access(CGroupBonding *b, mode_t mode, uid_t uid, gid_t gid) {
        assert(b);

        if (!b->realized)
                return -EINVAL;

        return cg_set_group_access(b->controller, b->path, mode, uid, gid);
}

int cgroup_bonding_set_group_access_list(CGroupBonding *first, mode_t mode, uid_t uid, gid_t gid) {
        CGroupBonding *b;
        int r;

        LIST_FOREACH(by_unit, b, first) {
                r = cgroup_bonding_set_group_access(b, mode, uid, gid);
                if (r < 0)
                        return r;
        }

        return 0;
}

int cgroup_bonding_set_task_access(CGroupBonding *b, mode_t mode, uid_t uid, gid_t gid, int sticky) {
        assert(b);

        if (!b->realized)
                return -EINVAL;

        return cg_set_task_access(b->controller, b->path, mode, uid, gid, sticky);
}

int cgroup_bonding_set_task_access_list(CGroupBonding *first, mode_t mode, uid_t uid, gid_t gid, int sticky) {
        CGroupBonding *b;
        int r;

        LIST_FOREACH(by_unit, b, first) {
                r = cgroup_bonding_set_task_access(b, mode, uid, gid, sticky);
                if (r < 0)
                        return r;
        }

        return 0;
}

int cgroup_bonding_kill(CGroupBonding *b, int sig, bool sigcont, bool rem, Set *s, const char *cgroup_suffix) {
        char *p = NULL;
        const char *path;
        int r;

        assert(b);
        assert(sig >= 0);

        /* Don't kill cgroups that aren't ours */
        if (!b->ours)
                return 0;

        if (cgroup_suffix) {
                p = strjoin(b->path, "/", cgroup_suffix, NULL);
                if (!p)
                        return -ENOMEM;

                path = p;
        } else
                path = b->path;

        r = cg_kill_recursive(b->controller, path, sig, sigcont, true, rem, s);
        free(p);

        return r;
}

int cgroup_bonding_kill_list(CGroupBonding *first, int sig, bool sigcont, bool rem, Set *s, const char *cgroup_suffix) {
        CGroupBonding *b;
        Set *allocated_set = NULL;
        int ret = -EAGAIN, r;

        if (!first)
                return 0;

        if (!s)
                if (!(s = allocated_set = set_new(trivial_hash_func, trivial_compare_func)))
                        return -ENOMEM;

        LIST_FOREACH(by_unit, b, first) {
                r = cgroup_bonding_kill(b, sig, sigcont, rem, s, cgroup_suffix);
                if (r < 0) {
                        if (r == -EAGAIN || r == -ESRCH)
                                continue;

                        ret = r;
                        goto finish;
                }

                if (ret < 0 || r > 0)
                        ret = r;
        }

finish:
        if (allocated_set)
                set_free(allocated_set);

        return ret;
}

/* Returns 1 if the group is empty, 0 if it is not, -EAGAIN if we
 * cannot know */
int cgroup_bonding_is_empty(CGroupBonding *b) {
        int r;

        assert(b);

        if ((r = cg_is_empty_recursive(b->controller, b->path, true)) < 0)
                return r;

        /* If it is empty it is empty */
        if (r > 0)
                return 1;

        /* It's not only us using this cgroup, so we just don't know */
        return b->ours ? 0 : -EAGAIN;
}

int cgroup_bonding_is_empty_list(CGroupBonding *first) {
        CGroupBonding *b;

        LIST_FOREACH(by_unit, b, first) {
                int r;

                if ((r = cgroup_bonding_is_empty(b)) < 0) {
                        /* If this returned -EAGAIN, then we don't know if the
                         * group is empty, so let's see if another group can
                         * tell us */

                        if (r != -EAGAIN)
                                return r;
                } else
                        return r;
        }

        return -EAGAIN;
}

int manager_setup_cgroup(Manager *m) {
        _cleanup_free_ char *current = NULL, *path = NULL;
        char suffix_buffer[sizeof("/systemd-") + DECIMAL_STR_MAX(pid_t)];
        const char *suffix;
        int r;

        assert(m);

        /* 0. Be nice to Ingo Molnar #628004 */
        if (path_is_mount_point("/sys/fs/cgroup/systemd", false) <= 0) {
                log_warning("No control group support available, not creating root group.");
                return 0;
        }

        /* 1. Determine hierarchy */
        r = cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER, 0, &current);
        if (r < 0) {
                log_error("Cannot determine cgroup we are running in: %s", strerror(-r));
                return r;
        }

        if (m->running_as == SYSTEMD_SYSTEM)
                suffix = "/system";
        else {
                sprintf(suffix_buffer, "/systemd-%lu", (unsigned long) getpid());
                suffix = suffix_buffer;
        }

        free(m->cgroup_hierarchy);
        if (endswith(current, suffix)) {
                /* We probably got reexecuted and can continue to use our root cgroup */
                m->cgroup_hierarchy = current;
                current = NULL;
        } else {
                /* We need a new root cgroup */
                if (streq(current, "/"))
                        m->cgroup_hierarchy = strdup(suffix);
                else
                        m->cgroup_hierarchy = strappend(current, suffix);

                if (!m->cgroup_hierarchy)
                        return log_oom();
        }

        /* 2. Show data */
        r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, m->cgroup_hierarchy, NULL, &path);
        if (r < 0) {
                log_error("Cannot find cgroup mount point: %s", strerror(-r));
                return r;
        }

        log_debug("Using cgroup controller " SYSTEMD_CGROUP_CONTROLLER ". File system hierarchy is at %s.", path);

        /* 3. Install agent */
        if (m->running_as == SYSTEMD_SYSTEM) {
                r = cg_install_release_agent(SYSTEMD_CGROUP_CONTROLLER, SYSTEMD_CGROUP_AGENT_PATH);
                if (r < 0)
                        log_warning("Failed to install release agent, ignoring: %s", strerror(-r));
                else if (r > 0)
                        log_debug("Installed release agent.");
                else
                        log_debug("Release agent already installed.");
        }

        /* 4. Realize the group */
        r = cg_create_and_attach(SYSTEMD_CGROUP_CONTROLLER, m->cgroup_hierarchy, 0);
        if (r < 0) {
                log_error("Failed to create root cgroup hierarchy: %s", strerror(-r));
                return r;
        }

        /* 5. And pin it, so that it cannot be unmounted */
        if (m->pin_cgroupfs_fd >= 0)
                close_nointr_nofail(m->pin_cgroupfs_fd);

        m->pin_cgroupfs_fd = open(path, O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOCTTY|O_NONBLOCK);
        if (r < 0) {
                log_error("Failed to open pin file: %m");
                return -errno;
        }

        /* 6. Remove non-existing controllers from the default controllers list */
        cg_shorten_controllers(m->default_controllers);

        /* 7. Let's create the user and machine hierarchies
         * right-away, so that people can inotify on them, if they
         * wish, without this being racy. */
        if (m->running_as == SYSTEMD_SYSTEM) {
                cg_create(SYSTEMD_CGROUP_CONTROLLER, m->cgroup_hierarchy, "../user");
                cg_create(SYSTEMD_CGROUP_CONTROLLER, m->cgroup_hierarchy, "../machine");
        }

        return 0;
}

void manager_shutdown_cgroup(Manager *m, bool delete) {
        assert(m);

        if (delete && m->cgroup_hierarchy)
                cg_delete(SYSTEMD_CGROUP_CONTROLLER, m->cgroup_hierarchy);

        if (m->pin_cgroupfs_fd >= 0) {
                close_nointr_nofail(m->pin_cgroupfs_fd);
                m->pin_cgroupfs_fd = -1;
        }

        free(m->cgroup_hierarchy);
        m->cgroup_hierarchy = NULL;
}

int cgroup_bonding_get(Manager *m, const char *cgroup, CGroupBonding **bonding) {
        CGroupBonding *b;
        char *p;

        assert(m);
        assert(cgroup);
        assert(bonding);

        b = hashmap_get(m->cgroup_bondings, cgroup);
        if (b) {
                *bonding = b;
                return 1;
        }

        p = strdupa(cgroup);
        if (!p)
                return -ENOMEM;

        for (;;) {
                char *e;

                e = strrchr(p, '/');
                if (e == p || !e) {
                        *bonding = NULL;
                        return 0;
                }

                *e = 0;

                b = hashmap_get(m->cgroup_bondings, p);
                if (b) {
                        *bonding = b;
                        return 1;
                }
        }
}

int cgroup_notify_empty(Manager *m, const char *group) {
        CGroupBonding *l, *b;
        int r;

        assert(m);
        assert(group);

        r = cgroup_bonding_get(m, group, &l);
        if (r <= 0)
                return r;

        LIST_FOREACH(by_path, b, l) {
                int t;

                if (!b->unit)
                        continue;

                t = cgroup_bonding_is_empty_list(b);
                if (t < 0) {

                        /* If we don't know, we don't know */
                        if (t != -EAGAIN)
                                log_warning("Failed to check whether cgroup is empty: %s", strerror(errno));

                        continue;
                }

                if (t > 0) {
                        /* If it is empty, let's delete it */
                        cgroup_bonding_trim_list(b->unit->cgroup_bondings, true);

                        if (UNIT_VTABLE(b->unit)->cgroup_notify_empty)
                                UNIT_VTABLE(b->unit)->cgroup_notify_empty(b->unit);
                }
        }

        return 0;
}

Unit* cgroup_unit_by_pid(Manager *m, pid_t pid) {
        CGroupBonding *l, *b;
        char *group = NULL;

        assert(m);

        if (pid <= 1)
                return NULL;

        if (cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER, pid, &group) < 0)
                return NULL;

        l = hashmap_get(m->cgroup_bondings, group);

        if (!l) {
                char *slash;

                while ((slash = strrchr(group, '/'))) {
                        if (slash == group)
                                break;

                        *slash = 0;

                        if ((l = hashmap_get(m->cgroup_bondings, group)))
                                break;
                }
        }

        free(group);

        LIST_FOREACH(by_path, b, l) {

                if (!b->unit)
                        continue;

                if (b->ours)
                        return b->unit;
        }

        return NULL;
}

CGroupBonding *cgroup_bonding_find_list(CGroupBonding *first, const char *controller) {
        CGroupBonding *b;

        if (!controller)
                controller = SYSTEMD_CGROUP_CONTROLLER;

        LIST_FOREACH(by_unit, b, first)
                if (streq(b->controller, controller))
                        return b;

        return NULL;
}

char *cgroup_bonding_to_string(CGroupBonding *b) {
        char *r;

        assert(b);

        if (asprintf(&r, "%s:%s", b->controller, b->path) < 0)
                return NULL;

        return r;
}

pid_t cgroup_bonding_search_main_pid(CGroupBonding *b) {
        FILE *f;
        pid_t pid = 0, npid, mypid;

        assert(b);

        if (!b->ours)
                return 0;

        if (cg_enumerate_processes(b->controller, b->path, &f) < 0)
                return 0;

        mypid = getpid();

        while (cg_read_pid(f, &npid) > 0)  {
                pid_t ppid;

                if (npid == pid)
                        continue;

                /* Ignore processes that aren't our kids */
                if (get_parent_of_pid(npid, &ppid) >= 0 && ppid != mypid)
                        continue;

                if (pid != 0) {
                        /* Dang, there's more than one daemonized PID
                        in this group, so we don't know what process
                        is the main process. */
                        pid = 0;
                        break;
                }

                pid = npid;
        }

        fclose(f);

        return pid;
}

pid_t cgroup_bonding_search_main_pid_list(CGroupBonding *first) {
        CGroupBonding *b;
        pid_t pid;

        /* Try to find a main pid from this cgroup, but checking if
         * there's only one PID in the cgroup and returning it. Later
         * on we might want to add additional, smarter heuristics
         * here. */

        LIST_FOREACH(by_unit, b, first)
                if ((pid = cgroup_bonding_search_main_pid(b)) != 0)
                        return pid;

        return 0;

}
