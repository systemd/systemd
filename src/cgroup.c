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
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/mount.h>
#include <fcntl.h>

#include "cgroup.h"
#include "cgroup-util.h"
#include "log.h"

int cgroup_bonding_realize(CGroupBonding *b) {
        int r;

        assert(b);
        assert(b->path);
        assert(b->controller);

        if (b->realized)
                return 0;

        if ((r = cg_create(b->controller, b->path)) < 0)
                return r;

        b->realized = true;

        if (b->only_us && b->clean_up)
                cg_trim(b->controller, b->path, false);

        return 0;
}

int cgroup_bonding_realize_list(CGroupBonding *first) {
        CGroupBonding *b;
        int r;

        LIST_FOREACH(by_unit, b, first)
                if ((r = cgroup_bonding_realize(b)) < 0)
                        return r;

        return 0;
}

void cgroup_bonding_free(CGroupBonding *b) {
        assert(b);

        if (b->unit) {
                CGroupBonding *f;

                LIST_REMOVE(CGroupBonding, by_unit, b->unit->meta.cgroup_bondings, b);

                assert_se(f = hashmap_get(b->unit->meta.manager->cgroup_bondings, b->path));
                LIST_REMOVE(CGroupBonding, by_path, f, b);

                if (f)
                        hashmap_replace(b->unit->meta.manager->cgroup_bondings, b->path, f);
                else
                        hashmap_remove(b->unit->meta.manager->cgroup_bondings, b->path);
        }

        if (b->realized && b->only_us && b->clean_up) {

                if (cgroup_bonding_is_empty(b) > 0)
                        cg_delete(b->controller, b->path);
                else
                        cg_trim(b->controller, b->path, false);
        }

        free(b->controller);
        free(b->path);
        free(b);
}

void cgroup_bonding_free_list(CGroupBonding *first) {
        CGroupBonding *b, *n;

        LIST_FOREACH_SAFE(by_unit, b, n, first)
                cgroup_bonding_free(b);
}

void cgroup_bonding_trim(CGroupBonding *b, bool delete_root) {
        assert(b);

        if (b->realized && b->only_us && b->clean_up)
                cg_trim(b->controller, b->path, delete_root);
}

void cgroup_bonding_trim_list(CGroupBonding *first, bool delete_root) {
        CGroupBonding *b;

        LIST_FOREACH(by_unit, b, first)
                cgroup_bonding_trim(b, delete_root);
}

int cgroup_bonding_install(CGroupBonding *b, pid_t pid) {
        int r;

        assert(b);
        assert(pid >= 0);

        if ((r = cg_create_and_attach(b->controller, b->path, pid)) < 0)
                return r;

        b->realized = true;
        return 0;
}

int cgroup_bonding_install_list(CGroupBonding *first, pid_t pid) {
        CGroupBonding *b;
        int r;

        LIST_FOREACH(by_unit, b, first)
                if ((r = cgroup_bonding_install(b, pid)) < 0)
                        return r;

        return 0;
}

int cgroup_bonding_kill(CGroupBonding *b, int sig) {
        int r;

        assert(b);
        assert(sig >= 0);

        if ((r = cgroup_bonding_realize(b)) < 0)
                return r;

        assert(b->realized);

        return cg_kill_recursive(b->controller, b->path, sig, true);
}

int cgroup_bonding_kill_list(CGroupBonding *first, int sig) {
        CGroupBonding *b;
        int r = -EAGAIN;

        LIST_FOREACH(by_unit, b, first) {
                if ((r = cgroup_bonding_kill(b, sig)) < 0) {
                        if (r == -EAGAIN || r == -ESRCH)
                                continue;

                        return r;
                }

                return 0;
        }

        return r;
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
        return b->only_us ? 0 : -EAGAIN;
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
        char *current = NULL, *path = NULL;
        int r;
        char suffix[32];

        assert(m);

        /* 1. Initialize libcg */
        if ((r = cg_init()) < 0) {
                log_error("Failed to initialize libcg: %s", strerror(-r));
                goto finish;
        }

        /* 2. Determine hierarchy */
        if ((r = cg_get_by_pid(SYSTEMD_CGROUP_CONTROLLER, 0, &current)) < 0)
                goto finish;

        snprintf(suffix, sizeof(suffix), "/systemd-%lu", (unsigned long) getpid());
        char_array_0(suffix);

        free(m->cgroup_hierarchy);
        if (endswith(current, suffix)) {
                /* We probably got reexecuted and can continue to use our root cgroup */
                m->cgroup_hierarchy = current;
                current = NULL;

        } else {
                /* We need a new root cgroup */
                m->cgroup_hierarchy = NULL;
                if ((r = asprintf(&m->cgroup_hierarchy, "%s%s", streq(current, "/") ? "" : current, suffix)) < 0) {
                        r = -ENOMEM;
                        goto finish;
                }
        }

        /* 3. Show data */
        if ((r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, m->cgroup_hierarchy, NULL, &path)) < 0)
                goto finish;

        log_debug("Using cgroup controller " SYSTEMD_CGROUP_CONTROLLER ". File system hierarchy is at %s.", path);

        /* 4. Install agent */
        if ((r = cg_install_release_agent(SYSTEMD_CGROUP_CONTROLLER, CGROUP_AGENT_PATH)) < 0)
                log_warning("Failed to install release agent, ignoring: %s", strerror(-r));
        else if (r > 0)
                log_debug("Installed release agent.");
        else
                log_debug("Release agent already installed.");

        /* 5. Realize the group */
        if ((r = cg_create_and_attach(SYSTEMD_CGROUP_CONTROLLER, m->cgroup_hierarchy, 0)) < 0) {
                log_error("Failed to create root cgroup hierarchy: %s", strerror(-r));
                goto finish;
        }

        /* 6. And pin it, so that it cannot be unmounted */
        if (m->pin_cgroupfs_fd >= 0)
                close_nointr_nofail(m->pin_cgroupfs_fd);

        if ((m->pin_cgroupfs_fd = open(path, O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOCTTY|O_NONBLOCK)) < 0) {
                r = -errno;
                goto finish;
        }

        log_debug("Created root group.");

finish:
        free(current);
        free(path);

        return r;
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

int cgroup_notify_empty(Manager *m, const char *group) {
        CGroupBonding *l, *b;

        assert(m);
        assert(group);

        if (!(l = hashmap_get(m->cgroup_bondings, group)))
                return 0;

        LIST_FOREACH(by_path, b, l) {
                int t;

                if (!b->unit)
                        continue;

                if ((t = cgroup_bonding_is_empty_list(b)) < 0) {

                        /* If we don't know, we don't know */
                        if (t != -EAGAIN)
                                log_warning("Failed to check whether cgroup is empty: %s", strerror(errno));

                        continue;
                }

                if (t > 0)
                        if (UNIT_VTABLE(b->unit)->cgroup_notify_empty)
                                UNIT_VTABLE(b->unit)->cgroup_notify_empty(b->unit);
        }

        return 0;
}

Unit* cgroup_unit_by_pid(Manager *m, pid_t pid) {
        CGroupBonding *l, *b;
        char *group = NULL;
        int r;

        assert(m);

        if (pid <= 1)
                return NULL;

        if ((r = cg_get_by_pid(SYSTEMD_CGROUP_CONTROLLER, pid, &group)))
                return NULL;

        l = hashmap_get(m->cgroup_bondings, group);
        free(group);

        LIST_FOREACH(by_path, b, l) {

                if (!b->unit)
                        continue;

                if (b->only_us)
                        return b->unit;
        }

        return NULL;
}

CGroupBonding *cgroup_bonding_find_list(CGroupBonding *first, const char *controller) {
        CGroupBonding *b;

        assert(controller);

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
