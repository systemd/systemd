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

#include "cgroup.h"
#include "log.h"

static int translate_error(int error, int _errno) {

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

int cgroup_bonding_realize(CGroupBonding *b) {
        int r;

        assert(b);
        assert(b->path);
        assert(b->controller);

        if (b->cgroup)
                return 0;

        if (!(b->cgroup = cgroup_new_cgroup(b->path)))
                return -ENOMEM;

        if (!cgroup_add_controller(b->cgroup, b->controller)) {
                r = -ENOMEM;
                goto fail;
        }

        if (b->inherit)
                r = cgroup_create_cgroup_from_parent(b->cgroup, true);
        else
                r = cgroup_create_cgroup(b->cgroup, true);

        if (r != 0) {
                r = translate_error(r, errno);
                goto fail;
        }

        return 0;

fail:
        cgroup_free(&b->cgroup);
        b->cgroup = NULL;
        return r;
}

int cgroup_bonding_realize_list(CGroupBonding *first) {
        CGroupBonding *b;

        LIST_FOREACH(by_unit, b, first) {
                int r;

                if ((r = cgroup_bonding_realize(b)) < 0)
                        return r;
        }

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

        if (b->cgroup) {
                if (b->only_us && b->clean_up && cgroup_bonding_is_empty(b) > 0)
                        cgroup_delete_cgroup_ext(b->cgroup, true);

                cgroup_free(&b->cgroup);
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

int cgroup_bonding_install(CGroupBonding *b, pid_t pid) {
        int r;

        assert(b);
        assert(pid >= 0);

        if (pid == 0)
                pid = getpid();

        if (!b->cgroup)
                return -ENOENT;

        if ((r = cgroup_attach_task_pid(b->cgroup, pid)))
                return translate_error(r, errno);

        return 0;
}

int cgroup_bonding_install_list(CGroupBonding *first, pid_t pid) {
        CGroupBonding *b;

        LIST_FOREACH(by_unit, b, first) {
                int r;

                if ((r = cgroup_bonding_install(b, pid)) < 0)
                        return r;
        }

        return 0;
}

int cgroup_bonding_kill(CGroupBonding *b, int sig) {
        int r;
        Set *s;
        bool done;
        bool killed = false;

        assert(b);
        assert(sig > 0);

        if (!b->only_us)
                return -EAGAIN;

        if (!(s = set_new(trivial_hash_func, trivial_compare_func)))
                return -ENOMEM;

        do {
                void *iterator;
                pid_t pid;

                done = true;

                if ((r = cgroup_get_task_begin(b->path, b->controller, &iterator, &pid)) != 0) {
                        if (r == ECGEOF) {
                                r = 0;
                                goto kill_done;
                        } else {
                                r = translate_error(r, errno);
                                break;
                        }
                }

                for (;;) {
                        if (set_get(s, INT_TO_PTR(pid)) != INT_TO_PTR(pid)) {

                                /* If we haven't killed this process
                                 * yet, kill it */

                                if (kill(pid, sig) < 0 && errno != ESRCH) {
                                        r = -errno;
                                        break;
                                }

                                killed = true;
                                done = false;

                                if ((r = set_put(s, INT_TO_PTR(pid))) < 0)
                                    break;
                        }

                        if ((r = cgroup_get_task_next(&iterator, &pid)) != 0) {

                                if (r == ECGEOF)
                                        r = 0;
                                else
                                        r = translate_error(r, errno);

                                break;
                        }
                }

        kill_done:
                assert_se(cgroup_get_task_end(&iterator) == 0);

                /* To avoid racing against processes which fork
                 * quicker than we can kill them we repeat this until
                 * no new pids need to be killed. */

        } while (!done && r >= 0);

        set_free(s);

        if (r < 0)
                return r;

        return killed ? 0 : -ESRCH;
}

int cgroup_bonding_kill_list(CGroupBonding *first, int sig) {
        CGroupBonding *b;
        int r = -EAGAIN;

        LIST_FOREACH(by_unit, b, first) {
                if ((r = cgroup_bonding_kill(b, sig)) < 0) {
                        if (r == -EAGAIN || -ESRCH)
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
        void *iterator;
        pid_t pid;
        int r;

        assert(b);

        r = cgroup_get_task_begin(b->path, b->controller, &iterator, &pid);

        if (r == 0 || r == ECGEOF)
                cgroup_get_task_end(&iterator);

        /* Hmm, no PID in this group? Then it is definitely empty */
        if (r == ECGEOF)
                return 1;

        /* Some error? Let's return it */
        if (r != 0)
                return translate_error(r, errno);

        /* It's not empty, and we are the only user, then it is
         * definitely not empty */
        if (b->only_us)
                return 0;

        /* There are PIDs in the group but we aren't the only users,
         * hence we cannot say */
        return -EAGAIN;
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

static int install_release_agent(Manager *m, const char *mount_point) {
        char *p, *c, *sc;
        int r;

        assert(m);
        assert(mount_point);

        if (asprintf(&p, "%s/release_agent", mount_point) < 0)
                return -ENOMEM;

        if ((r = read_one_line_file(p, &c)) < 0) {
                free(p);
                return r;
        }

        sc = strstrip(c);

        if (sc[0] == 0) {
                if ((r = write_one_line_file(p, CGROUP_AGENT_PATH "\n" )) < 0) {
                        free(p);
                        free(c);
                        return r;
                }
        } else if (!streq(sc, CGROUP_AGENT_PATH)) {
                free(p);
                free(c);
                return -EEXIST;
        }

        free(c);
        free(p);

        if (asprintf(&p, "%s/notify_on_release", mount_point) < 0)
                return -ENOMEM;

        if ((r = read_one_line_file(p, &c)) < 0) {
                free(p);
                return r;
        }

        sc = strstrip(c);

        if (streq(sc, "0")) {
                if ((r = write_one_line_file(p, "1\n")) < 0) {
                        free(p);
                        free(c);
                        return r;
                }
        } else if (!streq(sc, "1")) {
                free(p);
                free(c);
                return -EIO;
        }

        free(p);
        free(c);

        return 0;
}

static int create_hierarchy_cgroup(Manager *m) {
        struct cgroup *cg;
        int r;

        assert(m);

        if (!(cg = cgroup_new_cgroup(m->cgroup_hierarchy)))
                return -ENOMEM;

        if (!(cgroup_add_controller(cg, m->cgroup_controller))) {
                r = -ENOMEM;
                goto finish;
        }

        if ((r = cgroup_create_cgroup(cg, true)) != 0) {
                log_error("Failed to create cgroup hierarchy group: %s", cgroup_strerror(r));
                r = translate_error(r, errno);
                goto finish;
        }

        if ((r = cgroup_attach_task(cg)) != 0) {
                log_error("Failed to add ourselves to hierarchy group: %s", cgroup_strerror(r));
                r = translate_error(r, errno);
                goto finish;
        }

        r = 0;

finish:
        cgroup_free(&cg);
        return r;
}

int manager_setup_cgroup(Manager *m) {
        char *mp, *cp;
        int r;
        pid_t pid;
        char suffix[32];

        assert(m);

        if ((r = cgroup_init()) != 0) {
                log_error("Failed to initialize libcg: %s", cgroup_strerror(r));
                return translate_error(r, errno);
        }

        free(m->cgroup_controller);
        if (!(m->cgroup_controller = strdup("debug")))
                return -ENOMEM;

        if ((r = cgroup_get_subsys_mount_point(m->cgroup_controller, &mp)))
                return translate_error(r, errno);

        pid = getpid();

        if ((r = cgroup_get_current_controller_path(pid, m->cgroup_controller, &cp))) {
                free(mp);
                return translate_error(r, errno);
        }

        snprintf(suffix, sizeof(suffix), "/systemd-%u", (unsigned) pid);
        char_array_0(suffix);

        free(m->cgroup_hierarchy);

        if (endswith(cp, suffix))
                /* We probably got reexecuted and can continue to use our root cgroup */
                m->cgroup_hierarchy = cp;
        else {
                /* We need a new root cgroup */

                m->cgroup_hierarchy = NULL;
                r = asprintf(&m->cgroup_hierarchy, "%s%s", streq(cp, "/") ? "" : cp, suffix);
                free(cp);

                if (r < 0) {
                        free(mp);
                        return -ENOMEM;
                }
        }

        log_info("Using cgroup controller <%s>, hierarchy mounted at <%s>, using root group <%s>.",
                 m->cgroup_controller,
                 mp,
                 m->cgroup_hierarchy);

        if ((r = install_release_agent(m, mp)) < 0)
                log_warning("Failed to install release agent, ignoring: %s", strerror(-r));
        else
                log_info("Installed release agent, or already installed.");

        free(mp);

        if ((r = create_hierarchy_cgroup(m)) < 0)
                log_error("Failed to create root cgroup hierarchy: %s", strerror(-r));
        else
                log_info("Created root group.");

        return r;
}

int manager_shutdown_cgroup(Manager *m, bool delete) {
        struct cgroup *cg;
        int r;

        assert(m);

        if (!m->cgroup_hierarchy)
                return 0;

        if (!(cg = cgroup_new_cgroup(m->cgroup_hierarchy)))
                return -ENOMEM;

        if (!(cgroup_add_controller(cg, m->cgroup_controller))) {
                r = -ENOMEM;
                goto finish;
        }

        /* Often enough we won't be able to delete the cgroup we
         * ourselves are in, hence ignore all errors here */
        if (delete)
                cgroup_delete_cgroup_ext(cg, CGFLAG_DELETE_IGNORE_MIGRATION|CGFLAG_DELETE_RECURSIVE);
        r = 0;

finish:
        cgroup_free(&cg);
        return r;

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
