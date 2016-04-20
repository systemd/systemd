/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering

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

#include "alloc-util.h"
#include "bus-internal.h"
#include "bus-unit-util.h"
#include "bus-util.h"
#include "cgroup-util.h"
#include "env-util.h"
#include "escape.h"
#include "hashmap.h"
#include "list.h"
#include "locale-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "rlimit-util.h"
#include "signal-util.h"
#include "string-util.h"
#include "syslog-util.h"
#include "terminal-util.h"
#include "utf8.h"
#include "util.h"

struct CGroupInfo {
        char *cgroup_path;
        bool is_const; /* If false, cgroup_path should be free()'d */

        Hashmap *pids; /* PID → process name */
        bool done;

        struct CGroupInfo *parent;
        LIST_FIELDS(struct CGroupInfo, siblings);
        LIST_HEAD(struct CGroupInfo, children);
        size_t n_children;
};

static bool IS_ROOT(const char *p) {
        return isempty(p) || streq(p, "/");
}

static int add_cgroup(Hashmap *cgroups, const char *path, bool is_const, struct CGroupInfo **ret) {
        struct CGroupInfo *parent = NULL, *cg;
        int r;

        assert(cgroups);
        assert(ret);

        if (IS_ROOT(path))
                path = "/";

        cg = hashmap_get(cgroups, path);
        if (cg) {
                *ret = cg;
                return 0;
        }

        if (!IS_ROOT(path)) {
                const char *e, *pp;

                e = strrchr(path, '/');
                if (!e)
                        return -EINVAL;

                pp = strndupa(path, e - path);
                if (!pp)
                        return -ENOMEM;

                r = add_cgroup(cgroups, pp, false, &parent);
                if (r < 0)
                        return r;
        }

        cg = new0(struct CGroupInfo, 1);
        if (!cg)
                return -ENOMEM;

        if (is_const)
                cg->cgroup_path = (char*) path;
        else {
                cg->cgroup_path = strdup(path);
                if (!cg->cgroup_path) {
                        free(cg);
                        return -ENOMEM;
                }
        }

        cg->is_const = is_const;
        cg->parent = parent;

        r = hashmap_put(cgroups, cg->cgroup_path, cg);
        if (r < 0) {
                if (!is_const)
                        free(cg->cgroup_path);
                free(cg);
                return r;
        }

        if (parent) {
                LIST_PREPEND(siblings, parent->children, cg);
                parent->n_children++;
        }

        *ret = cg;
        return 1;
}

static int add_process(
                Hashmap *cgroups,
                const char *path,
                pid_t pid,
                const char *name) {

        struct CGroupInfo *cg;
        int r;

        assert(cgroups);
        assert(name);
        assert(pid > 0);

        r = add_cgroup(cgroups, path, true, &cg);
        if (r < 0)
                return r;

        r = hashmap_ensure_allocated(&cg->pids, &trivial_hash_ops);
        if (r < 0)
                return r;

        return hashmap_put(cg->pids, PID_TO_PTR(pid), (void*) name);
}

static void remove_cgroup(Hashmap *cgroups, struct CGroupInfo *cg) {
        assert(cgroups);
        assert(cg);

        while (cg->children)
                remove_cgroup(cgroups, cg->children);

        hashmap_remove(cgroups, cg->cgroup_path);

        if (!cg->is_const)
                free(cg->cgroup_path);

        hashmap_free(cg->pids);

        if (cg->parent)
                LIST_REMOVE(siblings, cg->parent->children, cg);

        free(cg);
}

static int cgroup_info_compare_func(const void *a, const void *b) {
        const struct CGroupInfo *x = *(const struct CGroupInfo* const*) a, *y = *(const struct CGroupInfo* const*) b;

        assert(x);
        assert(y);

        return strcmp(x->cgroup_path, y->cgroup_path);
}

static int dump_processes(
                Hashmap *cgroups,
                const char *cgroup_path,
                const char *prefix,
                unsigned n_columns,
                OutputFlags flags) {

        struct CGroupInfo *cg;
        int r;

        assert(prefix);

        if (IS_ROOT(cgroup_path))
                cgroup_path = "/";

        cg = hashmap_get(cgroups, cgroup_path);
        if (!cg)
                return 0;

        if (!hashmap_isempty(cg->pids)) {
                const char *name;
                size_t n = 0, i;
                pid_t *pids;
                void *pidp;
                Iterator j;
                int width;

                /* Order processes by their PID */
                pids = newa(pid_t, hashmap_size(cg->pids));

                HASHMAP_FOREACH_KEY(name, pidp, cg->pids, j)
                        pids[n++] = PTR_TO_PID(pidp);

                assert(n == hashmap_size(cg->pids));
                qsort_safe(pids, n, sizeof(pid_t), pid_compare_func);

                width = DECIMAL_STR_WIDTH(pids[n-1]);

                for (i = 0; i < n; i++) {
                        _cleanup_free_ char *e = NULL;
                        const char *special;
                        bool more;

                        name = hashmap_get(cg->pids, PID_TO_PTR(pids[i]));
                        assert(name);

                        if (n_columns != 0) {
                                unsigned k;

                                k = MAX(LESS_BY(n_columns, 2U + width + 1U), 20U);

                                e = ellipsize(name, k, 100);
                                if (e)
                                        name = e;
                        }

                        more = i+1 < n || cg->children;
                        special = draw_special_char(more ? DRAW_TREE_BRANCH : DRAW_TREE_RIGHT);

                        fprintf(stdout, "%s%s%*"PID_PRI" %s\n",
                                prefix,
                                special,
                                width, pids[i],
                                name);
                }
        }

        if (cg->children) {
                struct CGroupInfo **children, *child;
                size_t n = 0, i;

                /* Order subcgroups by their name */
                children = newa(struct CGroupInfo*, cg->n_children);
                LIST_FOREACH(siblings, child, cg->children)
                        children[n++] = child;
                assert(n == cg->n_children);
                qsort_safe(children, n, sizeof(struct CGroupInfo*), cgroup_info_compare_func);

                n_columns = MAX(LESS_BY(n_columns, 2U), 20U);

                for (i = 0; i < n; i++) {
                        _cleanup_free_ char *pp = NULL;
                        const char *name, *special;
                        bool more;

                        child = children[i];

                        name = strrchr(child->cgroup_path, '/');
                        if (!name)
                                return -EINVAL;
                        name++;

                        more = i+1 < n;
                        special = draw_special_char(more ? DRAW_TREE_BRANCH : DRAW_TREE_RIGHT);

                        fputs(prefix, stdout);
                        fputs(special, stdout);
                        fputs(name, stdout);
                        fputc('\n', stdout);

                        special = draw_special_char(more ? DRAW_TREE_VERTICAL : DRAW_TREE_SPACE);

                        pp = strappend(prefix, special);
                        if (!pp)
                                return -ENOMEM;

                        r = dump_processes(cgroups, child->cgroup_path, pp, n_columns, flags);
                        if (r < 0)
                                return r;
                }
        }

        cg->done = true;
        return 0;
}

static int dump_extra_processes(
                Hashmap *cgroups,
                const char *prefix,
                unsigned n_columns,
                OutputFlags flags) {

        _cleanup_free_ pid_t *pids = NULL;
        _cleanup_hashmap_free_ Hashmap *names = NULL;
        struct CGroupInfo *cg;
        size_t n_allocated = 0, n = 0, k;
        Iterator i;
        int width, r;

        /* Prints the extra processes, i.e. those that are in cgroups we haven't displayed yet. We show them as
         * combined, sorted, linear list. */

        HASHMAP_FOREACH(cg, cgroups, i) {
                const char *name;
                void *pidp;
                Iterator j;

                if (cg->done)
                        continue;

                if (hashmap_isempty(cg->pids))
                        continue;

                r = hashmap_ensure_allocated(&names, &trivial_hash_ops);
                if (r < 0)
                        return r;

                if (!GREEDY_REALLOC(pids, n_allocated, n + hashmap_size(cg->pids)))
                        return -ENOMEM;

                HASHMAP_FOREACH_KEY(name, pidp, cg->pids, j) {
                        pids[n++] = PTR_TO_PID(pidp);

                        r = hashmap_put(names, pidp, (void*) name);
                        if (r < 0)
                                return r;
                }
        }

        if (n == 0)
                return 0;

        qsort_safe(pids, n, sizeof(pid_t), pid_compare_func);
        width = DECIMAL_STR_WIDTH(pids[n-1]);

        for (k = 0; k < n; k++) {
                _cleanup_free_ char *e = NULL;
                const char *name;

                name = hashmap_get(names, PID_TO_PTR(pids[k]));
                assert(name);

                if (n_columns != 0) {
                        unsigned z;

                        z = MAX(LESS_BY(n_columns, 2U + width + 1U), 20U);

                        e = ellipsize(name, z, 100);
                        if (e)
                                name = e;
                }

                fprintf(stdout, "%s%s %*" PID_PRI " %s\n",
                        prefix,
                        draw_special_char(DRAW_TRIANGULAR_BULLET),
                        width, pids[k],
                        name);
        }

        return 0;
}

int unit_show_processes(
                sd_bus *bus,
                const char *unit,
                const char *cgroup_path,
                const char *prefix,
                unsigned n_columns,
                OutputFlags flags,
                sd_bus_error *error) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Hashmap *cgroups = NULL;
        struct CGroupInfo *cg;
        int r;

        assert(bus);
        assert(unit);

        if (flags & OUTPUT_FULL_WIDTH)
                n_columns = 0;
        else if (n_columns <= 0)
                n_columns = columns();

        prefix = strempty(prefix);

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "GetUnitProcesses",
                        error,
                        &reply,
                        "s",
                        unit);
        if (r < 0)
                return r;

        cgroups = hashmap_new(&string_hash_ops);
        if (!cgroups)
                return -ENOMEM;

        r = sd_bus_message_enter_container(reply, 'a', "(sus)");
        if (r < 0)
                goto finish;

        for (;;) {
                const char *path = NULL, *name = NULL;
                uint32_t pid;

                r = sd_bus_message_read(reply, "(sus)", &path, &pid, &name);
                if (r < 0)
                        goto finish;
                if (r == 0)
                        break;

                r = add_process(cgroups, path, pid, name);
                if (r < 0)
                        goto finish;
        }

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                goto finish;

        r = dump_processes(cgroups, cgroup_path, prefix, n_columns, flags);
        if (r < 0)
                goto finish;

        r = dump_extra_processes(cgroups, prefix, n_columns, flags);

finish:
        while ((cg = hashmap_first(cgroups)))
               remove_cgroup(cgroups, cg);

        hashmap_free(cgroups);

        return r;
}
