/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "ansi-color.h"
#include "bus-locator.h"
#include "bus-unit-procs.h"
#include "glyph-util.h"
#include "hashmap.h"
#include "list.h"
#include "macro.h"
#include "path-util.h"
#include "process-util.h"
#include "sort-util.h"
#include "string-util.h"
#include "terminal-util.h"

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

static int add_cgroup(Hashmap *cgroups, const char *path, bool is_const, struct CGroupInfo **ret) {
        struct CGroupInfo *parent = NULL, *cg;
        int r;

        assert(cgroups);
        assert(ret);

        path = empty_to_root(path);

        cg = hashmap_get(cgroups, path);
        if (cg) {
                *ret = cg;
                return 0;
        }

        if (!empty_or_root(path)) {
                const char *e, *pp;

                e = strrchr(path, '/');
                if (!e)
                        return -EINVAL;

                pp = strndupa_safe(path, e - path);

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

        return hashmap_ensure_put(&cg->pids, &trivial_hash_ops, PID_TO_PTR(pid), (void*) name);
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

static int cgroup_info_compare_func(struct CGroupInfo * const *a, struct CGroupInfo * const *b) {
        return strcmp((*a)->cgroup_path, (*b)->cgroup_path);
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

        cgroup_path = empty_to_root(cgroup_path);

        cg = hashmap_get(cgroups, cgroup_path);
        if (!cg)
                return 0;

        if (!hashmap_isempty(cg->pids)) {
                const char *name;
                size_t n = 0, i;
                pid_t *pids;
                void *pidp;
                int width;

                /* Order processes by their PID */
                pids = newa(pid_t, hashmap_size(cg->pids));

                HASHMAP_FOREACH_KEY(name, pidp, cg->pids)
                        pids[n++] = PTR_TO_PID(pidp);

                assert(n == hashmap_size(cg->pids));
                typesafe_qsort(pids, n, pid_compare_func);

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
                        special = special_glyph(more ? SPECIAL_GLYPH_TREE_BRANCH : SPECIAL_GLYPH_TREE_RIGHT);

                        fprintf(stdout, "%s%s%s%*"PID_PRI" %s%s\n",
                                prefix,
                                special,
                                ansi_grey(),
                                width, pids[i],
                                name,
                                ansi_normal());
                }
        }

        if (cg->children) {
                struct CGroupInfo **children;
                size_t n = 0, i;

                /* Order subcgroups by their name */
                children = newa(struct CGroupInfo*, cg->n_children);
                LIST_FOREACH(siblings, child, cg->children)
                        children[n++] = child;
                assert(n == cg->n_children);
                typesafe_qsort(children, n, cgroup_info_compare_func);

                if (n_columns != 0)
                        n_columns = MAX(LESS_BY(n_columns, 2U), 20U);

                for (i = 0; i < n; i++) {
                        _cleanup_free_ char *pp = NULL;
                        const char *name, *special;
                        bool more;

                        name = strrchr(children[i]->cgroup_path, '/');
                        if (!name)
                                return -EINVAL;
                        name++;

                        more = i+1 < n;
                        special = special_glyph(more ? SPECIAL_GLYPH_TREE_BRANCH : SPECIAL_GLYPH_TREE_RIGHT);

                        fputs(prefix, stdout);
                        fputs(special, stdout);
                        fputs(name, stdout);
                        fputc('\n', stdout);

                        special = special_glyph(more ? SPECIAL_GLYPH_TREE_VERTICAL : SPECIAL_GLYPH_TREE_SPACE);

                        pp = strjoin(prefix, special);
                        if (!pp)
                                return -ENOMEM;

                        r = dump_processes(cgroups, children[i]->cgroup_path, pp, n_columns, flags);
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
        size_t n = 0, k;
        int width, r;

        /* Prints the extra processes, i.e. those that are in cgroups we haven't displayed yet. We show them as
         * combined, sorted, linear list. */

        HASHMAP_FOREACH(cg, cgroups) {
                const char *name;
                void *pidp;

                if (cg->done)
                        continue;

                if (hashmap_isempty(cg->pids))
                        continue;

                r = hashmap_ensure_allocated(&names, &trivial_hash_ops);
                if (r < 0)
                        return r;

                if (!GREEDY_REALLOC(pids, n + hashmap_size(cg->pids)))
                        return -ENOMEM;

                HASHMAP_FOREACH_KEY(name, pidp, cg->pids) {
                        pids[n++] = PTR_TO_PID(pidp);

                        r = hashmap_put(names, pidp, (void*) name);
                        if (r < 0)
                                return r;
                }
        }

        if (n == 0)
                return 0;

        typesafe_qsort(pids, n, pid_compare_func);
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
                        special_glyph(SPECIAL_GLYPH_TRIANGULAR_BULLET),
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

        r = bus_call_method(
                        bus,
                        bus_systemd_mgr,
                        "GetUnitProcesses",
                        error,
                        &reply,
                        "s",
                        unit);
        if (r < 0)
                return r;

        cgroups = hashmap_new(&path_hash_ops);
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
                if (r == -ENOMEM)
                        goto finish;
                if (r < 0)
                        log_warning_errno(r, "Invalid process description in GetUnitProcesses reply: cgroup=\"%s\" pid=%u command=\"%s\", ignoring: %m",
                                          path, pid, name);
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
