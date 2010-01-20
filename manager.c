/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <assert.h>
#include <errno.h>
#include <string.h>

#include "manager.h"
#include "hashmap.h"
#include "macro.h"
#include "strv.h"
#include "log.h"

Manager* manager_new(void) {
        Manager *m;

        if (!(m = new0(Manager, 1)))
                return NULL;

        if (!(m->names = hashmap_new(string_hash_func, string_compare_func)))
                goto fail;

        if (!(m->jobs = hashmap_new(trivial_hash_func, trivial_compare_func)))
                goto fail;

        if (!(m->transaction_jobs = hashmap_new(trivial_hash_func, trivial_compare_func)))
                goto fail;

        return m;

fail:
        manager_free(m);
        return NULL;
}

void manager_free(Manager *m) {
        Name *n;
        Job *j;

        assert(m);

        while ((n = hashmap_first(m->names)))
                name_free(n);

        while ((j = hashmap_steal_first(m->transaction_jobs)))
                job_free(j);

        hashmap_free(m->names);
        hashmap_free(m->jobs);
        hashmap_free(m->transaction_jobs);

        free(m);
}

static void transaction_delete_job(Manager *m, Job *j) {
        assert(m);
        assert(j);

        manager_transaction_unlink_job(m, j);

        if (!j->linked)
                job_free(j);
}

static void transaction_abort(Manager *m) {
        Job *j;

        assert(m);

        while ((j = hashmap_first(m->transaction_jobs)))
                if (j->linked)
                        transaction_delete_job(m, j);
                else
                        job_free(j);

        assert(hashmap_isempty(m->transaction_jobs));
        assert(!m->transaction_anchor);
}

static void transaction_find_jobs_that_matter_to_anchor(Manager *m, Job *j, unsigned generation) {
        JobDependency *l;

        assert(m);

        for (l = j ? j->subject_list : m->transaction_anchor; l; l = l->subject_next) {

                /* This link does not matter */
                if (!l->matters)
                        continue;

                /* This name has already been marked */
                if (l->object->generation == generation)
                        continue;

                l->object->matters_to_anchor = true;
                l->object->generation = generation;

                transaction_find_jobs_that_matter_to_anchor(m, l->object, generation);
        }
}

static bool types_match(JobType a, JobType b, JobType c, JobType d) {
        return
                (a == c && b == d) ||
                (a == d && b == c);
}

static int types_merge(JobType *a, JobType b) {
        if (*a == b)
                return 0;

        if (types_match(*a, b, JOB_START, JOB_VERIFY_STARTED))
                *a = JOB_START;
        else if (types_match(*a, b, JOB_START, JOB_RELOAD) ||
                 types_match(*a, b, JOB_START, JOB_RELOAD_OR_START) ||
                 types_match(*a, b, JOB_VERIFY_STARTED, JOB_RELOAD_OR_START) ||
                 types_match(*a, b, JOB_RELOAD, JOB_RELOAD_OR_START))
                *a = JOB_RELOAD_OR_START;
        else if (types_match(*a, b, JOB_START, JOB_RESTART) ||
                 types_match(*a, b, JOB_START, JOB_TRY_RESTART) ||
                 types_match(*a, b, JOB_VERIFY_STARTED, JOB_RESTART) ||
                 types_match(*a, b, JOB_RELOAD, JOB_RESTART) ||
                 types_match(*a, b, JOB_RELOAD_OR_START, JOB_RESTART) ||
                 types_match(*a, b, JOB_RELOAD_OR_START, JOB_TRY_RESTART) ||
                 types_match(*a, b, JOB_RESTART, JOB_TRY_RESTART))
                *a = JOB_RESTART;
        else if (types_match(*a, b, JOB_VERIFY_STARTED, JOB_RELOAD))
                *a = JOB_RELOAD;
        else if (types_match(*a, b, JOB_VERIFY_STARTED, JOB_TRY_RESTART) ||
                 types_match(*a, b, JOB_RELOAD, JOB_TRY_RESTART))
                *a = JOB_TRY_RESTART;

        return -EEXIST;
}

static void transaction_merge_and_delete_job(Manager *m, Job *j, Job *other, JobType t) {
        JobDependency *l, *last;

        assert(j);
        assert(other);
        assert(j->name == other->name);
        assert(!j->linked);

        j->type = t;
        j->state = JOB_WAITING;

        j->matters_to_anchor = j->matters_to_anchor || other->matters_to_anchor;

        /* Patch us in as new owner of the JobDependency objects */
        last = NULL;
        for (l = other->subject_list; l; l = l->subject_next) {
                assert(l->subject == other);
                l->subject = j;
                last = l;
        }

        /* Merge both lists */
        if (last) {
                last->subject_next = j->subject_list;
                if (j->subject_list)
                        j->subject_list->subject_prev = last;
                j->subject_list = other->subject_list;
        }

        /* Patch us in as new owner of the JobDependency objects */
        last = NULL;
        for (l = other->object_list; l; l = l->object_next) {
                assert(l->object == other);
                l->object = j;
                last = l;
        }

        /* Merge both lists */
        if (last) {
                last->object_next = j->object_list;
                if (j->object_list)
                        j->object_list->object_prev = last;
                j->object_list = other->object_list;
        }

        /* Kill the other job */
        other->subject_list = NULL;
        other->object_list = NULL;
        transaction_delete_job(m, other);
}

static int transaction_merge_jobs(Manager *m) {
        Job *j;
        void *state;
        int r;

        assert(m);

        HASHMAP_FOREACH(j, m->transaction_jobs, state) {
                JobType t = j->type;
                Job *k;

                for (k = j->transaction_next; k; k = k->transaction_next)
                        if ((r = types_merge(&t, k->type)) < 0)
                                return r;

                while ((k = j->transaction_next)) {
                        if (j->linked) {
                                transaction_merge_and_delete_job(m, k, j, t);
                                j = k;
                        } else
                                transaction_merge_and_delete_job(m, j, k, t);
                }

                assert(!j->transaction_next);
                assert(!j->transaction_prev);
        }

        return 0;
}

static int transaction_verify_order_one(Manager *m, Job *j, Job *from, unsigned generation) {
        void *state;
        Name *n;
        int r;

        assert(m);
        assert(j);

        /* Did we find a cycle? */
        if (j->marker && j->generation == generation) {
                Job *k;

                /* So, we already have been here. We have a
                 * cycle. Let's try to break it. We go backwards in our
                 * path and try to find a suitable job to remove. */

                for (k = from; k; k = (k->generation == generation ? k->marker : NULL)) {
                        if (!k->matters_to_anchor) {
                                log_debug("Breaking order cycle by deleting job %s", name_id(k->name));
                                transaction_delete_job(m, k);
                                return -EAGAIN;
                        }

                        /* Check if this in fact was the beginning of
                         * the cycle */
                        if (k == j)
                                break;
                }

                return -ELOOP;
        }

        j->marker = from;
        j->generation = generation;

        /* We assume that the the dependencies are both-ways, and
         * hence can ignore NAME_AFTER */

        SET_FOREACH(n, j->name->meta.dependencies[NAME_BEFORE], state) {
                Job *o;

                if (!(o = hashmap_get(m->transaction_jobs, n)))
                        if (!(o = n->meta.job))
                                continue;

                if ((r = transaction_verify_order_one(m, o, j, generation)) < 0)
                        return r;
        }

        return 0;
}

static int transaction_verify_order(Manager *m, unsigned *generation) {
        bool again;
        assert(m);
        assert(generation);

        do {
                Job *j;
                int r;
                void *state;

                again = false;

                HASHMAP_FOREACH(j, m->transaction_jobs, state) {

                        /* Assume merged */
                        assert(!j->transaction_next);
                        assert(!j->transaction_prev);

                        if ((r = transaction_verify_order_one(m, j, NULL, (*generation)++)) < 0)  {

                                /* There was a cycleq, but it was fixed,
                                 * we need to restart our algorithm */
                                if (r == -EAGAIN) {
                                        again = true;
                                        break;
                                }

                                return r;
                        }
                }
        } while (again);

        return 0;
}

static void transaction_collect_garbage(Manager *m) {
        bool again;

        assert(m);

        do {
                void *state;
                Job *j;

                again = false;

                HASHMAP_FOREACH(j, m->transaction_jobs, state) {
                        if (j->object_list)
                                continue;

                        log_debug("Garbage collecting job %s", name_id(j->name));

                        transaction_delete_job(m, j);
                        again = true;
                        break;
                }

        } while (again);
}

static int transaction_is_destructive(Manager *m, JobMode mode) {
        void *state;
        Job *j;

        assert(m);

        /* Checks whether applying this transaction means that
         * existing jobs would be replaced */

        HASHMAP_FOREACH(j, m->transaction_jobs, state)
                if (j->name->meta.job && j->name->meta.job != j)
                        return -EEXIST;

        return 0;
}

static int transaction_apply(Manager *m, JobMode mode) {
        void *state;
        Job *j;
        int r;

        HASHMAP_FOREACH(j, m->transaction_jobs, state) {
                if (j->linked)
                        continue;

                if ((r = hashmap_put(m->jobs, UINT32_TO_PTR(j->id), j)) < 0)
                        goto rollback;
        }

        while ((j = hashmap_steal_first(m->transaction_jobs))) {
                if (j->linked)
                        continue;

                if (j->name->meta.job)
                        job_free(j->name->meta.job);

                j->name->meta.job = j;
                j->linked = true;

                /* We're fully installed. Now let's free data we don't
                 * need anymore. */

                assert(!j->transaction_next);
                assert(!j->transaction_prev);

                while (j->subject_list)
                        job_dependency_free(j->subject_list);
                while (j->object_list)
                        job_dependency_free(j->object_list);
        }

        return 0;

rollback:

        HASHMAP_FOREACH(j, m->transaction_jobs, state) {
                if (j->linked)
                        continue;

                hashmap_remove(m->jobs, UINT32_TO_PTR(j->id));
        }

        return r;
}


static int transaction_activate(Manager *m, JobMode mode) {
        int r;
        unsigned generation = 1;

        assert(m);

        /* This applies the changes recorded in transaction_jobs to
         * the actual list of jobs, if possible. */

        /* First step: figure out which jobs matter */
        transaction_find_jobs_that_matter_to_anchor(m, NULL, generation++);

        /* Second step: let's merge entries we can merge */
        if ((r = transaction_merge_jobs(m)) < 0)
                goto rollback;

        /* Third step: verify order makes sense */
        if ((r = transaction_verify_order(m, &generation)) < 0)
                goto rollback;

        /* Third step: do garbage colletion */
        transaction_collect_garbage(m);

        /* Fourth step: check whether we can actually apply this */
        if (mode == JOB_FAIL)
                if ((r = transaction_is_destructive(m, mode)) < 0)
                        goto rollback;

        /* Fifth step: apply changes */
        if ((r = transaction_apply(m, mode)) < 0)
                goto rollback;

        assert(hashmap_isempty(m->transaction_jobs));
        assert(!m->transaction_anchor);

        return 0;

rollback:
        transaction_abort(m);
        return r;
}

static Job* transaction_add_one_job(Manager *m, JobType type, Name *name, bool *is_new) {
        Job *j, *f;
        int r;

        assert(m);
        assert(name);

        /* Looks for an axisting prospective job and returns that. If
         * it doesn't exist it is created and added to the prospective
         * jobs list. */

        f = hashmap_get(m->transaction_jobs, name);

        for (j = f; j; j = j->transaction_next) {
                assert(j->name == name);

                if (j->type == type) {
                        if (is_new)
                                *is_new = false;
                        return j;
                }
        }

        if (name->meta.job && name->meta.job->type == type)
                j = name->meta.job;
        else if (!(j = job_new(m, type, name)))
                return NULL;

        if ((r = hashmap_replace(m->transaction_jobs, name, j)) < 0) {
                job_free(j);
                return NULL;
        }

        j->transaction_next = f;

        if (f)
                f->transaction_prev = j;

        j->generation = 0;
        j->marker = NULL;
        j->matters_to_anchor = false;

        if (is_new)
                *is_new = true;

        return j;
}

void manager_transaction_unlink_job(Manager *m, Job *j) {
        assert(m);
        assert(j);

        if (j->transaction_prev)
                j->transaction_prev->transaction_next = j->transaction_next;
        else if (j->transaction_next)
                hashmap_replace(m->transaction_jobs, j->name, j->transaction_next);
        else
                hashmap_remove_value(m->transaction_jobs, j->name, j);

        if (j->transaction_next)
                j->transaction_next->transaction_prev = j->transaction_prev;

        j->transaction_prev = j->transaction_next = NULL;

        while (j->subject_list)
                job_dependency_free(j->subject_list);

        while (j->object_list) {
                Job *other = j->object_list->matters ? j->object_list->subject : NULL;

                job_dependency_free(j->object_list);

                if (other) {
                        log_debug("Deleting job %s as dependency of job %s", name_id(other->name), name_id(j->name));
                        transaction_delete_job(m, other);
                }
        }
}

static int transaction_add_job_and_dependencies(Manager *m, JobType type, Name *name, Job *by, bool matters, bool force, Job **_ret) {
        Job *ret;
        void *state;
        Name *dep;
        int r;
        bool is_new;

        assert(m);
        assert(type < _JOB_TYPE_MAX);
        assert(name);

        if (name->meta.state != NAME_LOADED)
                return -EINVAL;

        /* First add the job. */
        if (!(ret = transaction_add_one_job(m, type, name, &is_new)))
                return -ENOMEM;

        /* Then, add a link to the job. */
        if (!job_dependency_new(by, ret, matters))
                return -ENOMEM;

        if (is_new) {
                /* Finally, recursively add in all dependencies. */
                if (type == JOB_START || type == JOB_RELOAD_OR_START) {
                        SET_FOREACH(dep, ret->name->meta.dependencies[NAME_REQUIRES], state)
                                if ((r = transaction_add_job_and_dependencies(m, JOB_START, dep, ret, true, force, NULL)) < 0)
                                        goto fail;
                        SET_FOREACH(dep, ret->name->meta.dependencies[NAME_SOFT_REQUIRES], state)
                                if ((r = transaction_add_job_and_dependencies(m, JOB_START, dep, ret, !force, force, NULL)) < 0)
                                        goto fail;
                        SET_FOREACH(dep, ret->name->meta.dependencies[NAME_WANTS], state)
                                if ((r = transaction_add_job_and_dependencies(m, JOB_START, dep, ret, false, force, NULL)) < 0)
                                        goto fail;
                        SET_FOREACH(dep, ret->name->meta.dependencies[NAME_REQUISITE], state)
                                if ((r = transaction_add_job_and_dependencies(m, JOB_VERIFY_STARTED, dep, ret, true, force, NULL)) < 0)
                                        goto fail;
                        SET_FOREACH(dep, ret->name->meta.dependencies[NAME_SOFT_REQUISITE], state)
                                if ((r = transaction_add_job_and_dependencies(m, JOB_VERIFY_STARTED, dep, ret, !force, force, NULL)) < 0)
                                        goto fail;
                        SET_FOREACH(dep, ret->name->meta.dependencies[NAME_CONFLICTS], state)
                                if ((r = transaction_add_job_and_dependencies(m, JOB_STOP, dep, ret, true, force, NULL)) < 0)
                                        goto fail;

                } else if (type == JOB_STOP || type == JOB_RESTART || type == JOB_TRY_RESTART) {

                        SET_FOREACH(dep, ret->name->meta.dependencies[NAME_REQUIRED_BY], state)
                                if ((r = transaction_add_job_and_dependencies(m, type, dep, ret, true, force, NULL)) < 0)
                                        goto fail;
                }

                /* JOB_VERIFY_STARTED, JOB_RELOAD require no dependency handling */
        }

        return 0;

fail:
        return r;
}

int manager_add_job(Manager *m, JobType type, Name *name, JobMode mode, bool force, Job **_ret) {
        int r;
        Job *ret;

        assert(m);
        assert(type < _JOB_TYPE_MAX);
        assert(name);
        assert(mode < _JOB_MODE_MAX);

        if ((r = transaction_add_job_and_dependencies(m, type, name, NULL, true, force, &ret))) {
                transaction_abort(m);
                return r;
        }

        if ((r = transaction_activate(m, mode)) < 0)
                return r;

        if (_ret)
                *_ret = ret;

        return 0;
}

Job *manager_get_job(Manager *m, uint32_t id) {
        assert(m);

        return hashmap_get(m->jobs, UINT32_TO_PTR(id));
}

Name *manager_get_name(Manager *m, const char *name) {
        assert(m);
        assert(name);

        return hashmap_get(m->names, name);
}

static int dispatch_load_queue(Manager *m) {
        Meta *meta;

        assert(m);

        /* Make sure we are not run recursively */
        if (m->dispatching_load_queue)
                return 0;

        m->dispatching_load_queue = true;

        /* Dispatches the load queue. Takes a name from the queue and
         * tries to load its data until the queue is empty */

        while ((meta = m->load_queue)) {
                name_load(NAME(meta));
                LIST_REMOVE(Meta, m->load_queue, meta);
        }

        m->dispatching_load_queue = false;

        return 0;
}

int manager_load_name(Manager *m, const char *name, Name **_ret) {
        Name *ret;
        NameType t;
        int r;
        char *n;

        assert(m);
        assert(name);
        assert(_ret);

        if (!name_is_valid(name))
                return -EINVAL;

        /* This will load the service information files, but not actually
         * start any services or anything */

        if ((ret = manager_get_name(m, name)))
                goto finish;

        if ((t = name_type_from_string(name)) == _NAME_TYPE_INVALID)
                return -EINVAL;

        if (!(ret = name_new(m)))
                return -ENOMEM;

        ret->meta.type = t;

        if (!(n = strdup(name))) {
                name_free(ret);
                return -ENOMEM;
        }

        if (set_put(ret->meta.names, n) < 0) {
                name_free(ret);
                free(n);
                return -ENOMEM;
        }

        if ((r = name_link(ret)) < 0) {
                name_free(ret);
                return r;
        }

        /* At this point the new entry is created and linked. However,
         * not loaded. Now load this entry and all its dependencies
         * recursively */

        dispatch_load_queue(m);

finish:

        *_ret = ret;
        return 0;
}

void manager_dump_jobs(Manager *s, FILE *f, const char *prefix) {
        void *state;
        Job *j;

        assert(s);
        assert(f);

        HASHMAP_FOREACH(j, s->jobs, state)
                job_dump(j, f, prefix);
}

void manager_dump_names(Manager *s, FILE *f, const char *prefix) {
        void *state;
        Name *n;
        const char *t;

        assert(s);
        assert(f);

        HASHMAP_FOREACH_KEY(n, t, s->names, state)
                if (name_id(n) == t)
                        name_dump(n, f, prefix);
}

void manager_clear_jobs(Manager *m) {
        Job *j;

        assert(m);

        transaction_abort(m);

        while ((j = hashmap_first(m->jobs)))
                job_free(j);
}
