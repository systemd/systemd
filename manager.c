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

        /* Deletes one job from the transaction */

        manager_transaction_unlink_job(m, j);

        if (!j->linked)
                job_free(j);
}

static void transaction_delete_name(Manager *m, Name *n) {
        Job *j;

        /* Deletes all jobs associated with a certain name from the
         * transaction */

        while ((j = hashmap_get(m->transaction_jobs, n)))
                transaction_delete_job(m, j);
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

        /* A recursive sweep through the graph that marks all names
         * that matter to the anchor job, i.e. are directly or
         * indirectly a dependency of the anchor job via paths that
         * are fully marked as mattering. */

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

static void transaction_merge_and_delete_job(Manager *m, Job *j, Job *other, JobType t) {
        JobDependency *l, *last;

        assert(j);
        assert(other);
        assert(j->name == other->name);
        assert(!j->linked);

        /* Merges 'other' into 'j' and then deletes j. */

        j->type = t;
        j->state = JOB_WAITING;
        j->forced = j->forced || other->forced;

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

static int delete_one_unmergeable_job(Manager *m, Job *j) {
        Job *k;

        assert(j);

        /* Tries to delete one item in the linked list
         * j->transaction_next->transaction_next->... that conflicts
         * whith another one, in an attempt to make an inconsistent
         * transaction work. */

        /* We rely here on the fact that if a merged with b does not
         * merge with c, either a or b merge with c neither */
        for (; j; j = j->transaction_next)
                for (k = j->transaction_next; k; k = k->transaction_next) {
                        Job *d;

                        /* Is this one mergeable? Then skip it */
                        if (job_type_is_mergeable(j->type, k->type))
                                continue;

                        /* Ok, we found two that conflict, let's see if we can
                         * drop one of them */
                        if (!j->matters_to_anchor)
                                d = j;
                        else if (!k->matters_to_anchor)
                                d = k;
                        else
                                return -ENOEXEC;

                        /* Ok, we can drop one, so let's do so. */
                        log_debug("Try to fix job merging by deleting job %s/%s", name_id(d->name), job_type_to_string(d->type));
                        transaction_delete_job(m, d);
                        return 0;
                }

        return -EINVAL;
}

static int transaction_merge_jobs(Manager *m) {
        Job *j;
        void *state;
        int r;

        assert(m);

        /* First step, check whether any of the jobs for one specific
         * task conflict. If so, try to drop one of them. */
        HASHMAP_FOREACH(j, m->transaction_jobs, state) {
                JobType t;
                Job *k;

                t = j->type;
                for (k = j->transaction_next; k; k = k->transaction_next) {
                        if ((r = job_type_merge(&t, k->type)) >= 0)
                                continue;

                        /* OK, we could not merge all jobs for this
                         * action. Let's see if we can get rid of one
                         * of them */

                        if ((r = delete_one_unmergeable_job(m, j)) >= 0)
                                /* Ok, we managed to drop one, now
                                 * let's ask our callers to call us
                                 * again after garbage collecting */
                                return -EAGAIN;

                        /* We couldn't merge anything. Failure */
                        return r;
                }
        }

        /* Second step, merge the jobs. */
        HASHMAP_FOREACH(j, m->transaction_jobs, state) {
                JobType t = j->type;
                Job *k;

                /* Merge all transactions */
                for (k = j->transaction_next; k; k = k->transaction_next)
                        assert_se(job_type_merge(&t, k->type) == 0);

                /* If an active job is mergeable, merge it too */
                if (j->name->meta.job)
                        job_type_merge(&t, j->name->meta.job->type); /* Might fail. Which is OK */

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

static bool name_matters_to_anchor(Name *n, Job *j) {
        assert(n);
        assert(!j->transaction_prev);

        /* Checks whether at least one of the jobs for this name
         * matters to the anchor. */

        for (; j; j = j->transaction_next)
                if (j->matters_to_anchor)
                        return true;

        return false;
}

static int transaction_verify_order_one(Manager *m, Job *j, Job *from, unsigned generation) {
        void *state;
        Name *n;
        int r;

        assert(m);
        assert(j);
        assert(!j->transaction_prev);

        /* Does a recursive sweep through the ordering graph, looking
         * for a cycle. If we find cycle we try to break it. */

        /* Did we find a cycle? */
        if (j->marker && j->generation == generation) {
                Job *k;

                /* So, we already have been here. We have a
                 * cycle. Let's try to break it. We go backwards in
                 * our path and try to find a suitable job to
                 * remove. We use the marker to find our way back,
                 * since smart how we are we stored our way back in
                 * there. */

                for (k = from; k; k = (k->generation == generation ? k->marker : NULL)) {

                        if (!k->linked &&
                            !name_matters_to_anchor(k->name, k)) {
                                /* Ok, we can drop this one, so let's
                                 * do so. */
                                log_debug("Breaking order cycle by deleting job %s/%s", name_id(k->name), job_type_to_string(k->type));
                                transaction_delete_name(m, k->name);
                                return -EAGAIN;
                        }

                        /* Check if this in fact was the beginning of
                         * the cycle */
                        if (k == j)
                                break;
                }

                return -ENOEXEC;
        }

        /* Make the marker point to where we come from, so that we can
         * find our way backwards if we want to break a cycle */
        j->marker = from;
        j->generation = generation;

        /* We assume that the the dependencies are bidirectional, and
         * hence can ignore NAME_AFTER */
        SET_FOREACH(n, j->name->meta.dependencies[NAME_BEFORE], state) {
                Job *o;

                /* Is there a job for this name? */
                if (!(o = hashmap_get(m->transaction_jobs, n)))

                        /* Ok, there is no job for this in the
                         * transaction, but maybe there is already one
                         * running? */
                        if (!(o = n->meta.job))
                                continue;

                if ((r = transaction_verify_order_one(m, o, j, generation)) < 0)
                        return r;
        }

        return 0;
}

static int transaction_verify_order(Manager *m, unsigned *generation) {
        Job *j;
        int r;
        void *state;

        assert(m);
        assert(generation);

        /* Check if the ordering graph is cyclic. If it is, try to fix
         * that up by dropping one of the jobs. */

        HASHMAP_FOREACH(j, m->transaction_jobs, state)
                if ((r = transaction_verify_order_one(m, j, NULL, (*generation)++)) < 0)
                        return r;

        return 0;
}

static void transaction_collect_garbage(Manager *m) {
        bool again;

        assert(m);

        /* Drop jobs that are not required by any other job */

        do {
                void *state;
                Job *j;

                again = false;

                HASHMAP_FOREACH(j, m->transaction_jobs, state) {
                        if (j->object_list)
                                continue;

                        log_debug("Garbage collecting job %s/%s", name_id(j->name), job_type_to_string(j->type));
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

        HASHMAP_FOREACH(j, m->transaction_jobs, state) {

                /* Assume merged */
                assert(!j->transaction_prev);
                assert(!j->transaction_next);

                if (j->name->meta.job &&
                    j->name->meta.job != j &&
                    !job_type_is_superset(j->type, j->name->meta.job->type))
                        return -EEXIST;
        }

        return 0;
}

static void transaction_minimize_impact(Manager *m) {
        bool again;
        assert(m);

        /* Drops all unnecessary jobs that reverse already active jobs
         * or that stop a running service. */

        do {
                Job *j;
                void *state;

                again = false;

                HASHMAP_FOREACH(j, m->transaction_jobs, state) {
                        for (; j; j = j->transaction_next) {

                                /* If it matters, we shouldn't drop it */
                                if (j->matters_to_anchor)
                                        continue;

                                /* Would this stop a running service?
                                 * Would this change an existing job?
                                 * If so, let's drop this entry */
                                if ((j->type != JOB_STOP || NAME_IS_INACTIVE_OR_DEACTIVATING(name_active_state(j->name))) &&
                                    (!j->name->meta.job  || job_type_is_conflicting(j->type, j->name->meta.job->state)))
                                        continue;

                                /* Ok, let's get rid of this */
                                log_debug("Deleting %s/%s to minimize impact", name_id(j->name), job_type_to_string(j->type));
                                transaction_delete_job(m, j);
                                again = true;
                                break;
                        }

                        if (again)
                                break;
                }

        } while (again);
}

static int transaction_apply(Manager *m, JobMode mode) {
        void *state;
        Job *j;
        int r;

        /* Moves the transaction jobs to the set of active jobs */

        HASHMAP_FOREACH(j, m->transaction_jobs, state) {
                /* Assume merged */
                assert(!j->transaction_prev);
                assert(!j->transaction_next);

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

        m->transaction_anchor = NULL;

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

        /* Second step: Try not to stop any running services if
         * we don't have to. Don't try to reverse running
         * jobs if we don't have to. */
        transaction_minimize_impact(m);

        for (;;) {
                /* Third step: Let's remove unneeded jobs that might
                 * be lurking. */
                transaction_collect_garbage(m);

                /* Fourth step: verify order makes sense and correct
                 * cycles if necessary and possible */
                if ((r = transaction_verify_order(m, &generation)) >= 0)
                        break;

                if (r != -EAGAIN)
                        goto rollback;

                /* Let's see if the resulting transaction ordering
                 * graph is still cyclic... */
        }

        for (;;) {
                /* Fifth step: let's drop unmergeable entries if
                 * necessary and possible, merge entries we can
                 * merge */
                if ((r = transaction_merge_jobs(m)) >= 0)
                        break;

                if (r != -EAGAIN)
                        goto rollback;

                /* Sixth step: an entry got dropped, let's garbage
                 * collect its dependencies. */
                transaction_collect_garbage(m);

                /* Let's see if the resulting transaction still has
                 * unmergeable entries ... */
        }

        /* Seventh step: check whether we can actually apply this */
        if (mode == JOB_FAIL)
                if ((r = transaction_is_destructive(m, mode)) < 0)
                        goto rollback;

        /* Eights step: apply changes */
        if ((r = transaction_apply(m, mode)) < 0)
                goto rollback;

        assert(hashmap_isempty(m->transaction_jobs));
        assert(!m->transaction_anchor);

        return 0;

rollback:
        transaction_abort(m);
        return r;
}

static Job* transaction_add_one_job(Manager *m, JobType type, Name *name, bool force, bool *is_new) {
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
        j->forced = force;

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
                        log_debug("Deleting job %s/%s as dependency of job %s/%s",
                                  name_id(other->name), job_type_to_string(other->type),
                                  name_id(j->name), job_type_to_string(j->type));
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

        if (name->meta.load_state != NAME_LOADED)
                return -EINVAL;

        if (!job_type_is_applicable(type, name->meta.type))
                return -EBADR;

        /* First add the job. */
        if (!(ret = transaction_add_one_job(m, type, name, force, &is_new)))
                return -ENOMEM;

        /* Then, add a link to the job. */
        if (!job_dependency_new(by, ret, matters))
                return -ENOMEM;

        if (is_new) {
                /* Finally, recursively add in all dependencies. */
                if (type == JOB_START || type == JOB_RELOAD_OR_START) {
                        SET_FOREACH(dep, ret->name->meta.dependencies[NAME_REQUIRES], state)
                                if ((r = transaction_add_job_and_dependencies(m, JOB_START, dep, ret, true, force, NULL)) < 0 && r != -EBADR)
                                        goto fail;
                        SET_FOREACH(dep, ret->name->meta.dependencies[NAME_SOFT_REQUIRES], state)
                                if ((r = transaction_add_job_and_dependencies(m, JOB_START, dep, ret, !force, force, NULL)) < 0 && r != -EBADR)
                                        goto fail;
                        SET_FOREACH(dep, ret->name->meta.dependencies[NAME_WANTS], state)
                                if ((r = transaction_add_job_and_dependencies(m, JOB_START, dep, ret, false, force, NULL)) < 0 && r != -EBADR)
                                        goto fail;
                        SET_FOREACH(dep, ret->name->meta.dependencies[NAME_REQUISITE], state)
                                if ((r = transaction_add_job_and_dependencies(m, JOB_VERIFY_ACTIVE, dep, ret, true, force, NULL)) < 0 && r != -EBADR)
                                        goto fail;
                        SET_FOREACH(dep, ret->name->meta.dependencies[NAME_SOFT_REQUISITE], state)
                                if ((r = transaction_add_job_and_dependencies(m, JOB_VERIFY_ACTIVE, dep, ret, !force, force, NULL)) < 0 && r != -EBADR)
                                        goto fail;
                        SET_FOREACH(dep, ret->name->meta.dependencies[NAME_CONFLICTS], state)
                                if ((r = transaction_add_job_and_dependencies(m, JOB_STOP, dep, ret, true, force, NULL)) < 0 && r != -EBADR)
                                        goto fail;

                } else if (type == JOB_STOP || type == JOB_RESTART || type == JOB_TRY_RESTART) {

                        SET_FOREACH(dep, ret->name->meta.dependencies[NAME_REQUIRED_BY], state)
                                if ((r = transaction_add_job_and_dependencies(m, type, dep, ret, true, force, NULL)) < 0 && r != -EBADR)
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

        if ((r = set_put(ret->meta.names, n)) < 0) {
                name_free(ret);
                free(n);
                return r;
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
