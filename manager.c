/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/epoll.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/poll.h>

#include "manager.h"
#include "hashmap.h"
#include "macro.h"
#include "strv.h"
#include "log.h"
#include "util.h"

static int manager_setup_signals(Manager *m) {
        sigset_t mask;
        struct epoll_event ev;

        assert(m);

        assert_se(reset_all_signal_handlers() == 0);

        assert_se(sigemptyset(&mask) == 0);
        assert_se(sigaddset(&mask, SIGCHLD) == 0);
        assert_se(sigaddset(&mask, SIGINT) == 0);   /* Kernel sends us this on control-alt-del */
        assert_se(sigaddset(&mask, SIGWINCH) == 0); /* Kernel sends us this on kbrequest (alt-arrowup) */
        assert_se(sigaddset(&mask, SIGTERM) == 0);
        assert_se(sigaddset(&mask, SIGHUP) == 0);
        assert_se(sigaddset(&mask, SIGUSR1) == 0);
        assert_se(sigaddset(&mask, SIGUSR2) == 0);
        assert_se(sigaddset(&mask, SIGPIPE) == 0);
        assert_se(sigprocmask(SIG_SETMASK, &mask, NULL) == 0);

        m->signal_watch.type = WATCH_SIGNAL;
        if ((m->signal_watch.fd = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC)) < 0)
                return -errno;

        zero(ev);
        ev.events = EPOLLIN;
        ev.data.ptr = &m->signal_watch;

        if (epoll_ctl(m->epoll_fd, EPOLL_CTL_ADD, m->signal_watch.fd, &ev) < 0)
                return -errno;

        return 0;
}

Manager* manager_new(void) {
        Manager *m;

        if (!(m = new0(Manager, 1)))
                return NULL;

        m->signal_watch.fd = m->mount_watch.fd = m->udev_watch.fd = m->epoll_fd = -1;

        if (!(m->units = hashmap_new(string_hash_func, string_compare_func)))
                goto fail;

        if (!(m->jobs = hashmap_new(trivial_hash_func, trivial_compare_func)))
                goto fail;

        if (!(m->transaction_jobs = hashmap_new(trivial_hash_func, trivial_compare_func)))
                goto fail;

        if (!(m->watch_pids = hashmap_new(trivial_hash_func, trivial_compare_func)))
                goto fail;

        if ((m->epoll_fd = epoll_create1(EPOLL_CLOEXEC)) < 0)
                goto fail;

        if (manager_setup_signals(m) < 0)
                goto fail;

        return m;

fail:
        manager_free(m);
        return NULL;
}

void manager_free(Manager *m) {
        UnitType c;
        Unit *u;
        Job *j;

        assert(m);

        while ((j = hashmap_first(m->transaction_jobs)))
                job_free(j);

        while ((u = hashmap_first(m->units)))
                unit_free(u);

        for (c = 0; c < _UNIT_TYPE_MAX; c++)
                if (unit_vtable[c]->shutdown)
                        unit_vtable[c]->shutdown(m);

        hashmap_free(m->units);
        hashmap_free(m->jobs);
        hashmap_free(m->transaction_jobs);
        hashmap_free(m->watch_pids);

        if (m->epoll_fd >= 0)
                close_nointr(m->epoll_fd);
        if (m->signal_watch.fd >= 0)
                close_nointr(m->signal_watch.fd);

        free(m);
}

int manager_coldplug(Manager *m) {
        int r;
        UnitType c;
        Iterator i;
        Unit *u;
        char *k;

        assert(m);

        /* First, let's ask every type to load all units from
         * disk/kernel that it might know */
        for (c = 0; c < _UNIT_TYPE_MAX; c++)
                if (unit_vtable[c]->enumerate)
                        if ((r = unit_vtable[c]->enumerate(m)) < 0)
                                return r;

        manager_dispatch_load_queue(m);

        /* Then, let's set up their initial state. */
        HASHMAP_FOREACH_KEY(u, k, m->units, i) {

                /* ignore aliases */
                if (unit_id(u) != k)
                        continue;

                if (UNIT_VTABLE(u)->coldplug)
                        if ((r = UNIT_VTABLE(u)->coldplug(u)) < 0)
                                return r;
        }

        return 0;
}

static void transaction_delete_job(Manager *m, Job *j) {
        assert(m);
        assert(j);

        /* Deletes one job from the transaction */

        manager_transaction_unlink_job(m, j);

        if (!j->installed)
                job_free(j);
}

static void transaction_delete_unit(Manager *m, Unit *u) {
        Job *j;

        /* Deletes all jobs associated with a certain unit from the
         * transaction */

        while ((j = hashmap_get(m->transaction_jobs, u)))
                transaction_delete_job(m, j);
}

static void transaction_clean_dependencies(Manager *m) {
        Iterator i;
        Job *j;

        assert(m);

        /* Drops all dependencies of all installed jobs */

        HASHMAP_FOREACH(j, m->jobs, i) {
                while (j->subject_list)
                        job_dependency_free(j->subject_list);
                while (j->object_list)
                        job_dependency_free(j->object_list);
        }

        assert(!m->transaction_anchor);
}

static void transaction_abort(Manager *m) {
        Job *j;

        assert(m);

        while ((j = hashmap_first(m->transaction_jobs)))
                if (j->installed)
                        transaction_delete_job(m, j);
                else
                        job_free(j);

        assert(hashmap_isempty(m->transaction_jobs));

        transaction_clean_dependencies(m);
}

static void transaction_find_jobs_that_matter_to_anchor(Manager *m, Job *j, unsigned generation) {
        JobDependency *l;

        assert(m);

        /* A recursive sweep through the graph that marks all units
         * that matter to the anchor job, i.e. are directly or
         * indirectly a dependency of the anchor job via paths that
         * are fully marked as mattering. */

        if (j)
                l = j->subject_list;
        else
                l = m->transaction_anchor;

        LIST_FOREACH(subject, l, l) {

                /* This link does not matter */
                if (!l->matters)
                        continue;

                /* This unit has already been marked */
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
        assert(j->unit == other->unit);
        assert(!j->installed);

        /* Merges 'other' into 'j' and then deletes j. */

        j->type = t;
        j->state = JOB_WAITING;
        j->forced = j->forced || other->forced;

        j->matters_to_anchor = j->matters_to_anchor || other->matters_to_anchor;

        /* Patch us in as new owner of the JobDependency objects */
        last = NULL;
        LIST_FOREACH(subject, l, other->subject_list) {
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
        LIST_FOREACH(object, l, other->object_list) {
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
        LIST_FOREACH(transaction, j, j)
                LIST_FOREACH(transaction, k, j->transaction_next) {
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
                        log_debug("Try to fix job merging by deleting job %s/%s", unit_id(d->unit), job_type_to_string(d->type));
                        transaction_delete_job(m, d);
                        return 0;
                }

        return -EINVAL;
}

static int transaction_merge_jobs(Manager *m) {
        Job *j;
        Iterator i;
        int r;

        assert(m);

        /* First step, check whether any of the jobs for one specific
         * task conflict. If so, try to drop one of them. */
        HASHMAP_FOREACH(j, m->transaction_jobs, i) {
                JobType t;
                Job *k;

                t = j->type;
                LIST_FOREACH(transaction, k, j->transaction_next) {
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
        HASHMAP_FOREACH(j, m->transaction_jobs, i) {
                JobType t = j->type;
                Job *k;

                /* Merge all transactions */
                LIST_FOREACH(transaction, k, j->transaction_next)
                        assert_se(job_type_merge(&t, k->type) == 0);

                /* If an active job is mergeable, merge it too */
                if (j->unit->meta.job)
                        job_type_merge(&t, j->unit->meta.job->type); /* Might fail. Which is OK */

                while ((k = j->transaction_next)) {
                        if (j->installed) {
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

static bool unit_matters_to_anchor(Unit *u, Job *j) {
        assert(u);
        assert(!j->transaction_prev);

        /* Checks whether at least one of the jobs for this unit
         * matters to the anchor. */

        LIST_FOREACH(transaction, j, j)
                if (j->matters_to_anchor)
                        return true;

        return false;
}

static int transaction_verify_order_one(Manager *m, Job *j, Job *from, unsigned generation) {
        Iterator i;
        Unit *u;
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

                log_debug("Found cycle on %s/%s", unit_id(j->unit), job_type_to_string(j->type));

                for (k = from; k; k = (k->generation == generation ? k->marker : NULL)) {

                        log_debug("Walked on cycle path to %s/%s", unit_id(j->unit), job_type_to_string(j->type));

                        if (!k->installed &&
                            !unit_matters_to_anchor(k->unit, k)) {
                                /* Ok, we can drop this one, so let's
                                 * do so. */
                                log_debug("Breaking order cycle by deleting job %s/%s", unit_id(k->unit), job_type_to_string(k->type));
                                transaction_delete_unit(m, k->unit);
                                return -EAGAIN;
                        }

                        /* Check if this in fact was the beginning of
                         * the cycle */
                        if (k == j)
                                break;
                }

                log_debug("Unable to break cycle");

                return -ENOEXEC;
        }

        /* Make the marker point to where we come from, so that we can
         * find our way backwards if we want to break a cycle */
        j->marker = from;
        j->generation = generation;

        /* We assume that the the dependencies are bidirectional, and
         * hence can ignore UNIT_AFTER */
        SET_FOREACH(u, j->unit->meta.dependencies[UNIT_BEFORE], i) {
                Job *o;

                /* Is there a job for this unit? */
                if (!(o = hashmap_get(m->transaction_jobs, u)))

                        /* Ok, there is no job for this in the
                         * transaction, but maybe there is already one
                         * running? */
                        if (!(o = u->meta.job))
                                continue;

                if ((r = transaction_verify_order_one(m, o, j, generation)) < 0)
                        return r;
        }

        /* Ok, let's backtrack, and remember that this entry is not on
         * our path anymore. */
        j->marker = NULL;

        return 0;
}

static int transaction_verify_order(Manager *m, unsigned *generation) {
        Job *j;
        int r;
        Iterator i;

        assert(m);
        assert(generation);

        /* Check if the ordering graph is cyclic. If it is, try to fix
         * that up by dropping one of the jobs. */

        HASHMAP_FOREACH(j, m->transaction_jobs, i)
                if ((r = transaction_verify_order_one(m, j, NULL, (*generation)++)) < 0)
                        return r;

        return 0;
}

static void transaction_collect_garbage(Manager *m) {
        bool again;

        assert(m);

        /* Drop jobs that are not required by any other job */

        do {
                Iterator i;
                Job *j;

                again = false;

                HASHMAP_FOREACH(j, m->transaction_jobs, i) {
                        if (j->object_list)
                                continue;

                        log_debug("Garbage collecting job %s/%s", unit_id(j->unit), job_type_to_string(j->type));
                        transaction_delete_job(m, j);
                        again = true;
                        break;
                }

        } while (again);
}

static int transaction_is_destructive(Manager *m, JobMode mode) {
        Iterator i;
        Job *j;

        assert(m);

        /* Checks whether applying this transaction means that
         * existing jobs would be replaced */

        HASHMAP_FOREACH(j, m->transaction_jobs, i) {

                /* Assume merged */
                assert(!j->transaction_prev);
                assert(!j->transaction_next);

                if (j->unit->meta.job &&
                    j->unit->meta.job != j &&
                    !job_type_is_superset(j->type, j->unit->meta.job->type))
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
                Iterator i;

                again = false;

                HASHMAP_FOREACH(j, m->transaction_jobs, i) {
                        LIST_FOREACH(transaction, j, j) {
                                bool stops_running_service, changes_existing_job;

                                /* If it matters, we shouldn't drop it */
                                if (j->matters_to_anchor)
                                        continue;

                                /* Would this stop a running service?
                                 * Would this change an existing job?
                                 * If so, let's drop this entry */

                                stops_running_service =
                                        j->type == JOB_STOP && UNIT_IS_ACTIVE_OR_ACTIVATING(unit_active_state(j->unit));

                                changes_existing_job =
                                        j->unit->meta.job && job_type_is_conflicting(j->type, j->unit->meta.job->state);

                                if (!stops_running_service && !changes_existing_job)
                                        continue;

                                if (stops_running_service)
                                        log_debug("%s/%s would stop a running service.", unit_id(j->unit), job_type_to_string(j->type));

                                if (changes_existing_job)
                                        log_debug("%s/%s would change existing job.", unit_id(j->unit), job_type_to_string(j->type));

                                /* Ok, let's get rid of this */
                                log_debug("Deleting %s/%s to minimize impact.", unit_id(j->unit), job_type_to_string(j->type));

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
        Iterator i;
        Job *j;
        int r;

        /* Moves the transaction jobs to the set of active jobs */

        HASHMAP_FOREACH(j, m->transaction_jobs, i) {
                /* Assume merged */
                assert(!j->transaction_prev);
                assert(!j->transaction_next);

                if (j->installed)
                        continue;

                if ((r = hashmap_put(m->jobs, UINT32_TO_PTR(j->id), j)) < 0)
                        goto rollback;
        }

        while ((j = hashmap_steal_first(m->transaction_jobs))) {
                if (j->installed)
                        continue;

                if (j->unit->meta.job)
                        job_free(j->unit->meta.job);

                j->unit->meta.job = j;
                j->installed = true;

                /* We're fully installed. Now let's free data we don't
                 * need anymore. */

                assert(!j->transaction_next);
                assert(!j->transaction_prev);

                job_schedule_run(j);
        }

        /* As last step, kill all remaining job dependencies. */
        transaction_clean_dependencies(m);

        return 0;

rollback:

        HASHMAP_FOREACH(j, m->transaction_jobs, i) {
                if (j->installed)
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

                if (r != -EAGAIN) {
                        log_debug("Requested transaction contains an unfixable cyclic ordering dependency: %s", strerror(-r));
                        goto rollback;
                }

                /* Let's see if the resulting transaction ordering
                 * graph is still cyclic... */
        }

        for (;;) {
                /* Fifth step: let's drop unmergeable entries if
                 * necessary and possible, merge entries we can
                 * merge */
                if ((r = transaction_merge_jobs(m)) >= 0)
                        break;

                if (r != -EAGAIN) {
                        log_debug("Requested transaction contains unmergable jobs: %s", strerror(-r));
                        goto rollback;
                }

                /* Sixth step: an entry got dropped, let's garbage
                 * collect its dependencies. */
                transaction_collect_garbage(m);

                /* Let's see if the resulting transaction still has
                 * unmergeable entries ... */
        }

        /* Seventh step: check whether we can actually apply this */
        if (mode == JOB_FAIL)
                if ((r = transaction_is_destructive(m, mode)) < 0) {
                        log_debug("Requested transaction contradicts existing jobs: %s", strerror(-r));
                        goto rollback;
                }

        /* Eights step: apply changes */
        if ((r = transaction_apply(m, mode)) < 0) {
                log_debug("Failed to apply transaction: %s", strerror(-r));
                goto rollback;
        }

        assert(hashmap_isempty(m->transaction_jobs));
        assert(!m->transaction_anchor);

        return 0;

rollback:
        transaction_abort(m);
        return r;
}

static Job* transaction_add_one_job(Manager *m, JobType type, Unit *unit, bool force, bool *is_new) {
        Job *j, *f;
        int r;

        assert(m);
        assert(unit);

        /* Looks for an axisting prospective job and returns that. If
         * it doesn't exist it is created and added to the prospective
         * jobs list. */

        f = hashmap_get(m->transaction_jobs, unit);

        LIST_FOREACH(transaction, j, f) {
                assert(j->unit == unit);

                if (j->type == type) {
                        if (is_new)
                                *is_new = false;
                        return j;
                }
        }

        if (unit->meta.job && unit->meta.job->type == type)
                j = unit->meta.job;
        else if (!(j = job_new(m, type, unit)))
                return NULL;

        j->generation = 0;
        j->marker = NULL;
        j->matters_to_anchor = false;
        j->forced = force;

        LIST_PREPEND(Job, transaction, f, j);

        if ((r = hashmap_replace(m->transaction_jobs, unit, f)) < 0) {
                job_free(j);
                return NULL;
        }

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
                hashmap_replace(m->transaction_jobs, j->unit, j->transaction_next);
        else
                hashmap_remove_value(m->transaction_jobs, j->unit, j);

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
                                  unit_id(other->unit), job_type_to_string(other->type),
                                  unit_id(j->unit), job_type_to_string(j->type));
                        transaction_delete_job(m, other);
                }
        }
}

static int transaction_add_job_and_dependencies(Manager *m, JobType type, Unit *unit, Job *by, bool matters, bool force, Job **_ret) {
        Job *ret;
        Iterator i;
        Unit *dep;
        int r;
        bool is_new;

        assert(m);
        assert(type < _JOB_TYPE_MAX);
        assert(unit);

        if (unit->meta.load_state != UNIT_LOADED)
                return -EINVAL;

        if (!unit_job_is_applicable(unit, type))
                return -EBADR;

        /* First add the job. */
        if (!(ret = transaction_add_one_job(m, type, unit, force, &is_new)))
                return -ENOMEM;

        /* Then, add a link to the job. */
        if (!job_dependency_new(by, ret, matters))
                return -ENOMEM;

        if (is_new) {
                /* Finally, recursively add in all dependencies. */
                if (type == JOB_START || type == JOB_RELOAD_OR_START) {
                        SET_FOREACH(dep, ret->unit->meta.dependencies[UNIT_REQUIRES], i)
                                if ((r = transaction_add_job_and_dependencies(m, JOB_START, dep, ret, true, force, NULL)) < 0 && r != -EBADR)
                                        goto fail;
                        SET_FOREACH(dep, ret->unit->meta.dependencies[UNIT_SOFT_REQUIRES], i)
                                if ((r = transaction_add_job_and_dependencies(m, JOB_START, dep, ret, !force, force, NULL)) < 0 && r != -EBADR)
                                        goto fail;
                        SET_FOREACH(dep, ret->unit->meta.dependencies[UNIT_WANTS], i)
                                if ((r = transaction_add_job_and_dependencies(m, JOB_START, dep, ret, false, force, NULL)) < 0 && r != -EBADR)
                                        goto fail;
                        SET_FOREACH(dep, ret->unit->meta.dependencies[UNIT_REQUISITE], i)
                                if ((r = transaction_add_job_and_dependencies(m, JOB_VERIFY_ACTIVE, dep, ret, true, force, NULL)) < 0 && r != -EBADR)
                                        goto fail;
                        SET_FOREACH(dep, ret->unit->meta.dependencies[UNIT_SOFT_REQUISITE], i)
                                if ((r = transaction_add_job_and_dependencies(m, JOB_VERIFY_ACTIVE, dep, ret, !force, force, NULL)) < 0 && r != -EBADR)
                                        goto fail;
                        SET_FOREACH(dep, ret->unit->meta.dependencies[UNIT_CONFLICTS], i)
                                if ((r = transaction_add_job_and_dependencies(m, JOB_STOP, dep, ret, true, force, NULL)) < 0 && r != -EBADR)
                                        goto fail;

                } else if (type == JOB_STOP || type == JOB_RESTART || type == JOB_TRY_RESTART) {

                        SET_FOREACH(dep, ret->unit->meta.dependencies[UNIT_REQUIRED_BY], i)
                                if ((r = transaction_add_job_and_dependencies(m, type, dep, ret, true, force, NULL)) < 0 && r != -EBADR)
                                        goto fail;
                }

                /* JOB_VERIFY_STARTED, JOB_RELOAD require no dependency handling */
        }

        return 0;

fail:
        return r;
}

int manager_add_job(Manager *m, JobType type, Unit *unit, JobMode mode, bool force, Job **_ret) {
        int r;
        Job *ret;

        assert(m);
        assert(type < _JOB_TYPE_MAX);
        assert(unit);
        assert(mode < _JOB_MODE_MAX);

        log_debug("Trying to enqueue job %s/%s", unit_id(unit), job_type_to_string(type));

        if ((r = transaction_add_job_and_dependencies(m, type, unit, NULL, true, force, &ret))) {
                transaction_abort(m);
                return r;
        }

        if ((r = transaction_activate(m, mode)) < 0)
                return r;

        log_debug("Enqueued job %s/%s", unit_id(unit), job_type_to_string(type));

        if (_ret)
                *_ret = ret;

        return 0;
}

Job *manager_get_job(Manager *m, uint32_t id) {
        assert(m);

        return hashmap_get(m->jobs, UINT32_TO_PTR(id));
}

Unit *manager_get_unit(Manager *m, const char *name) {
        assert(m);
        assert(name);

        return hashmap_get(m->units, name);
}

void manager_dispatch_load_queue(Manager *m) {
        Meta *meta;

        assert(m);

        /* Make sure we are not run recursively */
        if (m->dispatching_load_queue)
                return;

        m->dispatching_load_queue = true;

        /* Dispatches the load queue. Takes a unit from the queue and
         * tries to load its data until the queue is empty */

        while ((meta = m->load_queue)) {
                assert(meta->in_load_queue);

                unit_load(UNIT(meta));
        }

        m->dispatching_load_queue = false;
}

int manager_load_unit(Manager *m, const char *path, Unit **_ret) {
        Unit *ret;
        int r;
        const char *name;

        assert(m);
        assert(path);
        assert(_ret);

        /* This will load the service information files, but not actually
         * start any services or anything. */

        name = file_name_from_path(path);

        if ((ret = manager_get_unit(m, name))) {
                *_ret = ret;
                return 0;
        }

        if (!(ret = unit_new(m)))
                return -ENOMEM;

        if (is_path(path)) {
                if (!(ret->meta.load_path = strdup(path))) {
                        unit_free(ret);
                        return -ENOMEM;
                }
        }

        if ((r = unit_add_name(ret, name)) < 0) {
                unit_free(ret);
                return r;
        }

        unit_add_to_load_queue(ret);
        manager_dispatch_load_queue(m);

        *_ret = ret;
        return 0;
}

void manager_dump_jobs(Manager *s, FILE *f, const char *prefix) {
        Iterator i;
        Job *j;

        assert(s);
        assert(f);

        HASHMAP_FOREACH(j, s->jobs, i)
                job_dump(j, f, prefix);
}

void manager_dump_units(Manager *s, FILE *f, const char *prefix) {
        Iterator i;
        Unit *u;
        const char *t;

        assert(s);
        assert(f);

        HASHMAP_FOREACH_KEY(u, t, s->units, i)
                if (unit_id(u) == t)
                        unit_dump(u, f, prefix);
}

void manager_clear_jobs(Manager *m) {
        Job *j;

        assert(m);

        transaction_abort(m);

        while ((j = hashmap_first(m->jobs)))
                job_free(j);
}

void manager_dispatch_run_queue(Manager *m) {
        Job *j;

        if (m->dispatching_run_queue)
                return;

        m->dispatching_run_queue = true;

        while ((j = m->run_queue)) {
                assert(j->installed);
                assert(j->in_run_queue);

                job_run_and_invalidate(j);
        }

        m->dispatching_run_queue = false;
}

static int manager_dispatch_sigchld(Manager *m) {
        assert(m);

        log_debug("dispatching SIGCHLD");

        for (;;) {
                siginfo_t si;
                Unit *u;

                zero(si);
                if (waitid(P_ALL, 0, &si, WEXITED|WNOHANG) < 0) {

                        if (errno == ECHILD)
                                break;

                        return -errno;
                }

                if (si.si_pid == 0)
                        break;

                if (si.si_code != CLD_EXITED && si.si_code != CLD_KILLED && si.si_code != CLD_DUMPED)
                        continue;

                log_debug("child %llu died (code=%s, status=%i)", (long long unsigned) si.si_pid, sigchld_code(si.si_code), si.si_status);

                if (!(u = hashmap_remove(m->watch_pids, UINT32_TO_PTR(si.si_pid))))
                        continue;

                UNIT_VTABLE(u)->sigchld_event(u, si.si_pid, si.si_code, si.si_status);
        }

        return 0;
}

static int manager_process_signal_fd(Manager *m, bool *quit) {
        ssize_t n;
        struct signalfd_siginfo sfsi;
        bool sigchld = false;

        assert(m);

        for (;;) {
                if ((n = read(m->signal_watch.fd, &sfsi, sizeof(sfsi))) != sizeof(sfsi)) {

                        if (n >= 0)
                                return -EIO;

                        if (errno == EAGAIN)
                                break;

                        return -errno;
                }

                switch (sfsi.ssi_signo) {

                case SIGCHLD:
                        sigchld = true;
                        break;

                case SIGINT:
                case SIGTERM:
                        *quit = true;
                        return 0;

                default:
                        log_info("Got unhandled signal <%s>.", strsignal(sfsi.ssi_signo));
                }
        }

        if (sigchld)
                return manager_dispatch_sigchld(m);

        return 0;
}

static int process_event(Manager *m, struct epoll_event *ev, bool *quit) {
        int r;
        Watch *w;

        assert(m);
        assert(ev);

        assert(w = ev->data.ptr);

        switch (w->type) {

        case WATCH_SIGNAL:

                /* An incoming signal? */
                if (ev->events != EPOLLIN)
                        return -EINVAL;

                if ((r = manager_process_signal_fd(m, quit)) < 0)
                        return r;

                break;

        case WATCH_FD:

                /* Some fd event, to be dispatched to the units */
                UNIT_VTABLE(w->unit)->fd_event(w->unit, w->fd, ev->events, w);
                break;

        case WATCH_TIMER: {
                uint64_t v;
                ssize_t k;

                /* Some timer event, to be dispatched to the units */
                if ((k = read(ev->data.fd, &v, sizeof(v))) != sizeof(v)) {

                        if (k < 0 && (errno == EINTR || errno == EAGAIN))
                                break;

                        return k < 0 ? -errno : -EIO;
                }

                UNIT_VTABLE(w->unit)->timer_event(w->unit, v, w);
                break;
        }

        case WATCH_MOUNT:
                /* Some mount table change, intended for the mount subsystem */
                mount_fd_event(m, ev->events);
                break;

        case WATCH_UDEV:
                /* Some notification from udev, intended for the device subsystem */
                device_fd_event(m, ev->events);
                break;

        default:
                assert_not_reached("Unknown epoll event type.");
        }

        return 0;
}

int manager_loop(Manager *m) {
        int r;
        bool quit = false;

        assert(m);

        for (;;) {
                struct epoll_event event;
                int n;

                manager_dispatch_run_queue(m);

                if ((n = epoll_wait(m->epoll_fd, &event, 1, -1)) < 0) {

                        if (errno == -EINTR)
                                continue;

                        return -errno;
                }

                assert(n == 1);

                if ((r = process_event(m, &event, &quit)) < 0)
                        return r;

                if (quit)
                        return 0;
        }
}
