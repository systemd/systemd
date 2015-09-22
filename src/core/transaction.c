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

#include <unistd.h>
#include <fcntl.h>

#include "bus-common-errors.h"
#include "bus-error.h"
#include "transaction.h"
#include "terminal-util.h"

static void transaction_unlink_job(Transaction *tr, Job *j, bool delete_dependencies);

static void transaction_delete_job(Transaction *tr, Job *j, bool delete_dependencies) {
        assert(tr);
        assert(j);

        /* Deletes one job from the transaction */

        transaction_unlink_job(tr, j, delete_dependencies);

        job_free(j);
}

static void transaction_delete_unit(Transaction *tr, Unit *u) {
        Job *j;

        /* Deletes all jobs associated with a certain unit from the
         * transaction */

        while ((j = hashmap_get(tr->jobs, u)))
                transaction_delete_job(tr, j, true);
}

void transaction_abort(Transaction *tr) {
        Job *j;

        assert(tr);

        while ((j = hashmap_first(tr->jobs)))
                transaction_delete_job(tr, j, false);

        assert(hashmap_isempty(tr->jobs));
}

static void transaction_find_jobs_that_matter_to_anchor(Job *j, unsigned generation) {
        JobDependency *l;

        /* A recursive sweep through the graph that marks all units
         * that matter to the anchor job, i.e. are directly or
         * indirectly a dependency of the anchor job via paths that
         * are fully marked as mattering. */

        j->matters_to_anchor = true;
        j->generation = generation;

        LIST_FOREACH(subject, l, j->subject_list) {

                /* This link does not matter */
                if (!l->matters)
                        continue;

                /* This unit has already been marked */
                if (l->object->generation == generation)
                        continue;

                transaction_find_jobs_that_matter_to_anchor(l->object, generation);
        }
}

static void transaction_merge_and_delete_job(Transaction *tr, Job *j, Job *other, JobType t) {
        JobDependency *l, *last;

        assert(j);
        assert(other);
        assert(j->unit == other->unit);
        assert(!j->installed);

        /* Merges 'other' into 'j' and then deletes 'other'. */

        j->type = t;
        j->state = JOB_WAITING;
        j->override = j->override || other->override;
        j->irreversible = j->irreversible || other->irreversible;

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
        transaction_delete_job(tr, other, true);
}

_pure_ static bool job_is_conflicted_by(Job *j) {
        JobDependency *l;

        assert(j);

        /* Returns true if this job is pulled in by a least one
         * ConflictedBy dependency. */

        LIST_FOREACH(object, l, j->object_list)
                if (l->conflicts)
                        return true;

        return false;
}

static int delete_one_unmergeable_job(Transaction *tr, Job *j) {
        Job *k;

        assert(j);

        /* Tries to delete one item in the linked list
         * j->transaction_next->transaction_next->... that conflicts
         * with another one, in an attempt to make an inconsistent
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
                        if (!j->matters_to_anchor && !k->matters_to_anchor) {

                                /* Both jobs don't matter, so let's
                                 * find the one that is smarter to
                                 * remove. Let's think positive and
                                 * rather remove stops then starts --
                                 * except if something is being
                                 * stopped because it is conflicted by
                                 * another unit in which case we
                                 * rather remove the start. */

                                log_unit_debug(j->unit,
                                               "Looking at job %s/%s conflicted_by=%s",
                                               j->unit->id, job_type_to_string(j->type),
                                               yes_no(j->type == JOB_STOP && job_is_conflicted_by(j)));
                                log_unit_debug(k->unit,
                                               "Looking at job %s/%s conflicted_by=%s",
                                               k->unit->id, job_type_to_string(k->type),
                                               yes_no(k->type == JOB_STOP && job_is_conflicted_by(k)));

                                if (j->type == JOB_STOP) {

                                        if (job_is_conflicted_by(j))
                                                d = k;
                                        else
                                                d = j;

                                } else if (k->type == JOB_STOP) {

                                        if (job_is_conflicted_by(k))
                                                d = j;
                                        else
                                                d = k;
                                } else
                                        d = j;

                        } else if (!j->matters_to_anchor)
                                d = j;
                        else if (!k->matters_to_anchor)
                                d = k;
                        else
                                return -ENOEXEC;

                        /* Ok, we can drop one, so let's do so. */
                        log_unit_debug(d->unit,
                                       "Fixing conflicting jobs %s/%s,%s/%s by deleting job %s/%s",
                                       j->unit->id, job_type_to_string(j->type),
                                       k->unit->id, job_type_to_string(k->type),
                                       d->unit->id, job_type_to_string(d->type));
                        transaction_delete_job(tr, d, true);
                        return 0;
                }

        return -EINVAL;
}

static int transaction_merge_jobs(Transaction *tr, sd_bus_error *e) {
        Job *j;
        Iterator i;
        int r;

        assert(tr);

        /* First step, check whether any of the jobs for one specific
         * task conflict. If so, try to drop one of them. */
        HASHMAP_FOREACH(j, tr->jobs, i) {
                JobType t;
                Job *k;

                t = j->type;
                LIST_FOREACH(transaction, k, j->transaction_next) {
                        if (job_type_merge_and_collapse(&t, k->type, j->unit) >= 0)
                                continue;

                        /* OK, we could not merge all jobs for this
                         * action. Let's see if we can get rid of one
                         * of them */

                        r = delete_one_unmergeable_job(tr, j);
                        if (r >= 0)
                                /* Ok, we managed to drop one, now
                                 * let's ask our callers to call us
                                 * again after garbage collecting */
                                return -EAGAIN;

                        /* We couldn't merge anything. Failure */
                        return sd_bus_error_setf(e, BUS_ERROR_TRANSACTION_JOBS_CONFLICTING,
                                                 "Transaction contains conflicting jobs '%s' and '%s' for %s. "
                                                 "Probably contradicting requirement dependencies configured.",
                                                 job_type_to_string(t),
                                                 job_type_to_string(k->type),
                                                 k->unit->id);
                }
        }

        /* Second step, merge the jobs. */
        HASHMAP_FOREACH(j, tr->jobs, i) {
                JobType t = j->type;
                Job *k;

                /* Merge all transaction jobs for j->unit */
                LIST_FOREACH(transaction, k, j->transaction_next)
                        assert_se(job_type_merge_and_collapse(&t, k->type, j->unit) == 0);

                while ((k = j->transaction_next)) {
                        if (tr->anchor_job == k) {
                                transaction_merge_and_delete_job(tr, k, j, t);
                                j = k;
                        } else
                                transaction_merge_and_delete_job(tr, j, k, t);
                }

                assert(!j->transaction_next);
                assert(!j->transaction_prev);
        }

        return 0;
}

static void transaction_drop_redundant(Transaction *tr) {
        Job *j;
        Iterator i;

        /* Goes through the transaction and removes all jobs of the units
         * whose jobs are all noops. If not all of a unit's jobs are
         * redundant, they are kept. */

        assert(tr);

rescan:
        HASHMAP_FOREACH(j, tr->jobs, i) {
                Job *k;

                LIST_FOREACH(transaction, k, j) {

                        if (tr->anchor_job == k ||
                            !job_type_is_redundant(k->type, unit_active_state(k->unit)) ||
                            (k->unit->job && job_type_is_conflicting(k->type, k->unit->job->type)))
                                goto next_unit;
                }

                /* log_debug("Found redundant job %s/%s, dropping.", j->unit->id, job_type_to_string(j->type)); */
                transaction_delete_job(tr, j, false);
                goto rescan;
        next_unit:;
        }
}

_pure_ static bool unit_matters_to_anchor(Unit *u, Job *j) {
        assert(u);
        assert(!j->transaction_prev);

        /* Checks whether at least one of the jobs for this unit
         * matters to the anchor. */

        LIST_FOREACH(transaction, j, j)
                if (j->matters_to_anchor)
                        return true;

        return false;
}

static int transaction_verify_order_one(Transaction *tr, Job *j, Job *from, unsigned generation, sd_bus_error *e) {
        Iterator i;
        Unit *u;
        int r;

        assert(tr);
        assert(j);
        assert(!j->transaction_prev);

        /* Does a recursive sweep through the ordering graph, looking
         * for a cycle. If we find a cycle we try to break it. */

        /* Have we seen this before? */
        if (j->generation == generation) {
                Job *k, *delete;

                /* If the marker is NULL we have been here already and
                 * decided the job was loop-free from here. Hence
                 * shortcut things and return right-away. */
                if (!j->marker)
                        return 0;

                /* So, the marker is not NULL and we already have been
                 * here. We have a cycle. Let's try to break it. We go
                 * backwards in our path and try to find a suitable
                 * job to remove. We use the marker to find our way
                 * back, since smart how we are we stored our way back
                 * in there. */
                log_unit_warning(j->unit,
                                 "Found ordering cycle on %s/%s",
                                 j->unit->id, job_type_to_string(j->type));

                delete = NULL;
                for (k = from; k; k = ((k->generation == generation && k->marker != k) ? k->marker : NULL)) {

                        /* logging for j not k here here to provide consistent narrative */
                        log_unit_warning(j->unit,
                                         "Found dependency on %s/%s",
                                         k->unit->id, job_type_to_string(k->type));

                        if (!delete && hashmap_get(tr->jobs, k->unit) && !unit_matters_to_anchor(k->unit, k))
                                /* Ok, we can drop this one, so let's
                                 * do so. */
                                delete = k;

                        /* Check if this in fact was the beginning of
                         * the cycle */
                        if (k == j)
                                break;
                }


                if (delete) {
                        /* logging for j not k here here to provide consistent narrative */
                        log_unit_warning(j->unit,
                                         "Breaking ordering cycle by deleting job %s/%s",
                                         delete->unit->id, job_type_to_string(delete->type));
                        log_unit_error(delete->unit,
                                       "Job %s/%s deleted to break ordering cycle starting with %s/%s",
                                       delete->unit->id, job_type_to_string(delete->type),
                                       j->unit->id, job_type_to_string(j->type));
                        unit_status_printf(delete->unit, ANSI_HIGHLIGHT_RED " SKIP " ANSI_NORMAL,
                                           "Ordering cycle found, skipping %s");
                        transaction_delete_unit(tr, delete->unit);
                        return -EAGAIN;
                }

                log_error("Unable to break cycle");

                return sd_bus_error_setf(e, BUS_ERROR_TRANSACTION_ORDER_IS_CYCLIC,
                                         "Transaction order is cyclic. See system logs for details.");
        }

        /* Make the marker point to where we come from, so that we can
         * find our way backwards if we want to break a cycle. We use
         * a special marker for the beginning: we point to
         * ourselves. */
        j->marker = from ? from : j;
        j->generation = generation;

        /* We assume that the dependencies are bidirectional, and
         * hence can ignore UNIT_AFTER */
        SET_FOREACH(u, j->unit->dependencies[UNIT_BEFORE], i) {
                Job *o;

                /* Is there a job for this unit? */
                o = hashmap_get(tr->jobs, u);
                if (!o) {
                        /* Ok, there is no job for this in the
                         * transaction, but maybe there is already one
                         * running? */
                        o = u->job;
                        if (!o)
                                continue;
                }

                r = transaction_verify_order_one(tr, o, j, generation, e);
                if (r < 0)
                        return r;
        }

        /* Ok, let's backtrack, and remember that this entry is not on
         * our path anymore. */
        j->marker = NULL;

        return 0;
}

static int transaction_verify_order(Transaction *tr, unsigned *generation, sd_bus_error *e) {
        Job *j;
        int r;
        Iterator i;
        unsigned g;

        assert(tr);
        assert(generation);

        /* Check if the ordering graph is cyclic. If it is, try to fix
         * that up by dropping one of the jobs. */

        g = (*generation)++;

        HASHMAP_FOREACH(j, tr->jobs, i) {
                r = transaction_verify_order_one(tr, j, NULL, g, e);
                if (r < 0)
                        return r;
        }

        return 0;
}

static void transaction_collect_garbage(Transaction *tr) {
        Iterator i;
        Job *j;

        assert(tr);

        /* Drop jobs that are not required by any other job */

rescan:
        HASHMAP_FOREACH(j, tr->jobs, i) {
                if (tr->anchor_job == j || j->object_list) {
                        /* log_debug("Keeping job %s/%s because of %s/%s", */
                        /*           j->unit->id, job_type_to_string(j->type), */
                        /*           j->object_list->subject ? j->object_list->subject->unit->id : "root", */
                        /*           j->object_list->subject ? job_type_to_string(j->object_list->subject->type) : "root"); */
                        continue;
                }

                /* log_debug("Garbage collecting job %s/%s", j->unit->id, job_type_to_string(j->type)); */
                transaction_delete_job(tr, j, true);
                goto rescan;
        }
}

static int transaction_is_destructive(Transaction *tr, JobMode mode, sd_bus_error *e) {
        Iterator i;
        Job *j;

        assert(tr);

        /* Checks whether applying this transaction means that
         * existing jobs would be replaced */

        HASHMAP_FOREACH(j, tr->jobs, i) {

                /* Assume merged */
                assert(!j->transaction_prev);
                assert(!j->transaction_next);

                if (j->unit->job && (mode == JOB_FAIL || j->unit->job->irreversible) &&
                    job_type_is_conflicting(j->unit->job->type, j->type))
                        return sd_bus_error_setf(e, BUS_ERROR_TRANSACTION_IS_DESTRUCTIVE,
                                                 "Transaction is destructive.");
        }

        return 0;
}

static void transaction_minimize_impact(Transaction *tr) {
        Job *j;
        Iterator i;

        assert(tr);

        /* Drops all unnecessary jobs that reverse already active jobs
         * or that stop a running service. */

rescan:
        HASHMAP_FOREACH(j, tr->jobs, i) {
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
                                j->unit->job &&
                                job_type_is_conflicting(j->type, j->unit->job->type);

                        if (!stops_running_service && !changes_existing_job)
                                continue;

                        if (stops_running_service)
                                log_unit_debug(j->unit,
                                               "%s/%s would stop a running service.",
                                               j->unit->id, job_type_to_string(j->type));

                        if (changes_existing_job)
                                log_unit_debug(j->unit,
                                               "%s/%s would change existing job.",
                                               j->unit->id, job_type_to_string(j->type));

                        /* Ok, let's get rid of this */
                        log_unit_debug(j->unit,
                                       "Deleting %s/%s to minimize impact.",
                                       j->unit->id, job_type_to_string(j->type));

                        transaction_delete_job(tr, j, true);
                        goto rescan;
                }
        }
}

static int transaction_apply(Transaction *tr, Manager *m, JobMode mode) {
        Iterator i;
        Job *j;
        int r;

        /* Moves the transaction jobs to the set of active jobs */

        if (mode == JOB_ISOLATE || mode == JOB_FLUSH) {

                /* When isolating first kill all installed jobs which
                 * aren't part of the new transaction */
                HASHMAP_FOREACH(j, m->jobs, i) {
                        assert(j->installed);

                        if (hashmap_get(tr->jobs, j->unit))
                                continue;

                        /* Not invalidating recursively. Avoids triggering
                         * OnFailure= actions of dependent jobs. Also avoids
                         * invalidating our iterator. */
                        job_finish_and_invalidate(j, JOB_CANCELED, false);
                }
        }

        HASHMAP_FOREACH(j, tr->jobs, i) {
                /* Assume merged */
                assert(!j->transaction_prev);
                assert(!j->transaction_next);

                r = hashmap_put(m->jobs, UINT32_TO_PTR(j->id), j);
                if (r < 0)
                        goto rollback;
        }

        while ((j = hashmap_steal_first(tr->jobs))) {
                Job *installed_job;

                /* Clean the job dependencies */
                transaction_unlink_job(tr, j, false);

                installed_job = job_install(j);
                if (installed_job != j) {
                        /* j has been merged into a previously installed job */
                        if (tr->anchor_job == j)
                                tr->anchor_job = installed_job;
                        hashmap_remove(m->jobs, UINT32_TO_PTR(j->id));
                        job_free(j);
                        j = installed_job;
                }

                job_add_to_run_queue(j);
                job_add_to_dbus_queue(j);
                job_start_timer(j);
                job_shutdown_magic(j);
        }

        return 0;

rollback:

        HASHMAP_FOREACH(j, tr->jobs, i)
                hashmap_remove(m->jobs, UINT32_TO_PTR(j->id));

        return r;
}

int transaction_activate(Transaction *tr, Manager *m, JobMode mode, sd_bus_error *e) {
        Iterator i;
        Job *j;
        int r;
        unsigned generation = 1;

        assert(tr);

        /* This applies the changes recorded in tr->jobs to
         * the actual list of jobs, if possible. */

        /* Reset the generation counter of all installed jobs. The detection of cycles
         * looks at installed jobs. If they had a non-zero generation from some previous
         * walk of the graph, the algorithm would break. */
        HASHMAP_FOREACH(j, m->jobs, i)
                j->generation = 0;

        /* First step: figure out which jobs matter */
        transaction_find_jobs_that_matter_to_anchor(tr->anchor_job, generation++);

        /* Second step: Try not to stop any running services if
         * we don't have to. Don't try to reverse running
         * jobs if we don't have to. */
        if (mode == JOB_FAIL)
                transaction_minimize_impact(tr);

        /* Third step: Drop redundant jobs */
        transaction_drop_redundant(tr);

        for (;;) {
                /* Fourth step: Let's remove unneeded jobs that might
                 * be lurking. */
                if (mode != JOB_ISOLATE)
                        transaction_collect_garbage(tr);

                /* Fifth step: verify order makes sense and correct
                 * cycles if necessary and possible */
                r = transaction_verify_order(tr, &generation, e);
                if (r >= 0)
                        break;

                if (r != -EAGAIN) {
                        log_warning("Requested transaction contains an unfixable cyclic ordering dependency: %s", bus_error_message(e, r));
                        return r;
                }

                /* Let's see if the resulting transaction ordering
                 * graph is still cyclic... */
        }

        for (;;) {
                /* Sixth step: let's drop unmergeable entries if
                 * necessary and possible, merge entries we can
                 * merge */
                r = transaction_merge_jobs(tr, e);
                if (r >= 0)
                        break;

                if (r != -EAGAIN) {
                        log_warning("Requested transaction contains unmergeable jobs: %s", bus_error_message(e, r));
                        return r;
                }

                /* Seventh step: an entry got dropped, let's garbage
                 * collect its dependencies. */
                if (mode != JOB_ISOLATE)
                        transaction_collect_garbage(tr);

                /* Let's see if the resulting transaction still has
                 * unmergeable entries ... */
        }

        /* Eights step: Drop redundant jobs again, if the merging now allows us to drop more. */
        transaction_drop_redundant(tr);

        /* Ninth step: check whether we can actually apply this */
        r = transaction_is_destructive(tr, mode, e);
        if (r < 0) {
                log_notice("Requested transaction contradicts existing jobs: %s", bus_error_message(e, r));
                return r;
        }

        /* Tenth step: apply changes */
        r = transaction_apply(tr, m, mode);
        if (r < 0)
                return log_warning_errno(r, "Failed to apply transaction: %m");

        assert(hashmap_isempty(tr->jobs));

        if (!hashmap_isempty(m->jobs)) {
                /* Are there any jobs now? Then make sure we have the
                 * idle pipe around. We don't really care too much
                 * whether this works or not, as the idle pipe is a
                 * feature for cosmetics, not actually useful for
                 * anything beyond that. */

                if (m->idle_pipe[0] < 0 && m->idle_pipe[1] < 0 &&
                    m->idle_pipe[2] < 0 && m->idle_pipe[3] < 0) {
                        (void) pipe2(m->idle_pipe, O_NONBLOCK|O_CLOEXEC);
                        (void) pipe2(m->idle_pipe + 2, O_NONBLOCK|O_CLOEXEC);
                }
        }

        return 0;
}

static Job* transaction_add_one_job(Transaction *tr, JobType type, Unit *unit, bool override, bool *is_new) {
        Job *j, *f;

        assert(tr);
        assert(unit);

        /* Looks for an existing prospective job and returns that. If
         * it doesn't exist it is created and added to the prospective
         * jobs list. */

        f = hashmap_get(tr->jobs, unit);

        LIST_FOREACH(transaction, j, f) {
                assert(j->unit == unit);

                if (j->type == type) {
                        if (is_new)
                                *is_new = false;
                        return j;
                }
        }

        j = job_new(unit, type);
        if (!j)
                return NULL;

        j->generation = 0;
        j->marker = NULL;
        j->matters_to_anchor = false;
        j->override = override;
        j->irreversible = tr->irreversible;

        LIST_PREPEND(transaction, f, j);

        if (hashmap_replace(tr->jobs, unit, f) < 0) {
                LIST_REMOVE(transaction, f, j);
                job_free(j);
                return NULL;
        }

        if (is_new)
                *is_new = true;

        /* log_debug("Added job %s/%s to transaction.", unit->id, job_type_to_string(type)); */

        return j;
}

static void transaction_unlink_job(Transaction *tr, Job *j, bool delete_dependencies) {
        assert(tr);
        assert(j);

        if (j->transaction_prev)
                j->transaction_prev->transaction_next = j->transaction_next;
        else if (j->transaction_next)
                hashmap_replace(tr->jobs, j->unit, j->transaction_next);
        else
                hashmap_remove_value(tr->jobs, j->unit, j);

        if (j->transaction_next)
                j->transaction_next->transaction_prev = j->transaction_prev;

        j->transaction_prev = j->transaction_next = NULL;

        while (j->subject_list)
                job_dependency_free(j->subject_list);

        while (j->object_list) {
                Job *other = j->object_list->matters ? j->object_list->subject : NULL;

                job_dependency_free(j->object_list);

                if (other && delete_dependencies) {
                        log_unit_debug(other->unit,
                                       "Deleting job %s/%s as dependency of job %s/%s",
                                       other->unit->id, job_type_to_string(other->type),
                                       j->unit->id, job_type_to_string(j->type));
                        transaction_delete_job(tr, other, delete_dependencies);
                }
        }
}

int transaction_add_job_and_dependencies(
                Transaction *tr,
                JobType type,
                Unit *unit,
                Job *by,
                bool matters,
                bool override,
                bool conflicts,
                bool ignore_requirements,
                bool ignore_order,
                sd_bus_error *e) {
        Job *ret;
        Iterator i;
        Unit *dep;
        int r;
        bool is_new;

        assert(tr);
        assert(type < _JOB_TYPE_MAX);
        assert(type < _JOB_TYPE_MAX_IN_TRANSACTION);
        assert(unit);

        /* Before adding jobs for this unit, let's ensure that its state has been loaded
         * This matters when jobs are spawned as part of coldplugging itself (see e. g. path_coldplug()).
         * This way, we "recursively" coldplug units, ensuring that we do not look at state of
         * not-yet-coldplugged units. */
        if (unit->manager->n_reloading > 0)
                unit_coldplug(unit);

        /* log_debug("Pulling in %s/%s from %s/%s", */
        /*           unit->id, job_type_to_string(type), */
        /*           by ? by->unit->id : "NA", */
        /*           by ? job_type_to_string(by->type) : "NA"); */

        if (!IN_SET(unit->load_state, UNIT_LOADED, UNIT_ERROR, UNIT_NOT_FOUND, UNIT_MASKED))
                return sd_bus_error_setf(e, BUS_ERROR_LOAD_FAILED, "Unit %s is not loaded properly.", unit->id);

        if (type != JOB_STOP && unit->load_state == UNIT_ERROR) {
                if (unit->load_error == -ENOENT || unit->manager->test_run)
                        return sd_bus_error_setf(e, BUS_ERROR_LOAD_FAILED,
                                                 "Unit %s failed to load: %s.",
                                                 unit->id,
                                                 strerror(-unit->load_error));
                else
                        return sd_bus_error_setf(e, BUS_ERROR_LOAD_FAILED,
                                                 "Unit %s failed to load: %s. "
                                                 "See system logs and 'systemctl status %s' for details.",
                                                 unit->id,
                                                 strerror(-unit->load_error),
                                                 unit->id);
        }

        if (type != JOB_STOP && unit->load_state == UNIT_NOT_FOUND)
                return sd_bus_error_setf(e, BUS_ERROR_LOAD_FAILED,
                                         "Unit %s failed to load: %s.",
                                         unit->id, strerror(-unit->load_error));

        if (type != JOB_STOP && unit->load_state == UNIT_MASKED)
                return sd_bus_error_setf(e, BUS_ERROR_UNIT_MASKED,
                                         "Unit %s is masked.", unit->id);

        if (!unit_job_is_applicable(unit, type))
                return sd_bus_error_setf(e, BUS_ERROR_JOB_TYPE_NOT_APPLICABLE,
                                         "Job type %s is not applicable for unit %s.",
                                         job_type_to_string(type), unit->id);


        /* First add the job. */
        ret = transaction_add_one_job(tr, type, unit, override, &is_new);
        if (!ret)
                return -ENOMEM;

        ret->ignore_order = ret->ignore_order || ignore_order;

        /* Then, add a link to the job. */
        if (by) {
                if (!job_dependency_new(by, ret, matters, conflicts))
                        return -ENOMEM;
        } else {
                /* If the job has no parent job, it is the anchor job. */
                assert(!tr->anchor_job);
                tr->anchor_job = ret;
        }

        if (is_new && !ignore_requirements && type != JOB_NOP) {
                Set *following;

                /* If we are following some other unit, make sure we
                 * add all dependencies of everybody following. */
                if (unit_following_set(ret->unit, &following) > 0) {
                        SET_FOREACH(dep, following, i) {
                                r = transaction_add_job_and_dependencies(tr, type, dep, ret, false, override, false, false, ignore_order, e);
                                if (r < 0) {
                                        log_unit_warning(dep, "Cannot add dependency job for, ignoring: %s", bus_error_message(e, r));
                                        sd_bus_error_free(e);
                                }
                        }

                        set_free(following);
                }

                /* Finally, recursively add in all dependencies. */
                if (type == JOB_START || type == JOB_RESTART) {
                        SET_FOREACH(dep, ret->unit->dependencies[UNIT_REQUIRES], i) {
                                r = transaction_add_job_and_dependencies(tr, JOB_START, dep, ret, true, override, false, false, ignore_order, e);
                                if (r < 0) {
                                        if (r != -EBADR)
                                                goto fail;

                                        sd_bus_error_free(e);
                                }
                        }

                        SET_FOREACH(dep, ret->unit->dependencies[UNIT_BINDS_TO], i) {
                                r = transaction_add_job_and_dependencies(tr, JOB_START, dep, ret, true, override, false, false, ignore_order, e);
                                if (r < 0) {
                                        if (r != -EBADR)
                                                goto fail;

                                        sd_bus_error_free(e);
                                }
                        }

                        SET_FOREACH(dep, ret->unit->dependencies[UNIT_REQUIRES_OVERRIDABLE], i) {
                                r = transaction_add_job_and_dependencies(tr, JOB_START, dep, ret, !override, override, false, false, ignore_order, e);
                                if (r < 0) {
                                        log_unit_full(dep,
                                                      r == -EADDRNOTAVAIL ? LOG_DEBUG : LOG_WARNING, r,
                                                      "Cannot add dependency job, ignoring: %s",
                                                      bus_error_message(e, r));
                                        sd_bus_error_free(e);
                                }
                        }

                        SET_FOREACH(dep, ret->unit->dependencies[UNIT_WANTS], i) {
                                r = transaction_add_job_and_dependencies(tr, JOB_START, dep, ret, false, false, false, false, ignore_order, e);
                                if (r < 0) {
                                        log_unit_full(dep,
                                                      r == -EADDRNOTAVAIL ? LOG_DEBUG : LOG_WARNING, r,
                                                      "Cannot add dependency job, ignoring: %s",
                                                      bus_error_message(e, r));
                                        sd_bus_error_free(e);
                                }
                        }

                        SET_FOREACH(dep, ret->unit->dependencies[UNIT_REQUISITE], i) {
                                r = transaction_add_job_and_dependencies(tr, JOB_VERIFY_ACTIVE, dep, ret, true, override, false, false, ignore_order, e);
                                if (r < 0) {
                                        if (r != -EBADR)
                                                goto fail;

                                        sd_bus_error_free(e);
                                }
                        }

                        SET_FOREACH(dep, ret->unit->dependencies[UNIT_REQUISITE_OVERRIDABLE], i) {
                                r = transaction_add_job_and_dependencies(tr, JOB_VERIFY_ACTIVE, dep, ret, !override, override, false, false, ignore_order, e);
                                if (r < 0) {
                                        log_unit_full(dep,
                                                      r == -EADDRNOTAVAIL ? LOG_DEBUG : LOG_WARNING, r,
                                                      "Cannot add dependency job, ignoring: %s",
                                                      bus_error_message(e, r));
                                        sd_bus_error_free(e);
                                }
                        }

                        SET_FOREACH(dep, ret->unit->dependencies[UNIT_CONFLICTS], i) {
                                r = transaction_add_job_and_dependencies(tr, JOB_STOP, dep, ret, true, override, true, false, ignore_order, e);
                                if (r < 0) {
                                        if (r != -EBADR)
                                                goto fail;

                                        sd_bus_error_free(e);
                                }
                        }

                        SET_FOREACH(dep, ret->unit->dependencies[UNIT_CONFLICTED_BY], i) {
                                r = transaction_add_job_and_dependencies(tr, JOB_STOP, dep, ret, false, override, false, false, ignore_order, e);
                                if (r < 0) {
                                        log_unit_warning(dep,
                                                         "Cannot add dependency job, ignoring: %s",
                                                         bus_error_message(e, r));
                                        sd_bus_error_free(e);
                                }
                        }

                }

                if (type == JOB_STOP || type == JOB_RESTART) {
                        static const UnitDependency propagate_deps[] = {
                                UNIT_REQUIRED_BY,
                                UNIT_REQUISITE_OF,
                                UNIT_BOUND_BY,
                                UNIT_CONSISTS_OF,
                        };

                        JobType ptype;
                        unsigned j;

                        /* We propagate STOP as STOP, but RESTART only
                         * as TRY_RESTART, in order not to start
                         * dependencies that are not around. */
                        ptype = type == JOB_RESTART ? JOB_TRY_RESTART : type;

                        for (j = 0; j < ELEMENTSOF(propagate_deps); j++)
                                SET_FOREACH(dep, ret->unit->dependencies[propagate_deps[j]], i) {
                                        JobType nt;

                                        nt = job_type_collapse(ptype, dep);
                                        if (nt == JOB_NOP)
                                                continue;

                                        r = transaction_add_job_and_dependencies(tr, nt, dep, ret, true, override, false, false, ignore_order, e);
                                        if (r < 0) {
                                                if (r != -EBADR)
                                                        goto fail;

                                                sd_bus_error_free(e);
                                        }
                                }
                }

                if (type == JOB_RELOAD) {

                        SET_FOREACH(dep, ret->unit->dependencies[UNIT_PROPAGATES_RELOAD_TO], i) {
                                r = transaction_add_job_and_dependencies(tr, JOB_RELOAD, dep, ret, false, override, false, false, ignore_order, e);
                                if (r < 0) {
                                        log_unit_warning(dep,
                                                         "Cannot add dependency reload job, ignoring: %s",
                                                         bus_error_message(e, r));
                                        sd_bus_error_free(e);
                                }
                        }
                }

                /* JOB_VERIFY_STARTED require no dependency handling */
        }

        return 0;

fail:
        return r;
}

int transaction_add_isolate_jobs(Transaction *tr, Manager *m) {
        Iterator i;
        Unit *u;
        char *k;
        int r;

        assert(tr);
        assert(m);

        HASHMAP_FOREACH_KEY(u, k, m->units, i) {

                /* ignore aliases */
                if (u->id != k)
                        continue;

                if (u->ignore_on_isolate)
                        continue;

                /* No need to stop inactive jobs */
                if (UNIT_IS_INACTIVE_OR_FAILED(unit_active_state(u)) && !u->job)
                        continue;

                /* Is there already something listed for this? */
                if (hashmap_get(tr->jobs, u))
                        continue;

                r = transaction_add_job_and_dependencies(tr, JOB_STOP, u, tr->anchor_job, true, false, false, false, false, NULL);
                if (r < 0)
                        log_unit_warning_errno(u, r, "Cannot add isolate job, ignoring: %m");
        }

        return 0;
}

Transaction *transaction_new(bool irreversible) {
        Transaction *tr;

        tr = new0(Transaction, 1);
        if (!tr)
                return NULL;

        tr->jobs = hashmap_new(NULL);
        if (!tr->jobs) {
                free(tr);
                return NULL;
        }

        tr->irreversible = irreversible;

        return tr;
}

void transaction_free(Transaction *tr) {
        assert(hashmap_isempty(tr->jobs));
        hashmap_free(tr->jobs);
        free(tr);
}
