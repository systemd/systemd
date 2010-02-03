/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <assert.h>
#include <errno.h>

#include "set.h"
#include "unit.h"
#include "macro.h"
#include "strv.h"
#include "load-fragment.h"
#include "load-dropin.h"
#include "log.h"

Job* job_new(Manager *m, JobType type, Unit *unit) {
        Job *j;

        assert(m);
        assert(type < _JOB_TYPE_MAX);
        assert(unit);

        if (!(j = new0(Job, 1)))
                return NULL;

        j->manager = m;
        j->id = m->current_job_id++;
        j->type = type;
        j->unit = unit;

        /* We don't link it here, that's what job_dependency() is for */

        return j;
}

void job_free(Job *j) {
        assert(j);

        /* Detach from next 'bigger' objects */
        if (j->installed) {
                if (j->unit->meta.job == j)
                        j->unit->meta.job = NULL;

                hashmap_remove(j->manager->jobs, UINT32_TO_PTR(j->id));
                j->installed = false;
        }

        /* Detach from next 'smaller' objects */
        manager_transaction_unlink_job(j->manager, j);

        free(j);
}

JobDependency* job_dependency_new(Job *subject, Job *object, bool matters) {
        JobDependency *l;

        assert(object);

        /* Adds a new job link, which encodes that the 'subject' job
         * needs the 'object' job in some way. If 'subject' is NULL
         * this means the 'anchor' job (i.e. the one the user
         * explcitily asked for) is the requester. */

        if (!(l = new0(JobDependency, 1)))
                return NULL;

        l->subject = subject;
        l->object = object;
        l->matters = matters;

        if (subject)
                LIST_PREPEND(JobDependency, subject, subject->subject_list, l);
        else
                LIST_PREPEND(JobDependency, subject, object->manager->transaction_anchor, l);

        LIST_PREPEND(JobDependency, object, object->object_list, l);

        return l;
}

void job_dependency_free(JobDependency *l) {
        assert(l);

        if (l->subject)
                LIST_REMOVE(JobDependency, subject, l->subject->subject_list, l);
        else
                LIST_REMOVE(JobDependency, subject, l->object->manager->transaction_anchor, l);

        LIST_REMOVE(JobDependency, object, l->object->object_list, l);

        free(l);
}

void job_dependency_delete(Job *subject, Job *object, bool *matters) {
        JobDependency *l;

        assert(object);

        LIST_FOREACH(object, l, object->object_list) {
                assert(l->object == object);

                if (l->subject == subject)
                        break;
        }

        if (!l) {
                if (matters)
                        *matters = false;
                return;
        }

        if (matters)
                *matters = l->matters;

        job_dependency_free(l);
}

void job_dump(Job *j, FILE*f, const char *prefix) {


        assert(j);
        assert(f);

        fprintf(f,
                "%s→ Job %u:\n"
                "%s\tAction: %s → %s\n"
                "%s\tState: %s\n"
                "%s\tForced: %s\n",
                prefix, j->id,
                prefix, unit_id(j->unit), job_type_to_string(j->type),
                prefix, job_state_to_string(j->state),
                prefix, yes_no(j->forced));
}

bool job_is_anchor(Job *j) {
        JobDependency *l;

        assert(j);

        LIST_FOREACH(object, l, j->object_list)
                if (!l->subject)
                        return true;

        return false;
}

static bool types_match(JobType a, JobType b, JobType c, JobType d) {
        return
                (a == c && b == d) ||
                (a == d && b == c);
}

int job_type_merge(JobType *a, JobType b) {
        if (*a == b)
                return 0;

        /* Merging is associative! a merged with b merged with c is
         * the same as a merged with c merged with b. */

        /* Mergeability is transitive! if a can be merged with b and b
         * with c then a also with c */

        /* Also, if a merged with b cannot be merged with c, then
         * either a or b cannot be merged with c either */

        if (types_match(*a, b, JOB_START, JOB_VERIFY_ACTIVE))
                *a = JOB_START;
        else if (types_match(*a, b, JOB_START, JOB_RELOAD) ||
                 types_match(*a, b, JOB_START, JOB_RELOAD_OR_START) ||
                 types_match(*a, b, JOB_VERIFY_ACTIVE, JOB_RELOAD_OR_START) ||
                 types_match(*a, b, JOB_RELOAD, JOB_RELOAD_OR_START))
                *a = JOB_RELOAD_OR_START;
        else if (types_match(*a, b, JOB_START, JOB_RESTART) ||
                 types_match(*a, b, JOB_START, JOB_TRY_RESTART) ||
                 types_match(*a, b, JOB_VERIFY_ACTIVE, JOB_RESTART) ||
                 types_match(*a, b, JOB_RELOAD, JOB_RESTART) ||
                 types_match(*a, b, JOB_RELOAD_OR_START, JOB_RESTART) ||
                 types_match(*a, b, JOB_RELOAD_OR_START, JOB_TRY_RESTART) ||
                 types_match(*a, b, JOB_RESTART, JOB_TRY_RESTART))
                *a = JOB_RESTART;
        else if (types_match(*a, b, JOB_VERIFY_ACTIVE, JOB_RELOAD))
                *a = JOB_RELOAD;
        else if (types_match(*a, b, JOB_VERIFY_ACTIVE, JOB_TRY_RESTART) ||
                 types_match(*a, b, JOB_RELOAD, JOB_TRY_RESTART))
                *a = JOB_TRY_RESTART;
        else
                return -EEXIST;

        return 0;
}

bool job_type_is_mergeable(JobType a, JobType b) {
        return job_type_merge(&a, b) >= 0;
}

bool job_type_is_superset(JobType a, JobType b) {

        /* Checks whether operation a is a "superset" of b in its
         * actions */

        if (a == b)
                return true;

        switch (a) {
                case JOB_START:
                        return b == JOB_VERIFY_ACTIVE;

                case JOB_RELOAD:
                        return
                                b == JOB_VERIFY_ACTIVE;

                case JOB_RELOAD_OR_START:
                        return
                                b == JOB_RELOAD ||
                                b == JOB_START ||
                                b == JOB_VERIFY_ACTIVE;

                case JOB_RESTART:
                        return
                                b == JOB_START ||
                                b == JOB_VERIFY_ACTIVE ||
                                b == JOB_RELOAD ||
                                b == JOB_RELOAD_OR_START ||
                                b == JOB_TRY_RESTART;

                case JOB_TRY_RESTART:
                        return
                                b == JOB_VERIFY_ACTIVE ||
                                b == JOB_RELOAD;
                default:
                        return false;

        }
}

bool job_type_is_conflicting(JobType a, JobType b) {
        assert(a >= 0 && a < _JOB_TYPE_MAX);
        assert(b >= 0 && b < _JOB_TYPE_MAX);

        return (a == JOB_STOP) != (b == JOB_STOP);
}

bool job_is_runnable(Job *j) {
        Iterator i;
        Unit *other;

        assert(j);
        assert(j->installed);

        /* Checks whether there is any job running for the units this
         * job needs to be running after (in the case of a 'positive'
         * job type) or before (in the case of a 'negative' job type
         * . */

        if (j->type == JOB_START ||
            j->type == JOB_VERIFY_ACTIVE ||
            j->type == JOB_RELOAD ||
            j->type == JOB_RELOAD_OR_START) {

                /* Immediate result is that the job is or might be
                 * started. In this case lets wait for the
                 * dependencies, regardless whether they are
                 * starting or stopping something. */

                SET_FOREACH(other, j->unit->meta.dependencies[UNIT_AFTER], i)
                        if (other->meta.job)
                                return false;
        }

        /* Also, if something else is being stopped and we should
         * change state after it, then lets wait. */

        SET_FOREACH(other, j->unit->meta.dependencies[UNIT_BEFORE], i)
                if (other->meta.job &&
                    (other->meta.job->type == JOB_STOP ||
                     other->meta.job->type == JOB_RESTART ||
                     other->meta.job->type == JOB_TRY_RESTART))
                        return false;

        /* This means that for a service a and a service b where b
         * shall be started after a:
         *
         *  start a + start b → 1st step start a, 2nd step start b
         *  start a + stop b  → 1st step stop b,  2nd step start a
         *  stop a  + start b → 1st step stop a,  2nd step start b
         *  stop a  + stop b  → 1st step stop b,  2nd step stop a
         *
         *  This has the side effect that restarts are properly
         *  synchronized too. */

        return true;
}

int job_run_and_invalidate(Job *j) {
        int r;

        assert(j);
        assert(j->installed);

        if (j->in_run_queue) {
                LIST_REMOVE(Job, run_queue, j->manager->run_queue, j);
                j->in_run_queue = false;
        }

        if (j->state != JOB_WAITING)
                return 0;

        if (!job_is_runnable(j))
                return -EAGAIN;

        j->state = JOB_RUNNING;

        switch (j->type) {

                case JOB_START:
                        r = unit_start(j->unit);
                        if (r == -EBADR)
                                r = 0;
                        break;

                case JOB_VERIFY_ACTIVE: {
                        UnitActiveState t = unit_active_state(j->unit);
                        if (UNIT_IS_ACTIVE_OR_RELOADING(t))
                                r = -EALREADY;
                        else if (t == UNIT_ACTIVATING)
                                r = -EAGAIN;
                        else
                                r = -ENOEXEC;
                        break;
                }

                case JOB_STOP:
                        r = unit_stop(j->unit);
                        break;

                case JOB_RELOAD:
                        r = unit_reload(j->unit);
                        break;

                case JOB_RELOAD_OR_START:
                        if (unit_active_state(j->unit) == UNIT_ACTIVE)
                                r = unit_reload(j->unit);
                        else
                                r = unit_start(j->unit);
                        break;

                case JOB_RESTART: {
                        UnitActiveState t = unit_active_state(j->unit);
                        if (t == UNIT_INACTIVE || t == UNIT_ACTIVATING) {
                                j->type = JOB_START;
                                r = unit_start(j->unit);
                        } else
                                r = unit_stop(j->unit);
                        break;
                }

                case JOB_TRY_RESTART: {
                        UnitActiveState t = unit_active_state(j->unit);
                        if (t == UNIT_INACTIVE || t == UNIT_DEACTIVATING)
                                r = -ENOEXEC;
                        else if (t == UNIT_ACTIVATING) {
                                j->type = JOB_START;
                                r = unit_start(j->unit);
                        } else
                                r = unit_stop(j->unit);
                        break;
                }

                default:
                        assert_not_reached("Unknown job type");
        }

        if (r == -EALREADY)
                r = job_finish_and_invalidate(j, true);
        else if (r == -EAGAIN) {
                j->state = JOB_WAITING;
                return -EAGAIN;
        } else if (r < 0)
                r = job_finish_and_invalidate(j, false);

        return r;
}

int job_finish_and_invalidate(Job *j, bool success) {
        Unit *u;
        Unit *other;
        UnitType t;
        Iterator i;

        assert(j);
        assert(j->installed);

        log_debug("Job %s/%s finished, success=%s", unit_id(j->unit), job_type_to_string(j->type), yes_no(success));

        /* Patch restart jobs so that they become normal start jobs */
        if (success && (j->type == JOB_RESTART || j->type == JOB_TRY_RESTART)) {

                log_debug("Converting job %s/%s → %s/%s",
                          unit_id(j->unit), job_type_to_string(j->type),
                          unit_id(j->unit), job_type_to_string(JOB_START));

                j->state = JOB_RUNNING;
                j->type = JOB_START;

                job_schedule_run(j);
                return 0;
        }

        u = j->unit;
        t = j->type;
        job_free(j);

        /* Fail depending jobs on failure */
        if (!success) {

                if (t == JOB_START ||
                    t == JOB_VERIFY_ACTIVE ||
                    t == JOB_RELOAD_OR_START) {

                        SET_FOREACH(other, u->meta.dependencies[UNIT_REQUIRED_BY], i)
                                if (other->meta.job &&
                                    (other->meta.type == JOB_START ||
                                     other->meta.type == JOB_VERIFY_ACTIVE ||
                                     other->meta.type == JOB_RELOAD_OR_START))
                                        job_finish_and_invalidate(other->meta.job, false);

                        SET_FOREACH(other, u->meta.dependencies[UNIT_SOFT_REQUIRED_BY], i)
                                if (other->meta.job &&
                                    !other->meta.job->forced &&
                                    (other->meta.type == JOB_START ||
                                     other->meta.type == JOB_VERIFY_ACTIVE ||
                                     other->meta.type == JOB_RELOAD_OR_START))
                                        job_finish_and_invalidate(other->meta.job, false);

                } else if (t == JOB_STOP) {

                        SET_FOREACH(other, u->meta.dependencies[UNIT_CONFLICTS], i)
                                if (other->meta.job &&
                                    (t == JOB_START ||
                                     t == JOB_VERIFY_ACTIVE ||
                                     t == JOB_RELOAD_OR_START))
                                        job_finish_and_invalidate(other->meta.job, false);
                }
        }

        /* Try to start the next jobs that can be started */
        SET_FOREACH(other, u->meta.dependencies[UNIT_AFTER], i)
                if (other->meta.job)
                        job_schedule_run(other->meta.job);
        SET_FOREACH(other, u->meta.dependencies[UNIT_BEFORE], i)
                if (other->meta.job)
                        job_schedule_run(other->meta.job);

        return 0;
}

void job_schedule_run(Job *j) {
        assert(j);
        assert(j->installed);

        if (j->in_run_queue)
                return;

        LIST_PREPEND(Job, run_queue, j->manager->run_queue, j);
        j->in_run_queue = true;
}

char *job_dbus_path(Job *j) {
        char *p;

        assert(j);

        if (asprintf(&p, "/org/freedesktop/systemd1/job/%lu", (unsigned long) j->id) < 0)
                return NULL;

        return p;
}

static const char* const job_state_table[_JOB_STATE_MAX] = {
        [JOB_WAITING] = "waiting",
        [JOB_RUNNING] = "running"
};

DEFINE_STRING_TABLE_LOOKUP(job_state, JobState);

static const char* const job_type_table[_JOB_TYPE_MAX] = {
        [JOB_START] = "start",
        [JOB_VERIFY_ACTIVE] = "verify-active",
        [JOB_STOP] = "stop",
        [JOB_RELOAD] = "reload",
        [JOB_RELOAD_OR_START] = "reload-or-start",
        [JOB_RESTART] = "restart",
        [JOB_TRY_RESTART] = "try-restart",
};

DEFINE_STRING_TABLE_LOOKUP(job_type, JobType);

static const char* const job_mode_table[_JOB_MODE_MAX] = {
        [JOB_FAIL] = "fail",
        [JOB_REPLACE] = "replace"
};

DEFINE_STRING_TABLE_LOOKUP(job_mode, JobMode);
