/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <assert.h>
#include <errno.h>

#include "macro.h"
#include "job.h"

Job* job_new(Manager *m, JobType type, Name *name) {
        Job *j;

        assert(m);
        assert(type < _JOB_TYPE_MAX);
        assert(name);

        if (!(j = new0(Job, 1)))
                return NULL;

        j->manager = m;
        j->id = m->current_job_id++;
        j->type = type;
        j->name = name;

        /* We don't link it here, that's what job_dependency() is for */

        return j;
}

void job_free(Job *j) {
        assert(j);

        /* Detach from next 'bigger' objects */
        if (j->linked) {
                if (j->name->meta.job == j)
                        j->name->meta.job = NULL;

                hashmap_remove(j->manager->jobs, UINT32_TO_PTR(j->id));
                j->linked = false;
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

        if (subject) {
                l->subject_next = subject->subject_list;
                subject->subject_list = l;
        } else {
                l->subject_next = object->manager->transaction_anchor;
                object->manager->transaction_anchor = l;
        }

        if (l->subject_next)
                l->subject_next->subject_prev = l;
        l->subject_prev = NULL;

        if ((l->object_next = object->object_list))
                l->object_next->object_prev = l;
        l->object_prev = NULL;
        object->object_list = l;

        return l;
}

void job_dependency_free(JobDependency *l) {
        assert(l);

        if (l->subject_prev)
                l->subject_prev->subject_next = l->subject_next;
        else if (l->subject)
                l->subject->subject_list = l->subject_next;
        else
                l->object->manager->transaction_anchor = l->subject_next;

        if (l->subject_next)
                l->subject_next->subject_prev = l->subject_prev;

        if (l->object_prev)
                l->object_prev->object_next = l->object_next;
        else
                l->object->object_list = l->object_next;

        if (l->object_next)
                l->object_next->object_prev = l->object_prev;

        free(l);
}

void job_dependency_delete(Job *subject, Job *object, bool *matters) {
        JobDependency *l;

        assert(object);

        for (l = object->object_list; l; l = l->object_next) {
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

const char* job_type_to_string(JobType t) {

        static const char* const job_type_table[_JOB_TYPE_MAX] = {
                [JOB_START] = "start",
                [JOB_VERIFY_ACTIVE] = "verify-active",
                [JOB_STOP] = "stop",
                [JOB_RELOAD] = "reload",
                [JOB_RELOAD_OR_START] = "reload-or-start",
                [JOB_RESTART] = "restart",
                [JOB_TRY_RESTART] = "try-restart",
        };

        if (t < 0 || t >= _JOB_TYPE_MAX)
                return "n/a";

        return job_type_table[t];
}

void job_dump(Job *j, FILE*f, const char *prefix) {

        static const char* const job_state_table[_JOB_STATE_MAX] = {
                [JOB_WAITING] = "waiting",
                [JOB_RUNNING] = "running"
        };

        assert(j);
        assert(f);

        fprintf(f,
                "%sJob %u:\n"
                "%s\tAction: %s → %s\n"
                "%s\tState: %s\n"
                "%s\tForced: %s\n",
                prefix, j->id,
                prefix, name_id(j->name), job_type_to_string(j->type),
                prefix, job_state_table[j->state],
                prefix, yes_no(j->forced));
}

bool job_is_anchor(Job *j) {
        JobDependency *l;

        assert(j);

        for (l = j->object_list; l; l = l->object_next)
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

bool job_type_is_applicable(JobType j, NameType n) {
        assert(j >= 0 && j < _JOB_TYPE_MAX);
        assert(n >= 0 && n < _NAME_TYPE_MAX);

        switch (j) {
                case JOB_VERIFY_ACTIVE:
                case JOB_START:
                        return true;

                case JOB_STOP:
                case JOB_RESTART:
                case JOB_TRY_RESTART:
                        return name_type_can_start(n);

                case JOB_RELOAD:
                        return name_type_can_reload(n);

                case JOB_RELOAD_OR_START:
                        return name_type_can_reload(n) && name_type_can_start(n);

                default:
                        assert_not_reached("Invalid job type");
        }
}

bool job_is_runnable(Job *j) {
        void *state;
        Name *other;

        assert(j);
        assert(j->linked);

        /* Checks whether there is any job running for the names this
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

                SET_FOREACH(other, j->name->meta.dependencies[NAME_AFTER], state)
                        if (other->meta.job)
                                return false;
        }

        /* Also, if something else is being stopped and we should
         * change state after it, then lets wait. */

        SET_FOREACH(other, j->name->meta.dependencies[NAME_BEFORE], state)
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

        if (!job_is_runnable(j))
                return -EAGAIN;

        if (j->state != JOB_WAITING)
                return 0;

        j->state = JOB_RUNNING;

        switch (j->type) {

                case JOB_START:
                        r = name_start(j->name);
                        if (r == -EBADR)
                                r = 0;
                        break;

                case JOB_VERIFY_ACTIVE: {
                        NameActiveState t = name_active_state(j->name);
                        if (NAME_IS_ACTIVE_OR_RELOADING(t))
                                r = -EALREADY;
                        else if (t == NAME_ACTIVATING)
                                r = -EAGAIN;
                        else
                                r = -ENOEXEC;
                        break;
                }

                case JOB_STOP:
                        r = name_stop(j->name);
                        break;

                case JOB_RELOAD:
                        r = name_reload(j->name);
                        break;

                case JOB_RELOAD_OR_START:
                        if (name_active_state(j->name) == NAME_ACTIVE)
                                r = name_reload(j->name);
                        else
                                r = name_start(j->name);
                        break;

                case JOB_RESTART: {
                        NameActiveState t = name_active_state(j->name);
                        if (t == NAME_INACTIVE || t == NAME_ACTIVATING) {
                                j->type = JOB_START;
                                r = name_start(j->name);
                        } else
                                r = name_stop(j->name);
                        break;
                }

                case JOB_TRY_RESTART: {
                        NameActiveState t = name_active_state(j->name);
                        if (t == NAME_INACTIVE || t == NAME_DEACTIVATING)
                                r = -ENOEXEC;
                        else if (t == NAME_ACTIVATING) {
                                j->type = JOB_START;
                                r = name_start(j->name);
                        } else
                                r = name_stop(j->name);
                        break;
                }

                default:
                        ;
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
        Name *n;
        void *state;
        Name *other;
        NameType t;

        assert(j);

        if (success && (j->type == JOB_RESTART || j->type == JOB_TRY_RESTART)) {
                j->state = JOB_RUNNING;
                j->type = JOB_START;
                return job_run_and_invalidate(j);
        }

        n = j->name;
        t = j->type;
        job_free(j);

        /* Fail depending jobs on failure */
        if (!success) {

                if (t == JOB_START ||
                    t == JOB_VERIFY_ACTIVE ||
                    t == JOB_RELOAD_OR_START) {

                        SET_FOREACH(other, n->meta.dependencies[NAME_REQUIRED_BY], state)
                                if (other->meta.job &&
                                    (other->meta.type == JOB_START ||
                                     other->meta.type == JOB_VERIFY_ACTIVE ||
                                     other->meta.type == JOB_RELOAD_OR_START))
                                        job_finish_and_invalidate(other->meta.job, false);

                        SET_FOREACH(other, n->meta.dependencies[NAME_SOFT_REQUIRED_BY], state)
                                if (other->meta.job &&
                                    !other->meta.job->forced &&
                                    (other->meta.type == JOB_START ||
                                     other->meta.type == JOB_VERIFY_ACTIVE ||
                                     other->meta.type == JOB_RELOAD_OR_START))
                                        job_finish_and_invalidate(other->meta.job, false);

                } else if (t == JOB_STOP) {

                        SET_FOREACH(other, n->meta.dependencies[NAME_CONFLICTS], state)
                                if (other->meta.job &&
                                    (t == JOB_START ||
                                     t == JOB_VERIFY_ACTIVE ||
                                     t == JOB_RELOAD_OR_START))
                                        job_finish_and_invalidate(other->meta.job, false);
                }
        }

        /* Try to start the next jobs that can be started */
        SET_FOREACH(other, n->meta.dependencies[NAME_AFTER], state)
                if (other->meta.job)
                        job_run_and_invalidate(other->meta.job);
        SET_FOREACH(other, n->meta.dependencies[NAME_BEFORE], state)
                if (other->meta.job)
                        job_run_and_invalidate(other->meta.job);

        return 0;
}
