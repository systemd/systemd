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
        }

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
                [JOB_STOP] = "stop",
                [JOB_VERIFY_STARTED] = "verify-started",
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
                [JOB_RUNNING] = "running",
                [JOB_DONE] = "done"
        };

        assert(j);
        assert(f);

        fprintf(f,
                "%sJob %u:\n"
                "%s\tAction: %s → %s\n"
                "%s\tState: %s\n",
                prefix, j->id,
                prefix, name_id(j->name), job_type_to_string(j->type),
                prefix, job_state_table[j->state]);
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
        else
                return -EEXIST;

        return 0;
}

bool job_type_mergeable(JobType a, JobType b) {
        return job_type_merge(&a, b) >= 0;
}

bool job_type_is_superset(JobType a, JobType b) {

        /* Checks whether operation a is a "superset" of b */

        if (a == b)
                return true;

        switch (a) {
                case JOB_START:
                        return b == JOB_VERIFY_STARTED;

                case JOB_RELOAD:
                        return b == JOB_VERIFY_STARTED;

                case JOB_RELOAD_OR_START:
                        return
                                b == JOB_RELOAD ||
                                b == JOB_START;

                case JOB_RESTART:
                        return
                                b == JOB_START ||
                                b == JOB_VERIFY_STARTED ||
                                b == JOB_RELOAD ||
                                b == JOB_RELOAD_OR_START ||
                                b == JOB_TRY_RESTART;

                case JOB_TRY_RESTART:
                        return
                                b == JOB_VERIFY_STARTED ||
                                b == JOB_RELOAD;
                default:
                        return false;

        }
}

bool job_type_is_conflicting(JobType a, JobType b) {
        assert(a >= 0 && a < _JOB_TYPE_MAX);
        assert(b >= 0 && b < _JOB_TYPE_MAX);

        return
                (a == JOB_STOP && b != JOB_STOP) ||
                (b == JOB_STOP && a != JOB_STOP);
}

bool job_type_applicable(JobType j, NameType n) {
        assert(j >= 0 && j < _JOB_TYPE_MAX);
        assert(n >= 0 && n < _NAME_TYPE_MAX);

        switch (j) {
                case JOB_START:
                case JOB_STOP:
                case JOB_VERIFY_STARTED:
                        return true;

                case JOB_RELOAD:
                case JOB_RELOAD_OR_START:
                        return n == NAME_SERVICE || n == NAME_TIMER || n == NAME_MOUNT;

                case JOB_RESTART:
                case JOB_TRY_RESTART:
                        return n == NAME_SERVICE || n == NAME_TIMER || n == NAME_SOCKET || NAME_MOUNT || NAME_SNAPSHOT;

                default:
                        assert_not_reached("Invalid job type");
        }
}
