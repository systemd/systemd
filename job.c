/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <assert.h>

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

        manager_transaction_delete_job(j->manager, j);

        free(j);
}

JobDependency* job_dependency_new(Job *subject, Job *object, bool matters) {
        JobDependency *l;

        assert(object);

        /* Adds a new job link, which encodes that the 'subject' job
         * needs the 'object' job in some way. If 'subject' is NULL
         * this means the 'anchor' job (i.e. the one the user
         * explcitily asked for) is the requester. */

        if (!(l = new(JobDependency, 1)))
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

void job_dump(Job *j, FILE*f) {

        static const char* const job_type_table[_JOB_TYPE_MAX] = {
                [JOB_START] = "start",
                [JOB_STOP] = "stop",
                [JOB_VERIFY_STARTED] = "verify-started",
                [JOB_RELOAD] = "reload",
                [JOB_RELOAD_OR_START] = "reload-or-start",
                [JOB_RESTART] = "restart",
                [JOB_TRY_RESTART] = "try-restart",
        };

        static const char* const job_state_table[_JOB_STATE_MAX] = {
                [JOB_WAITING] = "waiting",
                [JOB_RUNNING] = "running",
                [JOB_DONE] = "done"
        };

        assert(j);
        assert(f);

        fprintf(f, "Job %u (%s) → %s in state %s\n",
                j->id,
                name_id(j->name),
                job_type_table[j->type],
                job_state_table[j->state]);
}

bool job_is_anchor(Job *j) {
        JobDependency *l;

        assert(j);

        for (l = j->object_list; l; l = l->object_next)
                if (!l->subject)
                        return true;

        return false;
}
