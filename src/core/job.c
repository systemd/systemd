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

#include <assert.h>
#include <errno.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>

#include "set.h"
#include "unit.h"
#include "macro.h"
#include "strv.h"
#include "load-fragment.h"
#include "load-dropin.h"
#include "log.h"
#include "dbus-job.h"

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

        j->timer_watch.type = WATCH_INVALID;

        /* We don't link it here, that's what job_dependency() is for */

        return j;
}

void job_uninstall(Job *j) {
        assert(j->installed);
        /* Detach from next 'bigger' objects */

        bus_job_send_removed_signal(j);

        if (j->unit->job == j) {
                j->unit->job = NULL;
                unit_add_to_gc_queue(j->unit);
        }

        hashmap_remove(j->manager->jobs, UINT32_TO_PTR(j->id));
        j->installed = false;
}

void job_free(Job *j) {
        assert(j);
        assert(!j->installed);
        assert(!j->transaction_prev);
        assert(!j->transaction_next);
        assert(!j->subject_list);
        assert(!j->object_list);

        if (j->in_run_queue)
                LIST_REMOVE(Job, run_queue, j->manager->run_queue, j);

        if (j->in_dbus_queue)
                LIST_REMOVE(Job, dbus_queue, j->manager->dbus_job_queue, j);

        if (j->timer_watch.type != WATCH_INVALID) {
                assert(j->timer_watch.type == WATCH_JOB_TIMER);
                assert(j->timer_watch.data.job == j);
                assert(j->timer_watch.fd >= 0);

                assert_se(epoll_ctl(j->manager->epoll_fd, EPOLL_CTL_DEL, j->timer_watch.fd, NULL) >= 0);
                close_nointr_nofail(j->timer_watch.fd);
        }

        free(j->bus_client);
        free(j);
}

JobDependency* job_dependency_new(Job *subject, Job *object, bool matters, bool conflicts, Transaction *tr) {
        JobDependency *l;

        assert(object);

        /* Adds a new job link, which encodes that the 'subject' job
         * needs the 'object' job in some way. If 'subject' is NULL
         * this means the 'anchor' job (i.e. the one the user
         * explicitly asked for) is the requester. */

        if (!(l = new0(JobDependency, 1)))
                return NULL;

        l->subject = subject;
        l->object = object;
        l->matters = matters;
        l->conflicts = conflicts;

        if (subject)
                LIST_PREPEND(JobDependency, subject, subject->subject_list, l);
        else
                LIST_PREPEND(JobDependency, subject, tr->anchor, l);

        LIST_PREPEND(JobDependency, object, object->object_list, l);

        return l;
}

void job_dependency_free(JobDependency *l, Transaction *tr) {
        assert(l);

        if (l->subject)
                LIST_REMOVE(JobDependency, subject, l->subject->subject_list, l);
        else
                LIST_REMOVE(JobDependency, subject, tr->anchor, l);

        LIST_REMOVE(JobDependency, object, l->object->object_list, l);

        free(l);
}

void job_dump(Job *j, FILE*f, const char *prefix) {
        assert(j);
        assert(f);

        if (!prefix)
                prefix = "";

        fprintf(f,
                "%s-> Job %u:\n"
                "%s\tAction: %s -> %s\n"
                "%s\tState: %s\n"
                "%s\tForced: %s\n",
                prefix, j->id,
                prefix, j->unit->id, job_type_to_string(j->type),
                prefix, job_state_to_string(j->state),
                prefix, yes_no(j->override));
}

bool job_is_anchor(Job *j) {
        JobDependency *l;

        assert(j);

        LIST_FOREACH(object, l, j->object_list)
                if (!l->subject)
                        return true;

        return false;
}

/*
 * Merging is commutative, so imagine the matrix as symmetric. We store only
 * its lower triangle to avoid duplication. We don't store the main diagonal,
 * because A merged with A is simply A.
 *
 * Merging is associative! A merged with B merged with C is the same as
 * A merged with C merged with B.
 *
 * Mergeability is transitive! If A can be merged with B and B with C then
 * A also with C.
 *
 * Also, if A merged with B cannot be merged with C, then either A or B cannot
 * be merged with C either.
 */
static const JobType job_merging_table[] = {
/* What \ With       *  JOB_START         JOB_VERIFY_ACTIVE  JOB_STOP JOB_RELOAD   JOB_RELOAD_OR_START  JOB_RESTART JOB_TRY_RESTART */
/************************************************************************************************************************************/
/*JOB_START          */
/*JOB_VERIFY_ACTIVE  */ JOB_START,
/*JOB_STOP           */ -1,                  -1,
/*JOB_RELOAD         */ JOB_RELOAD_OR_START, JOB_RELOAD,          -1,
/*JOB_RELOAD_OR_START*/ JOB_RELOAD_OR_START, JOB_RELOAD_OR_START, -1, JOB_RELOAD_OR_START,
/*JOB_RESTART        */ JOB_RESTART,         JOB_RESTART,         -1, JOB_RESTART,         JOB_RESTART,
/*JOB_TRY_RESTART    */ JOB_RESTART,         JOB_TRY_RESTART,     -1, JOB_TRY_RESTART,     JOB_RESTART, JOB_RESTART,
};

JobType job_type_lookup_merge(JobType a, JobType b) {
        assert_cc(ELEMENTSOF(job_merging_table) == _JOB_TYPE_MAX * (_JOB_TYPE_MAX - 1) / 2);
        assert(a >= 0 && a < _JOB_TYPE_MAX);
        assert(b >= 0 && b < _JOB_TYPE_MAX);

        if (a == b)
                return a;

        if (a < b) {
                JobType tmp = a;
                a = b;
                b = tmp;
        }

        return job_merging_table[(a - 1) * a / 2 + b];
}

bool job_type_is_redundant(JobType a, UnitActiveState b) {
        switch (a) {

        case JOB_START:
                return
                        b == UNIT_ACTIVE ||
                        b == UNIT_RELOADING;

        case JOB_STOP:
                return
                        b == UNIT_INACTIVE ||
                        b == UNIT_FAILED;

        case JOB_VERIFY_ACTIVE:
                return
                        b == UNIT_ACTIVE ||
                        b == UNIT_RELOADING;

        case JOB_RELOAD:
                return
                        b == UNIT_RELOADING;

        case JOB_RELOAD_OR_START:
                return
                        b == UNIT_ACTIVATING ||
                        b == UNIT_RELOADING;

        case JOB_RESTART:
                return
                        b == UNIT_ACTIVATING;

        case JOB_TRY_RESTART:
                return
                        b == UNIT_ACTIVATING;

        default:
                assert_not_reached("Invalid job type");
        }
}

bool job_is_runnable(Job *j) {
        Iterator i;
        Unit *other;

        assert(j);
        assert(j->installed);

        /* Checks whether there is any job running for the units this
         * job needs to be running after (in the case of a 'positive'
         * job type) or before (in the case of a 'negative' job
         * type. */

        /* First check if there is an override */
        if (j->ignore_order)
                return true;

        if (j->type == JOB_START ||
            j->type == JOB_VERIFY_ACTIVE ||
            j->type == JOB_RELOAD ||
            j->type == JOB_RELOAD_OR_START) {

                /* Immediate result is that the job is or might be
                 * started. In this case lets wait for the
                 * dependencies, regardless whether they are
                 * starting or stopping something. */

                SET_FOREACH(other, j->unit->dependencies[UNIT_AFTER], i)
                        if (other->job)
                                return false;
        }

        /* Also, if something else is being stopped and we should
         * change state after it, then lets wait. */

        SET_FOREACH(other, j->unit->dependencies[UNIT_BEFORE], i)
                if (other->job &&
                    (other->job->type == JOB_STOP ||
                     other->job->type == JOB_RESTART ||
                     other->job->type == JOB_TRY_RESTART))
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

static void job_change_type(Job *j, JobType newtype) {
        log_debug("Converting job %s/%s -> %s/%s",
                  j->unit->id, job_type_to_string(j->type),
                  j->unit->id, job_type_to_string(newtype));

        j->type = newtype;
}

int job_run_and_invalidate(Job *j) {
        int r;
        uint32_t id;
        Manager *m;

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
        job_add_to_dbus_queue(j);

        /* While we execute this operation the job might go away (for
         * example: because it is replaced by a new, conflicting
         * job.) To make sure we don't access a freed job later on we
         * store the id here, so that we can verify the job is still
         * valid. */
        id = j->id;
        m = j->manager;

        switch (j->type) {

                case JOB_RELOAD_OR_START:
                        if (unit_active_state(j->unit) == UNIT_ACTIVE) {
                                job_change_type(j, JOB_RELOAD);
                                r = unit_reload(j->unit);
                                break;
                        }
                        job_change_type(j, JOB_START);
                        /* fall through */

                case JOB_START:
                        r = unit_start(j->unit);

                        /* If this unit cannot be started, then simply wait */
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

                case JOB_TRY_RESTART:
                        if (UNIT_IS_INACTIVE_OR_DEACTIVATING(unit_active_state(j->unit))) {
                                r = -ENOEXEC;
                                break;
                        }
                        job_change_type(j, JOB_RESTART);
                        /* fall through */

                case JOB_STOP:
                case JOB_RESTART:
                        r = unit_stop(j->unit);

                        /* If this unit cannot stopped, then simply wait. */
                        if (r == -EBADR)
                                r = 0;
                        break;

                case JOB_RELOAD:
                        r = unit_reload(j->unit);
                        break;

                default:
                        assert_not_reached("Unknown job type");
        }

        if ((j = manager_get_job(m, id))) {
                if (r == -EALREADY)
                        r = job_finish_and_invalidate(j, JOB_DONE);
                else if (r == -ENOEXEC)
                        r = job_finish_and_invalidate(j, JOB_SKIPPED);
                else if (r == -EAGAIN)
                        j->state = JOB_WAITING;
                else if (r < 0)
                        r = job_finish_and_invalidate(j, JOB_FAILED);
        }

        return r;
}

static void job_print_status_message(Unit *u, JobType t, JobResult result) {
        assert(u);

        if (t == JOB_START) {

                switch (result) {

                case JOB_DONE:
                        if (u->condition_result)
                                unit_status_printf(u, ANSI_HIGHLIGHT_GREEN_ON "  OK  " ANSI_HIGHLIGHT_OFF, "Started %s", unit_description(u));
                        break;

                case JOB_FAILED:
                        unit_status_printf(u, ANSI_HIGHLIGHT_RED_ON "FAILED" ANSI_HIGHLIGHT_OFF, "Failed to start %s", unit_description(u));
                        unit_status_printf(u, NULL, "See 'systemctl status %s' for details.", u->id);
                        break;

                case JOB_DEPENDENCY:
                        unit_status_printf(u, ANSI_HIGHLIGHT_RED_ON " ABORT" ANSI_HIGHLIGHT_OFF, "Dependency failed. Aborted start of %s", unit_description(u));
                        break;

                case JOB_TIMEOUT:
                        unit_status_printf(u, ANSI_HIGHLIGHT_RED_ON " TIME " ANSI_HIGHLIGHT_OFF, "Timed out starting %s", unit_description(u));
                        break;

                default:
                        ;
                }

        } else if (t == JOB_STOP) {

                switch (result) {

                case JOB_TIMEOUT:
                        unit_status_printf(u, ANSI_HIGHLIGHT_RED_ON " TIME " ANSI_HIGHLIGHT_OFF, "Timed out stopping %s", unit_description(u));
                        break;

                case JOB_DONE:
                case JOB_FAILED:
                        unit_status_printf(u, ANSI_HIGHLIGHT_GREEN_ON "  OK  " ANSI_HIGHLIGHT_OFF, "Stopped %s", unit_description(u));
                        break;

                default:
                        ;
                }
        }
}

int job_finish_and_invalidate(Job *j, JobResult result) {
        Unit *u;
        Unit *other;
        JobType t;
        Iterator i;
        bool recursed = false;

        assert(j);
        assert(j->installed);

        job_add_to_dbus_queue(j);

        /* Patch restart jobs so that they become normal start jobs */
        if (result == JOB_DONE && j->type == JOB_RESTART) {

                job_change_type(j, JOB_START);
                j->state = JOB_WAITING;

                job_add_to_run_queue(j);

                u = j->unit;
                goto finish;
        }

        j->result = result;

        log_debug("Job %s/%s finished, result=%s", j->unit->id, job_type_to_string(j->type), job_result_to_string(result));

        if (result == JOB_FAILED)
                j->manager->n_failed_jobs ++;

        u = j->unit;
        t = j->type;
        job_uninstall(j);
        job_free(j);

        job_print_status_message(u, t, result);

        /* Fail depending jobs on failure */
        if (result != JOB_DONE) {

                if (t == JOB_START ||
                    t == JOB_VERIFY_ACTIVE ||
                    t == JOB_RELOAD_OR_START) {

                        SET_FOREACH(other, u->dependencies[UNIT_REQUIRED_BY], i)
                                if (other->job &&
                                    (other->job->type == JOB_START ||
                                     other->job->type == JOB_VERIFY_ACTIVE ||
                                     other->job->type == JOB_RELOAD_OR_START)) {
                                        job_finish_and_invalidate(other->job, JOB_DEPENDENCY);
                                        recursed = true;
                                }

                        SET_FOREACH(other, u->dependencies[UNIT_BOUND_BY], i)
                                if (other->job &&
                                    (other->job->type == JOB_START ||
                                     other->job->type == JOB_VERIFY_ACTIVE ||
                                     other->job->type == JOB_RELOAD_OR_START)) {
                                        job_finish_and_invalidate(other->job, JOB_DEPENDENCY);
                                        recursed = true;
                                }

                        SET_FOREACH(other, u->dependencies[UNIT_REQUIRED_BY_OVERRIDABLE], i)
                                if (other->job &&
                                    !other->job->override &&
                                    (other->job->type == JOB_START ||
                                     other->job->type == JOB_VERIFY_ACTIVE ||
                                     other->job->type == JOB_RELOAD_OR_START)) {
                                        job_finish_and_invalidate(other->job, JOB_DEPENDENCY);
                                        recursed = true;
                                }

                } else if (t == JOB_STOP) {

                        SET_FOREACH(other, u->dependencies[UNIT_CONFLICTED_BY], i)
                                if (other->job &&
                                    (other->job->type == JOB_START ||
                                     other->job->type == JOB_VERIFY_ACTIVE ||
                                     other->job->type == JOB_RELOAD_OR_START)) {
                                        job_finish_and_invalidate(other->job, JOB_DEPENDENCY);
                                        recursed = true;
                                }
                }
        }

        /* Trigger OnFailure dependencies that are not generated by
         * the unit itself. We don't tread JOB_CANCELED as failure in
         * this context. And JOB_FAILURE is already handled by the
         * unit itself. */
        if (result == JOB_TIMEOUT || result == JOB_DEPENDENCY) {
                log_notice("Job %s/%s failed with result '%s'.",
                           u->id,
                           job_type_to_string(t),
                           job_result_to_string(result));

                unit_trigger_on_failure(u);
        }

finish:
        /* Try to start the next jobs that can be started */
        SET_FOREACH(other, u->dependencies[UNIT_AFTER], i)
                if (other->job)
                        job_add_to_run_queue(other->job);
        SET_FOREACH(other, u->dependencies[UNIT_BEFORE], i)
                if (other->job)
                        job_add_to_run_queue(other->job);

        manager_check_finished(u->manager);

        return recursed;
}

int job_start_timer(Job *j) {
        struct itimerspec its;
        struct epoll_event ev;
        int fd, r;
        assert(j);

        if (j->unit->job_timeout <= 0 ||
            j->timer_watch.type == WATCH_JOB_TIMER)
                return 0;

        assert(j->timer_watch.type == WATCH_INVALID);

        if ((fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK|TFD_CLOEXEC)) < 0) {
                r = -errno;
                goto fail;
        }

        zero(its);
        timespec_store(&its.it_value, j->unit->job_timeout);

        if (timerfd_settime(fd, 0, &its, NULL) < 0) {
                r = -errno;
                goto fail;
        }

        zero(ev);
        ev.data.ptr = &j->timer_watch;
        ev.events = EPOLLIN;

        if (epoll_ctl(j->manager->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
                r = -errno;
                goto fail;
        }

        j->timer_watch.type = WATCH_JOB_TIMER;
        j->timer_watch.fd = fd;
        j->timer_watch.data.job = j;

        return 0;

fail:
        if (fd >= 0)
                close_nointr_nofail(fd);

        return r;
}

void job_add_to_run_queue(Job *j) {
        assert(j);
        assert(j->installed);

        if (j->in_run_queue)
                return;

        LIST_PREPEND(Job, run_queue, j->manager->run_queue, j);
        j->in_run_queue = true;
}

void job_add_to_dbus_queue(Job *j) {
        assert(j);
        assert(j->installed);

        if (j->in_dbus_queue)
                return;

        /* We don't check if anybody is subscribed here, since this
         * job might just have been created and not yet assigned to a
         * connection/client. */

        LIST_PREPEND(Job, dbus_queue, j->manager->dbus_job_queue, j);
        j->in_dbus_queue = true;
}

char *job_dbus_path(Job *j) {
        char *p;

        assert(j);

        if (asprintf(&p, "/org/freedesktop/systemd1/job/%lu", (unsigned long) j->id) < 0)
                return NULL;

        return p;
}

void job_timer_event(Job *j, uint64_t n_elapsed, Watch *w) {
        assert(j);
        assert(w == &j->timer_watch);

        log_warning("Job %s/%s timed out.", j->unit->id, job_type_to_string(j->type));
        job_finish_and_invalidate(j, JOB_TIMEOUT);
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
        [JOB_REPLACE] = "replace",
        [JOB_ISOLATE] = "isolate",
        [JOB_IGNORE_DEPENDENCIES] = "ignore-dependencies",
        [JOB_IGNORE_REQUIREMENTS] = "ignore-requirements"
};

DEFINE_STRING_TABLE_LOOKUP(job_mode, JobMode);

static const char* const job_result_table[_JOB_RESULT_MAX] = {
        [JOB_DONE] = "done",
        [JOB_CANCELED] = "canceled",
        [JOB_TIMEOUT] = "timeout",
        [JOB_FAILED] = "failed",
        [JOB_DEPENDENCY] = "dependency",
        [JOB_SKIPPED] = "skipped"
};

DEFINE_STRING_TABLE_LOOKUP(job_result, JobResult);
