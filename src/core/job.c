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

#include "sd-id128.h"
#include "sd-messages.h"
#include "set.h"
#include "unit.h"
#include "macro.h"
#include "strv.h"
#include "load-fragment.h"
#include "load-dropin.h"
#include "log.h"
#include "dbus-job.h"
#include "special.h"
#include "async.h"
#include "virt.h"
#include "dbus.h"

Job* job_new_raw(Unit *unit) {
        Job *j;

        /* used for deserialization */

        assert(unit);

        j = new0(Job, 1);
        if (!j)
                return NULL;

        j->manager = unit->manager;
        j->unit = unit;
        j->type = _JOB_TYPE_INVALID;

        return j;
}

Job* job_new(Unit *unit, JobType type) {
        Job *j;

        assert(type < _JOB_TYPE_MAX);

        j = job_new_raw(unit);
        if (!j)
                return NULL;

        j->id = j->manager->current_job_id++;
        j->type = type;

        /* We don't link it here, that's what job_dependency() is for */

        return j;
}

void job_free(Job *j) {
        assert(j);
        assert(!j->installed);
        assert(!j->transaction_prev);
        assert(!j->transaction_next);
        assert(!j->subject_list);
        assert(!j->object_list);

        if (j->in_run_queue)
                LIST_REMOVE(run_queue, j->manager->run_queue, j);

        if (j->in_dbus_queue)
                LIST_REMOVE(dbus_queue, j->manager->dbus_job_queue, j);

        sd_event_source_unref(j->timer_event_source);

        sd_bus_track_unref(j->subscribed);
        strv_free(j->deserialized_subscribed);

        free(j);
}

void job_uninstall(Job *j) {
        Job **pj;

        assert(j->installed);

        pj = (j->type == JOB_NOP) ? &j->unit->nop_job : &j->unit->job;
        assert(*pj == j);

        /* Detach from next 'bigger' objects */

        /* daemon-reload should be transparent to job observers */
        if (j->manager->n_reloading <= 0)
                bus_job_send_removed_signal(j);

        *pj = NULL;

        unit_add_to_gc_queue(j->unit);

        hashmap_remove(j->manager->jobs, UINT32_TO_PTR(j->id));
        j->installed = false;
}

static bool job_type_allows_late_merge(JobType t) {
        /* Tells whether it is OK to merge a job of type 't' with an already
         * running job.
         * Reloads cannot be merged this way. Think of the sequence:
         * 1. Reload of a daemon is in progress; the daemon has already loaded
         *    its config file, but hasn't completed the reload operation yet.
         * 2. Edit foo's config file.
         * 3. Trigger another reload to have the daemon use the new config.
         * Should the second reload job be merged into the first one, the daemon
         * would not know about the new config.
         * JOB_RESTART jobs on the other hand can be merged, because they get
         * patched into JOB_START after stopping the unit. So if we see a
         * JOB_RESTART running, it means the unit hasn't stopped yet and at
         * this time the merge is still allowed. */
        return t != JOB_RELOAD;
}

static void job_merge_into_installed(Job *j, Job *other) {
        assert(j->installed);
        assert(j->unit == other->unit);

        if (j->type != JOB_NOP)
                job_type_merge_and_collapse(&j->type, other->type, j->unit);
        else
                assert(other->type == JOB_NOP);

        j->override = j->override || other->override;
        j->irreversible = j->irreversible || other->irreversible;
        j->ignore_order = j->ignore_order || other->ignore_order;
}

Job* job_install(Job *j) {
        Job **pj;
        Job *uj;

        assert(!j->installed);
        assert(j->type < _JOB_TYPE_MAX_IN_TRANSACTION);

        pj = (j->type == JOB_NOP) ? &j->unit->nop_job : &j->unit->job;
        uj = *pj;

        if (uj) {
                if (j->type != JOB_NOP && job_type_is_conflicting(uj->type, j->type))
                        job_finish_and_invalidate(uj, JOB_CANCELED, false);
                else {
                        /* not conflicting, i.e. mergeable */

                        if (j->type == JOB_NOP || uj->state == JOB_WAITING ||
                            (job_type_allows_late_merge(j->type) && job_type_is_superset(uj->type, j->type))) {
                                job_merge_into_installed(uj, j);
                                log_debug_unit(uj->unit->id,
                                               "Merged into installed job %s/%s as %u",
                                               uj->unit->id, job_type_to_string(uj->type), (unsigned) uj->id);
                                return uj;
                        } else {
                                /* already running and not safe to merge into */
                                /* Patch uj to become a merged job and re-run it. */
                                /* XXX It should be safer to queue j to run after uj finishes, but it is
                                 * not currently possible to have more than one installed job per unit. */
                                job_merge_into_installed(uj, j);
                                log_debug_unit(uj->unit->id,
                                               "Merged into running job, re-running: %s/%s as %u",
                                               uj->unit->id, job_type_to_string(uj->type), (unsigned) uj->id);
                                uj->state = JOB_WAITING;
                                uj->manager->n_running_jobs--;
                                return uj;
                        }
                }
        }

        /* Install the job */
        *pj = j;
        j->installed = true;
        j->manager->n_installed_jobs ++;
        log_debug_unit(j->unit->id,
                       "Installed new job %s/%s as %u",
                       j->unit->id, job_type_to_string(j->type), (unsigned) j->id);
        return j;
}

int job_install_deserialized(Job *j) {
        Job **pj;

        assert(!j->installed);

        if (j->type < 0 || j->type >= _JOB_TYPE_MAX_IN_TRANSACTION) {
                log_debug("Invalid job type %s in deserialization.", strna(job_type_to_string(j->type)));
                return -EINVAL;
        }

        pj = (j->type == JOB_NOP) ? &j->unit->nop_job : &j->unit->job;

        if (*pj) {
                log_debug_unit(j->unit->id,
                               "Unit %s already has a job installed. Not installing deserialized job.",
                               j->unit->id);
                return -EEXIST;
        }
        *pj = j;
        j->installed = true;
        log_debug_unit(j->unit->id,
                       "Reinstalled deserialized job %s/%s as %u",
                       j->unit->id, job_type_to_string(j->type), (unsigned) j->id);
        return 0;
}

JobDependency* job_dependency_new(Job *subject, Job *object, bool matters, bool conflicts) {
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
                LIST_PREPEND(subject, subject->subject_list, l);

        LIST_PREPEND(object, object->object_list, l);

        return l;
}

void job_dependency_free(JobDependency *l) {
        assert(l);

        if (l->subject)
                LIST_REMOVE(subject, l->subject->subject_list, l);

        LIST_REMOVE(object, l->object->object_list, l);

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
                "%s\tForced: %s\n"
                "%s\tIrreversible: %s\n",
                prefix, j->id,
                prefix, j->unit->id, job_type_to_string(j->type),
                prefix, job_state_to_string(j->state),
                prefix, yes_no(j->override),
                prefix, yes_no(j->irreversible));
}

/*
 * Merging is commutative, so imagine the matrix as symmetric. We store only
 * its lower triangle to avoid duplication. We don't store the main diagonal,
 * because A merged with A is simply A.
 *
 * If the resulting type is collapsed immediately afterwards (to get rid of
 * the JOB_RELOAD_OR_START, which lies outside the lookup function's domain),
 * the following properties hold:
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
/* What \ With       *  JOB_START         JOB_VERIFY_ACTIVE  JOB_STOP JOB_RELOAD */
/*********************************************************************************/
/*JOB_START          */
/*JOB_VERIFY_ACTIVE  */ JOB_START,
/*JOB_STOP           */ -1,                  -1,
/*JOB_RELOAD         */ JOB_RELOAD_OR_START, JOB_RELOAD,          -1,
/*JOB_RESTART        */ JOB_RESTART,         JOB_RESTART,         -1, JOB_RESTART,
};

JobType job_type_lookup_merge(JobType a, JobType b) {
        assert_cc(ELEMENTSOF(job_merging_table) == _JOB_TYPE_MAX_MERGING * (_JOB_TYPE_MAX_MERGING - 1) / 2);
        assert(a >= 0 && a < _JOB_TYPE_MAX_MERGING);
        assert(b >= 0 && b < _JOB_TYPE_MAX_MERGING);

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

        case JOB_RESTART:
                return
                        b == UNIT_ACTIVATING;

        default:
                assert_not_reached("Invalid job type");
        }
}

void job_type_collapse(JobType *t, Unit *u) {
        UnitActiveState s;

        switch (*t) {

        case JOB_TRY_RESTART:
                s = unit_active_state(u);
                if (UNIT_IS_INACTIVE_OR_DEACTIVATING(s))
                        *t = JOB_NOP;
                else
                        *t = JOB_RESTART;
                break;

        case JOB_RELOAD_OR_START:
                s = unit_active_state(u);
                if (UNIT_IS_INACTIVE_OR_DEACTIVATING(s))
                        *t = JOB_START;
                else
                        *t = JOB_RELOAD;
                break;

        default:
                ;
        }
}

int job_type_merge_and_collapse(JobType *a, JobType b, Unit *u) {
        JobType t = job_type_lookup_merge(*a, b);
        if (t < 0)
                return -EEXIST;
        *a = t;
        job_type_collapse(a, u);
        return 0;
}

static bool job_is_runnable(Job *j) {
        Iterator i;
        Unit *other;

        assert(j);
        assert(j->installed);

        /* Checks whether there is any job running for the units this
         * job needs to be running after (in the case of a 'positive'
         * job type) or before (in the case of a 'negative' job
         * type. */

        /* Note that unit types have a say in what is runnable,
         * too. For example, if they return -EAGAIN from
         * unit_start() they can indicate they are not
         * runnable yet. */

        /* First check if there is an override */
        if (j->ignore_order)
                return true;

        if (j->type == JOB_NOP)
                return true;

        if (j->type == JOB_START ||
            j->type == JOB_VERIFY_ACTIVE ||
            j->type == JOB_RELOAD) {

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
                     other->job->type == JOB_RESTART))
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
        log_debug_unit(j->unit->id,
                       "Converting job %s/%s -> %s/%s",
                       j->unit->id, job_type_to_string(j->type),
                       j->unit->id, job_type_to_string(newtype));

        j->type = newtype;
}

int job_run_and_invalidate(Job *j) {
        int r;
        uint32_t id;
        Manager *m = j->manager;

        assert(j);
        assert(j->installed);
        assert(j->type < _JOB_TYPE_MAX_IN_TRANSACTION);
        assert(j->in_run_queue);

        LIST_REMOVE(run_queue, j->manager->run_queue, j);
        j->in_run_queue = false;

        if (j->state != JOB_WAITING)
                return 0;

        if (!job_is_runnable(j))
                return -EAGAIN;

        j->state = JOB_RUNNING;
        m->n_running_jobs++;
        job_add_to_dbus_queue(j);

        /* While we execute this operation the job might go away (for
         * example: because it is replaced by a new, conflicting
         * job.) To make sure we don't access a freed job later on we
         * store the id here, so that we can verify the job is still
         * valid. */
        id = j->id;

        switch (j->type) {

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
                                r = -EBADR;
                        break;
                }

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

                case JOB_NOP:
                        r = -EALREADY;
                        break;

                default:
                        assert_not_reached("Unknown job type");
        }

        j = manager_get_job(m, id);
        if (j) {
                if (r == -EALREADY)
                        r = job_finish_and_invalidate(j, JOB_DONE, true);
                else if (r == -EBADR)
                        r = job_finish_and_invalidate(j, JOB_SKIPPED, true);
                else if (r == -ENOEXEC)
                        r = job_finish_and_invalidate(j, JOB_INVALID, true);
                else if (r == -EAGAIN) {
                        j->state = JOB_WAITING;
                        m->n_running_jobs--;
                } else if (r < 0)
                        r = job_finish_and_invalidate(j, JOB_FAILED, true);
        }

        return r;
}

_pure_ static const char *job_get_status_message_format(Unit *u, JobType t, JobResult result) {
        const UnitStatusMessageFormats *format_table;

        assert(u);
        assert(t >= 0);
        assert(t < _JOB_TYPE_MAX);

        format_table = &UNIT_VTABLE(u)->status_message_formats;
        if (!format_table)
                return NULL;

        if (t == JOB_START)
                return format_table->finished_start_job[result];
        else if (t == JOB_STOP || t == JOB_RESTART)
                return format_table->finished_stop_job[result];

        return NULL;
}

_pure_ static const char *job_get_status_message_format_try_harder(Unit *u, JobType t, JobResult result) {
        const char *format;

        assert(u);
        assert(t >= 0);
        assert(t < _JOB_TYPE_MAX);

        format = job_get_status_message_format(u, t, result);
        if (format)
                return format;

        /* Return generic strings */
        if (t == JOB_START) {
                if (result == JOB_DONE)
                        return "Started %s.";
                else if (result == JOB_FAILED)
                        return "Failed to start %s.";
                else if (result == JOB_DEPENDENCY)
                        return "Dependency failed for %s.";
                else if (result == JOB_TIMEOUT)
                        return "Timed out starting %s.";
        } else if (t == JOB_STOP || t == JOB_RESTART) {
                if (result == JOB_DONE)
                        return "Stopped %s.";
                else if (result == JOB_FAILED)
                        return "Stopped (with error) %s.";
                else if (result == JOB_TIMEOUT)
                        return "Timed out stoppping %s.";
        } else if (t == JOB_RELOAD) {
                if (result == JOB_DONE)
                        return "Reloaded %s.";
                else if (result == JOB_FAILED)
                        return "Reload failed for %s.";
                else if (result == JOB_TIMEOUT)
                        return "Timed out reloading %s.";
        }

        return NULL;
}

static void job_print_status_message(Unit *u, JobType t, JobResult result) {
        const char *format;

        assert(u);
        assert(t >= 0);
        assert(t < _JOB_TYPE_MAX);

        DISABLE_WARNING_FORMAT_NONLITERAL;

        if (t == JOB_START) {
                format = job_get_status_message_format(u, t, result);
                if (!format)
                        return;

                switch (result) {

                case JOB_DONE:
                        if (u->condition_result)
                                unit_status_printf(u, ANSI_GREEN_ON "  OK  " ANSI_HIGHLIGHT_OFF, format);
                        break;

                case JOB_FAILED:
                        manager_flip_auto_status(u->manager, true);
                        unit_status_printf(u, ANSI_HIGHLIGHT_RED_ON "FAILED" ANSI_HIGHLIGHT_OFF, format);
                        manager_status_printf(u->manager, false, NULL, "See 'systemctl status %s' for details.", u->id);
                        break;

                case JOB_DEPENDENCY:
                        manager_flip_auto_status(u->manager, true);
                        unit_status_printf(u, ANSI_HIGHLIGHT_YELLOW_ON "DEPEND" ANSI_HIGHLIGHT_OFF, format);
                        break;

                case JOB_TIMEOUT:
                        manager_flip_auto_status(u->manager, true);
                        unit_status_printf(u, ANSI_HIGHLIGHT_RED_ON " TIME " ANSI_HIGHLIGHT_OFF, format);
                        break;

                default:
                        ;
                }

        } else if (t == JOB_STOP || t == JOB_RESTART) {

                format = job_get_status_message_format(u, t, result);
                if (!format)
                        return;

                switch (result) {

                case JOB_TIMEOUT:
                        manager_flip_auto_status(u->manager, true);
                        unit_status_printf(u, ANSI_HIGHLIGHT_RED_ON " TIME " ANSI_HIGHLIGHT_OFF, format);
                        break;

                case JOB_DONE:
                case JOB_FAILED:
                        unit_status_printf(u, ANSI_GREEN_ON "  OK  " ANSI_HIGHLIGHT_OFF, format);
                        break;

                default:
                        ;
                }

        } else if (t == JOB_VERIFY_ACTIVE) {

                /* When verify-active detects the unit is inactive, report it.
                 * Most likely a DEPEND warning from a requisiting unit will
                 * occur next and it's nice to see what was requisited. */
                if (result == JOB_SKIPPED)
                        unit_status_printf(u, ANSI_HIGHLIGHT_ON " INFO " ANSI_HIGHLIGHT_OFF, "%s is not active.");
        }

        REENABLE_WARNING;
}

static void job_log_status_message(Unit *u, JobType t, JobResult result) {
        const char *format;
        char buf[LINE_MAX];

        assert(u);
        assert(t >= 0);
        assert(t < _JOB_TYPE_MAX);

        /* Skip this if it goes to the console. since we already print
         * to the console anyway... */

        if (log_on_console())
                return;

        format = job_get_status_message_format_try_harder(u, t, result);
        if (!format)
                return;

        DISABLE_WARNING_FORMAT_NONLITERAL;
        snprintf(buf, sizeof(buf), format, unit_description(u));
        char_array_0(buf);
        REENABLE_WARNING;

        if (t == JOB_START) {
                sd_id128_t mid;

                mid = result == JOB_DONE ? SD_MESSAGE_UNIT_STARTED : SD_MESSAGE_UNIT_FAILED;
                log_struct_unit(result == JOB_DONE ? LOG_INFO : LOG_ERR,
                           u->id,
                           MESSAGE_ID(mid),
                           "RESULT=%s", job_result_to_string(result),
                           "MESSAGE=%s", buf,
                           NULL);

        } else if (t == JOB_STOP)
                log_struct_unit(result == JOB_DONE ? LOG_INFO : LOG_ERR,
                           u->id,
                           MESSAGE_ID(SD_MESSAGE_UNIT_STOPPED),
                           "RESULT=%s", job_result_to_string(result),
                           "MESSAGE=%s", buf,
                           NULL);

        else if (t == JOB_RELOAD)
                log_struct_unit(result == JOB_DONE ? LOG_INFO : LOG_ERR,
                           u->id,
                           MESSAGE_ID(SD_MESSAGE_UNIT_RELOADED),
                           "RESULT=%s", job_result_to_string(result),
                           "MESSAGE=%s", buf,
                           NULL);
}

int job_finish_and_invalidate(Job *j, JobResult result, bool recursive) {
        Unit *u;
        Unit *other;
        JobType t;
        Iterator i;

        assert(j);
        assert(j->installed);
        assert(j->type < _JOB_TYPE_MAX_IN_TRANSACTION);

        u = j->unit;
        t = j->type;

        j->result = result;

        if (j->state == JOB_RUNNING)
                j->manager->n_running_jobs--;

        log_debug_unit(u->id, "Job %s/%s finished, result=%s",
                       u->id, job_type_to_string(t), job_result_to_string(result));

        job_print_status_message(u, t, result);
        job_log_status_message(u, t, result);

        job_add_to_dbus_queue(j);

        /* Patch restart jobs so that they become normal start jobs */
        if (result == JOB_DONE && t == JOB_RESTART) {

                job_change_type(j, JOB_START);
                j->state = JOB_WAITING;

                job_add_to_run_queue(j);

                goto finish;
        }

        if (result == JOB_FAILED || result == JOB_INVALID)
                j->manager->n_failed_jobs ++;

        job_uninstall(j);
        job_free(j);

        /* Fail depending jobs on failure */
        if (result != JOB_DONE && recursive) {

                if (t == JOB_START ||
                    t == JOB_VERIFY_ACTIVE) {

                        SET_FOREACH(other, u->dependencies[UNIT_REQUIRED_BY], i)
                                if (other->job &&
                                    (other->job->type == JOB_START ||
                                     other->job->type == JOB_VERIFY_ACTIVE))
                                        job_finish_and_invalidate(other->job, JOB_DEPENDENCY, true);

                        SET_FOREACH(other, u->dependencies[UNIT_BOUND_BY], i)
                                if (other->job &&
                                    (other->job->type == JOB_START ||
                                     other->job->type == JOB_VERIFY_ACTIVE))
                                        job_finish_and_invalidate(other->job, JOB_DEPENDENCY, true);

                        SET_FOREACH(other, u->dependencies[UNIT_REQUIRED_BY_OVERRIDABLE], i)
                                if (other->job &&
                                    !other->job->override &&
                                    (other->job->type == JOB_START ||
                                     other->job->type == JOB_VERIFY_ACTIVE))
                                        job_finish_and_invalidate(other->job, JOB_DEPENDENCY, true);

                } else if (t == JOB_STOP) {

                        SET_FOREACH(other, u->dependencies[UNIT_CONFLICTED_BY], i)
                                if (other->job &&
                                    (other->job->type == JOB_START ||
                                     other->job->type == JOB_VERIFY_ACTIVE))
                                        job_finish_and_invalidate(other->job, JOB_DEPENDENCY, true);
                }
        }

        /* Trigger OnFailure dependencies that are not generated by
         * the unit itself. We don't treat JOB_CANCELED as failure in
         * this context. And JOB_FAILURE is already handled by the
         * unit itself. */
        if (result == JOB_TIMEOUT || result == JOB_DEPENDENCY) {
                log_struct_unit(LOG_NOTICE,
                           u->id,
                           "JOB_TYPE=%s", job_type_to_string(t),
                           "JOB_RESULT=%s", job_result_to_string(result),
                           "Job %s/%s failed with result '%s'.",
                           u->id,
                           job_type_to_string(t),
                           job_result_to_string(result),
                           NULL);

                unit_start_on_failure(u);
        }

        unit_trigger_notify(u);

finish:
        /* Try to start the next jobs that can be started */
        SET_FOREACH(other, u->dependencies[UNIT_AFTER], i)
                if (other->job)
                        job_add_to_run_queue(other->job);
        SET_FOREACH(other, u->dependencies[UNIT_BEFORE], i)
                if (other->job)
                        job_add_to_run_queue(other->job);

        manager_check_finished(u->manager);

        return 0;
}

static int job_dispatch_timer(sd_event_source *s, uint64_t monotonic, void *userdata) {
        Job *j = userdata;

        assert(j);
        assert(s == j->timer_event_source);

        log_warning_unit(j->unit->id, "Job %s/%s timed out.",
                         j->unit->id, job_type_to_string(j->type));

        job_finish_and_invalidate(j, JOB_TIMEOUT, true);
        return 0;
}

int job_start_timer(Job *j) {
        int r;

        if (j->timer_event_source)
                return 0;

        j->begin_usec = now(CLOCK_MONOTONIC);

        if (j->unit->job_timeout <= 0)
                return 0;

        r = sd_event_add_time(
                        j->manager->event,
                        &j->timer_event_source,
                        CLOCK_MONOTONIC,
                        j->begin_usec + j->unit->job_timeout, 0,
                        job_dispatch_timer, j);
        if (r < 0)
                return r;

        return 0;
}

void job_add_to_run_queue(Job *j) {
        assert(j);
        assert(j->installed);

        if (j->in_run_queue)
                return;

        if (!j->manager->run_queue)
                sd_event_source_set_enabled(j->manager->run_queue_event_source, SD_EVENT_ONESHOT);

        LIST_PREPEND(run_queue, j->manager->run_queue, j);
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

        LIST_PREPEND(dbus_queue, j->manager->dbus_job_queue, j);
        j->in_dbus_queue = true;
}

char *job_dbus_path(Job *j) {
        char *p;

        assert(j);

        if (asprintf(&p, "/org/freedesktop/systemd1/job/%"PRIu32, j->id) < 0)
                return NULL;

        return p;
}

int job_serialize(Job *j, FILE *f, FDSet *fds) {
        fprintf(f, "job-id=%u\n", j->id);
        fprintf(f, "job-type=%s\n", job_type_to_string(j->type));
        fprintf(f, "job-state=%s\n", job_state_to_string(j->state));
        fprintf(f, "job-override=%s\n", yes_no(j->override));
        fprintf(f, "job-irreversible=%s\n", yes_no(j->irreversible));
        fprintf(f, "job-sent-dbus-new-signal=%s\n", yes_no(j->sent_dbus_new_signal));
        fprintf(f, "job-ignore-order=%s\n", yes_no(j->ignore_order));

        if (j->begin_usec > 0)
                fprintf(f, "job-begin="USEC_FMT"\n", j->begin_usec);

        bus_track_serialize(j->subscribed, f);

        /* End marker */
        fputc('\n', f);
        return 0;
}

int job_deserialize(Job *j, FILE *f, FDSet *fds) {
        assert(j);

        for (;;) {
                char line[LINE_MAX], *l, *v;
                size_t k;

                if (!fgets(line, sizeof(line), f)) {
                        if (feof(f))
                                return 0;
                        return -errno;
                }

                char_array_0(line);
                l = strstrip(line);

                /* End marker */
                if (l[0] == 0)
                        return 0;

                k = strcspn(l, "=");

                if (l[k] == '=') {
                        l[k] = 0;
                        v = l+k+1;
                } else
                        v = l+k;

                if (streq(l, "job-id")) {

                        if (safe_atou32(v, &j->id) < 0)
                                log_debug("Failed to parse job id value %s", v);

                } else if (streq(l, "job-type")) {
                        JobType t;

                        t = job_type_from_string(v);
                        if (t < 0)
                                log_debug("Failed to parse job type %s", v);
                        else if (t >= _JOB_TYPE_MAX_IN_TRANSACTION)
                                log_debug("Cannot deserialize job of type %s", v);
                        else
                                j->type = t;

                } else if (streq(l, "job-state")) {
                        JobState s;

                        s = job_state_from_string(v);
                        if (s < 0)
                                log_debug("Failed to parse job state %s", v);
                        else
                                j->state = s;

                } else if (streq(l, "job-override")) {
                        int b;

                        b = parse_boolean(v);
                        if (b < 0)
                                log_debug("Failed to parse job override flag %s", v);
                        else
                                j->override = j->override || b;

                } else if (streq(l, "job-irreversible")) {
                        int b;

                        b = parse_boolean(v);
                        if (b < 0)
                                log_debug("Failed to parse job irreversible flag %s", v);
                        else
                                j->irreversible = j->irreversible || b;

                } else if (streq(l, "job-sent-dbus-new-signal")) {
                        int b;

                        b = parse_boolean(v);
                        if (b < 0)
                                log_debug("Failed to parse job sent_dbus_new_signal flag %s", v);
                        else
                                j->sent_dbus_new_signal = j->sent_dbus_new_signal || b;

                } else if (streq(l, "job-ignore-order")) {
                        int b;

                        b = parse_boolean(v);
                        if (b < 0)
                                log_debug("Failed to parse job ignore_order flag %s", v);
                        else
                                j->ignore_order = j->ignore_order || b;

                } else if (streq(l, "job-begin")) {
                        unsigned long long ull;

                        if (sscanf(v, "%llu", &ull) != 1)
                                log_debug("Failed to parse job-begin value %s", v);
                        else
                                j->begin_usec = ull;

                } else if (streq(l, "subscribed")) {

                        if (strv_extend(&j->deserialized_subscribed, v) < 0)
                                return log_oom();
                }
        }
}

int job_coldplug(Job *j) {
        int r;

        assert(j);

        /* After deserialization is complete and the bus connection
         * set up again, let's start watching our subscribers again */
        r = bus_track_coldplug(j->manager, &j->subscribed, &j->deserialized_subscribed);
        if (r < 0)
                return r;

        if (j->begin_usec == 0 || j->unit->job_timeout == 0)
                return 0;

        if (j->timer_event_source)
                j->timer_event_source = sd_event_source_unref(j->timer_event_source);

        if (j->state == JOB_WAITING)
                job_add_to_run_queue(j);

        r = sd_event_add_time(
                        j->manager->event,
                        &j->timer_event_source,
                        CLOCK_MONOTONIC,
                        j->begin_usec + j->unit->job_timeout, 0,
                        job_dispatch_timer, j);
        if (r < 0)
                log_debug("Failed to restart timeout for job: %s", strerror(-r));

        return r;
}

void job_shutdown_magic(Job *j) {
        assert(j);

        /* The shutdown target gets some special treatment here: we
         * tell the kernel to begin with flushing its disk caches, to
         * optimize shutdown time a bit. Ideally we wouldn't hardcode
         * this magic into PID 1. However all other processes aren't
         * options either since they'd exit much sooner than PID 1 and
         * asynchronous sync() would cause their exit to be
         * delayed. */

        if (j->type != JOB_START)
                return;

        if (j->unit->manager->running_as != SYSTEMD_SYSTEM)
                return;

        if (!unit_has_name(j->unit, SPECIAL_SHUTDOWN_TARGET))
                return;

        /* In case messages on console has been disabled on boot */
        j->unit->manager->no_console_output = false;

        if (detect_container(NULL) > 0)
                return;

        asynchronous_sync();
}

int job_get_timeout(Job *j, uint64_t *timeout) {
        Unit *u = j->unit;
        uint64_t x = -1, y = -1;
        int r = 0, q = 0;

        assert(u);

        if (j->timer_event_source) {
                r = sd_event_source_get_time(j->timer_event_source, &x);
                if (r < 0)
                        return r;
                r = 1;
        }

        if (UNIT_VTABLE(u)->get_timeout) {
                q = UNIT_VTABLE(u)->get_timeout(u, &y);
                if (q < 0)
                        return q;
        }

        if (r == 0 && q == 0)
                return 0;

        *timeout = MIN(x, y);

        return 1;
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
        [JOB_NOP] = "nop",
};

DEFINE_STRING_TABLE_LOOKUP(job_type, JobType);

static const char* const job_mode_table[_JOB_MODE_MAX] = {
        [JOB_FAIL] = "fail",
        [JOB_REPLACE] = "replace",
        [JOB_REPLACE_IRREVERSIBLY] = "replace-irreversibly",
        [JOB_ISOLATE] = "isolate",
        [JOB_FLUSH] = "flush",
        [JOB_IGNORE_DEPENDENCIES] = "ignore-dependencies",
        [JOB_IGNORE_REQUIREMENTS] = "ignore-requirements",
};

DEFINE_STRING_TABLE_LOOKUP(job_mode, JobMode);

static const char* const job_result_table[_JOB_RESULT_MAX] = {
        [JOB_DONE] = "done",
        [JOB_CANCELED] = "canceled",
        [JOB_TIMEOUT] = "timeout",
        [JOB_FAILED] = "failed",
        [JOB_DEPENDENCY] = "dependency",
        [JOB_SKIPPED] = "skipped",
        [JOB_INVALID] = "invalid",
};

DEFINE_STRING_TABLE_LOOKUP(job_result, JobResult);
