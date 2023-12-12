/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>

#include "sd-id128.h"
#include "sd-messages.h"

#include "alloc-util.h"
#include "async.h"
#include "cgroup.h"
#include "dbus-job.h"
#include "dbus.h"
#include "escape.h"
#include "fileio.h"
#include "job.h"
#include "log.h"
#include "macro.h"
#include "parse-util.h"
#include "serialize.h"
#include "set.h"
#include "sort-util.h"
#include "special.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "unit.h"
#include "virt.h"

Job* job_new_raw(Unit *unit) {
        Job *j;

        /* used for deserialization */

        assert(unit);

        j = new(Job, 1);
        if (!j)
                return NULL;

        *j = (Job) {
                .manager = unit->manager,
                .unit = unit,
                .type = _JOB_TYPE_INVALID,
        };

        return j;
}

static uint32_t manager_get_new_job_id(Manager *m) {
        bool overflow = false;

        assert(m);

        for (;;) {
                uint32_t id = m->current_job_id;

                if (_unlikely_(id == UINT32_MAX)) {
                        assert_se(!overflow);
                        m->current_job_id = 1;
                        overflow = true;
                } else
                        m->current_job_id++;

                if (hashmap_contains(m->jobs, UINT32_TO_PTR(id)))
                        continue;

                return id;
        }
}

Job* job_new(Unit *unit, JobType type) {
        Job *j;

        assert(type < _JOB_TYPE_MAX);

        j = job_new_raw(unit);
        if (!j)
                return NULL;

        j->id = manager_get_new_job_id(j->manager);
        j->type = type;

        /* We don't link it here, that's what job_dependency() is for */

        return j;
}

void job_unlink(Job *j) {
        assert(j);
        assert(!j->installed);
        assert(!j->transaction_prev);
        assert(!j->transaction_next);
        assert(!j->subject_list);
        assert(!j->object_list);

        if (j->in_run_queue) {
                prioq_remove(j->manager->run_queue, j, &j->run_queue_idx);
                j->in_run_queue = false;
        }

        if (j->in_dbus_queue) {
                LIST_REMOVE(dbus_queue, j->manager->dbus_job_queue, j);
                j->in_dbus_queue = false;
        }

        if (j->in_gc_queue) {
                LIST_REMOVE(gc_queue, j->manager->gc_job_queue, j);
                j->in_gc_queue = false;
        }

        j->timer_event_source = sd_event_source_disable_unref(j->timer_event_source);
}

Job* job_free(Job *j) {
        assert(j);
        assert(!j->installed);
        assert(!j->transaction_prev);
        assert(!j->transaction_next);
        assert(!j->subject_list);
        assert(!j->object_list);

        job_unlink(j);

        sd_bus_track_unref(j->bus_track);
        strv_free(j->deserialized_clients);

        activation_details_unref(j->activation_details);

        return mfree(j);
}

static void job_set_state(Job *j, JobState state) {
        assert(j);
        assert(state >= 0);
        assert(state < _JOB_STATE_MAX);

        if (j->state == state)
                return;

        j->state = state;

        if (!j->installed)
                return;

        if (j->state == JOB_RUNNING)
                j->unit->manager->n_running_jobs++;
        else {
                assert(j->state == JOB_WAITING);
                assert(j->unit->manager->n_running_jobs > 0);

                j->unit->manager->n_running_jobs--;

                if (j->unit->manager->n_running_jobs <= 0)
                        j->unit->manager->jobs_in_progress_event_source = sd_event_source_disable_unref(j->unit->manager->jobs_in_progress_event_source);
        }
}

void job_uninstall(Job *j) {
        Job **pj;

        assert(j->installed);

        job_set_state(j, JOB_WAITING);

        pj = j->type == JOB_NOP ? &j->unit->nop_job : &j->unit->job;
        assert(*pj == j);

        /* Detach from next 'bigger' objects */

        /* daemon-reload should be transparent to job observers */
        if (!MANAGER_IS_RELOADING(j->manager))
                bus_job_send_removed_signal(j);

        *pj = NULL;

        unit_add_to_gc_queue(j->unit);

        unit_add_to_dbus_queue(j->unit); /* The Job property of the unit has changed now */

        hashmap_remove_value(j->manager->jobs, UINT32_TO_PTR(j->id), j);
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

        if (j->type != JOB_NOP) {
                assert_se(job_type_merge_and_collapse(&j->type, other->type, j->unit) == 0);

                /* Keep the oldest ActivationDetails, if any */
                if (!j->activation_details)
                        j->activation_details = TAKE_PTR(other->activation_details);
        } else
                assert(other->type == JOB_NOP);

        j->irreversible = j->irreversible || other->irreversible;
        j->ignore_order = j->ignore_order || other->ignore_order;
}

Job* job_install(Job *j, bool refuse_late_merge) {
        Job **pj;
        Job *uj;

        assert(j);
        assert(!j->installed);
        assert(j->type < _JOB_TYPE_MAX_IN_TRANSACTION);
        assert(j->state == JOB_WAITING);

        pj = j->type == JOB_NOP ? &j->unit->nop_job : &j->unit->job;
        uj = *pj;

        if (uj) {
                if (job_type_is_conflicting(uj->type, j->type))
                        job_finish_and_invalidate(uj, JOB_CANCELED, false, false);
                else {
                        /* not conflicting, i.e. mergeable */

                        if (uj->state == JOB_WAITING ||
                            (!refuse_late_merge && job_type_allows_late_merge(j->type) && job_type_is_superset(uj->type, j->type))) {
                                job_merge_into_installed(uj, j);
                                log_unit_debug(uj->unit,
                                               "Merged %s/%s into installed job %s/%s as %"PRIu32,
                                               j->unit->id, job_type_to_string(j->type), uj->unit->id,
                                               job_type_to_string(uj->type), uj->id);
                                return uj;
                        } else {
                                /* already running and not safe to merge into */
                                /* Patch uj to become a merged job and re-run it. */
                                /* XXX It should be safer to queue j to run after uj finishes, but it is
                                 * not currently possible to have more than one installed job per unit. */
                                job_merge_into_installed(uj, j);
                                log_unit_debug(uj->unit,
                                               "Merged into running job, re-running: %s/%s as %"PRIu32,
                                               uj->unit->id, job_type_to_string(uj->type), uj->id);

                                job_set_state(uj, JOB_WAITING);
                                return uj;
                        }
                }
        }

        /* Install the job */
        assert(!*pj);
        *pj = j;
        j->installed = true;

        j->manager->n_installed_jobs++;
        log_unit_debug(j->unit,
                       "Installed new job %s/%s as %u",
                       j->unit->id, job_type_to_string(j->type), (unsigned) j->id);

        job_add_to_gc_queue(j);

        job_add_to_dbus_queue(j); /* announce this job to clients */
        unit_add_to_dbus_queue(j->unit); /* The Job property of the unit has changed now */

        return j;
}

int job_install_deserialized(Job *j) {
        Job **pj;
        int r;

        assert(!j->installed);

        if (j->type < 0 || j->type >= _JOB_TYPE_MAX_IN_TRANSACTION)
                return log_unit_debug_errno(j->unit, SYNTHETIC_ERRNO(EINVAL),
                                            "Invalid job type %s in deserialization.",
                                            strna(job_type_to_string(j->type)));

        pj = j->type == JOB_NOP ? &j->unit->nop_job : &j->unit->job;
        if (*pj)
                return log_unit_debug_errno(j->unit, SYNTHETIC_ERRNO(EEXIST),
                                            "Unit already has a job installed. Not installing deserialized job.");

        /* When the job does not have ID, or we failed to deserialize the job ID, then use a new ID. */
        if (j->id <= 0)
                j->id = manager_get_new_job_id(j->manager);

        r = hashmap_ensure_put(&j->manager->jobs, NULL, UINT32_TO_PTR(j->id), j);
        if (r == -EEXIST)
                return log_unit_debug_errno(j->unit, r, "Job ID %" PRIu32 " already used, cannot deserialize job.", j->id);
        if (r < 0)
                return log_unit_debug_errno(j->unit, r, "Failed to insert job into jobs hash table: %m");

        *pj = j;
        j->installed = true;

        if (j->state == JOB_RUNNING)
                j->unit->manager->n_running_jobs++;

        log_unit_debug(j->unit,
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

        l = new0(JobDependency, 1);
        if (!l)
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

void job_dump(Job *j, FILE *f, const char *prefix) {
        assert(j);
        assert(f);

        prefix = strempty(prefix);

        fprintf(f,
                "%s-> Job %u:\n"
                "%s\tAction: %s -> %s\n"
                "%s\tState: %s\n"
                "%s\tIrreversible: %s\n"
                "%s\tMay GC: %s\n",
                prefix, j->id,
                prefix, j->unit->id, job_type_to_string(j->type),
                prefix, job_state_to_string(j->state),
                prefix, yes_no(j->irreversible),
                prefix, yes_no(job_may_gc(j)));
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
 * Merging is associative! A merged with B, and then merged with C is the same
 * as A merged with the result of B merged with C.
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
                return IN_SET(b, UNIT_ACTIVE, UNIT_RELOADING);

        case JOB_STOP:
                return IN_SET(b, UNIT_INACTIVE, UNIT_FAILED);

        case JOB_VERIFY_ACTIVE:
                return IN_SET(b, UNIT_ACTIVE, UNIT_RELOADING);

        case JOB_RELOAD:
                return
                        b == UNIT_RELOADING;

        case JOB_RESTART:
                /* Restart jobs must always be kept.
                 *
                 * For ACTIVE/RELOADING units, this is obvious.
                 *
                 * For ACTIVATING units, it's more subtle:
                 *
                 * Generally, if a service Requires= another unit, restarts of
                 * the unit must be propagated to the service. If the service is
                 * ACTIVATING, it must still be restarted since it might have
                 * stale information regarding the other unit.
                 *
                 * For example, consider a service that Requires= a socket: if
                 * the socket is restarted, but the service is still ACTIVATING,
                 * it's necessary to restart the service so that it gets the new
                 * socket. */
                return false;

        case JOB_NOP:
                return true;

        default:
                assert_not_reached();
        }
}

JobType job_type_collapse(JobType t, Unit *u) {
        UnitActiveState s;

        switch (t) {

        case JOB_TRY_RESTART:
                /* Be sure to keep the restart job even if the unit is
                 * ACTIVATING.
                 *
                 * See the job_type_is_redundant(JOB_RESTART) for more info */
                s = unit_active_state(u);
                if (!UNIT_IS_ACTIVE_OR_ACTIVATING(s))
                        return JOB_NOP;

                return JOB_RESTART;

        case JOB_TRY_RELOAD:
                s = unit_active_state(u);
                if (!UNIT_IS_ACTIVE_OR_RELOADING(s))
                        return JOB_NOP;

                return JOB_RELOAD;

        case JOB_RELOAD_OR_START:
                s = unit_active_state(u);
                if (!UNIT_IS_ACTIVE_OR_RELOADING(s))
                        return JOB_START;

                return JOB_RELOAD;

        default:
                return t;
        }
}

int job_type_merge_and_collapse(JobType *a, JobType b, Unit *u) {
        JobType t;

        t = job_type_lookup_merge(*a, b);
        if (t < 0)
                return -EEXIST;

        *a = job_type_collapse(t, u);
        return 0;
}

static bool job_is_runnable(Job *j) {
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

        UNIT_FOREACH_DEPENDENCY(other, j->unit, UNIT_ATOM_AFTER)
                if (other->job && job_compare(j, other->job, UNIT_ATOM_AFTER) > 0) {
                        log_unit_debug(j->unit,
                                       "starting held back, waiting for: %s",
                                       other->id);
                        return false;
                }

        UNIT_FOREACH_DEPENDENCY(other, j->unit, UNIT_ATOM_BEFORE)
                if (other->job && job_compare(j, other->job, UNIT_ATOM_BEFORE) > 0) {
                        log_unit_debug(j->unit,
                                       "stopping held back, waiting for: %s",
                                       other->id);
                        return false;
                }

        return true;
}

static void job_change_type(Job *j, JobType newtype) {
        assert(j);

        log_unit_debug(j->unit,
                       "Converting job %s/%s -> %s/%s",
                       j->unit->id, job_type_to_string(j->type),
                       j->unit->id, job_type_to_string(newtype));

        j->type = newtype;
}

static const char* job_start_message_format(Unit *u, JobType t) {
        assert(u);
        assert(IN_SET(t, JOB_START, JOB_STOP, JOB_RELOAD));

        if (t == JOB_RELOAD)
                return "Reloading %s...";
        else if (t == JOB_START)
                return UNIT_VTABLE(u)->status_message_formats.starting_stopping[0] ?: "Starting %s...";
        else
                return UNIT_VTABLE(u)->status_message_formats.starting_stopping[1] ?: "Stopping %s...";
}

static void job_emit_start_message(Unit *u, uint32_t job_id, JobType t) {
        _cleanup_free_ char *free_ident = NULL;
        const char *ident, *format;

        assert(u);
        assert(t >= 0);
        assert(t < _JOB_TYPE_MAX);
        assert(u->id); /* We better don't try to run a unit that doesn't even have an id. */

        if (!IN_SET(t, JOB_START, JOB_STOP, JOB_RELOAD))
                return;

        if (!unit_log_level_test(u, LOG_INFO))
                return;

        format = job_start_message_format(u, t);
        ident = unit_status_string(u, &free_ident);

        bool do_console = t != JOB_RELOAD;
        bool console_only = do_console && log_on_console(); /* Reload status messages have traditionally
                                                             * not been printed to the console. */

        /* Print to the log first. */
        if (!console_only) {  /* Skip this if it would only go on the console anyway */

                const char *mid =
                        t == JOB_START ? "MESSAGE_ID=" SD_MESSAGE_UNIT_STARTING_STR :
                        t == JOB_STOP  ? "MESSAGE_ID=" SD_MESSAGE_UNIT_STOPPING_STR :
                                         "MESSAGE_ID=" SD_MESSAGE_UNIT_RELOADING_STR;
                const char *msg_fmt = strjoina("MESSAGE=", format);

                /* Note that we deliberately use LOG_MESSAGE() instead of LOG_UNIT_MESSAGE() here, since this
                 * is supposed to mimic closely what is written to screen using the status output, which is
                 * supposed to be high level friendly output. */

                DISABLE_WARNING_FORMAT_NONLITERAL;
                log_unit_struct(u, LOG_INFO,
                                msg_fmt, ident,
                                "JOB_ID=%" PRIu32, job_id,
                                "JOB_TYPE=%s", job_type_to_string(t),
                                LOG_UNIT_INVOCATION_ID(u),
                                mid);
                REENABLE_WARNING;
        }

        /* Log to the console second. */
        if (do_console) {
                DISABLE_WARNING_FORMAT_NONLITERAL;
                unit_status_printf(u, STATUS_TYPE_NORMAL, "", format, ident);
                REENABLE_WARNING;
        }
}

static const char* job_done_message_format(Unit *u, JobType t, JobResult result) {
        static const char* const generic_finished_start_job[_JOB_RESULT_MAX] = {
                [JOB_DONE]        = "Started %s.",
                [JOB_TIMEOUT]     = "Timed out starting %s.",
                [JOB_FAILED]      = "Failed to start %s.",
                [JOB_DEPENDENCY]  = "Dependency failed for %s.",
                [JOB_ASSERT]      = "Assertion failed for %s.",
                [JOB_UNSUPPORTED] = "Starting of %s unsupported.",
                [JOB_COLLECTED]   = "Unnecessary job was removed for %s.",
                [JOB_ONCE]        = "Unit %s has been started before and cannot be started again.",
        };
        static const char* const generic_finished_stop_job[_JOB_RESULT_MAX] = {
                [JOB_DONE]        = "Stopped %s.",
                [JOB_FAILED]      = "Stopped %s with error.",
                [JOB_TIMEOUT]     = "Timed out stopping %s.",
        };
        static const char* const generic_finished_reload_job[_JOB_RESULT_MAX] = {
                [JOB_DONE]        = "Reloaded %s.",
                [JOB_FAILED]      = "Reload failed for %s.",
                [JOB_TIMEOUT]     = "Timed out reloading %s.",
        };
        /* When verify-active detects the unit is inactive, report it.
         * Most likely a DEPEND warning from a requisiting unit will
         * occur next and it's nice to see what was requisited. */
        static const char* const generic_finished_verify_active_job[_JOB_RESULT_MAX] = {
                [JOB_SKIPPED]     = "%s is inactive.",
        };
        const char *format;

        assert(u);
        assert(t >= 0);
        assert(t < _JOB_TYPE_MAX);

        /* Show condition check message if the job did not actually do anything due to unmet condition. */
        if (t == JOB_START && result == JOB_DONE && !u->condition_result)
                return "Condition check resulted in %s being skipped.";

        if (IN_SET(t, JOB_START, JOB_STOP, JOB_RESTART)) {
                const UnitStatusMessageFormats *formats = &UNIT_VTABLE(u)->status_message_formats;
                if (formats->finished_job) {
                        format = formats->finished_job(u, t, result);
                        if (format)
                                return format;
                }

                format = (t == JOB_START ? formats->finished_start_job : formats->finished_stop_job)[result];
                if (format)
                        return format;
        }

        /* Return generic strings */
        switch (t) {
        case JOB_START:
                return generic_finished_start_job[result];
        case JOB_STOP:
        case JOB_RESTART:
                return generic_finished_stop_job[result];
        case JOB_RELOAD:
                return generic_finished_reload_job[result];
        case JOB_VERIFY_ACTIVE:
                return generic_finished_verify_active_job[result];
        default:
                return NULL;
        }
}

static const struct {
        int log_level;
        const char *color, *word;
} job_done_messages[_JOB_RESULT_MAX] = {
        [JOB_DONE]        = { LOG_INFO,    ANSI_OK_COLOR,         "  OK  " },
        [JOB_CANCELED]    = { LOG_INFO,                                    },
        [JOB_TIMEOUT]     = { LOG_ERR,     ANSI_HIGHLIGHT_RED,    " TIME " },
        [JOB_FAILED]      = { LOG_ERR,     ANSI_HIGHLIGHT_RED,    "FAILED" },
        [JOB_DEPENDENCY]  = { LOG_WARNING, ANSI_HIGHLIGHT_YELLOW, "DEPEND" },
        [JOB_SKIPPED]     = { LOG_NOTICE,  ANSI_HIGHLIGHT,        " INFO " },
        [JOB_INVALID]     = { LOG_INFO,                                    },
        [JOB_ASSERT]      = { LOG_WARNING, ANSI_HIGHLIGHT_YELLOW, "ASSERT" },
        [JOB_UNSUPPORTED] = { LOG_WARNING, ANSI_HIGHLIGHT_YELLOW, "UNSUPP" },
        [JOB_COLLECTED]   = { LOG_INFO,                                    },
        [JOB_ONCE]        = { LOG_ERR,     ANSI_HIGHLIGHT_RED,    " ONCE " },
};

static const char* job_done_mid(JobType type, JobResult result) {
        switch (type) {
        case JOB_START:
                if (result == JOB_DONE)
                        return "MESSAGE_ID=" SD_MESSAGE_UNIT_STARTED_STR;
                else
                        return "MESSAGE_ID=" SD_MESSAGE_UNIT_FAILED_STR;

        case JOB_RELOAD:
                return "MESSAGE_ID=" SD_MESSAGE_UNIT_RELOADED_STR;

        case JOB_STOP:
        case JOB_RESTART:
                return "MESSAGE_ID=" SD_MESSAGE_UNIT_STOPPED_STR;

        default:
                return NULL;
        }
}

static void job_emit_done_message(Unit *u, uint32_t job_id, JobType t, JobResult result) {
        _cleanup_free_ char *free_ident = NULL;
        const char *ident, *format;

        assert(u);
        assert(t >= 0);
        assert(t < _JOB_TYPE_MAX);

        if (!unit_log_level_test(u, job_done_messages[result].log_level))
                return;

        format = job_done_message_format(u, t, result);
        if (!format)
                return;

        ident = unit_status_string(u, &free_ident);

        const char *status = job_done_messages[result].word;
        bool do_console = t != JOB_RELOAD && status;
        bool console_only = do_console && log_on_console();

        if (t == JOB_START && result == JOB_DONE && !u->condition_result) {
                /* No message on the console if the job did not actually do anything due to unmet condition. */
                if (console_only)
                        return;
                else
                        do_console = false;
        }

        if (!console_only) {  /* Skip printing if output goes to the console, and job_print_status_message()
                               * will actually print something to the console. */
                Condition *c;
                const char *mid = job_done_mid(t, result);  /* mid may be NULL. log_unit_struct() will ignore it. */

                c = t == JOB_START && result == JOB_DONE ? unit_find_failed_condition(u) : NULL;
                if (c) {
                        /* Special case units that were skipped because of a unmet condition check so that
                         * we can add more information to the message. */
                        if (c->trigger)
                                log_unit_struct(
                                        u,
                                        job_done_messages[result].log_level,
                                        LOG_MESSAGE("%s was skipped because no trigger condition checks were met.",
                                                    ident),
                                        "JOB_ID=%" PRIu32, job_id,
                                        "JOB_TYPE=%s", job_type_to_string(t),
                                        "JOB_RESULT=%s", job_result_to_string(result),
                                        LOG_UNIT_INVOCATION_ID(u),
                                        mid);
                        else
                                log_unit_struct(
                                        u,
                                        job_done_messages[result].log_level,
                                        LOG_MESSAGE("%s was skipped because of an unmet condition check (%s=%s%s).",
                                                    ident,
                                                    condition_type_to_string(c->type),
                                                    c->negate ? "!" : "",
                                                    c->parameter),
                                        "JOB_ID=%" PRIu32, job_id,
                                        "JOB_TYPE=%s", job_type_to_string(t),
                                        "JOB_RESULT=%s", job_result_to_string(result),
                                        LOG_UNIT_INVOCATION_ID(u),
                                        mid);
                } else {
                        const char *msg_fmt = strjoina("MESSAGE=", format);

                        DISABLE_WARNING_FORMAT_NONLITERAL;
                        log_unit_struct(u, job_done_messages[result].log_level,
                                        msg_fmt, ident,
                                        "JOB_ID=%" PRIu32, job_id,
                                        "JOB_TYPE=%s", job_type_to_string(t),
                                        "JOB_RESULT=%s", job_result_to_string(result),
                                        LOG_UNIT_INVOCATION_ID(u),
                                        mid);
                        REENABLE_WARNING;
                }
        }

        if (do_console) {
                if (log_get_show_color())
                        status = strjoina(job_done_messages[result].color,
                                          status,
                                          ANSI_NORMAL);

                DISABLE_WARNING_FORMAT_NONLITERAL;
                unit_status_printf(u,
                                   result == JOB_DONE ? STATUS_TYPE_NORMAL : STATUS_TYPE_NOTICE,
                                   status, format, ident);
                REENABLE_WARNING;

                if (t == JOB_START && result == JOB_FAILED) {
                        _cleanup_free_ char *quoted = NULL;

                        quoted = shell_maybe_quote(u->id, 0);
                        if (quoted)
                                manager_status_printf(u->manager, STATUS_TYPE_NORMAL, NULL,
                                                      "See 'systemctl status %s' for details.", quoted);
                }
        }
}

static int job_perform_on_unit(Job **j) {
        ActivationDetails *a;
        uint32_t id;
        Manager *m;
        JobType t;
        Unit *u;
        bool wait_only;
        int r;

        /* While we execute this operation the job might go away (for example: because it finishes immediately
         * or is replaced by a new, conflicting job). To make sure we don't access a freed job later on we
         * store the id here, so that we can verify the job is still valid. */

        assert(j);
        assert(*j);

        m = (*j)->manager;
        u = (*j)->unit;
        t = (*j)->type;
        id = (*j)->id;
        a = (*j)->activation_details;

        switch (t) {
                case JOB_START:
                        r = unit_start(u, a);
                        wait_only = r == -EBADR; /* If the unit type does not support starting, then simply wait. */
                        break;

                case JOB_RESTART:
                        t = JOB_STOP;
                        _fallthrough_;
                case JOB_STOP:
                        r = unit_stop(u);
                        wait_only = r == -EBADR; /* If the unit type does not support stopping, then simply wait. */
                        break;

                case JOB_RELOAD:
                        r = unit_reload(u);
                        wait_only = false; /* A clear error is generated if reload is not supported. */
                        break;

                default:
                        assert_not_reached();
        }

        /* Log if the job still exists and the start/stop/reload function actually did something or we're
         * only waiting for unit status change (common for device units). The latter ensures that job start
         * messages for device units are correctly shown. Note that if the job disappears too quickly, e.g.
         * for units for which there's no 'activating' phase (i.e. because we transition directly from
         * 'inactive' to 'active'), we'll possibly skip the "Starting..." message. */
        *j = manager_get_job(m, id);
        if (*j && (r > 0 || wait_only))
                job_emit_start_message(u, id, t);

        return wait_only ? 0 : r;
}

int job_run_and_invalidate(Job *j) {
        int r;

        assert(j);
        assert(j->installed);
        assert(j->type < _JOB_TYPE_MAX_IN_TRANSACTION);
        assert(j->in_run_queue);

        prioq_remove(j->manager->run_queue, j, &j->run_queue_idx);
        j->in_run_queue = false;

        if (j->state != JOB_WAITING)
                return 0;

        if (!job_is_runnable(j))
                return -EAGAIN;

        job_start_timer(j, true);
        job_set_state(j, JOB_RUNNING);
        job_add_to_dbus_queue(j);

        switch (j->type) {

                case JOB_VERIFY_ACTIVE: {
                        UnitActiveState t;

                        t = unit_active_state(j->unit);
                        if (UNIT_IS_ACTIVE_OR_RELOADING(t))
                                r = -EALREADY;
                        else if (t == UNIT_ACTIVATING)
                                r = -EAGAIN;
                        else
                                r = -EBADR;
                        break;
                }

                case JOB_START:
                case JOB_STOP:
                case JOB_RESTART:
                case JOB_RELOAD:
                        r = job_perform_on_unit(&j);
                        break;

                case JOB_NOP:
                        r = -EALREADY;
                        break;

                default:
                        assert_not_reached();
        }

        if (j) {
                if (r == -EAGAIN)
                        job_set_state(j, JOB_WAITING); /* Hmm, not ready after all, let's return to JOB_WAITING state */
                else if (r == -EALREADY) /* already being executed */
                        r = job_finish_and_invalidate(j, JOB_DONE, true, true);
                else if (r == -ECOMM)
                        r = job_finish_and_invalidate(j, JOB_DONE, true, false);
                else if (r == -EBADR)
                        r = job_finish_and_invalidate(j, JOB_SKIPPED, true, false);
                else if (r == -ENOEXEC)
                        r = job_finish_and_invalidate(j, JOB_INVALID, true, false);
                else if (r == -EPROTO)
                        r = job_finish_and_invalidate(j, JOB_ASSERT, true, false);
                else if (r == -EOPNOTSUPP)
                        r = job_finish_and_invalidate(j, JOB_UNSUPPORTED, true, false);
                else if (r == -ENOLINK)
                        r = job_finish_and_invalidate(j, JOB_DEPENDENCY, true, false);
                else if (r == -ESTALE)
                        r = job_finish_and_invalidate(j, JOB_ONCE, true, false);
                else if (r < 0)
                        r = job_finish_and_invalidate(j, JOB_FAILED, true, false);
        }

        return r;
}

static void job_fail_dependencies(Unit *u, UnitDependencyAtom match_atom) {
        Unit *other;

        assert(u);

        UNIT_FOREACH_DEPENDENCY(other, u, match_atom) {
                Job *j = other->job;

                if (!j)
                        continue;
                if (!IN_SET(j->type, JOB_START, JOB_VERIFY_ACTIVE))
                        continue;

                job_finish_and_invalidate(j, JOB_DEPENDENCY, true, false);
        }
}

int job_finish_and_invalidate(Job *j, JobResult result, bool recursive, bool already) {
        Unit *u, *other;
        JobType t;

        assert(j);
        assert(j->installed);
        assert(j->type < _JOB_TYPE_MAX_IN_TRANSACTION);

        u = j->unit;
        t = j->type;

        j->result = result;

        log_unit_debug(u, "Job %" PRIu32 " %s/%s finished, result=%s",
                       j->id, u->id, job_type_to_string(t), job_result_to_string(result));

        /* If this job did nothing to the respective unit we don't log the status message */
        if (!already)
                job_emit_done_message(u, j->id, t, result);

        /* Patch restart jobs so that they become normal start jobs */
        if (result == JOB_DONE && t == JOB_RESTART) {

                job_change_type(j, JOB_START);
                job_set_state(j, JOB_WAITING);

                job_add_to_dbus_queue(j);
                job_add_to_run_queue(j);
                job_add_to_gc_queue(j);

                goto finish;
        }

        if (IN_SET(result, JOB_FAILED, JOB_INVALID))
                j->manager->n_failed_jobs++;

        job_uninstall(j);
        job_free(j);

        /* Fail depending jobs on failure */
        if (result != JOB_DONE && recursive) {
                if (IN_SET(t, JOB_START, JOB_VERIFY_ACTIVE))
                        job_fail_dependencies(u, UNIT_ATOM_PROPAGATE_START_FAILURE);
                else if (t == JOB_STOP)
                        job_fail_dependencies(u, UNIT_ATOM_PROPAGATE_STOP_FAILURE);
        }

        /* A special check to make sure we take down anything RequisiteOf= if we aren't active. This is when
         * the verify-active job merges with a satisfying job type, and then loses its invalidation effect,
         * as the result there is JOB_DONE for the start job we merged into, while we should be failing the
         * depending job if the said unit isn't in fact active. Oneshots are an example of this, where going
         * directly from activating to inactive is success.
         *
         * This happens when you use ConditionXYZ= in a unit too, since in that case the job completes with
         * the JOB_DONE result, but the unit never really becomes active. Note that such a case still
         * involves merging:
         *
         * A start job waits for something else, and a verify-active comes in and merges in the installed
         * job. Then, later, when it becomes runnable, it finishes with JOB_DONE result as execution on
         * conditions not being met is skipped, breaking our dependency semantics.
         *
         * Also, depending on if start job waits or not, the merging may or may not happen (the verify-active
         * job may trigger after it finishes), so you get undeterministic results without this check.
         */
        if (result == JOB_DONE && recursive &&
            IN_SET(t, JOB_START, JOB_RELOAD) &&
            !UNIT_IS_ACTIVE_OR_RELOADING(unit_active_state(u)))
                job_fail_dependencies(u, UNIT_ATOM_PROPAGATE_INACTIVE_START_AS_FAILURE);

        /* Trigger OnFailure= dependencies that are not generated by the unit itself. We don't treat
         * JOB_CANCELED as failure in this context. And JOB_FAILURE is already handled by the unit itself. */
        if (IN_SET(result, JOB_TIMEOUT, JOB_DEPENDENCY)) {
                log_unit_struct(u, LOG_NOTICE,
                                "JOB_TYPE=%s", job_type_to_string(t),
                                "JOB_RESULT=%s", job_result_to_string(result),
                                LOG_UNIT_MESSAGE(u, "Job %s/%s failed with result '%s'.",
                                                 u->id,
                                                 job_type_to_string(t),
                                                 job_result_to_string(result)));

                unit_start_on_failure(u, "OnFailure=", UNIT_ATOM_ON_FAILURE, u->on_failure_job_mode);
        }

        unit_trigger_notify(u);

finish:
        /* Try to start the next jobs that can be started */
        UNIT_FOREACH_DEPENDENCY(other, u, UNIT_ATOM_AFTER)
                if (other->job) {
                        job_add_to_run_queue(other->job);
                        job_add_to_gc_queue(other->job);
                }
        UNIT_FOREACH_DEPENDENCY(other, u, UNIT_ATOM_BEFORE)
                if (other->job) {
                        job_add_to_run_queue(other->job);
                        job_add_to_gc_queue(other->job);
                }

        /* Ensure that when an upheld/unneeded/bound unit activation job fails we requeue it, if it still
         * necessary. If there are no state changes in the triggerer, it would not be retried otherwise. */
        unit_submit_to_start_when_upheld_queue(u);
        unit_submit_to_stop_when_bound_queue(u);
        unit_submit_to_stop_when_unneeded_queue(u);

        manager_check_finished(u->manager);

        return 0;
}

static int job_dispatch_timer(sd_event_source *s, uint64_t monotonic, void *userdata) {
        Job *j = ASSERT_PTR(userdata);
        Unit *u;

        assert(s == j->timer_event_source);

        log_unit_warning(j->unit, "Job %s/%s timed out.", j->unit->id, job_type_to_string(j->type));

        u = j->unit;
        job_finish_and_invalidate(j, JOB_TIMEOUT, true, false);

        emergency_action(u->manager, u->job_timeout_action,
                         EMERGENCY_ACTION_IS_WATCHDOG|EMERGENCY_ACTION_WARN,
                         u->job_timeout_reboot_arg, -1, "job timed out");

        return 0;
}

int job_start_timer(Job *j, bool job_running) {
        int r;
        usec_t timeout_time, old_timeout_time;

        if (job_running) {
                j->begin_running_usec = now(CLOCK_MONOTONIC);

                if (j->unit->job_running_timeout == USEC_INFINITY)
                        return 0;

                timeout_time = usec_add(j->begin_running_usec, j->unit->job_running_timeout);

                if (j->timer_event_source) {
                        /* Update only if JobRunningTimeoutSec= results in earlier timeout */
                        r = sd_event_source_get_time(j->timer_event_source, &old_timeout_time);
                        if (r < 0)
                                return r;

                        if (old_timeout_time <= timeout_time)
                                return 0;

                        return sd_event_source_set_time(j->timer_event_source, timeout_time);
                }
        } else {
                if (j->timer_event_source)
                        return 0;

                j->begin_usec = now(CLOCK_MONOTONIC);

                if (j->unit->job_timeout == USEC_INFINITY)
                        return 0;

                timeout_time = usec_add(j->begin_usec, j->unit->job_timeout);
        }

        r = sd_event_add_time(
                        j->manager->event,
                        &j->timer_event_source,
                        CLOCK_MONOTONIC,
                        timeout_time, 0,
                        job_dispatch_timer, j);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(j->timer_event_source, "job-start");

        return 0;
}

void job_add_to_run_queue(Job *j) {
        int r;

        assert(j);
        assert(j->installed);

        if (j->in_run_queue)
                return;

        r = prioq_put(j->manager->run_queue, j, &j->run_queue_idx);
        if (r < 0)
                log_warning_errno(r, "Failed put job in run queue, ignoring: %m");
        else
                j->in_run_queue = true;

        manager_trigger_run_queue(j->manager);
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

int job_serialize(Job *j, FILE *f) {
        assert(j);
        assert(f);

        (void) serialize_item_format(f, "job-id", "%u", j->id);
        (void) serialize_item(f, "job-type", job_type_to_string(j->type));
        (void) serialize_item(f, "job-state", job_state_to_string(j->state));
        (void) serialize_bool(f, "job-irreversible", j->irreversible);
        (void) serialize_bool(f, "job-sent-dbus-new-signal", j->sent_dbus_new_signal);
        (void) serialize_bool(f, "job-ignore-order", j->ignore_order);

        if (j->begin_usec > 0)
                (void) serialize_usec(f, "job-begin", j->begin_usec);
        if (j->begin_running_usec > 0)
                (void) serialize_usec(f, "job-begin-running", j->begin_running_usec);

        bus_track_serialize(j->bus_track, f, "subscribed");

        activation_details_serialize(j->activation_details, f);

        /* End marker */
        fputc('\n', f);
        return 0;
}

int job_deserialize(Job *j, FILE *f) {
        int r;

        assert(j);
        assert(f);

        for (;;) {
                _cleanup_free_ char *l = NULL;
                size_t k;
                char *v;

                r = deserialize_read_line(f, &l);
                if (r < 0)
                        return r;
                if (r == 0) /* eof or end marker */
                        break;

                k = strcspn(l, "=");

                if (l[k] == '=') {
                        l[k] = 0;
                        v = l+k+1;
                } else
                        v = l+k;

                if (streq(l, "job-id")) {

                        if (safe_atou32(v, &j->id) < 0)
                                log_debug("Failed to parse job id value: %s", v);

                } else if (streq(l, "job-type")) {
                        JobType t;

                        t = job_type_from_string(v);
                        if (t < 0)
                                log_debug("Failed to parse job type: %s", v);
                        else if (t >= _JOB_TYPE_MAX_IN_TRANSACTION)
                                log_debug("Cannot deserialize job of type: %s", v);
                        else
                                j->type = t;

                } else if (streq(l, "job-state")) {
                        JobState s;

                        s = job_state_from_string(v);
                        if (s < 0)
                                log_debug("Failed to parse job state: %s", v);
                        else
                                job_set_state(j, s);

                } else if (streq(l, "job-irreversible")) {
                        int b;

                        b = parse_boolean(v);
                        if (b < 0)
                                log_debug("Failed to parse job irreversible flag: %s", v);
                        else
                                j->irreversible = j->irreversible || b;

                } else if (streq(l, "job-sent-dbus-new-signal")) {
                        int b;

                        b = parse_boolean(v);
                        if (b < 0)
                                log_debug("Failed to parse job sent_dbus_new_signal flag: %s", v);
                        else
                                j->sent_dbus_new_signal = j->sent_dbus_new_signal || b;

                } else if (streq(l, "job-ignore-order")) {
                        int b;

                        b = parse_boolean(v);
                        if (b < 0)
                                log_debug("Failed to parse job ignore_order flag: %s", v);
                        else
                                j->ignore_order = j->ignore_order || b;

                } else if (streq(l, "job-begin"))
                        (void) deserialize_usec(v, &j->begin_usec);

                else if (streq(l, "job-begin-running"))
                        (void) deserialize_usec(v, &j->begin_running_usec);

                else if (streq(l, "subscribed")) {
                        if (strv_extend(&j->deserialized_clients, v) < 0)
                                return log_oom();

                } else if (startswith(l, "activation-details")) {
                        if (activation_details_deserialize(l, v, &j->activation_details) < 0)
                                log_debug("Failed to parse job ActivationDetails element: %s", v);

                } else
                        log_debug("Unknown job serialization key: %s", l);
        }

        return 0;
}

int job_coldplug(Job *j) {
        int r;
        usec_t timeout_time = USEC_INFINITY;

        assert(j);

        /* After deserialization is complete and the bus connection
         * set up again, let's start watching our subscribers again */
        (void) bus_job_coldplug_bus_track(j);

        if (j->state == JOB_WAITING)
                job_add_to_run_queue(j);

        /* Maybe due to new dependencies we don't actually need this job anymore? */
        job_add_to_gc_queue(j);

        /* Create timer only when job began or began running and the respective timeout is finite.
         * Follow logic of job_start_timer() if both timeouts are finite */
        if (j->begin_usec == 0)
                return 0;

        if (j->unit->job_timeout != USEC_INFINITY)
                timeout_time = usec_add(j->begin_usec, j->unit->job_timeout);

        if (timestamp_is_set(j->begin_running_usec))
                timeout_time = MIN(timeout_time, usec_add(j->begin_running_usec, j->unit->job_running_timeout));

        if (timeout_time == USEC_INFINITY)
                return 0;

        j->timer_event_source = sd_event_source_disable_unref(j->timer_event_source);

        r = sd_event_add_time(
                        j->manager->event,
                        &j->timer_event_source,
                        CLOCK_MONOTONIC,
                        timeout_time, 0,
                        job_dispatch_timer, j);
        if (r < 0)
                log_debug_errno(r, "Failed to restart timeout for job: %m");

        (void) sd_event_source_set_description(j->timer_event_source, "job-timeout");

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

        if (!MANAGER_IS_SYSTEM(j->unit->manager))
                return;

        if (!unit_has_name(j->unit, SPECIAL_SHUTDOWN_TARGET))
                return;

        /* In case messages on console has been disabled on boot */
        j->unit->manager->no_console_output = false;

        manager_invalidate_startup_units(j->unit->manager);

        if (detect_container() > 0)
                return;

        (void) asynchronous_sync(NULL);
}

int job_get_timeout(Job *j, usec_t *ret) {
        usec_t x = USEC_INFINITY, y = USEC_INFINITY;
        Unit *u = ASSERT_PTR(ASSERT_PTR(j)->unit);
        int r;

        assert(ret);

        if (j->timer_event_source) {
                r = sd_event_source_get_time(j->timer_event_source, &x);
                if (r < 0)
                        return r;
        }

        if (UNIT_VTABLE(u)->get_timeout) {
                r = UNIT_VTABLE(u)->get_timeout(u, &y);
                if (r < 0)
                        return r;
        }

        if (x == USEC_INFINITY && y == USEC_INFINITY) {
                *ret = 0;
                return 0;
        }

        *ret = MIN(x, y);
        return 1;
}

bool job_may_gc(Job *j) {
        Unit *other;

        assert(j);

        /* Checks whether this job should be GC'ed away. We only do this for jobs of units that have no effect on their
         * own and just track external state. For now the only unit type that qualifies for this are .device units.
         * Returns true if the job can be collected. */

        if (!UNIT_VTABLE(j->unit)->gc_jobs)
                return false;

        /* Make sure to send out pending D-Bus events before we unload the unit */
        if (j->in_dbus_queue)
                return false;

        if (sd_bus_track_count(j->bus_track) > 0)
                return false;

        /* FIXME: So this is a bit ugly: for now we don't properly track references made via private bus connections
         * (because it's nasty, as sd_bus_track doesn't apply to it). We simply remember that the job was once
         * referenced by one, and reset this whenever we notice that no private bus connections are around. This means
         * the GC is a bit too conservative when it comes to jobs created by private bus connections. */
        if (j->ref_by_private_bus) {
                if (set_isempty(j->unit->manager->private_buses))
                        j->ref_by_private_bus = false;
                else
                        return false;
        }

        if (j->type == JOB_NOP)
                return false;

        /* The logic is inverse to job_is_runnable, we cannot GC as long as we block any job. */
        UNIT_FOREACH_DEPENDENCY(other, j->unit, UNIT_ATOM_BEFORE)
                if (other->job && job_compare(j, other->job, UNIT_ATOM_BEFORE) < 0)
                        return false;

        UNIT_FOREACH_DEPENDENCY(other, j->unit, UNIT_ATOM_AFTER)
                if (other->job && job_compare(j, other->job, UNIT_ATOM_AFTER) < 0)
                        return false;

        return true;
}

void job_add_to_gc_queue(Job *j) {
        assert(j);

        if (j->in_gc_queue)
                return;

        if (!job_may_gc(j))
                return;

        LIST_PREPEND(gc_queue, j->unit->manager->gc_job_queue, j);
        j->in_gc_queue = true;
}

static int job_compare_id(Job * const *a, Job * const *b) {
        return CMP((*a)->id, (*b)->id);
}

static size_t sort_job_list(Job **list, size_t n) {
        Job *previous = NULL;
        size_t a, b;

        /* Order by numeric IDs */
        typesafe_qsort(list, n, job_compare_id);

        /* Filter out duplicates */
        for (a = 0, b = 0; a < n; a++) {

                if (previous == list[a])
                        continue;

                previous = list[b++] = list[a];
        }

        return b;
}

int job_get_before(Job *j, Job*** ret) {
        _cleanup_free_ Job** list = NULL;
        Unit *other = NULL;
        size_t n = 0;

        /* Returns a list of all pending jobs that need to finish before this job may be started. */

        assert(j);
        assert(ret);

        if (j->ignore_order) {
                *ret = NULL;
                return 0;
        }

        UNIT_FOREACH_DEPENDENCY(other, j->unit, UNIT_ATOM_AFTER) {
                if (!other->job)
                        continue;
                if (job_compare(j, other->job, UNIT_ATOM_AFTER) <= 0)
                        continue;

                if (!GREEDY_REALLOC(list, n+1))
                        return -ENOMEM;
                list[n++] = other->job;
        }

        UNIT_FOREACH_DEPENDENCY(other, j->unit, UNIT_ATOM_BEFORE) {
                if (!other->job)
                        continue;
                if (job_compare(j, other->job, UNIT_ATOM_BEFORE) <= 0)
                        continue;

                if (!GREEDY_REALLOC(list, n+1))
                        return -ENOMEM;
                list[n++] = other->job;
        }

        n = sort_job_list(list, n);

        *ret = TAKE_PTR(list);

        return (int) n;
}

int job_get_after(Job *j, Job*** ret) {
        _cleanup_free_ Job** list = NULL;
        Unit *other = NULL;
        size_t n = 0;

        assert(j);
        assert(ret);

        /* Returns a list of all pending jobs that are waiting for this job to finish. */

        UNIT_FOREACH_DEPENDENCY(other, j->unit, UNIT_ATOM_BEFORE) {
                if (!other->job)
                        continue;

                if (other->job->ignore_order)
                        continue;

                if (job_compare(j, other->job, UNIT_ATOM_BEFORE) >= 0)
                        continue;

                if (!GREEDY_REALLOC(list, n+1))
                        return -ENOMEM;
                list[n++] = other->job;
        }

        UNIT_FOREACH_DEPENDENCY(other, j->unit, UNIT_ATOM_AFTER) {
                if (!other->job)
                        continue;

                if (other->job->ignore_order)
                        continue;

                if (job_compare(j, other->job, UNIT_ATOM_AFTER) >= 0)
                        continue;

                if (!GREEDY_REALLOC(list, n+1))
                        return -ENOMEM;
                list[n++] = other->job;
        }

        n = sort_job_list(list, n);

        *ret = TAKE_PTR(list);

        return (int) n;
}

static const char* const job_state_table[_JOB_STATE_MAX] = {
        [JOB_WAITING] = "waiting",
        [JOB_RUNNING] = "running",
};

DEFINE_STRING_TABLE_LOOKUP(job_state, JobState);

static const char* const job_type_table[_JOB_TYPE_MAX] = {
        [JOB_START]           = "start",
        [JOB_VERIFY_ACTIVE]   = "verify-active",
        [JOB_STOP]            = "stop",
        [JOB_RELOAD]          = "reload",
        [JOB_RELOAD_OR_START] = "reload-or-start",
        [JOB_RESTART]         = "restart",
        [JOB_TRY_RESTART]     = "try-restart",
        [JOB_TRY_RELOAD]      = "try-reload",
        [JOB_NOP]             = "nop",
};

DEFINE_STRING_TABLE_LOOKUP(job_type, JobType);

static const char* const job_mode_table[_JOB_MODE_MAX] = {
        [JOB_FAIL]                 = "fail",
        [JOB_REPLACE]              = "replace",
        [JOB_REPLACE_IRREVERSIBLY] = "replace-irreversibly",
        [JOB_ISOLATE]              = "isolate",
        [JOB_FLUSH]                = "flush",
        [JOB_IGNORE_DEPENDENCIES]  = "ignore-dependencies",
        [JOB_IGNORE_REQUIREMENTS]  = "ignore-requirements",
        [JOB_TRIGGERING]           = "triggering",
        [JOB_RESTART_DEPENDENCIES] = "restart-dependencies",
};

DEFINE_STRING_TABLE_LOOKUP(job_mode, JobMode);

static const char* const job_result_table[_JOB_RESULT_MAX] = {
        [JOB_DONE]        = "done",
        [JOB_CANCELED]    = "canceled",
        [JOB_TIMEOUT]     = "timeout",
        [JOB_FAILED]      = "failed",
        [JOB_DEPENDENCY]  = "dependency",
        [JOB_SKIPPED]     = "skipped",
        [JOB_INVALID]     = "invalid",
        [JOB_ASSERT]      = "assert",
        [JOB_UNSUPPORTED] = "unsupported",
        [JOB_COLLECTED]   = "collected",
        [JOB_ONCE]        = "once",
};

DEFINE_STRING_TABLE_LOOKUP(job_result, JobResult);

const char* job_type_to_access_method(JobType t) {
        assert(t >= 0);
        assert(t < _JOB_TYPE_MAX);

        if (IN_SET(t, JOB_START, JOB_RESTART, JOB_TRY_RESTART))
                return "start";
        else if (t == JOB_STOP)
                return "stop";
        else
                return "reload";
}

/*
 * assume_dep   assumed dependency between units (a is before/after b)
 *
 * Returns
 *    0         jobs are independent,
 *   >0         a should run after b,
 *   <0         a should run before b,
 *
 * The logic means that for a service a and a service b where b.After=a:
 *
 *  start a + start b → 1st step start a, 2nd step start b
 *  start a + stop b  → 1st step stop b,  2nd step start a
 *  stop a  + start b → 1st step stop a,  2nd step start b
 *  stop a  + stop b  → 1st step stop b,  2nd step stop a
 *
 *  This has the side effect that restarts are properly synchronized too.
 */
int job_compare(Job *a, Job *b, UnitDependencyAtom assume_dep) {
        assert(a);
        assert(b);
        assert(a->type < _JOB_TYPE_MAX_IN_TRANSACTION);
        assert(b->type < _JOB_TYPE_MAX_IN_TRANSACTION);
        assert(IN_SET(assume_dep, UNIT_ATOM_AFTER, UNIT_ATOM_BEFORE));

        /* Trivial cases first */
        if (a->type == JOB_NOP || b->type == JOB_NOP)
                return 0;

        if (a->ignore_order || b->ignore_order)
                return 0;

        if (assume_dep == UNIT_ATOM_AFTER)
                return -job_compare(b, a, UNIT_ATOM_BEFORE);

        /* Let's make it simple, JOB_STOP goes always first (in case both ua and ub stop, then ub's stop goes
         * first anyway). JOB_RESTART is JOB_STOP in disguise (before it is patched to JOB_START). */
        if (IN_SET(b->type, JOB_STOP, JOB_RESTART))
                return 1;
        else
                return -1;
}

void job_set_activation_details(Job *j, ActivationDetails *info) {
        /* Existing (older) ActivationDetails win, newer ones are discarded. */
        if (!j || j->activation_details || !info)
                return; /* Nothing to do. */

        j->activation_details = activation_details_ref(info);
}
