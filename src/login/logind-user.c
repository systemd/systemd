/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <unistd.h>

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-util.h"
#include "cgroup-util.h"
#include "clean-ipc.h"
#include "env-file.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "hashmap.h"
#include "label-util.h"
#include "limits-util.h"
#include "logind-dbus.h"
#include "logind-user-dbus.h"
#include "logind-user.h"
#include "mkdir-label.h"
#include "parse-util.h"
#include "path-util.h"
#include "percent-util.h"
#include "rm-rf.h"
#include "serialize.h"
#include "special.h"
#include "stdio-util.h"
#include "string-table.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "uid-classification.h"
#include "unit-name.h"
#include "user-util.h"

int user_new(Manager *m, UserRecord *ur, User **ret) {
        _cleanup_(user_freep) User *u = NULL;
        char lu[DECIMAL_STR_MAX(uid_t) + 1];
        int r;

        assert(m);
        assert(ur);
        assert(ret);

        if (!ur->user_name)
                return -EINVAL;

        if (!uid_is_valid(ur->uid))
                return -EINVAL;

        u = new(User, 1);
        if (!u)
                return -ENOMEM;

        *u = (User) {
                .manager = m,
                .user_record = user_record_ref(ur),
                .last_session_timestamp = USEC_INFINITY,
                .gc_mode = USER_GC_BY_ANY,
        };

        if (asprintf(&u->state_file, "/run/systemd/users/" UID_FMT, ur->uid) < 0)
                return -ENOMEM;

        if (asprintf(&u->runtime_path, "/run/user/" UID_FMT, ur->uid) < 0)
                return -ENOMEM;

        xsprintf(lu, UID_FMT, ur->uid);
        r = slice_build_subslice(SPECIAL_USER_SLICE, lu, &u->slice);
        if (r < 0)
                return r;

        r = unit_name_build("user-runtime-dir", lu, ".service", &u->runtime_dir_unit);
        if (r < 0)
                return r;

        r = unit_name_build("user", lu, ".service", &u->service_manager_unit);
        if (r < 0)
                return r;

        r = hashmap_put(m->users, UID_TO_PTR(ur->uid), u);
        if (r < 0)
                return r;

        r = hashmap_put(m->user_units, u->slice, u);
        if (r < 0)
                return r;

        r = hashmap_put(m->user_units, u->runtime_dir_unit, u);
        if (r < 0)
                return r;

        r = hashmap_put(m->user_units, u->service_manager_unit, u);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(u);
        return 0;
}

User *user_free(User *u) {
        if (!u)
                return NULL;

        if (u->in_gc_queue)
                LIST_REMOVE(gc_queue, u->manager->user_gc_queue, u);

        while (u->sessions)
                session_free(u->sessions);

        sd_event_source_unref(u->timer_event_source);

        if (u->service_manager_unit) {
                (void) hashmap_remove_value(u->manager->user_units, u->service_manager_unit, u);
                free(u->service_manager_job);
                free(u->service_manager_unit);
        }

        if (u->runtime_dir_unit) {
                (void) hashmap_remove_value(u->manager->user_units, u->runtime_dir_unit, u);
                free(u->runtime_dir_job);
                free(u->runtime_dir_unit);
        }

        if (u->slice) {
                (void) hashmap_remove_value(u->manager->user_units, u->slice, u);
                free(u->slice);
        }

        (void) hashmap_remove_value(u->manager->users, UID_TO_PTR(u->user_record->uid), u);

        free(u->runtime_path);
        free(u->state_file);

        user_record_unref(u->user_record);

        free(u->secure_lock_callbacks);
        free(u->secure_lock_userdata);
        sd_event_source_disable_unref(u->pending_secure_lock_timeout_source);
        sd_event_source_disable_unref(u->delay_secure_lock_event_source);
        sd_event_source_disable_unref(u->inhibit_auto_secure_lock_event_source);
        sd_event_source_disable_unref(u->secure_lock_backend_event_source);

        return mfree(u);
}

static int user_save_internal(User *u) {
        _cleanup_(unlink_and_freep) char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(u);
        assert(u->state_file);

        r = mkdir_safe_label("/run/systemd/users", 0755, 0, 0, MKDIR_WARN_MODE);
        if (r < 0)
                goto fail;

        r = fopen_temporary(u->state_file, &f, &temp_path);
        if (r < 0)
                goto fail;

        (void) fchmod(fileno(f), 0644);

        fprintf(f,
                "# This is private data. Do not parse.\n"
                "NAME=%s\n"
                "STATE=%s\n"         /* friendly user-facing state */
                "STOPPING=%s\n"      /* low-level state */
                "GC_MODE=%s\n",
                u->user_record->user_name,
                user_state_to_string(user_get_state(u)),
                yes_no(u->stopping),
                user_gc_mode_to_string(u->gc_mode));

        if (u->secure_lock_backend_event_source)
                fprintf(f, "SL_BACKEND=yes\n");
        if (u->delay_secure_lock_event_source)
                fprintf(f, "SL_DELAY=yes\n");
        if (u->inhibit_auto_secure_lock_event_source)
                fprintf(f, "SL_AUTO_INHIBITOR=yes\n");

        /* LEGACY: no-one reads RUNTIME= anymore, drop it at some point */
        if (u->runtime_path)
                fprintf(f, "RUNTIME=%s\n", u->runtime_path);

        if (u->runtime_dir_job)
                fprintf(f, "RUNTIME_DIR_JOB=%s\n", u->runtime_dir_job);

        if (u->service_manager_job)
                fprintf(f, "SERVICE_JOB=%s\n", u->service_manager_job);

        if (u->display)
                fprintf(f, "DISPLAY=%s\n", u->display->id);

        if (dual_timestamp_is_set(&u->timestamp))
                fprintf(f,
                        "REALTIME="USEC_FMT"\n"
                        "MONOTONIC="USEC_FMT"\n",
                        u->timestamp.realtime,
                        u->timestamp.monotonic);

        if (u->last_session_timestamp != USEC_INFINITY)
                fprintf(f, "LAST_SESSION_TIMESTAMP=" USEC_FMT "\n",
                        u->last_session_timestamp);

        if (u->sessions) {
                bool first;

                fputs("SESSIONS=", f);
                first = true;
                LIST_FOREACH(sessions_by_user, i, u->sessions) {
                        if (first)
                                first = false;
                        else
                                fputc(' ', f);

                        fputs(i->id, f);
                }

                fputs("\nSEATS=", f);
                first = true;
                LIST_FOREACH(sessions_by_user, i, u->sessions) {
                        if (!i->seat)
                                continue;

                        if (first)
                                first = false;
                        else
                                fputc(' ', f);

                        fputs(i->seat->id, f);
                }

                fputs("\nACTIVE_SESSIONS=", f);
                first = true;
                LIST_FOREACH(sessions_by_user, i, u->sessions) {
                        if (!session_is_active(i))
                                continue;

                        if (first)
                                first = false;
                        else
                                fputc(' ', f);

                        fputs(i->id, f);
                }

                fputs("\nONLINE_SESSIONS=", f);
                first = true;
                LIST_FOREACH(sessions_by_user, i, u->sessions) {
                        if (session_get_state(i) == SESSION_CLOSING)
                                continue;

                        if (first)
                                first = false;
                        else
                                fputc(' ', f);

                        fputs(i->id, f);
                }

                fputs("\nACTIVE_SEATS=", f);
                first = true;
                LIST_FOREACH(sessions_by_user, i, u->sessions) {
                        if (!session_is_active(i) || !i->seat)
                                continue;

                        if (first)
                                first = false;
                        else
                                fputc(' ', f);

                        fputs(i->seat->id, f);
                }

                fputs("\nONLINE_SEATS=", f);
                first = true;
                LIST_FOREACH(sessions_by_user, i, u->sessions) {
                        if (session_get_state(i) == SESSION_CLOSING || !i->seat)
                                continue;

                        if (first)
                                first = false;
                        else
                                fputc(' ', f);

                        fputs(i->seat->id, f);
                }
                fputc('\n', f);
        }

        r = fflush_and_check(f);
        if (r < 0)
                goto fail;

        if (rename(temp_path, u->state_file) < 0) {
                r = -errno;
                goto fail;
        }

        temp_path = mfree(temp_path);
        return 0;

fail:
        (void) unlink(u->state_file);

        return log_error_errno(r, "Failed to save user data %s: %m", u->state_file);
}

int user_save(User *u) {
        assert(u);

        if (!u->started)
                return 0;

        return user_save_internal(u);
}

int user_load(User *u) {
        _cleanup_free_ char *realtime = NULL, *monotonic = NULL, *stopping = NULL, *last_session_timestamp = NULL,
                            *gc_mode = NULL, *sl_backend = NULL, *sl_delay = NULL, *sl_auto_inhibitor = NULL;
        int r;

        assert(u);

        r = parse_env_file(NULL, u->state_file,
                           "RUNTIME_DIR_JOB",        &u->runtime_dir_job,
                           "SERVICE_JOB",            &u->service_manager_job,
                           "STOPPING",               &stopping,
                           "REALTIME",               &realtime,
                           "MONOTONIC",              &monotonic,
                           "LAST_SESSION_TIMESTAMP", &last_session_timestamp,
                           "GC_MODE",                &gc_mode,
                           "SL_BACKEND",             &sl_backend,
                           "SL_DELAY",               &sl_delay,
                           "SL_AUTO_INHIBITOR",      &sl_auto_inhibitor);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to read %s: %m", u->state_file);

        if (stopping) {
                r = parse_boolean(stopping);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse 'STOPPING' boolean: %s", stopping);
                else {
                        u->stopping = r;
                        if (u->stopping && !u->runtime_dir_job)
                                log_debug("User '%s' is stopping, but no job is being tracked.", u->user_record->user_name);
                }
        }

        if (realtime)
                (void) deserialize_usec(realtime, &u->timestamp.realtime);
        if (monotonic)
                (void) deserialize_usec(monotonic, &u->timestamp.monotonic);
        if (last_session_timestamp)
                (void) deserialize_usec(last_session_timestamp, &u->last_session_timestamp);

        u->gc_mode = user_gc_mode_from_string(gc_mode);
        if (u->gc_mode < 0)
                u->gc_mode = USER_GC_BY_PIN;

        /* Try to recover our FIFOs if they were open. */

        if (sl_backend) {
                _cleanup_close_ int fd = -EBADF;

                /* We reopen the FIFO on both sides, then immediately close the writing side.
                 * If a client still has its end of the FIFO open, we'll return to the state
                 * we were in before logind exited. If the client has since closed its end of
                 * the FIFO, we'll get a notification and handle it now. */

                fd = user_enable_secure_lock(u);
                if (fd < 0)
                        return log_error_errno(fd, "Failed to reopen secure lock backend: %m");
        }

        if (sl_delay) {
                _cleanup_close_ int fd = -EBADF;

                fd = user_delay_secure_lock(u);
                if (fd < 0)
                        return log_error_errno(fd, "Failed to reopen secure lock delay FIFO: %m");
        }

        if (sl_auto_inhibitor) {
                _cleanup_close_ int fd = -EBADF;

                fd = user_inhibit_auto_secure_lock(u);
                if (fd < 0)
                        return log_error_errno(fd, "Failed to reopen inhibit auto secure lock FIFO: %m");
        }

        return 0;
}

static int user_start_runtime_dir(User *u) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(u);
        assert(!u->stopping);
        assert(u->manager);
        assert(u->runtime_dir_unit);

        u->runtime_dir_job = mfree(u->runtime_dir_job);

        r = manager_start_unit(u->manager, u->runtime_dir_unit, &error, &u->runtime_dir_job);
        if (r < 0)
                return log_full_errno(sd_bus_error_has_name(&error, BUS_ERROR_UNIT_MASKED) ? LOG_DEBUG : LOG_ERR,
                                      r, "Failed to start user service '%s': %s",
                                      u->runtime_dir_unit, bus_error_message(&error, r));

        return 0;
}

static bool user_wants_service_manager(User *u) {
        assert(u);

        LIST_FOREACH(sessions_by_user, s, u->sessions)
                if (SESSION_CLASS_WANTS_SERVICE_MANAGER(s->class))
                        return true;

        return false;
}

int user_start_service_manager(User *u) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(u);
        assert(!u->stopping);
        assert(u->manager);
        assert(u->service_manager_unit);

        if (u->service_manager_started)
                return 1;

        /* Only start user service manager if there's at least one session which wants it */
        if (!user_wants_service_manager(u))
                return 0;

        u->service_manager_job = mfree(u->service_manager_job);

        r = manager_start_unit(u->manager, u->service_manager_unit, &error, &u->service_manager_job);
        if (r < 0) {
                if (sd_bus_error_has_name(&error, BUS_ERROR_UNIT_MASKED))
                        return 0;

                return log_error_errno(r, "Failed to start user service '%s': %s",
                                       u->service_manager_unit, bus_error_message(&error, r));
        }

        return (u->service_manager_started = true);
}

static int update_slice_callback(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        _cleanup_(user_record_unrefp) UserRecord *ur = ASSERT_PTR(userdata);
        const sd_bus_error *e;
        int r;

        assert(m);

        e = sd_bus_message_get_error(m);
        if (e) {
                r = sd_bus_error_get_errno(e);
                log_warning_errno(r,
                                  "Failed to update slice of %s, ignoring: %s",
                                  ur->user_name,
                                  bus_error_message(e, r));

                return 0;
        }

        log_debug("Successfully set slice parameters of %s.", ur->user_name);
        return 0;
}

static int user_update_slice(User *u) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        int r;

        assert(u);

        if (u->user_record->tasks_max == UINT64_MAX &&
            u->user_record->memory_high == UINT64_MAX &&
            u->user_record->memory_max == UINT64_MAX &&
            u->user_record->cpu_weight == UINT64_MAX &&
            u->user_record->io_weight == UINT64_MAX)
                return 0;

        r = bus_message_new_method_call(u->manager->bus, &m, bus_systemd_mgr, "SetUnitProperties");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "sb", u->slice, true);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'a', "(sv)");
        if (r < 0)
                return bus_log_create_error(r);

        const struct {
                const char *name;
                uint64_t value;
        } settings[] = {
                { "TasksMax",   u->user_record->tasks_max   },
                { "MemoryMax",  u->user_record->memory_max  },
                { "MemoryHigh", u->user_record->memory_high },
                { "CPUWeight",  u->user_record->cpu_weight  },
                { "IOWeight",   u->user_record->io_weight   },
        };

        FOREACH_ARRAY(st, settings, ELEMENTSOF(settings)) {
                if (st->value == UINT64_MAX)
                        continue;

                r = sd_bus_message_append(m, "(sv)", st->name, "t", st->value);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call_async(u->manager->bus, NULL, m, update_slice_callback, u->user_record, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to change user slice properties: %m");

        /* Ref the user record pointer, so that the slot keeps it pinned */
        user_record_ref(u->user_record);

        return 0;
}

int user_start(User *u) {
        int r;

        assert(u);

        if (u->service_manager_started) {
                /* Everything is up. No action needed. */
                assert(u->started && !u->stopping);
                return 0;
        }

        if (!u->started || u->stopping) {
                /* If u->stopping is set, the user is marked for removal and service stop-jobs are queued.
                 * We have to clear that flag before queueing the start-jobs again. If they succeed, the
                 * user object can be re-used just fine (pid1 takes care of job-ordering and proper restart),
                 * but if they fail, we want to force another user_stop() so possibly pending units are
                 * stopped. */
                u->stopping = false;

                if (!u->started)
                        log_debug("Tracking new user %s.", u->user_record->user_name);

                /* Save the user data so far, because pam_systemd will read the XDG_RUNTIME_DIR out of it
                 * while starting up systemd --user. We need to do user_save_internal() because we have not
                 * "officially" started yet. */
                user_save_internal(u);

                /* Set slice parameters */
                (void) user_update_slice(u);

                (void) user_start_runtime_dir(u);
        }

        /* Start user@UID.service if needed. */
        r = user_start_service_manager(u);
        if (r < 0)
                return r;

        if (!u->started) {
                if (!dual_timestamp_is_set(&u->timestamp))
                        dual_timestamp_now(&u->timestamp);

                user_send_signal(u, true);
                u->started = true;
        }

        /* Save new user data */
        user_save(u);

        return 0;
}

static void user_stop_service(User *u, bool force) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(u);
        assert(u->manager);
        assert(u->runtime_dir_unit);

        /* Note that we only stop user-runtime-dir@.service here, and let BindsTo= deal with the user@.service
         * instance. However, we still need to clear service_manager_job here, so that if the stop is
         * interrupted, the new sessions won't be confused by leftovers. */

        u->service_manager_job = mfree(u->service_manager_job);
        u->service_manager_started = false;

        u->runtime_dir_job = mfree(u->runtime_dir_job);

        r = manager_stop_unit(u->manager, u->runtime_dir_unit, force ? "replace" : "fail", &error, &u->runtime_dir_job);
        if (r < 0)
                log_warning_errno(r, "Failed to stop user service '%s', ignoring: %s",
                                  u->runtime_dir_unit, bus_error_message(&error, r));
}

int user_stop(User *u, bool force) {
        int r = 0;

        assert(u);

        /* This is called whenever we begin with tearing down a user record. It's called in two cases: explicit API
         * request to do so via the bus (in which case 'force' is true) and automatically due to GC, if there's no
         * session left pinning it (in which case 'force' is false). Note that this just initiates tearing down of the
         * user, the User object will remain in memory until user_finalize() is called, see below. */

        if (!u->started)
                return 0;

        if (u->stopping) { /* Stop jobs have already been queued */
                user_save(u);
                return 0;
        }

        LIST_FOREACH(sessions_by_user, s, u->sessions)
                RET_GATHER(r, session_stop(s, force));

        user_stop_service(u, force);

        u->stopping = true;

        user_save(u);

        return r;
}

static int user_finish_secure_lock(User *u, const sd_bus_error *error);

int user_finalize(User *u) {
        int r = 0;

        assert(u);

        /* Called when the user is really ready to be freed, i.e. when all unit stop jobs and suchlike for it are
         * done. This is called as a result of an earlier user_done() when all jobs are completed. */

        if (u->started)
                log_debug("User %s exited.", u->user_record->user_name);

        LIST_FOREACH(sessions_by_user, s, u->sessions)
                RET_GATHER(r, session_finalize(s));

        /* Clean SysV + POSIX IPC objects, but only if this is not a system user. Background: in many setups cronjobs
         * are run in full PAM and thus logind sessions, even if the code run doesn't belong to actual users but to
         * system components. Since enable RemoveIPC= globally for all users, we need to be a bit careful with such
         * cases, as we shouldn't accidentally remove a system service's IPC objects while it is running, just because
         * a cronjob running as the same user just finished. Hence: exclude system users generally from IPC clean-up,
         * and do it only for normal users. */
        if (u->manager->remove_ipc && !uid_is_system(u->user_record->uid))
                RET_GATHER(r, clean_ipc_by_uid(u->user_record->uid));

        (void) unlink(u->state_file);
        user_add_to_gc_queue(u);

        if (u->started) {
                user_send_signal(u, false);
                u->started = false;
        }

        if (u->n_pending_secure_locks > 0) { /* We have pending SecureLock() calls */
                /* Stop waiting for whatever we were waiting for */
                u->secure_lock_backend_event_source = sd_event_source_disable_unref(u->secure_lock_backend_event_source);
                u->pending_secure_lock_timeout_source = sd_event_source_disable_unref(u->pending_secure_lock_timeout_source);

                /* Return an error */
                (void) user_finish_secure_lock(u, &SD_BUS_ERROR_MAKE_CONST(BUS_ERROR_NO_SUCH_USER, "User is exiting."));
        }

        return r;
}

int user_get_idle_hint(User *u, dual_timestamp *t) {
        bool idle_hint = true;
        dual_timestamp ts = DUAL_TIMESTAMP_NULL;

        assert(u);

        LIST_FOREACH(sessions_by_user, s, u->sessions) {
                dual_timestamp k;
                int ih;

                if (!SESSION_CLASS_CAN_IDLE(s->class))
                        continue;

                ih = session_get_idle_hint(s, &k);
                if (ih < 0)
                        return ih;

                if (!ih) {
                        if (!idle_hint) {
                                if (k.monotonic < ts.monotonic)
                                        ts = k;
                        } else {
                                idle_hint = false;
                                ts = k;
                        }
                } else if (idle_hint) {

                        if (k.monotonic > ts.monotonic)
                                ts = k;
                }
        }

        if (t)
                *t = ts;

        return idle_hint;
}

int user_check_linger_file(User *u) {
        _cleanup_free_ char *cc = NULL;
        char *p = NULL;

        cc = cescape(u->user_record->user_name);
        if (!cc)
                return -ENOMEM;

        p = strjoina("/var/lib/systemd/linger/", cc);
        if (access(p, F_OK) < 0) {
                if (errno != ENOENT)
                        return -errno;

                return false;
        }

        return true;
}

static bool user_unit_active(User *u) {
        int r;

        assert(u->slice);
        assert(u->runtime_dir_unit);
        assert(u->service_manager_unit);

        FOREACH_STRING(i, u->slice, u->runtime_dir_unit, u->service_manager_unit) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                r = manager_unit_is_active(u->manager, i, &error);
                if (r < 0)
                        log_debug_errno(r, "Failed to determine whether unit '%s' is active, ignoring: %s", i, bus_error_message(&error, r));
                if (r != 0)
                        return true;
        }

        return false;
}

static usec_t user_get_stop_delay(User *u) {
        assert(u);

        if (u->user_record->stop_delay_usec != UINT64_MAX)
                return u->user_record->stop_delay_usec;

        if (user_record_removable(u->user_record) > 0)
                return 0; /* For removable users lower the stop delay to zero */

        return u->manager->user_stop_delay;
}

static bool user_pinned_by_sessions(User *u) {
        assert(u);

        /* Returns true if at least one session exists that shall keep the user tracking alive. That
         * generally means one session that isn't the service manager still exists. */

        switch (u->gc_mode) {

        case USER_GC_BY_ANY:
                return u->sessions;

        case USER_GC_BY_PIN:
                LIST_FOREACH(sessions_by_user, i, u->sessions)
                        if (SESSION_CLASS_PIN_USER(i->class))
                                return true;

                return false;

        default:
                assert_not_reached();
        }
}

bool user_may_gc(User *u, bool drop_not_started) {
        int r;

        assert(u);

        if (drop_not_started && !u->started)
                return true;

        if (user_pinned_by_sessions(u))
                return false;

        if (u->last_session_timestamp != USEC_INFINITY) {
                usec_t user_stop_delay;

                /* All sessions have been closed. Let's see if we shall leave the user record around for a bit */

                user_stop_delay = user_get_stop_delay(u);

                if (user_stop_delay == USEC_INFINITY)
                        return false; /* Leave it around forever! */
                if (user_stop_delay > 0 &&
                    now(CLOCK_MONOTONIC) < usec_add(u->last_session_timestamp, user_stop_delay))
                        return false; /* Leave it around for a bit longer. */
        }

        /* Is this a user that shall stay around forever ("linger")? Before we say "no" to GC'ing for lingering users, let's check
         * if any of the three units that we maintain for this user is still around. If none of them is,
         * there's no need to keep this user around even if lingering is enabled. */
        if (user_check_linger_file(u) > 0 && user_unit_active(u))
                return false;

        /* Check if our job is still pending */
        const char *j;
        FOREACH_ARGUMENT(j, u->runtime_dir_job, u->service_manager_job) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                if (!j)
                        continue;

                r = manager_job_is_active(u->manager, j, &error);
                if (r < 0)
                        log_debug_errno(r, "Failed to determine whether job '%s' is pending, ignoring: %s",
                                        j, bus_error_message(&error, r));
                if (r != 0)
                        return false;
        }

        /* Note that we don't care if the three units we manage for each user object are up or not, as we are
         * managing their state rather than tracking it. */

        return true;
}

void user_add_to_gc_queue(User *u) {
        assert(u);

        if (u->in_gc_queue)
                return;

        LIST_PREPEND(gc_queue, u->manager->user_gc_queue, u);
        u->in_gc_queue = true;
}

UserState user_get_state(User *u) {
        assert(u);

        if (u->stopping)
                return USER_CLOSING;

        if (!u->started || u->runtime_dir_job)
                return USER_OPENING;

        bool any = false, all_closing = true;
        LIST_FOREACH(sessions_by_user, i, u->sessions) {
                SessionState state;

                /* Ignore sessions that don't pin the user, i.e. are not supposed to have an effect on user state */
                if (!SESSION_CLASS_PIN_USER(i->class))
                        continue;

                state = session_get_state(i);
                if (state == SESSION_ACTIVE)
                        return USER_ACTIVE;
                if (state != SESSION_CLOSING)
                        all_closing = false;

                any = true;
        }

        if (any)
                return all_closing ? USER_CLOSING : USER_ONLINE;

        if (user_check_linger_file(u) > 0 && user_unit_active(u))
                return USER_LINGERING;

        return USER_CLOSING;
}

int user_kill(User *u, int signo) {
        assert(u);

        return manager_kill_unit(u->manager, u->slice, KILL_ALL, signo, NULL);
}

bool user_can_secure_lock(User *u) {
        assert(u);

        LIST_FOREACH(sessions_by_user, s, u->sessions)
                if (SESSION_CLASS_CAN_LOCK(s->class) && !s->can_secure_lock)
                        return false;

        return !!u->secure_lock_backend_event_source;
}

bool user_should_auto_secure_lock(User *u) {
        assert(u);

        if (!user_can_secure_lock(u))
                return false;

        return !u->inhibit_auto_secure_lock_event_source;
}

static int user_finish_secure_lock(User *u, const sd_bus_error *error) {
        assert(u);

        for (size_t i = 0; i < u->n_pending_secure_locks; i++) {
                user_secure_lock_cb_t cb = u->secure_lock_callbacks[i];
                void *userdata = u->secure_lock_userdata[i];

                cb(u, userdata, error);
        }

        u->secure_lock_callbacks = mfree(u->secure_lock_callbacks);
        u->secure_lock_userdata = mfree(u->secure_lock_userdata);
        u->n_pending_secure_locks = 0;

        return 0;
}

static int user_on_delayed_secure_lock(sd_event_source *s, uint64_t usec, void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        User *u = ASSERT_PTR(userdata);
        int r;

        u->pending_secure_lock_timeout_source = sd_event_source_disable_unref(u->pending_secure_lock_timeout_source);

        log_info("Delayed secure lock for user %s timed out, locking now.", u->user_record->user_name);

        r = user_send_trigger_secure_lock(u);
        if (r < 0) {
                sd_bus_error_set_errnof(&error, r, "Failed to emit TriggerSecureLock(): %m");
                return user_finish_secure_lock(u, &error);
        }

        return 0;
}

int user_secure_lock(User *u, user_secure_lock_cb_t cb, void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(u);
        assert(cb);

        if (!GREEDY_REALLOC(u->secure_lock_callbacks, u->n_pending_secure_locks + 1))
                return log_oom();
        if (!GREEDY_REALLOC(u->secure_lock_userdata, u->n_pending_secure_locks + 1))
                return log_oom();
        u->secure_lock_callbacks[u->n_pending_secure_locks] = cb;
        u->secure_lock_userdata[u->n_pending_secure_locks] = userdata;
        u->n_pending_secure_locks++;

        if (u->n_pending_secure_locks > 1) /* We're already processing another secure lock request */
                return 0;

        r = user_send_prepare_for_secure_lock(u, true);
        if (r < 0)
                log_warning_errno(r, "Failed to emit PrepareForSecureLock(true), ignoring: %m");

        if (u->delay_secure_lock_event_source) {
                log_info("Delaying secure lock for user %s.", u->user_record->user_name);

                assert(!u->pending_secure_lock_timeout_source); /* Otherwise n_pending_secure_locks must be > 1 */

                r = sd_event_add_time_relative(
                                u->manager->event,
                                &u->pending_secure_lock_timeout_source,
                                CLOCK_MONOTONIC,
                                u->manager->inhibit_delay_max,
                                0 /* default accuracy */,
                                user_on_delayed_secure_lock,
                                u);
                if (r >= 0) {
                        (void) sd_event_source_set_description(u->pending_secure_lock_timeout_source, "pending-secure-lock");
                        return 0;
                }

                log_warning_errno(r,
                                  "Failed to schedule delayed secure lock for user %s, locking immediately: %m",
                                  u->user_record->user_name);
        } else
                log_info("Secure locking user %s now.", u->user_record->user_name);

        r = user_send_trigger_secure_lock(u);
        if (r < 0) {
                sd_bus_error_set_errnof(&error, r, "Failed to emit TriggerSecureLock(): %m");
                return user_finish_secure_lock(u, &error);
        }

        return 0;
}

static int secure_lock_open_fifo(User *u, sd_event_source **ret, const char *name, sd_event_io_handler_t handler) {
        _cleanup_(sd_event_source_disable_unrefp) sd_event_source *evt = NULL;
        _cleanup_close_ int fd = -EBADF;
        const char *fn;
        int r;

        fn = strjoina("/run/systemd/users/", u->user_record->user_name, ".", name);

        if (!*ret) {
                _cleanup_close_ int read_fd = -EBADF;

                r = mkdir_safe_label("/run/systemd/users", 0755, 0, 0, MKDIR_WARN_MODE);
                if (r < 0)
                        return log_error_errno(r, "Failed to create /run/systemd/users: %m");

                if (mkfifo(fn, 0600) < 0 && errno != EEXIST)
                        return log_error_errno(errno, "Failed to create FIFO %s: %m", fn);

                read_fd = open(fn, O_RDONLY|O_CLOEXEC|O_NONBLOCK);
                if (read_fd < 0)
                        return log_error_errno(errno, "Failed to open FIFO %s for reading: %m", fn);

                r = sd_event_add_io(u->manager->event, &evt, read_fd, 0, handler, u);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate %s FIFO event source: %m", name);

                (void) sd_event_source_set_description(evt, name);

                r = sd_event_source_set_io_fd_own(evt, true);
                if (r < 0)
                        return log_error_errno(r, "failed to pass ownership of FIFO event fd to event source: %m");
                TAKE_FD(read_fd);
        }

        fd = open(fn, O_WRONLY|O_CLOEXEC|O_NONBLOCK);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open FIFO %s for writing: %m", fn);

        *ret = TAKE_PTR(evt);
        return TAKE_FD(fd);
}

static int user_secure_lock_backend_eof(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        User *u = ASSERT_PTR(userdata);

        u->pending_secure_lock_timeout_source = sd_event_source_disable_unref(u->pending_secure_lock_timeout_source);
        u->secure_lock_backend_event_source = sd_event_source_disable_unref(u->secure_lock_backend_event_source);

        log_info("Dropped secure lock backend for user %s.", u->user_record->user_name);

        return user_finish_secure_lock(u, NULL);
}

int user_enable_secure_lock(User *u) {
        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(u);

        if (u->secure_lock_backend_event_source)
                return -EBUSY;

        r = user_send_prepare_for_secure_lock(u, false);
        if (r < 0)
                return r;

        fd = secure_lock_open_fifo(u,
                                   &u->secure_lock_backend_event_source,
                                   "secure-lock-backend",
                                   user_secure_lock_backend_eof);
        if (fd < 0)
                return fd;

        log_info("Set up secure lock backend for user %s.", u->user_record->user_name);

        return TAKE_FD(fd);
}

static int user_delay_secure_lock_eof(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        User *u = ASSERT_PTR(userdata);
        int r;

        u->delay_secure_lock_event_source = sd_event_source_disable_unref(u->delay_secure_lock_event_source);

        if (!u->pending_secure_lock_timeout_source) {
                log_info("All clients dropped requests to delay secure lock of user %s.", u->user_record->user_name);
                return 0;
        } else
                log_info("All clients dropped requests to delay secure lock of user %s, locking now.", u->user_record->user_name);

        u->pending_secure_lock_timeout_source = sd_event_source_disable_unref(u->pending_secure_lock_timeout_source);

        r = user_send_trigger_secure_lock(u);
        if (r < 0) {
                sd_bus_error_set_errnof(&error, r, "Failed to emit TriggerSecureLock(): %m");
                return user_finish_secure_lock(u, &error);
        }

        return 0;
}

int user_delay_secure_lock(User *u) {
        assert(u);

        if (!u->delay_secure_lock_event_source)
                log_info("A client has requested to delay secure lock of user %s.", u->user_record->user_name);

        return secure_lock_open_fifo(u,
                                     &u->delay_secure_lock_event_source,
                                     "delay-secure-lock",
                                     user_delay_secure_lock_eof);
}

static int user_inhibit_auto_secure_lock_eof(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        User *u = ASSERT_PTR(userdata);
        u->inhibit_auto_secure_lock_event_source = sd_event_source_disable_unref(u->inhibit_auto_secure_lock_event_source);
        log_info("All clients dropped requests to inhibit automatic secure lock of user %s.", u->user_record->user_name);
        return 0;
}

int user_inhibit_auto_secure_lock(User *u) {
        assert(u);

        if (!u->inhibit_auto_secure_lock_event_source)
                log_info("A client has requested to inhibit automatic secure lock of user %s.", u->user-record->user_name);

        return secure_lock_open_fifo(u,
                                     &u->inhibit_auto_secure_lock_event_source,
                                     "inhibit-auto-secure-lock",
                                     user_inhibit_auto_secure_lock_eof);
}

static bool elect_display_filter(Session *s) {
        /* Return true if the session is a candidate for the user’s ‘primary session’ or ‘display’. */
        assert(s);

        return SESSION_CLASS_CAN_DISPLAY(s->class) && s->started && !s->stopping;
}

static int elect_display_compare(Session *s1, Session *s2) {
        /* Indexed by SessionType. Lower numbers mean more preferred. */
        static const int type_ranks[_SESSION_TYPE_MAX] = {
                [SESSION_UNSPECIFIED] = 0,
                [SESSION_TTY] = -2,
                [SESSION_X11] = -3,
                [SESSION_WAYLAND] = -3,
                [SESSION_MIR] = -3,
                [SESSION_WEB] = -1,
        };

        /* Calculate the partial order relationship between s1 and s2,
         * returning < 0 if s1 is preferred as the user’s ‘primary session’,
         * 0 if s1 and s2 are equally preferred or incomparable, or > 0 if s2
         * is preferred.
         *
         * s1 or s2 may be NULL. */
        if (!s1 && !s2)
                return 0;

        if ((s1 == NULL) != (s2 == NULL))
                return (s1 == NULL) - (s2 == NULL);

        if (s1->stopping != s2->stopping)
                return s1->stopping - s2->stopping;

        if ((s1->class != SESSION_USER) != (s2->class != SESSION_USER))
                return (s1->class != SESSION_USER) - (s2->class != SESSION_USER);

        if ((s1->class != SESSION_USER_EARLY) != (s2->class != SESSION_USER_EARLY))
                return (s1->class != SESSION_USER_EARLY) - (s2->class != SESSION_USER_EARLY);

        if ((s1->type == _SESSION_TYPE_INVALID) != (s2->type == _SESSION_TYPE_INVALID))
                return (s1->type == _SESSION_TYPE_INVALID) - (s2->type == _SESSION_TYPE_INVALID);

        if (s1->type != s2->type)
                return type_ranks[s1->type] - type_ranks[s2->type];

        return 0;
}

void user_elect_display(User *u) {
        assert(u);

        /* This elects a primary session for each user, which we call the "display". We try to keep the assignment
         * stable, but we "upgrade" to better choices. */
        log_debug("Electing new display for user %s", u->user_record->user_name);

        LIST_FOREACH(sessions_by_user, s, u->sessions) {
                if (!elect_display_filter(s)) {
                        log_debug("Ignoring session %s", s->id);
                        continue;
                }

                if (elect_display_compare(s, u->display) < 0) {
                        log_debug("Choosing session %s in preference to %s", s->id, u->display ? u->display->id : "-");
                        u->display = s;
                }
        }
}

static int user_stop_timeout_callback(sd_event_source *es, uint64_t usec, void *userdata) {
        User *u = ASSERT_PTR(userdata);

        user_add_to_gc_queue(u);

        return 0;
}

void user_update_last_session_timer(User *u) {
        usec_t user_stop_delay;
        int r;

        assert(u);

        if (user_pinned_by_sessions(u)) {
                /* There are sessions, turn off the timer */
                u->last_session_timestamp = USEC_INFINITY;
                u->timer_event_source = sd_event_source_unref(u->timer_event_source);
                return;
        }

        if (u->last_session_timestamp != USEC_INFINITY)
                return; /* Timer already started */

        u->last_session_timestamp = now(CLOCK_MONOTONIC);

        assert(!u->timer_event_source);

        user_stop_delay = user_get_stop_delay(u);
        if (!timestamp_is_set(user_stop_delay))
                return;

        if (sd_event_get_state(u->manager->event) == SD_EVENT_FINISHED) {
                log_debug("Not allocating user stop timeout, since we are already exiting.");
                return;
        }

        r = sd_event_add_time(u->manager->event,
                              &u->timer_event_source,
                              CLOCK_MONOTONIC,
                              usec_add(u->last_session_timestamp, user_stop_delay), 0,
                              user_stop_timeout_callback, u);
        if (r < 0)
                log_warning_errno(r, "Failed to enqueue user stop event source, ignoring: %m");

        if (DEBUG_LOGGING)
                log_debug("Last session of user '%s' logged out, terminating user context in %s.",
                          u->user_record->user_name,
                          FORMAT_TIMESPAN(user_stop_delay, USEC_PER_MSEC));
}

static const char* const user_state_table[_USER_STATE_MAX] = {
        [USER_OFFLINE]   = "offline",
        [USER_OPENING]   = "opening",
        [USER_LINGERING] = "lingering",
        [USER_ONLINE]    = "online",
        [USER_ACTIVE]    = "active",
        [USER_CLOSING]   = "closing"
};

DEFINE_STRING_TABLE_LOOKUP(user_state, UserState);

static const char* const user_gc_mode_table[_USER_GC_MODE_MAX] = {
        [USER_GC_BY_PIN] = "pin",
        [USER_GC_BY_ANY] = "any",
};

DEFINE_STRING_TABLE_LOOKUP(user_gc_mode, UserGCMode);

int config_parse_tmpfs_size(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        uint64_t *sz = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        /* First, try to parse as percentage */
        r = parse_permyriad(rvalue);
        if (r > 0)
                *sz = physical_memory_scale(r, 10000U);
        else {
                uint64_t k;

                /* If the passed argument was not a percentage, or out of range, parse as byte size */

                r = parse_size(rvalue, 1024, &k);
                if (r >= 0 && (k <= 0 || (uint64_t) (size_t) k != k))
                        r = -ERANGE;
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse size value '%s', ignoring: %m", rvalue);
                        return 0;
                }

                *sz = PAGE_ALIGN((size_t) k);
        }

        return 0;
}

int config_parse_compat_user_tasks_max(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        log_syntax(unit, LOG_NOTICE, filename, line, 0,
                   "Support for option %s= has been removed.",
                   lvalue);
        log_info("Hint: try creating /etc/systemd/system/user-.slice.d/50-limits.conf with:\n"
                 "        [Slice]\n"
                 "        TasksMax=%s",
                 rvalue);
        return 0;
}
