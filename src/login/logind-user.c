/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "bus-error.h"
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
#include "label.h"
#include "limits-util.h"
#include "logind-dbus.h"
#include "logind-user.h"
#include "logind-user-dbus.h"
#include "mkdir.h"
#include "parse-util.h"
#include "path-util.h"
#include "rm-rf.h"
#include "serialize.h"
#include "special.h"
#include "stdio-util.h"
#include "string-table.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "unit-name.h"
#include "user-util.h"
#include "util.h"

int user_new(User **ret,
             Manager *m,
             uid_t uid,
             gid_t gid,
             const char *name,
             const char *home) {

        _cleanup_(user_freep) User *u = NULL;
        char lu[DECIMAL_STR_MAX(uid_t) + 1];
        int r;

        assert(ret);
        assert(m);
        assert(name);

        u = new(User, 1);
        if (!u)
                return -ENOMEM;

        *u = (User) {
                .manager = m,
                .uid = uid,
                .gid = gid,
                .last_session_timestamp = USEC_INFINITY,
        };

        u->name = strdup(name);
        if (!u->name)
                return -ENOMEM;

        u->home = strdup(home);
        if (!u->home)
                return -ENOMEM;

        path_simplify(u->home, true);

        if (asprintf(&u->state_file, "/run/systemd/users/"UID_FMT, uid) < 0)
                return -ENOMEM;

        if (asprintf(&u->runtime_path, "/run/user/"UID_FMT, uid) < 0)
                return -ENOMEM;

        xsprintf(lu, UID_FMT, uid);
        r = slice_build_subslice(SPECIAL_USER_SLICE, lu, &u->slice);
        if (r < 0)
                return r;

        r = unit_name_build("user", lu, ".service", &u->service);
        if (r < 0)
                return r;

        r = unit_name_build("user-runtime-dir", lu, ".service", &u->runtime_dir_service);
        if (r < 0)
                return r;

        r = hashmap_put(m->users, UID_TO_PTR(uid), u);
        if (r < 0)
                return r;

        r = hashmap_put(m->user_units, u->slice, u);
        if (r < 0)
                return r;

        r = hashmap_put(m->user_units, u->service, u);
        if (r < 0)
                return r;

        r = hashmap_put(m->user_units, u->runtime_dir_service, u);
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

        if (u->service)
                hashmap_remove_value(u->manager->user_units, u->service, u);

        if (u->runtime_dir_service)
                hashmap_remove_value(u->manager->user_units, u->runtime_dir_service, u);

        if (u->slice)
                hashmap_remove_value(u->manager->user_units, u->slice, u);

        hashmap_remove_value(u->manager->users, UID_TO_PTR(u->uid), u);

        (void) sd_event_source_unref(u->timer_event_source);

        u->service_job = mfree(u->service_job);

        u->service = mfree(u->service);
        u->runtime_dir_service = mfree(u->runtime_dir_service);
        u->slice = mfree(u->slice);
        u->runtime_path = mfree(u->runtime_path);
        u->state_file = mfree(u->state_file);
        u->name = mfree(u->name);
        u->home = mfree(u->home);

        return mfree(u);
}

static int user_save_internal(User *u) {
        _cleanup_free_ char *temp_path = NULL;
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
                "STOPPING=%s\n",     /* low-level state */
                u->name,
                user_state_to_string(user_get_state(u)),
                yes_no(u->stopping));

        /* LEGACY: no-one reads RUNTIME= anymore, drop it at some point */
        if (u->runtime_path)
                fprintf(f, "RUNTIME=%s\n", u->runtime_path);

        if (u->service_job)
                fprintf(f, "SERVICE_JOB=%s\n", u->service_job);

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
                Session *i;
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

        return 0;

fail:
        (void) unlink(u->state_file);

        if (temp_path)
                (void) unlink(temp_path);

        return log_error_errno(r, "Failed to save user data %s: %m", u->state_file);
}

int user_save(User *u) {
        assert(u);

        if (!u->started)
                return 0;

        return user_save_internal(u);
}

int user_load(User *u) {
        _cleanup_free_ char *realtime = NULL, *monotonic = NULL, *stopping = NULL, *last_session_timestamp = NULL;
        int r;

        assert(u);

        r = parse_env_file(NULL, u->state_file,
                           "SERVICE_JOB",            &u->service_job,
                           "STOPPING",               &stopping,
                           "REALTIME",               &realtime,
                           "MONOTONIC",              &monotonic,
                           "LAST_SESSION_TIMESTAMP", &last_session_timestamp);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to read %s: %m", u->state_file);

        if (stopping) {
                r = parse_boolean(stopping);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse 'STOPPING' boolean: %s", stopping);
                else
                        u->stopping = r;
        }

        if (realtime)
                (void) deserialize_usec(realtime, &u->timestamp.realtime);
        if (monotonic)
                (void) deserialize_usec(monotonic, &u->timestamp.monotonic);
        if (last_session_timestamp)
                (void) deserialize_usec(last_session_timestamp, &u->last_session_timestamp);

        return 0;
}

static void user_start_service(User *u) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(u);

        /* Start the service containing the "systemd --user" instance (user@.service). Note that we don't explicitly
         * start the per-user slice or the systemd-runtime-dir@.service instance, as those are pulled in both by
         * user@.service and the session scopes as dependencies. */

        u->service_job = mfree(u->service_job);

        r = manager_start_unit(u->manager, u->service, &error, &u->service_job);
        if (r < 0)
                log_full_errno(sd_bus_error_has_name(&error, BUS_ERROR_UNIT_MASKED) ? LOG_DEBUG : LOG_WARNING, r,
                               "Failed to start user service '%s', ignoring: %s", u->service, bus_error_message(&error, r));
}

int user_start(User *u) {
        assert(u);

        if (u->started && !u->stopping)
                return 0;

        /* If u->stopping is set, the user is marked for removal and service stop-jobs are queued. We have to clear
         * that flag before queueing the start-jobs again. If they succeed, the user object can be re-used just fine
         * (pid1 takes care of job-ordering and proper restart), but if they fail, we want to force another user_stop()
         * so possibly pending units are stopped. */
        u->stopping = false;

        if (!u->started)
                log_debug("Starting services for new user %s.", u->name);

        /* Save the user data so far, because pam_systemd will read the XDG_RUNTIME_DIR out of it while starting up
         * systemd --user.  We need to do user_save_internal() because we have not "officially" started yet. */
        user_save_internal(u);

        /* Start user@UID.service */
        user_start_service(u);

        if (!u->started) {
                if (!dual_timestamp_is_set(&u->timestamp))
                        dual_timestamp_get(&u->timestamp);
                user_send_signal(u, true);
                u->started = true;
        }

        /* Save new user data */
        user_save(u);

        return 0;
}

static void user_stop_service(User *u) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(u);
        assert(u->service);

        /* The reverse of user_start_service(). Note that we only stop user@UID.service here, and let StopWhenUnneeded=
         * deal with the slice and the user-runtime-dir@.service instance. */

        u->service_job = mfree(u->service_job);

        r = manager_stop_unit(u->manager, u->service, &error, &u->service_job);
        if (r < 0)
                log_warning_errno(r, "Failed to stop user service '%s', ignoring: %s", u->service, bus_error_message(&error, r));
}

int user_stop(User *u, bool force) {
        Session *s;
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

        LIST_FOREACH(sessions_by_user, s, u->sessions) {
                int k;

                k = session_stop(s, force);
                if (k < 0)
                        r = k;
        }

        user_stop_service(u);

        u->stopping = true;

        user_save(u);

        return r;
}

int user_finalize(User *u) {
        Session *s;
        int r = 0, k;

        assert(u);

        /* Called when the user is really ready to be freed, i.e. when all unit stop jobs and suchlike for it are
         * done. This is called as a result of an earlier user_done() when all jobs are completed. */

        if (u->started)
                log_debug("User %s logged out.", u->name);

        LIST_FOREACH(sessions_by_user, s, u->sessions) {
                k = session_finalize(s);
                if (k < 0)
                        r = k;
        }

        /* Clean SysV + POSIX IPC objects, but only if this is not a system user. Background: in many setups cronjobs
         * are run in full PAM and thus logind sessions, even if the code run doesn't belong to actual users but to
         * system components. Since enable RemoveIPC= globally for all users, we need to be a bit careful with such
         * cases, as we shouldn't accidentally remove a system service's IPC objects while it is running, just because
         * a cronjob running as the same user just finished. Hence: exclude system users generally from IPC clean-up,
         * and do it only for normal users. */
        if (u->manager->remove_ipc && !uid_is_system(u->uid)) {
                k = clean_ipc_by_uid(u->uid);
                if (k < 0)
                        r = k;
        }

        (void) unlink(u->state_file);
        user_add_to_gc_queue(u);

        if (u->started) {
                user_send_signal(u, false);
                u->started = false;
        }

        return r;
}

int user_get_idle_hint(User *u, dual_timestamp *t) {
        Session *s;
        bool idle_hint = true;
        dual_timestamp ts = DUAL_TIMESTAMP_NULL;

        assert(u);

        LIST_FOREACH(sessions_by_user, s, u->sessions) {
                dual_timestamp k;
                int ih;

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

        cc = cescape(u->name);
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
        const char *i;
        int r;

        assert(u->service);
        assert(u->runtime_dir_service);
        assert(u->slice);

        FOREACH_STRING(i, u->service, u->runtime_dir_service, u->slice) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                r = manager_unit_is_active(u->manager, i, &error);
                if (r < 0)
                        log_debug_errno(r, "Failed to determine whether unit '%s' is active, ignoring: %s", u->service, bus_error_message(&error, r));
                if (r != 0)
                        return true;
        }

        return false;
}

bool user_may_gc(User *u, bool drop_not_started) {
        int r;

        assert(u);

        if (drop_not_started && !u->started)
                return true;

        if (u->sessions)
                return false;

        if (u->last_session_timestamp != USEC_INFINITY) {
                /* All sessions have been closed. Let's see if we shall leave the user record around for a bit */

                if (u->manager->user_stop_delay == USEC_INFINITY)
                        return false; /* Leave it around forever! */
                if (u->manager->user_stop_delay > 0 &&
                    now(CLOCK_MONOTONIC) < usec_add(u->last_session_timestamp, u->manager->user_stop_delay))
                        return false; /* Leave it around for a bit longer. */
        }

        /* Is this a user that shall stay around forever ("linger")? Before we say "no" to GC'ing for lingering users, let's check
         * if any of the three units that we maintain for this user is still around. If none of them is,
         * there's no need to keep this user around even if lingering is enabled. */
        if (user_check_linger_file(u) > 0 && user_unit_active(u))
                return false;

        /* Check if our job is still pending */
        if (u->service_job) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                r = manager_job_is_active(u->manager, u->service_job, &error);
                if (r < 0)
                        log_debug_errno(r, "Failed to determine whether job '%s' is pending, ignoring: %s", u->service_job, bus_error_message(&error, r));
                if (r != 0)
                        return false;
        }

        /* Note that we don't care if the three units we manage for each user object are up or not, as we are managing
         * their state rather than tracking it. */

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
        Session *i;

        assert(u);

        if (u->stopping)
                return USER_CLOSING;

        if (!u->started || u->service_job)
                return USER_OPENING;

        if (u->sessions) {
                bool all_closing = true;

                LIST_FOREACH(sessions_by_user, i, u->sessions) {
                        SessionState state;

                        state = session_get_state(i);
                        if (state == SESSION_ACTIVE)
                                return USER_ACTIVE;
                        if (state != SESSION_CLOSING)
                                all_closing = false;
                }

                return all_closing ? USER_CLOSING : USER_ONLINE;
        }

        if (user_check_linger_file(u) > 0 && user_unit_active(u))
                return USER_LINGERING;

        return USER_CLOSING;
}

int user_kill(User *u, int signo) {
        assert(u);

        return manager_kill_unit(u->manager, u->slice, KILL_ALL, signo, NULL);
}

static bool elect_display_filter(Session *s) {
        /* Return true if the session is a candidate for the user’s ‘primary session’ or ‘display’. */
        assert(s);

        return IN_SET(s->class, SESSION_USER, SESSION_GREETER) && s->started && !s->stopping;
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

        if ((s1->type == _SESSION_TYPE_INVALID) != (s2->type == _SESSION_TYPE_INVALID))
                return (s1->type == _SESSION_TYPE_INVALID) - (s2->type == _SESSION_TYPE_INVALID);

        if (s1->type != s2->type)
                return type_ranks[s1->type] - type_ranks[s2->type];

        return 0;
}

void user_elect_display(User *u) {
        Session *s;

        assert(u);

        /* This elects a primary session for each user, which we call the "display". We try to keep the assignment
         * stable, but we "upgrade" to better choices. */
        log_debug("Electing new display for user %s", u->name);

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
        User *u = userdata;

        assert(u);
        user_add_to_gc_queue(u);

        return 0;
}

void user_update_last_session_timer(User *u) {
        int r;

        assert(u);

        if (u->sessions) {
                /* There are sessions, turn off the timer */
                u->last_session_timestamp = USEC_INFINITY;
                u->timer_event_source = sd_event_source_unref(u->timer_event_source);
                return;
        }

        if (u->last_session_timestamp != USEC_INFINITY)
                return; /* Timer already started */

        u->last_session_timestamp = now(CLOCK_MONOTONIC);

        assert(!u->timer_event_source);

        if (IN_SET(u->manager->user_stop_delay, 0, USEC_INFINITY))
                return;

        if (sd_event_get_state(u->manager->event) == SD_EVENT_FINISHED) {
                log_debug("Not allocating user stop timeout, since we are already exiting.");
                return;
        }

        r = sd_event_add_time(u->manager->event,
                              &u->timer_event_source,
                              CLOCK_MONOTONIC,
                              usec_add(u->last_session_timestamp, u->manager->user_stop_delay), 0,
                              user_stop_timeout_callback, u);
        if (r < 0)
                log_warning_errno(r, "Failed to enqueue user stop event source, ignoring: %m");

        if (DEBUG_LOGGING) {
                char s[FORMAT_TIMESPAN_MAX];

                log_debug("Last session of user '%s' logged out, terminating user context in %s.",
                          u->name,
                          format_timespan(s, sizeof(s), u->manager->user_stop_delay, USEC_PER_MSEC));
        }
}

static const char* const user_state_table[_USER_STATE_MAX] = {
        [USER_OFFLINE] = "offline",
        [USER_OPENING] = "opening",
        [USER_LINGERING] = "lingering",
        [USER_ONLINE] = "online",
        [USER_ACTIVE] = "active",
        [USER_CLOSING] = "closing"
};

DEFINE_STRING_TABLE_LOOKUP(user_state, UserState);

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

        uint64_t *sz = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        /* First, try to parse as percentage */
        r = parse_permille(rvalue);
        if (r > 0 && r < 1000)
                *sz = physical_memory_scale(r, 1000U);
        else {
                uint64_t k;

                /* If the passed argument was not a percentage, or out of range, parse as byte size */

                r = parse_size(rvalue, 1024, &k);
                if (r >= 0 && (k <= 0 || (uint64_t) (size_t) k != k))
                        r = -ERANGE;
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse size value '%s', ignoring: %m", rvalue);
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
        assert(data);

        log_syntax(unit, LOG_NOTICE, filename, line, 0,
                   "Support for option %s= has been removed.",
                   lvalue);
        log_info("Hint: try creating /etc/systemd/system/user-.slice.d/50-limits.conf with:\n"
                 "        [Slice]\n"
                 "        TasksMax=%s",
                 rvalue);
        return 0;
}
