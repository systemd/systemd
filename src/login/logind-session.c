/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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

#include <errno.h>
#include <fcntl.h>
#include <linux/vt.h>
#include <linux/kd.h>
#include <signal.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "sd-messages.h"
#include "util.h"
#include "mkdir.h"
#include "path-util.h"
#include "fileio.h"
#include "audit.h"
#include "bus-util.h"
#include "bus-error.h"
#include "logind-session.h"
#include "formats-util.h"
#include "terminal-util.h"

#define RELEASE_USEC (20*USEC_PER_SEC)

static void session_remove_fifo(Session *s);

Session* session_new(Manager *m, const char *id) {
        Session *s;

        assert(m);
        assert(id);
        assert(session_id_valid(id));

        s = new0(Session, 1);
        if (!s)
                return NULL;

        s->state_file = strappend("/run/systemd/sessions/", id);
        if (!s->state_file) {
                free(s);
                return NULL;
        }

        s->devices = hashmap_new(&devt_hash_ops);
        if (!s->devices) {
                free(s->state_file);
                free(s);
                return NULL;
        }

        s->id = basename(s->state_file);

        if (hashmap_put(m->sessions, s->id, s) < 0) {
                hashmap_free(s->devices);
                free(s->state_file);
                free(s);
                return NULL;
        }

        s->manager = m;
        s->fifo_fd = -1;
        s->vtfd = -1;

        return s;
}

void session_free(Session *s) {
        SessionDevice *sd;

        assert(s);

        if (s->in_gc_queue)
                LIST_REMOVE(gc_queue, s->manager->session_gc_queue, s);

        s->timer_event_source = sd_event_source_unref(s->timer_event_source);

        session_remove_fifo(s);

        session_drop_controller(s);

        while ((sd = hashmap_first(s->devices)))
                session_device_free(sd);

        hashmap_free(s->devices);

        if (s->user) {
                LIST_REMOVE(sessions_by_user, s->user->sessions, s);

                if (s->user->display == s)
                        s->user->display = NULL;
        }

        if (s->seat) {
                if (s->seat->active == s)
                        s->seat->active = NULL;
                if (s->seat->pending_switch == s)
                        s->seat->pending_switch = NULL;

                seat_evict_position(s->seat, s);
                LIST_REMOVE(sessions_by_seat, s->seat->sessions, s);
        }

        if (s->scope) {
                hashmap_remove(s->manager->session_units, s->scope);
                free(s->scope);
        }

        free(s->scope_job);

        sd_bus_message_unref(s->create_message);

        free(s->tty);
        free(s->display);
        free(s->remote_host);
        free(s->remote_user);
        free(s->service);
        free(s->desktop);

        hashmap_remove(s->manager->sessions, s->id);

        free(s->state_file);
        free(s);
}

void session_set_user(Session *s, User *u) {
        assert(s);
        assert(!s->user);

        s->user = u;
        LIST_PREPEND(sessions_by_user, u->sessions, s);
}

int session_save(Session *s) {
        _cleanup_free_ char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r = 0;

        assert(s);

        if (!s->user)
                return -ESTALE;

        if (!s->started)
                return 0;

        r = mkdir_safe_label("/run/systemd/sessions", 0755, 0, 0);
        if (r < 0)
                goto fail;

        r = fopen_temporary(s->state_file, &f, &temp_path);
        if (r < 0)
                goto fail;

        assert(s->user);

        fchmod(fileno(f), 0644);

        fprintf(f,
                "# This is private data. Do not parse.\n"
                "UID="UID_FMT"\n"
                "USER=%s\n"
                "ACTIVE=%i\n"
                "STATE=%s\n"
                "REMOTE=%i\n",
                s->user->uid,
                s->user->name,
                session_is_active(s),
                session_state_to_string(session_get_state(s)),
                s->remote);

        if (s->type >= 0)
                fprintf(f, "TYPE=%s\n", session_type_to_string(s->type));

        if (s->class >= 0)
                fprintf(f, "CLASS=%s\n", session_class_to_string(s->class));

        if (s->scope)
                fprintf(f, "SCOPE=%s\n", s->scope);
        if (s->scope_job)
                fprintf(f, "SCOPE_JOB=%s\n", s->scope_job);

        if (s->fifo_path)
                fprintf(f, "FIFO=%s\n", s->fifo_path);

        if (s->seat)
                fprintf(f, "SEAT=%s\n", s->seat->id);

        if (s->tty)
                fprintf(f, "TTY=%s\n", s->tty);

        if (s->display)
                fprintf(f, "DISPLAY=%s\n", s->display);

        if (s->remote_host) {
                _cleanup_free_ char *escaped;

                escaped = cescape(s->remote_host);
                if (!escaped) {
                        r = -ENOMEM;
                        goto fail;
                }

                fprintf(f, "REMOTE_HOST=%s\n", escaped);
        }

        if (s->remote_user) {
                _cleanup_free_ char *escaped;

                escaped = cescape(s->remote_user);
                if (!escaped) {
                        r = -ENOMEM;
                        goto fail;
                }

                fprintf(f, "REMOTE_USER=%s\n", escaped);
        }

        if (s->service) {
                _cleanup_free_ char *escaped;

                escaped = cescape(s->service);
                if (!escaped) {
                        r = -ENOMEM;
                        goto fail;
                }

                fprintf(f, "SERVICE=%s\n", escaped);
        }

        if (s->desktop) {
                _cleanup_free_ char *escaped;


                escaped = cescape(s->desktop);
                if (!escaped) {
                        r = -ENOMEM;
                        goto fail;
                }

                fprintf(f, "DESKTOP=%s\n", escaped);
        }

        if (s->seat && seat_has_vts(s->seat))
                fprintf(f, "VTNR=%u\n", s->vtnr);

        if (!s->vtnr)
                fprintf(f, "POSITION=%u\n", s->position);

        if (s->leader > 0)
                fprintf(f, "LEADER="PID_FMT"\n", s->leader);

        if (s->audit_id > 0)
                fprintf(f, "AUDIT=%"PRIu32"\n", s->audit_id);

        if (dual_timestamp_is_set(&s->timestamp))
                fprintf(f,
                        "REALTIME="USEC_FMT"\n"
                        "MONOTONIC="USEC_FMT"\n",
                        s->timestamp.realtime,
                        s->timestamp.monotonic);

        if (s->controller)
                fprintf(f, "CONTROLLER=%s\n", s->controller);

        r = fflush_and_check(f);
        if (r < 0)
                goto fail;

        if (rename(temp_path, s->state_file) < 0) {
                r = -errno;
                goto fail;
        }

        return 0;

fail:
        (void) unlink(s->state_file);

        if (temp_path)
                (void) unlink(temp_path);

        return log_error_errno(r, "Failed to save session data %s: %m", s->state_file);
}


int session_load(Session *s) {
        _cleanup_free_ char *remote = NULL,
                *seat = NULL,
                *vtnr = NULL,
                *state = NULL,
                *position = NULL,
                *leader = NULL,
                *type = NULL,
                *class = NULL,
                *uid = NULL,
                *realtime = NULL,
                *monotonic = NULL,
                *controller = NULL;

        int k, r;

        assert(s);

        r = parse_env_file(s->state_file, NEWLINE,
                           "REMOTE",         &remote,
                           "SCOPE",          &s->scope,
                           "SCOPE_JOB",      &s->scope_job,
                           "FIFO",           &s->fifo_path,
                           "SEAT",           &seat,
                           "TTY",            &s->tty,
                           "DISPLAY",        &s->display,
                           "REMOTE_HOST",    &s->remote_host,
                           "REMOTE_USER",    &s->remote_user,
                           "SERVICE",        &s->service,
                           "DESKTOP",        &s->desktop,
                           "VTNR",           &vtnr,
                           "STATE",          &state,
                           "POSITION",       &position,
                           "LEADER",         &leader,
                           "TYPE",           &type,
                           "CLASS",          &class,
                           "UID",            &uid,
                           "REALTIME",       &realtime,
                           "MONOTONIC",      &monotonic,
                           "CONTROLLER",     &controller,
                           NULL);

        if (r < 0)
                return log_error_errno(r, "Failed to read %s: %m", s->state_file);

        if (!s->user) {
                uid_t u;
                User *user;

                if (!uid) {
                        log_error("UID not specified for session %s", s->id);
                        return -ENOENT;
                }

                r = parse_uid(uid, &u);
                if (r < 0)  {
                        log_error("Failed to parse UID value %s for session %s.", uid, s->id);
                        return r;
                }

                user = hashmap_get(s->manager->users, UID_TO_PTR(u));
                if (!user) {
                        log_error("User of session %s not known.", s->id);
                        return -ENOENT;
                }

                session_set_user(s, user);
        }

        if (remote) {
                k = parse_boolean(remote);
                if (k >= 0)
                        s->remote = k;
        }

        if (vtnr)
                safe_atou(vtnr, &s->vtnr);

        if (seat && !s->seat) {
                Seat *o;

                o = hashmap_get(s->manager->seats, seat);
                if (o)
                        r = seat_attach_session(o, s);
                if (!o || r < 0)
                        log_error("Cannot attach session %s to seat %s", s->id, seat);
        }

        if (!s->seat || !seat_has_vts(s->seat))
                s->vtnr = 0;

        if (position && s->seat) {
                unsigned int npos;

                safe_atou(position, &npos);
                seat_claim_position(s->seat, s, npos);
        }

        if (leader) {
                k = parse_pid(leader, &s->leader);
                if (k >= 0)
                        audit_session_from_pid(s->leader, &s->audit_id);
        }

        if (type) {
                SessionType t;

                t = session_type_from_string(type);
                if (t >= 0)
                        s->type = t;
        }

        if (class) {
                SessionClass c;

                c = session_class_from_string(class);
                if (c >= 0)
                        s->class = c;
        }

        if (state && streq(state, "closing"))
                s->stopping = true;

        if (s->fifo_path) {
                int fd;

                /* If we open an unopened pipe for reading we will not
                   get an EOF. to trigger an EOF we hence open it for
                   writing, but close it right away which then will
                   trigger the EOF. This will happen immediately if no
                   other process has the FIFO open for writing, i. e.
                   when the session died before logind (re)started. */

                fd = session_create_fifo(s);
                safe_close(fd);
        }

        if (realtime) {
                unsigned long long l;
                if (sscanf(realtime, "%llu", &l) > 0)
                        s->timestamp.realtime = l;
        }

        if (monotonic) {
                unsigned long long l;
                if (sscanf(monotonic, "%llu", &l) > 0)
                        s->timestamp.monotonic = l;
        }

        if (controller) {
                if (bus_name_has_owner(s->manager->bus, controller, NULL) > 0)
                        session_set_controller(s, controller, false);
                else
                        session_restore_vt(s);
        }

        return r;
}

int session_activate(Session *s) {
        unsigned int num_pending;

        assert(s);
        assert(s->user);

        if (!s->seat)
                return -EOPNOTSUPP;

        if (s->seat->active == s)
                return 0;

        /* on seats with VTs, we let VTs manage session-switching */
        if (seat_has_vts(s->seat)) {
                if (!s->vtnr)
                        return -EOPNOTSUPP;

                return chvt(s->vtnr);
        }

        /* On seats without VTs, we implement session-switching in logind. We
         * try to pause all session-devices and wait until the session
         * controller acknowledged them. Once all devices are asleep, we simply
         * switch the active session and be done.
         * We save the session we want to switch to in seat->pending_switch and
         * seat_complete_switch() will perform the final switch. */

        s->seat->pending_switch = s;

        /* if no devices are running, immediately perform the session switch */
        num_pending = session_device_try_pause_all(s);
        if (!num_pending)
                seat_complete_switch(s->seat);

        return 0;
}

static int session_start_scope(Session *s) {
        int r;

        assert(s);
        assert(s->user);
        assert(s->user->slice);

        if (!s->scope) {
                _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_free_ char *description = NULL;
                char *scope, *job = NULL;

                description = strjoin("Session ", s->id, " of user ", s->user->name, NULL);
                if (!description)
                        return log_oom();

                scope = strjoin("session-", s->id, ".scope", NULL);
                if (!scope)
                        return log_oom();

                r = manager_start_scope(s->manager, scope, s->leader, s->user->slice, description, "systemd-logind.service", "systemd-user-sessions.service", &error, &job);
                if (r < 0) {
                        log_error("Failed to start session scope %s: %s %s",
                                  scope, bus_error_message(&error, r), error.name);
                        free(scope);
                        return r;
                } else {
                        s->scope = scope;

                        free(s->scope_job);
                        s->scope_job = job;
                }
        }

        if (s->scope)
                hashmap_put(s->manager->session_units, s->scope, s);

        return 0;
}

int session_start(Session *s) {
        int r;

        assert(s);

        if (!s->user)
                return -ESTALE;

        if (s->started)
                return 0;

        r = user_start(s->user);
        if (r < 0)
                return r;

        /* Create cgroup */
        r = session_start_scope(s);
        if (r < 0)
                return r;

        log_struct(s->class == SESSION_BACKGROUND ? LOG_DEBUG : LOG_INFO,
                   LOG_MESSAGE_ID(SD_MESSAGE_SESSION_START),
                   "SESSION_ID=%s", s->id,
                   "USER_ID=%s", s->user->name,
                   "LEADER="PID_FMT, s->leader,
                   LOG_MESSAGE("New session %s of user %s.", s->id, s->user->name),
                   NULL);

        if (!dual_timestamp_is_set(&s->timestamp))
                dual_timestamp_get(&s->timestamp);

        if (s->seat)
                seat_read_active_vt(s->seat);

        s->started = true;

        user_elect_display(s->user);

        /* Save data */
        session_save(s);
        user_save(s->user);
        if (s->seat)
                seat_save(s->seat);

        /* Send signals */
        session_send_signal(s, true);
        user_send_changed(s->user, "Sessions", "Display", NULL);
        if (s->seat) {
                if (s->seat->active == s)
                        seat_send_changed(s->seat, "Sessions", "ActiveSession", NULL);
                else
                        seat_send_changed(s->seat, "Sessions", NULL);
        }

        return 0;
}

static int session_stop_scope(Session *s, bool force) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        char *job = NULL;
        int r;

        assert(s);

        if (!s->scope)
                return 0;

        if (force || manager_shall_kill(s->manager, s->user->name)) {
                r = manager_stop_unit(s->manager, s->scope, &error, &job);
                if (r < 0) {
                        log_error("Failed to stop session scope: %s", bus_error_message(&error, r));
                        return r;
                }

                free(s->scope_job);
                s->scope_job = job;
        } else {
                r = manager_abandon_scope(s->manager, s->scope, &error);
                if (r < 0) {
                        log_error("Failed to abandon session scope: %s", bus_error_message(&error, r));
                        return r;
                }
        }

        return 0;
}

int session_stop(Session *s, bool force) {
        int r;

        assert(s);

        if (!s->user)
                return -ESTALE;

        s->timer_event_source = sd_event_source_unref(s->timer_event_source);

        if (s->seat)
                seat_evict_position(s->seat, s);

        /* We are going down, don't care about FIFOs anymore */
        session_remove_fifo(s);

        /* Kill cgroup */
        r = session_stop_scope(s, force);

        s->stopping = true;

        user_elect_display(s->user);

        session_save(s);
        user_save(s->user);

        return r;
}

int session_finalize(Session *s) {
        SessionDevice *sd;

        assert(s);

        if (!s->user)
                return -ESTALE;

        if (s->started)
                log_struct(s->class == SESSION_BACKGROUND ? LOG_DEBUG : LOG_INFO,
                           LOG_MESSAGE_ID(SD_MESSAGE_SESSION_STOP),
                           "SESSION_ID=%s", s->id,
                           "USER_ID=%s", s->user->name,
                           "LEADER="PID_FMT, s->leader,
                           LOG_MESSAGE("Removed session %s.", s->id),
                           NULL);

        s->timer_event_source = sd_event_source_unref(s->timer_event_source);

        if (s->seat)
                seat_evict_position(s->seat, s);

        /* Kill session devices */
        while ((sd = hashmap_first(s->devices)))
                session_device_free(sd);

        (void) unlink(s->state_file);
        session_add_to_gc_queue(s);
        user_add_to_gc_queue(s->user);

        if (s->started) {
                session_send_signal(s, false);
                s->started = false;
        }

        if (s->seat) {
                if (s->seat->active == s)
                        seat_set_active(s->seat, NULL);

                seat_save(s->seat);
                seat_send_changed(s->seat, "Sessions", NULL);
        }

        user_save(s->user);
        user_send_changed(s->user, "Sessions", "Display", NULL);

        return 0;
}

static int release_timeout_callback(sd_event_source *es, uint64_t usec, void *userdata) {
        Session *s = userdata;

        assert(es);
        assert(s);

        session_stop(s, false);
        return 0;
}

int session_release(Session *s) {
        assert(s);

        if (!s->started || s->stopping)
                return 0;

        if (s->timer_event_source)
                return 0;

        return sd_event_add_time(s->manager->event,
                                 &s->timer_event_source,
                                 CLOCK_MONOTONIC,
                                 now(CLOCK_MONOTONIC) + RELEASE_USEC, 0,
                                 release_timeout_callback, s);
}

bool session_is_active(Session *s) {
        assert(s);

        if (!s->seat)
                return true;

        return s->seat->active == s;
}

static int get_tty_atime(const char *tty, usec_t *atime) {
        _cleanup_free_ char *p = NULL;
        struct stat st;

        assert(tty);
        assert(atime);

        if (!path_is_absolute(tty)) {
                p = strappend("/dev/", tty);
                if (!p)
                        return -ENOMEM;

                tty = p;
        } else if (!path_startswith(tty, "/dev/"))
                return -ENOENT;

        if (lstat(tty, &st) < 0)
                return -errno;

        *atime = timespec_load(&st.st_atim);
        return 0;
}

static int get_process_ctty_atime(pid_t pid, usec_t *atime) {
        _cleanup_free_ char *p = NULL;
        int r;

        assert(pid > 0);
        assert(atime);

        r = get_ctty(pid, NULL, &p);
        if (r < 0)
                return r;

        return get_tty_atime(p, atime);
}

int session_get_idle_hint(Session *s, dual_timestamp *t) {
        usec_t atime = 0, n;
        int r;

        assert(s);

        /* Explicit idle hint is set */
        if (s->idle_hint) {
                if (t)
                        *t = s->idle_hint_timestamp;

                return s->idle_hint;
        }

        /* Graphical sessions should really implement a real
         * idle hint logic */
        if (s->display)
                goto dont_know;

        /* For sessions with an explicitly configured tty, let's check
         * its atime */
        if (s->tty) {
                r = get_tty_atime(s->tty, &atime);
                if (r >= 0)
                        goto found_atime;
        }

        /* For sessions with a leader but no explicitly configured
         * tty, let's check the controlling tty of the leader */
        if (s->leader > 0) {
                r = get_process_ctty_atime(s->leader, &atime);
                if (r >= 0)
                        goto found_atime;
        }

dont_know:
        if (t)
                *t = s->idle_hint_timestamp;

        return 0;

found_atime:
        if (t)
                dual_timestamp_from_realtime(t, atime);

        n = now(CLOCK_REALTIME);

        if (s->manager->idle_action_usec <= 0)
                return 0;

        return atime + s->manager->idle_action_usec <= n;
}

void session_set_idle_hint(Session *s, bool b) {
        assert(s);

        if (s->idle_hint == b)
                return;

        s->idle_hint = b;
        dual_timestamp_get(&s->idle_hint_timestamp);

        session_send_changed(s, "IdleHint", "IdleSinceHint", "IdleSinceHintMonotonic", NULL);

        if (s->seat)
                seat_send_changed(s->seat, "IdleHint", "IdleSinceHint", "IdleSinceHintMonotonic", NULL);

        user_send_changed(s->user, "IdleHint", "IdleSinceHint", "IdleSinceHintMonotonic", NULL);
        manager_send_changed(s->manager, "IdleHint", "IdleSinceHint", "IdleSinceHintMonotonic", NULL);
}

static int session_dispatch_fifo(sd_event_source *es, int fd, uint32_t revents, void *userdata) {
        Session *s = userdata;

        assert(s);
        assert(s->fifo_fd == fd);

        /* EOF on the FIFO means the session died abnormally. */

        session_remove_fifo(s);
        session_stop(s, false);

        return 1;
}

int session_create_fifo(Session *s) {
        int r;

        assert(s);

        /* Create FIFO */
        if (!s->fifo_path) {
                r = mkdir_safe_label("/run/systemd/sessions", 0755, 0, 0);
                if (r < 0)
                        return r;

                if (asprintf(&s->fifo_path, "/run/systemd/sessions/%s.ref", s->id) < 0)
                        return -ENOMEM;

                if (mkfifo(s->fifo_path, 0600) < 0 && errno != EEXIST)
                        return -errno;
        }

        /* Open reading side */
        if (s->fifo_fd < 0) {
                s->fifo_fd = open(s->fifo_path, O_RDONLY|O_CLOEXEC|O_NDELAY);
                if (s->fifo_fd < 0)
                        return -errno;

        }

        if (!s->fifo_event_source) {
                r = sd_event_add_io(s->manager->event, &s->fifo_event_source, s->fifo_fd, 0, session_dispatch_fifo, s);
                if (r < 0)
                        return r;

                r = sd_event_source_set_priority(s->fifo_event_source, SD_EVENT_PRIORITY_IDLE);
                if (r < 0)
                        return r;
        }

        /* Open writing side */
        r = open(s->fifo_path, O_WRONLY|O_CLOEXEC|O_NDELAY);
        if (r < 0)
                return -errno;

        return r;
}

static void session_remove_fifo(Session *s) {
        assert(s);

        s->fifo_event_source = sd_event_source_unref(s->fifo_event_source);
        s->fifo_fd = safe_close(s->fifo_fd);

        if (s->fifo_path) {
                unlink(s->fifo_path);
                free(s->fifo_path);
                s->fifo_path = NULL;
        }
}

bool session_check_gc(Session *s, bool drop_not_started) {
        assert(s);

        if (drop_not_started && !s->started)
                return false;

        if (!s->user)
                return false;

        if (s->fifo_fd >= 0) {
                if (pipe_eof(s->fifo_fd) <= 0)
                        return true;
        }

        if (s->scope_job && manager_job_is_active(s->manager, s->scope_job))
                return true;

        if (s->scope && manager_unit_is_active(s->manager, s->scope))
                return true;

        return false;
}

void session_add_to_gc_queue(Session *s) {
        assert(s);

        if (s->in_gc_queue)
                return;

        LIST_PREPEND(gc_queue, s->manager->session_gc_queue, s);
        s->in_gc_queue = true;
}

SessionState session_get_state(Session *s) {
        assert(s);

        /* always check closing first */
        if (s->stopping || s->timer_event_source)
                return SESSION_CLOSING;

        if (s->scope_job || s->fifo_fd < 0)
                return SESSION_OPENING;

        if (session_is_active(s))
                return SESSION_ACTIVE;

        return SESSION_ONLINE;
}

int session_kill(Session *s, KillWho who, int signo) {
        assert(s);

        if (!s->scope)
                return -ESRCH;

        return manager_kill_unit(s->manager, s->scope, who, signo, NULL);
}

static int session_open_vt(Session *s) {
        char path[sizeof("/dev/tty") + DECIMAL_STR_MAX(s->vtnr)];

        if (s->vtnr < 1)
                return -ENODEV;

        if (s->vtfd >= 0)
                return s->vtfd;

        sprintf(path, "/dev/tty%u", s->vtnr);
        s->vtfd = open_terminal(path, O_RDWR | O_CLOEXEC | O_NONBLOCK | O_NOCTTY);
        if (s->vtfd < 0)
                return log_error_errno(errno, "cannot open VT %s of session %s: %m", path, s->id);

        return s->vtfd;
}

int session_prepare_vt(Session *s) {
        int vt, r;
        struct vt_mode mode = { 0 };

        if (s->vtnr < 1)
                return 0;

        vt = session_open_vt(s);
        if (vt < 0)
                return vt;

        r = fchown(vt, s->user->uid, -1);
        if (r < 0) {
                r = -errno;
                log_error_errno(errno, "Cannot change owner of /dev/tty%u: %m", s->vtnr);
                goto error;
        }

        r = ioctl(vt, KDSKBMODE, K_OFF);
        if (r < 0) {
                r = -errno;
                log_error_errno(errno, "Cannot set K_OFF on /dev/tty%u: %m", s->vtnr);
                goto error;
        }

        r = ioctl(vt, KDSETMODE, KD_GRAPHICS);
        if (r < 0) {
                r = -errno;
                log_error_errno(errno, "Cannot set KD_GRAPHICS on /dev/tty%u: %m", s->vtnr);
                goto error;
        }

        /* Oh, thanks to the VT layer, VT_AUTO does not work with KD_GRAPHICS.
         * So we need a dummy handler here which just acknowledges *all* VT
         * switch requests. */
        mode.mode = VT_PROCESS;
        mode.relsig = SIGRTMIN;
        mode.acqsig = SIGRTMIN + 1;
        r = ioctl(vt, VT_SETMODE, &mode);
        if (r < 0) {
                r = -errno;
                log_error_errno(errno, "Cannot set VT_PROCESS on /dev/tty%u: %m", s->vtnr);
                goto error;
        }

        return 0;

error:
        session_restore_vt(s);
        return r;
}

void session_restore_vt(Session *s) {
        _cleanup_free_ char *utf8 = NULL;
        int vt, kb = K_XLATE;
        struct vt_mode mode = { 0 };

        /* We need to get a fresh handle to the virtual terminal,
         * since the old file-descriptor is potentially in a hung-up
         * state after the controlling process exited; we do a
         * little dance to avoid having the terminal be available
         * for reuse before we've cleaned it up.
         */
        int old_fd = s->vtfd;
        s->vtfd = -1;

        vt = session_open_vt(s);
        safe_close(old_fd);

        if (vt < 0)
                return;

        (void) ioctl(vt, KDSETMODE, KD_TEXT);

        if (read_one_line_file("/sys/module/vt/parameters/default_utf8", &utf8) >= 0 && *utf8 == '1')
                kb = K_UNICODE;

        (void) ioctl(vt, KDSKBMODE, kb);

        mode.mode = VT_AUTO;
        (void) ioctl(vt, VT_SETMODE, &mode);

        fchown(vt, 0, -1);

        s->vtfd = safe_close(s->vtfd);
}

void session_leave_vt(Session *s) {
        int r;

        assert(s);

        /* This is called whenever we get a VT-switch signal from the kernel.
         * We acknowledge all of them unconditionally. Note that session are
         * free to overwrite those handlers and we only register them for
         * sessions with controllers. Legacy sessions are not affected.
         * However, if we switch from a non-legacy to a legacy session, we must
         * make sure to pause all device before acknowledging the switch. We
         * process the real switch only after we are notified via sysfs, so the
         * legacy session might have already started using the devices. If we
         * don't pause the devices before the switch, we might confuse the
         * session we switch to. */

        if (s->vtfd < 0)
                return;

        session_device_pause_all(s);
        r = ioctl(s->vtfd, VT_RELDISP, 1);
        if (r < 0)
                log_debug_errno(errno, "Cannot release VT of session %s: %m", s->id);
}

bool session_is_controller(Session *s, const char *sender) {
        assert(s);

        return streq_ptr(s->controller, sender);
}

static void session_release_controller(Session *s, bool notify) {
        _cleanup_free_ char *name = NULL;
        SessionDevice *sd;

        if (!s->controller)
                return;

        name = s->controller;

        /* By resetting the controller before releasing the devices, we won't
         * send notification signals. This avoids sending useless notifications
         * if the controller is released on disconnects. */
        if (!notify)
                s->controller = NULL;

        while ((sd = hashmap_first(s->devices)))
                session_device_free(sd);

        s->controller = NULL;
        s->track = sd_bus_track_unref(s->track);
}

static int on_bus_track(sd_bus_track *track, void *userdata) {
        Session *s = userdata;

        assert(track);
        assert(s);

        session_drop_controller(s);

        return 0;
}

int session_set_controller(Session *s, const char *sender, bool force) {
        _cleanup_free_ char *name = NULL;
        int r;

        assert(s);
        assert(sender);

        if (session_is_controller(s, sender))
                return 0;
        if (s->controller && !force)
                return -EBUSY;

        name = strdup(sender);
        if (!name)
                return -ENOMEM;

        s->track = sd_bus_track_unref(s->track);
        r = sd_bus_track_new(s->manager->bus, &s->track, on_bus_track, s);
        if (r < 0)
                return r;

        r = sd_bus_track_add_name(s->track, name);
        if (r < 0)
                return r;

        /* When setting a session controller, we forcibly mute the VT and set
         * it into graphics-mode. Applications can override that by changing
         * VT state after calling TakeControl(). However, this serves as a good
         * default and well-behaving controllers can now ignore VTs entirely.
         * Note that we reset the VT on ReleaseControl() and if the controller
         * exits.
         * If logind crashes/restarts, we restore the controller during restart
         * or reset the VT in case it crashed/exited, too. */
        r = session_prepare_vt(s);
        if (r < 0) {
                s->track = sd_bus_track_unref(s->track);
                return r;
        }

        session_release_controller(s, true);
        s->controller = name;
        name = NULL;
        session_save(s);

        return 0;
}

void session_drop_controller(Session *s) {
        assert(s);

        if (!s->controller)
                return;

        s->track = sd_bus_track_unref(s->track);
        session_release_controller(s, false);
        session_save(s);
        session_restore_vt(s);
}

static const char* const session_state_table[_SESSION_STATE_MAX] = {
        [SESSION_OPENING] = "opening",
        [SESSION_ONLINE] = "online",
        [SESSION_ACTIVE] = "active",
        [SESSION_CLOSING] = "closing"
};

DEFINE_STRING_TABLE_LOOKUP(session_state, SessionState);

static const char* const session_type_table[_SESSION_TYPE_MAX] = {
        [SESSION_UNSPECIFIED] = "unspecified",
        [SESSION_TTY] = "tty",
        [SESSION_X11] = "x11",
        [SESSION_WAYLAND] = "wayland",
        [SESSION_MIR] = "mir",
        [SESSION_WEB] = "web",
};

DEFINE_STRING_TABLE_LOOKUP(session_type, SessionType);

static const char* const session_class_table[_SESSION_CLASS_MAX] = {
        [SESSION_USER] = "user",
        [SESSION_GREETER] = "greeter",
        [SESSION_LOCK_SCREEN] = "lock-screen",
        [SESSION_BACKGROUND] = "background"
};

DEFINE_STRING_TABLE_LOOKUP(session_class, SessionClass);

static const char* const kill_who_table[_KILL_WHO_MAX] = {
        [KILL_LEADER] = "leader",
        [KILL_ALL] = "all"
};

DEFINE_STRING_TABLE_LOOKUP(kill_who, KillWho);
