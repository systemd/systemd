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
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <fcntl.h>

#include <systemd/sd-id128.h>
#include <systemd/sd-messages.h>

#include "strv.h"
#include "util.h"
#include "mkdir.h"
#include "path-util.h"
#include "fileio.h"
#include "dbus-common.h"
#include "logind-session.h"

static unsigned devt_hash_func(const void *p) {
        uint64_t u = *(const dev_t*)p;

        return uint64_hash_func(&u);
}

static int devt_compare_func(const void *_a, const void *_b) {
        dev_t a, b;

        a = *(const dev_t*) _a;
        b = *(const dev_t*) _b;

        return a < b ? -1 : (a > b ? 1 : 0);
}

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

        s->devices = hashmap_new(devt_hash_func, devt_compare_func);
        if (!s->devices) {
                free(s->state_file);
                free(s);
                return NULL;
        }

        s->id = path_get_file_name(s->state_file);

        if (hashmap_put(m->sessions, s->id, s) < 0) {
                hashmap_free(s->devices);
                free(s->state_file);
                free(s);
                return NULL;
        }

        s->manager = m;
        s->fifo_fd = -1;

        return s;
}

void session_free(Session *s) {
        SessionDevice *sd;

        assert(s);

        if (s->in_gc_queue)
                LIST_REMOVE(Session, gc_queue, s->manager->session_gc_queue, s);

        session_drop_controller(s);

        while ((sd = hashmap_first(s->devices)))
                session_device_free(sd);

        hashmap_free(s->devices);

        if (s->user) {
                LIST_REMOVE(Session, sessions_by_user, s->user->sessions, s);

                if (s->user->display == s)
                        s->user->display = NULL;
        }

        if (s->seat) {
                if (s->seat->active == s)
                        s->seat->active = NULL;
                if (s->seat->pending_switch == s)
                        s->seat->pending_switch = NULL;

                LIST_REMOVE(Session, sessions_by_seat, s->seat->sessions, s);
        }

        if (s->scope) {
                hashmap_remove(s->manager->session_units, s->scope);
                free(s->scope);
        }

        free(s->scope_job);

        if (s->create_message)
                dbus_message_unref(s->create_message);

        free(s->tty);
        free(s->display);
        free(s->remote_host);
        free(s->remote_user);
        free(s->service);

        hashmap_remove(s->manager->sessions, s->id);
        session_remove_fifo(s);

        free(s->state_file);
        free(s);
}

void session_set_user(Session *s, User *u) {
        assert(s);
        assert(!s->user);

        s->user = u;
        LIST_PREPEND(Session, sessions_by_user, u->sessions, s);
}

int session_save(Session *s) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *temp_path = NULL;
        int r = 0;

        assert(s);

        if (!s->user)
                return -ESTALE;

        if (!s->started)
                return 0;

        r = mkdir_safe_label("/run/systemd/sessions", 0755, 0, 0);
        if (r < 0)
                goto finish;

        r = fopen_temporary(s->state_file, &f, &temp_path);
        if (r < 0)
                goto finish;

        assert(s->user);

        fchmod(fileno(f), 0644);

        fprintf(f,
                "# This is private data. Do not parse.\n"
                "UID=%lu\n"
                "USER=%s\n"
                "ACTIVE=%i\n"
                "STATE=%s\n"
                "REMOTE=%i\n",
                (unsigned long) s->user->uid,
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

        if (s->remote_host)
                fprintf(f, "REMOTE_HOST=%s\n", s->remote_host);

        if (s->remote_user)
                fprintf(f, "REMOTE_USER=%s\n", s->remote_user);

        if (s->service)
                fprintf(f, "SERVICE=%s\n", s->service);

        if (s->seat && seat_has_vts(s->seat))
                fprintf(f, "VTNR=%i\n", s->vtnr);

        if (s->leader > 0)
                fprintf(f, "LEADER=%lu\n", (unsigned long) s->leader);

        if (s->audit_id > 0)
                fprintf(f, "AUDIT=%"PRIu32"\n", s->audit_id);

        if (dual_timestamp_is_set(&s->timestamp))
                fprintf(f,
                        "REALTIME=%llu\n"
                        "MONOTONIC=%llu\n",
                        (unsigned long long) s->timestamp.realtime,
                        (unsigned long long) s->timestamp.monotonic);

        fflush(f);

        if (ferror(f) || rename(temp_path, s->state_file) < 0) {
                r = -errno;
                unlink(s->state_file);
                unlink(temp_path);
        }

finish:
        if (r < 0)
                log_error("Failed to save session data for %s: %s", s->id, strerror(-r));

        return r;
}

int session_load(Session *s) {
        _cleanup_free_ char *remote = NULL,
                *seat = NULL,
                *vtnr = NULL,
                *leader = NULL,
                *type = NULL,
                *class = NULL,
                *uid = NULL,
                *realtime = NULL,
                *monotonic = NULL;

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
                           "VTNR",           &vtnr,
                           "LEADER",         &leader,
                           "TYPE",           &type,
                           "CLASS",          &class,
                           "UID",            &uid,
                           "REALTIME",       &realtime,
                           "MONOTONIC",      &monotonic,
                           NULL);

        if (r < 0) {
                log_error("Failed to read %s: %s", s->state_file, strerror(-r));
                return r;
        }

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

                user = hashmap_get(s->manager->users, ULONG_TO_PTR((unsigned long) u));
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

        if (seat && !s->seat) {
                Seat *o;

                o = hashmap_get(s->manager->seats, seat);
                if (o)
                        seat_attach_session(o, s);
        }

        if (vtnr && s->seat && seat_has_vts(s->seat)) {
                int v;

                k = safe_atoi(vtnr, &v);
                if (k >= 0 && v >= 1)
                        s->vtnr = v;
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

        if (s->fifo_path) {
                int fd;

                /* If we open an unopened pipe for reading we will not
                   get an EOF. to trigger an EOF we hence open it for
                   reading, but close it right-away which then will
                   trigger the EOF. */

                fd = session_create_fifo(s);
                if (fd >= 0)
                        close_nointr_nofail(fd);
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

        return r;
}

int session_activate(Session *s) {
        unsigned int num_pending;

        assert(s);
        assert(s->user);

        if (!s->seat)
                return -ENOTSUP;

        if (s->seat->active == s)
                return 0;

        /* on seats with VTs, we let VTs manage session-switching */
        if (seat_has_vts(s->seat)) {
                if (s->vtnr <= 0)
                        return -ENOTSUP;

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

static int session_link_x11_socket(Session *s) {
        _cleanup_free_ char *t = NULL, *f = NULL;
        char *c;
        size_t k;

        assert(s);
        assert(s->user);
        assert(s->user->runtime_path);

        if (s->user->display)
                return 0;

        if (!s->display || !display_is_local(s->display))
                return 0;

        k = strspn(s->display+1, "0123456789");
        f = new(char, sizeof("/tmp/.X11-unix/X") + k);
        if (!f)
                return log_oom();

        c = stpcpy(f, "/tmp/.X11-unix/X");
        memcpy(c, s->display+1, k);
        c[k] = 0;

        if (access(f, F_OK) < 0) {
                log_warning("Session %s has display %s with non-existing socket %s.", s->id, s->display, f);
                return -ENOENT;
        }

        /* Note that this cannot be in a subdir to avoid
         * vulnerabilities since we are privileged but the runtime
         * path is owned by the user */

        t = strappend(s->user->runtime_path, "/X11-display");
        if (!t)
                return log_oom();

        if (link(f, t) < 0) {
                if (errno == EEXIST) {
                        unlink(t);

                        if (link(f, t) >= 0)
                                goto done;
                }

                if (symlink(f, t) < 0) {

                        if (errno == EEXIST) {
                                unlink(t);

                                if (symlink(f, t) >= 0)
                                        goto done;
                        }

                        log_error("Failed to link %s to %s: %m", f, t);
                        return -errno;
                }
        }

done:
        log_info("Linked %s to %s.", f, t);
        s->user->display = s;

        return 0;
}

static int session_start_scope(Session *s) {
        DBusError error;
        int r;

        assert(s);
        assert(s->user);
        assert(s->user->slice);

        dbus_error_init(&error);

        if (!s->scope) {
                _cleanup_free_ char *description = NULL;
                const char *kill_mode;
                char *scope, *job;

                description = strjoin("Session ", s->id, " of user ", s->user->name, NULL);
                if (!description)
                        return log_oom();

                scope = strjoin("session-", s->id, ".scope", NULL);
                if (!scope)
                        return log_oom();

                kill_mode = manager_shall_kill(s->manager, s->user->name) ? "control-group" : "none";

                r = manager_start_scope(s->manager, scope, s->leader, s->user->slice, description, "systemd-user-sessions.service", kill_mode, &error, &job);
                if (r < 0) {
                        log_error("Failed to start session scope %s: %s %s",
                                  scope, bus_error(&error, r), error.name);
                        dbus_error_free(&error);

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

        log_struct(s->type == SESSION_TTY || s->type == SESSION_X11 ? LOG_INFO : LOG_DEBUG,
                   MESSAGE_ID(SD_MESSAGE_SESSION_START),
                   "SESSION_ID=%s", s->id,
                   "USER_ID=%s", s->user->name,
                   "LEADER=%lu", (unsigned long) s->leader,
                   "MESSAGE=New session %s of user %s.", s->id, s->user->name,
                   NULL);

        /* Create X11 symlink */
        session_link_x11_socket(s);

        if (!dual_timestamp_is_set(&s->timestamp))
                dual_timestamp_get(&s->timestamp);

        if (s->seat)
                seat_read_active_vt(s->seat);

        s->started = true;

        /* Save session data */
        session_save(s);
        user_save(s->user);

        session_send_signal(s, true);

        if (s->seat) {
                seat_save(s->seat);

                if (s->seat->active == s)
                        seat_send_changed(s->seat, "Sessions\0ActiveSession\0");
                else
                        seat_send_changed(s->seat, "Sessions\0");
        }

        user_send_changed(s->user, "Sessions\0");

        return 0;
}

static int session_stop_scope(Session *s) {
        DBusError error;
        char *job;
        int r;

        assert(s);

        dbus_error_init(&error);

        if (!s->scope)
                return 0;

        r = manager_stop_unit(s->manager, s->scope, &error, &job);
        if (r < 0) {
                log_error("Failed to stop session scope: %s", bus_error(&error, r));
                dbus_error_free(&error);
                return r;
        }

        free(s->scope_job);
        s->scope_job = job;

        return 0;
}

static int session_unlink_x11_socket(Session *s) {
        _cleanup_free_ char *t = NULL;
        int r;

        assert(s);
        assert(s->user);

        if (s->user->display != s)
                return 0;

        s->user->display = NULL;

        t = strappend(s->user->runtime_path, "/X11-display");
        if (!t)
                return log_oom();

        r = unlink(t);
        return r < 0 ? -errno : 0;
}

int session_stop(Session *s) {
        int r;

        assert(s);

        if (!s->user)
                return -ESTALE;

        /* Kill cgroup */
        r = session_stop_scope(s);

        session_save(s);

        return r;
}

int session_finalize(Session *s) {
        int r = 0;
        SessionDevice *sd;

        assert(s);

        if (!s->user)
                return -ESTALE;

        if (s->started)
                log_struct(s->type == SESSION_TTY || s->type == SESSION_X11 ? LOG_INFO : LOG_DEBUG,
                           MESSAGE_ID(SD_MESSAGE_SESSION_STOP),
                           "SESSION_ID=%s", s->id,
                           "USER_ID=%s", s->user->name,
                           "LEADER=%lu", (unsigned long) s->leader,
                           "MESSAGE=Removed session %s.", s->id,
                           NULL);

        /* Kill session devices */
        while ((sd = hashmap_first(s->devices)))
                session_device_free(sd);

        /* Remove X11 symlink */
        session_unlink_x11_socket(s);

        unlink(s->state_file);
        session_add_to_gc_queue(s);
        user_add_to_gc_queue(s->user);

        if (s->started) {
                session_send_signal(s, false);
                s->started = false;
        }

        if (s->seat) {
                if (s->seat->active == s)
                        seat_set_active(s->seat, NULL);

                seat_send_changed(s->seat, "Sessions\0");
                seat_save(s->seat);
        }

        user_send_changed(s->user, "Sessions\0");
        user_save(s->user);

        return r;
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

        session_send_changed(s,
                             "IdleHint\0"
                             "IdleSinceHint\0"
                             "IdleSinceHintMonotonic\0");

        if (s->seat)
                seat_send_changed(s->seat,
                                  "IdleHint\0"
                                  "IdleSinceHint\0"
                                  "IdleSinceHintMonotonic\0");

        user_send_changed(s->user,
                          "IdleHint\0"
                          "IdleSinceHint\0"
                          "IdleSinceHintMonotonic\0");

        manager_send_changed(s->manager,
                             "IdleHint\0"
                             "IdleSinceHint\0"
                             "IdleSinceHintMonotonic\0");
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
                struct epoll_event ev = {};

                s->fifo_fd = open(s->fifo_path, O_RDONLY|O_CLOEXEC|O_NDELAY);
                if (s->fifo_fd < 0)
                        return -errno;

                r = hashmap_put(s->manager->session_fds, INT_TO_PTR(s->fifo_fd + 1), s);
                if (r < 0)
                        return r;

                ev.events = 0;
                ev.data.u32 = FD_OTHER_BASE + s->fifo_fd;

                if (epoll_ctl(s->manager->epoll_fd, EPOLL_CTL_ADD, s->fifo_fd, &ev) < 0)
                        return -errno;
        }

        /* Open writing side */
        r = open(s->fifo_path, O_WRONLY|O_CLOEXEC|O_NDELAY);
        if (r < 0)
                return -errno;

        return r;
}

void session_remove_fifo(Session *s) {
        assert(s);

        if (s->fifo_fd >= 0) {
                assert_se(hashmap_remove(s->manager->session_fds, INT_TO_PTR(s->fifo_fd + 1)) == s);
                assert_se(epoll_ctl(s->manager->epoll_fd, EPOLL_CTL_DEL, s->fifo_fd, NULL) == 0);
                close_nointr_nofail(s->fifo_fd);
                s->fifo_fd = -1;

                session_save(s);
                user_save(s->user);
        }

        if (s->fifo_path) {
                unlink(s->fifo_path);
                free(s->fifo_path);
                s->fifo_path = NULL;
        }
}

int session_check_gc(Session *s, bool drop_not_started) {
        int r;

        assert(s);

        if (drop_not_started && !s->started)
                return 0;

        if (!s->user)
                return 0;

        if (s->fifo_fd >= 0) {
                r = pipe_eof(s->fifo_fd);
                if (r < 0)
                        return r;

                if (r == 0)
                        return 1;
        }

        if (s->scope_job)
                return 1;

        if (s->scope)
                return manager_unit_is_active(s->manager, s->scope) != 0;

        return 0;
}

void session_add_to_gc_queue(Session *s) {
        assert(s);

        if (s->in_gc_queue)
                return;

        LIST_PREPEND(Session, gc_queue, s->manager->session_gc_queue, s);
        s->in_gc_queue = true;
}

SessionState session_get_state(Session *s) {
        assert(s);

        if (s->closing)
                return SESSION_CLOSING;

        if (s->scope_job)
                return SESSION_OPENING;

        if (s->fifo_fd < 0)
                return SESSION_CLOSING;

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

bool session_is_controller(Session *s, const char *sender)
{
        assert(s);

        return streq_ptr(s->controller, sender);
}

int session_set_controller(Session *s, const char *sender, bool force) {
        char *t;
        int r;

        assert(s);
        assert(sender);

        if (session_is_controller(s, sender))
                return 0;
        if (s->controller && !force)
                return -EBUSY;

        t = strdup(sender);
        if (!t)
                return -ENOMEM;

        r = manager_watch_busname(s->manager, sender);
        if (r) {
                free(t);
                return r;
        }

        session_drop_controller(s);

        s->controller = t;
        return 0;
}

void session_drop_controller(Session *s) {
        SessionDevice *sd;

        assert(s);

        if (!s->controller)
                return;

        manager_drop_busname(s->manager, s->controller);
        free(s->controller);
        s->controller = NULL;

        /* Drop all devices as they're now unused. Do that after the controller
         * is released to avoid sending out useles dbus signals. */
        while ((sd = hashmap_first(s->devices)))
                session_device_free(sd);
}

static const char* const session_state_table[_SESSION_STATE_MAX] = {
        [SESSION_OPENING] = "opening",
        [SESSION_ONLINE] = "online",
        [SESSION_ACTIVE] = "active",
        [SESSION_CLOSING] = "closing"
};

DEFINE_STRING_TABLE_LOOKUP(session_state, SessionState);

static const char* const session_type_table[_SESSION_TYPE_MAX] = {
        [SESSION_TTY] = "tty",
        [SESSION_X11] = "x11",
        [SESSION_UNSPECIFIED] = "unspecified"
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
