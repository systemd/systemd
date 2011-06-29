/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <fcntl.h>

#include "logind-session.h"
#include "strv.h"
#include "util.h"
#include "cgroup-util.h"

#define IDLE_THRESHOLD_USEC (5*USEC_PER_MINUTE)

Session* session_new(Manager *m, User *u, const char *id) {
        Session *s;

        assert(m);
        assert(id);

        s = new0(Session, 1);
        if (!s)
                return NULL;

        s->state_file = strappend("/run/systemd/sessions/", id);
        if (!s->state_file) {
                free(s);
                return NULL;
        }

        s->id = file_name_from_path(s->state_file);

        if (hashmap_put(m->sessions, s->id, s) < 0) {
                free(s->id);
                free(s);
                return NULL;
        }

        s->manager = m;
        s->fifo_fd = -1;
        s->user = u;

        LIST_PREPEND(Session, sessions_by_user, u->sessions, s);

        return s;
}

void session_free(Session *s) {
        assert(s);

        if (s->in_gc_queue)
                LIST_REMOVE(Session, gc_queue, s->manager->session_gc_queue, s);

        if (s->user) {
                LIST_REMOVE(Session, sessions_by_user, s->user->sessions, s);

                if (s->user->display == s)
                        s->user->display = NULL;
        }

        if (s->seat) {
                if (s->seat->active == s)
                        s->seat->active = NULL;

                LIST_REMOVE(Session, sessions_by_seat, s->seat->sessions, s);
        }

        if (s->cgroup_path)
                hashmap_remove(s->manager->cgroups, s->cgroup_path);

        free(s->cgroup_path);
        strv_free(s->controllers);

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

int session_save(Session *s) {
        FILE *f;
        int r = 0;
        char *temp_path;

        assert(s);

        if (!s->started)
                return 0;

        r = safe_mkdir("/run/systemd/sessions", 0755, 0, 0);
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
                "REMOTE=%i\n"
                "KILL_PROCESSES=%i\n",
                (unsigned long) s->user->uid,
                s->user->name,
                session_is_active(s),
                s->remote,
                s->kill_processes);

        if (s->type >= 0)
                fprintf(f,
                        "TYPE=%s\n",
                        session_type_to_string(s->type));

        if (s->cgroup_path)
                fprintf(f,
                        "CGROUP=%s\n",
                        s->cgroup_path);

        if (s->fifo_path)
                fprintf(f,
                        "FIFO=%s\n",
                        s->fifo_path);

        if (s->seat)
                fprintf(f,
                        "SEAT=%s\n",
                        s->seat->id);

        if (s->tty)
                fprintf(f,
                        "TTY=%s\n",
                        s->tty);

        if (s->display)
                fprintf(f,
                        "DISPLAY=%s\n",
                        s->display);

        if (s->remote_host)
                fprintf(f,
                        "REMOTE_HOST=%s\n",
                        s->remote_host);

        if (s->remote_user)
                fprintf(f,
                        "REMOTE_USER=%s\n",
                        s->remote_user);

        if (s->service)
                fprintf(f,
                        "SERVICE=%s\n",
                        s->service);

        if (s->seat && seat_is_vtconsole(s->seat))
                fprintf(f,
                        "VTNR=%i\n",
                        s->vtnr);

        if (s->leader > 0)
                fprintf(f,
                        "LEADER=%lu\n",
                        (unsigned long) s->leader);

        if (s->audit_id > 0)
                fprintf(f,
                        "AUDIT=%llu\n",
                        (unsigned long long) s->audit_id);

        fflush(f);

        if (ferror(f) || rename(temp_path, s->state_file) < 0) {
                r = -errno;
                unlink(s->state_file);
                unlink(temp_path);
        }

        fclose(f);
        free(temp_path);

finish:
        if (r < 0)
                log_error("Failed to save session data for %s: %s", s->id, strerror(-r));

        return r;
}

int session_load(Session *s) {
        char *remote = NULL,
                *kill_processes = NULL,
                *seat = NULL,
                *vtnr = NULL,
                *leader = NULL,
                *audit_id = NULL,
                *type = NULL;

        int k, r;

        assert(s);

        r = parse_env_file(s->state_file, NEWLINE,
                           "REMOTE",         &remote,
                           "KILL_PROCESSES", &kill_processes,
                           "CGROUP",         &s->cgroup_path,
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
                           NULL);

        if (r < 0)
                goto finish;

        if (remote) {
                k = parse_boolean(remote);
                if (k >= 0)
                        s->remote = k;
        }

        if (kill_processes) {
                k = parse_boolean(kill_processes);
                if (k >= 0)
                        s->kill_processes = k;
        }

        if (seat && !s->seat) {
                Seat *o;

                o = hashmap_get(s->manager->seats, seat);
                if (o)
                        seat_attach_session(o, s);
        }

        if (vtnr && s->seat && seat_is_vtconsole(s->seat)) {
                int v;

                k = safe_atoi(vtnr, &v);
                if (k >= 0 && v >= 1)
                        s->vtnr = v;
        }

        if (leader) {
                pid_t pid;

                k = parse_pid(leader, &pid);
                if (k >= 0 && pid >= 1) {
                        s->leader = pid;

                        audit_session_from_pid(pid, &s->audit_id);
                }
        }

        if (type) {
                SessionType t;

                t = session_type_from_string(type);
                if (t >= 0)
                        s->type = t;
        }

        session_open_fifo(s);

finish:
        free(remote);
        free(kill_processes);
        free(seat);
        free(vtnr);
        free(leader);
        free(audit_id);

        return r;
}

int session_activate(Session *s) {
        int r;
        Session *old_active;

        assert(s);

        if (s->vtnr < 0)
                return -ENOTSUP;

        if (!s->seat)
                return -ENOTSUP;

        if (s->seat->active == s)
                return 0;

        assert(seat_is_vtconsole(s->seat));

        r = chvt(s->vtnr);
        if (r < 0)
                return r;

        old_active = s->seat->active;
        s->seat->active = s;

        return seat_apply_acls(s->seat, old_active);
}

static int session_link_x11_socket(Session *s) {
        char *t, *f, *c;
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
        if (!f) {
                log_error("Out of memory");
                return -ENOMEM;
        }

        c = stpcpy(f, "/tmp/.X11-unix/X");
        memcpy(c, s->display+1, k);
        c[k] = 0;

        if (access(f, F_OK) < 0) {
                log_warning("Session %s has display %s with nonexisting socket %s.", s->id, s->display, f);
                free(f);
                return -ENOENT;
        }

        t = strappend(s->user->runtime_path, "/display");
        if (!t) {
                log_error("Out of memory");
                free(f);
                return -ENOMEM;
        }

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
                        free(f);
                        free(t);
                        return -errno;
                }
        }

done:
        log_info("Linked %s to %s.", f, t);
        free(f);
        free(t);

        s->user->display = s;

        return 0;
}

static int session_create_one_group(Session *s, const char *controller, const char *path) {
        int r;

        assert(s);
        assert(controller);
        assert(path);

        if (s->leader > 0) {
                r = cg_create_and_attach(controller, path, s->leader);
                if (r < 0)
                        r = cg_create(controller, path);
        } else
                r = cg_create(controller, path);

        if (r < 0)
                return r;

        r = cg_set_task_access(controller, path, 0644, s->user->uid, s->user->gid);
        if (r >= 0)
                r = cg_set_group_access(controller, path, 0755, s->user->uid, s->user->gid);

        return r;
}

static int session_create_cgroup(Session *s) {
        char **k;
        char *p;
        int r;

        assert(s);
        assert(s->user);
        assert(s->user->cgroup_path);

        if (!s->cgroup_path) {
                if (asprintf(&p, "%s/%s", s->user->cgroup_path, s->id) < 0) {
                        log_error("Out of memory");
                        return -ENOMEM;
                }
        } else
                p = s->cgroup_path;

        r = session_create_one_group(s, SYSTEMD_CGROUP_CONTROLLER, p);
        if (r < 0) {
                log_error("Failed to create "SYSTEMD_CGROUP_CONTROLLER":%s: %s", p, strerror(-r));
                free(p);
                s->cgroup_path = NULL;
                return r;
        }

        s->cgroup_path = p;

        STRV_FOREACH(k, s->controllers) {

                if (strv_contains(s->reset_controllers, *k))
                        continue;

                r = session_create_one_group(s, *k, p);
                if (r < 0)
                        log_warning("Failed to create %s:%s: %s", *k, p, strerror(-r));
        }

        STRV_FOREACH(k, s->manager->controllers) {

                if (strv_contains(s->reset_controllers, *k) ||
                    strv_contains(s->manager->reset_controllers, *k) ||
                    strv_contains(s->controllers, *k))
                        continue;

                r = session_create_one_group(s, *k, p);
                if (r < 0)
                        log_warning("Failed to create %s:%s: %s", *k, p, strerror(-r));
        }

        if (s->leader > 0) {

                STRV_FOREACH(k, s->reset_controllers) {
                        r = cg_attach(*k, "/", s->leader);
                        if (r < 0)
                                log_warning("Failed to reset controller %s: %s", *k, strerror(-r));

                }

                STRV_FOREACH(k, s->manager->reset_controllers) {

                        if (strv_contains(s->reset_controllers, *k) ||
                            strv_contains(s->controllers, *k))
                                continue;

                        r = cg_attach(*k, "/", s->leader);
                        if (r < 0)
                                log_warning("Failed to reset controller %s: %s", *k, strerror(-r));

                }
        }

        hashmap_put(s->manager->cgroups, s->cgroup_path, s);

        return 0;
}

int session_start(Session *s) {
        int r;

        assert(s);
        assert(s->user);

        if (s->started)
                return 0;

        r = user_start(s->user);
        if (r < 0)
                return r;

        log_info("New session %s of user %s.", s->id, s->user->name);

        /* Create cgroup */
        r = session_create_cgroup(s);
        if (r < 0)
                return r;

        /* Create X11 symlink */
        session_link_x11_socket(s);

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

static bool session_shall_kill(Session *s) {
        assert(s);

        if (!s->kill_processes)
                return false;

        if (strv_contains(s->manager->kill_exclude_users, s->user->name))
                return false;

        if (strv_isempty(s->manager->kill_only_users))
                return true;

        return strv_contains(s->manager->kill_only_users, s->user->name);
}

static int session_kill_cgroup(Session *s) {
        int r;
        char **k;

        assert(s);

        if (!s->cgroup_path)
                return 0;

        cg_trim(SYSTEMD_CGROUP_CONTROLLER, s->cgroup_path, false);

        if (session_shall_kill(s)) {

                r = cg_kill_recursive_and_wait(SYSTEMD_CGROUP_CONTROLLER, s->cgroup_path, true);
                if (r < 0)
                        log_error("Failed to kill session cgroup: %s", strerror(-r));

        } else {
                r = cg_is_empty_recursive(SYSTEMD_CGROUP_CONTROLLER, s->cgroup_path, true);
                if (r < 0)
                        log_error("Failed to check session cgroup: %s", strerror(-r));
                else if (r > 0) {
                        r = cg_delete(SYSTEMD_CGROUP_CONTROLLER, s->cgroup_path);
                        if (r < 0)
                                log_error("Failed to delete session cgroup: %s", strerror(-r));
                } else
                        r = -EBUSY;
        }

        STRV_FOREACH(k, s->user->manager->controllers)
                cg_trim(*k, s->cgroup_path, true);

        hashmap_remove(s->manager->cgroups, s->cgroup_path);

        free(s->cgroup_path);
        s->cgroup_path = NULL;

        return r;
}

static int session_unlink_x11_socket(Session *s) {
        char *t;
        int r;

        assert(s);
        assert(s->user);

        if (s->user->display != s)
                return 0;

        s->user->display = NULL;

        t = strappend(s->user->runtime_path, "/display");
        if (!t) {
                log_error("Out of memory");
                return -ENOMEM;
        }

        r = unlink(t);
        free(t);

        return r < 0 ? -errno : 0;
}

int session_stop(Session *s) {
        int r = 0, k;

        assert(s);

        if (s->started)
                log_info("Removed session %s.", s->id);

        /* Kill cgroup */
        k = session_kill_cgroup(s);
        if (k < 0)
                r = k;

        /* Remove X11 symlink */
        session_unlink_x11_socket(s);

        unlink(s->state_file);
        session_add_to_gc_queue(s);
        user_add_to_gc_queue(s->user);

        if (s->started)
                session_send_signal(s, false);

        if (s->seat) {
                if (s->seat->active == s)
                        seat_set_active(s->seat, NULL);

                seat_send_changed(s->seat, "Sessions\0");
        }

        user_send_changed(s->user, "Sessions\0");

        s->started = false;

        return r;
}

bool session_is_active(Session *s) {
        assert(s);

        if (!s->seat)
                return true;

        return s->seat->active == s;
}

int session_get_idle_hint(Session *s, dual_timestamp *t) {
        char *p;
        struct stat st;
        usec_t u, n;
        bool b;
        int k;

        assert(s);

        if (s->idle_hint) {
                if (t)
                        *t = s->idle_hint_timestamp;

                return s->idle_hint;
        }

        if (isempty(s->tty))
                goto dont_know;

        if (s->tty[0] != '/') {
                p = strappend("/dev/", s->tty);
                if (!p)
                        return -ENOMEM;
        } else
                p = NULL;

        if (!startswith(p ? p : s->tty, "/dev/")) {
                free(p);
                goto dont_know;
        }

        k = lstat(p ? p : s->tty, &st);
        free(p);

        if (k < 0)
                goto dont_know;

        u = timespec_load(&st.st_atim);
        n = now(CLOCK_REALTIME);
        b = u + IDLE_THRESHOLD_USEC < n;

        if (t)
                dual_timestamp_from_realtime(t, u + b ? IDLE_THRESHOLD_USEC : 0);

        return b;

dont_know:
        if (t)
                *t = s->idle_hint_timestamp;

        return 0;
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

int session_open_fifo(Session *s) {
        struct epoll_event ev;
        int r;

        assert(s);

        if (s->fifo_fd >= 0)
                return 0;

        if (!s->fifo_path)
                return -EINVAL;

        s->fifo_fd = open(s->fifo_path, O_RDONLY|O_CLOEXEC|O_NDELAY);
        if (s->fifo_fd < 0)
                return -errno;

        r = hashmap_put(s->manager->fifo_fds, INT_TO_PTR(s->fifo_fd + 1), s);
        if (r < 0)
                return r;

        zero(ev);
        ev.events = 0;
        ev.data.u32 = FD_FIFO_BASE + s->fifo_fd;

        if (epoll_ctl(s->manager->epoll_fd, EPOLL_CTL_ADD, s->fifo_fd, &ev) < 0)
                return -errno;

        return 0;
}

int session_create_fifo(Session *s) {
        int r;

        assert(s);

        if (!s->fifo_path) {
                if (asprintf(&s->fifo_path, "/run/systemd/sessions/%s.ref", s->id) < 0)
                        return -ENOMEM;

                if (mkfifo(s->fifo_path, 0600) < 0 && errno != EEXIST)
                        return -errno;
        }

        /* Open reading side */
        r = session_open_fifo(s);
        if (r < 0)
                return r;

        /* Open writing side */
        r = open(s->fifo_path, O_WRONLY|O_CLOEXEC|O_NDELAY);
        if (r < 0)
                return -errno;

        return r;
}

void session_remove_fifo(Session *s) {
        assert(s);

        if (s->fifo_fd >= 0) {
                assert_se(hashmap_remove(s->manager->fifo_fds, INT_TO_PTR(s->fifo_fd + 1)) == s);
                assert_se(epoll_ctl(s->manager->epoll_fd, EPOLL_CTL_DEL, s->fifo_fd, NULL) == 0);
                close_nointr_nofail(s->fifo_fd);
                s->fifo_fd = -1;
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

        if (s->fifo_fd >= 0) {

                r = pipe_eof(s->fifo_fd);
                if (r < 0)
                        return r;

                if (r == 0)
                        return 1;
        }

        if (s->cgroup_path) {

                r = cg_is_empty_recursive(SYSTEMD_CGROUP_CONTROLLER, s->cgroup_path, false);
                if (r < 0)
                        return r;

                if (r <= 0)
                        return 1;
        }

        return 0;
}

void session_add_to_gc_queue(Session *s) {
        assert(s);

        if (s->in_gc_queue)
                return;

        LIST_PREPEND(Session, gc_queue, s->manager->session_gc_queue, s);
        s->in_gc_queue = true;
}

static const char* const session_type_table[_SESSION_TYPE_MAX] = {
        [SESSION_TTY] = "tty",
        [SESSION_X11] = "x11",
        [SESSION_UNSPECIFIED] = "unspecified"
};

DEFINE_STRING_TABLE_LOOKUP(session_type, SessionType);
