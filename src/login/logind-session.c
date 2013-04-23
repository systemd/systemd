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

#include "systemd/sd-id128.h"
#include "systemd/sd-messages.h"
#include "strv.h"
#include "util.h"
#include "mkdir.h"
#include "path-util.h"
#include "cgroup-util.h"
#include "logind-session.h"
#include "fileio.h"

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

        s->id = path_get_file_name(s->state_file);

        if (hashmap_put(m->sessions, s->id, s) < 0) {
                free(s->state_file);
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
                hashmap_remove(s->manager->session_cgroups, s->cgroup_path);

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
                "REMOTE=%i\n"
                "KILL_PROCESSES=%i\n",
                (unsigned long) s->user->uid,
                s->user->name,
                session_is_active(s),
                session_state_to_string(session_get_state(s)),
                s->remote,
                s->kill_processes);

        if (s->type >= 0)
                fprintf(f,
                        "TYPE=%s\n",
                        session_type_to_string(s->type));

        if (s->class >= 0)
                fprintf(f,
                        "CLASS=%s\n",
                        session_class_to_string(s->class));

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

        if (s->seat && seat_can_multi_session(s->seat))
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
                *type = NULL,
                *class = NULL;

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
                           "CLASS",          &class,
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

        if (vtnr && s->seat && seat_can_multi_session(s->seat)) {
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

finish:
        free(remote);
        free(kill_processes);
        free(seat);
        free(vtnr);
        free(leader);
        free(audit_id);
        free(class);

        return r;
}

int session_activate(Session *s) {
        int r;

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

        return seat_set_active(s->seat, s);
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
        if (!f)
                return log_oom();

        c = stpcpy(f, "/tmp/.X11-unix/X");
        memcpy(c, s->display+1, k);
        c[k] = 0;

        if (access(f, F_OK) < 0) {
                log_warning("Session %s has display %s with non-existing socket %s.", s->id, s->display, f);
                free(f);
                return -ENOENT;
        }

        /* Note that this cannot be in a subdir to avoid
         * vulnerabilities since we are privileged but the runtime
         * path is owned by the user */

        t = strappend(s->user->runtime_path, "/X11-display");
        if (!t) {
                free(f);
                return log_oom();
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
        assert(path);

        if (s->leader > 0) {
                r = cg_create_and_attach(controller, path, s->leader);
                if (r < 0)
                        r = cg_create(controller, path, NULL);
        } else
                r = cg_create(controller, path, NULL);

        if (r < 0)
                return r;

        r = cg_set_task_access(controller, path, 0644, s->user->uid, s->user->gid, -1);
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
                _cleanup_free_ char *name = NULL, *escaped = NULL;

                name = strappend(s->id, ".session");
                if (!name)
                        return log_oom();

                escaped = cg_escape(name);
                if (!escaped)
                        return log_oom();

                p = strjoin(s->user->cgroup_path, "/", escaped, NULL);
                if (!p)
                        return log_oom();
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

        r = hashmap_put(s->manager->session_cgroups, s->cgroup_path, s);
        if (r < 0)
                log_warning("Failed to create mapping between cgroup and session");

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

        log_struct(s->type == SESSION_TTY || s->type == SESSION_X11 ? LOG_INFO : LOG_DEBUG,
                   MESSAGE_ID(SD_MESSAGE_SESSION_START),
                   "SESSION_ID=%s", s->id,
                   "USER_ID=%s", s->user->name,
                   "LEADER=%lu", (unsigned long) s->leader,
                   "MESSAGE=New session %s of user %s.", s->id, s->user->name,
                   NULL);

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

static int session_terminate_cgroup(Session *s) {
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
                if (s->leader > 0) {
                        Session *t;

                        /* We still send a HUP to the leader process,
                         * even if we are not supposed to kill the
                         * whole cgroup. But let's first check the
                         * leader still exists and belongs to our
                         * session... */

                        r = manager_get_session_by_pid(s->manager, s->leader, &t);
                        if (r > 0 && t == s) {
                                kill(s->leader, SIGTERM); /* for normal processes */
                                kill(s->leader, SIGHUP);  /* for shells */
                                kill(s->leader, SIGCONT); /* in case they are stopped */
                        }
                }

                r = cg_is_empty_recursive(SYSTEMD_CGROUP_CONTROLLER, s->cgroup_path, true);
                if (r < 0)
                        log_error("Failed to check session cgroup: %s", strerror(-r));
                else if (r > 0) {
                        r = cg_delete(SYSTEMD_CGROUP_CONTROLLER, s->cgroup_path);
                        if (r < 0)
                                log_error("Failed to delete session cgroup: %s", strerror(-r));
                }
        }

        STRV_FOREACH(k, s->user->manager->controllers)
                cg_trim(*k, s->cgroup_path, true);

        hashmap_remove(s->manager->session_cgroups, s->cgroup_path);

        free(s->cgroup_path);
        s->cgroup_path = NULL;

        return 0;
}

static int session_unlink_x11_socket(Session *s) {
        char *t;
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
        free(t);

        return r < 0 ? -errno : 0;
}

int session_stop(Session *s) {
        int r = 0, k;

        assert(s);

        if (s->started)
                log_struct(s->type == SESSION_TTY || s->type == SESSION_X11 ? LOG_INFO : LOG_DEBUG,
                           MESSAGE_ID(SD_MESSAGE_SESSION_STOP),
                           "SESSION_ID=%s", s->id,
                           "USER_ID=%s", s->user->name,
                           "LEADER=%lu", (unsigned long) s->leader,
                           "MESSAGE=Removed session %s.", s->id,
                           NULL);

        /* Kill cgroup */
        k = session_terminate_cgroup(s);
        if (k < 0)
                r = k;

        /* Remove X11 symlink */
        session_unlink_x11_socket(s);

        unlink(s->state_file);
        session_add_to_gc_queue(s);
        user_add_to_gc_queue(s->user);

        if (s->started)
                session_send_signal(s, false);

        s->started = false;

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

        /* For other TTY sessions, let's find the most recent atime of
         * the ttys of any of the processes of the session */
        if (s->cgroup_path) {
                _cleanup_fclose_ FILE *f = NULL;

                if (cg_enumerate_processes(SYSTEMD_CGROUP_CONTROLLER, s->cgroup_path, &f) >= 0) {
                        pid_t pid;

                        atime = 0;
                        while (cg_read_pid(f, &pid) > 0) {
                                usec_t a;

                                if (get_process_ctty_atime(pid, &a) >= 0)
                                        if (atime == 0 || atime < a)
                                                atime = a;
                        }

                        if (atime != 0)
                                goto found_atime;
                }
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

SessionState session_get_state(Session *s) {
        assert(s);

        if (s->fifo_fd < 0)
                return SESSION_CLOSING;

        if (session_is_active(s))
                return SESSION_ACTIVE;

        return SESSION_ONLINE;
}

int session_kill(Session *s, KillWho who, int signo) {
        int r = 0;
        Set *pid_set = NULL;

        assert(s);

        if (!s->cgroup_path)
                return -ESRCH;

        if (s->leader <= 0 && who == KILL_LEADER)
                return -ESRCH;

        if (s->leader > 0)
                if (kill(s->leader, signo) < 0)
                        r = -errno;

        if (who == KILL_ALL) {
                int q;

                pid_set = set_new(trivial_hash_func, trivial_compare_func);
                if (!pid_set)
                        return -ENOMEM;

                if (s->leader > 0) {
                        q = set_put(pid_set, LONG_TO_PTR(s->leader));
                        if (q < 0)
                                r = q;
                }

                q = cg_kill_recursive(SYSTEMD_CGROUP_CONTROLLER, s->cgroup_path, signo, false, true, false, pid_set);
                if (q < 0)
                        if (q != -EAGAIN && q != -ESRCH && q != -ENOENT)
                                r = q;
        }

        if (pid_set)
                set_free(pid_set);

        return r;
}

static const char* const session_state_table[_SESSION_TYPE_MAX] = {
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
