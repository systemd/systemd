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

#include "logind-session.h"
#include "strv.h"
#include "util.h"
#include "cgroup-util.h"

Session* session_new(Manager *m, User *u, const char *id) {
        Session *s;

        assert(m);
        assert(id);

        s = new0(Session, 1);
        if (!s)
                return NULL;

        s->state_file = strappend("/run/systemd/session/", id);
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
        s->pipe_fd = -1;
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

        if (s->seat)
                LIST_REMOVE(Session, sessions_by_seat, s->seat->sessions, s);

        free(s->cgroup_path);
        strv_free(s->controllers);

        free(s->tty);
        free(s->display);
        free(s->remote_host);
        free(s->remote_user);

        hashmap_remove(s->manager->sessions, s->id);

        free(s->state_file);
        free(s);
}

int session_save(Session *s) {
        FILE *f;
        int r = 0;
        char *temp_path;

        assert(s);

        r = safe_mkdir("/run/systemd/session", 0755, 0, 0);
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

        if (s->cgroup_path)
                fprintf(f,
                        "CGROUP=%s\n",
                        s->cgroup_path);

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

        if (s->seat && s->seat->manager->vtconsole == s->seat)
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
        assert(s);

        return 0;
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

        assert(s->manager->vtconsole == s->seat);

        r = chvt(s->vtnr);
        if (r < 0)
                return r;

        old_active = s->seat->active;
        s->seat->active = s;

        return seat_apply_acls(s->seat, old_active);
}

bool x11_display_is_local(const char *display) {
        assert(display);

        return
                display[0] == ':' &&
                display[1] >= '0' &&
                display[1] <= '9';
}

static int session_link_x11_socket(Session *s) {
        char *t, *f, *c;
        size_t k;

        assert(s);
        assert(s->user);
        assert(s->user->runtime_path);

        if (s->user->display)
                return 0;

        if (!s->display || !x11_display_is_local(s->display))
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

        if (s->leader > 0)
                r = cg_create_and_attach(SYSTEMD_CGROUP_CONTROLLER, p, s->leader);
        else
                r = cg_create(SYSTEMD_CGROUP_CONTROLLER, p);

        if (r < 0) {
                free(p);
                s->cgroup_path = NULL;
                log_error("Failed to create "SYSTEMD_CGROUP_CONTROLLER":%s: %s", p, strerror(-r));
                return r;
        }

        s->cgroup_path = p;

        STRV_FOREACH(k, s->manager->controllers) {
                if (s->leader > 0)
                        r = cg_create_and_attach(*k, p, s->leader);
                else
                        r = cg_create(*k, p);

                if (r < 0)
                        log_warning("Failed to create cgroup %s:%s: %s", *k, p, strerror(-r));
        }

        return 0;
}

int session_start(Session *s) {
        int r;

        assert(s);
        assert(s->user);

        /* Create cgroup */
        r = session_create_cgroup(s);
        if (r < 0)
                return r;

        /* Create X11 symlink */
        session_link_x11_socket(s);

        /* Save session data */
        session_save(s);

        dual_timestamp_get(&s->timestamp);

        return 0;
}

static bool session_shall_kill(Session *s) {
        assert(s);

        return s->kill_processes;
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

        /* Kill cgroup */
        k = session_kill_cgroup(s);
        if (k < 0)
                r = k;

        /* Remove X11 symlink */
        session_unlink_x11_socket(s);

        unlink(s->state_file);
        session_add_to_gc_queue(s);

        return r;
}

bool session_is_active(Session *s) {
        assert(s);

        if (!s->seat)
                return true;

        return s->seat->active == s;
}

int session_check_gc(Session *s) {
        int r;

        assert(s);

        if (s->pipe_fd >= 0) {

                r = pipe_eof(s->pipe_fd);
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
        [SESSION_X11] = "x11"
};

DEFINE_STRING_TABLE_LOOKUP(session_type, SessionType);
