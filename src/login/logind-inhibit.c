/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

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
#include <sys/epoll.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "util.h"
#include "mkdir.h"
#include "path-util.h"
#include "logind-inhibit.h"
#include "fileio.h"

Inhibitor* inhibitor_new(Manager *m, const char* id) {
        Inhibitor *i;

        assert(m);

        i = new0(Inhibitor, 1);
        if (!i)
                return NULL;

        i->state_file = strappend("/run/systemd/inhibit/", id);
        if (!i->state_file) {
                free(i);
                return NULL;
        }

        i->id = path_get_file_name(i->state_file);

        if (hashmap_put(m->inhibitors, i->id, i) < 0) {
                free(i->state_file);
                free(i);
                return NULL;
        }

        i->manager = m;
        i->fifo_fd = -1;

        return i;
}

void inhibitor_free(Inhibitor *i) {
        assert(i);

        free(i->who);
        free(i->why);

        hashmap_remove(i->manager->inhibitors, i->id);
        inhibitor_remove_fifo(i);

        if (i->state_file) {
                unlink(i->state_file);
                free(i->state_file);
        }

        free(i);
}

int inhibitor_save(Inhibitor *i) {
        char *temp_path, *cc;
        int r;
        FILE *f;

        assert(i);

        r = mkdir_safe_label("/run/systemd/inhibit", 0755, 0, 0);
        if (r < 0)
                goto finish;

        r = fopen_temporary(i->state_file, &f, &temp_path);
        if (r < 0)
                goto finish;

        fchmod(fileno(f), 0644);

        fprintf(f,
                "# This is private data. Do not parse.\n"
                "WHAT=%s\n"
                "MODE=%s\n"
                "UID=%lu\n"
                "PID=%lu\n",
                inhibit_what_to_string(i->what),
                inhibit_mode_to_string(i->mode),
                (unsigned long) i->uid,
                (unsigned long) i->pid);

        if (i->who) {
                cc = cescape(i->who);
                if (!cc)
                        r = -ENOMEM;
                else {
                        fprintf(f, "WHO=%s\n", cc);
                        free(cc);
                }
        }

        if (i->why) {
                cc = cescape(i->why);
                if (!cc)
                        r = -ENOMEM;
                else {
                        fprintf(f, "WHY=%s\n", cc);
                        free(cc);
                }
        }

        if (i->fifo_path)
                fprintf(f, "FIFO=%s\n", i->fifo_path);

        fflush(f);

        if (ferror(f) || rename(temp_path, i->state_file) < 0) {
                r = -errno;
                unlink(i->state_file);
                unlink(temp_path);
        }

        fclose(f);
        free(temp_path);

finish:
        if (r < 0)
                log_error("Failed to save inhibit data for %s: %s", i->id, strerror(-r));

        return r;
}

int inhibitor_start(Inhibitor *i) {
        assert(i);

        if (i->started)
                return 0;

        dual_timestamp_get(&i->since);

        log_debug("Inhibitor %s (%s) pid=%lu uid=%lu mode=%s started.",
                  strna(i->who), strna(i->why),
                  (unsigned long) i->pid, (unsigned long) i->uid,
                  inhibit_mode_to_string(i->mode));

        inhibitor_save(i);

        i->started = true;

        manager_send_changed(i->manager, i->mode == INHIBIT_BLOCK ? "BlockInhibited\0" : "DelayInhibited\0");

        return 0;
}

int inhibitor_stop(Inhibitor *i) {
        assert(i);

        if (i->started)
                log_debug("Inhibitor %s (%s) pid=%lu uid=%lu mode=%s stopped.",
                          strna(i->who), strna(i->why),
                          (unsigned long) i->pid, (unsigned long) i->uid,
                          inhibit_mode_to_string(i->mode));

        if (i->state_file)
                unlink(i->state_file);

        i->started = false;

        manager_send_changed(i->manager, i->mode == INHIBIT_BLOCK ? "BlockInhibited\0" : "DelayInhibited\0");

        return 0;
}

int inhibitor_load(Inhibitor *i) {
        InhibitWhat w;
        InhibitMode mm;
        int r;
        char *cc,
                *what = NULL,
                *uid = NULL,
                *pid = NULL,
                *who = NULL,
                *why = NULL,
                *mode = NULL;

        r = parse_env_file(i->state_file, NEWLINE,
                           "WHAT", &what,
                           "UID", &uid,
                           "PID", &pid,
                           "WHO", &who,
                           "WHY", &why,
                           "MODE", &mode,
                           "FIFO", &i->fifo_path,
                           NULL);
        if (r < 0)
                goto finish;

        w = what ? inhibit_what_from_string(what) : 0;
        if (w >= 0)
                i->what = w;

        mm = mode ? inhibit_mode_from_string(mode) : INHIBIT_BLOCK;
        if  (mm >= 0)
                i->mode = mm;

        if (uid) {
                r = parse_uid(uid, &i->uid);
                if (r < 0)
                        goto finish;
        }

        if (pid) {
                r = parse_pid(pid, &i->pid);
                if (r < 0)
                        goto finish;
        }

        if (who) {
                cc = cunescape(who);
                if (!cc) {
                        r = -ENOMEM;
                        goto finish;
                }

                free(i->who);
                i->who = cc;
        }

        if (why) {
                cc = cunescape(why);
                if (!cc) {
                        r = -ENOMEM;
                        goto finish;
                }

                free(i->why);
                i->why = cc;
        }

        if (i->fifo_path) {
                int fd;

                fd = inhibitor_create_fifo(i);
                if (fd >= 0)
                        close_nointr_nofail(fd);
        }

finish:
        free(what);
        free(uid);
        free(pid);
        free(who);
        free(why);

        return r;
}

int inhibitor_create_fifo(Inhibitor *i) {
        int r;

        assert(i);

        /* Create FIFO */
        if (!i->fifo_path) {
                r = mkdir_safe_label("/run/systemd/inhibit", 0755, 0, 0);
                if (r < 0)
                        return r;

                if (asprintf(&i->fifo_path, "/run/systemd/inhibit/%s.ref", i->id) < 0)
                        return -ENOMEM;

                if (mkfifo(i->fifo_path, 0600) < 0 && errno != EEXIST)
                        return -errno;
        }

        /* Open reading side */
        if (i->fifo_fd < 0) {
                struct epoll_event ev = {};

                i->fifo_fd = open(i->fifo_path, O_RDONLY|O_CLOEXEC|O_NDELAY);
                if (i->fifo_fd < 0)
                        return -errno;

                r = hashmap_put(i->manager->inhibitor_fds, INT_TO_PTR(i->fifo_fd + 1), i);
                if (r < 0)
                        return r;

                ev.events = 0;
                ev.data.u32 = FD_OTHER_BASE + i->fifo_fd;

                if (epoll_ctl(i->manager->epoll_fd, EPOLL_CTL_ADD, i->fifo_fd, &ev) < 0)
                        return -errno;
        }

        /* Open writing side */
        r = open(i->fifo_path, O_WRONLY|O_CLOEXEC|O_NDELAY);
        if (r < 0)
                return -errno;

        return r;
}

void inhibitor_remove_fifo(Inhibitor *i) {
        assert(i);

        if (i->fifo_fd >= 0) {
                assert_se(hashmap_remove(i->manager->inhibitor_fds, INT_TO_PTR(i->fifo_fd + 1)) == i);
                assert_se(epoll_ctl(i->manager->epoll_fd, EPOLL_CTL_DEL, i->fifo_fd, NULL) == 0);
                close_nointr_nofail(i->fifo_fd);
                i->fifo_fd = -1;
        }

        if (i->fifo_path) {
                unlink(i->fifo_path);
                free(i->fifo_path);
                i->fifo_path = NULL;
        }
}

InhibitWhat manager_inhibit_what(Manager *m, InhibitMode mm) {
        Inhibitor *i;
        Iterator j;
        InhibitWhat what = 0;

        assert(m);

        HASHMAP_FOREACH(i, m->inhibitor_fds, j)
                if (i->mode == mm)
                        what |= i->what;

        return what;
}

static int pid_is_active(Manager *m, pid_t pid) {
        Session *s;
        int r;

        r = manager_get_session_by_pid(m, pid, &s);
        if (r < 0)
                return r;

        /* If there's no session assigned to it, then it's globally
         * active on all ttys */
        if (r == 0)
                return 1;

        return session_is_active(s);
}

bool manager_is_inhibited(
                Manager *m,
                InhibitWhat w,
                InhibitMode mm,
                dual_timestamp *since,
                bool ignore_inactive,
                bool ignore_uid,
                uid_t uid) {

        Inhibitor *i;
        Iterator j;
        struct dual_timestamp ts = { 0, 0 };
        bool inhibited = false;

        assert(m);
        assert(w > 0 && w < _INHIBIT_WHAT_MAX);

        HASHMAP_FOREACH(i, m->inhibitor_fds, j) {
                if (!(i->what & w))
                        continue;

                if (i->mode != mm)
                        continue;

                if (ignore_inactive && pid_is_active(m, i->pid) <= 0)
                        continue;

                if (ignore_uid && i->uid == uid)
                        continue;

                if (!inhibited ||
                    i->since.monotonic < ts.monotonic)
                        ts = i->since;

                inhibited = true;
        }

        if (since)
                *since = ts;

        return inhibited;
}

const char *inhibit_what_to_string(InhibitWhat w) {
        static __thread char buffer[97];
        char *p;

        if (w < 0 || w >= _INHIBIT_WHAT_MAX)
                return NULL;

        p = buffer;
        if (w & INHIBIT_SHUTDOWN)
                p = stpcpy(p, "shutdown:");
        if (w & INHIBIT_SLEEP)
                p = stpcpy(p, "sleep:");
        if (w & INHIBIT_IDLE)
                p = stpcpy(p, "idle:");
        if (w & INHIBIT_HANDLE_POWER_KEY)
                p = stpcpy(p, "handle-power-key:");
        if (w & INHIBIT_HANDLE_SUSPEND_KEY)
                p = stpcpy(p, "handle-suspend-key:");
        if (w & INHIBIT_HANDLE_HIBERNATE_KEY)
                p = stpcpy(p, "handle-hibernate-key:");
        if (w & INHIBIT_HANDLE_LID_SWITCH)
                p = stpcpy(p, "handle-lid-switch:");

        if (p > buffer)
                *(p-1) = 0;
        else
                *p = 0;

        return buffer;
}

InhibitWhat inhibit_what_from_string(const char *s) {
        InhibitWhat what = 0;
        char *w, *state;
        size_t l;

        FOREACH_WORD_SEPARATOR(w, l, s, ":", state) {
                if (l == 8 && strneq(w, "shutdown", l))
                        what |= INHIBIT_SHUTDOWN;
                else if (l == 5 && strneq(w, "sleep", l))
                        what |= INHIBIT_SLEEP;
                else if (l == 4 && strneq(w, "idle", l))
                        what |= INHIBIT_IDLE;
                else if (l == 16 && strneq(w, "handle-power-key", l))
                        what |= INHIBIT_HANDLE_POWER_KEY;
                else if (l == 18 && strneq(w, "handle-suspend-key", l))
                        what |= INHIBIT_HANDLE_SUSPEND_KEY;
                else if (l == 20 && strneq(w, "handle-hibernate-key", l))
                        what |= INHIBIT_HANDLE_HIBERNATE_KEY;
                else if (l == 17 && strneq(w, "handle-lid-switch", l))
                        what |= INHIBIT_HANDLE_LID_SWITCH;
                else
                        return _INHIBIT_WHAT_INVALID;
        }

        return what;
}

static const char* const inhibit_mode_table[_INHIBIT_MODE_MAX] = {
        [INHIBIT_BLOCK] = "block",
        [INHIBIT_DELAY] = "delay"
};

DEFINE_STRING_TABLE_LOOKUP(inhibit_mode, InhibitMode);
