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

#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/vt.h>
#include <string.h>

#include "logind-seat.h"
#include "logind-acl.h"
#include "util.h"

Seat *seat_new(Manager *m, const char *id) {
        Seat *s;

        assert(m);
        assert(id);

        s = new0(Seat, 1);
        if (!s)
                return NULL;

        s->state_file = strappend("/run/systemd/seat/", id);
        if (!s->state_file) {
                free(s);
                return NULL;
        }

        s->id = file_name_from_path(s->state_file);

        if (hashmap_put(m->seats, s->id, s) < 0) {
                free(s->id);
                free(s);
                return NULL;
        }

        s->manager = m;

        return s;
}

void seat_free(Seat *s) {
        assert(s);

        while (s->sessions)
                session_free(s->sessions);

        assert(!s->active);

        while (s->devices)
                device_free(s->devices);

        hashmap_remove(s->manager->seats, s->id);

        free(s->state_file);
        free(s);
}

int seat_save(Seat *s) {
        FILE *f;
        int r;

        assert(s);

        r = safe_mkdir("/run/systemd/seat", 0755, 0, 0);
        if (r < 0)
                return r;

        f = fopen(s->state_file, "we");
        if (!f)
                return -errno;

        fprintf(f,
                "IS_VTCONSOLE=%i\n",
                s->manager->vtconsole == s);

        if (s->active) {
                assert(s->active->user);

                fprintf(f,
                        "ACTIVE=%s\n"
                        "ACTIVE_UID=%lu\n",
                        s->active->id,
                        (unsigned long) s->active->user->uid);
        }

        if (s->sessions) {
                Session *i;
                fputs("OTHER_UIDS=", f);

                LIST_FOREACH(sessions_by_seat, i, s->sessions) {
                        assert(i->user);

                        if (i == s->active)
                                continue;

                        fprintf(f,
                                "%s%lu",
                                i == s->sessions ? "" : " ",
                                (unsigned long) i->user->uid);
                }
        }

        fflush(f);
        if (ferror(f)) {
                r = -errno;
                unlink(s->state_file);
        }

        fclose(f);
        return r;
}

int seat_load(Seat *s) {
        assert(s);

        return 0;
}

static int vt_allocate(int vtnr) {
        int fd, r;
        char *p;

        assert(vtnr >= 1);

        if (asprintf(&p, "/dev/tty%i", vtnr) < 0)
                return -ENOMEM;

        fd = open_terminal(p, O_RDWR|O_NOCTTY|O_CLOEXEC);
        free(p);

        r = fd < 0 ? -errno : 0;

        if (fd >= 0)
                close_nointr_nofail(fd);

        return r;
}

int seat_preallocate_vts(Seat *s) {
        int i, r = 0;

        assert(s);
        assert(s->manager);

        if (s->manager->n_autovts <= 0)
                return 0;

        if (s->manager->vtconsole != s)
                return 0;

        for (i = 1; i < s->manager->n_autovts; i++) {
                int q;

                q = vt_allocate(i);
                if (r >= 0 && q < 0)
                        r = q;
        }

        return r;
}

int seat_apply_acls(Seat *s, Session *old_active) {
        int r;

        assert(s);

        r = devnode_acl_all(s->manager->udev,
                            s->id,
                            false,
                            !!old_active, old_active ? old_active->user->uid : 0,
                            !!s->active, s->active ? s->active->user->uid : 0);

        if (r < 0)
                log_error("Failed to apply ACLs: %s", strerror(-r));

        return r;
}

int seat_active_vt_changed(Seat *s, int vtnr) {
        Session *i;
        Session *old_active;

        assert(s);
        assert(vtnr >= 1);
        assert(s->manager->vtconsole == s);

        old_active = s->active;
        s->active = NULL;

        LIST_FOREACH(sessions_by_seat, i, s->sessions)
                if (i->vtnr == vtnr) {
                        s->active = i;
                        break;
                }

        if (old_active == s->active)
                return 0;

        seat_apply_acls(s, old_active);
        manager_spawn_autovt(s->manager, vtnr);

        return 0;
}

int seat_stop(Seat *s) {
        Session *session;
        int r = 0;

        assert(s);

        LIST_FOREACH(sessions_by_seat, session, s->sessions) {
                int k;

                k = session_stop(session);
                if (k < 0)
                        r = k;
        }

        return r;
}
