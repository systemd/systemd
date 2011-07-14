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

#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "util.h"
#include "cgroup-util.h"
#include "macro.h"
#include "sd-login.h"

_public_ int sd_pid_get_session(pid_t pid, char **session) {
        int r;
        char *cg_process, *cg_init, *p;

        if (pid == 0)
                pid = getpid();

        if (pid <= 0)
                return -EINVAL;

        if (!session)
                return -EINVAL;

        r = cg_get_by_pid(SYSTEMD_CGROUP_CONTROLLER, pid, &cg_process);
        if (r < 0)
                return r;

        r = cg_get_by_pid(SYSTEMD_CGROUP_CONTROLLER, 1, &cg_init);
        if (r < 0) {
                free(cg_process);
                return r;
        }

        if (endswith(cg_init, "/system"))
                cg_init[strlen(cg_init)-7] = 0;
        else if (streq(cg_init, "/"))
                cg_init[0] = 0;

        if (startswith(cg_process, cg_init))
                p = cg_process + strlen(cg_init);
        else
                p = cg_process;

        free(cg_init);

        if (!startswith(p, "/user/")) {
                free(cg_process);
                return -ENOENT;
        }

        p += 6;
        if (startswith(p, "shared/") || streq(p, "shared")) {
                free(cg_process);
                return -ENOENT;
        }

        p = strchr(p, '/');
        if (!p) {
                free(cg_process);
                return -ENOENT;
        }

        p++;
        p = strndup(p, strcspn(p, "/"));
        free(cg_process);

        if (!p)
                return -ENOMEM;

        *session = p;
        return 0;
}

_public_ int sd_uid_get_state(uid_t uid, char**state) {
        char *p, *s = NULL;
        int r;

        if (!state)
                return -EINVAL;

        if (asprintf(&p, "/run/systemd/users/%lu", (unsigned long) uid) < 0)
                return -ENOMEM;

        r = parse_env_file(p, NEWLINE, "STATE", &s, NULL);
        free(p);

        if (r == -ENOENT) {
                free(s);
                s = strdup("offline");
                if (!s)
                        return -ENOMEM;

                *state = s;
                return 0;
        } else if (r < 0) {
                free(s);
                return r;
        } else if (!s)
                return -EIO;

        *state = s;
        return 0;
}

static int uid_is_on_seat_internal(uid_t uid, const char *seat, const char *variable) {
        char *p, *w, *t, *state, *s = NULL;
        size_t l;
        int r;

        if (!seat)
                return -EINVAL;

        p = strappend("/run/systemd/seats/", seat);
        if (!p)
                return -ENOMEM;

        r = parse_env_file(p, NEWLINE, "UIDS", &s, NULL);
        free(p);

        if (r < 0) {
                free(s);
                return r;
        }

        if (!s)
                return -EIO;

        if (asprintf(&t, "%lu", (unsigned long) uid) < 0) {
                free(s);
                return -ENOMEM;
        }

        FOREACH_WORD(w, l, s, state) {
                if (strncmp(t, w, l) == 0) {
                        free(s);
                        free(t);

                        return 1;
                }
        }

        free(s);
        free(t);

        return 0;
}

_public_ int sd_uid_is_on_seat(uid_t uid, const char *seat) {
        return uid_is_on_seat_internal(uid, seat, "UIDS");
}

_public_ int sd_uid_is_active_on_seat(uid_t uid, const char *seat) {
        return uid_is_on_seat_internal(uid, seat, "ACTIVE_UID");
}

_public_ int sd_session_is_active(const char *session) {
        int r;
        char *p, *s = NULL;

        if (!session)
                return -EINVAL;

        p = strappend("/run/systemd/sessions/", session);
        if (!p)
                return -ENOMEM;

        r = parse_env_file(p, NEWLINE, "ACTIVE", &s, NULL);
        free(p);

        if (r < 0) {
                free(s);
                return r;
        }

        if (!s)
                return -EIO;

        r = parse_boolean(s);
        free(s);

        return r;
}

_public_ int sd_session_get_uid(const char *session, uid_t *uid) {
        int r;
        char *p, *s = NULL;
        unsigned long ul;

        if (!session)
                return -EINVAL;
        if (!uid)
                return -EINVAL;

        p = strappend("/run/systemd/sessions/", session);
        if (!p)
                return -ENOMEM;

        r = parse_env_file(p, NEWLINE, "UID", &s, NULL);
        free(p);

        if (r < 0) {
                free(s);
                return r;
        }

        if (!s)
                return -EIO;

        r = safe_atolu(s, &ul);
        free(s);

        if (r < 0)
                return r;

        *uid = (uid_t) ul;
        return 0;
}

_public_ int sd_session_get_seat(const char *session, char **seat) {
        char *p, *s = NULL;
        int r;

        if (!session)
                return -EINVAL;
        if (!seat)
                return -EINVAL;

        p = strappend("/run/systemd/sessions/", session);
        if (!p)
                return -ENOMEM;

        r = parse_env_file(p, NEWLINE, "SEAT", &s, NULL);
        free(p);

        if (r < 0) {
                free(s);
                return r;
        }

        if (isempty(s))
                return -ENOENT;

        *seat = s;
        return 0;
}

_public_ int sd_seat_get_active(const char *seat, char **session, uid_t *uid) {
        char *p, *s = NULL, *t = NULL;
        int r;

        if (!seat)
                return -EINVAL;
        if (!session && !uid)
                return -EINVAL;

        p = strappend("/run/systemd/seats/", seat);
        if (!p)
                return -ENOMEM;

        r = parse_env_file(p, NEWLINE,
                           "ACTIVE", &s,
                           "ACTIVE_UID", &t,
                           NULL);
        free(p);

        if (r < 0) {
                free(s);
                free(t);
                return r;
        }

        if (session && !s)  {
                free(t);
                return -EIO;
        }

        if (uid && !t) {
                free(s);
                return -EIO;
        }

        if (uid && t) {
                unsigned long ul;

                r = safe_atolu(t, &ul);
                if (r < 0) {
                        free(t);
                        free(s);
                        return r;
                }

                *uid = (uid_t) ul;
        }

        free(t);

        if (session && s)
                *session = s;
        else
                free(s);

        return 0;
}
