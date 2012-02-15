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
#include <sys/inotify.h>

#include "util.h"
#include "cgroup-util.h"
#include "macro.h"
#include "sd-login.h"
#include "strv.h"

static int pid_get_cgroup(pid_t pid, char **root, char **cgroup) {
        char *cg_process, *cg_init, *p;
        int r;

        if (pid == 0)
                pid = getpid();

        if (pid <= 0)
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

        if (cgroup) {
                char* c;

                c = strdup(p);
                if (!c) {
                        free(cg_process);
                        return -ENOMEM;
                }

                *cgroup = c;
        }

        if (root) {
                cg_process[p-cg_process] = 0;
                *root = cg_process;
        } else
                free(cg_process);

        return 0;
}

_public_ int sd_pid_get_session(pid_t pid, char **session) {
        int r;
        char *cgroup, *p;

        if (!session)
                return -EINVAL;

        r = pid_get_cgroup(pid, NULL, &cgroup);
        if (r < 0)
                return r;

        if (!startswith(cgroup, "/user/")) {
                free(cgroup);
                return -ENOENT;
        }

        p = strchr(cgroup + 6, '/');
        if (!p) {
                free(cgroup);
                return -ENOENT;
        }

        p++;
        if (startswith(p, "shared/") || streq(p, "shared")) {
                free(cgroup);
                return -ENOENT;
        }

        p = strndup(p, strcspn(p, "/"));
        free(cgroup);

        if (!p)
                return -ENOMEM;

        *session = p;
        return 0;
}

_public_ int sd_pid_get_unit(pid_t pid, char **unit) {
        int r;
        char *cgroup, *p, *at, *b;
        size_t k;

        if (!unit)
                return -EINVAL;

        r = pid_get_cgroup(pid, NULL, &cgroup);
        if (r < 0)
                return r;

        if (!startswith(cgroup, "/system/")) {
                free(cgroup);
                return -ENOENT;
        }

        p = cgroup + 8;
        k = strcspn(p, "/");

        at = memchr(p, '@', k);
        if (at && at[1] == '.') {
                size_t j;

                /* This is a templated service */
                if (p[k] != '/') {
                        free(cgroup);
                        return -EIO;
                }

                j = strcspn(p+k+1, "/");

                b = malloc(k + j + 1);

                if (b) {
                        memcpy(b, p, at - p + 1);
                        memcpy(b + (at - p) + 1, p + k + 1, j);
                        memcpy(b + (at - p) + 1 + j, at + 1, k - (at - p) - 1);
                        b[k+j] = 0;
                }
        } else
                  b = strndup(p, k);

        free(cgroup);

        if (!b)
                return -ENOMEM;

        *unit = b;
        return 0;
}

_public_ int sd_pid_get_owner_uid(pid_t pid, uid_t *uid) {
        int r;
        char *root, *cgroup, *p, *cc;
        struct stat st;

        if (!uid)
                return -EINVAL;

        r = pid_get_cgroup(pid, &root, &cgroup);
        if (r < 0)
                return r;

        if (!startswith(cgroup, "/user/")) {
                free(cgroup);
                free(root);
                return -ENOENT;
        }

        p = strchr(cgroup + 6, '/');
        if (!p) {
                free(cgroup);
                return -ENOENT;
        }

        p++;
        p += strcspn(p, "/");
        *p = 0;

        r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, root, cgroup, &cc);
        free(root);
        free(cgroup);

        if (r < 0)
                return -ENOMEM;

        r = lstat(cc, &st);
        free(cc);

        if (r < 0)
                return -errno;

        if (!S_ISDIR(st.st_mode))
                return -ENOTDIR;

        *uid = st.st_uid;
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

_public_ int sd_uid_is_on_seat(uid_t uid, int require_active, const char *seat) {
        char *p, *w, *t, *state, *s = NULL;
        size_t l;
        int r;
        const char *variable;

        if (!seat)
                return -EINVAL;

        variable = require_active ? "ACTIVE_UID" : "UIDS";

        p = strappend("/run/systemd/seats/", seat);
        if (!p)
                return -ENOMEM;

        r = parse_env_file(p, NEWLINE, variable, &s, NULL);
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

static int uid_get_array(uid_t uid, const char *variable, char ***array) {
        char *p, *s = NULL;
        char **a;
        int r;

        if (asprintf(&p, "/run/systemd/users/%lu", (unsigned long) uid) < 0)
                return -ENOMEM;

        r = parse_env_file(p, NEWLINE,
                           variable, &s,
                           NULL);
        free(p);

        if (r < 0) {
                free(s);

                if (r == -ENOENT) {
                        if (array)
                                *array = NULL;
                        return 0;
                }

                return r;
        }

        if (!s) {
                if (array)
                        *array = NULL;
                return 0;
        }

        a = strv_split(s, " ");
        free(s);

        if (!a)
                return -ENOMEM;

        strv_uniq(a);
        r = strv_length(a);

        if (array)
                *array = a;
        else
                strv_free(a);

        return r;
}

_public_ int sd_uid_get_sessions(uid_t uid, int require_active, char ***sessions) {
        return uid_get_array(uid, require_active ? "ACTIVE_SESSIONS" : "SESSIONS", sessions);
}

_public_ int sd_uid_get_seats(uid_t uid, int require_active, char ***seats) {
        return uid_get_array(uid, require_active ? "ACTIVE_SEATS" : "SEATS", seats);
}

static int file_of_session(const char *session, char **_p) {
        char *p;
        int r;

        assert(_p);

        if (session)
                p = strappend("/run/systemd/sessions/", session);
        else {
                char *buf;

                r = sd_pid_get_session(0, &buf);
                if (r < 0)
                        return r;

                p = strappend("/run/systemd/sessions/", buf);
                free(buf);
        }

        if (!p)
                return -ENOMEM;

        *_p = p;
        return 0;
}

_public_ int sd_session_is_active(const char *session) {
        int r;
        char *p, *s = NULL;

        r = file_of_session(session, &p);
        if (r < 0)
                return r;

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

        if (!uid)
                return -EINVAL;

        r = file_of_session(session, &p);
        if (r < 0)
                return r;

        r = parse_env_file(p, NEWLINE, "UID", &s, NULL);
        free(p);

        if (r < 0) {
                free(s);
                return r;
        }

        if (!s)
                return -EIO;

        r = parse_uid(s, uid);
        free(s);

        return r;
}

static int session_get_string(const char *session, const char *field, char **value) {
        char *p, *s = NULL;
        int r;

        if (!value)
                return -EINVAL;

        r = file_of_session(session, &p);
        if (r < 0)
                return r;

        r = parse_env_file(p, NEWLINE, field, &s, NULL);
        free(p);

        if (r < 0) {
                free(s);
                return r;
        }

        if (isempty(s))
                return -ENOENT;

        *value = s;
        return 0;
}

_public_ int sd_session_get_seat(const char *session, char **seat) {
        return session_get_string(session, "SEAT", seat);
}

_public_ int sd_session_get_service(const char *session, char **service) {
        return session_get_string(session, "SERVICE", service);
}

_public_ int sd_session_get_type(const char *session, char **type) {
        return session_get_string(session, "TYPE", type);
}

_public_ int sd_session_get_class(const char *session, char **class) {
        return session_get_string(session, "CLASS", class);
}

_public_ int sd_session_get_display(const char *session, char **display) {
        return session_get_string(session, "DISPLAY", display);
}

static int file_of_seat(const char *seat, char **_p) {
        char *p;
        int r;

        assert(_p);

        if (seat)
                p = strappend("/run/systemd/seats/", seat);
        else {
                char *buf;

                r = sd_session_get_seat(NULL, &buf);
                if (r < 0)
                        return r;

                p = strappend("/run/systemd/seats/", buf);
                free(buf);
        }

        if (!p)
                return -ENOMEM;

        *_p = p;
        return 0;
}

_public_ int sd_seat_get_active(const char *seat, char **session, uid_t *uid) {
        char *p, *s = NULL, *t = NULL;
        int r;

        if (!session && !uid)
                return -EINVAL;

        r = file_of_seat(seat, &p);
        if (r < 0)
                return r;

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
                return -ENOENT;
        }

        if (uid && !t) {
                free(s);
                return -ENOENT;
        }

        if (uid && t) {
                r = parse_uid(t, uid);
                if (r < 0) {
                        free(t);
                        free(s);
                        return r;
                }
        }

        free(t);

        if (session && s)
                *session = s;
        else
                free(s);

        return 0;
}

_public_ int sd_seat_get_sessions(const char *seat, char ***sessions, uid_t **uids, unsigned *n_uids) {
        char *p, *s = NULL, *t = NULL, **a = NULL;
        uid_t *b = NULL;
        unsigned n = 0;
        int r;

        r = file_of_seat(seat, &p);
        if (r < 0)
                return r;

        r = parse_env_file(p, NEWLINE,
                           "SESSIONS", &s,
                           "ACTIVE_SESSIONS", &t,
                           NULL);
        free(p);

        if (r < 0) {
                free(s);
                free(t);
                return r;
        }

        if (s) {
                a = strv_split(s, " ");
                if (!a) {
                        free(s);
                        free(t);
                        return -ENOMEM;
                }
        }

        free(s);

        if (uids && t) {
                char *w, *state;
                size_t l;

                FOREACH_WORD(w, l, t, state)
                        n++;

                if (n == 0)
                        b = NULL;
                else {
                        unsigned i = 0;

                        b = new(uid_t, n);
                        if (!b) {
                                strv_free(a);
                                return -ENOMEM;
                        }

                        FOREACH_WORD(w, l, t, state) {
                                char *k;

                                k = strndup(w, l);
                                if (!k) {
                                        free(t);
                                        free(b);
                                        strv_free(a);
                                        return -ENOMEM;
                                }

                                r = parse_uid(k, b + i);
                                free(k);
                                if (r < 0)
                                        continue;

                                i++;
                        }
                }
        }

        free(t);

        r = strv_length(a);

        if (sessions)
                *sessions = a;
        else
                strv_free(a);

        if (uids)
                *uids = b;

        if (n_uids)
                *n_uids = n;

        return r;
}

_public_ int sd_seat_can_multi_session(const char *seat) {
        char *p, *s = NULL;
        int r;

        r = file_of_seat(seat, &p);
        if (r < 0)
                return r;

        r = parse_env_file(p, NEWLINE,
                           "CAN_MULTI_SESSION", &s,
                           NULL);
        free(p);

        if (r < 0) {
                free(s);
                return r;
        }

        if (s) {
                r = parse_boolean(s);
                free(s);
        } else
                r = 0;

        return r;
}

_public_ int sd_get_seats(char ***seats) {
        return get_files_in_directory("/run/systemd/seats/", seats);
}

_public_ int sd_get_sessions(char ***sessions) {
        return get_files_in_directory("/run/systemd/sessions/", sessions);
}

_public_ int sd_get_uids(uid_t **users) {
        DIR *d;
        int r = 0;
        unsigned n = 0;
        uid_t *l = NULL;

        d = opendir("/run/systemd/users/");
        if (!d)
                return -errno;

        for (;;) {
                struct dirent buffer, *de;
                int k;
                uid_t uid;

                k = readdir_r(d, &buffer, &de);
                if (k != 0) {
                        r = -k;
                        goto finish;
                }

                if (!de)
                        break;

                dirent_ensure_type(d, de);

                if (!dirent_is_file(de))
                        continue;

                k = parse_uid(de->d_name, &uid);
                if (k < 0)
                        continue;

                if (users) {
                        if ((unsigned) r >= n) {
                                uid_t *t;

                                n = MAX(16, 2*r);
                                t = realloc(l, sizeof(uid_t) * n);
                                if (!t) {
                                        r = -ENOMEM;
                                        goto finish;
                                }

                                l = t;
                        }

                        assert((unsigned) r < n);
                        l[r++] = uid;
                } else
                        r++;
        }

finish:
        if (d)
                closedir(d);

        if (r >= 0) {
                if (users)
                        *users = l;
        } else
                free(l);

        return r;
}

static inline int MONITOR_TO_FD(sd_login_monitor *m) {
        return (int) (unsigned long) m - 1;
}

static inline sd_login_monitor* FD_TO_MONITOR(int fd) {
        return (sd_login_monitor*) (unsigned long) (fd + 1);
}

_public_ int sd_login_monitor_new(const char *category, sd_login_monitor **m) {
        int fd, k;
        bool good = false;

        if (!m)
                return -EINVAL;

        fd = inotify_init1(IN_NONBLOCK|IN_CLOEXEC);
        if (fd < 0)
                return errno;

        if (!category || streq(category, "seat")) {
                k = inotify_add_watch(fd, "/run/systemd/seats/", IN_MOVED_TO|IN_DELETE);
                if (k < 0) {
                        close_nointr_nofail(fd);
                        return -errno;
                }

                good = true;
        }

        if (!category || streq(category, "session")) {
                k = inotify_add_watch(fd, "/run/systemd/sessions/", IN_MOVED_TO|IN_DELETE);
                if (k < 0) {
                        close_nointr_nofail(fd);
                        return -errno;
                }

                good = true;
        }

        if (!category || streq(category, "uid")) {
                k = inotify_add_watch(fd, "/run/systemd/users/", IN_MOVED_TO|IN_DELETE);
                if (k < 0) {
                        close_nointr_nofail(fd);
                        return -errno;
                }

                good = true;
        }

        if (!good) {
                close_nointr(fd);
                return -EINVAL;
        }

        *m = FD_TO_MONITOR(fd);
        return 0;
}

_public_ sd_login_monitor* sd_login_monitor_unref(sd_login_monitor *m) {
        int fd;

        if (!m)
                return NULL;

        fd = MONITOR_TO_FD(m);
        close_nointr(fd);

        return NULL;
}

_public_ int sd_login_monitor_flush(sd_login_monitor *m) {

        if (!m)
                return -EINVAL;

        return flush_fd(MONITOR_TO_FD(m));
}

_public_ int sd_login_monitor_get_fd(sd_login_monitor *m) {

        if (!m)
                return -EINVAL;

        return MONITOR_TO_FD(m);
}
