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

#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "logind.h"
#include "util.h"
#include "cgroup-util.h"
#include "hashmap.h"
#include "strv.h"

User* user_new(Manager *m, uid_t uid, gid_t gid, const char *name) {
        User *u;

        assert(m);
        assert(name);

        u = new(User, 1);
        if (!u)
                return NULL;

        u->name = strdup(name);
        if (!u->name) {
                free(u);
                return NULL;
        }

        if (asprintf(&u->state_file, "/run/systemd/user/%lu", (unsigned long) uid) < 0) {
                free(u->name);
                free(u);
                return NULL;
        }

        if (hashmap_put(m->users, ULONG_TO_PTR((unsigned long) uid), u) < 0) {
                free(u->state_file);
                free(u->name);
                free(u);
                return NULL;
        }

        u->manager = m;
        u->uid = uid;
        u->gid = gid;

        return u;
}

void user_free(User *u) {
        assert(u);

        while (u->sessions)
                session_free(u->sessions);

        free(u->cgroup_path);

        free(u->service);
        free(u->runtime_path);

        hashmap_remove(u->manager->users, ULONG_TO_PTR((unsigned long) u->uid));

        free(u->name);
        free(u->state_file);
        free(u);
}

int user_save(User *u) {
        FILE *f;
        int r;

        assert(u);
        assert(u->state_file);

        r = safe_mkdir("/run/systemd/user", 0755, 0, 0);
        if (r < 0)
                return r;

        f = fopen(u->state_file, "we");
        if (!f)
                return -errno;

        fprintf(f,
                "NAME=%s\n"
                "STATE=%s\n",
                u->name,
                user_state_to_string(user_get_state(u)));

        if (u->cgroup_path)
                fprintf(f,
                        "CGROUP=%s\n",
                        u->cgroup_path);

        if (u->runtime_path)
                fprintf(f,
                        "RUNTIME=%s\n",
                        u->runtime_path);

        if (u->service)
                fprintf(f,
                        "SERVICE=%s\n",
                        u->service);

        if (u->display)
                fprintf(f,
                        "DISPLAY=%s\n",
                        u->display->id);

        fflush(f);
        if (ferror(f)) {
                r = -errno;
                unlink(u->state_file);
        }

        fclose(f);
        return r;
}

int user_load(User *u) {
        int r;
        char *display = NULL;
        Session *s;

        assert(u);

        r = parse_env_file(u->state_file, "r",
                           "CGROUP", &u->cgroup_path,
                           "RUNTIME", &u->runtime_path,
                           "SERVICE", &u->service,
                           "DISPLAY", &display,
                           NULL);
        if (r < 0) {
                free(display);

                if (r == -ENOENT)
                        return 0;

                log_error("Failed to read %s: %s", u->state_file, strerror(-r));
                return r;
        }

        s = hashmap_get(u->manager->sessions, display);
        free(display);

        if (s && s->display && x11_display_is_local(s->display))
                u->display = s;

        return r;
}

static int user_mkdir_runtime_path(User *u) {
        char *p;
        int r;

        assert(u);

        r = safe_mkdir("/run/user", 0755, 0, 0);
        if (r < 0) {
                log_error("Failed to create /run/user: %s", strerror(-r));
                return r;
        }

        if (!u->runtime_path) {
                p = strappend("/run/user/", u->name);

                if (!p) {
                        log_error("Out of memory");
                        return -ENOMEM;
                }
        } else
                p = u->runtime_path;

        r = safe_mkdir(p, 0700, u->uid, u->gid);
        if (r < 0) {
                log_error("Failed to create runtime directory %s: %s", p, strerror(-r));
                free(p);
                u->runtime_path = NULL;
                return r;
        }

        u->runtime_path = p;
        return 0;
}

static int user_create_cgroup(User *u) {
        char **k;
        char *p;
        int r;

        assert(u);

        if (!u->cgroup_path) {
                if (asprintf(&p, "%s/%s", u->manager->cgroup_path, u->name) < 0) {
                        log_error("Out of memory");
                        return -ENOMEM;
                }
        } else
                p = u->cgroup_path;

        r = cg_create(SYSTEMD_CGROUP_CONTROLLER, p);
        if (r < 0) {
                free(p);
                u->cgroup_path = NULL;
                log_error("Failed to create cgroup "SYSTEMD_CGROUP_CONTROLLER":%s: %s", p, strerror(-r));
                return r;
        }

        u->cgroup_path = p;

        STRV_FOREACH(k, u->manager->controllers) {
                r = cg_create(*k, p);
                if (r < 0)
                        log_warning("Failed to create cgroup %s:%s: %s", *k, p, strerror(-r));
        }

        return 0;
}

static int user_start_service(User *u) {
        assert(u);

        return 0;
}

int user_start(User *u) {
        int r;

        assert(u);

        /* Make XDG_RUNTIME_DIR */
        r = user_mkdir_runtime_path(u);
        if (r < 0)
                return r;

        /* Create cgroup */
        r = user_create_cgroup(u);
        if (r < 0)
                return r;

        /* Spawn user systemd */
        r = user_start_service(u);
        if (r < 0)
                return r;

        dual_timestamp_get(&u->timestamp);

        return 0;
}

static int user_stop_service(User *u) {
        assert(u);

        if (!u->service)
                return 0;

        return 0;
}

static int user_shall_kill(User *u) {
        assert(u);

        return u->manager->kill_user_processes;
}

static int user_kill_cgroup(User *u) {
        int r;
        char **k;

        assert(u);

        if (!u->cgroup_path)
                return 0;

        cg_trim(SYSTEMD_CGROUP_CONTROLLER, u->cgroup_path, false);

        if (user_shall_kill(u)) {

                r = cg_kill_recursive_and_wait(SYSTEMD_CGROUP_CONTROLLER, u->cgroup_path, true);
                if (r < 0)
                        log_error("Failed to kill user cgroup: %s", strerror(-r));
        } else {

                r = cg_is_empty_recursive(SYSTEMD_CGROUP_CONTROLLER, u->cgroup_path, true);
                if (r < 0)
                        log_error("Failed to check user cgroup: %s", strerror(-r));
                else if (r > 0) {
                        r = cg_delete(SYSTEMD_CGROUP_CONTROLLER, u->cgroup_path);
                        if (r < 0)
                                log_error("Failed to delete user cgroup: %s", strerror(-r));
                } else
                        r = -EBUSY;
        }

        STRV_FOREACH(k, u->manager->controllers)
                cg_trim(*k, u->cgroup_path, true);

        free(u->cgroup_path);
        u->cgroup_path = NULL;

        return r;
}

static int user_remove_runtime_path(User *u) {
        int r;

        assert(u);

        if (!u->runtime_path)
                return 0;

        r = rm_rf(u->runtime_path, false, true);
        if (r < 0)
                log_error("Failed to remove runtime directory %s: %s", u->runtime_path, strerror(-r));

        free(u->runtime_path);
        u->runtime_path = NULL;

        return r;
}

int user_stop(User *u) {
        Session *s;
        int r = 0, k;
        assert(u);

        LIST_FOREACH(sessions_by_user, s, u->sessions) {
                k = session_stop(s);
                if (k < 0)
                        r = k;
        }

        /* Kill systemd */
        k = user_stop_service(u);
        if (k < 0)
                r = k;

        /* Kill cgroup */
        k = user_kill_cgroup(u);
        if (k < 0)
                r = k;

        /* Kill XDG_RUNTIME_DIR */
        k = user_remove_runtime_path(u);
        if (k < 0)
                r = k;

        return r;
}

int user_check_gc(User *u) {
        int r;
        char *p;

        assert(u);

        if (u->sessions)
                return 1;

        if (asprintf(&p, "/var/lib/systemd/linger/%s", u->name) < 0)
                return -ENOMEM;

        r = access(p, F_OK) >= 0;
        free(p);

        if (r > 0)
                return 1;

        if (u->cgroup_path) {
                r = cg_is_empty_recursive(SYSTEMD_CGROUP_CONTROLLER, u->cgroup_path, false);
                if (r < 0)
                        return r;

                if (r <= 0)
                        return 1;
        }

        return 0;
}

UserState user_get_state(User *u) {
        Session *i;

        assert(u);

        if (!u->sessions)
                return USER_LINGERING;

        LIST_FOREACH(sessions_by_user, i, u->sessions)
                if (session_is_active(i))
                        return USER_ACTIVE;

        return USER_ONLINE;
}

static const char* const user_state_table[_USER_STATE_MAX] = {
        [USER_OFFLINE] = "offline",
        [USER_LINGERING] = "lingering",
        [USER_ONLINE] = "online",
        [USER_ACTIVE] = "active"
};

DEFINE_STRING_TABLE_LOOKUP(user_state, UserState);
