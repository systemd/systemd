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

#include <sys/mount.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "util.h"
#include "mkdir.h"
#include "rm-rf.h"
#include "hashmap.h"
#include "fileio.h"
#include "path-util.h"
#include "special.h"
#include "unit-name.h"
#include "bus-util.h"
#include "bus-error.h"
#include "conf-parser.h"
#include "clean-ipc.h"
#include "logind-user.h"
#include "smack-util.h"
#include "formats-util.h"

User* user_new(Manager *m, uid_t uid, gid_t gid, const char *name) {
        User *u;

        assert(m);
        assert(name);

        u = new0(User, 1);
        if (!u)
                return NULL;

        u->name = strdup(name);
        if (!u->name)
                goto fail;

        if (asprintf(&u->state_file, "/run/systemd/users/"UID_FMT, uid) < 0)
                goto fail;

        if (hashmap_put(m->users, UID_TO_PTR(uid), u) < 0)
                goto fail;

        u->manager = m;
        u->uid = uid;
        u->gid = gid;

        return u;

fail:
        free(u->state_file);
        free(u->name);
        free(u);

        return NULL;
}

void user_free(User *u) {
        assert(u);

        if (u->in_gc_queue)
                LIST_REMOVE(gc_queue, u->manager->user_gc_queue, u);

        while (u->sessions)
                session_free(u->sessions);

        if (u->slice) {
                hashmap_remove(u->manager->user_units, u->slice);
                free(u->slice);
        }

        if (u->service) {
                hashmap_remove(u->manager->user_units, u->service);
                free(u->service);
        }

        free(u->slice_job);
        free(u->service_job);

        free(u->runtime_path);

        hashmap_remove(u->manager->users, UID_TO_PTR(u->uid));

        free(u->name);
        free(u->state_file);
        free(u);
}

int user_save(User *u) {
        _cleanup_free_ char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(u);
        assert(u->state_file);

        if (!u->started)
                return 0;

        r = mkdir_safe_label("/run/systemd/users", 0755, 0, 0);
        if (r < 0)
                goto finish;

        r = fopen_temporary(u->state_file, &f, &temp_path);
        if (r < 0)
                goto finish;

        fchmod(fileno(f), 0644);

        fprintf(f,
                "# This is private data. Do not parse.\n"
                "NAME=%s\n"
                "STATE=%s\n",
                u->name,
                user_state_to_string(user_get_state(u)));

        if (u->runtime_path)
                fprintf(f, "RUNTIME=%s\n", u->runtime_path);

        if (u->service)
                fprintf(f, "SERVICE=%s\n", u->service);
        if (u->service_job)
                fprintf(f, "SERVICE_JOB=%s\n", u->service_job);

        if (u->slice)
                fprintf(f, "SLICE=%s\n", u->slice);
        if (u->slice_job)
                fprintf(f, "SLICE_JOB=%s\n", u->slice_job);

        if (u->display)
                fprintf(f, "DISPLAY=%s\n", u->display->id);

        if (dual_timestamp_is_set(&u->timestamp))
                fprintf(f,
                        "REALTIME="USEC_FMT"\n"
                        "MONOTONIC="USEC_FMT"\n",
                        u->timestamp.realtime,
                        u->timestamp.monotonic);

        if (u->sessions) {
                Session *i;
                bool first;

                fputs("SESSIONS=", f);
                first = true;
                LIST_FOREACH(sessions_by_user, i, u->sessions) {
                        if (first)
                                first = false;
                        else
                                fputc(' ', f);

                        fputs(i->id, f);
                }

                fputs("\nSEATS=", f);
                first = true;
                LIST_FOREACH(sessions_by_user, i, u->sessions) {
                        if (!i->seat)
                                continue;

                        if (first)
                                first = false;
                        else
                                fputc(' ', f);

                        fputs(i->seat->id, f);
                }

                fputs("\nACTIVE_SESSIONS=", f);
                first = true;
                LIST_FOREACH(sessions_by_user, i, u->sessions) {
                        if (!session_is_active(i))
                                continue;

                        if (first)
                                first = false;
                        else
                                fputc(' ', f);

                        fputs(i->id, f);
                }

                fputs("\nONLINE_SESSIONS=", f);
                first = true;
                LIST_FOREACH(sessions_by_user, i, u->sessions) {
                        if (session_get_state(i) == SESSION_CLOSING)
                                continue;

                        if (first)
                                first = false;
                        else
                                fputc(' ', f);

                        fputs(i->id, f);
                }

                fputs("\nACTIVE_SEATS=", f);
                first = true;
                LIST_FOREACH(sessions_by_user, i, u->sessions) {
                        if (!session_is_active(i) || !i->seat)
                                continue;

                        if (first)
                                first = false;
                        else
                                fputc(' ', f);

                        fputs(i->seat->id, f);
                }

                fputs("\nONLINE_SEATS=", f);
                first = true;
                LIST_FOREACH(sessions_by_user, i, u->sessions) {
                        if (session_get_state(i) == SESSION_CLOSING || !i->seat)
                                continue;

                        if (first)
                                first = false;
                        else
                                fputc(' ', f);

                        fputs(i->seat->id, f);
                }
                fputc('\n', f);
        }

        fflush(f);

        if (ferror(f) || rename(temp_path, u->state_file) < 0) {
                r = -errno;
                unlink(u->state_file);
                unlink(temp_path);
        }

finish:
        if (r < 0)
                log_error_errno(r, "Failed to save user data %s: %m", u->state_file);

        return r;
}

int user_load(User *u) {
        _cleanup_free_ char *display = NULL, *realtime = NULL, *monotonic = NULL;
        Session *s = NULL;
        int r;

        assert(u);

        r = parse_env_file(u->state_file, NEWLINE,
                           "RUNTIME",     &u->runtime_path,
                           "SERVICE",     &u->service,
                           "SERVICE_JOB", &u->service_job,
                           "SLICE",       &u->slice,
                           "SLICE_JOB",   &u->slice_job,
                           "DISPLAY",     &display,
                           "REALTIME",    &realtime,
                           "MONOTONIC",   &monotonic,
                           NULL);
        if (r < 0) {
                if (r == -ENOENT)
                        return 0;

                log_error_errno(r, "Failed to read %s: %m", u->state_file);
                return r;
        }

        if (display)
                s = hashmap_get(u->manager->sessions, display);

        if (s && s->display && display_is_local(s->display))
                u->display = s;

        if (realtime) {
                unsigned long long l;
                if (sscanf(realtime, "%llu", &l) > 0)
                        u->timestamp.realtime = l;
        }

        if (monotonic) {
                unsigned long long l;
                if (sscanf(monotonic, "%llu", &l) > 0)
                        u->timestamp.monotonic = l;
        }

        return r;
}

static int user_mkdir_runtime_path(User *u) {
        char *p;
        int r;

        assert(u);

        r = mkdir_safe_label("/run/user", 0755, 0, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to create /run/user: %m");

        if (!u->runtime_path) {
                if (asprintf(&p, "/run/user/" UID_FMT, u->uid) < 0)
                        return log_oom();
        } else
                p = u->runtime_path;

        if (path_is_mount_point(p, false) <= 0) {
                _cleanup_free_ char *t = NULL;

                (void) mkdir(p, 0700);

                if (mac_smack_use())
                        r = asprintf(&t, "mode=0700,smackfsroot=*,uid=" UID_FMT ",gid=" GID_FMT ",size=%zu", u->uid, u->gid, u->manager->runtime_dir_size);
                else
                        r = asprintf(&t, "mode=0700,uid=" UID_FMT ",gid=" GID_FMT ",size=%zu", u->uid, u->gid, u->manager->runtime_dir_size);
                if (r < 0) {
                        r = log_oom();
                        goto fail;
                }

                r = mount("tmpfs", p, "tmpfs", MS_NODEV|MS_NOSUID, t);
                if (r < 0) {
                        if (errno != EPERM) {
                                r = log_error_errno(errno, "Failed to mount per-user tmpfs directory %s: %m", p);
                                goto fail;
                        }

                        /* Lacking permissions, maybe
                         * CAP_SYS_ADMIN-less container? In this case,
                         * just use a normal directory. */

                        r = chmod_and_chown(p, 0700, u->uid, u->gid);
                        if (r < 0) {
                                log_error_errno(r, "Failed to change runtime directory ownership and mode: %m");
                                goto fail;
                        }
                }
        }

        u->runtime_path = p;
        return 0;

fail:
        if (p) {
                /* Try to clean up, but ignore errors */
                (void) rmdir(p);
                free(p);
        }

        u->runtime_path = NULL;
        return r;
}

static int user_start_slice(User *u) {
        char *job;
        int r;

        assert(u);

        if (!u->slice) {
                _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
                char lu[DECIMAL_STR_MAX(uid_t) + 1], *slice;
                sprintf(lu, UID_FMT, u->uid);

                r = slice_build_subslice(SPECIAL_USER_SLICE, lu, &slice);
                if (r < 0)
                        return r;

                r = manager_start_unit(u->manager, slice, &error, &job);
                if (r < 0) {
                        log_error("Failed to start user slice: %s", bus_error_message(&error, r));
                        free(slice);
                } else {
                        u->slice = slice;

                        free(u->slice_job);
                        u->slice_job = job;
                }
        }

        if (u->slice)
                hashmap_put(u->manager->user_units, u->slice, u);

        return 0;
}

static int user_start_service(User *u) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        char *job;
        int r;

        assert(u);

        if (!u->service) {
                char lu[DECIMAL_STR_MAX(uid_t) + 1], *service;
                sprintf(lu, UID_FMT, u->uid);

                r = unit_name_build("user", lu, ".service", &service);
                if (r < 0)
                        return log_error_errno(r, "Failed to build service name: %m");

                r = manager_start_unit(u->manager, service, &error, &job);
                if (r < 0) {
                        log_error("Failed to start user service: %s", bus_error_message(&error, r));
                        free(service);
                } else {
                        u->service = service;

                        free(u->service_job);
                        u->service_job = job;
                }
        }

        if (u->service)
                hashmap_put(u->manager->user_units, u->service, u);

        return 0;
}

int user_start(User *u) {
        int r;

        assert(u);

        if (u->started)
                return 0;

        log_debug("New user %s logged in.", u->name);

        /* Make XDG_RUNTIME_DIR */
        r = user_mkdir_runtime_path(u);
        if (r < 0)
                return r;

        /* Create cgroup */
        r = user_start_slice(u);
        if (r < 0)
                return r;

        /* Spawn user systemd */
        r = user_start_service(u);
        if (r < 0)
                return r;

        if (!dual_timestamp_is_set(&u->timestamp))
                dual_timestamp_get(&u->timestamp);

        u->started = true;

        /* Save new user data */
        user_save(u);

        user_send_signal(u, true);

        return 0;
}

static int user_stop_slice(User *u) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        char *job;
        int r;

        assert(u);

        if (!u->slice)
                return 0;

        r = manager_stop_unit(u->manager, u->slice, &error, &job);
        if (r < 0) {
                log_error("Failed to stop user slice: %s", bus_error_message(&error, r));
                return r;
        }

        free(u->slice_job);
        u->slice_job = job;

        return r;
}

static int user_stop_service(User *u) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        char *job;
        int r;

        assert(u);

        if (!u->service)
                return 0;

        r = manager_stop_unit(u->manager, u->service, &error, &job);
        if (r < 0) {
                log_error("Failed to stop user service: %s", bus_error_message(&error, r));
                return r;
        }

        free(u->service_job);
        u->service_job = job;

        return r;
}

static int user_remove_runtime_path(User *u) {
        int r;

        assert(u);

        if (!u->runtime_path)
                return 0;

        r = rm_rf(u->runtime_path, 0);
        if (r < 0)
                log_error_errno(r, "Failed to remove runtime directory %s: %m", u->runtime_path);

        /* Ignore cases where the directory isn't mounted, as that's
         * quite possible, if we lacked the permissions to mount
         * something */
        r = umount2(u->runtime_path, MNT_DETACH);
        if (r < 0 && errno != EINVAL && errno != ENOENT)
                log_error_errno(errno, "Failed to unmount user runtime directory %s: %m", u->runtime_path);

        r = rm_rf(u->runtime_path, REMOVE_ROOT);
        if (r < 0)
                log_error_errno(r, "Failed to remove runtime directory %s: %m", u->runtime_path);

        free(u->runtime_path);
        u->runtime_path = NULL;

        return r;
}

int user_stop(User *u, bool force) {
        Session *s;
        int r = 0, k;
        assert(u);

        /* Stop jobs have already been queued */
        if (u->stopping) {
                user_save(u);
                return r;
        }

        LIST_FOREACH(sessions_by_user, s, u->sessions) {
                k = session_stop(s, force);
                if (k < 0)
                        r = k;
        }

        /* Kill systemd */
        k = user_stop_service(u);
        if (k < 0)
                r = k;

        /* Kill cgroup */
        k = user_stop_slice(u);
        if (k < 0)
                r = k;

        u->stopping = true;

        user_save(u);

        return r;
}

int user_finalize(User *u) {
        Session *s;
        int r = 0, k;

        assert(u);

        if (u->started)
                log_debug("User %s logged out.", u->name);

        LIST_FOREACH(sessions_by_user, s, u->sessions) {
                k = session_finalize(s);
                if (k < 0)
                        r = k;
        }

        /* Kill XDG_RUNTIME_DIR */
        k = user_remove_runtime_path(u);
        if (k < 0)
                r = k;

        /* Clean SysV + POSIX IPC objects */
        if (u->manager->remove_ipc) {
                k = clean_ipc(u->uid);
                if (k < 0)
                        r = k;
        }

        unlink(u->state_file);
        user_add_to_gc_queue(u);

        if (u->started) {
                user_send_signal(u, false);
                u->started = false;
        }

        return r;
}

int user_get_idle_hint(User *u, dual_timestamp *t) {
        Session *s;
        bool idle_hint = true;
        dual_timestamp ts = { 0, 0 };

        assert(u);

        LIST_FOREACH(sessions_by_user, s, u->sessions) {
                dual_timestamp k;
                int ih;

                ih = session_get_idle_hint(s, &k);
                if (ih < 0)
                        return ih;

                if (!ih) {
                        if (!idle_hint) {
                                if (k.monotonic < ts.monotonic)
                                        ts = k;
                        } else {
                                idle_hint = false;
                                ts = k;
                        }
                } else if (idle_hint) {

                        if (k.monotonic > ts.monotonic)
                                ts = k;
                }
        }

        if (t)
                *t = ts;

        return idle_hint;
}

int user_check_linger_file(User *u) {
        _cleanup_free_ char *cc = NULL;
        char *p = NULL;

        cc = cescape(u->name);
        if (!cc)
                return -ENOMEM;

        p = strjoina("/var/lib/systemd/linger/", cc);

        return access(p, F_OK) >= 0;
}

bool user_check_gc(User *u, bool drop_not_started) {
        assert(u);

        if (drop_not_started && !u->started)
                return false;

        if (u->sessions)
                return true;

        if (user_check_linger_file(u) > 0)
                return true;

        if (u->slice_job && manager_job_is_active(u->manager, u->slice_job))
                return true;

        if (u->service_job && manager_job_is_active(u->manager, u->service_job))
                return true;

        return false;
}

void user_add_to_gc_queue(User *u) {
        assert(u);

        if (u->in_gc_queue)
                return;

        LIST_PREPEND(gc_queue, u->manager->user_gc_queue, u);
        u->in_gc_queue = true;
}

UserState user_get_state(User *u) {
        Session *i;

        assert(u);

        if (u->stopping)
                return USER_CLOSING;

        if (u->slice_job || u->service_job)
                return USER_OPENING;

        if (u->sessions) {
                bool all_closing = true;

                LIST_FOREACH(sessions_by_user, i, u->sessions) {
                        SessionState state;

                        state = session_get_state(i);
                        if (state == SESSION_ACTIVE)
                                return USER_ACTIVE;
                        if (state != SESSION_CLOSING)
                                all_closing = false;
                }

                return all_closing ? USER_CLOSING : USER_ONLINE;
        }

        if (user_check_linger_file(u) > 0)
                return USER_LINGERING;

        return USER_CLOSING;
}

int user_kill(User *u, int signo) {
        assert(u);

        if (!u->slice)
                return -ESRCH;

        return manager_kill_unit(u->manager, u->slice, KILL_ALL, signo, NULL);
}

void user_elect_display(User *u) {
        Session *graphical = NULL, *text = NULL, *other = NULL, *s;

        assert(u);

        /* This elects a primary session for each user, which we call
         * the "display". We try to keep the assignment stable, but we
         * "upgrade" to better choices. */

        LIST_FOREACH(sessions_by_user, s, u->sessions) {

                if (s->class != SESSION_USER)
                        continue;

                if (s->stopping)
                        continue;

                if (SESSION_TYPE_IS_GRAPHICAL(s->type))
                        graphical = s;
                else if (s->type == SESSION_TTY)
                        text = s;
                else
                        other = s;
        }

        if (graphical &&
            (!u->display ||
             u->display->class != SESSION_USER ||
             u->display->stopping ||
             !SESSION_TYPE_IS_GRAPHICAL(u->display->type))) {
                u->display = graphical;
                return;
        }

        if (text &&
            (!u->display ||
             u->display->class != SESSION_USER ||
             u->display->stopping ||
             u->display->type != SESSION_TTY)) {
                u->display = text;
                return;
        }

        if (other &&
            (!u->display ||
             u->display->class != SESSION_USER ||
             u->display->stopping))
                u->display = other;
}

static const char* const user_state_table[_USER_STATE_MAX] = {
        [USER_OFFLINE] = "offline",
        [USER_OPENING] = "opening",
        [USER_LINGERING] = "lingering",
        [USER_ONLINE] = "online",
        [USER_ACTIVE] = "active",
        [USER_CLOSING] = "closing"
};

DEFINE_STRING_TABLE_LOOKUP(user_state, UserState);

int config_parse_tmpfs_size(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        size_t *sz = data;
        const char *e;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        e = endswith(rvalue, "%");
        if (e) {
                unsigned long ul;
                char *f;

                errno = 0;
                ul = strtoul(rvalue, &f, 10);
                if (errno != 0 || f != e) {
                        log_syntax(unit, LOG_ERR, filename, line, errno ? errno : EINVAL, "Failed to parse percentage value, ignoring: %s", rvalue);
                        return 0;
                }

                if (ul <= 0 || ul >= 100) {
                        log_syntax(unit, LOG_ERR, filename, line, errno ? errno : EINVAL, "Percentage value out of range, ignoring: %s", rvalue);
                        return 0;
                }

                *sz = PAGE_ALIGN((size_t) ((physical_memory() * (uint64_t) ul) / (uint64_t) 100));
        } else {
                off_t o;

                r = parse_size(rvalue, 1024, &o);
                if (r < 0 || (off_t) (size_t) o != o) {
                        log_syntax(unit, LOG_ERR, filename, line, r < 0 ? -r : ERANGE, "Failed to parse size value, ignoring: %s", rvalue);
                        return 0;
                }

                *sz = PAGE_ALIGN((size_t) o);
        }

        return 0;
}
