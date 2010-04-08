/*-*- Mode: C; c-basic-offset: 8 -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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
#include <signal.h>
#include <dirent.h>
#include <unistd.h>

#include "unit.h"
#include "service.h"
#include "load-fragment.h"
#include "load-dropin.h"
#include "log.h"
#include "strv.h"

#define COMMENTS "#;\n"
#define NEWLINES "\n\r"
#define LINE_MAX 4096

static const char * const rcnd_table[] = {
        "/rc0.d",  SPECIAL_RUNLEVEL0_TARGET,
        "/rc1.d",  SPECIAL_RUNLEVEL1_TARGET,
        "/rc2.d",  SPECIAL_RUNLEVEL2_TARGET,
        "/rc3.d",  SPECIAL_RUNLEVEL3_TARGET,
        "/rc4.d",  SPECIAL_RUNLEVEL4_TARGET,
        "/rc5.d",  SPECIAL_RUNLEVEL5_TARGET,
        "/rc6.d",  SPECIAL_RUNLEVEL6_TARGET,
        "/boot.d", SPECIAL_BASIC_TARGET
};

static const UnitActiveState state_translation_table[_SERVICE_STATE_MAX] = {
        [SERVICE_DEAD] = UNIT_INACTIVE,
        [SERVICE_START_PRE] = UNIT_ACTIVATING,
        [SERVICE_START] = UNIT_ACTIVATING,
        [SERVICE_START_POST] = UNIT_ACTIVATING,
        [SERVICE_RUNNING] = UNIT_ACTIVE,
        [SERVICE_RELOAD] = UNIT_ACTIVE_RELOADING,
        [SERVICE_STOP] = UNIT_DEACTIVATING,
        [SERVICE_STOP_SIGTERM] = UNIT_DEACTIVATING,
        [SERVICE_STOP_SIGKILL] = UNIT_DEACTIVATING,
        [SERVICE_STOP_POST] = UNIT_DEACTIVATING,
        [SERVICE_FINAL_SIGTERM] = UNIT_DEACTIVATING,
        [SERVICE_FINAL_SIGKILL] = UNIT_DEACTIVATING,
        [SERVICE_MAINTAINANCE] = UNIT_INACTIVE,
        [SERVICE_AUTO_RESTART] = UNIT_ACTIVATING,
};

static void service_done(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        free(s->pid_file);
        s->pid_file = NULL;

        free(s->sysv_path);
        s->sysv_path = NULL;

        free(s->sysv_runlevels);
        s->sysv_runlevels = NULL;

        exec_context_done(&s->exec_context);
        exec_command_free_array(s->exec_command, _SERVICE_EXEC_MAX);
        s->control_command = NULL;

        /* This will leak a process, but at least no memory or any of
         * our resources */
        if (s->main_pid > 0) {
                unit_unwatch_pid(u, s->main_pid);
                s->main_pid = 0;
        }

        if (s->control_pid > 0) {
                unit_unwatch_pid(u, s->control_pid);
                s->control_pid = 0;
        }

        unit_unwatch_timer(u, &s->timer_watch);
}

static int sysv_translate_name(const char *name, char **_r) {

        static const char * const table[] = {
                "$local_fs",  SPECIAL_LOCAL_FS_TARGET,
                "$network",   SPECIAL_NETWORK_TARGET,
                "$named",     SPECIAL_NSS_LOOKUP_TARGET,
                "$portmap",   SPECIAL_RPCBIND_TARGET,
                "$remote_fs", SPECIAL_REMOTE_FS_TARGET,
                "$syslog",    SPECIAL_SYSLOG_TARGET,
                "$time",      SPECIAL_RTC_SET_TARGET
        };

        unsigned i;
        char *r;

        for (i = 0; i < ELEMENTSOF(table); i += 2)
                if (streq(table[i], name)) {
                        if (!(r = strdup(table[i+1])))
                                return -ENOMEM;

                        goto finish;
                }

        if (*name == '$')
                return 0;

        if (asprintf(&r, "%s.service", name) < 0)
                return -ENOMEM;

finish:

        if (_r)
                *_r = r;

        return 1;
}

static int sysv_chkconfig_order(Service *s) {
        Meta *other;
        int r;

        assert(s);

        if (s->sysv_start_priority < 0)
                return 0;

        /* For each pair of services where at least one lacks a LSB
         * header, we use the start priority value to order things. */

        LIST_FOREACH(units_per_type, other, UNIT(s)->meta.manager->units_per_type[UNIT_SERVICE]) {
                Service *t;
                UnitDependency d;

                t = (Service*) other;

                if (s == t)
                        continue;

                if (t->sysv_start_priority < 0)
                        continue;

                if (s->sysv_has_lsb && t->sysv_has_lsb)
                        continue;

                if (t->sysv_start_priority < s->sysv_start_priority)
                        d = UNIT_AFTER;
                else if (t->sysv_start_priority > s->sysv_start_priority)
                        d = UNIT_BEFORE;
                else
                        continue;

                /* FIXME: Maybe we should compare the name here lexicographically? */

                if (!(r = unit_add_dependency(UNIT(s), d, UNIT(t))) < 0)
                        return r;
        }

        return 0;
}

static ExecCommand *exec_command_new(const char *path, const char *arg1) {
        ExecCommand *c;

        if (!(c = new0(ExecCommand, 1)))
                return NULL;

        if (!(c->path = strdup(path))) {
                free(c);
                return NULL;
        }

        if (!(c->argv = strv_new(path, arg1, NULL))) {
                free(c->path);
                free(c);
                return NULL;
        }

        return c;
}

static int sysv_exec_commands(Service *s) {
        ExecCommand *c;

        assert(s);
        assert(s->sysv_path);

        if (!(c = exec_command_new(s->sysv_path, "start")))
                return -ENOMEM;
        exec_command_append_list(s->exec_command+SERVICE_EXEC_START, c);

        if (!(c = exec_command_new(s->sysv_path, "stop")))
                return -ENOMEM;
        exec_command_append_list(s->exec_command+SERVICE_EXEC_STOP, c);

        if (!(c = exec_command_new(s->sysv_path, "reload")))
                return -ENOMEM;
        exec_command_append_list(s->exec_command+SERVICE_EXEC_RELOAD, c);

        return 0;
}

static int priority_from_rcd(Service *s, const char *init_script) {
        char **p;
        unsigned i;

        STRV_FOREACH(p, UNIT(s)->meta.manager->sysvrcnd_path)
                for (i = 0; i < ELEMENTSOF(rcnd_table); i += 2) {
                        char *path;
                        DIR *d;
                        struct dirent *de;

                        if (asprintf(&path, "%s/%s", *p, rcnd_table[i]) < 0)
                                return -ENOMEM;

                        d = opendir(path);
                        free(path);

                        if (!d) {
                                if (errno != ENOENT)
                                        log_warning("opendir() failed on %s: %s", path, strerror(errno));

                                continue;
                        }

                        while ((de = readdir(d))) {
                                int a, b;

                                if (ignore_file(de->d_name))
                                        continue;

                                if (de->d_name[0] != 'S')
                                        continue;

                                if (strlen(de->d_name) < 4)
                                        continue;

                                if (!streq(de->d_name + 3, init_script))
                                        continue;

                                /* Yay, we found it! Now decode the priority */

                                a = undecchar(de->d_name[1]);
                                b = undecchar(de->d_name[2]);

                                if (a < 0 || b < 0)
                                        continue;

                                s->sysv_start_priority = a*10 + b;

                                log_debug("Determined priority %i from link farm for %s", s->sysv_start_priority, unit_id(UNIT(s)));

                                closedir(d);
                                return 0;
                        }

                        closedir(d);
                }

        return 0;
}

static int service_load_sysv_path(Service *s, const char *path, UnitLoadState *new_state) {
        FILE *f;
        Unit *u;
        unsigned line = 0;
        int r;
        enum {
                NORMAL,
                DESCRIPTION,
                LSB,
                LSB_DESCRIPTION
        } state = NORMAL;

        assert(s);
        assert(path);
        assert(new_state);

        u = UNIT(s);

        if (!(f = fopen(path, "re"))) {
                r = errno == ENOENT ? 0 : -errno;
                goto finish;
        }

        s->type = SERVICE_FORKING;
        s->restart = SERVICE_ONCE;

        free(s->sysv_path);
        if (!(s->sysv_path = strdup(path))) {
                r = -ENOMEM;
                goto finish;
        }

        while (!feof(f)) {
                char l[LINE_MAX], *t;

                if (!fgets(l, sizeof(l), f)) {
                        if (feof(f))
                                break;

                        r = -errno;
                        log_error("Failed to read configuration file '%s': %s", path, strerror(-r));
                        goto finish;
                }

                line++;

                t = strstrip(l);
                if (*t != '#')
                        continue;

                if (state == NORMAL && streq(t, "### BEGIN INIT INFO")) {
                        state = LSB;
                        s->sysv_has_lsb = true;
                        continue;
                }

                if ((state == LSB_DESCRIPTION || state == LSB) && streq(t, "### END INIT INFO")) {
                        state = NORMAL;
                        continue;
                }

                t++;
                t += strspn(t, WHITESPACE);

                if (state == NORMAL) {

                        /* Try to parse Red Hat style chkconfig headers */

                        if (startswith(t, "chkconfig:")) {
                                int start_priority;
                                char runlevels[16], *k;

                                state = NORMAL;

                                if (sscanf(t+10, "%15s %i %*i",
                                           runlevels,
                                           &start_priority) != 2) {

                                        log_warning("[%s:%u] Failed to parse chkconfig line. Ignoring.", path, line);
                                        continue;
                                }

                                if (start_priority < 0 || start_priority > 99)
                                        log_warning("[%s:%u] Start priority out of range. Ignoring.", path, line);
                                else
                                        s->sysv_start_priority = start_priority;

                                char_array_0(runlevels);
                                k = delete_chars(runlevels, WHITESPACE "-");

                                if (k[0]) {
                                        char *d;

                                        if (!(d = strdup(k))) {
                                                r = -ENOMEM;
                                                goto finish;
                                        }

                                        free(s->sysv_runlevels);
                                        s->sysv_runlevels = d;
                                }


                        } else if (startswith(t, "description:")) {

                                size_t k = strlen(t);
                                char *d;

                                if (t[k-1] == '\\') {
                                        state = DESCRIPTION;
                                        t[k-1] = 0;
                                }

                                if (!(d = strdup(strstrip(t+12)))) {
                                        r = -ENOMEM;
                                        goto finish;
                                }

                                free(u->meta.description);
                                u->meta.description = d;

                        } else if (startswith(t, "pidfile:")) {

                                char *fn;

                                state = NORMAL;

                                fn = strstrip(t+8);
                                if (!path_is_absolute(fn)) {
                                        log_warning("[%s:%u] PID file not absolute. Ignoring.", path, line);
                                        continue;
                                }

                                if (!(fn = strdup(fn))) {
                                        r = -ENOMEM;
                                        goto finish;
                                }

                                free(s->pid_file);
                                s->pid_file = fn;
                        }

                } else if (state == DESCRIPTION) {

                        /* Try to parse Red Hat style description
                         * continuation */

                        size_t k = strlen(t);
                        char *d;

                        if (t[k-1] == '\\')
                                t[k-1] = 0;
                        else
                                state = NORMAL;

                        assert(u->meta.description);
                        if (asprintf(&d, "%s %s", u->meta.description, strstrip(t)) < 0) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        free(u->meta.description);
                        u->meta.description = d;

                } else if (state == LSB || state == LSB_DESCRIPTION) {

                        if (startswith(t, "Provides:")) {
                                char *i, *w;
                                size_t z;

                                state = LSB;

                                FOREACH_WORD(w, z, t+9, i) {
                                        char *n, *m;

                                        if (!(n = strndup(w, z))) {
                                                r = -ENOMEM;
                                                goto finish;
                                        }

                                        r = sysv_translate_name(n, &m);
                                        free(n);

                                        if (r < 0)
                                                goto finish;

                                        if (r == 0)
                                                continue;

                                        if (unit_name_to_type(m) == UNIT_SERVICE)
                                                r = unit_add_name(u, m);
                                        else {
                                                if ((r = unit_add_dependency_by_name_inverse(u, UNIT_REQUIRES, m)) >= 0)
                                                        r = unit_add_dependency_by_name(u, UNIT_BEFORE, m);
                                        }

                                        free(m);

                                        if (r < 0)
                                                goto finish;
                                }

                        } else if (startswith(t, "Required-Start:") ||
                                   startswith(t, "Should-Start:")) {
                                char *i, *w;
                                size_t z;

                                state = LSB;

                                FOREACH_WORD(w, z, strchr(t, ':')+1, i) {
                                        char *n, *m;

                                        if (!(n = strndup(w, z))) {
                                                r = -ENOMEM;
                                                goto finish;
                                        }

                                        r = sysv_translate_name(n, &m);
                                        free(n);

                                        if (r < 0)
                                                goto finish;

                                        if (r == 0)
                                                continue;

                                        r = unit_add_dependency_by_name(u, UNIT_AFTER, m);
                                        free(m);

                                        if (r < 0)
                                                goto finish;
                                }
                        } else if (startswith(t, "Default-Start:")) {
                                char *k, *d;

                                state = LSB;

                                k = delete_chars(t+14, WHITESPACE "-");

                                if (k[0] != 0) {
                                        if (!(d = strdup(k))) {
                                                r = -ENOMEM;
                                                goto finish;
                                        }

                                        free(s->sysv_runlevels);
                                        s->sysv_runlevels = d;
                                }

                        } else if (startswith(t, "Description:")) {
                                char *d;

                                state = LSB_DESCRIPTION;

                                if (!(d = strdup(strstrip(t+12)))) {
                                        r = -ENOMEM;
                                        goto finish;
                                }

                                free(u->meta.description);
                                u->meta.description = d;

                        } else if (startswith(t, "Short-Description:") &&
                                   !u->meta.description) {
                                char *d;

                                /* We use the short description only
                                 * if no long description is set. */

                                state = LSB;

                                if (!(d = strdup(strstrip(t+18)))) {
                                        r = -ENOMEM;
                                        goto finish;
                                }

                                u->meta.description = d;

                        } else if (state == LSB_DESCRIPTION) {

                                if (startswith(l, "#\t") || startswith(l, "#  ")) {
                                        char *d;

                                        assert(u->meta.description);
                                        if (asprintf(&d, "%s %s", u->meta.description, t) < 0) {
                                                r = -ENOMEM;
                                                goto finish;
                                        }

                                        free(u->meta.description);
                                        u->meta.description = d;
                                } else
                                        state = LSB;
                        }
                }
        }

        /* If init scripts have no LSB header, then we enforce the
         * ordering via the chkconfig priorities. We try to determine
         * a priority for *all* init scripts here, since they are
         * needed as soon as at least one non-LSB script is used. */

        if (s->sysv_start_priority < 0) {
                log_debug("%s has no chkconfig header, trying to determine SysV priority from link farm.", unit_id(u));

                if ((r = priority_from_rcd(s, file_name_from_path(path))) < 0)
                        goto finish;

                if (s->sysv_start_priority < 0)
                        log_warning("%s has neither a chkconfig header nor a directory link, cannot order unit!", unit_id(u));
        }

        if ((r = sysv_exec_commands(s)) < 0)
                goto finish;

        if (!s->sysv_runlevels || chars_intersect("12345", s->sysv_runlevels)) {
                /* If there a runlevels configured for this service
                 * but none of the standard ones, then we assume this
                 * is some special kind of service (which might be
                 * needed for early boot) and don't create any links
                 * to it. */

                if ((r = unit_add_dependency_by_name(u, UNIT_REQUIRES, SPECIAL_BASIC_TARGET)) < 0 ||
                    (r = unit_add_dependency_by_name(u, UNIT_AFTER, SPECIAL_BASIC_TARGET)) < 0)
                        goto finish;
        }

        *new_state = UNIT_LOADED;
        r = 0;

finish:

        if (f)
                fclose(f);

        return r;
}

static int service_load_sysv_name(Service *s, const char *name, UnitLoadState *new_state) {
        char **p;

        assert(s);
        assert(name);

        STRV_FOREACH(p, UNIT(s)->meta.manager->sysvinit_path) {
                char *path;
                int r;

                if (asprintf(&path, "%s/%s", *p, name) < 0)
                        return -ENOMEM;

                assert(endswith(path, ".service"));
                path[strlen(path)-8] = 0;

                r = service_load_sysv_path(s, path, new_state);
                free(path);

                if (r < 0)
                        return r;

                if (*new_state != UNIT_STUB)
                        break;
        }

        return 0;
}

static int service_load_sysv(Service *s, UnitLoadState *new_state) {
        const char *t;
        Iterator i;
        int r;

        assert(s);
        assert(new_state);

        /* Load service data from SysV init scripts, preferably with
         * LSB headers ... */

        if (strv_isempty(UNIT(s)->meta.manager->sysvinit_path))
                return 0;

        if ((t = unit_id(UNIT(s))))
                if ((r = service_load_sysv_name(s, t, new_state)) < 0)
                        return r;

        if (*new_state == UNIT_STUB)
                SET_FOREACH(t, UNIT(s)->meta.names, i) {
                        if ((r == service_load_sysv_name(s, t, new_state)) < 0)
                                return r;

                        if (*new_state != UNIT_STUB)
                                break;
                }

        return 0;
}

static int service_init(Unit *u, UnitLoadState *new_state) {
        int r;
        Service *s = SERVICE(u);

        assert(s);
        assert(new_state);
        assert(*new_state == UNIT_STUB);

        /* First, reset everything to the defaults, in case this is a
         * reload */

        s->type = 0;
        s->restart = 0;

        s->timeout_usec = DEFAULT_TIMEOUT_USEC;
        s->restart_usec = DEFAULT_RESTART_USEC;

        exec_context_init(&s->exec_context);

        s->timer_watch.type = WATCH_INVALID;

        s->state = SERVICE_DEAD;

        s->sysv_start_priority = -1;
        s->permissions_start_only = false;
        s->root_directory_start_only = false;
        s->valid_no_process = false;
        s->kill_mode = 0;
        s->sysv_has_lsb = false;
        s->main_pid = s->control_pid = 0;
        s->main_pid_known = false;
        s->failure = false;

        RATELIMIT_INIT(s->ratelimit, 10*USEC_PER_SEC, 5);

        /* Load a .service file */
        if ((r = unit_load_fragment(u, new_state)) < 0)
                return r;

        /* Load a classic init script as a fallback, if we couldn't find anything */
        if (*new_state == UNIT_STUB)
                if ((r = service_load_sysv(s, new_state)) < 0)
                        return r;

        /* Still nothing found? Then let's give up */
        if (*new_state == UNIT_STUB)
                return -ENOENT;

        /* We were able to load something, then let's add in the
         * dropin directories. */
        if ((r = unit_load_dropin(unit_follow_merge(u))) < 0)
                return r;

        /* This is a new unit? Then let's add in some extras */
        if (*new_state == UNIT_LOADED) {
                if ((r = unit_add_exec_dependencies(u, &s->exec_context)) < 0)
                        return r;

                if ((r = unit_add_default_cgroup(u)) < 0)
                        return r;

                if ((r = sysv_chkconfig_order(s)) < 0)
                        return r;
        }

        return 0;
}

static void service_dump(Unit *u, FILE *f, const char *prefix) {

        ServiceExecCommand c;
        Service *s = SERVICE(u);
        const char *prefix2;
        char *p2;

        assert(s);

        p2 = strappend(prefix, "\t");
        prefix2 = p2 ? p2 : prefix;

        fprintf(f,
                "%sService State: %s\n"
                "%sPermissionsStartOnly: %s\n"
                "%sRootDirectoryStartOnly: %s\n"
                "%sValidNoProcess: %s\n"
                "%sKillMode: %s\n"
                "%sType: %s\n",
                prefix, service_state_to_string(s->state),
                prefix, yes_no(s->permissions_start_only),
                prefix, yes_no(s->root_directory_start_only),
                prefix, yes_no(s->valid_no_process),
                prefix, kill_mode_to_string(s->kill_mode),
                prefix, service_type_to_string(s->type));

        if (s->control_pid > 0)
                fprintf(f,
                        "%sControl PID: %llu\n",
                        prefix, (unsigned long long) s->control_pid);

        if (s->main_pid > 0)
                fprintf(f,
                        "%sMain PID: %llu\n",
                        prefix, (unsigned long long) s->main_pid);

        if (s->pid_file)
                fprintf(f,
                        "%sPIDFile: %s\n",
                        prefix, s->pid_file);

        exec_context_dump(&s->exec_context, f, prefix);

        for (c = 0; c < _SERVICE_EXEC_MAX; c++) {

                if (!s->exec_command[c])
                        continue;

                fprintf(f, "%s→ %s:\n",
                        prefix, service_exec_command_to_string(c));

                exec_command_dump_list(s->exec_command[c], f, prefix2);
        }

        if (s->sysv_path)
                fprintf(f,
                        "%sSysV Init Script Path: %s\n"
                        "%sSysV Init Script has LSB Header: %s\n",
                        prefix, s->sysv_path,
                        prefix, yes_no(s->sysv_has_lsb));

        if (s->sysv_start_priority >= 0)
                fprintf(f,
                        "%sSysVStartPriority: %i\n",
                        prefix, s->sysv_start_priority);

        if (s->sysv_runlevels)
                fprintf(f, "%sSysVRunLevels: %s\n",
                        prefix, s->sysv_runlevels);

        free(p2);
}

static int service_load_pid_file(Service *s) {
        char *k;
        unsigned long p;
        int r;

        assert(s);

        if (s->main_pid_known)
                return 0;

        if (!s->pid_file)
                return -ENOENT;

        if ((r = read_one_line_file(s->pid_file, &k)) < 0)
                return r;

        if ((r = safe_atolu(k, &p)) < 0) {
                free(k);
                return r;
        }

        if ((unsigned long) (pid_t) p != p)
                return -ERANGE;

        if (kill((pid_t) p, 0) < 0 && errno != EPERM) {
                log_warning("PID %llu read from file %s does not exist. Your service or init script might be broken.",
                            (unsigned long long) p, s->pid_file);
                return -ESRCH;
        }

        if ((r = unit_watch_pid(UNIT(s), (pid_t) p)) < 0)
                /* FIXME: we need to do something here */
                return r;

        s->main_pid = (pid_t) p;
        s->main_pid_known = true;

        return 0;
}

static int service_get_sockets(Service *s, Set **_set) {
        Set *set;
        Iterator i;
        char *t;
        int r;

        assert(s);
        assert(_set);

        /* Collects all Socket objects that belong to this
         * service. Note that a service might have multiple sockets
         * via multiple names. */

        if (!(set = set_new(NULL, NULL)))
                return -ENOMEM;

        SET_FOREACH(t, UNIT(s)->meta.names, i) {
                char *k;
                Unit *p;

                /* Look for all socket objects that go by any of our
                 * units and collect their fds */

                if (!(k = unit_name_change_suffix(t, ".socket"))) {
                        r = -ENOMEM;
                        goto fail;
                }

                p = manager_get_unit(UNIT(s)->meta.manager, k);
                free(k);

                if (!p) continue;

                if ((r = set_put(set, p)) < 0)
                        goto fail;
        }

        *_set = set;
        return 0;

fail:
        set_free(set);
        return r;
}


static int service_notify_sockets(Service *s) {
        Iterator i;
        Set *set;
        Socket *sock;
        int r;

        assert(s);

        /* Notifies all our sockets when we die */

        if ((r = service_get_sockets(s, &set)) < 0)
                return r;

        SET_FOREACH(sock, set, i)
                socket_notify_service_dead(sock);

        set_free(set);

        return 0;
}

static void service_set_state(Service *s, ServiceState state) {
        ServiceState old_state;
        assert(s);

        old_state = s->state;
        s->state = state;

        if (state != SERVICE_START_PRE &&
            state != SERVICE_START &&
            state != SERVICE_START_POST &&
            state != SERVICE_RELOAD &&
            state != SERVICE_STOP &&
            state != SERVICE_STOP_SIGTERM &&
            state != SERVICE_STOP_SIGKILL &&
            state != SERVICE_STOP_POST &&
            state != SERVICE_FINAL_SIGTERM &&
            state != SERVICE_FINAL_SIGKILL &&
            state != SERVICE_AUTO_RESTART)
                unit_unwatch_timer(UNIT(s), &s->timer_watch);

        if (state != SERVICE_START &&
            state != SERVICE_START_POST &&
            state != SERVICE_RUNNING &&
            state != SERVICE_RELOAD &&
            state != SERVICE_STOP &&
            state != SERVICE_STOP_SIGTERM &&
            state != SERVICE_STOP_SIGKILL)
                if (s->main_pid > 0) {
                        unit_unwatch_pid(UNIT(s), s->main_pid);
                        s->main_pid = 0;
                }

        if (state != SERVICE_START_PRE &&
            state != SERVICE_START &&
            state != SERVICE_START_POST &&
            state != SERVICE_RELOAD &&
            state != SERVICE_STOP &&
            state != SERVICE_STOP_SIGTERM &&
            state != SERVICE_STOP_SIGKILL &&
            state != SERVICE_STOP_POST &&
            state != SERVICE_FINAL_SIGTERM &&
            state != SERVICE_FINAL_SIGKILL)
                if (s->control_pid > 0) {
                        unit_unwatch_pid(UNIT(s), s->control_pid);
                        s->control_pid = 0;
                }

        if (state != SERVICE_START_PRE &&
            state != SERVICE_START &&
            state != SERVICE_START_POST &&
            state != SERVICE_RELOAD &&
            state != SERVICE_STOP &&
            state != SERVICE_STOP_POST)
                s->control_command = NULL;

        if (state == SERVICE_DEAD ||
            state == SERVICE_STOP ||
            state == SERVICE_STOP_SIGTERM ||
            state == SERVICE_STOP_SIGKILL ||
            state == SERVICE_STOP_POST ||
            state == SERVICE_FINAL_SIGTERM ||
            state == SERVICE_FINAL_SIGKILL ||
            state == SERVICE_MAINTAINANCE ||
            state == SERVICE_AUTO_RESTART)
                service_notify_sockets(s);

        if (old_state == state)
                return;

        log_debug("%s changed %s → %s", unit_id(UNIT(s)), service_state_to_string(old_state), service_state_to_string(state));

        unit_notify(UNIT(s), state_translation_table[old_state], state_translation_table[state]);
}

static int service_collect_fds(Service *s, int **fds, unsigned *n_fds) {
        Iterator i;
        int r;
        int *rfds = NULL;
        unsigned rn_fds = 0;
        Set *set;
        Socket *sock;

        assert(s);
        assert(fds);
        assert(n_fds);

        if ((r = service_get_sockets(s, &set)) < 0)
                return r;

        SET_FOREACH(sock, set, i) {
                int *cfds;
                unsigned cn_fds;

                if ((r = socket_collect_fds(sock, &cfds, &cn_fds)) < 0)
                        goto fail;

                if (!cfds)
                        continue;

                if (!rfds) {
                        rfds = cfds;
                        rn_fds = cn_fds;
                } else {
                        int *t;

                        if (!(t = new(int, rn_fds+cn_fds))) {
                                free(cfds);
                                r = -ENOMEM;
                                goto fail;
                        }

                        memcpy(t, rfds, rn_fds);
                        memcpy(t+rn_fds, cfds, cn_fds);
                        free(rfds);
                        free(cfds);

                        rfds = t;
                        rn_fds = rn_fds+cn_fds;
                }
        }

        *fds = rfds;
        *n_fds = rn_fds;

        set_free(set);

        return 0;

fail:
        set_free(set);
        free(rfds);

        return r;
}

static int service_spawn(
                Service *s,
                ExecCommand *c,
                bool timeout,
                bool pass_fds,
                bool apply_permissions,
                bool apply_chroot,
                pid_t *_pid) {

        pid_t pid;
        int r;
        int *fds = NULL;
        unsigned n_fds = 0;

        assert(s);
        assert(c);
        assert(_pid);

        if (pass_fds)
                if ((r = service_collect_fds(s, &fds, &n_fds)) < 0)
                        goto fail;

        if (timeout) {
                if ((r = unit_watch_timer(UNIT(s), s->timeout_usec, &s->timer_watch)) < 0)
                        goto fail;
        } else
                unit_unwatch_timer(UNIT(s), &s->timer_watch);

        if ((r = exec_spawn(c,
                            &s->exec_context,
                            fds, n_fds,
                            apply_permissions,
                            apply_chroot,
                            UNIT(s)->meta.cgroup_bondings,
                            &pid)) < 0)
                goto fail;

        if ((r = unit_watch_pid(UNIT(s), pid)) < 0)
                /* FIXME: we need to do something here */
                goto fail;

        free(fds);
        *_pid = pid;

        return 0;

fail:
        free(fds);

        if (timeout)
                unit_unwatch_timer(UNIT(s), &s->timer_watch);

        return r;
}

static void service_enter_dead(Service *s, bool success, bool allow_restart) {
        int r;
        assert(s);

        if (!success)
                s->failure = true;

        if (allow_restart &&
            (s->restart == SERVICE_RESTART_ALWAYS ||
             (s->restart == SERVICE_RESTART_ON_SUCCESS && !s->failure))) {

                if ((r = unit_watch_timer(UNIT(s), s->restart_usec, &s->timer_watch)) < 0)
                        goto fail;

                service_set_state(s, SERVICE_AUTO_RESTART);
        } else
                service_set_state(s, s->failure ? SERVICE_MAINTAINANCE : SERVICE_DEAD);

        return;

fail:
        log_warning("%s failed to run install restart timer: %s", unit_id(UNIT(s)), strerror(-r));
        service_enter_dead(s, false, false);
}

static void service_enter_signal(Service *s, ServiceState state, bool success);

static void service_enter_stop_post(Service *s, bool success) {
        int r;
        assert(s);

        if (!success)
                s->failure = true;

        if ((s->control_command = s->exec_command[SERVICE_EXEC_STOP_POST]))
                if ((r = service_spawn(s,
                                       s->control_command,
                                       true,
                                       false,
                                       !s->permissions_start_only,
                                       !s->root_directory_start_only,
                                       &s->control_pid)) < 0)
                        goto fail;


        service_set_state(s, SERVICE_STOP_POST);

        if (!s->control_command)
                service_enter_dead(s, true, true);

        return;

fail:
        log_warning("%s failed to run stop executable: %s", unit_id(UNIT(s)), strerror(-r));
        service_enter_signal(s, SERVICE_FINAL_SIGTERM, false);
}

static void service_enter_signal(Service *s, ServiceState state, bool success) {
        int r;
        bool sent = false;

        assert(s);

        if (!success)
                s->failure = true;

        if (s->main_pid > 0 || s->control_pid > 0) {
                int sig;

                sig = (state == SERVICE_STOP_SIGTERM || state == SERVICE_FINAL_SIGTERM) ? SIGTERM : SIGKILL;

                if (s->kill_mode == KILL_CONTROL_GROUP) {

                        if ((r = cgroup_bonding_kill_list(UNIT(s)->meta.cgroup_bondings, sig)) < 0) {
                                if (r != -EAGAIN && r != -ESRCH)
                                        goto fail;
                        } else
                                sent = true;
                }

                if (!sent) {
                        r = 0;
                        if (s->main_pid > 0) {
                                if (kill(s->kill_mode == KILL_PROCESS ? s->main_pid : -s->main_pid, sig) < 0 && errno != ESRCH)
                                        r = -errno;
                                else
                                        sent = true;
                        }

                        if (s->control_pid > 0) {
                                if (kill(s->kill_mode == KILL_PROCESS ? s->control_pid : -s->control_pid, sig) < 0 && errno != ESRCH)
                                        r = -errno;
                                else
                                        sent = true;
                        }

                        if (r < 0)
                                goto fail;
                }
        }

        service_set_state(s, state);

        if (s->main_pid <= 0 && s->control_pid <= 0)
                service_enter_dead(s, true, true);

        return;

fail:
        log_warning("%s failed to kill processes: %s", unit_id(UNIT(s)), strerror(-r));

        if (sent)  {
                s->failure = true;
                service_set_state(s, state);
        } else if (state == SERVICE_STOP_SIGTERM || state == SERVICE_STOP_SIGKILL)
                service_enter_stop_post(s, false);
        else
                service_enter_dead(s, false, true);
}

static void service_enter_stop(Service *s, bool success) {
        int r;
        assert(s);

        if (!success)
                s->failure = true;

        if ((s->control_command = s->exec_command[SERVICE_EXEC_STOP]))
                if ((r = service_spawn(s,
                                       s->control_command,
                                       true,
                                       false,
                                       !s->permissions_start_only,
                                       !s->root_directory_start_only,
                                       &s->control_pid)) < 0)
                        goto fail;

        service_set_state(s, SERVICE_STOP);

        if (!s->control_command)
                service_enter_signal(s, SERVICE_STOP_SIGTERM, true);

        return;

fail:
        log_warning("%s failed to run stop executable: %s", unit_id(UNIT(s)), strerror(-r));
        service_enter_signal(s, SERVICE_STOP_SIGTERM, false);
}

static void service_enter_start_post(Service *s) {
        int r;
        assert(s);

        if ((s->control_command = s->exec_command[SERVICE_EXEC_START_POST]))
                if ((r = service_spawn(s,
                                       s->control_command,
                                       true,
                                       false,
                                       !s->permissions_start_only,
                                       !s->root_directory_start_only,
                                       &s->control_pid)) < 0)
                        goto fail;


        service_set_state(s, SERVICE_START_POST);

        if (!s->control_command)
                service_set_state(s, SERVICE_RUNNING);

        return;

fail:
        log_warning("%s failed to run start-post executable: %s", unit_id(UNIT(s)), strerror(-r));
        service_enter_stop(s, false);
}

static void service_enter_start(Service *s) {
        pid_t pid;
        int r;

        assert(s);

        assert(s->exec_command[SERVICE_EXEC_START]);
        assert(!s->exec_command[SERVICE_EXEC_START]->command_next);

        if ((r = service_spawn(s,
                               s->exec_command[SERVICE_EXEC_START],
                               s->type == SERVICE_FORKING,
                               true,
                               true,
                               true,
                               &pid)) < 0)
                goto fail;

        service_set_state(s, SERVICE_START);

        if (s->type == SERVICE_SIMPLE) {
                /* For simple services we immediately start
                 * the START_POST binaries. */

                s->main_pid = pid;
                s->main_pid_known = true;
                service_enter_start_post(s);

        } else  if (s->type == SERVICE_FORKING) {

                /* For forking services we wait until the start
                 * process exited. */

                s->control_pid = pid;
                s->control_command = s->exec_command[SERVICE_EXEC_START];
        } else if (s->type == SERVICE_FINISH) {

                /* For finishing services we wait until the start
                 * process exited, too, but it is our main process. */

                s->main_pid = pid;
                s->control_command = s->exec_command[SERVICE_EXEC_START];
        } else
                assert_not_reached("Unknown service type");

        return;

fail:
        log_warning("%s failed to run start exectuable: %s", unit_id(UNIT(s)), strerror(-r));
        service_enter_stop(s, false);
}

static void service_enter_start_pre(Service *s) {
        int r;

        assert(s);

        if ((s->control_command = s->exec_command[SERVICE_EXEC_START_PRE]))
                if ((r = service_spawn(s,
                                       s->control_command,
                                       true,
                                       false,
                                       !s->permissions_start_only,
                                       !s->root_directory_start_only,
                                       &s->control_pid)) < 0)
                        goto fail;

        service_set_state(s, SERVICE_START_PRE);

        if (!s->control_command)
                service_enter_start(s);

        return;

fail:
        log_warning("%s failed to run start-pre executable: %s", unit_id(UNIT(s)), strerror(-r));
        service_enter_dead(s, false, true);
}

static void service_enter_restart(Service *s) {
        int r;
        assert(s);

        if ((r = manager_add_job(UNIT(s)->meta.manager, JOB_START, UNIT(s), JOB_FAIL, false, NULL)) < 0)
                goto fail;

        log_debug("%s scheduled restart job.", unit_id(UNIT(s)));
        service_enter_dead(s, true, false);
        return;

fail:

        log_warning("%s failed to schedule restart job: %s", unit_id(UNIT(s)), strerror(-r));
        service_enter_dead(s, false, false);
}

static void service_enter_reload(Service *s) {
        int r;

        assert(s);

        if ((s->control_command = s->exec_command[SERVICE_EXEC_RELOAD]))
                if ((r = service_spawn(s,
                                       s->control_command,
                                       true,
                                       false,
                                       !s->permissions_start_only,
                                       !s->root_directory_start_only,
                                       &s->control_pid)) < 0)
                        goto fail;

        service_set_state(s, SERVICE_RELOAD);

        if (!s->control_command)
                service_set_state(s, SERVICE_RUNNING);

        return;

fail:
        log_warning("%s failed to run reload executable: %s", unit_id(UNIT(s)), strerror(-r));
        service_enter_stop(s, false);
}

static void service_run_next(Service *s, bool success) {
        int r;

        assert(s);
        assert(s->control_command);
        assert(s->control_command->command_next);

        if (!success)
                s->failure = true;

        s->control_command = s->control_command->command_next;

        if ((r = service_spawn(s,
                               s->control_command,
                               true,
                               false,
                               !s->permissions_start_only,
                               !s->root_directory_start_only,
                               &s->control_pid)) < 0)
                goto fail;

        return;

fail:
        log_warning("%s failed to run spawn next executable: %s", unit_id(UNIT(s)), strerror(-r));

        if (s->state == SERVICE_STOP)
                service_enter_stop_post(s, false);
        else if (s->state == SERVICE_STOP_POST)
                service_enter_dead(s, false, true);
        else
                service_enter_stop(s, false);
}

static int service_start(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        /* We cannot fulfill this request right now, try again later
         * please! */
        if (s->state == SERVICE_STOP ||
            s->state == SERVICE_STOP_SIGTERM ||
            s->state == SERVICE_STOP_SIGKILL ||
            s->state == SERVICE_STOP_POST ||
            s->state == SERVICE_FINAL_SIGTERM ||
            s->state == SERVICE_FINAL_SIGKILL)
                return -EAGAIN;

        /* Already on it! */
        if (s->state == SERVICE_START_PRE ||
            s->state == SERVICE_START ||
            s->state == SERVICE_START_POST)
                return 0;

        assert(s->state == SERVICE_DEAD || s->state == SERVICE_MAINTAINANCE || s->state == SERVICE_AUTO_RESTART);

        /* Make sure we don't enter a busy loop of some kind. */
        if (!ratelimit_test(&s->ratelimit)) {
                log_warning("%s start request repeated too quickly, refusing to start.", unit_id(u));
                return -EAGAIN;
        }

        s->failure = false;
        s->main_pid_known = false;

        service_enter_start_pre(s);
        return 0;
}

static int service_stop(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        if (s->state == SERVICE_START_PRE ||
            s->state == SERVICE_START ||
            s->state == SERVICE_START_POST ||
            s->state == SERVICE_RELOAD)
                return -EAGAIN;

        if (s->state == SERVICE_AUTO_RESTART) {
                service_set_state(s, SERVICE_DEAD);
                return 0;
        }

        assert(s->state == SERVICE_RUNNING);

        service_enter_stop(s, true);
        return 0;
}

static int service_reload(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        assert(s->state == SERVICE_RUNNING);

        service_enter_reload(s);
        return 0;
}

static bool service_can_reload(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        return !!s->exec_command[SERVICE_EXEC_RELOAD];
}

static UnitActiveState service_active_state(Unit *u) {
        assert(u);

        return state_translation_table[SERVICE(u)->state];
}

static int main_pid_good(Service *s) {
        assert(s);

        /* Returns 0 if the pid is dead, 1 if it is good, -1 if we
         * don't know */

        /* If we know the pid file, then lets just check if it is
         * still valid */
        if (s->main_pid_known)
                return s->main_pid > 0;

        /* We don't know the pid */
        return -EAGAIN;
}

static bool control_pid_good(Service *s) {
        assert(s);

        return s->control_pid > 0;
}

static int cgroup_good(Service *s) {
        assert(s);

        if (s->valid_no_process)
                return -EAGAIN;

        return cgroup_bonding_is_empty_list(UNIT(s)->meta.cgroup_bondings);
}

static void service_sigchld_event(Unit *u, pid_t pid, int code, int status) {
        Service *s = SERVICE(u);
        bool success;

        assert(s);
        assert(pid >= 0);

        success = code == CLD_EXITED && status == 0;
        s->failure = s->failure || !success;

        if (s->main_pid == pid) {

                exec_status_fill(&s->main_exec_status, pid, code, status);
                s->main_pid = 0;

                if (s->type == SERVICE_SIMPLE || s->type == SERVICE_FINISH) {
                        assert(s->exec_command[SERVICE_EXEC_START]);
                        s->exec_command[SERVICE_EXEC_START]->exec_status = s->main_exec_status;
                }

                log_debug("%s: main process exited, code=%s, status=%i", unit_id(u), sigchld_code_to_string(code), status);

                /* The service exited, so the service is officially
                 * gone. */

                switch (s->state) {

                case SERVICE_START_POST:
                case SERVICE_RELOAD:
                case SERVICE_STOP:
                        /* Need to wait until the operation is
                         * done */
                        break;

                case SERVICE_START:
                        assert(s->type == SERVICE_FINISH);

                        /* This was our main goal, so let's go on */
                        if (success)
                                service_enter_start_post(s);
                        else
                                service_enter_stop(s, false);
                        break;

                case SERVICE_RUNNING:
                        service_enter_stop(s, success);
                        break;

                case SERVICE_STOP_SIGTERM:
                case SERVICE_STOP_SIGKILL:

                        if (!control_pid_good(s))
                                service_enter_stop_post(s, success);

                        /* If there is still a control process, wait for that first */
                        break;

                default:
                        assert_not_reached("Uh, main process died at wrong time.");
                }

        } else if (s->control_pid == pid) {
                assert(s->control_command);

                exec_status_fill(&s->control_command->exec_status, pid, code, status);
                s->control_pid = 0;

                log_debug("%s: control process exited, code=%s status=%i", unit_id(u), sigchld_code_to_string(code), status);

                /* If we are shutting things down anyway we
                 * don't care about failing commands. */

                if (s->control_command->command_next &&
                    (success || (s->state == SERVICE_STOP || s->state == SERVICE_STOP_POST)))

                        /* There is another command to *
                         * execute, so let's do that. */

                        service_run_next(s, success);

                else {
                        /* No further commands for this step, so let's
                         * figure out what to do next */

                        log_debug("%s got final SIGCHLD for state %s", unit_id(u), service_state_to_string(s->state));

                        switch (s->state) {

                        case SERVICE_START_PRE:
                                if (success)
                                        service_enter_start(s);
                                else
                                        service_enter_stop(s, false);
                                break;

                        case SERVICE_START:
                                assert(s->type == SERVICE_FORKING);

                                /* Let's try to load the pid
                                 * file here if we can. We
                                 * ignore the return value,
                                 * since the PID file might
                                 * actually be created by a
                                 * START_POST script */

                                if (success) {
                                        if (s->pid_file)
                                                service_load_pid_file(s);

                                        service_enter_start_post(s);
                                } else
                                        service_enter_stop(s, false);

                                break;

                        case SERVICE_START_POST:
                                if (success && s->pid_file && !s->main_pid_known) {
                                        int r;

                                        /* Hmm, let's see if we can
                                         * load the pid now after the
                                         * start-post scripts got
                                         * executed. */

                                        if ((r = service_load_pid_file(s)) < 0)
                                                log_warning("%s: failed to load PID file %s: %s", unit_id(UNIT(s)), s->pid_file, strerror(-r));
                                }

                                /* Fall through */

                        case SERVICE_RELOAD:
                                if (success) {
                                        if (main_pid_good(s) != 0 && cgroup_good(s) != 0)
                                                service_set_state(s, SERVICE_RUNNING);
                                        else
                                                service_enter_stop(s, true);
                                } else
                                        service_enter_stop(s, false);

                                break;

                        case SERVICE_STOP:
                                if (main_pid_good(s) > 0)
                                        /* Still not dead and we know the PID? Let's go hunting. */
                                        service_enter_signal(s, SERVICE_STOP_SIGTERM, success);
                                else
                                        service_enter_stop_post(s, success);
                                break;

                        case SERVICE_STOP_SIGTERM:
                        case SERVICE_STOP_SIGKILL:
                                if (main_pid_good(s) <= 0)
                                        service_enter_stop_post(s, success);

                                /* If there is still a service
                                 * process around, wait until
                                 * that one quit, too */
                                break;

                        case SERVICE_STOP_POST:
                        case SERVICE_FINAL_SIGTERM:
                        case SERVICE_FINAL_SIGKILL:
                                service_enter_dead(s, success, true);
                                break;

                        default:
                                assert_not_reached("Uh, control process died at wrong time.");
                        }
                }
        } else
                assert_not_reached("Got SIGCHLD for unkown PID");
}

static void service_timer_event(Unit *u, uint64_t elapsed, Watch* w) {
        Service *s = SERVICE(u);

        assert(s);
        assert(elapsed == 1);

        assert(w == &s->timer_watch);

        switch (s->state) {

        case SERVICE_START_PRE:
        case SERVICE_START:
        case SERVICE_START_POST:
        case SERVICE_RELOAD:
                log_warning("%s operation timed out. Stopping.", unit_id(u));
                service_enter_stop(s, false);
                break;

        case SERVICE_STOP:
                log_warning("%s stopping timed out. Terminating.", unit_id(u));
                service_enter_signal(s, SERVICE_STOP_SIGTERM, false);
                break;

        case SERVICE_STOP_SIGTERM:
                log_warning("%s stopping timed out. Killing.", unit_id(u));
                service_enter_signal(s, SERVICE_STOP_SIGKILL, false);
                break;

        case SERVICE_STOP_SIGKILL:
                /* Uh, wie sent a SIGKILL and it is still not gone?
                 * Must be something we cannot kill, so let's just be
                 * weirded out and continue */

                log_warning("%s still around after SIGKILL. Ignoring.", unit_id(u));
                service_enter_stop_post(s, false);
                break;

        case SERVICE_STOP_POST:
                log_warning("%s stopping timed out (2). Terminating.", unit_id(u));
                service_enter_signal(s, SERVICE_FINAL_SIGTERM, false);
                break;

        case SERVICE_FINAL_SIGTERM:
                log_warning("%s stopping timed out (2). Killing.", unit_id(u));
                service_enter_signal(s, SERVICE_FINAL_SIGKILL, false);
                break;

        case SERVICE_FINAL_SIGKILL:
                log_warning("%s still around after SIGKILL (2). Entering maintainance mode.", unit_id(u));
                service_enter_dead(s, false, true);
                break;

        case SERVICE_AUTO_RESTART:
                log_debug("%s holdoff time over, scheduling restart.", unit_id(u));
                service_enter_restart(s);
                break;

        default:
                assert_not_reached("Timeout at wrong time.");
        }
}

static void service_cgroup_notify_event(Unit *u) {
        Service *s = SERVICE(u);

        assert(u);

        log_debug("%s: cgroup is empty", unit_id(u));

        switch (s->state) {

                /* Waiting for SIGCHLD is usually more interesting,
                 * because it includes return codes/signals. Which is
                 * why we ignore the cgroup events for most cases,
                 * except when we don't know pid which to expect the
                 * SIGCHLD for. */

        case SERVICE_RUNNING:

                if (!s->valid_no_process && main_pid_good(s) <= 0)
                        service_enter_stop(s, true);

                break;

        default:
                ;
        }
}

static int service_enumerate(Manager *m) {
        char **p;
        unsigned i;
        DIR *d = NULL;
        char *path = NULL, *fpath = NULL, *name = NULL;
        int r;

        assert(m);

        STRV_FOREACH(p, m->sysvrcnd_path)
                for (i = 0; i < ELEMENTSOF(rcnd_table); i += 2) {
                        struct dirent *de;

                        free(path);
                        path = NULL;
                        if (asprintf(&path, "%s/%s", *p, rcnd_table[i]) < 0) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        if (d)
                                closedir(d);

                        if (!(d = opendir(path))) {
                                if (errno != ENOENT)
                                        log_warning("opendir() failed on %s: %s", path, strerror(errno));

                                continue;
                        }

                        while ((de = readdir(d))) {
                                Unit *runlevel, *service;

                                if (ignore_file(de->d_name))
                                        continue;

                                if (de->d_name[0] != 'S' && de->d_name[0] != 'K')
                                        continue;

                                if (strlen(de->d_name) < 4)
                                        continue;

                                free(fpath);
                                fpath = NULL;
                                if (asprintf(&fpath, "%s/%s/%s", *p, rcnd_table[i], de->d_name) < 0) {
                                        r = -ENOMEM;
                                        goto finish;
                                }

                                if (access(fpath, X_OK) < 0) {

                                        if (errno != ENOENT)
                                                log_warning("access() failed on %s: %s", fpath, strerror(errno));

                                        continue;
                                }

                                free(name);
                                name = NULL;
                                if (asprintf(&name, "%s.service", de->d_name+3) < 0) {
                                        r = -ENOMEM;
                                        goto finish;
                                }

                                if ((r = manager_load_unit(m, name, &service)) < 0)
                                        goto finish;

                                if ((r = manager_load_unit(m, rcnd_table[i+1], &runlevel)) < 0)
                                        goto finish;

                                if (de->d_name[0] == 'S') {
                                        if ((r = unit_add_dependency(runlevel, UNIT_WANTS, service)) < 0)
                                                goto finish;

                                        if ((r = unit_add_dependency(runlevel, UNIT_AFTER, service)) < 0)
                                                goto finish;

                                } else if (de->d_name[0] == 'K' &&
                                           (streq(rcnd_table[i+1], SPECIAL_RUNLEVEL0_TARGET) ||
                                            streq(rcnd_table[i+1], SPECIAL_RUNLEVEL6_TARGET))) {

                                        /* We honour K links only for
                                         * halt/reboot. For the normal
                                         * runlevels we assume the
                                         * stop jobs will be
                                         * implicitly added by the
                                         * core logic. */

                                        if ((r = unit_add_dependency(runlevel, UNIT_CONFLICTS, service)) < 0)
                                                goto finish;

                                        if ((r = unit_add_dependency(runlevel, UNIT_BEFORE, service)) < 0)
                                                goto finish;
                                }
                        }
                }

        r = 0;

finish:
        free(path);
        free(fpath);
        free(name);
        closedir(d);

        return r;
}

static const char* const service_state_table[_SERVICE_STATE_MAX] = {
        [SERVICE_DEAD] = "dead",
        [SERVICE_START_PRE] = "start-pre",
        [SERVICE_START] = "start",
        [SERVICE_START_POST] = "start-post",
        [SERVICE_RUNNING] = "running",
        [SERVICE_RELOAD] = "reload",
        [SERVICE_STOP] = "stop",
        [SERVICE_STOP_SIGTERM] = "stop-sigterm",
        [SERVICE_STOP_SIGKILL] = "stop-sigkill",
        [SERVICE_STOP_POST] = "stop-post",
        [SERVICE_FINAL_SIGTERM] = "final-sigterm",
        [SERVICE_FINAL_SIGKILL] = "final-sigkill",
        [SERVICE_MAINTAINANCE] = "maintainance",
        [SERVICE_AUTO_RESTART] = "auto-restart",
};

DEFINE_STRING_TABLE_LOOKUP(service_state, ServiceState);

static const char* const service_restart_table[_SERVICE_RESTART_MAX] = {
        [SERVICE_ONCE] = "once",
        [SERVICE_RESTART_ON_SUCCESS] = "restart-on-success",
        [SERVICE_RESTART_ALWAYS] = "restart-on-failure",
};

DEFINE_STRING_TABLE_LOOKUP(service_restart, ServiceRestart);

static const char* const service_type_table[_SERVICE_TYPE_MAX] = {
        [SERVICE_FORKING] = "forking",
        [SERVICE_SIMPLE] = "simple",
        [SERVICE_FINISH] = "finish"
};

DEFINE_STRING_TABLE_LOOKUP(service_type, ServiceType);

static const char* const service_exec_command_table[_SERVICE_EXEC_MAX] = {
        [SERVICE_EXEC_START_PRE] = "ExecStartPre",
        [SERVICE_EXEC_START] = "ExecStart",
        [SERVICE_EXEC_START_POST] = "ExecStartPost",
        [SERVICE_EXEC_RELOAD] = "ExecReload",
        [SERVICE_EXEC_STOP] = "ExecStop",
        [SERVICE_EXEC_STOP_POST] = "ExecStopPost",
};

DEFINE_STRING_TABLE_LOOKUP(service_exec_command, ServiceExecCommand);

const UnitVTable service_vtable = {
        .suffix = ".service",

        .init = service_init,
        .done = service_done,

        .dump = service_dump,

        .start = service_start,
        .stop = service_stop,
        .reload = service_reload,

        .can_reload = service_can_reload,

        .active_state = service_active_state,

        .sigchld_event = service_sigchld_event,
        .timer_event = service_timer_event,

        .cgroup_notify_empty = service_cgroup_notify_event,

        .enumerate = service_enumerate
};
