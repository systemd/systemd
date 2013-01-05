/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <sys/inotify.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <unistd.h>

#include "unit.h"
#include "unit-name.h"
#include "path.h"
#include "mkdir.h"
#include "dbus-path.h"
#include "special.h"
#include "bus-errors.h"
#include "path-util.h"

static const UnitActiveState state_translation_table[_PATH_STATE_MAX] = {
        [PATH_DEAD] = UNIT_INACTIVE,
        [PATH_WAITING] = UNIT_ACTIVE,
        [PATH_RUNNING] = UNIT_ACTIVE,
        [PATH_FAILED] = UNIT_FAILED
};

int path_spec_watch(PathSpec *s, Unit *u) {

        static const int flags_table[_PATH_TYPE_MAX] = {
                [PATH_EXISTS] = IN_DELETE_SELF|IN_MOVE_SELF|IN_ATTRIB,
                [PATH_EXISTS_GLOB] = IN_DELETE_SELF|IN_MOVE_SELF|IN_ATTRIB,
                [PATH_CHANGED] = IN_DELETE_SELF|IN_MOVE_SELF|IN_ATTRIB|IN_CLOSE_WRITE|IN_CREATE|IN_DELETE|IN_MOVED_FROM|IN_MOVED_TO,
                [PATH_MODIFIED] = IN_DELETE_SELF|IN_MOVE_SELF|IN_ATTRIB|IN_CLOSE_WRITE|IN_CREATE|IN_DELETE|IN_MOVED_FROM|IN_MOVED_TO|IN_MODIFY,
                [PATH_DIRECTORY_NOT_EMPTY] = IN_DELETE_SELF|IN_MOVE_SELF|IN_ATTRIB|IN_CREATE|IN_MOVED_TO
        };

        bool exists = false;
        char *k, *slash;
        int r;

        assert(u);
        assert(s);

        path_spec_unwatch(s, u);

        if (!(k = strdup(s->path)))
                return -ENOMEM;

        if ((s->inotify_fd = inotify_init1(IN_NONBLOCK|IN_CLOEXEC)) < 0) {
                r = -errno;
                goto fail;
        }

        if (unit_watch_fd(u, s->inotify_fd, EPOLLIN, &s->watch) < 0) {
                r = -errno;
                goto fail;
        }

        s->primary_wd = inotify_add_watch(s->inotify_fd, k, flags_table[s->type]);
        if (s->primary_wd >= 0)
                exists = true;

        do {
                int flags;

                /* This assumes the path was passed through path_kill_slashes()! */
                slash = strrchr(k, '/');
                if (!slash)
                        break;

                /* Trim the path at the last slash. Keep the slash if it's the root dir. */
                slash[slash == k] = 0;

                flags = IN_MOVE_SELF;
                if (!exists)
                        flags |= IN_DELETE_SELF | IN_ATTRIB | IN_CREATE | IN_MOVED_TO;

                if (inotify_add_watch(s->inotify_fd, k, flags) >= 0)
                        exists = true;
        } while (slash != k);

        return 0;

fail:
        free(k);

        path_spec_unwatch(s, u);
        return r;
}

void path_spec_unwatch(PathSpec *s, Unit *u) {

        if (s->inotify_fd < 0)
                return;

        unit_unwatch_fd(u, &s->watch);

        close_nointr_nofail(s->inotify_fd);
        s->inotify_fd = -1;
}

int path_spec_fd_event(PathSpec *s, uint32_t events) {
        uint8_t *buf = NULL;
        struct inotify_event *e;
        ssize_t k;
        int l;
        int r = 0;

        if (events != EPOLLIN) {
                log_error("Got invalid poll event on inotify.");
                r = -EINVAL;
                goto out;
        }

        if (ioctl(s->inotify_fd, FIONREAD, &l) < 0) {
                log_error("FIONREAD failed: %m");
                r = -errno;
                goto out;
        }

        assert(l > 0);

        buf = malloc(l);
        if (!buf) {
                log_error("Failed to allocate buffer: %m");
                r = -errno;
                goto out;
        }

        k = read(s->inotify_fd, buf, l);
        if (k < 0) {
                log_error("Failed to read inotify event: %m");
                r = -errno;
                goto out;
        }

        e = (struct inotify_event*) buf;

        while (k > 0) {
                size_t step;

                if ((s->type == PATH_CHANGED || s->type == PATH_MODIFIED) &&
                    s->primary_wd == e->wd)
                        r = 1;

                step = sizeof(struct inotify_event) + e->len;
                assert(step <= (size_t) k);

                e = (struct inotify_event*) ((uint8_t*) e + step);
                k -= step;
        }
out:
        free(buf);
        return r;
}

static bool path_spec_check_good(PathSpec *s, bool initial) {
        bool good = false;

        switch (s->type) {

        case PATH_EXISTS:
                good = access(s->path, F_OK) >= 0;
                break;

        case PATH_EXISTS_GLOB:
                good = glob_exists(s->path) > 0;
                break;

        case PATH_DIRECTORY_NOT_EMPTY: {
                int k;

                k = dir_is_empty(s->path);
                good = !(k == -ENOENT || k > 0);
                break;
        }

        case PATH_CHANGED:
        case PATH_MODIFIED: {
                bool b;

                b = access(s->path, F_OK) >= 0;
                good = !initial && b != s->previous_exists;
                s->previous_exists = b;
                break;
        }

        default:
                ;
        }

        return good;
}

static bool path_spec_startswith(PathSpec *s, const char *what) {
        return path_startswith(s->path, what);
}

static void path_spec_mkdir(PathSpec *s, mode_t mode) {
        int r;

        if (s->type == PATH_EXISTS || s->type == PATH_EXISTS_GLOB)
                return;

        r = mkdir_p_label(s->path, mode);
        if (r < 0)
                log_warning("mkdir(%s) failed: %s", s->path, strerror(-r));
}

static void path_spec_dump(PathSpec *s, FILE *f, const char *prefix) {
        fprintf(f,
                "%s%s: %s\n",
                prefix,
                path_type_to_string(s->type),
                s->path);
}

void path_spec_done(PathSpec *s) {
        assert(s);
        assert(s->inotify_fd == -1);

        free(s->path);
}

static void path_init(Unit *u) {
        Path *p = PATH(u);

        assert(u);
        assert(u->load_state == UNIT_STUB);

        p->directory_mode = 0755;
}

static void path_done(Unit *u) {
        Path *p = PATH(u);
        PathSpec *s;

        assert(p);

        unit_ref_unset(&p->unit);

        while ((s = p->specs)) {
                path_spec_unwatch(s, u);
                LIST_REMOVE(PathSpec, spec, p->specs, s);
                path_spec_done(s);
                free(s);
        }
}

int path_add_one_mount_link(Path *p, Mount *m) {
        PathSpec *s;
        int r;

        assert(p);
        assert(m);

        if (UNIT(p)->load_state != UNIT_LOADED ||
            UNIT(m)->load_state != UNIT_LOADED)
                return 0;

        LIST_FOREACH(spec, s, p->specs) {

                if (!path_spec_startswith(s, m->where))
                        continue;

                if ((r = unit_add_two_dependencies(UNIT(p), UNIT_AFTER, UNIT_REQUIRES, UNIT(m), true)) < 0)
                        return r;
        }

        return 0;
}

static int path_add_mount_links(Path *p) {
        Unit *other;
        int r;

        assert(p);

        LIST_FOREACH(units_by_type, other, UNIT(p)->manager->units_by_type[UNIT_MOUNT])
                if ((r = path_add_one_mount_link(p, MOUNT(other))) < 0)
                        return r;

        return 0;
}

static int path_verify(Path *p) {
        assert(p);

        if (UNIT(p)->load_state != UNIT_LOADED)
                return 0;

        if (!p->specs) {
                log_error("%s lacks path setting. Refusing.", UNIT(p)->id);
                return -EINVAL;
        }

        return 0;
}

static int path_add_default_dependencies(Path *p) {
        int r;

        assert(p);

        if (UNIT(p)->manager->running_as == SYSTEMD_SYSTEM) {
                if ((r = unit_add_dependency_by_name(UNIT(p), UNIT_BEFORE, SPECIAL_BASIC_TARGET, NULL, true)) < 0)
                        return r;

                if ((r = unit_add_two_dependencies_by_name(UNIT(p), UNIT_AFTER, UNIT_REQUIRES, SPECIAL_SYSINIT_TARGET, NULL, true)) < 0)
                        return r;
        }

        return unit_add_two_dependencies_by_name(UNIT(p), UNIT_BEFORE, UNIT_CONFLICTS, SPECIAL_SHUTDOWN_TARGET, NULL, true);
}

static int path_load(Unit *u) {
        Path *p = PATH(u);
        int r;

        assert(u);
        assert(u->load_state == UNIT_STUB);

        if ((r = unit_load_fragment_and_dropin(u)) < 0)
                return r;

        if (u->load_state == UNIT_LOADED) {

                if (!UNIT_DEREF(p->unit)) {
                        Unit *x;

                        r = unit_load_related_unit(u, ".service", &x);
                        if (r < 0)
                                return r;

                        unit_ref_set(&p->unit, x);
                }

                r = unit_add_two_dependencies(u, UNIT_BEFORE, UNIT_TRIGGERS, UNIT_DEREF(p->unit), true);
                if (r < 0)
                        return r;

                if ((r = path_add_mount_links(p)) < 0)
                        return r;

                if (UNIT(p)->default_dependencies)
                        if ((r = path_add_default_dependencies(p)) < 0)
                                return r;
        }

        return path_verify(p);
}

static void path_dump(Unit *u, FILE *f, const char *prefix) {
        Path *p = PATH(u);
        PathSpec *s;

        assert(p);
        assert(f);

        fprintf(f,
                "%sPath State: %s\n"
                "%sResult: %s\n"
                "%sUnit: %s\n"
                "%sMakeDirectory: %s\n"
                "%sDirectoryMode: %04o\n",
                prefix, path_state_to_string(p->state),
                prefix, path_result_to_string(p->result),
                prefix, UNIT_DEREF(p->unit)->id,
                prefix, yes_no(p->make_directory),
                prefix, p->directory_mode);

        LIST_FOREACH(spec, s, p->specs)
                path_spec_dump(s, f, prefix);
}

static void path_unwatch(Path *p) {
        PathSpec *s;

        assert(p);

        LIST_FOREACH(spec, s, p->specs)
                path_spec_unwatch(s, UNIT(p));
}

static int path_watch(Path *p) {
        int r;
        PathSpec *s;

        assert(p);

        LIST_FOREACH(spec, s, p->specs)
                if ((r = path_spec_watch(s, UNIT(p))) < 0)
                        return r;

        return 0;
}

static void path_set_state(Path *p, PathState state) {
        PathState old_state;
        assert(p);

        old_state = p->state;
        p->state = state;

        if (state != PATH_WAITING &&
            (state != PATH_RUNNING || p->inotify_triggered))
                path_unwatch(p);

        if (state != old_state)
                log_debug("%s changed %s -> %s",
                          UNIT(p)->id,
                          path_state_to_string(old_state),
                          path_state_to_string(state));

        unit_notify(UNIT(p), state_translation_table[old_state], state_translation_table[state], true);
}

static void path_enter_waiting(Path *p, bool initial, bool recheck);

static int path_coldplug(Unit *u) {
        Path *p = PATH(u);

        assert(p);
        assert(p->state == PATH_DEAD);

        if (p->deserialized_state != p->state) {

                if (p->deserialized_state == PATH_WAITING ||
                    p->deserialized_state == PATH_RUNNING)
                        path_enter_waiting(p, true, true);
                else
                        path_set_state(p, p->deserialized_state);
        }

        return 0;
}

static void path_enter_dead(Path *p, PathResult f) {
        assert(p);

        if (f != PATH_SUCCESS)
                p->result = f;

        path_set_state(p, p->result != PATH_SUCCESS ? PATH_FAILED : PATH_DEAD);
}

static void path_enter_running(Path *p) {
        int r;
        DBusError error;

        assert(p);
        dbus_error_init(&error);

        /* Don't start job if we are supposed to go down */
        if (UNIT(p)->job && UNIT(p)->job->type == JOB_STOP)
                return;

        if ((r = manager_add_job(UNIT(p)->manager, JOB_START, UNIT_DEREF(p->unit), JOB_REPLACE, true, &error, NULL)) < 0)
                goto fail;

        p->inotify_triggered = false;

        if ((r = path_watch(p)) < 0)
                goto fail;

        path_set_state(p, PATH_RUNNING);
        return;

fail:
        log_warning("%s failed to queue unit startup job: %s", UNIT(p)->id, bus_error(&error, r));
        path_enter_dead(p, PATH_FAILURE_RESOURCES);

        dbus_error_free(&error);
}

static bool path_check_good(Path *p, bool initial) {
        PathSpec *s;
        bool good = false;

        assert(p);

        LIST_FOREACH(spec, s, p->specs) {
                good = path_spec_check_good(s, initial);

                if (good)
                        break;
        }

        return good;
}

static void path_enter_waiting(Path *p, bool initial, bool recheck) {
        int r;

        if (recheck)
                if (path_check_good(p, initial)) {
                        log_debug("%s got triggered.", UNIT(p)->id);
                        path_enter_running(p);
                        return;
                }

        if ((r = path_watch(p)) < 0)
                goto fail;

        /* Hmm, so now we have created inotify watches, but the file
         * might have appeared/been removed by now, so we must
         * recheck */

        if (recheck)
                if (path_check_good(p, false)) {
                        log_debug("%s got triggered.", UNIT(p)->id);
                        path_enter_running(p);
                        return;
                }

        path_set_state(p, PATH_WAITING);
        return;

fail:
        log_warning("%s failed to enter waiting state: %s", UNIT(p)->id, strerror(-r));
        path_enter_dead(p, PATH_FAILURE_RESOURCES);
}

static void path_mkdir(Path *p) {
        PathSpec *s;

        assert(p);

        if (!p->make_directory)
                return;

        LIST_FOREACH(spec, s, p->specs)
                path_spec_mkdir(s, p->directory_mode);
}

static int path_start(Unit *u) {
        Path *p = PATH(u);

        assert(p);
        assert(p->state == PATH_DEAD || p->state == PATH_FAILED);

        if (UNIT_DEREF(p->unit)->load_state != UNIT_LOADED)
                return -ENOENT;

        path_mkdir(p);

        p->result = PATH_SUCCESS;
        path_enter_waiting(p, true, true);

        return 0;
}

static int path_stop(Unit *u) {
        Path *p = PATH(u);

        assert(p);
        assert(p->state == PATH_WAITING || p->state == PATH_RUNNING);

        path_enter_dead(p, PATH_SUCCESS);
        return 0;
}

static int path_serialize(Unit *u, FILE *f, FDSet *fds) {
        Path *p = PATH(u);

        assert(u);
        assert(f);
        assert(fds);

        unit_serialize_item(u, f, "state", path_state_to_string(p->state));
        unit_serialize_item(u, f, "result", path_result_to_string(p->result));

        return 0;
}

static int path_deserialize_item(Unit *u, const char *key, const char *value, FDSet *fds) {
        Path *p = PATH(u);

        assert(u);
        assert(key);
        assert(value);
        assert(fds);

        if (streq(key, "state")) {
                PathState state;

                if ((state = path_state_from_string(value)) < 0)
                        log_debug("Failed to parse state value %s", value);
                else
                        p->deserialized_state = state;

        } else if (streq(key, "result")) {
                PathResult f;

                f = path_result_from_string(value);
                if (f < 0)
                        log_debug("Failed to parse result value %s", value);
                else if (f != PATH_SUCCESS)
                        p->result = f;

        } else
                log_debug("Unknown serialization key '%s'", key);

        return 0;
}

static UnitActiveState path_active_state(Unit *u) {
        assert(u);

        return state_translation_table[PATH(u)->state];
}

static const char *path_sub_state_to_string(Unit *u) {
        assert(u);

        return path_state_to_string(PATH(u)->state);
}

static void path_fd_event(Unit *u, int fd, uint32_t events, Watch *w) {
        Path *p = PATH(u);
        PathSpec *s;
        int changed;

        assert(p);
        assert(fd >= 0);

        if (p->state != PATH_WAITING &&
            p->state != PATH_RUNNING)
                return;

        /* log_debug("inotify wakeup on %s.", u->id); */

        LIST_FOREACH(spec, s, p->specs)
                if (path_spec_owns_inotify_fd(s, fd))
                        break;

        if (!s) {
                log_error("Got event on unknown fd.");
                goto fail;
        }

        changed = path_spec_fd_event(s, events);
        if (changed < 0)
                goto fail;

        /* If we are already running, then remember that one event was
         * dispatched so that we restart the service only if something
         * actually changed on disk */
        p->inotify_triggered = true;

        if (changed)
                path_enter_running(p);
        else
                path_enter_waiting(p, false, true);

        return;

fail:
        path_enter_dead(p, PATH_FAILURE_RESOURCES);
}

void path_unit_notify(Unit *u, UnitActiveState new_state) {
        Iterator i;
        Unit *k;

        if (u->type == UNIT_PATH)
                return;

        SET_FOREACH(k, u->dependencies[UNIT_TRIGGERED_BY], i) {
                Path *p;

                if (k->type != UNIT_PATH)
                        continue;

                if (k->load_state != UNIT_LOADED)
                        continue;

                p = PATH(k);

                if (p->state == PATH_RUNNING && new_state == UNIT_INACTIVE) {
                        log_debug("%s got notified about unit deactivation.", UNIT(p)->id);

                        /* Hmm, so inotify was triggered since the
                         * last activation, so I guess we need to
                         * recheck what is going on. */
                        path_enter_waiting(p, false, p->inotify_triggered);
                }
        }
}

static void path_reset_failed(Unit *u) {
        Path *p = PATH(u);

        assert(p);

        if (p->state == PATH_FAILED)
                path_set_state(p, PATH_DEAD);

        p->result = PATH_SUCCESS;
}

static const char* const path_state_table[_PATH_STATE_MAX] = {
        [PATH_DEAD] = "dead",
        [PATH_WAITING] = "waiting",
        [PATH_RUNNING] = "running",
        [PATH_FAILED] = "failed"
};

DEFINE_STRING_TABLE_LOOKUP(path_state, PathState);

static const char* const path_type_table[_PATH_TYPE_MAX] = {
        [PATH_EXISTS] = "PathExists",
        [PATH_EXISTS_GLOB] = "PathExistsGlob",
        [PATH_CHANGED] = "PathChanged",
        [PATH_MODIFIED] = "PathModified",
        [PATH_DIRECTORY_NOT_EMPTY] = "DirectoryNotEmpty"
};

DEFINE_STRING_TABLE_LOOKUP(path_type, PathType);

static const char* const path_result_table[_PATH_RESULT_MAX] = {
        [PATH_SUCCESS] = "success",
        [PATH_FAILURE_RESOURCES] = "resources"
};

DEFINE_STRING_TABLE_LOOKUP(path_result, PathResult);

const UnitVTable path_vtable = {
        .object_size = sizeof(Path),
        .sections =
                "Unit\0"
                "Path\0"
                "Install\0",

        .init = path_init,
        .done = path_done,
        .load = path_load,

        .coldplug = path_coldplug,

        .dump = path_dump,

        .start = path_start,
        .stop = path_stop,

        .serialize = path_serialize,
        .deserialize_item = path_deserialize_item,

        .active_state = path_active_state,
        .sub_state_to_string = path_sub_state_to_string,

        .fd_event = path_fd_event,

        .reset_failed = path_reset_failed,

        .bus_interface = "org.freedesktop.systemd1.Path",
        .bus_message_handler = bus_path_message_handler,
        .bus_invalidating_properties = bus_path_invalidating_properties
};
