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

#include <sys/inotify.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <unistd.h>

#include "unit.h"
#include "unit-name.h"
#include "path.h"
#include "dbus-path.h"

static const UnitActiveState state_translation_table[_PATH_STATE_MAX] = {
        [PATH_DEAD] = UNIT_INACTIVE,
        [PATH_WAITING] = UNIT_ACTIVE,
        [PATH_RUNNING] = UNIT_ACTIVE,
        [PATH_MAINTENANCE] = UNIT_MAINTENANCE
};

static void path_done(Unit *u) {
        Path *p = PATH(u);
        PathSpec *s;

        assert(p);

        while ((s = p->specs)) {
                LIST_REMOVE(PathSpec, spec, p->specs, s);
                free(s);
        }
}

int path_add_one_mount_link(Path *p, Mount *m) {
        PathSpec *s;
        int r;

        assert(p);
        assert(m);

        if (p->meta.load_state != UNIT_LOADED ||
            m->meta.load_state != UNIT_LOADED)
                return 0;

        LIST_FOREACH(spec, s, p->specs) {

                if (!path_startswith(s->path, m->where))
                        continue;

                if ((r = unit_add_two_dependencies(UNIT(p), UNIT_AFTER, UNIT_REQUIRES, UNIT(m), true)) < 0)
                        return r;
        }

        return 0;
}

static int path_add_mount_links(Path *p) {
        Meta *other;
        int r;

        assert(p);

        LIST_FOREACH(units_per_type, other, p->meta.manager->units_per_type[UNIT_MOUNT])
                if ((r = path_add_one_mount_link(p, (Mount*) other)) < 0)
                        return r;

        return 0;
}

static int path_verify(Path *p) {
        assert(p);

        if (p->meta.load_state != UNIT_LOADED)
                return 0;

        if (!p->specs) {
                log_error("%s lacks path setting. Refusing.", p->meta.id);
                return -EINVAL;
        }

        return 0;
}

static int path_load(Unit *u) {
        Path *p = PATH(u);
        int r;

        assert(u);
        assert(u->meta.load_state == UNIT_STUB);

        if ((r = unit_load_fragment_and_dropin(u)) < 0)
                return r;

        if (u->meta.load_state == UNIT_LOADED) {

                if (!p->unit)
                        if ((r = unit_load_related_unit(u, ".service", &p->unit)))
                                return r;

                if ((r = unit_add_dependency(u, UNIT_BEFORE, p->unit, true)) < 0)
                        return r;

                if ((r = path_add_mount_links(p)) < 0)
                        return r;
        }

        return path_verify(p);
}

static void path_dump(Unit *u, FILE *f, const char *prefix) {
        Path *p = PATH(u);
        const char *prefix2;
        char *p2;
        PathSpec *s;

        p2 = strappend(prefix, "\t");
        prefix2 = p2 ? p2 : prefix;

        fprintf(f,
                "%sPath State: %s\n"
                "%sUnit: %s\n",
                prefix, path_state_to_string(p->state),
                prefix, p->unit->meta.id);

        LIST_FOREACH(spec, s, p->specs)
                fprintf(f,
                        "%s%s: %s\n",
                        prefix,
                        path_type_to_string(s->type),
                        s->path);

        free(p2);
}

static void path_unwatch_one(Path *p, PathSpec *s) {

        if (s->inotify_fd < 0)
                return;

        unit_unwatch_fd(UNIT(p), &s->watch);

        close_nointr_nofail(s->inotify_fd);
        s->inotify_fd = -1;
}

static int path_watch_one(Path *p, PathSpec *s) {
        static const int flags_table[_PATH_TYPE_MAX] = {
                [PATH_EXISTS] = IN_DELETE_SELF|IN_MOVE_SELF,
                [PATH_CHANGED] = IN_DELETE_SELF|IN_MOVE_SELF|IN_ATTRIB|IN_CLOSE_WRITE|IN_CREATE|IN_DELETE|IN_MOVED_FROM|IN_MOVED_TO,
                [PATH_DIRECTORY_NOT_EMPTY] = IN_DELETE_SELF|IN_MOVE_SELF|IN_CREATE|IN_MOVED_TO
        };

        bool exists = false;
        char *k;
        int r;

        assert(p);
        assert(s);

        path_unwatch_one(p, s);

        if (!(k = strdup(s->path)))
                return -ENOMEM;

        if ((s->inotify_fd = inotify_init1(IN_NONBLOCK|IN_CLOEXEC)) < 0) {
                r = -errno;
                goto fail;
        }

        if (unit_watch_fd(UNIT(p), s->inotify_fd, EPOLLIN, &s->watch) < 0) {
                r = -errno;
                goto fail;
        }

        if ((s->primary_wd = inotify_add_watch(s->inotify_fd, k, flags_table[s->type])) >= 0)
                exists = true;

        for (;;) {
                int flags;
                char *slash;

                /* This assumes the path was passed through path_kill_slashes()! */
                if (!(slash = strrchr(k, '/')))
                        break;

                *slash = 0;

                flags = IN_DELETE_SELF|IN_MOVE_SELF;
                if (!exists)
                        flags |= IN_CREATE | IN_MOVED_TO | IN_ATTRIB;

                if (inotify_add_watch(s->inotify_fd, k, flags) >= 0)
                        exists = true;
        }

        return 0;

fail:
        free(k);

        path_unwatch_one(p, s);
        return r;
}

static void path_unwatch(Path *p) {
        PathSpec *s;

        assert(p);

        LIST_FOREACH(spec, s, p->specs)
                path_unwatch_one(p, s);
}

static int path_watch(Path *p) {
        int r;
        PathSpec *s;

        assert(p);

        LIST_FOREACH(spec, s, p->specs)
                if ((r = path_watch_one(p, s)) < 0)
                        return r;

        return 0;
}

static void path_set_state(Path *p, PathState state) {
        PathState old_state;
        assert(p);

        old_state = p->state;
        p->state = state;

        if (state != PATH_WAITING)
                path_unwatch(p);

        if (state != old_state)
                log_debug("%s changed %s -> %s",
                          p->meta.id,
                          path_state_to_string(old_state),
                          path_state_to_string(state));

        unit_notify(UNIT(p), state_translation_table[old_state], state_translation_table[state]);
}

static void path_enter_waiting(Path *p, bool initial);

static int path_coldplug(Unit *u) {
        Path *p = PATH(u);

        assert(p);
        assert(p->state == PATH_DEAD);

        if (p->deserialized_state != p->state) {

                if (p->deserialized_state == PATH_WAITING ||
                    p->deserialized_state == PATH_RUNNING)
                        path_enter_waiting(p, true);
                else
                        path_set_state(p, p->deserialized_state);
        }

        return 0;
}

static void path_enter_dead(Path *p, bool success) {
        assert(p);

        if (!success)
                p->failure = true;

        path_set_state(p, p->failure ? PATH_MAINTENANCE : PATH_DEAD);
}

static void path_enter_running(Path *p) {
        int r;
        assert(p);

        if ((r = manager_add_job(p->meta.manager, JOB_START, p->unit, JOB_REPLACE, true, NULL)) < 0)
                goto fail;

        path_set_state(p, PATH_RUNNING);
        return;

fail:
        log_warning("%s failed to queue unit startup job: %s", p->meta.id, strerror(-r));
        path_enter_dead(p, false);
}


static void path_enter_waiting(Path *p, bool initial) {
        PathSpec *s;
        int r;
        bool good = false;

        LIST_FOREACH(spec, s, p->specs) {

                switch (s->type) {

                case PATH_EXISTS:
                        good = access(s->path, F_OK) >= 0;
                        break;

                case PATH_DIRECTORY_NOT_EMPTY:
                        good = dir_is_empty(s->path) == 0;
                        break;

                case PATH_CHANGED: {
                        bool b;

                        b = access(s->path, F_OK) >= 0;
                        good = !initial && b != s->previous_exists;
                        s->previous_exists = b;
                        break;
                }

                default:
                        ;
                }

                if (good)
                        break;
        }

        if (good) {
                path_enter_running(p);
                return;
        }

        if ((r = path_watch(p)) < 0)
                goto fail;

        path_set_state(p, PATH_WAITING);
        return;

fail:
        log_warning("%s failed to enter waiting state: %s", p->meta.id, strerror(-r));
        path_enter_dead(p, false);
}

static int path_start(Unit *u) {
        Path *p = PATH(u);

        assert(p);
        assert(p->state == PATH_DEAD || p->state == PATH_MAINTENANCE);

        if (p->unit->meta.load_state != UNIT_LOADED)
                return -ENOENT;

        p->failure = false;
path_enter_waiting(p, true);
        return 0;
}

static int path_stop(Unit *u) {
        Path *p = PATH(u);

        assert(p);
        assert(p->state == PATH_WAITING || p->state == PATH_RUNNING);

        path_enter_dead(p, true);
        return 0;
}

static int path_serialize(Unit *u, FILE *f, FDSet *fds) {
        Path *p = PATH(u);

        assert(u);
        assert(f);
        assert(fds);

        unit_serialize_item(u, f, "state", path_state_to_string(p->state));

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
        int l;
        ssize_t k;
        struct inotify_event *buf = NULL;
        PathSpec *s;

        assert(p);
        assert(fd >= 0);

        if (p->state != PATH_WAITING)
                return;

        log_debug("inotify wakeup on %s.", u->meta.id);

        if (events != EPOLLIN) {
                log_error("Got Invalid poll event on inotify.");
                goto fail;
        }

        LIST_FOREACH(spec, s, p->specs)
                if (s->inotify_fd == fd)
                        break;

        if (!s) {
                log_error("Got event on unknown fd.");
                goto fail;
        }

        if (ioctl(fd, FIONREAD, &l) < 0) {
                log_error("FIONREAD failed: %s", strerror(errno));
                goto fail;
        }

        if (!(buf = malloc(l))) {
                log_error("Failed to allocate buffer: %s", strerror(-ENOMEM));
                goto fail;
        }

        if ((k = read(fd, buf, l)) < 0) {
                log_error("Failed to read inotify event: %s", strerror(-errno));
                goto fail;
        }

        if ((size_t) k < sizeof(struct inotify_event) ||
            (size_t) k < sizeof(struct inotify_event) + buf->len) {
                log_error("inotify event too small.");
                goto fail;
        }

        if (s->type == PATH_CHANGED && s->primary_wd == buf->wd)
                path_enter_running(p);
        else
                path_enter_waiting(p, false);

        free(buf);

        return;

fail:
        free(buf);
        path_enter_dead(p, false);
}

void path_unit_notify(Unit *u, UnitActiveState new_state) {
        char *n;
        int r;
        Iterator i;

        if (u->meta.type == UNIT_PATH)
                return;

        SET_FOREACH(n, u->meta.names, i) {
                char *k;
                Unit *t;
                Path *p;

                if (!(k = unit_name_change_suffix(n, ".path"))) {
                        r = -ENOMEM;
                        goto fail;
                }

                t = manager_get_unit(u->meta.manager, k);
                free(k);

                if (!t)
                        continue;

                if (t->meta.load_state != UNIT_LOADED)
                        continue;

                p = PATH(t);

                if (p->unit != u)
                        continue;

                if (p->state == PATH_RUNNING && new_state == UNIT_INACTIVE) {
                        log_debug("%s got notified about unit deactivation.", p->meta.id);
                        path_enter_waiting(p, false);
                }
        }

        return;

fail:
        log_error("Failed find path unit: %s", strerror(-r));
}

static const char* const path_state_table[_PATH_STATE_MAX] = {
        [PATH_DEAD] = "dead",
        [PATH_WAITING] = "waiting",
        [PATH_RUNNING] = "running",
        [PATH_MAINTENANCE] = "maintenance"
};

DEFINE_STRING_TABLE_LOOKUP(path_state, PathState);

static const char* const path_type_table[_PATH_TYPE_MAX] = {
        [PATH_EXISTS] = "PathExists",
        [PATH_CHANGED] = "PathChanged",
        [PATH_DIRECTORY_NOT_EMPTY] = "DirectoryNotEmpty"
};

DEFINE_STRING_TABLE_LOOKUP(path_type, PathType);

const UnitVTable path_vtable = {
        .suffix = ".path",

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

        .bus_message_handler = bus_path_message_handler
};
