/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <unistd.h>

#include "bus-error.h"
#include "bus-util.h"
#include "dbus-path.h"
#include "fd-util.h"
#include "fs-util.h"
#include "glob-util.h"
#include "macro.h"
#include "mkdir.h"
#include "path.h"
#include "special.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "unit-name.h"
#include "unit.h"

static const UnitActiveState state_translation_table[_PATH_STATE_MAX] = {
        [PATH_DEAD] = UNIT_INACTIVE,
        [PATH_WAITING] = UNIT_ACTIVE,
        [PATH_RUNNING] = UNIT_ACTIVE,
        [PATH_FAILED] = UNIT_FAILED
};

static int path_dispatch_io(sd_event_source *source, int fd, uint32_t revents, void *userdata);

int path_spec_watch(PathSpec *s, sd_event_io_handler_t handler) {

        static const int flags_table[_PATH_TYPE_MAX] = {
                [PATH_EXISTS] = IN_DELETE_SELF|IN_MOVE_SELF|IN_ATTRIB,
                [PATH_EXISTS_GLOB] = IN_DELETE_SELF|IN_MOVE_SELF|IN_ATTRIB,
                [PATH_CHANGED] = IN_DELETE_SELF|IN_MOVE_SELF|IN_ATTRIB|IN_CLOSE_WRITE|IN_CREATE|IN_DELETE|IN_MOVED_FROM|IN_MOVED_TO,
                [PATH_MODIFIED] = IN_DELETE_SELF|IN_MOVE_SELF|IN_ATTRIB|IN_CLOSE_WRITE|IN_CREATE|IN_DELETE|IN_MOVED_FROM|IN_MOVED_TO|IN_MODIFY,
                [PATH_DIRECTORY_NOT_EMPTY] = IN_DELETE_SELF|IN_MOVE_SELF|IN_ATTRIB|IN_CREATE|IN_MOVED_TO
        };

        bool exists = false;
        char *slash, *oldslash = NULL;
        int r;

        assert(s);
        assert(s->unit);
        assert(handler);

        path_spec_unwatch(s);

        s->inotify_fd = inotify_init1(IN_NONBLOCK|IN_CLOEXEC);
        if (s->inotify_fd < 0) {
                r = -errno;
                goto fail;
        }

        r = sd_event_add_io(s->unit->manager->event, &s->event_source, s->inotify_fd, EPOLLIN, handler, s);
        if (r < 0)
                goto fail;

        (void) sd_event_source_set_description(s->event_source, "path");

        /* This function assumes the path was passed through path_simplify()! */
        assert(!strstr(s->path, "//"));

        for (slash = strchr(s->path, '/'); ; slash = strchr(slash+1, '/')) {
                char *cut = NULL;
                int flags;
                char tmp;

                if (slash) {
                        cut = slash + (slash == s->path);
                        tmp = *cut;
                        *cut = '\0';

                        flags = IN_MOVE_SELF | IN_DELETE_SELF | IN_ATTRIB | IN_CREATE | IN_MOVED_TO;
                } else
                        flags = flags_table[s->type];

                r = inotify_add_watch(s->inotify_fd, s->path, flags);
                if (r < 0) {
                        if (IN_SET(errno, EACCES, ENOENT)) {
                                if (cut)
                                        *cut = tmp;
                                break;
                        }

                        r = log_warning_errno(errno, "Failed to add watch on %s: %s", s->path, errno == ENOSPC ? "too many watches" : strerror(-r));
                        if (cut)
                                *cut = tmp;
                        goto fail;
                } else {
                        exists = true;

                        /* Path exists, we don't need to watch parent too closely. */
                        if (oldslash) {
                                char *cut2 = oldslash + (oldslash == s->path);
                                char tmp2 = *cut2;
                                *cut2 = '\0';

                                (void) inotify_add_watch(s->inotify_fd, s->path, IN_MOVE_SELF);
                                /* Error is ignored, the worst can happen is we get spurious events. */

                                *cut2 = tmp2;
                        }
                }

                if (cut)
                        *cut = tmp;

                if (slash)
                        oldslash = slash;
                else {
                        /* whole path has been iterated over */
                        s->primary_wd = r;
                        break;
                }
        }

        if (!exists) {
                r = log_error_errno(errno, "Failed to add watch on any of the components of %s: %m", s->path);
                /* either EACCESS or ENOENT */
                goto fail;
        }

        return 0;

fail:
        path_spec_unwatch(s);
        return r;
}

void path_spec_unwatch(PathSpec *s) {
        assert(s);

        s->event_source = sd_event_source_unref(s->event_source);
        s->inotify_fd = safe_close(s->inotify_fd);
}

int path_spec_fd_event(PathSpec *s, uint32_t revents) {
        union inotify_event_buffer buffer;
        struct inotify_event *e;
        ssize_t l;
        int r = 0;

        if (revents != EPOLLIN) {
                log_error("Got invalid poll event on inotify.");
                return -EINVAL;
        }

        l = read(s->inotify_fd, &buffer, sizeof(buffer));
        if (l < 0) {
                if (IN_SET(errno, EAGAIN, EINTR))
                        return 0;

                return log_error_errno(errno, "Failed to read inotify event: %m");
        }

        FOREACH_INOTIFY_EVENT(e, buffer, l) {
                if (IN_SET(s->type, PATH_CHANGED, PATH_MODIFIED) &&
                    s->primary_wd == e->wd)
                        r = 1;
        }

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

static void path_spec_mkdir(PathSpec *s, mode_t mode) {
        int r;

        if (IN_SET(s->type, PATH_EXISTS, PATH_EXISTS_GLOB))
                return;

        r = mkdir_p_label(s->path, mode);
        if (r < 0)
                log_warning_errno(r, "mkdir(%s) failed: %m", s->path);
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

void path_free_specs(Path *p) {
        PathSpec *s;

        assert(p);

        while ((s = p->specs)) {
                path_spec_unwatch(s);
                LIST_REMOVE(spec, p->specs, s);
                path_spec_done(s);
                free(s);
        }
}

static void path_done(Unit *u) {
        Path *p = PATH(u);

        assert(p);

        path_free_specs(p);
}

static int path_add_mount_dependencies(Path *p) {
        PathSpec *s;
        int r;

        assert(p);

        LIST_FOREACH(spec, s, p->specs) {
                r = unit_require_mounts_for(UNIT(p), s->path, UNIT_DEPENDENCY_FILE);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int path_verify(Path *p) {
        assert(p);

        if (UNIT(p)->load_state != UNIT_LOADED)
                return 0;

        if (!p->specs) {
                log_unit_error(UNIT(p), "Path unit lacks path setting. Refusing.");
                return -ENOEXEC;
        }

        return 0;
}

static int path_add_default_dependencies(Path *p) {
        int r;

        assert(p);

        if (!UNIT(p)->default_dependencies)
                return 0;

        r = unit_add_dependency_by_name(UNIT(p), UNIT_BEFORE, SPECIAL_PATHS_TARGET, true, UNIT_DEPENDENCY_DEFAULT);
        if (r < 0)
                return r;

        if (MANAGER_IS_SYSTEM(UNIT(p)->manager)) {
                r = unit_add_two_dependencies_by_name(UNIT(p), UNIT_AFTER, UNIT_REQUIRES, SPECIAL_SYSINIT_TARGET, true, UNIT_DEPENDENCY_DEFAULT);
                if (r < 0)
                        return r;
        }

        return unit_add_two_dependencies_by_name(UNIT(p), UNIT_BEFORE, UNIT_CONFLICTS, SPECIAL_SHUTDOWN_TARGET, true, UNIT_DEPENDENCY_DEFAULT);
}

static int path_add_trigger_dependencies(Path *p) {
        Unit *x;
        int r;

        assert(p);

        if (!hashmap_isempty(UNIT(p)->dependencies[UNIT_TRIGGERS]))
                return 0;

        r = unit_load_related_unit(UNIT(p), ".service", &x);
        if (r < 0)
                return r;

        return unit_add_two_dependencies(UNIT(p), UNIT_BEFORE, UNIT_TRIGGERS, x, true, UNIT_DEPENDENCY_IMPLICIT);
}

static int path_load(Unit *u) {
        Path *p = PATH(u);
        int r;

        assert(u);
        assert(u->load_state == UNIT_STUB);

        r = unit_load_fragment_and_dropin(u);
        if (r < 0)
                return r;

        if (u->load_state == UNIT_LOADED) {

                r = path_add_trigger_dependencies(p);
                if (r < 0)
                        return r;

                r = path_add_mount_dependencies(p);
                if (r < 0)
                        return r;

                r = path_add_default_dependencies(p);
                if (r < 0)
                        return r;
        }

        return path_verify(p);
}

static void path_dump(Unit *u, FILE *f, const char *prefix) {
        Path *p = PATH(u);
        Unit *trigger;
        PathSpec *s;

        assert(p);
        assert(f);

        trigger = UNIT_TRIGGER(u);

        fprintf(f,
                "%sPath State: %s\n"
                "%sResult: %s\n"
                "%sUnit: %s\n"
                "%sMakeDirectory: %s\n"
                "%sDirectoryMode: %04o\n",
                prefix, path_state_to_string(p->state),
                prefix, path_result_to_string(p->result),
                prefix, trigger ? trigger->id : "n/a",
                prefix, yes_no(p->make_directory),
                prefix, p->directory_mode);

        LIST_FOREACH(spec, s, p->specs)
                path_spec_dump(s, f, prefix);
}

static void path_unwatch(Path *p) {
        PathSpec *s;

        assert(p);

        LIST_FOREACH(spec, s, p->specs)
                path_spec_unwatch(s);
}

static int path_watch(Path *p) {
        int r;
        PathSpec *s;

        assert(p);

        LIST_FOREACH(spec, s, p->specs) {
                r = path_spec_watch(s, path_dispatch_io);
                if (r < 0)
                        return r;
        }

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
                log_unit_debug(UNIT(p), "Changed %s -> %s", path_state_to_string(old_state), path_state_to_string(state));

        unit_notify(UNIT(p), state_translation_table[old_state], state_translation_table[state], 0);
}

static void path_enter_waiting(Path *p, bool initial, bool recheck);

static int path_coldplug(Unit *u) {
        Path *p = PATH(u);

        assert(p);
        assert(p->state == PATH_DEAD);

        if (p->deserialized_state != p->state) {

                if (IN_SET(p->deserialized_state, PATH_WAITING, PATH_RUNNING))
                        path_enter_waiting(p, true, true);
                else
                        path_set_state(p, p->deserialized_state);
        }

        return 0;
}

static void path_enter_dead(Path *p, PathResult f) {
        assert(p);

        if (p->result == PATH_SUCCESS)
                p->result = f;

        if (p->result != PATH_SUCCESS)
                log_unit_warning(UNIT(p), "Failed with result '%s'.", path_result_to_string(p->result));

        path_set_state(p, p->result != PATH_SUCCESS ? PATH_FAILED : PATH_DEAD);
}

static void path_enter_running(Path *p) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        Unit *trigger;
        int r;

        assert(p);

        /* Don't start job if we are supposed to go down */
        if (unit_stop_pending(UNIT(p)))
                return;

        trigger = UNIT_TRIGGER(UNIT(p));
        if (!trigger) {
                log_unit_error(UNIT(p), "Unit to trigger vanished.");
                path_enter_dead(p, PATH_FAILURE_RESOURCES);
                return;
        }

        r = manager_add_job(UNIT(p)->manager, JOB_START, trigger, JOB_REPLACE, &error, NULL);
        if (r < 0)
                goto fail;

        p->inotify_triggered = false;

        r = path_watch(p);
        if (r < 0)
                goto fail;

        path_set_state(p, PATH_RUNNING);
        return;

fail:
        log_unit_warning(UNIT(p), "Failed to queue unit startup job: %s", bus_error_message(&error, r));
        path_enter_dead(p, PATH_FAILURE_RESOURCES);
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
                        log_unit_debug(UNIT(p), "Got triggered.");
                        path_enter_running(p);
                        return;
                }

        r = path_watch(p);
        if (r < 0)
                goto fail;

        /* Hmm, so now we have created inotify watches, but the file
         * might have appeared/been removed by now, so we must
         * recheck */

        if (recheck)
                if (path_check_good(p, false)) {
                        log_unit_debug(UNIT(p), "Got triggered.");
                        path_enter_running(p);
                        return;
                }

        path_set_state(p, PATH_WAITING);
        return;

fail:
        log_unit_warning_errno(UNIT(p), r, "Failed to enter waiting state: %m");
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
        Unit *trigger;
        int r;

        assert(p);
        assert(IN_SET(p->state, PATH_DEAD, PATH_FAILED));

        trigger = UNIT_TRIGGER(u);
        if (!trigger || trigger->load_state != UNIT_LOADED) {
                log_unit_error(u, "Refusing to start, unit to trigger not loaded.");
                return -ENOENT;
        }

        r = unit_start_limit_test(u);
        if (r < 0) {
                path_enter_dead(p, PATH_FAILURE_START_LIMIT_HIT);
                return r;
        }

        r = unit_acquire_invocation_id(u);
        if (r < 0)
                return r;

        path_mkdir(p);

        p->result = PATH_SUCCESS;
        path_enter_waiting(p, true, true);

        return 1;
}

static int path_stop(Unit *u) {
        Path *p = PATH(u);

        assert(p);
        assert(IN_SET(p->state, PATH_WAITING, PATH_RUNNING));

        path_enter_dead(p, PATH_SUCCESS);
        return 1;
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

                state = path_state_from_string(value);
                if (state < 0)
                        log_unit_debug(u, "Failed to parse state value: %s", value);
                else
                        p->deserialized_state = state;

        } else if (streq(key, "result")) {
                PathResult f;

                f = path_result_from_string(value);
                if (f < 0)
                        log_unit_debug(u, "Failed to parse result value: %s", value);
                else if (f != PATH_SUCCESS)
                        p->result = f;

        } else
                log_unit_debug(u, "Unknown serialization key: %s", key);

        return 0;
}

_pure_ static UnitActiveState path_active_state(Unit *u) {
        assert(u);

        return state_translation_table[PATH(u)->state];
}

_pure_ static const char *path_sub_state_to_string(Unit *u) {
        assert(u);

        return path_state_to_string(PATH(u)->state);
}

static int path_dispatch_io(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        PathSpec *s = userdata;
        Path *p;
        int changed;

        assert(s);
        assert(s->unit);
        assert(fd >= 0);

        p = PATH(s->unit);

        if (!IN_SET(p->state, PATH_WAITING, PATH_RUNNING))
                return 0;

        /* log_debug("inotify wakeup on %s.", u->id); */

        LIST_FOREACH(spec, s, p->specs)
                if (path_spec_owns_inotify_fd(s, fd))
                        break;

        if (!s) {
                log_error("Got event on unknown fd.");
                goto fail;
        }

        changed = path_spec_fd_event(s, revents);
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

        return 0;

fail:
        path_enter_dead(p, PATH_FAILURE_RESOURCES);
        return 0;
}

static void path_trigger_notify(Unit *u, Unit *other) {
        Path *p = PATH(u);

        assert(u);
        assert(other);

        /* Invoked whenever the unit we trigger changes state or gains
         * or loses a job */

        if (other->load_state != UNIT_LOADED)
                return;

        if (p->state == PATH_RUNNING &&
            UNIT_IS_INACTIVE_OR_FAILED(unit_active_state(other))) {
                log_unit_debug(UNIT(p), "Got notified about unit deactivation.");

                /* Hmm, so inotify was triggered since the
                 * last activation, so I guess we need to
                 * recheck what is going on. */
                path_enter_waiting(p, false, p->inotify_triggered);
        }
}

static void path_reset_failed(Unit *u) {
        Path *p = PATH(u);

        assert(p);

        if (p->state == PATH_FAILED)
                path_set_state(p, PATH_DEAD);

        p->result = PATH_SUCCESS;
}

static const char* const path_type_table[_PATH_TYPE_MAX] = {
        [PATH_EXISTS] = "PathExists",
        [PATH_EXISTS_GLOB] = "PathExistsGlob",
        [PATH_DIRECTORY_NOT_EMPTY] = "DirectoryNotEmpty",
        [PATH_CHANGED] = "PathChanged",
        [PATH_MODIFIED] = "PathModified",
};

DEFINE_STRING_TABLE_LOOKUP(path_type, PathType);

static const char* const path_result_table[_PATH_RESULT_MAX] = {
        [PATH_SUCCESS] = "success",
        [PATH_FAILURE_RESOURCES] = "resources",
        [PATH_FAILURE_START_LIMIT_HIT] = "start-limit-hit",
};

DEFINE_STRING_TABLE_LOOKUP(path_result, PathResult);

const UnitVTable path_vtable = {
        .object_size = sizeof(Path),

        .sections =
                "Unit\0"
                "Path\0"
                "Install\0",
        .private_section = "Path",

        .can_transient = true,

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

        .trigger_notify = path_trigger_notify,

        .reset_failed = path_reset_failed,

        .bus_vtable = bus_path_vtable,
        .bus_set_property = bus_path_set_property,
};
