/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <unistd.h>

#include "bus-error.h"
#include "bus-util.h"
#include "dbus-path.h"
#include "dbus-unit.h"
#include "escape.h"
#include "event-util.h"
#include "fd-util.h"
#include "glob-util.h"
#include "inotify-util.h"
#include "macro.h"
#include "mkdir-label.h"
#include "path.h"
#include "path-util.h"
#include "serialize.h"
#include "special.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "unit-name.h"
#include "unit.h"

static const UnitActiveState state_translation_table[_PATH_STATE_MAX] = {
        [PATH_DEAD]    = UNIT_INACTIVE,
        [PATH_WAITING] = UNIT_ACTIVE,
        [PATH_RUNNING] = UNIT_ACTIVE,
        [PATH_FAILED]  = UNIT_FAILED,
};

static int path_dispatch_io(sd_event_source *source, int fd, uint32_t revents, void *userdata);

int path_spec_watch(PathSpec *s, sd_event_io_handler_t handler) {
        static const int flags_table[_PATH_TYPE_MAX] = {
                [PATH_EXISTS]              = IN_DELETE_SELF|IN_MOVE_SELF|IN_ATTRIB,
                [PATH_EXISTS_GLOB]         = IN_DELETE_SELF|IN_MOVE_SELF|IN_ATTRIB,
                [PATH_CHANGED]             = IN_DELETE_SELF|IN_MOVE_SELF|IN_ATTRIB|IN_CLOSE_WRITE|IN_CREATE|IN_DELETE|IN_MOVED_FROM|IN_MOVED_TO,
                [PATH_MODIFIED]            = IN_DELETE_SELF|IN_MOVE_SELF|IN_ATTRIB|IN_CLOSE_WRITE|IN_CREATE|IN_DELETE|IN_MOVED_FROM|IN_MOVED_TO|IN_MODIFY,
                [PATH_DIRECTORY_NOT_EMPTY] = IN_DELETE_SELF|IN_MOVE_SELF|IN_ATTRIB|IN_CREATE|IN_MOVED_TO,
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
                r = log_error_errno(errno, "Failed to allocate inotify fd: %m");
                goto fail;
        }

        r = sd_event_add_io(s->unit->manager->event, &s->event_source, s->inotify_fd, EPOLLIN, handler, s);
        if (r < 0) {
                log_error_errno(r, "Failed to add inotify fd to event loop: %m");
                goto fail;
        }

        (void) sd_event_source_set_description(s->event_source, "path");

        /* This function assumes the path was passed through path_simplify()! */
        assert(!strstr(s->path, "//"));

        for (slash = strchr(s->path, '/'); ; slash = strchr(slash+1, '/')) {
                bool incomplete = false;
                int flags, wd = -1;
                char tmp, *cut;

                if (slash) {
                        cut = slash + (slash == s->path);
                        tmp = *cut;
                        *cut = '\0';

                        flags = IN_MOVE_SELF | IN_DELETE_SELF | IN_ATTRIB | IN_CREATE | IN_MOVED_TO;
                } else {
                        cut = NULL;
                        flags = flags_table[s->type];
                }

                /* If this is a symlink watch both the symlink inode and where it points to. If the inode is
                 * not a symlink both calls will install the same watch, which is redundant and doesn't
                 * hurt. */
                for (int follow_symlink = 0; follow_symlink < 2; follow_symlink++) {
                        uint32_t f = flags;

                        SET_FLAG(f, IN_DONT_FOLLOW, !follow_symlink);

                        wd = inotify_add_watch(s->inotify_fd, s->path, f);
                        if (wd < 0) {
                                if (IN_SET(errno, EACCES, ENOENT)) {
                                        incomplete = true; /* This is an expected error, let's accept this
                                                            * quietly: we have an incomplete watch for
                                                            * now. */
                                        break;
                                }

                                /* This second call to inotify_add_watch() should fail like the previous one
                                 * and is done for logging the error in a comprehensive way. */
                                wd = inotify_add_watch_and_warn(s->inotify_fd, s->path, f);
                                if (wd < 0) {
                                        if (cut)
                                                *cut = tmp;

                                        r = wd;
                                        goto fail;
                                }

                                /* Hmm, we succeeded in adding the watch this time... let's continue. */
                        }
                }

                if (incomplete) {
                        if (cut)
                                *cut = tmp;

                        break;
                }

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

                if (cut)
                        *cut = tmp;

                if (slash)
                        oldslash = slash;
                else {
                        /* whole path has been iterated over */
                        s->primary_wd = wd;
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

        s->event_source = sd_event_source_disable_unref(s->event_source);
        s->inotify_fd = safe_close(s->inotify_fd);
}

int path_spec_fd_event(PathSpec *s, uint32_t revents) {
        union inotify_event_buffer buffer;
        ssize_t l;

        assert(s);

        if (revents != EPOLLIN)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Got invalid poll event on inotify.");

        l = read(s->inotify_fd, &buffer, sizeof(buffer));
        if (l < 0) {
                if (ERRNO_IS_TRANSIENT(errno))
                        return 0;

                return log_error_errno(errno, "Failed to read inotify event: %m");
        }

        if (IN_SET(s->type, PATH_CHANGED, PATH_MODIFIED))
                FOREACH_INOTIFY_EVENT_WARN(e, buffer, l)
                        if (s->primary_wd == e->wd)
                                return 1;

        return 0;
}

static bool path_spec_check_good(PathSpec *s, bool initial, bool from_trigger_notify, char **ret_trigger_path) {
        _cleanup_free_ char *trigger = NULL;
        bool b, good = false;

        assert(s);
        assert(ret_trigger_path);

        switch (s->type) {

        case PATH_EXISTS:
                good = access(s->path, F_OK) >= 0;
                break;

        case PATH_EXISTS_GLOB:
                good = glob_first(s->path, &trigger) > 0;
                break;

        case PATH_DIRECTORY_NOT_EMPTY: {
                int k;

                k = dir_is_empty(s->path, /* ignore_hidden_or_backup= */ true);
                good = !(IN_SET(k, -ENOENT, -ENOTDIR) || k > 0);
                break;
        }

        case PATH_CHANGED:
        case PATH_MODIFIED:
                b = access(s->path, F_OK) >= 0;
                good = !initial && !from_trigger_notify && b != s->previous_exists;
                s->previous_exists = b;
                break;

        default:
                ;
        }

        if (good) {
                if (!trigger) {
                        trigger = strdup(s->path);
                        if (!trigger)
                                (void) log_oom_debug();
                }
                *ret_trigger_path = TAKE_PTR(trigger);
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
        const char *type;

        assert_se(type = path_type_to_string(s->type));
        fprintf(f, "%s%s: %s\n", prefix, type, s->path);
}

void path_spec_done(PathSpec *s) {
        assert(s);
        assert(s->inotify_fd == -EBADF);

        free(s->path);
}

static void path_init(Unit *u) {
        Path *p = PATH(u);

        assert(u);
        assert(u->load_state == UNIT_STUB);

        p->directory_mode = 0755;

        p->trigger_limit = RATELIMIT_OFF;
}

void path_free_specs(Path *p) {
        PathSpec *s;

        assert(p);

        while ((s = LIST_POP(spec, p->specs))) {
                path_spec_unwatch(s);
                path_spec_done(s);
                free(s);
        }
}

static void path_done(Unit *u) {
        Path *p = PATH(u);

        assert(p);

        p->trigger_notify_event_source = sd_event_source_disable_unref(p->trigger_notify_event_source);
        path_free_specs(p);
}

static int path_add_mount_dependencies(Path *p) {
        int r;

        assert(p);

        LIST_FOREACH(spec, s, p->specs) {
                r = unit_add_mounts_for(UNIT(p), s->path, UNIT_DEPENDENCY_FILE, UNIT_MOUNT_REQUIRES);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int path_verify(Path *p) {
        assert(p);
        assert(UNIT(p)->load_state == UNIT_LOADED);

        if (!p->specs)
                return log_unit_error_errno(UNIT(p), SYNTHETIC_ERRNO(ENOEXEC), "Path unit lacks path setting. Refusing.");

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

        if (UNIT_TRIGGER(UNIT(p)))
                return 0;

        r = unit_load_related_unit(UNIT(p), ".service", &x);
        if (r < 0)
                return r;

        return unit_add_two_dependencies(UNIT(p), UNIT_BEFORE, UNIT_TRIGGERS, x, true, UNIT_DEPENDENCY_IMPLICIT);
}

static int path_add_extras(Path *p) {
        int r;

        assert(p);

        /* To avoid getting pid1 in a busy-loop state (eg: unmet condition on associated service),
         * set a default trigger limit if the user didn't specify any. */
        if (p->trigger_limit.interval == USEC_INFINITY)
                p->trigger_limit.interval = 2 * USEC_PER_SEC;

        if (p->trigger_limit.burst == UINT_MAX)
                p->trigger_limit.burst = 200;

        r = path_add_trigger_dependencies(p);
        if (r < 0)
                return r;

        r = path_add_mount_dependencies(p);
        if (r < 0)
                return r;

        return path_add_default_dependencies(p);
}

static int path_load(Unit *u) {
        Path *p = PATH(u);
        int r;

        assert(u);
        assert(u->load_state == UNIT_STUB);

        r = unit_load_fragment_and_dropin(u, true);
        if (r < 0)
                return r;

        if (u->load_state != UNIT_LOADED)
                return 0;

        r = path_add_extras(p);
        if (r < 0)
                return r;

        return path_verify(p);
}

static void path_dump(Unit *u, FILE *f, const char *prefix) {
        Path *p = PATH(u);
        Unit *trigger;

        assert(p);
        assert(f);

        trigger = UNIT_TRIGGER(u);

        fprintf(f,
                "%sPath State: %s\n"
                "%sResult: %s\n"
                "%sUnit: %s\n"
                "%sMakeDirectory: %s\n"
                "%sDirectoryMode: %04o\n"
                "%sTriggerLimitIntervalSec: %s\n"
                "%sTriggerLimitBurst: %u\n",
                prefix, path_state_to_string(p->state),
                prefix, path_result_to_string(p->result),
                prefix, trigger ? trigger->id : "n/a",
                prefix, yes_no(p->make_directory),
                prefix, p->directory_mode,
                prefix, FORMAT_TIMESPAN(p->trigger_limit.interval, USEC_PER_SEC),
                prefix, p->trigger_limit.burst);

        LIST_FOREACH(spec, s, p->specs)
                path_spec_dump(s, f, prefix);
}

static void path_unwatch(Path *p) {
        assert(p);

        LIST_FOREACH(spec, s, p->specs)
                path_spec_unwatch(s);
}

static int path_watch(Path *p) {
        int r;

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

        if (p->state != state)
                bus_unit_send_pending_change_signal(UNIT(p), false);

        old_state = p->state;
        p->state = state;

        if (!IN_SET(state, PATH_WAITING, PATH_RUNNING))
                path_unwatch(p);

        if (state != old_state)
                log_unit_debug(UNIT(p), "Changed %s -> %s", path_state_to_string(old_state), path_state_to_string(state));

        unit_notify(UNIT(p), state_translation_table[old_state], state_translation_table[state], /* reload_success = */ true);
}

static void path_enter_waiting(Path *p, bool initial, bool from_trigger_notify);

static int path_coldplug(Unit *u) {
        Path *p = PATH(u);

        assert(p);
        assert(p->state == PATH_DEAD);

        if (p->deserialized_state != p->state) {

                if (IN_SET(p->deserialized_state, PATH_WAITING, PATH_RUNNING))
                        path_enter_waiting(p, true, false);
                else
                        path_set_state(p, p->deserialized_state);
        }

        return 0;
}

static void path_enter_dead(Path *p, PathResult f) {
        assert(p);

        if (p->result == PATH_SUCCESS)
                p->result = f;

        unit_log_result(UNIT(p), p->result == PATH_SUCCESS, path_result_to_string(p->result));
        path_set_state(p, p->result != PATH_SUCCESS ? PATH_FAILED : PATH_DEAD);
}

static void path_enter_running(Path *p, char *trigger_path) {
        _cleanup_(activation_details_unrefp) ActivationDetails *details = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        Unit *trigger;
        Job *job;
        int r;

        assert(p);

        /* Don't start job if we are supposed to go down */
        if (unit_stop_pending(UNIT(p)))
                return;

        if (!ratelimit_below(&p->trigger_limit)) {
                log_unit_warning(UNIT(p), "Trigger limit hit, refusing further activation.");
                path_enter_dead(p, PATH_FAILURE_TRIGGER_LIMIT_HIT);
                return;
        }

        trigger = UNIT_TRIGGER(UNIT(p));
        if (!trigger) {
                log_unit_error(UNIT(p), "Unit to trigger vanished.");
                goto fail;
        }

        details = activation_details_new(UNIT(p));
        if (!details) {
                log_oom();
                goto fail;
        }

        r = free_and_strdup(&(ACTIVATION_DETAILS_PATH(details))->trigger_path_filename, trigger_path);
        if (r < 0) {
                log_oom();
                goto fail;
        }

        r = manager_add_job(UNIT(p)->manager, JOB_START, trigger, JOB_REPLACE, NULL, &error, &job);
        if (r < 0) {
                log_unit_warning(UNIT(p), "Failed to queue unit startup job: %s", bus_error_message(&error, r));
                goto fail;
        }

        job_set_activation_details(job, details);

        path_set_state(p, PATH_RUNNING);
        path_unwatch(p);

        return;

fail:
        path_enter_dead(p, PATH_FAILURE_RESOURCES);
}

static bool path_check_good(Path *p, bool initial, bool from_trigger_notify, char **ret_trigger_path) {
        assert(p);
        assert(ret_trigger_path);

        LIST_FOREACH(spec, s, p->specs)
                if (path_spec_check_good(s, initial, from_trigger_notify, ret_trigger_path))
                        return true;

        return false;
}

static void path_enter_waiting(Path *p, bool initial, bool from_trigger_notify) {
        _cleanup_free_ char *trigger_path = NULL;
        Unit *trigger;
        int r;

        if (p->trigger_notify_event_source)
                (void) event_source_disable(p->trigger_notify_event_source);

        /* If the triggered unit is already running, so are we */
        trigger = UNIT_TRIGGER(UNIT(p));
        if (trigger && !UNIT_IS_INACTIVE_OR_FAILED(unit_active_state(trigger))) {
                path_set_state(p, PATH_RUNNING);
                path_unwatch(p);
                return;
        }

        if (path_check_good(p, initial, from_trigger_notify, &trigger_path)) {
                log_unit_debug(UNIT(p), "Got triggered.");
                path_enter_running(p, trigger_path);
                return;
        }

        r = path_watch(p);
        if (r < 0) {
                log_unit_warning_errno(UNIT(p), r, "Failed to enter waiting state: %m");
                path_enter_dead(p, PATH_FAILURE_RESOURCES);
                return;
        }

        /* Hmm, so now we have created inotify watches, but the file
         * might have appeared/been removed by now, so we must
         * recheck */

        if (path_check_good(p, false, from_trigger_notify, &trigger_path)) {
                log_unit_debug(UNIT(p), "Got triggered.");
                path_enter_running(p, trigger_path);
                return;
        }

        path_set_state(p, PATH_WAITING);
}

static void path_mkdir(Path *p) {
        assert(p);

        if (!p->make_directory)
                return;

        LIST_FOREACH(spec, s, p->specs)
                path_spec_mkdir(s, p->directory_mode);
}

static int path_start(Unit *u) {
        Path *p = PATH(u);
        int r;

        assert(p);
        assert(IN_SET(p->state, PATH_DEAD, PATH_FAILED));

        r = unit_test_trigger_loaded(u);
        if (r < 0)
                return r;

        r = unit_acquire_invocation_id(u);
        if (r < 0)
                return r;

        path_mkdir(p);

        p->result = PATH_SUCCESS;
        path_enter_waiting(p, true, false);

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

        (void) serialize_item(f, "state", path_state_to_string(p->state));
        (void) serialize_item(f, "result", path_result_to_string(p->result));

        LIST_FOREACH(spec, s, p->specs) {
                const char *type;
                _cleanup_free_ char *escaped = NULL;

                escaped = cescape(s->path);
                if (!escaped)
                        return log_oom();

                assert_se(type = path_type_to_string(s->type));
                (void) serialize_item_format(f, "path-spec", "%s %i %s",
                                             type,
                                             s->previous_exists,
                                             escaped);
        }

        (void) serialize_ratelimit(f, "trigger-ratelimit", &p->trigger_limit);

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

        } else if (streq(key, "path-spec")) {
                int previous_exists, skip = 0;
                _cleanup_free_ char *type_str = NULL;

                if (sscanf(value, "%ms %i %n", &type_str, &previous_exists, &skip) < 2)
                        log_unit_debug(u, "Failed to parse path-spec value: %s", value);
                else {
                        _cleanup_free_ char *unescaped = NULL;
                        ssize_t l;
                        PathType type;

                        type = path_type_from_string(type_str);
                        if (type < 0) {
                                log_unit_warning(u, "Unknown path type \"%s\", ignoring.", type_str);
                                return 0;
                        }

                        l = cunescape(value+skip, 0, &unescaped);
                        if (l < 0) {
                                log_unit_warning_errno(u, l, "Failed to unescape serialize path: %m");
                                return 0;
                        }

                        LIST_FOREACH(spec, s, p->specs)
                                if (s->type == type &&
                                    path_equal(s->path, unescaped)) {

                                        s->previous_exists = previous_exists;
                                        break;
                                }
                }

        } else if (streq(key, "trigger-ratelimit"))
                deserialize_ratelimit(&p->trigger_limit, key, value);

        else
                log_unit_debug(u, "Unknown serialization key: %s", key);

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

static int path_dispatch_io(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        PathSpec *s = userdata, *found = NULL;
        Path *p;
        int changed;

        assert(s);
        assert(s->unit);
        assert(fd >= 0);

        p = PATH(s->unit);

        if (!IN_SET(p->state, PATH_WAITING, PATH_RUNNING))
                return 0;

        LIST_FOREACH(spec, i, p->specs)
                if (path_spec_owns_inotify_fd(i, fd)) {
                        found = i;
                        break;
                }

        if (!found) {
                log_error("Got event on unknown fd.");
                goto fail;
        }

        changed = path_spec_fd_event(found, revents);
        if (changed < 0)
                goto fail;

        if (changed)
                path_enter_running(p, found->path);
        else
                path_enter_waiting(p, false, false);

        return 0;

fail:
        path_enter_dead(p, PATH_FAILURE_RESOURCES);
        return 0;
}

static void path_trigger_notify_impl(Unit *u, Unit *other, bool on_defer);

static int path_trigger_notify_on_defer(sd_event_source *s, void *userdata) {
        Path *p = ASSERT_PTR(userdata);
        Unit *trigger;

        assert(s);

        trigger = UNIT_TRIGGER(UNIT(p));
        if (!trigger) {
                log_unit_error(UNIT(p), "Unit to trigger vanished.");
                path_enter_dead(p, PATH_FAILURE_RESOURCES);
                return 0;
        }

        path_trigger_notify_impl(UNIT(p), trigger, /* on_defer = */ true);
        return 0;
}

static void path_trigger_notify_impl(Unit *u, Unit *other, bool on_defer) {
        Path *p = PATH(u);
        int r;

        assert(u);
        assert(other);

        /* Invoked whenever the unit we trigger changes state or gains or loses a job */

        /* Filter out invocations with bogus state */
        assert(UNIT_IS_LOAD_COMPLETE(other->load_state));

        /* Don't propagate state changes from the triggered unit if we are already down */
        if (!IN_SET(p->state, PATH_WAITING, PATH_RUNNING))
                return;

        /* Propagate start limit hit state */
        if (other->start_limit_hit) {
                path_enter_dead(p, PATH_FAILURE_UNIT_START_LIMIT_HIT);
                return;
        }

        /* Don't propagate anything if there's still a job queued */
        if (other->job)
                return;

        if (p->state == PATH_RUNNING &&
            UNIT_IS_INACTIVE_OR_FAILED(unit_active_state(other))) {
                if (!on_defer)
                        log_unit_debug(u, "Got notified about unit deactivation.");
        } else if (p->state == PATH_WAITING &&
                   !UNIT_IS_INACTIVE_OR_FAILED(unit_active_state(other))) {
                if (!on_defer)
                        log_unit_debug(u, "Got notified about unit activation.");
        } else
                return;

        if (on_defer) {
                path_enter_waiting(p, /* initial = */ false, /* from_trigger_notify = */ true);
                return;
        }

        /* Do not call path_enter_waiting() directly from path_trigger_notify(), as this may be called by
         * job_install() -> job_finish_and_invalidate() -> unit_trigger_notify(), and path_enter_waiting()
         * may install another job and will trigger assertion in job_install().
         * https://github.com/systemd/systemd/issues/24577#issuecomment-1522628906
         * Hence, first setup defer event source here, and call path_enter_waiting() slightly later. */
        if (p->trigger_notify_event_source) {
                r = sd_event_source_set_enabled(p->trigger_notify_event_source, SD_EVENT_ONESHOT);
                if (r < 0) {
                        log_unit_warning_errno(u, r, "Failed to enable event source for triggering notify: %m");
                        path_enter_dead(p, PATH_FAILURE_RESOURCES);
                        return;
                }
        } else {
                r = sd_event_add_defer(u->manager->event, &p->trigger_notify_event_source, path_trigger_notify_on_defer, p);
                if (r < 0) {
                        log_unit_warning_errno(u, r, "Failed to allocate event source for triggering notify: %m");
                        path_enter_dead(p, PATH_FAILURE_RESOURCES);
                        return;
                }

                (void) sd_event_source_set_description(p->trigger_notify_event_source, "path-trigger-notify");
        }
}

static void path_trigger_notify(Unit *u, Unit *other) {
        path_trigger_notify_impl(u, other, /* on_defer = */ false);
}

static void path_reset_failed(Unit *u) {
        Path *p = PATH(u);

        assert(p);

        if (p->state == PATH_FAILED)
                path_set_state(p, PATH_DEAD);

        p->result = PATH_SUCCESS;
}

static int path_can_start(Unit *u) {
        Path *p = PATH(u);
        int r;

        assert(p);

        r = unit_test_start_limit(u);
        if (r < 0) {
                path_enter_dead(p, PATH_FAILURE_START_LIMIT_HIT);
                return r;
        }

        return 1;
}

static void activation_details_path_done(ActivationDetails *details) {
        ActivationDetailsPath *p = ASSERT_PTR(ACTIVATION_DETAILS_PATH(details));

        p->trigger_path_filename = mfree(p->trigger_path_filename);
}

static void activation_details_path_serialize(ActivationDetails *details, FILE *f) {
        ActivationDetailsPath *p = ASSERT_PTR(ACTIVATION_DETAILS_PATH(details));

        assert(f);

        if (p->trigger_path_filename)
                (void) serialize_item(f, "activation-details-path-filename", p->trigger_path_filename);
}

static int activation_details_path_deserialize(const char *key, const char *value, ActivationDetails **details) {
        int r;

        assert(key);
        assert(value);

        if (!details || !*details)
                return -EINVAL;

        ActivationDetailsPath *p = ACTIVATION_DETAILS_PATH(*details);
        if (!p)
                return -EINVAL;

        if (!streq(key, "activation-details-path-filename"))
                return -EINVAL;

        r = free_and_strdup(&p->trigger_path_filename, value);
        if (r < 0)
                return r;

        return 0;
}

static int activation_details_path_append_env(ActivationDetails *details, char ***strv) {
        ActivationDetailsPath *p = ACTIVATION_DETAILS_PATH(details);
        char *s;
        int r;

        assert(details);
        assert(strv);
        assert(p);

        if (isempty(p->trigger_path_filename))
                return 0;

        s = strjoin("TRIGGER_PATH=", p->trigger_path_filename);
        if (!s)
                return -ENOMEM;

        r = strv_consume(strv, TAKE_PTR(s));
        if (r < 0)
                return r;

        return 1; /* Return the number of variables added to the env block */
}

static int activation_details_path_append_pair(ActivationDetails *details, char ***strv) {
        ActivationDetailsPath *p = ACTIVATION_DETAILS_PATH(details);
        int r;

        assert(details);
        assert(strv);
        assert(p);

        if (isempty(p->trigger_path_filename))
                return 0;

        r = strv_extend(strv, "trigger_path");
        if (r < 0)
                return r;

        r = strv_extend(strv, p->trigger_path_filename);
        if (r < 0)
                return r;

        return 1; /* Return the number of pairs added to the env block */
}

static const char* const path_type_table[_PATH_TYPE_MAX] = {
        [PATH_EXISTS]              = "PathExists",
        [PATH_EXISTS_GLOB]         = "PathExistsGlob",
        [PATH_DIRECTORY_NOT_EMPTY] = "DirectoryNotEmpty",
        [PATH_CHANGED]             = "PathChanged",
        [PATH_MODIFIED]            = "PathModified",
};

DEFINE_STRING_TABLE_LOOKUP(path_type, PathType);

static const char* const path_result_table[_PATH_RESULT_MAX] = {
        [PATH_SUCCESS]                      = "success",
        [PATH_FAILURE_RESOURCES]            = "resources",
        [PATH_FAILURE_START_LIMIT_HIT]      = "start-limit-hit",
        [PATH_FAILURE_UNIT_START_LIMIT_HIT] = "unit-start-limit-hit",
        [PATH_FAILURE_TRIGGER_LIMIT_HIT]    = "trigger-limit-hit",
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
        .can_fail = true,
        .can_trigger = true,

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

        .bus_set_property = bus_path_set_property,

        .can_start = path_can_start,
};

const ActivationDetailsVTable activation_details_path_vtable = {
        .object_size = sizeof(ActivationDetailsPath),

        .done = activation_details_path_done,
        .serialize = activation_details_path_serialize,
        .deserialize = activation_details_path_deserialize,
        .append_env = activation_details_path_append_env,
        .append_pair = activation_details_path_append_pair,
};
