/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

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

#include <sys/mman.h>

#include "special.h"
#include "bus-kernel.h"
#include "bus-internal.h"
#include "bus-util.h"
#include "service.h"
#include "kdbus.h"
#include "bus-policy.h"
#include "dbus-busname.h"
#include "busname.h"
#include "formats-util.h"

static const UnitActiveState state_translation_table[_BUSNAME_STATE_MAX] = {
        [BUSNAME_DEAD] = UNIT_INACTIVE,
        [BUSNAME_MAKING] = UNIT_ACTIVATING,
        [BUSNAME_REGISTERED] = UNIT_ACTIVE,
        [BUSNAME_LISTENING] = UNIT_ACTIVE,
        [BUSNAME_RUNNING] = UNIT_ACTIVE,
        [BUSNAME_SIGTERM] = UNIT_DEACTIVATING,
        [BUSNAME_SIGKILL] = UNIT_DEACTIVATING,
        [BUSNAME_FAILED] = UNIT_FAILED
};

static int busname_dispatch_io(sd_event_source *source, int fd, uint32_t revents, void *userdata);
static int busname_dispatch_timer(sd_event_source *source, usec_t usec, void *userdata);

static void busname_init(Unit *u) {
        BusName *n = BUSNAME(u);

        assert(u);
        assert(u->load_state == UNIT_STUB);

        n->starter_fd = -1;
        n->accept_fd = true;
        n->activating = true;

        n->timeout_usec = u->manager->default_timeout_start_usec;
}

static void busname_unwatch_control_pid(BusName *n) {
        assert(n);

        if (n->control_pid <= 0)
                return;

        unit_unwatch_pid(UNIT(n), n->control_pid);
        n->control_pid = 0;
}

static void busname_free_policy(BusName *n) {
        BusNamePolicy *p;

        assert(n);

        while ((p = n->policy)) {
                LIST_REMOVE(policy, n->policy, p);

                free(p->name);
                free(p);
        }
}

static void busname_close_fd(BusName *n) {
        assert(n);

        n->starter_event_source = sd_event_source_unref(n->starter_event_source);
        n->starter_fd = safe_close(n->starter_fd);
}

static void busname_done(Unit *u) {
        BusName *n = BUSNAME(u);

        assert(n);

        free(n->name);
        n->name = NULL;

        busname_free_policy(n);
        busname_unwatch_control_pid(n);
        busname_close_fd(n);

        unit_ref_unset(&n->service);

        n->timer_event_source = sd_event_source_unref(n->timer_event_source);
}

static int busname_arm_timer(BusName *n) {
        int r;

        assert(n);

        if (n->timeout_usec <= 0) {
                n->timer_event_source = sd_event_source_unref(n->timer_event_source);
                return 0;
        }

        if (n->timer_event_source) {
                r = sd_event_source_set_time(n->timer_event_source, now(CLOCK_MONOTONIC) + n->timeout_usec);
                if (r < 0)
                        return r;

                return sd_event_source_set_enabled(n->timer_event_source, SD_EVENT_ONESHOT);
        }

        r =  sd_event_add_time(
                        UNIT(n)->manager->event,
                        &n->timer_event_source,
                        CLOCK_MONOTONIC,
                        now(CLOCK_MONOTONIC) + n->timeout_usec, 0,
                        busname_dispatch_timer, n);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(n->timer_event_source, "busname-timer");

        return 0;
}

static int busname_add_default_default_dependencies(BusName *n) {
        int r;

        assert(n);

        r = unit_add_dependency_by_name(UNIT(n), UNIT_BEFORE, SPECIAL_BUSNAMES_TARGET, NULL, true);
        if (r < 0)
                return r;

        if (UNIT(n)->manager->running_as == MANAGER_SYSTEM) {
                r = unit_add_two_dependencies_by_name(UNIT(n), UNIT_AFTER, UNIT_REQUIRES, SPECIAL_SYSINIT_TARGET, NULL, true);
                if (r < 0)
                        return r;
        }

        return unit_add_two_dependencies_by_name(UNIT(n), UNIT_BEFORE, UNIT_CONFLICTS, SPECIAL_SHUTDOWN_TARGET, NULL, true);
}

static int busname_add_extras(BusName *n) {
        Unit *u = UNIT(n);
        int r;

        assert(n);

        if (!n->name) {
                r = unit_name_to_prefix(u->id, &n->name);
                if (r < 0)
                        return r;
        }

        if (!u->description) {
                r = unit_set_description(u, n->name);
                if (r < 0)
                        return r;
        }

        if (n->activating) {
                if (!UNIT_DEREF(n->service)) {
                        Unit *x;

                        r = unit_load_related_unit(u, ".service", &x);
                        if (r < 0)
                                return r;

                        unit_ref_set(&n->service, x);
                }

                r = unit_add_two_dependencies(u, UNIT_BEFORE, UNIT_TRIGGERS, UNIT_DEREF(n->service), true);
                if (r < 0)
                        return r;
        }

        if (u->default_dependencies) {
                r = busname_add_default_default_dependencies(n);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int busname_verify(BusName *n) {
        char *e;

        assert(n);

        if (UNIT(n)->load_state != UNIT_LOADED)
                return 0;

        if (!service_name_is_valid(n->name)) {
                log_unit_error(UNIT(n), "Name= setting is not a valid service name Refusing.");
                return -EINVAL;
        }

        e = strjoina(n->name, ".busname");
        if (!unit_has_name(UNIT(n), e)) {
                log_unit_error(UNIT(n), "Name= setting doesn't match unit name. Refusing.");
                return -EINVAL;
        }

        return 0;
}

static int busname_load(Unit *u) {
        BusName *n = BUSNAME(u);
        int r;

        assert(u);
        assert(u->load_state == UNIT_STUB);

        r = unit_load_fragment_and_dropin(u);
        if (r < 0)
                return r;

        if (u->load_state == UNIT_LOADED) {
                /* This is a new unit? Then let's add in some extras */
                r = busname_add_extras(n);
                if (r < 0)
                        return r;
        }

        return busname_verify(n);
}

static void busname_dump(Unit *u, FILE *f, const char *prefix) {
        BusName *n = BUSNAME(u);

        assert(n);
        assert(f);

        fprintf(f,
                "%sBus Name State: %s\n"
                "%sResult: %s\n"
                "%sName: %s\n"
                "%sActivating: %s\n"
                "%sAccept FD: %s\n",
                prefix, busname_state_to_string(n->state),
                prefix, busname_result_to_string(n->result),
                prefix, n->name,
                prefix, yes_no(n->activating),
                prefix, yes_no(n->accept_fd));

        if (n->control_pid > 0)
                fprintf(f,
                        "%sControl PID: "PID_FMT"\n",
                        prefix, n->control_pid);
}

static void busname_unwatch_fd(BusName *n) {
        int r;

        assert(n);

        if (!n->starter_event_source)
                return;

        r = sd_event_source_set_enabled(n->starter_event_source, SD_EVENT_OFF);
        if (r < 0)
                log_unit_debug_errno(UNIT(n), r, "Failed to disable event source: %m");
}

static int busname_watch_fd(BusName *n) {
        int r;

        assert(n);

        if (n->starter_fd < 0)
                return 0;

        if (n->starter_event_source) {
                r = sd_event_source_set_enabled(n->starter_event_source, SD_EVENT_ON);
                if (r < 0)
                        goto fail;
        } else {
                r = sd_event_add_io(UNIT(n)->manager->event, &n->starter_event_source, n->starter_fd, EPOLLIN, busname_dispatch_io, n);
                if (r < 0)
                        goto fail;

                (void) sd_event_source_set_description(n->starter_event_source, "busname-starter");
        }

        return 0;

fail:
        log_unit_warning_errno(UNIT(n), r, "Failed to watch starter fd: %m");
        busname_unwatch_fd(n);
        return r;
}

static int busname_open_fd(BusName *n) {
        _cleanup_free_ char *path = NULL;
        const char *mode;

        assert(n);

        if (n->starter_fd >= 0)
                return 0;

        mode = UNIT(n)->manager->running_as == MANAGER_SYSTEM ? "system" : "user";
        n->starter_fd = bus_kernel_open_bus_fd(mode, &path);
        if (n->starter_fd < 0)
                return log_unit_warning_errno(UNIT(n), n->starter_fd, "Failed to open %s: %m", path ?: "kdbus");

        return 0;
}

static void busname_set_state(BusName *n, BusNameState state) {
        BusNameState old_state;
        assert(n);

        old_state = n->state;
        n->state = state;

        if (!IN_SET(state, BUSNAME_MAKING, BUSNAME_SIGTERM, BUSNAME_SIGKILL)) {
                n->timer_event_source = sd_event_source_unref(n->timer_event_source);
                busname_unwatch_control_pid(n);
        }

        if (state != BUSNAME_LISTENING)
                busname_unwatch_fd(n);

        if (!IN_SET(state, BUSNAME_LISTENING, BUSNAME_MAKING, BUSNAME_REGISTERED, BUSNAME_RUNNING))
                busname_close_fd(n);

        if (state != old_state)
                log_unit_debug(UNIT(n), "Changed %s -> %s", busname_state_to_string(old_state), busname_state_to_string(state));

        unit_notify(UNIT(n), state_translation_table[old_state], state_translation_table[state], true);
}

static int busname_coldplug(Unit *u) {
        BusName *n = BUSNAME(u);
        int r;

        assert(n);
        assert(n->state == BUSNAME_DEAD);

        if (n->deserialized_state == n->state)
                return 0;

        if (IN_SET(n->deserialized_state, BUSNAME_MAKING, BUSNAME_SIGTERM, BUSNAME_SIGKILL)) {

                if (n->control_pid <= 0)
                        return -EBADMSG;

                r = unit_watch_pid(UNIT(n), n->control_pid);
                if (r < 0)
                        return r;

                r = busname_arm_timer(n);
                if (r < 0)
                        return r;
        }

        if (IN_SET(n->deserialized_state, BUSNAME_MAKING, BUSNAME_LISTENING, BUSNAME_REGISTERED, BUSNAME_RUNNING)) {
                r = busname_open_fd(n);
                if (r < 0)
                        return r;
        }

        if (n->deserialized_state == BUSNAME_LISTENING) {
                r = busname_watch_fd(n);
                if (r < 0)
                        return r;
        }

        busname_set_state(n, n->deserialized_state);
        return 0;
}

static int busname_make_starter(BusName *n, pid_t *_pid) {
        pid_t pid;
        int r;

        r = busname_arm_timer(n);
        if (r < 0)
                goto fail;

        /* We have to resolve the user/group names out-of-process,
         * hence let's fork here. It's messy, but well, what can we
         * do? */

        pid = fork();
        if (pid < 0)
                return -errno;

        if (pid == 0) {
                int ret;

                default_signals(SIGNALS_CRASH_HANDLER, SIGNALS_IGNORE, -1);
                ignore_signals(SIGPIPE, -1);
                log_forget_fds();

                r = bus_kernel_make_starter(n->starter_fd, n->name, n->activating, n->accept_fd, n->policy, n->policy_world);
                if (r < 0) {
                        ret = EXIT_MAKE_STARTER;
                        goto fail_child;
                }

                _exit(0);

        fail_child:
                log_open();
                log_error_errno(r, "Failed to create starter connection at step %s: %m", exit_status_to_string(ret, EXIT_STATUS_SYSTEMD));

                _exit(ret);
        }

        r = unit_watch_pid(UNIT(n), pid);
        if (r < 0)
                goto fail;

        *_pid = pid;
        return 0;

fail:
        n->timer_event_source = sd_event_source_unref(n->timer_event_source);
        return r;
}

static void busname_enter_dead(BusName *n, BusNameResult f) {
        assert(n);

        if (f != BUSNAME_SUCCESS)
                n->result = f;

        busname_set_state(n, n->result != BUSNAME_SUCCESS ? BUSNAME_FAILED : BUSNAME_DEAD);
}

static void busname_enter_signal(BusName *n, BusNameState state, BusNameResult f) {
        KillContext kill_context = {};
        int r;

        assert(n);

        if (f != BUSNAME_SUCCESS)
                n->result = f;

        kill_context_init(&kill_context);

        r = unit_kill_context(UNIT(n),
                              &kill_context,
                              state != BUSNAME_SIGTERM ? KILL_KILL : KILL_TERMINATE,
                              -1,
                              n->control_pid,
                              false);
        if (r < 0) {
                log_unit_warning_errno(UNIT(n), r, "Failed to kill control process: %m");
                goto fail;
        }

        if (r > 0) {
                r = busname_arm_timer(n);
                if (r < 0) {
                        log_unit_warning_errno(UNIT(n), r, "Failed to arm timer: %m");
                        goto fail;
                }

                busname_set_state(n, state);
        } else if (state == BUSNAME_SIGTERM)
                busname_enter_signal(n, BUSNAME_SIGKILL, BUSNAME_SUCCESS);
        else
                busname_enter_dead(n, BUSNAME_SUCCESS);

        return;

fail:
        busname_enter_dead(n, BUSNAME_FAILURE_RESOURCES);
}

static void busname_enter_listening(BusName *n) {
        int r;

        assert(n);

        if (n->activating) {
                r = busname_watch_fd(n);
                if (r < 0) {
                        log_unit_warning_errno(UNIT(n), r, "Failed to watch names: %m");
                        goto fail;
                }

                busname_set_state(n, BUSNAME_LISTENING);
        } else
                busname_set_state(n, BUSNAME_REGISTERED);

        return;

fail:
        busname_enter_signal(n, BUSNAME_SIGTERM, BUSNAME_FAILURE_RESOURCES);
}

static void busname_enter_making(BusName *n) {
        int r;

        assert(n);

        r = busname_open_fd(n);
        if (r < 0)
                goto fail;

        if (n->policy) {
                /* If there is a policy, we need to resolve user/group
                 * names, which we can't do from PID1, hence let's
                 * fork. */
                busname_unwatch_control_pid(n);

                r = busname_make_starter(n, &n->control_pid);
                if (r < 0) {
                        log_unit_warning_errno(UNIT(n), r, "Failed to fork 'making' task: %m");
                        goto fail;
                }

                busname_set_state(n, BUSNAME_MAKING);
        } else {
                /* If there is no policy, we can do everything
                 * directly from PID 1, hence do so. */

                r = bus_kernel_make_starter(n->starter_fd, n->name, n->activating, n->accept_fd, NULL, n->policy_world);
                if (r < 0) {
                        log_unit_warning_errno(UNIT(n), r, "Failed to make starter: %m");
                        goto fail;
                }

                busname_enter_listening(n);
        }

        return;

fail:
        busname_enter_dead(n, BUSNAME_FAILURE_RESOURCES);
}

static void busname_enter_running(BusName *n) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        bool pending = false;
        Unit *other;
        Iterator i;
        int r;

        assert(n);

        if (!n->activating)
                return;

        /* We don't take connections anymore if we are supposed to
         * shut down anyway */

        if (unit_stop_pending(UNIT(n))) {
                log_unit_debug(UNIT(n), "Suppressing activation request since unit stop is scheduled.");

                /* Flush all queued activation reqeuest by closing and reopening the connection */
                bus_kernel_drop_one(n->starter_fd);

                busname_enter_listening(n);
                return;
        }

        /* If there's already a start pending don't bother to do
         * anything */
        SET_FOREACH(other, UNIT(n)->dependencies[UNIT_TRIGGERS], i)
                if (unit_active_or_pending(other)) {
                        pending = true;
                        break;
                }

        if (!pending) {
                r = manager_add_job(UNIT(n)->manager, JOB_START, UNIT_DEREF(n->service), JOB_REPLACE, true, &error, NULL);
                if (r < 0)
                        goto fail;
        }

        busname_set_state(n, BUSNAME_RUNNING);
        return;

fail:
        log_unit_warning(UNIT(n), "Failed to queue service startup job: %s", bus_error_message(&error, r));
        busname_enter_dead(n, BUSNAME_FAILURE_RESOURCES);
}

static int busname_start(Unit *u) {
        BusName *n = BUSNAME(u);

        assert(n);

        /* We cannot fulfill this request right now, try again later
         * please! */
        if (IN_SET(n->state, BUSNAME_SIGTERM, BUSNAME_SIGKILL))
                return -EAGAIN;

        /* Already on it! */
        if (n->state == BUSNAME_MAKING)
                return 0;

        if (n->activating && UNIT_ISSET(n->service)) {
                Service *service;

                service = SERVICE(UNIT_DEREF(n->service));

                if (UNIT(service)->load_state != UNIT_LOADED) {
                        log_unit_error(u, "Bus service %s not loaded, refusing.", UNIT(service)->id);
                        return -ENOENT;
                }
        }

        assert(IN_SET(n->state, BUSNAME_DEAD, BUSNAME_FAILED));

        n->result = BUSNAME_SUCCESS;
        busname_enter_making(n);

        return 1;
}

static int busname_stop(Unit *u) {
        BusName *n = BUSNAME(u);

        assert(n);

        /* Already on it */
        if (IN_SET(n->state, BUSNAME_SIGTERM, BUSNAME_SIGKILL))
                return 0;

        /* If there's already something running, we go directly into
         * kill mode. */

        if (n->state == BUSNAME_MAKING) {
                busname_enter_signal(n, BUSNAME_SIGTERM, BUSNAME_SUCCESS);
                return -EAGAIN;
        }

        assert(IN_SET(n->state, BUSNAME_REGISTERED, BUSNAME_LISTENING, BUSNAME_RUNNING));

        busname_enter_dead(n, BUSNAME_SUCCESS);
        return 1;
}

static int busname_serialize(Unit *u, FILE *f, FDSet *fds) {
        BusName *n = BUSNAME(u);

        assert(n);
        assert(f);
        assert(fds);

        unit_serialize_item(u, f, "state", busname_state_to_string(n->state));
        unit_serialize_item(u, f, "result", busname_result_to_string(n->result));

        if (n->control_pid > 0)
                unit_serialize_item_format(u, f, "control-pid", PID_FMT, n->control_pid);

        if (n->starter_fd >= 0) {
                int copy;

                copy = fdset_put_dup(fds, n->starter_fd);
                if (copy < 0)
                        return copy;

                unit_serialize_item_format(u, f, "starter-fd", "%i", copy);
        }

        return 0;
}

static int busname_deserialize_item(Unit *u, const char *key, const char *value, FDSet *fds) {
        BusName *n = BUSNAME(u);

        assert(n);
        assert(key);
        assert(value);

        if (streq(key, "state")) {
                BusNameState state;

                state = busname_state_from_string(value);
                if (state < 0)
                        log_unit_debug(u, "Failed to parse state value: %s", value);
                else
                        n->deserialized_state = state;

        } else if (streq(key, "result")) {
                BusNameResult f;

                f = busname_result_from_string(value);
                if (f < 0)
                        log_unit_debug(u, "Failed to parse result value: %s", value);
                else if (f != BUSNAME_SUCCESS)
                        n->result = f;

        } else if (streq(key, "control-pid")) {
                pid_t pid;

                if (parse_pid(value, &pid) < 0)
                        log_unit_debug(u, "Failed to parse control-pid value: %s", value);
                else
                        n->control_pid = pid;
        } else if (streq(key, "starter-fd")) {
                int fd;

                if (safe_atoi(value, &fd) < 0 || fd < 0 || !fdset_contains(fds, fd))
                        log_unit_debug(u, "Failed to parse starter fd value: %s", value);
                else {
                        safe_close(n->starter_fd);
                        n->starter_fd = fdset_remove(fds, fd);
                }
        } else
                log_unit_debug(u, "Unknown serialization key: %s", key);

        return 0;
}

_pure_ static UnitActiveState busname_active_state(Unit *u) {
        assert(u);

        return state_translation_table[BUSNAME(u)->state];
}

_pure_ static const char *busname_sub_state_to_string(Unit *u) {
        assert(u);

        return busname_state_to_string(BUSNAME(u)->state);
}

static int busname_peek_message(BusName *n) {
        struct kdbus_cmd_recv cmd_recv = {
                .size = sizeof(cmd_recv),
                .flags = KDBUS_RECV_PEEK,
        };
        struct kdbus_cmd_free cmd_free = {
                .size = sizeof(cmd_free),
        };
        const char *comm = NULL;
        struct kdbus_item *d;
        struct kdbus_msg *k;
        size_t start, ps, sz, delta;
        void *p = NULL;
        pid_t pid = 0;
        int r;

        /* Generate a friendly debug log message about which process
         * caused triggering of this bus name. This simply peeks the
         * metadata of the first queued message and logs it. */

        assert(n);

        /* Let's shortcut things a bit, if debug logging is turned off
         * anyway. */

        if (log_get_max_level() < LOG_DEBUG)
                return 0;

        r = ioctl(n->starter_fd, KDBUS_CMD_RECV, &cmd_recv);
        if (r < 0) {
                if (errno == EINTR || errno == EAGAIN)
                        return 0;

                return log_unit_error_errno(UNIT(n), errno, "Failed to query activation message: %m");
        }

        /* We map as late as possible, and unmap imemdiately after
         * use. On 32bit address space is scarce and we want to be
         * able to handle a lot of activator connections at the same
         * time, and hence shouldn't keep the mmap()s around for
         * longer than necessary. */

        ps = page_size();
        start = (cmd_recv.msg.offset / ps) * ps;
        delta = cmd_recv.msg.offset - start;
        sz = PAGE_ALIGN(delta + cmd_recv.msg.msg_size);

        p = mmap(NULL, sz, PROT_READ, MAP_SHARED, n->starter_fd, start);
        if (p == MAP_FAILED) {
                r = log_unit_error_errno(UNIT(n), errno, "Failed to map activation message: %m");
                goto finish;
        }

        k = (struct kdbus_msg *) ((uint8_t *) p + delta);
        KDBUS_ITEM_FOREACH(d, k, items) {
                switch (d->type) {

                case KDBUS_ITEM_PIDS:
                        pid = d->pids.pid;
                        break;

                case KDBUS_ITEM_PID_COMM:
                        comm = d->str;
                        break;
                }
        }

        if (pid > 0)
                log_unit_debug(UNIT(n), "Activation triggered by process " PID_FMT " (%s)", pid, strna(comm));

        r = 0;

finish:
        if (p)
                (void) munmap(p, sz);

        cmd_free.offset = cmd_recv.msg.offset;
        if (ioctl(n->starter_fd, KDBUS_CMD_FREE, &cmd_free) < 0)
                log_unit_warning(UNIT(n), "Failed to free peeked message, ignoring: %m");

        return r;
}

static int busname_dispatch_io(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        BusName *n = userdata;

        assert(n);
        assert(fd >= 0);

        if (n->state != BUSNAME_LISTENING)
                return 0;

        log_unit_debug(UNIT(n), "Activation request");

        if (revents != EPOLLIN) {
                log_unit_error(UNIT(n), "Got unexpected poll event (0x%x) on starter fd.", revents);
                goto fail;
        }

        busname_peek_message(n);
        busname_enter_running(n);
        return 0;
fail:

        busname_enter_dead(n, BUSNAME_FAILURE_RESOURCES);
        return 0;
}

static void busname_sigchld_event(Unit *u, pid_t pid, int code, int status) {
        BusName *n = BUSNAME(u);
        BusNameResult f;

        assert(n);
        assert(pid >= 0);

        if (pid != n->control_pid)
                return;

        n->control_pid = 0;

        if (is_clean_exit(code, status, NULL))
                f = BUSNAME_SUCCESS;
        else if (code == CLD_EXITED)
                f = BUSNAME_FAILURE_EXIT_CODE;
        else if (code == CLD_KILLED)
                f = BUSNAME_FAILURE_SIGNAL;
        else if (code == CLD_DUMPED)
                f = BUSNAME_FAILURE_CORE_DUMP;
        else
                assert_not_reached("Unknown sigchld code");

        log_unit_full(u, f == BUSNAME_SUCCESS ? LOG_DEBUG : LOG_NOTICE, 0,
                      "Control process exited, code=%s status=%i", sigchld_code_to_string(code), status);

        if (f != BUSNAME_SUCCESS)
                n->result = f;

        switch (n->state) {

        case BUSNAME_MAKING:
                if (f == BUSNAME_SUCCESS)
                        busname_enter_listening(n);
                else
                        busname_enter_signal(n, BUSNAME_SIGTERM, f);
                break;

        case BUSNAME_SIGTERM:
        case BUSNAME_SIGKILL:
                busname_enter_dead(n, f);
                break;

        default:
                assert_not_reached("Uh, control process died at wrong time.");
        }

        /* Notify clients about changed exit status */
        unit_add_to_dbus_queue(u);
}

static int busname_dispatch_timer(sd_event_source *source, usec_t usec, void *userdata) {
        BusName *n = BUSNAME(userdata);

        assert(n);
        assert(n->timer_event_source == source);

        switch (n->state) {

        case BUSNAME_MAKING:
                log_unit_warning(UNIT(n), "Making timed out. Terminating.");
                busname_enter_signal(n, BUSNAME_SIGTERM, BUSNAME_FAILURE_TIMEOUT);
                break;

        case BUSNAME_SIGTERM:
                log_unit_warning(UNIT(n), "Stopping timed out. Killing.");
                busname_enter_signal(n, BUSNAME_SIGKILL, BUSNAME_FAILURE_TIMEOUT);
                break;

        case BUSNAME_SIGKILL:
                log_unit_warning(UNIT(n), "Processes still around after SIGKILL. Ignoring.");
                busname_enter_dead(n, BUSNAME_FAILURE_TIMEOUT);
                break;

        default:
                assert_not_reached("Timeout at wrong time.");
        }

        return 0;
}

static void busname_reset_failed(Unit *u) {
        BusName *n = BUSNAME(u);

        assert(n);

        if (n->state == BUSNAME_FAILED)
                busname_set_state(n, BUSNAME_DEAD);

        n->result = BUSNAME_SUCCESS;
}

static void busname_trigger_notify(Unit *u, Unit *other) {
        BusName *n = BUSNAME(u);
        Service *s;

        assert(n);
        assert(other);

        if (!IN_SET(n->state, BUSNAME_RUNNING, BUSNAME_LISTENING))
                return;

        if (other->load_state != UNIT_LOADED || other->type != UNIT_SERVICE)
                return;

        s = SERVICE(other);

        if (s->state == SERVICE_FAILED && s->result == SERVICE_FAILURE_START_LIMIT)
                busname_enter_dead(n, BUSNAME_FAILURE_SERVICE_FAILED_PERMANENT);
        else if (IN_SET(s->state,
                        SERVICE_DEAD, SERVICE_FAILED,
                        SERVICE_STOP, SERVICE_STOP_SIGTERM, SERVICE_STOP_SIGKILL,
                        SERVICE_STOP_POST, SERVICE_FINAL_SIGTERM, SERVICE_FINAL_SIGKILL,
                        SERVICE_AUTO_RESTART))
                busname_enter_listening(n);
}

static int busname_kill(Unit *u, KillWho who, int signo, sd_bus_error *error) {
        return unit_kill_common(u, who, signo, -1, BUSNAME(u)->control_pid, error);
}

static int busname_get_timeout(Unit *u, uint64_t *timeout) {
        BusName *n = BUSNAME(u);
        int r;

        if (!n->timer_event_source)
                return 0;

        r = sd_event_source_get_time(n->timer_event_source, timeout);
        if (r < 0)
                return r;

        return 1;
}

static bool busname_supported(void) {
        static int supported = -1;

        if (supported < 0)
                supported = is_kdbus_available();

        return supported;
}

static const char* const busname_state_table[_BUSNAME_STATE_MAX] = {
        [BUSNAME_DEAD] = "dead",
        [BUSNAME_MAKING] = "making",
        [BUSNAME_REGISTERED] = "registered",
        [BUSNAME_LISTENING] = "listening",
        [BUSNAME_RUNNING] = "running",
        [BUSNAME_SIGTERM] = "sigterm",
        [BUSNAME_SIGKILL] = "sigkill",
        [BUSNAME_FAILED] = "failed",
};

DEFINE_STRING_TABLE_LOOKUP(busname_state, BusNameState);

static const char* const busname_result_table[_BUSNAME_RESULT_MAX] = {
        [BUSNAME_SUCCESS] = "success",
        [BUSNAME_FAILURE_RESOURCES] = "resources",
        [BUSNAME_FAILURE_TIMEOUT] = "timeout",
        [BUSNAME_FAILURE_EXIT_CODE] = "exit-code",
        [BUSNAME_FAILURE_SIGNAL] = "signal",
        [BUSNAME_FAILURE_CORE_DUMP] = "core-dump",
        [BUSNAME_FAILURE_SERVICE_FAILED_PERMANENT] = "service-failed-permanent",
};

DEFINE_STRING_TABLE_LOOKUP(busname_result, BusNameResult);

const UnitVTable busname_vtable = {
        .object_size = sizeof(BusName),

        .sections =
                "Unit\0"
                "BusName\0"
                "Install\0",
        .private_section = "BusName",

        .no_alias = true,
        .no_instances = true,

        .init = busname_init,
        .done = busname_done,
        .load = busname_load,

        .coldplug = busname_coldplug,

        .dump = busname_dump,

        .start = busname_start,
        .stop = busname_stop,

        .kill = busname_kill,

        .get_timeout = busname_get_timeout,

        .serialize = busname_serialize,
        .deserialize_item = busname_deserialize_item,

        .active_state = busname_active_state,
        .sub_state_to_string = busname_sub_state_to_string,

        .sigchld_event = busname_sigchld_event,

        .trigger_notify = busname_trigger_notify,

        .reset_failed = busname_reset_failed,

        .supported = busname_supported,

        .bus_interface = "org.freedesktop.systemd1.BusName",
        .bus_vtable = bus_busname_vtable,

        .status_message_formats = {
                .finished_start_job = {
                        [JOB_DONE]       = "Listening on %s.",
                        [JOB_FAILED]     = "Failed to listen on %s.",
                        [JOB_DEPENDENCY] = "Dependency failed for %s.",
                        [JOB_TIMEOUT]    = "Timed out starting %s.",
                },
                .finished_stop_job = {
                        [JOB_DONE]       = "Closed %s.",
                        [JOB_FAILED]     = "Failed stopping %s.",
                        [JOB_TIMEOUT]    = "Timed out stopping %s.",
                },
        },
};
