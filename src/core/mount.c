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

#include <errno.h>
#include <stdio.h>
#include <mntent.h>
#include <sys/epoll.h>
#include <signal.h>

#include "manager.h"
#include "unit.h"
#include "mount.h"
#include "load-fragment.h"
#include "load-dropin.h"
#include "log.h"
#include "sd-messages.h"
#include "strv.h"
#include "mkdir.h"
#include "path-util.h"
#include "mount-setup.h"
#include "unit-name.h"
#include "dbus-mount.h"
#include "special.h"
#include "bus-errors.h"
#include "exit-status.h"
#include "def.h"

static const UnitActiveState state_translation_table[_MOUNT_STATE_MAX] = {
        [MOUNT_DEAD] = UNIT_INACTIVE,
        [MOUNT_MOUNTING] = UNIT_ACTIVATING,
        [MOUNT_MOUNTING_DONE] = UNIT_ACTIVE,
        [MOUNT_MOUNTED] = UNIT_ACTIVE,
        [MOUNT_REMOUNTING] = UNIT_RELOADING,
        [MOUNT_UNMOUNTING] = UNIT_DEACTIVATING,
        [MOUNT_MOUNTING_SIGTERM] = UNIT_DEACTIVATING,
        [MOUNT_MOUNTING_SIGKILL] = UNIT_DEACTIVATING,
        [MOUNT_REMOUNTING_SIGTERM] = UNIT_RELOADING,
        [MOUNT_REMOUNTING_SIGKILL] = UNIT_RELOADING,
        [MOUNT_UNMOUNTING_SIGTERM] = UNIT_DEACTIVATING,
        [MOUNT_UNMOUNTING_SIGKILL] = UNIT_DEACTIVATING,
        [MOUNT_FAILED] = UNIT_FAILED
};

static int mount_dispatch_timer(sd_event_source *source, usec_t usec, void *userdata);
static int mount_dispatch_io(sd_event_source *source, int fd, uint32_t revents, void *userdata);

static bool mount_is_network(MountParameters *p) {
        assert(p);

        if (mount_test_option(p->options, "_netdev"))
                return true;

        if (p->fstype && fstype_is_network(p->fstype))
                return true;

        return false;
}

static bool mount_is_bind(MountParameters *p) {
        assert(p);

        if (mount_test_option(p->options, "bind"))
                return true;

        if (p->fstype && streq(p->fstype, "bind"))
                return true;

        if (mount_test_option(p->options, "rbind"))
                return true;

        if (p->fstype && streq(p->fstype, "rbind"))
                return true;

        return false;
}

static bool mount_is_auto(MountParameters *p) {
        assert(p);

        return !mount_test_option(p->options, "noauto");
}

static bool needs_quota(MountParameters *p) {
        assert(p);

        if (mount_is_network(p))
                return false;

        if (mount_is_bind(p))
                return false;

        return mount_test_option(p->options, "usrquota") ||
                mount_test_option(p->options, "grpquota") ||
                mount_test_option(p->options, "quota") ||
                mount_test_option(p->options, "usrjquota") ||
                mount_test_option(p->options, "grpjquota");
}

static void mount_init(Unit *u) {
        Mount *m = MOUNT(u);

        assert(u);
        assert(u->load_state == UNIT_STUB);

        m->timeout_usec = u->manager->default_timeout_start_usec;
        m->directory_mode = 0755;

        if (unit_has_name(u, "-.mount")) {
                /* Don't allow start/stop for root directory */
                u->refuse_manual_start = true;
                u->refuse_manual_stop = true;
        } else {
                /* The stdio/kmsg bridge socket is on /, in order to avoid a
                 * dep loop, don't use kmsg logging for -.mount */
                m->exec_context.std_output = u->manager->default_std_output;
                m->exec_context.std_error = u->manager->default_std_error;
        }

        /* We need to make sure that /bin/mount is always called in
         * the same process group as us, so that the autofs kernel
         * side doesn't send us another mount request while we are
         * already trying to comply its last one. */
        m->exec_context.same_pgrp = true;

        m->control_command_id = _MOUNT_EXEC_COMMAND_INVALID;

        u->ignore_on_isolate = true;
}

static int mount_arm_timer(Mount *m) {
        int r;

        assert(m);

        if (m->timeout_usec <= 0) {
                m->timer_event_source = sd_event_source_unref(m->timer_event_source);
                return 0;
        }

        if (m->timer_event_source) {
                r = sd_event_source_set_time(m->timer_event_source, now(CLOCK_MONOTONIC) + m->timeout_usec);
                if (r < 0)
                        return r;

                return sd_event_source_set_enabled(m->timer_event_source, SD_EVENT_ONESHOT);
        }

        return sd_event_add_time(
                        UNIT(m)->manager->event,
                        &m->timer_event_source,
                        CLOCK_MONOTONIC,
                        now(CLOCK_MONOTONIC) + m->timeout_usec, 0,
                        mount_dispatch_timer, m);
}

static void mount_unwatch_control_pid(Mount *m) {
        assert(m);

        if (m->control_pid <= 0)
                return;

        unit_unwatch_pid(UNIT(m), m->control_pid);
        m->control_pid = 0;
}

static void mount_parameters_done(MountParameters *p) {
        assert(p);

        free(p->what);
        free(p->options);
        free(p->fstype);

        p->what = p->options = p->fstype = NULL;
}

static void mount_done(Unit *u) {
        Mount *m = MOUNT(u);

        assert(m);

        free(m->where);
        m->where = NULL;

        mount_parameters_done(&m->parameters_proc_self_mountinfo);
        mount_parameters_done(&m->parameters_fragment);

        m->exec_runtime = exec_runtime_unref(m->exec_runtime);
        exec_command_done_array(m->exec_command, _MOUNT_EXEC_COMMAND_MAX);
        m->control_command = NULL;

        mount_unwatch_control_pid(m);

        m->timer_event_source = sd_event_source_unref(m->timer_event_source);
}

_pure_ static MountParameters* get_mount_parameters_fragment(Mount *m) {
        assert(m);

        if (m->from_fragment)
                return &m->parameters_fragment;

        return NULL;
}

_pure_ static MountParameters* get_mount_parameters(Mount *m) {
        assert(m);

        if (m->from_proc_self_mountinfo)
                return &m->parameters_proc_self_mountinfo;

        return get_mount_parameters_fragment(m);
}

static int mount_add_mount_links(Mount *m) {
        _cleanup_free_ char *parent = NULL;
        MountParameters *pm;
        Unit *other;
        Iterator i;
        Set *s;
        int r;

        assert(m);

        if (!path_equal(m->where, "/")) {
                /* Adds in links to other mount points that might lie further
                 * up in the hierarchy */
                r = path_get_parent(m->where, &parent);
                if (r < 0)
                        return r;

                r = unit_require_mounts_for(UNIT(m), parent);
                if (r < 0)
                        return r;
        }

        /* Adds in links to other mount points that might be needed
         * for the source path (if this is a bind mount) to be
         * available. */
        pm = get_mount_parameters_fragment(m);
        if (pm && pm->what &&
            path_is_absolute(pm->what) &&
            !mount_is_network(pm)) {

                r = unit_require_mounts_for(UNIT(m), pm->what);
                if (r < 0)
                        return r;
        }

        /* Adds in links to other units that use this path or paths
         * further down in the hierarchy */
        s = manager_get_units_requiring_mounts_for(UNIT(m)->manager, m->where);
        SET_FOREACH(other, s, i) {

                if (other->load_state != UNIT_LOADED)
                        continue;

                if (other == UNIT(m))
                        continue;

                r = unit_add_dependency(other, UNIT_AFTER, UNIT(m), true);
                if (r < 0)
                        return r;

                if (UNIT(m)->fragment_path) {
                        /* If we have fragment configuration, then make this dependency required */
                        r = unit_add_dependency(other, UNIT_REQUIRES, UNIT(m), true);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int mount_add_device_links(Mount *m) {
        MountParameters *p;
        bool device_wants_mount = false;
        int r;

        assert(m);

        p = get_mount_parameters_fragment(m);
        if (!p)
                return 0;

        if (!p->what)
                return 0;

        if (mount_is_bind(p))
                return 0;

        if (!is_device_path(p->what))
                return 0;

        if (path_equal(m->where, "/"))
                return 0;

        if (mount_is_auto(p) && UNIT(m)->manager->running_as == SYSTEMD_SYSTEM)
                device_wants_mount = true;

        r = unit_add_node_link(UNIT(m), p->what, device_wants_mount);
        if (r < 0)
                return r;

        return 0;
}

static int mount_add_quota_links(Mount *m) {
        int r;
        MountParameters *p;

        assert(m);

        if (UNIT(m)->manager->running_as != SYSTEMD_SYSTEM)
                return 0;

        p = get_mount_parameters_fragment(m);
        if (!p)
                return 0;

        if (!needs_quota(p))
                return 0;

        r = unit_add_two_dependencies_by_name(UNIT(m), UNIT_BEFORE, UNIT_WANTS, SPECIAL_QUOTACHECK_SERVICE, NULL, true);
        if (r < 0)
                return r;

        r = unit_add_two_dependencies_by_name(UNIT(m), UNIT_BEFORE, UNIT_WANTS, SPECIAL_QUOTAON_SERVICE, NULL, true);
        if (r < 0)
                return r;

        return 0;
}

static bool should_umount(Mount *m) {
        MountParameters *p;

        if (path_equal(m->where, "/") ||
            path_equal(m->where, "/usr"))
                return false;

        p = get_mount_parameters(m);
        if (p && mount_test_option(p->options, "x-initrd.mount") &&
            !in_initrd())
                return false;

        return true;
}

static int mount_add_default_dependencies(Mount *m) {
        const char *after, *after2, *online;
        MountParameters *p;
        int r;

        assert(m);

        if (UNIT(m)->manager->running_as != SYSTEMD_SYSTEM)
                return 0;

        p = get_mount_parameters(m);

        if (!p)
                return 0;

        if (path_equal(m->where, "/"))
                return 0;

        if (mount_is_network(p)) {
                after = SPECIAL_REMOTE_FS_PRE_TARGET;
                after2 = SPECIAL_NETWORK_TARGET;
                online = SPECIAL_NETWORK_ONLINE_TARGET;
        } else {
                after = SPECIAL_LOCAL_FS_PRE_TARGET;
                after2 = NULL;
                online = NULL;
        }

        r = unit_add_dependency_by_name(UNIT(m), UNIT_AFTER, after, NULL, true);
        if (r < 0)
                return r;

        if (after2) {
                r = unit_add_dependency_by_name(UNIT(m), UNIT_AFTER, after2, NULL, true);
                if (r < 0)
                        return r;
        }

        if (online) {
                r = unit_add_two_dependencies_by_name(UNIT(m), UNIT_WANTS, UNIT_AFTER, online, NULL, true);
                if (r < 0)
                        return r;
        }

        if (should_umount(m)) {
                r = unit_add_two_dependencies_by_name(UNIT(m), UNIT_BEFORE, UNIT_CONFLICTS, SPECIAL_UMOUNT_TARGET, NULL, true);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int mount_verify(Mount *m) {
        _cleanup_free_ char *e = NULL;
        bool b;

        assert(m);

        if (UNIT(m)->load_state != UNIT_LOADED)
                return 0;

        if (!m->from_fragment && !m->from_proc_self_mountinfo)
                return -ENOENT;

        e = unit_name_from_path(m->where, ".mount");
        if (!e)
                return -ENOMEM;

        b = unit_has_name(UNIT(m), e);
        if (!b) {
                log_error_unit(UNIT(m)->id, "%s's Where= setting doesn't match unit name. Refusing.", UNIT(m)->id);
                return -EINVAL;
        }

        if (mount_point_is_api(m->where) || mount_point_ignore(m->where)) {
                log_error_unit(UNIT(m)->id, "Cannot create mount unit for API file system %s. Refusing.", m->where);
                return -EINVAL;
        }

        if (UNIT(m)->fragment_path && !m->parameters_fragment.what) {
                log_error_unit(UNIT(m)->id, "%s's What setting is missing. Refusing.", UNIT(m)->id);
                return -EBADMSG;
        }

        if (m->exec_context.pam_name && m->kill_context.kill_mode != KILL_CONTROL_GROUP) {
                log_error_unit(UNIT(m)->id, "%s has PAM enabled. Kill mode must be set to control-group'. Refusing.",UNIT(m)->id);
                return -EINVAL;
        }

        return 0;
}

static int mount_add_extras(Mount *m) {
        Unit *u = UNIT(m);
        int r;

        assert(m);

        if (u->fragment_path)
                m->from_fragment = true;

        if (!m->where) {
                m->where = unit_name_to_path(u->id);
                if (!m->where)
                        return -ENOMEM;
        }

        path_kill_slashes(m->where);

        if (!u->description) {
                r = unit_set_description(u, m->where);
                if (r < 0)
                        return r;
        }

        r = mount_add_device_links(m);
        if (r < 0)
                return r;

        r = mount_add_mount_links(m);
        if (r < 0)
                return r;

        r = mount_add_quota_links(m);
        if (r < 0)
                return r;

        r = unit_patch_contexts(u);
        if (r < 0)
                return r;

        r = unit_add_exec_dependencies(u, &m->exec_context);
        if (r < 0)
                return r;

        r = unit_add_default_slice(u, &m->cgroup_context);
        if (r < 0)
                return r;

        if (u->default_dependencies) {
                r = mount_add_default_dependencies(m);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int mount_load(Unit *u) {
        Mount *m = MOUNT(u);
        int r;

        assert(u);
        assert(u->load_state == UNIT_STUB);

        if (m->from_proc_self_mountinfo)
                r = unit_load_fragment_and_dropin_optional(u);
        else
                r = unit_load_fragment_and_dropin(u);

        if (r < 0)
                return r;

        /* This is a new unit? Then let's add in some extras */
        if (u->load_state == UNIT_LOADED) {
                r = mount_add_extras(m);
                if (r < 0)
                        return r;
        }

        return mount_verify(m);
}

static int mount_notify_automount(Mount *m, int status) {
        Unit *p;
        int r;
        Iterator i;

        assert(m);

        SET_FOREACH(p, UNIT(m)->dependencies[UNIT_TRIGGERED_BY], i)
                if (p->type == UNIT_AUTOMOUNT) {
                         r = automount_send_ready(AUTOMOUNT(p), status);
                         if (r < 0)
                                 return r;
                }

        return 0;
}

static void mount_set_state(Mount *m, MountState state) {
        MountState old_state;
        assert(m);

        old_state = m->state;
        m->state = state;

        if (state != MOUNT_MOUNTING &&
            state != MOUNT_MOUNTING_DONE &&
            state != MOUNT_REMOUNTING &&
            state != MOUNT_UNMOUNTING &&
            state != MOUNT_MOUNTING_SIGTERM &&
            state != MOUNT_MOUNTING_SIGKILL &&
            state != MOUNT_UNMOUNTING_SIGTERM &&
            state != MOUNT_UNMOUNTING_SIGKILL &&
            state != MOUNT_REMOUNTING_SIGTERM &&
            state != MOUNT_REMOUNTING_SIGKILL) {
                m->timer_event_source = sd_event_source_unref(m->timer_event_source);
                mount_unwatch_control_pid(m);
                m->control_command = NULL;
                m->control_command_id = _MOUNT_EXEC_COMMAND_INVALID;
        }

        if (state == MOUNT_MOUNTED ||
            state == MOUNT_REMOUNTING)
                mount_notify_automount(m, 0);
        else if (state == MOUNT_DEAD ||
                 state == MOUNT_UNMOUNTING ||
                 state == MOUNT_MOUNTING_SIGTERM ||
                 state == MOUNT_MOUNTING_SIGKILL ||
                 state == MOUNT_REMOUNTING_SIGTERM ||
                 state == MOUNT_REMOUNTING_SIGKILL ||
                 state == MOUNT_UNMOUNTING_SIGTERM ||
                 state == MOUNT_UNMOUNTING_SIGKILL ||
                 state == MOUNT_FAILED) {
                if (state != old_state)
                        mount_notify_automount(m, -ENODEV);
        }

        if (state != old_state)
                log_debug_unit(UNIT(m)->id,
                               "%s changed %s -> %s",
                               UNIT(m)->id,
                               mount_state_to_string(old_state),
                               mount_state_to_string(state));

        unit_notify(UNIT(m), state_translation_table[old_state], state_translation_table[state], m->reload_result == MOUNT_SUCCESS);
        m->reload_result = MOUNT_SUCCESS;
}

static int mount_coldplug(Unit *u) {
        Mount *m = MOUNT(u);
        MountState new_state = MOUNT_DEAD;
        int r;

        assert(m);
        assert(m->state == MOUNT_DEAD);

        if (m->deserialized_state != m->state)
                new_state = m->deserialized_state;
        else if (m->from_proc_self_mountinfo)
                new_state = MOUNT_MOUNTED;

        if (new_state == m->state)
                return 0;

        if (new_state == MOUNT_MOUNTING ||
            new_state == MOUNT_MOUNTING_DONE ||
            new_state == MOUNT_REMOUNTING ||
            new_state == MOUNT_UNMOUNTING ||
            new_state == MOUNT_MOUNTING_SIGTERM ||
            new_state == MOUNT_MOUNTING_SIGKILL ||
            new_state == MOUNT_UNMOUNTING_SIGTERM ||
            new_state == MOUNT_UNMOUNTING_SIGKILL ||
            new_state == MOUNT_REMOUNTING_SIGTERM ||
            new_state == MOUNT_REMOUNTING_SIGKILL) {

                if (m->control_pid <= 0)
                        return -EBADMSG;

                r = unit_watch_pid(UNIT(m), m->control_pid);
                if (r < 0)
                        return r;

                r = mount_arm_timer(m);
                if (r < 0)
                        return r;
        }

        mount_set_state(m, new_state);
        return 0;
}

static void mount_dump(Unit *u, FILE *f, const char *prefix) {
        Mount *m = MOUNT(u);
        MountParameters *p;

        assert(m);
        assert(f);

        p = get_mount_parameters(m);

        fprintf(f,
                "%sMount State: %s\n"
                "%sResult: %s\n"
                "%sWhere: %s\n"
                "%sWhat: %s\n"
                "%sFile System Type: %s\n"
                "%sOptions: %s\n"
                "%sFrom /proc/self/mountinfo: %s\n"
                "%sFrom fragment: %s\n"
                "%sDirectoryMode: %04o\n",
                prefix, mount_state_to_string(m->state),
                prefix, mount_result_to_string(m->result),
                prefix, m->where,
                prefix, p ? strna(p->what) : "n/a",
                prefix, p ? strna(p->fstype) : "n/a",
                prefix, p ? strna(p->options) : "n/a",
                prefix, yes_no(m->from_proc_self_mountinfo),
                prefix, yes_no(m->from_fragment),
                prefix, m->directory_mode);

        if (m->control_pid > 0)
                fprintf(f,
                        "%sControl PID: "PID_FMT"\n",
                        prefix, m->control_pid);

        exec_context_dump(&m->exec_context, f, prefix);
        kill_context_dump(&m->kill_context, f, prefix);
}

static int mount_spawn(Mount *m, ExecCommand *c, pid_t *_pid) {
        pid_t pid;
        int r;

        assert(m);
        assert(c);
        assert(_pid);

        unit_realize_cgroup(UNIT(m));

        r = unit_setup_exec_runtime(UNIT(m));
        if (r < 0)
                goto fail;

        r = mount_arm_timer(m);
        if (r < 0)
                goto fail;

        r = exec_spawn(c,
                       NULL,
                       &m->exec_context,
                       NULL, 0,
                       UNIT(m)->manager->environment,
                       true,
                       true,
                       true,
                       UNIT(m)->manager->confirm_spawn,
                       UNIT(m)->manager->cgroup_supported,
                       UNIT(m)->cgroup_path,
                       manager_get_runtime_prefix(UNIT(m)->manager),
                       UNIT(m)->id,
                       0,
                       NULL,
                       m->exec_runtime,
                       &pid);
        if (r < 0)
                goto fail;

        r = unit_watch_pid(UNIT(m), pid);
        if (r < 0)
                /* FIXME: we need to do something here */
                goto fail;

        *_pid = pid;

        return 0;

fail:
        m->timer_event_source = sd_event_source_unref(m->timer_event_source);

        return r;
}

static void mount_enter_dead(Mount *m, MountResult f) {
        assert(m);

        if (f != MOUNT_SUCCESS)
                m->result = f;

        exec_runtime_destroy(m->exec_runtime);
        m->exec_runtime = exec_runtime_unref(m->exec_runtime);

        exec_context_destroy_runtime_directory(&m->exec_context, manager_get_runtime_prefix(UNIT(m)->manager));

        mount_set_state(m, m->result != MOUNT_SUCCESS ? MOUNT_FAILED : MOUNT_DEAD);
}

static void mount_enter_mounted(Mount *m, MountResult f) {
        assert(m);

        if (f != MOUNT_SUCCESS)
                m->result = f;

        mount_set_state(m, MOUNT_MOUNTED);
}

static void mount_enter_signal(Mount *m, MountState state, MountResult f) {
        int r;

        assert(m);

        if (f != MOUNT_SUCCESS)
                m->result = f;

        r = unit_kill_context(
                        UNIT(m),
                        &m->kill_context,
                        state != MOUNT_MOUNTING_SIGTERM && state != MOUNT_UNMOUNTING_SIGTERM && state != MOUNT_REMOUNTING_SIGTERM,
                        -1,
                        m->control_pid,
                        false);
        if (r < 0)
                goto fail;

        if (r > 0) {
                r = mount_arm_timer(m);
                if (r < 0)
                        goto fail;

                mount_set_state(m, state);
        } else if (state == MOUNT_REMOUNTING_SIGTERM)
                mount_enter_signal(m, MOUNT_REMOUNTING_SIGKILL, MOUNT_SUCCESS);
        else if (state == MOUNT_REMOUNTING_SIGKILL)
                mount_enter_mounted(m, MOUNT_SUCCESS);
        else if (state == MOUNT_MOUNTING_SIGTERM)
                mount_enter_signal(m, MOUNT_MOUNTING_SIGKILL, MOUNT_SUCCESS);
        else if (state == MOUNT_UNMOUNTING_SIGTERM)
                mount_enter_signal(m, MOUNT_UNMOUNTING_SIGKILL, MOUNT_SUCCESS);
        else
                mount_enter_dead(m, MOUNT_SUCCESS);

        return;

fail:
        log_warning_unit(UNIT(m)->id,
                         "%s failed to kill processes: %s", UNIT(m)->id, strerror(-r));

        if (state == MOUNT_REMOUNTING_SIGTERM || state == MOUNT_REMOUNTING_SIGKILL)
                mount_enter_mounted(m, MOUNT_FAILURE_RESOURCES);
        else
                mount_enter_dead(m, MOUNT_FAILURE_RESOURCES);
}

void warn_if_dir_nonempty(const char *unit, const char* where) {
        assert(unit);
        assert(where);

        if (dir_is_empty(where) > 0)
                return;

        log_struct_unit(LOG_NOTICE,
                   unit,
                   "MESSAGE=%s: Directory %s to mount over is not empty, mounting anyway.",
                   unit, where,
                   "WHERE=%s", where,
                   MESSAGE_ID(SD_MESSAGE_OVERMOUNTING),
                   NULL);
}

static void mount_enter_unmounting(Mount *m) {
        int r;

        assert(m);

        m->control_command_id = MOUNT_EXEC_UNMOUNT;
        m->control_command = m->exec_command + MOUNT_EXEC_UNMOUNT;

        if ((r = exec_command_set(
                             m->control_command,
                             "/bin/umount",
                             "-n",
                             m->where,
                             NULL)) < 0)
                goto fail;

        mount_unwatch_control_pid(m);

        if ((r = mount_spawn(m, m->control_command, &m->control_pid)) < 0)
                goto fail;

        mount_set_state(m, MOUNT_UNMOUNTING);

        return;

fail:
        log_warning_unit(UNIT(m)->id,
                         "%s failed to run 'umount' task: %s",
                         UNIT(m)->id, strerror(-r));
        mount_enter_mounted(m, MOUNT_FAILURE_RESOURCES);
}

static void mount_enter_mounting(Mount *m) {
        int r;
        MountParameters *p;

        assert(m);

        m->control_command_id = MOUNT_EXEC_MOUNT;
        m->control_command = m->exec_command + MOUNT_EXEC_MOUNT;

        mkdir_p_label(m->where, m->directory_mode);

        warn_if_dir_nonempty(m->meta.id, m->where);

        /* Create the source directory for bind-mounts if needed */
        p = get_mount_parameters_fragment(m);
        if (p && mount_is_bind(p))
                mkdir_p_label(p->what, m->directory_mode);

        if (m->from_fragment)
                r = exec_command_set(
                                m->control_command,
                                "/bin/mount",
                                m->sloppy_options ? "-ns" : "-n",
                                m->parameters_fragment.what,
                                m->where,
                                "-t", m->parameters_fragment.fstype ? m->parameters_fragment.fstype : "auto",
                                m->parameters_fragment.options ? "-o" : NULL, m->parameters_fragment.options,
                                NULL);
        else
                r = -ENOENT;

        if (r < 0)
                goto fail;

        mount_unwatch_control_pid(m);

        r = mount_spawn(m, m->control_command, &m->control_pid);
        if (r < 0)
                goto fail;

        mount_set_state(m, MOUNT_MOUNTING);

        return;

fail:
        log_warning_unit(UNIT(m)->id,
                         "%s failed to run 'mount' task: %s",
                         UNIT(m)->id, strerror(-r));
        mount_enter_dead(m, MOUNT_FAILURE_RESOURCES);
}

static void mount_enter_remounting(Mount *m) {
        int r;

        assert(m);

        m->control_command_id = MOUNT_EXEC_REMOUNT;
        m->control_command = m->exec_command + MOUNT_EXEC_REMOUNT;

        if (m->from_fragment) {
                const char *o;

                if (m->parameters_fragment.options)
                        o = strappenda("remount,", m->parameters_fragment.options);
                else
                        o = "remount";

                r = exec_command_set(
                                m->control_command,
                                "/bin/mount",
                                m->sloppy_options ? "-ns" : "-n",
                                m->parameters_fragment.what,
                                m->where,
                                "-t", m->parameters_fragment.fstype ? m->parameters_fragment.fstype : "auto",
                                "-o", o,
                                NULL);
        } else
                r = -ENOENT;

        if (r < 0)
                goto fail;

        mount_unwatch_control_pid(m);

        r = mount_spawn(m, m->control_command, &m->control_pid);
        if (r < 0)
                goto fail;

        mount_set_state(m, MOUNT_REMOUNTING);

        return;

fail:
        log_warning_unit(UNIT(m)->id,
                         "%s failed to run 'remount' task: %s",
                         UNIT(m)->id, strerror(-r));
        m->reload_result = MOUNT_FAILURE_RESOURCES;
        mount_enter_mounted(m, MOUNT_SUCCESS);
}

static int mount_start(Unit *u) {
        Mount *m = MOUNT(u);

        assert(m);

        /* We cannot fulfill this request right now, try again later
         * please! */
        if (m->state == MOUNT_UNMOUNTING ||
            m->state == MOUNT_UNMOUNTING_SIGTERM ||
            m->state == MOUNT_UNMOUNTING_SIGKILL ||
            m->state == MOUNT_MOUNTING_SIGTERM ||
            m->state == MOUNT_MOUNTING_SIGKILL)
                return -EAGAIN;

        /* Already on it! */
        if (m->state == MOUNT_MOUNTING)
                return 0;

        assert(m->state == MOUNT_DEAD || m->state == MOUNT_FAILED);

        m->result = MOUNT_SUCCESS;
        m->reload_result = MOUNT_SUCCESS;

        mount_enter_mounting(m);
        return 0;
}

static int mount_stop(Unit *u) {
        Mount *m = MOUNT(u);

        assert(m);

        /* Already on it */
        if (m->state == MOUNT_UNMOUNTING ||
            m->state == MOUNT_UNMOUNTING_SIGKILL ||
            m->state == MOUNT_UNMOUNTING_SIGTERM ||
            m->state == MOUNT_MOUNTING_SIGTERM ||
            m->state == MOUNT_MOUNTING_SIGKILL)
                return 0;

        assert(m->state == MOUNT_MOUNTING ||
               m->state == MOUNT_MOUNTING_DONE ||
               m->state == MOUNT_MOUNTED ||
               m->state == MOUNT_REMOUNTING ||
               m->state == MOUNT_REMOUNTING_SIGTERM ||
               m->state == MOUNT_REMOUNTING_SIGKILL);

        mount_enter_unmounting(m);
        return 0;
}

static int mount_reload(Unit *u) {
        Mount *m = MOUNT(u);

        assert(m);

        if (m->state == MOUNT_MOUNTING_DONE)
                return -EAGAIN;

        assert(m->state == MOUNT_MOUNTED);

        mount_enter_remounting(m);
        return 0;
}

static int mount_serialize(Unit *u, FILE *f, FDSet *fds) {
        Mount *m = MOUNT(u);

        assert(m);
        assert(f);
        assert(fds);

        unit_serialize_item(u, f, "state", mount_state_to_string(m->state));
        unit_serialize_item(u, f, "result", mount_result_to_string(m->result));
        unit_serialize_item(u, f, "reload-result", mount_result_to_string(m->reload_result));

        if (m->control_pid > 0)
                unit_serialize_item_format(u, f, "control-pid", PID_FMT, m->control_pid);

        if (m->control_command_id >= 0)
                unit_serialize_item(u, f, "control-command", mount_exec_command_to_string(m->control_command_id));

        return 0;
}

static int mount_deserialize_item(Unit *u, const char *key, const char *value, FDSet *fds) {
        Mount *m = MOUNT(u);

        assert(u);
        assert(key);
        assert(value);
        assert(fds);

        if (streq(key, "state")) {
                MountState state;

                if ((state = mount_state_from_string(value)) < 0)
                        log_debug_unit(u->id, "Failed to parse state value %s", value);
                else
                        m->deserialized_state = state;
        } else if (streq(key, "result")) {
                MountResult f;

                f = mount_result_from_string(value);
                if (f < 0)
                        log_debug_unit(UNIT(m)->id,
                                       "Failed to parse result value %s", value);
                else if (f != MOUNT_SUCCESS)
                        m->result = f;

        } else if (streq(key, "reload-result")) {
                MountResult f;

                f = mount_result_from_string(value);
                if (f < 0)
                        log_debug_unit(UNIT(m)->id,
                                       "Failed to parse reload result value %s", value);
                else if (f != MOUNT_SUCCESS)
                        m->reload_result = f;

        } else if (streq(key, "control-pid")) {
                pid_t pid;

                if (parse_pid(value, &pid) < 0)
                        log_debug_unit(UNIT(m)->id,
                                       "Failed to parse control-pid value %s", value);
                else
                        m->control_pid = pid;
        } else if (streq(key, "control-command")) {
                MountExecCommand id;

                if ((id = mount_exec_command_from_string(value)) < 0)
                        log_debug_unit(UNIT(m)->id,
                                       "Failed to parse exec-command value %s", value);
                else {
                        m->control_command_id = id;
                        m->control_command = m->exec_command + id;
                }
        } else
                log_debug_unit(UNIT(m)->id,
                               "Unknown serialization key '%s'", key);

        return 0;
}

_pure_ static UnitActiveState mount_active_state(Unit *u) {
        assert(u);

        return state_translation_table[MOUNT(u)->state];
}

_pure_ static const char *mount_sub_state_to_string(Unit *u) {
        assert(u);

        return mount_state_to_string(MOUNT(u)->state);
}

_pure_ static bool mount_check_gc(Unit *u) {
        Mount *m = MOUNT(u);

        assert(m);

        return m->from_proc_self_mountinfo;
}

static void mount_sigchld_event(Unit *u, pid_t pid, int code, int status) {
        Mount *m = MOUNT(u);
        MountResult f;

        assert(m);
        assert(pid >= 0);

        if (pid != m->control_pid)
                return;

        m->control_pid = 0;

        if (is_clean_exit(code, status, NULL))
                f = MOUNT_SUCCESS;
        else if (code == CLD_EXITED)
                f = MOUNT_FAILURE_EXIT_CODE;
        else if (code == CLD_KILLED)
                f = MOUNT_FAILURE_SIGNAL;
        else if (code == CLD_DUMPED)
                f = MOUNT_FAILURE_CORE_DUMP;
        else
                assert_not_reached("Unknown code");

        if (f != MOUNT_SUCCESS)
                m->result = f;

        if (m->control_command) {
                exec_status_exit(&m->control_command->exec_status, &m->exec_context, pid, code, status);

                m->control_command = NULL;
                m->control_command_id = _MOUNT_EXEC_COMMAND_INVALID;
        }

        log_full_unit(f == MOUNT_SUCCESS ? LOG_DEBUG : LOG_NOTICE, u->id,
                      "%s mount process exited, code=%s status=%i",
                      u->id, sigchld_code_to_string(code), status);

        /* Note that mount(8) returning and the kernel sending us a
         * mount table change event might happen out-of-order. If an
         * operation succeed we assume the kernel will follow soon too
         * and already change into the resulting state.  If it fails
         * we check if the kernel still knows about the mount. and
         * change state accordingly. */

        switch (m->state) {

        case MOUNT_MOUNTING:
        case MOUNT_MOUNTING_DONE:
        case MOUNT_MOUNTING_SIGKILL:
        case MOUNT_MOUNTING_SIGTERM:

                if (f == MOUNT_SUCCESS)
                        mount_enter_mounted(m, f);
                else if (m->from_proc_self_mountinfo)
                        mount_enter_mounted(m, f);
                else
                        mount_enter_dead(m, f);
                break;

        case MOUNT_REMOUNTING:
        case MOUNT_REMOUNTING_SIGKILL:
        case MOUNT_REMOUNTING_SIGTERM:

                m->reload_result = f;
                if (m->from_proc_self_mountinfo)
                        mount_enter_mounted(m, MOUNT_SUCCESS);
                else
                        mount_enter_dead(m, MOUNT_SUCCESS);

                break;

        case MOUNT_UNMOUNTING:
        case MOUNT_UNMOUNTING_SIGKILL:
        case MOUNT_UNMOUNTING_SIGTERM:

                if (f == MOUNT_SUCCESS)
                        mount_enter_dead(m, f);
                else if (m->from_proc_self_mountinfo)
                        mount_enter_mounted(m, f);
                else
                        mount_enter_dead(m, f);
                break;

        default:
                assert_not_reached("Uh, control process died at wrong time.");
        }

        /* Notify clients about changed exit status */
        unit_add_to_dbus_queue(u);
}

static int mount_dispatch_timer(sd_event_source *source, usec_t usec, void *userdata) {
        Mount *m = MOUNT(userdata);

        assert(m);
        assert(m->timer_event_source == source);

        switch (m->state) {

        case MOUNT_MOUNTING:
        case MOUNT_MOUNTING_DONE:
                log_warning_unit(UNIT(m)->id,
                                 "%s mounting timed out. Stopping.", UNIT(m)->id);
                mount_enter_signal(m, MOUNT_MOUNTING_SIGTERM, MOUNT_FAILURE_TIMEOUT);
                break;

        case MOUNT_REMOUNTING:
                log_warning_unit(UNIT(m)->id,
                                 "%s remounting timed out. Stopping.", UNIT(m)->id);
                m->reload_result = MOUNT_FAILURE_TIMEOUT;
                mount_enter_mounted(m, MOUNT_SUCCESS);
                break;

        case MOUNT_UNMOUNTING:
                log_warning_unit(UNIT(m)->id,
                                 "%s unmounting timed out. Stopping.", UNIT(m)->id);
                mount_enter_signal(m, MOUNT_UNMOUNTING_SIGTERM, MOUNT_FAILURE_TIMEOUT);
                break;

        case MOUNT_MOUNTING_SIGTERM:
                if (m->kill_context.send_sigkill) {
                        log_warning_unit(UNIT(m)->id,
                                         "%s mounting timed out. Killing.", UNIT(m)->id);
                        mount_enter_signal(m, MOUNT_MOUNTING_SIGKILL, MOUNT_FAILURE_TIMEOUT);
                } else {
                        log_warning_unit(UNIT(m)->id,
                                         "%s mounting timed out. Skipping SIGKILL. Ignoring.",
                                         UNIT(m)->id);

                        if (m->from_proc_self_mountinfo)
                                mount_enter_mounted(m, MOUNT_FAILURE_TIMEOUT);
                        else
                                mount_enter_dead(m, MOUNT_FAILURE_TIMEOUT);
                }
                break;

        case MOUNT_REMOUNTING_SIGTERM:
                if (m->kill_context.send_sigkill) {
                        log_warning_unit(UNIT(m)->id,
                                         "%s remounting timed out. Killing.", UNIT(m)->id);
                        mount_enter_signal(m, MOUNT_REMOUNTING_SIGKILL, MOUNT_FAILURE_TIMEOUT);
                } else {
                        log_warning_unit(UNIT(m)->id,
                                         "%s remounting timed out. Skipping SIGKILL. Ignoring.",
                                         UNIT(m)->id);

                        if (m->from_proc_self_mountinfo)
                                mount_enter_mounted(m, MOUNT_FAILURE_TIMEOUT);
                        else
                                mount_enter_dead(m, MOUNT_FAILURE_TIMEOUT);
                }
                break;

        case MOUNT_UNMOUNTING_SIGTERM:
                if (m->kill_context.send_sigkill) {
                        log_warning_unit(UNIT(m)->id,
                                         "%s unmounting timed out. Killing.", UNIT(m)->id);
                        mount_enter_signal(m, MOUNT_UNMOUNTING_SIGKILL, MOUNT_FAILURE_TIMEOUT);
                } else {
                        log_warning_unit(UNIT(m)->id,
                                         "%s unmounting timed out. Skipping SIGKILL. Ignoring.",
                                         UNIT(m)->id);

                        if (m->from_proc_self_mountinfo)
                                mount_enter_mounted(m, MOUNT_FAILURE_TIMEOUT);
                        else
                                mount_enter_dead(m, MOUNT_FAILURE_TIMEOUT);
                }
                break;

        case MOUNT_MOUNTING_SIGKILL:
        case MOUNT_REMOUNTING_SIGKILL:
        case MOUNT_UNMOUNTING_SIGKILL:
                log_warning_unit(UNIT(m)->id,
                                 "%s mount process still around after SIGKILL. Ignoring.",
                                 UNIT(m)->id);

                if (m->from_proc_self_mountinfo)
                        mount_enter_mounted(m, MOUNT_FAILURE_TIMEOUT);
                else
                        mount_enter_dead(m, MOUNT_FAILURE_TIMEOUT);
                break;

        default:
                assert_not_reached("Timeout at wrong time.");
        }

        return 0;
}

static int mount_add_one(
                Manager *m,
                const char *what,
                const char *where,
                const char *options,
                const char *fstype,
                bool set_flags) {

        _cleanup_free_ char *e = NULL, *w = NULL, *o = NULL, *f = NULL;
        bool load_extras = false;
        MountParameters *p;
        bool delete, changed = false;
        Unit *u;
        int r;

        assert(m);
        assert(what);
        assert(where);
        assert(options);
        assert(fstype);

        /* Ignore API mount points. They should never be referenced in
         * dependencies ever. */
        if (mount_point_is_api(where) || mount_point_ignore(where))
                return 0;

        if (streq(fstype, "autofs"))
                return 0;

        /* probably some kind of swap, ignore */
        if (!is_path(where))
                return 0;

        e = unit_name_from_path(where, ".mount");
        if (!e)
                return -ENOMEM;

        u = manager_get_unit(m, e);
        if (!u) {
                delete = true;

                u = unit_new(m, sizeof(Mount));
                if (!u)
                        return -ENOMEM;

                r = unit_add_name(u, e);
                if (r < 0)
                        goto fail;

                MOUNT(u)->where = strdup(where);
                if (!MOUNT(u)->where) {
                        r = -ENOMEM;
                        goto fail;
                }

                u->source_path = strdup("/proc/self/mountinfo");
                if (!u->source_path) {
                        r = -ENOMEM;
                        goto fail;
                }


                if (m->running_as == SYSTEMD_SYSTEM) {
                        const char* target;

                        target = fstype_is_network(fstype) ? SPECIAL_REMOTE_FS_TARGET : SPECIAL_LOCAL_FS_TARGET;

                        r = unit_add_dependency_by_name(u, UNIT_BEFORE, target, NULL, true);
                        if (r < 0)
                                goto fail;

                        if (should_umount(MOUNT(u))) {
                                r = unit_add_dependency_by_name(u, UNIT_CONFLICTS, SPECIAL_UMOUNT_TARGET, NULL, true);
                                if (r < 0)
                                        goto fail;
                        }
                }

                unit_add_to_load_queue(u);
                changed = true;
        } else {
                delete = false;

                if (!MOUNT(u)->where) {
                        MOUNT(u)->where = strdup(where);
                        if (!MOUNT(u)->where) {
                                r = -ENOMEM;
                                goto fail;
                        }
                }

                if (u->load_state == UNIT_NOT_FOUND) {
                        u->load_state = UNIT_LOADED;
                        u->load_error = 0;

                        /* Load in the extras later on, after we
                         * finished initialization of the unit */
                        load_extras = true;
                        changed = true;
                }
        }

        w = strdup(what);
        o = strdup(options);
        f = strdup(fstype);
        if (!w || !o || !f) {
                r = -ENOMEM;
                goto fail;
        }

        p = &MOUNT(u)->parameters_proc_self_mountinfo;

        changed = changed ||
                !streq_ptr(p->options, options) ||
                !streq_ptr(p->what, what) ||
                !streq_ptr(p->fstype, fstype);

        if (set_flags) {
                MOUNT(u)->is_mounted = true;
                MOUNT(u)->just_mounted = !MOUNT(u)->from_proc_self_mountinfo;
                MOUNT(u)->just_changed = changed;
        }

        MOUNT(u)->from_proc_self_mountinfo = true;

        free(p->what);
        p->what = w;
        w = NULL;

        free(p->options);
        p->options = o;
        o = NULL;

        free(p->fstype);
        p->fstype = f;
        f = NULL;

        if (load_extras) {
                r = mount_add_extras(MOUNT(u));
                if (r < 0)
                        goto fail;
        }

        if (changed)
                unit_add_to_dbus_queue(u);

        return 0;

fail:
        if (delete && u)
                unit_free(u);

        return r;
}

static int mount_load_proc_self_mountinfo(Manager *m, bool set_flags) {
        int r = 0;
        unsigned i;

        assert(m);

        rewind(m->proc_self_mountinfo);

        for (i = 1;; i++) {
                _cleanup_free_ char *device = NULL, *path = NULL, *options = NULL, *options2 = NULL, *fstype = NULL, *d = NULL, *p = NULL, *o = NULL;
                int k;

                k = fscanf(m->proc_self_mountinfo,
                           "%*s "       /* (1) mount id */
                           "%*s "       /* (2) parent id */
                           "%*s "       /* (3) major:minor */
                           "%*s "       /* (4) root */
                           "%ms "       /* (5) mount point */
                           "%ms"        /* (6) mount options */
                           "%*[^-]"     /* (7) optional fields */
                           "- "         /* (8) separator */
                           "%ms "       /* (9) file system type */
                           "%ms"        /* (10) mount source */
                           "%ms"        /* (11) mount options 2 */
                           "%*[^\n]",   /* some rubbish at the end */
                           &path,
                           &options,
                           &fstype,
                           &device,
                           &options2);

                if (k == EOF)
                        break;

                if (k != 5) {
                        log_warning("Failed to parse /proc/self/mountinfo:%u.", i);
                        continue;
                }

                o = strjoin(options, ",", options2, NULL);
                if (!o)
                        return log_oom();

                d = cunescape(device);
                p = cunescape(path);
                if (!d || !p)
                        return log_oom();

                k = mount_add_one(m, d, p, o, fstype, set_flags);
                if (k < 0)
                        r = k;
        }

        return r;
}

static void mount_shutdown(Manager *m) {
        assert(m);

        m->mount_event_source = sd_event_source_unref(m->mount_event_source);

        if (m->proc_self_mountinfo) {
                fclose(m->proc_self_mountinfo);
                m->proc_self_mountinfo = NULL;
        }
}

static int mount_get_timeout(Unit *u, uint64_t *timeout) {
        Mount *m = MOUNT(u);
        int r;

        if (!m->timer_event_source)
                return 0;

        r = sd_event_source_get_time(m->timer_event_source, timeout);
        if (r < 0)
                return r;

        return 1;
}

static int mount_enumerate(Manager *m) {
        int r;
        assert(m);

        if (!m->proc_self_mountinfo) {
                m->proc_self_mountinfo = fopen("/proc/self/mountinfo", "re");
                if (!m->proc_self_mountinfo)
                        return -errno;

                r = sd_event_add_io(m->event, &m->mount_event_source, fileno(m->proc_self_mountinfo), EPOLLPRI, mount_dispatch_io, m);
                if (r < 0)
                        goto fail;

                /* Dispatch this before we dispatch SIGCHLD, so that
                 * we always get the events from /proc/self/mountinfo
                 * before the SIGCHLD of /bin/mount. */
                r = sd_event_source_set_priority(m->mount_event_source, -10);
                if (r < 0)
                        goto fail;
        }

        r = mount_load_proc_self_mountinfo(m, false);
        if (r < 0)
                goto fail;

        return 0;

fail:
        mount_shutdown(m);
        return r;
}

static int mount_dispatch_io(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        Manager *m = userdata;
        Unit *u;
        int r;

        assert(m);
        assert(revents & EPOLLPRI);

        /* The manager calls this for every fd event happening on the
         * /proc/self/mountinfo file, which informs us about mounting
         * table changes */

        r = mount_load_proc_self_mountinfo(m, true);
        if (r < 0) {
                log_error("Failed to reread /proc/self/mountinfo: %s", strerror(-r));

                /* Reset flags, just in case, for later calls */
                LIST_FOREACH(units_by_type, u, m->units_by_type[UNIT_MOUNT]) {
                        Mount *mount = MOUNT(u);

                        mount->is_mounted = mount->just_mounted = mount->just_changed = false;
                }

                return 0;
        }

        manager_dispatch_load_queue(m);

        LIST_FOREACH(units_by_type, u, m->units_by_type[UNIT_MOUNT]) {
                Mount *mount = MOUNT(u);

                if (!mount->is_mounted) {

                        mount->from_proc_self_mountinfo = false;

                        switch (mount->state) {

                        case MOUNT_MOUNTED:
                                /* This has just been unmounted by
                                 * somebody else, follow the state
                                 * change. */
                                mount_enter_dead(mount, MOUNT_SUCCESS);
                                break;

                        default:
                                break;
                        }

                } else if (mount->just_mounted || mount->just_changed) {

                        /* New or changed mount entry */

                        switch (mount->state) {

                        case MOUNT_DEAD:
                        case MOUNT_FAILED:
                                /* This has just been mounted by
                                 * somebody else, follow the state
                                 * change. */
                                mount_enter_mounted(mount, MOUNT_SUCCESS);
                                break;

                        case MOUNT_MOUNTING:
                                mount_set_state(mount, MOUNT_MOUNTING_DONE);
                                break;

                        default:
                                /* Nothing really changed, but let's
                                 * issue an notification call
                                 * nonetheless, in case somebody is
                                 * waiting for this. (e.g. file system
                                 * ro/rw remounts.) */
                                mount_set_state(mount, mount->state);
                                break;
                        }
                }

                /* Reset the flags for later calls */
                mount->is_mounted = mount->just_mounted = mount->just_changed = false;
        }

        return 0;
}

static void mount_reset_failed(Unit *u) {
        Mount *m = MOUNT(u);

        assert(m);

        if (m->state == MOUNT_FAILED)
                mount_set_state(m, MOUNT_DEAD);

        m->result = MOUNT_SUCCESS;
        m->reload_result = MOUNT_SUCCESS;
}

static int mount_kill(Unit *u, KillWho who, int signo, sd_bus_error *error) {
        return unit_kill_common(u, who, signo, -1, MOUNT(u)->control_pid, error);
}

static const char* const mount_state_table[_MOUNT_STATE_MAX] = {
        [MOUNT_DEAD] = "dead",
        [MOUNT_MOUNTING] = "mounting",
        [MOUNT_MOUNTING_DONE] = "mounting-done",
        [MOUNT_MOUNTED] = "mounted",
        [MOUNT_REMOUNTING] = "remounting",
        [MOUNT_UNMOUNTING] = "unmounting",
        [MOUNT_MOUNTING_SIGTERM] = "mounting-sigterm",
        [MOUNT_MOUNTING_SIGKILL] = "mounting-sigkill",
        [MOUNT_REMOUNTING_SIGTERM] = "remounting-sigterm",
        [MOUNT_REMOUNTING_SIGKILL] = "remounting-sigkill",
        [MOUNT_UNMOUNTING_SIGTERM] = "unmounting-sigterm",
        [MOUNT_UNMOUNTING_SIGKILL] = "unmounting-sigkill",
        [MOUNT_FAILED] = "failed"
};

DEFINE_STRING_TABLE_LOOKUP(mount_state, MountState);

static const char* const mount_exec_command_table[_MOUNT_EXEC_COMMAND_MAX] = {
        [MOUNT_EXEC_MOUNT] = "ExecMount",
        [MOUNT_EXEC_UNMOUNT] = "ExecUnmount",
        [MOUNT_EXEC_REMOUNT] = "ExecRemount",
};

DEFINE_STRING_TABLE_LOOKUP(mount_exec_command, MountExecCommand);

static const char* const mount_result_table[_MOUNT_RESULT_MAX] = {
        [MOUNT_SUCCESS] = "success",
        [MOUNT_FAILURE_RESOURCES] = "resources",
        [MOUNT_FAILURE_TIMEOUT] = "timeout",
        [MOUNT_FAILURE_EXIT_CODE] = "exit-code",
        [MOUNT_FAILURE_SIGNAL] = "signal",
        [MOUNT_FAILURE_CORE_DUMP] = "core-dump"
};

DEFINE_STRING_TABLE_LOOKUP(mount_result, MountResult);

const UnitVTable mount_vtable = {
        .object_size = sizeof(Mount),
        .exec_context_offset = offsetof(Mount, exec_context),
        .cgroup_context_offset = offsetof(Mount, cgroup_context),
        .kill_context_offset = offsetof(Mount, kill_context),
        .exec_runtime_offset = offsetof(Mount, exec_runtime),

        .sections =
                "Unit\0"
                "Mount\0"
                "Install\0",
        .private_section = "Mount",

        .no_alias = true,
        .no_instances = true,

        .init = mount_init,
        .load = mount_load,
        .done = mount_done,

        .coldplug = mount_coldplug,

        .dump = mount_dump,

        .start = mount_start,
        .stop = mount_stop,
        .reload = mount_reload,

        .kill = mount_kill,

        .serialize = mount_serialize,
        .deserialize_item = mount_deserialize_item,

        .active_state = mount_active_state,
        .sub_state_to_string = mount_sub_state_to_string,

        .check_gc = mount_check_gc,

        .sigchld_event = mount_sigchld_event,

        .reset_failed = mount_reset_failed,

        .bus_interface = "org.freedesktop.systemd1.Mount",
        .bus_vtable = bus_mount_vtable,
        .bus_set_property = bus_mount_set_property,
        .bus_commit_properties = bus_mount_commit_properties,

        .get_timeout = mount_get_timeout,

        .can_transient = true,

        .enumerate = mount_enumerate,
        .shutdown = mount_shutdown,

        .status_message_formats = {
                .starting_stopping = {
                        [0] = "Mounting %s...",
                        [1] = "Unmounting %s...",
                },
                .finished_start_job = {
                        [JOB_DONE]       = "Mounted %s.",
                        [JOB_FAILED]     = "Failed to mount %s.",
                        [JOB_DEPENDENCY] = "Dependency failed for %s.",
                        [JOB_TIMEOUT]    = "Timed out mounting %s.",
                },
                .finished_stop_job = {
                        [JOB_DONE]       = "Unmounted %s.",
                        [JOB_FAILED]     = "Failed unmounting %s.",
                        [JOB_TIMEOUT]    = "Timed out unmounting %s.",
                },
        },
};
