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
#include <sys/epoll.h>
#include <signal.h>
#include <libmount.h>
#include <sys/inotify.h>

#include "manager.h"
#include "unit.h"
#include "mount.h"
#include "log.h"
#include "sd-messages.h"
#include "strv.h"
#include "mkdir.h"
#include "path-util.h"
#include "mount-setup.h"
#include "unit-name.h"
#include "dbus-mount.h"
#include "special.h"
#include "exit-status.h"
#include "fstab-util.h"
#include "formats-util.h"

#define RETRY_UMOUNT_MAX 32

DEFINE_TRIVIAL_CLEANUP_FUNC(struct libmnt_table*, mnt_free_table);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct libmnt_iter*, mnt_free_iter);

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

static bool mount_needs_network(const char *options, const char *fstype) {
        if (fstab_test_option(options, "_netdev\0"))
                return true;

        if (fstype && fstype_is_network(fstype))
                return true;

        return false;
}

static bool mount_is_network(const MountParameters *p) {
        assert(p);

        return mount_needs_network(p->options, p->fstype);
}

static bool mount_is_bind(const MountParameters *p) {
        assert(p);

        if (fstab_test_option(p->options, "bind\0" "rbind\0"))
                return true;

        if (p->fstype && STR_IN_SET(p->fstype, "bind", "rbind"))
                return true;

        return false;
}

static bool mount_is_auto(const MountParameters *p) {
        assert(p);

        return !fstab_test_option(p->options, "noauto\0");
}

static bool needs_quota(const MountParameters *p) {
        assert(p);

        /* Quotas are not enabled on network filesystems,
         * but we want them, for example, on storage connected via iscsi */
        if (p->fstype && fstype_is_network(p->fstype))
                return false;

        if (mount_is_bind(p))
                return false;

        return fstab_test_option(p->options,
                                 "usrquota\0" "grpquota\0" "quota\0" "usrjquota\0" "grpjquota\0");
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

        /* We need to make sure that /usr/bin/mount is always called
         * in the same process group as us, so that the autofs kernel
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

        r = sd_event_add_time(
                        UNIT(m)->manager->event,
                        &m->timer_event_source,
                        CLOCK_MONOTONIC,
                        now(CLOCK_MONOTONIC) + m->timeout_usec, 0,
                        mount_dispatch_timer, m);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(m->timer_event_source, "mount-timer");

        return 0;
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

        p = get_mount_parameters(m);
        if (!p)
                return 0;

        if (!p->what)
                return 0;

        if (mount_is_bind(p))
                return 0;

        if (!is_device_path(p->what))
                return 0;

        /* /dev/root is a really weird thing, it's not a real device,
         * but just a path the kernel exports for the root file system
         * specified on the kernel command line. Ignore it here. */
        if (path_equal(p->what, "/dev/root"))
                return 0;

        if (path_equal(m->where, "/"))
                return 0;

        if (mount_is_auto(p) && UNIT(m)->manager->running_as == MANAGER_SYSTEM)
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

        if (UNIT(m)->manager->running_as != MANAGER_SYSTEM)
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
        if (p && fstab_test_option(p->options, "x-initrd.mount\0") &&
            !in_initrd())
                return false;

        return true;
}

static int mount_add_default_dependencies(Mount *m) {
        const char *after, *after2, *online;
        MountParameters *p;
        int r;

        assert(m);

        if (UNIT(m)->manager->running_as != MANAGER_SYSTEM)
                return 0;

        /* We do not add any default dependencies to / and /usr, since
         * they are guaranteed to stay mounted the whole time, since
         * our system is on it. Also, don't bother with anything
         * mounted below virtual file systems, it's also going to be
         * virtual, and hence not worth the effort. */
        if (path_equal(m->where, "/") ||
            path_equal(m->where, "/usr") ||
            path_startswith(m->where, "/proc") ||
            path_startswith(m->where, "/sys") ||
            path_startswith(m->where, "/dev"))
                return 0;

        p = get_mount_parameters(m);
        if (!p)
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
        int r;

        assert(m);

        if (UNIT(m)->load_state != UNIT_LOADED)
                return 0;

        if (!m->from_fragment && !m->from_proc_self_mountinfo)
                return -ENOENT;

        r = unit_name_from_path(m->where, ".mount", &e);
        if (r < 0)
                return log_unit_error_errno(UNIT(m), r, "Failed to generate unit name from mount path: %m");

        if (!unit_has_name(UNIT(m), e)) {
                log_unit_error(UNIT(m), "Where= setting doesn't match unit name. Refusing.");
                return -EINVAL;
        }

        if (mount_point_is_api(m->where) || mount_point_ignore(m->where)) {
                log_unit_error(UNIT(m), "Cannot create mount unit for API file system %s. Refusing.", m->where);
                return -EINVAL;
        }

        if (UNIT(m)->fragment_path && !m->parameters_fragment.what) {
                log_unit_error(UNIT(m), "What= setting is missing. Refusing.");
                return -EBADMSG;
        }

        if (m->exec_context.pam_name && m->kill_context.kill_mode != KILL_CONTROL_GROUP) {
                log_unit_error(UNIT(m), "Unit has PAM enabled. Kill mode must be set to control-group'. Refusing.");
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
                r = unit_name_to_path(u->id, &m->where);
                if (r < 0)
                        return r;
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

static int mount_notify_automount(Mount *m, MountState old_state, MountState state) {
        Unit *p;
        int r;
        Iterator i;

        assert(m);

        SET_FOREACH(p, UNIT(m)->dependencies[UNIT_TRIGGERED_BY], i)
                if (p->type == UNIT_AUTOMOUNT) {
                         r = automount_update_mount(AUTOMOUNT(p), old_state, state);
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

        mount_notify_automount(m, old_state, state);

        if (state != old_state)
                log_unit_debug(UNIT(m), "Changed %s -> %s", mount_state_to_string(old_state), mount_state_to_string(state));

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
        ExecParameters exec_params = {
                .apply_permissions = true,
                .apply_chroot      = true,
                .apply_tty_stdin   = true,
                .bus_endpoint_fd   = -1,
        };

        assert(m);
        assert(c);
        assert(_pid);

        (void) unit_realize_cgroup(UNIT(m));
        if (m->reset_cpu_usage) {
                (void) unit_reset_cpu_usage(UNIT(m));
                m->reset_cpu_usage = false;
        }

        r = unit_setup_exec_runtime(UNIT(m));
        if (r < 0)
                goto fail;

        r = mount_arm_timer(m);
        if (r < 0)
                goto fail;

        exec_params.environment = UNIT(m)->manager->environment;
        exec_params.confirm_spawn = UNIT(m)->manager->confirm_spawn;
        exec_params.cgroup_supported = UNIT(m)->manager->cgroup_supported;
        exec_params.cgroup_path = UNIT(m)->cgroup_path;
        exec_params.cgroup_delegate = m->cgroup_context.delegate;
        exec_params.runtime_prefix = manager_get_runtime_prefix(UNIT(m)->manager);

        r = exec_spawn(UNIT(m),
                       c,
                       &m->exec_context,
                       &exec_params,
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
                        (state != MOUNT_MOUNTING_SIGTERM && state != MOUNT_UNMOUNTING_SIGTERM && state != MOUNT_REMOUNTING_SIGTERM) ?
                        KILL_KILL : KILL_TERMINATE,
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
        log_unit_warning_errno(UNIT(m), r, "Failed to kill processes: %m");

        if (state == MOUNT_REMOUNTING_SIGTERM || state == MOUNT_REMOUNTING_SIGKILL)
                mount_enter_mounted(m, MOUNT_FAILURE_RESOURCES);
        else
                mount_enter_dead(m, MOUNT_FAILURE_RESOURCES);
}

static void mount_enter_unmounting(Mount *m) {
        int r;

        assert(m);

        /* Start counting our attempts */
        if (!IN_SET(m->state,
                    MOUNT_UNMOUNTING,
                    MOUNT_UNMOUNTING_SIGTERM,
                    MOUNT_UNMOUNTING_SIGKILL))
                m->n_retry_umount = 0;

        m->control_command_id = MOUNT_EXEC_UNMOUNT;
        m->control_command = m->exec_command + MOUNT_EXEC_UNMOUNT;

        r = exec_command_set(m->control_command, UMOUNT_PATH, m->where, NULL);
        if (r >= 0 && UNIT(m)->manager->running_as == MANAGER_SYSTEM)
                r = exec_command_append(m->control_command, "-n", NULL);
        if (r < 0)
                goto fail;

        mount_unwatch_control_pid(m);

        r = mount_spawn(m, m->control_command, &m->control_pid);
        if (r < 0)
                goto fail;

        mount_set_state(m, MOUNT_UNMOUNTING);

        return;

fail:
        log_unit_warning_errno(UNIT(m), r, "Failed to run 'umount' task: %m");
        mount_enter_mounted(m, MOUNT_FAILURE_RESOURCES);
}

static void mount_enter_mounting(Mount *m) {
        int r;
        MountParameters *p;

        assert(m);

        m->control_command_id = MOUNT_EXEC_MOUNT;
        m->control_command = m->exec_command + MOUNT_EXEC_MOUNT;

        r = unit_fail_if_symlink(UNIT(m), m->where);
        if (r < 0)
                goto fail;

        (void) mkdir_p_label(m->where, m->directory_mode);

        unit_warn_if_dir_nonempty(UNIT(m), m->where);

        /* Create the source directory for bind-mounts if needed */
        p = get_mount_parameters_fragment(m);
        if (p && mount_is_bind(p))
                (void) mkdir_p_label(p->what, m->directory_mode);

        if (m->from_fragment) {
                _cleanup_free_ char *opts = NULL;

                r = fstab_filter_options(m->parameters_fragment.options,
                                         "nofail\0" "noauto\0" "auto\0", NULL, NULL, &opts);
                if (r < 0)
                        goto fail;

                r = exec_command_set(m->control_command, MOUNT_PATH,
                                     m->parameters_fragment.what, m->where, NULL);
                if (r >= 0 && UNIT(m)->manager->running_as == MANAGER_SYSTEM)
                        r = exec_command_append(m->control_command, "-n", NULL);
                if (r >= 0 && m->sloppy_options)
                        r = exec_command_append(m->control_command, "-s", NULL);
                if (r >= 0 && m->parameters_fragment.fstype)
                        r = exec_command_append(m->control_command, "-t", m->parameters_fragment.fstype, NULL);
                if (r >= 0 && !isempty(opts))
                        r = exec_command_append(m->control_command, "-o", opts, NULL);
        } else
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
        log_unit_warning_errno(UNIT(m), r, "Failed to run 'mount' task: %m");
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
                        o = strjoina("remount,", m->parameters_fragment.options);
                else
                        o = "remount";

                r = exec_command_set(m->control_command, MOUNT_PATH,
                                     m->parameters_fragment.what, m->where,
                                     "-o", o, NULL);
                if (r >= 0 && UNIT(m)->manager->running_as == MANAGER_SYSTEM)
                        r = exec_command_append(m->control_command, "-n", NULL);
                if (r >= 0 && m->sloppy_options)
                        r = exec_command_append(m->control_command, "-s", NULL);
                if (r >= 0 && m->parameters_fragment.fstype)
                        r = exec_command_append(m->control_command, "-t", m->parameters_fragment.fstype, NULL);
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
        log_unit_warning_errno(UNIT(m), r, "Failed to run 'remount' task: %m");
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
        m->reset_cpu_usage = true;

        mount_enter_mounting(m);
        return 1;
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
        return 1;
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
                        log_unit_debug(u, "Failed to parse state value: %s", value);
                else
                        m->deserialized_state = state;
        } else if (streq(key, "result")) {
                MountResult f;

                f = mount_result_from_string(value);
                if (f < 0)
                        log_unit_debug(u, "Failed to parse result value: %s", value);
                else if (f != MOUNT_SUCCESS)
                        m->result = f;

        } else if (streq(key, "reload-result")) {
                MountResult f;

                f = mount_result_from_string(value);
                if (f < 0)
                        log_unit_debug(u, "Failed to parse reload result value: %s", value);
                else if (f != MOUNT_SUCCESS)
                        m->reload_result = f;

        } else if (streq(key, "control-pid")) {
                pid_t pid;

                if (parse_pid(value, &pid) < 0)
                        log_unit_debug(u, "Failed to parse control-pid value: %s", value);
                else
                        m->control_pid = pid;
        } else if (streq(key, "control-command")) {
                MountExecCommand id;

                id = mount_exec_command_from_string(value);
                if (id < 0)
                        log_unit_debug(u, "Failed to parse exec-command value: %s", value);
                else {
                        m->control_command_id = id;
                        m->control_command = m->exec_command + id;
                }
        } else
                log_unit_debug(u, "Unknown serialization key: %s", key);

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

        log_unit_full(u, f == MOUNT_SUCCESS ? LOG_DEBUG : LOG_NOTICE, 0,
                      "Mount process exited, code=%s status=%i", sigchld_code_to_string(code), status);

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

                if (f == MOUNT_SUCCESS) {

                        if (m->from_proc_self_mountinfo) {

                                /* Still a mount point? If so, let's
                                 * try again. Most likely there were
                                 * multiple mount points stacked on
                                 * top of each other. Note that due to
                                 * the io event priority logic we can
                                 * be sure the new mountinfo is loaded
                                 * before we process the SIGCHLD for
                                 * the mount command. */

                                if (m->n_retry_umount < RETRY_UMOUNT_MAX) {
                                        log_unit_debug(u, "Mount still present, trying again.");
                                        m->n_retry_umount++;
                                        mount_enter_unmounting(m);
                                } else {
                                        log_unit_debug(u, "Mount still present after %u attempts to unmount, giving up.", m->n_retry_umount);
                                        mount_enter_mounted(m, f);
                                }
                        } else
                                mount_enter_dead(m, f);

                } else if (m->from_proc_self_mountinfo)
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
                log_unit_warning(UNIT(m), "Mounting timed out. Stopping.");
                mount_enter_signal(m, MOUNT_MOUNTING_SIGTERM, MOUNT_FAILURE_TIMEOUT);
                break;

        case MOUNT_REMOUNTING:
                log_unit_warning(UNIT(m), "Remounting timed out. Stopping.");
                m->reload_result = MOUNT_FAILURE_TIMEOUT;
                mount_enter_mounted(m, MOUNT_SUCCESS);
                break;

        case MOUNT_UNMOUNTING:
                log_unit_warning(UNIT(m), "Unmounting timed out. Stopping.");
                mount_enter_signal(m, MOUNT_UNMOUNTING_SIGTERM, MOUNT_FAILURE_TIMEOUT);
                break;

        case MOUNT_MOUNTING_SIGTERM:
                if (m->kill_context.send_sigkill) {
                        log_unit_warning(UNIT(m), "Mounting timed out. Killing.");
                        mount_enter_signal(m, MOUNT_MOUNTING_SIGKILL, MOUNT_FAILURE_TIMEOUT);
                } else {
                        log_unit_warning(UNIT(m), "Mounting timed out. Skipping SIGKILL. Ignoring.");

                        if (m->from_proc_self_mountinfo)
                                mount_enter_mounted(m, MOUNT_FAILURE_TIMEOUT);
                        else
                                mount_enter_dead(m, MOUNT_FAILURE_TIMEOUT);
                }
                break;

        case MOUNT_REMOUNTING_SIGTERM:
                if (m->kill_context.send_sigkill) {
                        log_unit_warning(UNIT(m), "Remounting timed out. Killing.");
                        mount_enter_signal(m, MOUNT_REMOUNTING_SIGKILL, MOUNT_FAILURE_TIMEOUT);
                } else {
                        log_unit_warning(UNIT(m), "Remounting timed out. Skipping SIGKILL. Ignoring.");

                        if (m->from_proc_self_mountinfo)
                                mount_enter_mounted(m, MOUNT_FAILURE_TIMEOUT);
                        else
                                mount_enter_dead(m, MOUNT_FAILURE_TIMEOUT);
                }
                break;

        case MOUNT_UNMOUNTING_SIGTERM:
                if (m->kill_context.send_sigkill) {
                        log_unit_warning(UNIT(m), "Unmounting timed out. Killing.");
                        mount_enter_signal(m, MOUNT_UNMOUNTING_SIGKILL, MOUNT_FAILURE_TIMEOUT);
                } else {
                        log_unit_warning(UNIT(m), "Unmounting timed out. Skipping SIGKILL. Ignoring.");

                        if (m->from_proc_self_mountinfo)
                                mount_enter_mounted(m, MOUNT_FAILURE_TIMEOUT);
                        else
                                mount_enter_dead(m, MOUNT_FAILURE_TIMEOUT);
                }
                break;

        case MOUNT_MOUNTING_SIGKILL:
        case MOUNT_REMOUNTING_SIGKILL:
        case MOUNT_UNMOUNTING_SIGKILL:
                log_unit_warning(UNIT(m),"Mount process still around after SIGKILL. Ignoring.");

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

static int mount_setup_unit(
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

        r = unit_name_from_path(where, ".mount", &e);
        if (r < 0)
                return r;

        u = manager_get_unit(m, e);
        if (!u) {
                delete = true;

                u = unit_new(m, sizeof(Mount));
                if (!u)
                        return log_oom();

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

                if (m->running_as == MANAGER_SYSTEM) {
                        const char* target;

                        target = mount_needs_network(options, fstype) ?  SPECIAL_REMOTE_FS_TARGET : SPECIAL_LOCAL_FS_TARGET;
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

                if (m->running_as == MANAGER_SYSTEM &&
                    mount_needs_network(options, fstype)) {
                        /* _netdev option may have shown up late, or on a
                         * remount. Add remote-fs dependencies, even though
                         * local-fs ones may already be there. */
                        unit_add_dependency_by_name(u, UNIT_BEFORE, SPECIAL_REMOTE_FS_TARGET, NULL, true);
                        load_extras = true;
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
        log_warning_errno(r, "Failed to set up mount unit: %m");

        if (delete && u)
                unit_free(u);

        return r;
}

static int mount_load_proc_self_mountinfo(Manager *m, bool set_flags) {
        _cleanup_(mnt_free_tablep) struct libmnt_table *t = NULL;
        _cleanup_(mnt_free_iterp) struct libmnt_iter *i = NULL;
        int r = 0;

        assert(m);

        t = mnt_new_table();
        if (!t)
                return log_oom();

        i = mnt_new_iter(MNT_ITER_FORWARD);
        if (!i)
                return log_oom();

        r = mnt_table_parse_mtab(t, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to parse /proc/self/mountinfo: %m");

        r = 0;
        for (;;) {
                const char *device, *path, *options, *fstype;
                _cleanup_free_ char *d = NULL, *p = NULL;
                struct libmnt_fs *fs;
                int k;

                k = mnt_table_next_fs(t, i, &fs);
                if (k == 1)
                        break;
                if (k < 0)
                        return log_error_errno(k, "Failed to get next entry from /proc/self/mountinfo: %m");

                device = mnt_fs_get_source(fs);
                path = mnt_fs_get_target(fs);
                options = mnt_fs_get_options(fs);
                fstype = mnt_fs_get_fstype(fs);

                if (cunescape(device, UNESCAPE_RELAX, &d) < 0)
                        return log_oom();

                if (cunescape(path, UNESCAPE_RELAX, &p) < 0)
                        return log_oom();

                (void) device_found_node(m, d, true, DEVICE_FOUND_MOUNT, set_flags);

                k = mount_setup_unit(m, d, p, options, fstype, set_flags);
                if (r == 0 && k < 0)
                        r = k;
        }

        return r;
}

static void mount_shutdown(Manager *m) {
        assert(m);

        m->mount_event_source = sd_event_source_unref(m->mount_event_source);
        m->mount_utab_event_source = sd_event_source_unref(m->mount_utab_event_source);

        if (m->proc_self_mountinfo) {
                fclose(m->proc_self_mountinfo);
                m->proc_self_mountinfo = NULL;
        }
        m->utab_inotify_fd = safe_close(m->utab_inotify_fd);
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

        mnt_init_debug(0);

        if (!m->proc_self_mountinfo) {
                m->proc_self_mountinfo = fopen("/proc/self/mountinfo", "re");
                if (!m->proc_self_mountinfo)
                        return -errno;

                r = sd_event_add_io(m->event, &m->mount_event_source, fileno(m->proc_self_mountinfo), EPOLLPRI, mount_dispatch_io, m);
                if (r < 0)
                        goto fail;

                /* Dispatch this before we dispatch SIGCHLD, so that
                 * we always get the events from /proc/self/mountinfo
                 * before the SIGCHLD of /usr/bin/mount. */
                r = sd_event_source_set_priority(m->mount_event_source, -10);
                if (r < 0)
                        goto fail;

                (void) sd_event_source_set_description(m->mount_event_source, "mount-mountinfo-dispatch");
        }

        if (m->utab_inotify_fd < 0) {
                m->utab_inotify_fd = inotify_init1(IN_NONBLOCK|IN_CLOEXEC);
                if (m->utab_inotify_fd < 0) {
                        r = -errno;
                        goto fail;
                }

                (void) mkdir_p_label("/run/mount", 0755);

                r = inotify_add_watch(m->utab_inotify_fd, "/run/mount", IN_MOVED_TO);
                if (r < 0) {
                        r = -errno;
                        goto fail;
                }

                r = sd_event_add_io(m->event, &m->mount_utab_event_source, m->utab_inotify_fd, EPOLLIN, mount_dispatch_io, m);
                if (r < 0)
                        goto fail;

                r = sd_event_source_set_priority(m->mount_utab_event_source, -10);
                if (r < 0)
                        goto fail;

                (void) sd_event_source_set_description(m->mount_utab_event_source, "mount-utab-dispatch");
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
        _cleanup_set_free_ Set *around = NULL, *gone = NULL;
        Manager *m = userdata;
        const char *what;
        Iterator i;
        Unit *u;
        int r;

        assert(m);
        assert(revents & (EPOLLPRI | EPOLLIN));

        /* The manager calls this for every fd event happening on the
         * /proc/self/mountinfo file, which informs us about mounting
         * table changes, and for /run/mount events which we watch
         * for mount options. */

        if (fd == m->utab_inotify_fd) {
                bool rescan = false;

                /* FIXME: We *really* need to replace this with
                 * libmount's own API for this, we should not hardcode
                 * internal behaviour of libmount here. */

                for (;;) {
                        union inotify_event_buffer buffer;
                        struct inotify_event *e;
                        ssize_t l;

                        l = read(fd, &buffer, sizeof(buffer));
                        if (l < 0) {
                                if (errno == EAGAIN || errno == EINTR)
                                        break;

                                log_error_errno(errno, "Failed to read utab inotify: %m");
                                break;
                        }

                        FOREACH_INOTIFY_EVENT(e, buffer, l) {
                                /* Only care about changes to utab,
                                 * but we have to monitor the
                                 * directory to reliably get
                                 * notifications about when utab is
                                 * replaced using rename(2) */
                                if ((e->mask & IN_Q_OVERFLOW) || streq(e->name, "utab"))
                                        rescan = true;
                        }
                }

                if (!rescan)
                        return 0;
        }

        r = mount_load_proc_self_mountinfo(m, true);
        if (r < 0) {
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

                        /* A mount point is not around right now. It
                         * might be gone, or might never have
                         * existed. */

                        if (mount->from_proc_self_mountinfo &&
                            mount->parameters_proc_self_mountinfo.what) {

                                /* Remember that this device might just have disappeared */
                                if (set_ensure_allocated(&gone, &string_hash_ops) < 0 ||
                                    set_put(gone, mount->parameters_proc_self_mountinfo.what) < 0)
                                        log_oom(); /* we don't care too much about OOM here... */
                        }

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

                        /* A mount point was added or changed */

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

                if (mount->is_mounted &&
                    mount->from_proc_self_mountinfo &&
                    mount->parameters_proc_self_mountinfo.what) {

                        if (set_ensure_allocated(&around, &string_hash_ops) < 0 ||
                            set_put(around, mount->parameters_proc_self_mountinfo.what) < 0)
                                log_oom();
                }

                /* Reset the flags for later calls */
                mount->is_mounted = mount->just_mounted = mount->just_changed = false;
        }

        SET_FOREACH(what, gone, i) {
                if (set_contains(around, what))
                        continue;

                /* Let the device units know that the device is no longer mounted */
                (void) device_found_node(m, what, false, DEVICE_FOUND_MOUNT, true);
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
