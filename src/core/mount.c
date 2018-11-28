/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/epoll.h>

#include <libmount.h>

#include "sd-messages.h"

#include "alloc-util.h"
#include "dbus-mount.h"
#include "dbus-unit.h"
#include "device.h"
#include "escape.h"
#include "exit-status.h"
#include "format-util.h"
#include "fstab-util.h"
#include "log.h"
#include "manager.h"
#include "mkdir.h"
#include "mount-setup.h"
#include "mount.h"
#include "mountpoint-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "serialize.h"
#include "special.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "unit-name.h"
#include "unit.h"

#define RETRY_UMOUNT_MAX 32

DEFINE_TRIVIAL_CLEANUP_FUNC(struct libmnt_table*, mnt_free_table);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct libmnt_iter*, mnt_free_iter);

static const UnitActiveState state_translation_table[_MOUNT_STATE_MAX] = {
        [MOUNT_DEAD] = UNIT_INACTIVE,
        [MOUNT_MOUNTING] = UNIT_ACTIVATING,
        [MOUNT_MOUNTING_DONE] = UNIT_ACTIVATING,
        [MOUNT_MOUNTED] = UNIT_ACTIVE,
        [MOUNT_REMOUNTING] = UNIT_RELOADING,
        [MOUNT_UNMOUNTING] = UNIT_DEACTIVATING,
        [MOUNT_REMOUNTING_SIGTERM] = UNIT_RELOADING,
        [MOUNT_REMOUNTING_SIGKILL] = UNIT_RELOADING,
        [MOUNT_UNMOUNTING_SIGTERM] = UNIT_DEACTIVATING,
        [MOUNT_UNMOUNTING_SIGKILL] = UNIT_DEACTIVATING,
        [MOUNT_FAILED] = UNIT_FAILED
};

static int mount_dispatch_timer(sd_event_source *source, usec_t usec, void *userdata);
static int mount_dispatch_io(sd_event_source *source, int fd, uint32_t revents, void *userdata);

static bool MOUNT_STATE_WITH_PROCESS(MountState state) {
        return IN_SET(state,
                      MOUNT_MOUNTING,
                      MOUNT_MOUNTING_DONE,
                      MOUNT_REMOUNTING,
                      MOUNT_REMOUNTING_SIGTERM,
                      MOUNT_REMOUNTING_SIGKILL,
                      MOUNT_UNMOUNTING,
                      MOUNT_UNMOUNTING_SIGTERM,
                      MOUNT_UNMOUNTING_SIGKILL);
}

static bool mount_is_network(const MountParameters *p) {
        assert(p);

        if (fstab_test_option(p->options, "_netdev\0"))
                return true;

        if (p->fstype && fstype_is_network(p->fstype))
                return true;

        return false;
}

static bool mount_is_loop(const MountParameters *p) {
        assert(p);

        if (fstab_test_option(p->options, "loop\0"))
                return true;

        return false;
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

static bool mount_is_automount(const MountParameters *p) {
        assert(p);

        return fstab_test_option(p->options,
                                 "comment=systemd.automount\0"
                                 "x-systemd.automount\0");
}

static bool mount_is_bound_to_device(const Mount *m) {
        const MountParameters *p;

        if (m->from_fragment)
                return true;

        p = &m->parameters_proc_self_mountinfo;
        return fstab_test_option(p->options, "x-systemd.device-bound\0");
}

static bool mount_needs_quota(const MountParameters *p) {
        assert(p);

        /* Quotas are not enabled on network filesystems, but we want them, for example, on storage connected via
         * iscsi. We hence don't use mount_is_network() here, as that would also return true for _netdev devices. */
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

        m->exec_context.std_output = u->manager->default_std_output;
        m->exec_context.std_error = u->manager->default_std_error;

        m->directory_mode = 0755;

        /* We need to make sure that /usr/bin/mount is always called
         * in the same process group as us, so that the autofs kernel
         * side doesn't send us another mount request while we are
         * already trying to comply its last one. */
        m->exec_context.same_pgrp = true;

        m->control_command_id = _MOUNT_EXEC_COMMAND_INVALID;

        u->ignore_on_isolate = true;
}

static int mount_arm_timer(Mount *m, usec_t usec) {
        int r;

        assert(m);

        if (m->timer_event_source) {
                r = sd_event_source_set_time(m->timer_event_source, usec);
                if (r < 0)
                        return r;

                return sd_event_source_set_enabled(m->timer_event_source, SD_EVENT_ONESHOT);
        }

        if (usec == USEC_INFINITY)
                return 0;

        r = sd_event_add_time(
                        UNIT(m)->manager->event,
                        &m->timer_event_source,
                        CLOCK_MONOTONIC,
                        usec, 0,
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

        p->what = mfree(p->what);
        p->options = mfree(p->options);
        p->fstype = mfree(p->fstype);
}

static void mount_done(Unit *u) {
        Mount *m = MOUNT(u);

        assert(m);

        m->where = mfree(m->where);

        mount_parameters_done(&m->parameters_proc_self_mountinfo);
        mount_parameters_done(&m->parameters_fragment);

        m->exec_runtime = exec_runtime_unref(m->exec_runtime, false);
        exec_command_done_array(m->exec_command, _MOUNT_EXEC_COMMAND_MAX);
        m->control_command = NULL;

        dynamic_creds_unref(&m->dynamic_creds);

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

static int mount_add_mount_dependencies(Mount *m) {
        MountParameters *pm;
        Unit *other;
        Iterator i;
        Set *s;
        int r;

        assert(m);

        if (!path_equal(m->where, "/")) {
                _cleanup_free_ char *parent = NULL;

                /* Adds in links to other mount points that might lie further up in the hierarchy */

                parent = dirname_malloc(m->where);
                if (!parent)
                        return -ENOMEM;

                r = unit_require_mounts_for(UNIT(m), parent, UNIT_DEPENDENCY_IMPLICIT);
                if (r < 0)
                        return r;
        }

        /* Adds in dependencies to other mount points that might be needed for the source path (if this is a bind mount
         * or a loop mount) to be available. */
        pm = get_mount_parameters_fragment(m);
        if (pm && pm->what &&
            path_is_absolute(pm->what) &&
            (mount_is_bind(pm) || mount_is_loop(pm) || !mount_is_network(pm))) {

                r = unit_require_mounts_for(UNIT(m), pm->what, UNIT_DEPENDENCY_FILE);
                if (r < 0)
                        return r;
        }

        /* Adds in dependencies to other units that use this path or paths further down in the hierarchy */
        s = manager_get_units_requiring_mounts_for(UNIT(m)->manager, m->where);
        SET_FOREACH(other, s, i) {

                if (other->load_state != UNIT_LOADED)
                        continue;

                if (other == UNIT(m))
                        continue;

                r = unit_add_dependency(other, UNIT_AFTER, UNIT(m), true, UNIT_DEPENDENCY_PATH);
                if (r < 0)
                        return r;

                if (UNIT(m)->fragment_path) {
                        /* If we have fragment configuration, then make this dependency required */
                        r = unit_add_dependency(other, UNIT_REQUIRES, UNIT(m), true, UNIT_DEPENDENCY_PATH);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int mount_add_device_dependencies(Mount *m) {
        bool device_wants_mount;
        UnitDependencyMask mask;
        MountParameters *p;
        UnitDependency dep;
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

        device_wants_mount =
                mount_is_auto(p) && !mount_is_automount(p) && MANAGER_IS_SYSTEM(UNIT(m)->manager);

        /* Mount units from /proc/self/mountinfo are not bound to devices
         * by default since they're subject to races when devices are
         * unplugged. But the user can still force this dep with an
         * appropriate option (or udev property) so the mount units are
         * automatically stopped when the device disappears suddenly. */
        dep = mount_is_bound_to_device(m) ? UNIT_BINDS_TO : UNIT_REQUIRES;

        mask = m->from_fragment ? UNIT_DEPENDENCY_FILE : UNIT_DEPENDENCY_MOUNTINFO_IMPLICIT;

        r = unit_add_node_dependency(UNIT(m), p->what, device_wants_mount, dep, mask);
        if (r < 0)
                return r;

        return 0;
}

static int mount_add_quota_dependencies(Mount *m) {
        UnitDependencyMask mask;
        MountParameters *p;
        int r;

        assert(m);

        if (!MANAGER_IS_SYSTEM(UNIT(m)->manager))
                return 0;

        p = get_mount_parameters_fragment(m);
        if (!p)
                return 0;

        if (!mount_needs_quota(p))
                return 0;

        mask = m->from_fragment ? UNIT_DEPENDENCY_FILE : UNIT_DEPENDENCY_MOUNTINFO_IMPLICIT;

        r = unit_add_two_dependencies_by_name(UNIT(m), UNIT_BEFORE, UNIT_WANTS, SPECIAL_QUOTACHECK_SERVICE, true, mask);
        if (r < 0)
                return r;

        r = unit_add_two_dependencies_by_name(UNIT(m), UNIT_BEFORE, UNIT_WANTS, SPECIAL_QUOTAON_SERVICE, true, mask);
        if (r < 0)
                return r;

        return 0;
}

static bool mount_is_extrinsic(Mount *m) {
        MountParameters *p;
        assert(m);

        /* Returns true for all units that are "magic" and should be excluded from the usual start-up and shutdown
         * dependencies. We call them "extrinsic" here, as they are generally mounted outside of the systemd dependency
         * logic. We shouldn't attempt to manage them ourselves but it's fine if the user operates on them with us. */

        if (!MANAGER_IS_SYSTEM(UNIT(m)->manager)) /* We only automatically manage mounts if we are in system mode */
                return true;

        if (PATH_IN_SET(m->where,  /* Don't bother with the OS data itself */
                        "/",
                        "/usr"))
                return true;

        if (PATH_STARTSWITH_SET(m->where,
                                "/run/initramfs",    /* This should stay around from before we boot until after we shutdown */
                                "/proc",             /* All of this is API VFS */
                                "/sys",              /* … dito … */
                                "/dev"))             /* … dito … */
                return true;

        /* If this is an initrd mount, and we are not in the initrd, then leave this around forever, too. */
        p = get_mount_parameters(m);
        if (p && fstab_test_option(p->options, "x-initrd.mount\0") && !in_initrd())
                return true;

        return false;
}

static int mount_add_default_dependencies(Mount *m) {
        const char *after, *before;
        UnitDependencyMask mask;
        MountParameters *p;
        int r;

        assert(m);

        if (!UNIT(m)->default_dependencies)
                return 0;

        /* We do not add any default dependencies to /, /usr or /run/initramfs/, since they are guaranteed to stay
         * mounted the whole time, since our system is on it.  Also, don't bother with anything mounted below virtual
         * file systems, it's also going to be virtual, and hence not worth the effort. */
        if (mount_is_extrinsic(m))
                return 0;

        p = get_mount_parameters(m);
        if (!p)
                return 0;

        mask = m->from_fragment ? UNIT_DEPENDENCY_FILE : UNIT_DEPENDENCY_MOUNTINFO_DEFAULT;

        if (mount_is_network(p)) {
                /* We order ourselves after network.target. This is
                 * primarily useful at shutdown: services that take
                 * down the network should order themselves before
                 * network.target, so that they are shut down only
                 * after this mount unit is stopped. */

                r = unit_add_dependency_by_name(UNIT(m), UNIT_AFTER, SPECIAL_NETWORK_TARGET, true, mask);
                if (r < 0)
                        return r;

                /* We pull in network-online.target, and order
                 * ourselves after it. This is useful at start-up to
                 * actively pull in tools that want to be started
                 * before we start mounting network file systems, and
                 * whose purpose it is to delay this until the network
                 * is "up". */

                r = unit_add_two_dependencies_by_name(UNIT(m), UNIT_WANTS, UNIT_AFTER, SPECIAL_NETWORK_ONLINE_TARGET, true, mask);
                if (r < 0)
                        return r;

                after = SPECIAL_REMOTE_FS_PRE_TARGET;
                before = SPECIAL_REMOTE_FS_TARGET;
        } else {
                after = SPECIAL_LOCAL_FS_PRE_TARGET;
                before = SPECIAL_LOCAL_FS_TARGET;
        }

        r = unit_add_dependency_by_name(UNIT(m), UNIT_BEFORE, before, true, mask);
        if (r < 0)
                return r;

        r = unit_add_dependency_by_name(UNIT(m), UNIT_AFTER, after, true, mask);
        if (r < 0)
                return r;

        r = unit_add_two_dependencies_by_name(UNIT(m), UNIT_BEFORE, UNIT_CONFLICTS, SPECIAL_UMOUNT_TARGET, true, mask);
        if (r < 0)
                return r;

        /* If this is a tmpfs mount then we have to unmount it before we try to deactivate swaps */
        if (streq_ptr(p->fstype, "tmpfs")) {
                r = unit_add_dependency_by_name(UNIT(m), UNIT_AFTER, SPECIAL_SWAP_TARGET, true, mask);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int mount_verify(Mount *m) {
        _cleanup_free_ char *e = NULL;
        MountParameters *p;
        int r;

        assert(m);

        if (UNIT(m)->load_state != UNIT_LOADED)
                return 0;

        if (!m->from_fragment && !m->from_proc_self_mountinfo && !UNIT(m)->perpetual)
                return -ENOENT;

        r = unit_name_from_path(m->where, ".mount", &e);
        if (r < 0)
                return log_unit_error_errno(UNIT(m), r, "Failed to generate unit name from mount path: %m");

        if (!unit_has_name(UNIT(m), e)) {
                log_unit_error(UNIT(m), "Where= setting doesn't match unit name. Refusing.");
                return -ENOEXEC;
        }

        if (mount_point_is_api(m->where) || mount_point_ignore(m->where)) {
                log_unit_error(UNIT(m), "Cannot create mount unit for API file system %s. Refusing.", m->where);
                return -ENOEXEC;
        }

        p = get_mount_parameters_fragment(m);
        if (p && !p->what) {
                log_unit_error(UNIT(m), "What= setting is missing. Refusing.");
                return -ENOEXEC;
        }

        if (m->exec_context.pam_name && m->kill_context.kill_mode != KILL_CONTROL_GROUP) {
                log_unit_error(UNIT(m), "Unit has PAM enabled. Kill mode must be set to control-group'. Refusing.");
                return -ENOEXEC;
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

        path_simplify(m->where, false);

        if (!u->description) {
                r = unit_set_description(u, m->where);
                if (r < 0)
                        return r;
        }

        r = mount_add_device_dependencies(m);
        if (r < 0)
                return r;

        r = mount_add_mount_dependencies(m);
        if (r < 0)
                return r;

        r = mount_add_quota_dependencies(m);
        if (r < 0)
                return r;

        r = unit_patch_contexts(u);
        if (r < 0)
                return r;

        r = unit_add_exec_dependencies(u, &m->exec_context);
        if (r < 0)
                return r;

        r = unit_set_default_slice(u);
        if (r < 0)
                return r;

        r = mount_add_default_dependencies(m);
        if (r < 0)
                return r;

        return 0;
}

static int mount_load_root_mount(Unit *u) {
        assert(u);

        if (!unit_has_name(u, SPECIAL_ROOT_MOUNT))
                return 0;

        u->perpetual = true;
        u->default_dependencies = false;

        /* The stdio/kmsg bridge socket is on /, in order to avoid a dep loop, don't use kmsg logging for -.mount */
        MOUNT(u)->exec_context.std_output = EXEC_OUTPUT_NULL;
        MOUNT(u)->exec_context.std_input = EXEC_INPUT_NULL;

        if (!u->description)
                u->description = strdup("Root Mount");

        return 1;
}

static int mount_load(Unit *u) {
        Mount *m = MOUNT(u);
        int r;

        assert(u);
        assert(u->load_state == UNIT_STUB);

        r = mount_load_root_mount(u);
        if (r < 0)
                return r;

        if (m->from_proc_self_mountinfo || u->perpetual)
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

static void mount_set_state(Mount *m, MountState state) {
        MountState old_state;
        assert(m);

        if (m->state != state)
                bus_unit_send_pending_change_signal(UNIT(m), false);

        old_state = m->state;
        m->state = state;

        if (!MOUNT_STATE_WITH_PROCESS(state)) {
                m->timer_event_source = sd_event_source_unref(m->timer_event_source);
                mount_unwatch_control_pid(m);
                m->control_command = NULL;
                m->control_command_id = _MOUNT_EXEC_COMMAND_INVALID;
        }

        if (state != old_state)
                log_unit_debug(UNIT(m), "Changed %s -> %s", mount_state_to_string(old_state), mount_state_to_string(state));

        unit_notify(UNIT(m), state_translation_table[old_state], state_translation_table[state],
                    m->reload_result == MOUNT_SUCCESS ? 0 : UNIT_NOTIFY_RELOAD_FAILURE);
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

        if (m->control_pid > 0 &&
            pid_is_unwaited(m->control_pid) &&
            MOUNT_STATE_WITH_PROCESS(new_state)) {

                r = unit_watch_pid(UNIT(m), m->control_pid);
                if (r < 0)
                        return r;

                r = mount_arm_timer(m, usec_add(u->state_change_timestamp.monotonic, m->timeout_usec));
                if (r < 0)
                        return r;
        }

        if (!IN_SET(new_state, MOUNT_DEAD, MOUNT_FAILED)) {
                (void) unit_setup_dynamic_creds(u);
                (void) unit_setup_exec_runtime(u);
        }

        mount_set_state(m, new_state);
        return 0;
}

static void mount_dump(Unit *u, FILE *f, const char *prefix) {
        char buf[FORMAT_TIMESPAN_MAX];
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
                "%sExtrinsic: %s\n"
                "%sDirectoryMode: %04o\n"
                "%sSloppyOptions: %s\n"
                "%sLazyUnmount: %s\n"
                "%sForceUnmount: %s\n"
                "%sTimoutSec: %s\n",
                prefix, mount_state_to_string(m->state),
                prefix, mount_result_to_string(m->result),
                prefix, m->where,
                prefix, p ? strna(p->what) : "n/a",
                prefix, p ? strna(p->fstype) : "n/a",
                prefix, p ? strna(p->options) : "n/a",
                prefix, yes_no(m->from_proc_self_mountinfo),
                prefix, yes_no(m->from_fragment),
                prefix, yes_no(mount_is_extrinsic(m)),
                prefix, m->directory_mode,
                prefix, yes_no(m->sloppy_options),
                prefix, yes_no(m->lazy_unmount),
                prefix, yes_no(m->force_unmount),
                prefix, format_timespan(buf, sizeof(buf), m->timeout_usec, USEC_PER_SEC));

        if (m->control_pid > 0)
                fprintf(f,
                        "%sControl PID: "PID_FMT"\n",
                        prefix, m->control_pid);

        exec_context_dump(&m->exec_context, f, prefix);
        kill_context_dump(&m->kill_context, f, prefix);
        cgroup_context_dump(&m->cgroup_context, f, prefix);
}

static int mount_spawn(Mount *m, ExecCommand *c, pid_t *_pid) {

        _cleanup_(exec_params_clear) ExecParameters exec_params = {
                .flags     = EXEC_APPLY_SANDBOXING|EXEC_APPLY_CHROOT|EXEC_APPLY_TTY_STDIN,
                .stdin_fd  = -1,
                .stdout_fd = -1,
                .stderr_fd = -1,
                .exec_fd   = -1,
        };
        pid_t pid;
        int r;

        assert(m);
        assert(c);
        assert(_pid);

        r = unit_prepare_exec(UNIT(m));
        if (r < 0)
                return r;

        r = mount_arm_timer(m, usec_add(now(CLOCK_MONOTONIC), m->timeout_usec));
        if (r < 0)
                return r;

        r = unit_set_exec_params(UNIT(m), &exec_params);
        if (r < 0)
                return r;

        r = exec_spawn(UNIT(m),
                       c,
                       &m->exec_context,
                       &exec_params,
                       m->exec_runtime,
                       &m->dynamic_creds,
                       &pid);
        if (r < 0)
                return r;

        r = unit_watch_pid(UNIT(m), pid);
        if (r < 0)
                /* FIXME: we need to do something here */
                return r;

        *_pid = pid;

        return 0;
}

static void mount_enter_dead(Mount *m, MountResult f) {
        assert(m);

        if (m->result == MOUNT_SUCCESS)
                m->result = f;

        unit_log_result(UNIT(m), m->result == MOUNT_SUCCESS, mount_result_to_string(m->result));
        mount_set_state(m, m->result != MOUNT_SUCCESS ? MOUNT_FAILED : MOUNT_DEAD);

        m->exec_runtime = exec_runtime_unref(m->exec_runtime, true);

        exec_context_destroy_runtime_directory(&m->exec_context, UNIT(m)->manager->prefix[EXEC_DIRECTORY_RUNTIME]);

        unit_unref_uid_gid(UNIT(m), true);

        dynamic_creds_destroy(&m->dynamic_creds);
}

static void mount_enter_mounted(Mount *m, MountResult f) {
        assert(m);

        if (m->result == MOUNT_SUCCESS)
                m->result = f;

        mount_set_state(m, MOUNT_MOUNTED);
}

static void mount_enter_dead_or_mounted(Mount *m, MountResult f) {
        assert(m);

        /* Enter DEAD or MOUNTED state, depending on what the kernel currently says about the mount point. We use this
         * whenever we executed an operation, so that our internal state reflects what the kernel says again, after all
         * ultimately we just mirror the kernel's internal state on this. */

        if (m->from_proc_self_mountinfo)
                mount_enter_mounted(m, f);
        else
                mount_enter_dead(m, f);
}

static int state_to_kill_operation(MountState state) {
        switch (state) {

        case MOUNT_REMOUNTING_SIGTERM:
        case MOUNT_UNMOUNTING_SIGTERM:
                return KILL_TERMINATE;

        case MOUNT_REMOUNTING_SIGKILL:
        case MOUNT_UNMOUNTING_SIGKILL:
                return KILL_KILL;

        default:
                return _KILL_OPERATION_INVALID;
        }
}

static void mount_enter_signal(Mount *m, MountState state, MountResult f) {
        int r;

        assert(m);

        if (m->result == MOUNT_SUCCESS)
                m->result = f;

        r = unit_kill_context(
                        UNIT(m),
                        &m->kill_context,
                        state_to_kill_operation(state),
                        -1,
                        m->control_pid,
                        false);
        if (r < 0)
                goto fail;

        if (r > 0) {
                r = mount_arm_timer(m, usec_add(now(CLOCK_MONOTONIC), m->timeout_usec));
                if (r < 0)
                        goto fail;

                mount_set_state(m, state);
        } else if (state == MOUNT_REMOUNTING_SIGTERM && m->kill_context.send_sigkill)
                mount_enter_signal(m, MOUNT_REMOUNTING_SIGKILL, MOUNT_SUCCESS);
        else if (IN_SET(state, MOUNT_REMOUNTING_SIGTERM, MOUNT_REMOUNTING_SIGKILL))
                mount_enter_mounted(m, MOUNT_SUCCESS);
        else if (state == MOUNT_UNMOUNTING_SIGTERM && m->kill_context.send_sigkill)
                mount_enter_signal(m, MOUNT_UNMOUNTING_SIGKILL, MOUNT_SUCCESS);
        else
                mount_enter_dead_or_mounted(m, MOUNT_SUCCESS);

        return;

fail:
        log_unit_warning_errno(UNIT(m), r, "Failed to kill processes: %m");
        mount_enter_dead_or_mounted(m, MOUNT_FAILURE_RESOURCES);
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

        r = exec_command_set(m->control_command, UMOUNT_PATH, m->where, "-c", NULL);
        if (r >= 0 && m->lazy_unmount)
                r = exec_command_append(m->control_command, "-l", NULL);
        if (r >= 0 && m->force_unmount)
                r = exec_command_append(m->control_command, "-f", NULL);
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
        mount_enter_dead_or_mounted(m, MOUNT_FAILURE_RESOURCES);
}

static void mount_enter_mounting(Mount *m) {
        int r;
        MountParameters *p;

        assert(m);

        r = unit_fail_if_noncanonical(UNIT(m), m->where);
        if (r < 0)
                goto fail;

        (void) mkdir_p_label(m->where, m->directory_mode);

        unit_warn_if_dir_nonempty(UNIT(m), m->where);

        unit_warn_leftover_processes(UNIT(m));

        m->control_command_id = MOUNT_EXEC_MOUNT;
        m->control_command = m->exec_command + MOUNT_EXEC_MOUNT;

        /* Create the source directory for bind-mounts if needed */
        p = get_mount_parameters_fragment(m);
        if (p && mount_is_bind(p))
                (void) mkdir_p_label(p->what, m->directory_mode);

        if (p) {
                _cleanup_free_ char *opts = NULL;

                r = fstab_filter_options(p->options, "nofail\0" "noauto\0" "auto\0", NULL, NULL, &opts);
                if (r < 0)
                        goto fail;

                r = exec_command_set(m->control_command, MOUNT_PATH, p->what, m->where, NULL);
                if (r >= 0 && m->sloppy_options)
                        r = exec_command_append(m->control_command, "-s", NULL);
                if (r >= 0 && p->fstype)
                        r = exec_command_append(m->control_command, "-t", p->fstype, NULL);
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
        mount_enter_dead_or_mounted(m, MOUNT_FAILURE_RESOURCES);
}

static void mount_set_reload_result(Mount *m, MountResult result) {
        assert(m);

        /* Only store the first error we encounter */
        if (m->reload_result != MOUNT_SUCCESS)
                return;

        m->reload_result = result;
}

static void mount_enter_remounting(Mount *m) {
        int r;
        MountParameters *p;

        assert(m);

        /* Reset reload result when we are about to start a new remount operation */
        m->reload_result = MOUNT_SUCCESS;

        m->control_command_id = MOUNT_EXEC_REMOUNT;
        m->control_command = m->exec_command + MOUNT_EXEC_REMOUNT;

        p = get_mount_parameters_fragment(m);
        if (p) {
                const char *o;

                if (p->options)
                        o = strjoina("remount,", p->options);
                else
                        o = "remount";

                r = exec_command_set(m->control_command, MOUNT_PATH,
                                     p->what, m->where,
                                     "-o", o, NULL);
                if (r >= 0 && m->sloppy_options)
                        r = exec_command_append(m->control_command, "-s", NULL);
                if (r >= 0 && p->fstype)
                        r = exec_command_append(m->control_command, "-t", p->fstype, NULL);
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
        mount_set_reload_result(m, MOUNT_FAILURE_RESOURCES);
        mount_enter_dead_or_mounted(m, MOUNT_SUCCESS);
}

static int mount_start(Unit *u) {
        Mount *m = MOUNT(u);
        int r;

        assert(m);

        /* We cannot fulfill this request right now, try again later
         * please! */
        if (IN_SET(m->state,
                   MOUNT_UNMOUNTING,
                   MOUNT_UNMOUNTING_SIGTERM,
                   MOUNT_UNMOUNTING_SIGKILL))
                return -EAGAIN;

        /* Already on it! */
        if (m->state == MOUNT_MOUNTING)
                return 0;

        assert(IN_SET(m->state, MOUNT_DEAD, MOUNT_FAILED));

        r = unit_start_limit_test(u);
        if (r < 0) {
                mount_enter_dead(m, MOUNT_FAILURE_START_LIMIT_HIT);
                return r;
        }

        r = unit_acquire_invocation_id(u);
        if (r < 0)
                return r;

        m->result = MOUNT_SUCCESS;
        m->reload_result = MOUNT_SUCCESS;
        exec_command_reset_status_array(m->exec_command, _MOUNT_EXEC_COMMAND_MAX);

        u->reset_accounting = true;

        mount_enter_mounting(m);
        return 1;
}

static int mount_stop(Unit *u) {
        Mount *m = MOUNT(u);

        assert(m);

        switch (m->state) {

        case MOUNT_UNMOUNTING:
        case MOUNT_UNMOUNTING_SIGKILL:
        case MOUNT_UNMOUNTING_SIGTERM:
                /* Already on it */
                return 0;

        case MOUNT_MOUNTING:
        case MOUNT_MOUNTING_DONE:
        case MOUNT_REMOUNTING:
                /* If we are still waiting for /bin/mount, we go directly into kill mode. */
                mount_enter_signal(m, MOUNT_UNMOUNTING_SIGTERM, MOUNT_SUCCESS);
                return 0;

        case MOUNT_REMOUNTING_SIGTERM:
                /* If we are already waiting for a hung remount, convert this to the matching unmounting state */
                mount_set_state(m, MOUNT_UNMOUNTING_SIGTERM);
                return 0;

        case MOUNT_REMOUNTING_SIGKILL:
                /* as above */
                mount_set_state(m, MOUNT_UNMOUNTING_SIGKILL);
                return 0;

        case MOUNT_MOUNTED:
                mount_enter_unmounting(m);
                return 1;

        default:
                assert_not_reached("Unexpected state.");
        }
}

static int mount_reload(Unit *u) {
        Mount *m = MOUNT(u);

        assert(m);
        assert(m->state == MOUNT_MOUNTED);

        mount_enter_remounting(m);

        return 1;
}

static int mount_serialize(Unit *u, FILE *f, FDSet *fds) {
        Mount *m = MOUNT(u);

        assert(m);
        assert(f);
        assert(fds);

        (void) serialize_item(f, "state", mount_state_to_string(m->state));
        (void) serialize_item(f, "result", mount_result_to_string(m->result));
        (void) serialize_item(f, "reload-result", mount_result_to_string(m->reload_result));

        if (m->control_pid > 0)
                (void) serialize_item_format(f, "control-pid", PID_FMT, m->control_pid);

        if (m->control_command_id >= 0)
                (void) serialize_item(f, "control-command", mount_exec_command_to_string(m->control_command_id));

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

_pure_ static bool mount_may_gc(Unit *u) {
        Mount *m = MOUNT(u);

        assert(m);

        if (m->from_proc_self_mountinfo)
                return false;

        return true;
}

static void mount_sigchld_event(Unit *u, pid_t pid, int code, int status) {
        Mount *m = MOUNT(u);
        MountResult f;

        assert(m);
        assert(pid >= 0);

        if (pid != m->control_pid)
                return;

        m->control_pid = 0;

        if (is_clean_exit(code, status, EXIT_CLEAN_COMMAND, NULL))
                f = MOUNT_SUCCESS;
        else if (code == CLD_EXITED)
                f = MOUNT_FAILURE_EXIT_CODE;
        else if (code == CLD_KILLED)
                f = MOUNT_FAILURE_SIGNAL;
        else if (code == CLD_DUMPED)
                f = MOUNT_FAILURE_CORE_DUMP;
        else
                assert_not_reached("Unknown code");

        if (IN_SET(m->state, MOUNT_REMOUNTING, MOUNT_REMOUNTING_SIGKILL, MOUNT_REMOUNTING_SIGTERM))
                mount_set_reload_result(m, f);
        else if (m->result == MOUNT_SUCCESS)
                m->result = f;

        if (m->control_command) {
                exec_status_exit(&m->control_command->exec_status, &m->exec_context, pid, code, status);

                m->control_command = NULL;
                m->control_command_id = _MOUNT_EXEC_COMMAND_INVALID;
        }

        unit_log_process_exit(
                        u, f == MOUNT_SUCCESS ? LOG_DEBUG : LOG_NOTICE,
                        "Mount process",
                        mount_exec_command_to_string(m->control_command_id),
                        code, status);

        /* Note that due to the io event priority logic, we can be sure the new mountinfo is loaded
         * before we process the SIGCHLD for the mount command. */

        switch (m->state) {

        case MOUNT_MOUNTING:
                /* Our mount point has not appeared in mountinfo.  Something went wrong. */

                if (f == MOUNT_SUCCESS) {
                        /* Either /bin/mount has an unexpected definition of success,
                         * or someone raced us and we lost. */
                        log_unit_warning(UNIT(m), "Mount process finished, but there is no mount.");
                        f = MOUNT_FAILURE_PROTOCOL;
                }
                mount_enter_dead(m, f);
                break;

        case MOUNT_MOUNTING_DONE:
                mount_enter_mounted(m, f);
                break;

        case MOUNT_REMOUNTING:
        case MOUNT_REMOUNTING_SIGTERM:
        case MOUNT_REMOUNTING_SIGKILL:
                mount_enter_dead_or_mounted(m, MOUNT_SUCCESS);
                break;

        case MOUNT_UNMOUNTING:

                if (f == MOUNT_SUCCESS && m->from_proc_self_mountinfo) {

                        /* Still a mount point? If so, let's try again. Most likely there were multiple mount points
                         * stacked on top of each other. We might exceed the timeout specified by the user overall,
                         * but we will stop as soon as any one umount times out. */

                        if (m->n_retry_umount < RETRY_UMOUNT_MAX) {
                                log_unit_debug(u, "Mount still present, trying again.");
                                m->n_retry_umount++;
                                mount_enter_unmounting(m);
                        } else {
                                log_unit_warning(u, "Mount still present after %u attempts to unmount, giving up.", m->n_retry_umount);
                                mount_enter_mounted(m, f);
                        }
                } else
                        mount_enter_dead_or_mounted(m, f);

                break;

        case MOUNT_UNMOUNTING_SIGKILL:
        case MOUNT_UNMOUNTING_SIGTERM:
                mount_enter_dead_or_mounted(m, f);
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
                log_unit_warning(UNIT(m), "Mounting timed out. Terminating.");
                mount_enter_signal(m, MOUNT_UNMOUNTING_SIGTERM, MOUNT_FAILURE_TIMEOUT);
                break;

        case MOUNT_REMOUNTING:
                log_unit_warning(UNIT(m), "Remounting timed out. Terminating remount process.");
                mount_set_reload_result(m, MOUNT_FAILURE_TIMEOUT);
                mount_enter_signal(m, MOUNT_REMOUNTING_SIGTERM, MOUNT_SUCCESS);
                break;

        case MOUNT_REMOUNTING_SIGTERM:
                mount_set_reload_result(m, MOUNT_FAILURE_TIMEOUT);

                if (m->kill_context.send_sigkill) {
                        log_unit_warning(UNIT(m), "Remounting timed out. Killing.");
                        mount_enter_signal(m, MOUNT_REMOUNTING_SIGKILL, MOUNT_SUCCESS);
                } else {
                        log_unit_warning(UNIT(m), "Remounting timed out. Skipping SIGKILL. Ignoring.");
                        mount_enter_dead_or_mounted(m, MOUNT_SUCCESS);
                }
                break;

        case MOUNT_REMOUNTING_SIGKILL:
                mount_set_reload_result(m, MOUNT_FAILURE_TIMEOUT);

                log_unit_warning(UNIT(m), "Mount process still around after SIGKILL. Ignoring.");
                mount_enter_dead_or_mounted(m, MOUNT_SUCCESS);
                break;

        case MOUNT_UNMOUNTING:
                log_unit_warning(UNIT(m), "Unmounting timed out. Terminating.");
                mount_enter_signal(m, MOUNT_UNMOUNTING_SIGTERM, MOUNT_FAILURE_TIMEOUT);
                break;

        case MOUNT_UNMOUNTING_SIGTERM:
                if (m->kill_context.send_sigkill) {
                        log_unit_warning(UNIT(m), "Mount process timed out. Killing.");
                        mount_enter_signal(m, MOUNT_UNMOUNTING_SIGKILL, MOUNT_FAILURE_TIMEOUT);
                } else {
                        log_unit_warning(UNIT(m), "Mount process timed out. Skipping SIGKILL. Ignoring.");
                        mount_enter_dead_or_mounted(m, MOUNT_FAILURE_TIMEOUT);
                }
                break;

        case MOUNT_UNMOUNTING_SIGKILL:
                log_unit_warning(UNIT(m), "Mount process still around after SIGKILL. Ignoring.");
                mount_enter_dead_or_mounted(m, MOUNT_FAILURE_TIMEOUT);
                break;

        default:
                assert_not_reached("Timeout at wrong time.");
        }

        return 0;
}

typedef struct {
        bool is_mounted;
        bool just_mounted;
        bool just_changed;
} MountSetupFlags;

static int mount_setup_new_unit(
                Unit *u,
                const char *what,
                const char *where,
                const char *options,
                const char *fstype,
                MountSetupFlags *flags) {

        MountParameters *p;

        assert(u);
        assert(flags);

        u->source_path = strdup("/proc/self/mountinfo");
        MOUNT(u)->where = strdup(where);
        if (!u->source_path || !MOUNT(u)->where)
                return -ENOMEM;

        /* Make sure to initialize those fields before mount_is_extrinsic(). */
        MOUNT(u)->from_proc_self_mountinfo = true;
        p = &MOUNT(u)->parameters_proc_self_mountinfo;

        p->what = strdup(what);
        p->options = strdup(options);
        p->fstype = strdup(fstype);
        if (!p->what || !p->options || !p->fstype)
                return -ENOMEM;

        if (!mount_is_extrinsic(MOUNT(u))) {
                const char *target;
                int r;

                target = mount_is_network(p) ? SPECIAL_REMOTE_FS_TARGET : SPECIAL_LOCAL_FS_TARGET;
                r = unit_add_dependency_by_name(u, UNIT_BEFORE, target, true, UNIT_DEPENDENCY_MOUNTINFO_IMPLICIT);
                if (r < 0)
                        return r;

                r = unit_add_dependency_by_name(u, UNIT_CONFLICTS, SPECIAL_UMOUNT_TARGET, true, UNIT_DEPENDENCY_MOUNTINFO_IMPLICIT);
                if (r < 0)
                        return r;
        }

        unit_add_to_load_queue(u);
        flags->is_mounted = true;
        flags->just_mounted = true;
        flags->just_changed = true;

        return 0;
}

static int mount_setup_existing_unit(
                Unit *u,
                const char *what,
                const char *where,
                const char *options,
                const char *fstype,
                MountSetupFlags *flags) {

        MountParameters *p;
        bool load_extras = false;
        int r1, r2, r3;

        assert(u);
        assert(flags);

        if (!MOUNT(u)->where) {
                MOUNT(u)->where = strdup(where);
                if (!MOUNT(u)->where)
                        return -ENOMEM;
        }

        /* Make sure to initialize those fields before mount_is_extrinsic(). */
        p = &MOUNT(u)->parameters_proc_self_mountinfo;

        r1 = free_and_strdup(&p->what, what);
        r2 = free_and_strdup(&p->options, options);
        r3 = free_and_strdup(&p->fstype, fstype);
        if (r1 < 0 || r2 < 0 || r3 < 0)
                return -ENOMEM;

        flags->just_changed = r1 > 0 || r2 > 0 || r3 > 0;
        flags->is_mounted = true;
        flags->just_mounted = !MOUNT(u)->from_proc_self_mountinfo || MOUNT(u)->just_mounted;

        MOUNT(u)->from_proc_self_mountinfo = true;

        if (!mount_is_extrinsic(MOUNT(u)) && mount_is_network(p)) {
                /* _netdev option may have shown up late, or on a
                 * remount. Add remote-fs dependencies, even though
                 * local-fs ones may already be there.
                 *
                 * Note: due to a current limitation (we don't track
                 * in the dependency "Set*" objects who created a
                 * dependency), we can only add deps, never lose them,
                 * until the next full daemon-reload. */
                unit_add_dependency_by_name(u, UNIT_BEFORE, SPECIAL_REMOTE_FS_TARGET, true, UNIT_DEPENDENCY_MOUNTINFO_IMPLICIT);
                load_extras = true;
        }

        if (u->load_state == UNIT_NOT_FOUND) {
                u->load_state = UNIT_LOADED;
                u->load_error = 0;

                /* Load in the extras later on, after we
                 * finished initialization of the unit */

                /* FIXME: since we're going to load the unit later on, why setting load_extras=true ? */
                load_extras = true;
                flags->just_changed = true;
        }

        if (load_extras)
                return mount_add_extras(MOUNT(u));

        return 0;
}

static int mount_setup_unit(
                Manager *m,
                const char *what,
                const char *where,
                const char *options,
                const char *fstype,
                bool set_flags) {

        _cleanup_free_ char *e = NULL;
        MountSetupFlags flags;
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
                /* First time we see this mount point meaning that it's
                 * not been initiated by a mount unit but rather by the
                 * sysadmin having called mount(8) directly. */
                r = unit_new_for_name(m, sizeof(Mount), e, &u);
                if (r < 0)
                        goto fail;

                r = mount_setup_new_unit(u, what, where, options, fstype, &flags);
                if (r < 0)
                        unit_free(u);
        } else
                r = mount_setup_existing_unit(u, what, where, options, fstype, &flags);

        if (r < 0)
                goto fail;

        if (set_flags) {
                MOUNT(u)->is_mounted = flags.is_mounted;
                MOUNT(u)->just_mounted = flags.just_mounted;
                MOUNT(u)->just_changed = flags.just_changed;
        }

        if (flags.just_changed)
                unit_add_to_dbus_queue(u);

        return 0;
fail:
        return log_warning_errno(r, "Failed to set up mount unit: %m");
}

static int mount_load_proc_self_mountinfo(Manager *m, bool set_flags) {
        _cleanup_(mnt_free_tablep) struct libmnt_table *t = NULL;
        _cleanup_(mnt_free_iterp) struct libmnt_iter *i = NULL;
        int r = 0;

        assert(m);

        t = mnt_new_table();
        i = mnt_new_iter(MNT_ITER_FORWARD);
        if (!t || !i)
                return log_oom();

        r = mnt_table_parse_mtab(t, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to parse /proc/self/mountinfo: %m");

        r = 0;
        for (;;) {
                struct libmnt_fs *fs;
                const char *device, *path, *options, *fstype;
                _cleanup_free_ char *d = NULL, *p = NULL;
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

                if (!device || !path)
                        continue;

                if (cunescape(device, UNESCAPE_RELAX, &d) < 0)
                        return log_oom();

                if (cunescape(path, UNESCAPE_RELAX, &p) < 0)
                        return log_oom();

                device_found_node(m, d, DEVICE_FOUND_MOUNT, DEVICE_FOUND_MOUNT);

                k = mount_setup_unit(m, d, p, options, fstype, set_flags);
                if (r == 0 && k < 0)
                        r = k;
        }

        return r;
}

static void mount_shutdown(Manager *m) {
        assert(m);

        m->mount_event_source = sd_event_source_unref(m->mount_event_source);

        mnt_unref_monitor(m->mount_monitor);
        m->mount_monitor = NULL;
}

static int mount_get_timeout(Unit *u, usec_t *timeout) {
        Mount *m = MOUNT(u);
        usec_t t;
        int r;

        if (!m->timer_event_source)
                return 0;

        r = sd_event_source_get_time(m->timer_event_source, &t);
        if (r < 0)
                return r;
        if (t == USEC_INFINITY)
                return 0;

        *timeout = t;
        return 1;
}

static void mount_enumerate_perpetual(Manager *m) {
        Unit *u;
        int r;

        assert(m);

        /* Whatever happens, we know for sure that the root directory is around, and cannot go away. Let's
         * unconditionally synthesize it here and mark it as perpetual. */

        u = manager_get_unit(m, SPECIAL_ROOT_MOUNT);
        if (!u) {
                r = unit_new_for_name(m, sizeof(Mount), SPECIAL_ROOT_MOUNT, &u);
                if (r < 0) {
                        log_error_errno(r, "Failed to allocate the special " SPECIAL_ROOT_MOUNT " unit: %m");
                        return;
                }
        }

        u->perpetual = true;
        MOUNT(u)->deserialized_state = MOUNT_MOUNTED;

        unit_add_to_load_queue(u);
        unit_add_to_dbus_queue(u);
}

static bool mount_is_mounted(Mount *m) {
        assert(m);

        return UNIT(m)->perpetual || m->is_mounted;
}

static void mount_enumerate(Manager *m) {
        int r;

        assert(m);

        mnt_init_debug(0);

        if (!m->mount_monitor) {
                int fd;

                m->mount_monitor = mnt_new_monitor();
                if (!m->mount_monitor) {
                        log_oom();
                        goto fail;
                }

                r = mnt_monitor_enable_kernel(m->mount_monitor, 1);
                if (r < 0) {
                        log_error_errno(r, "Failed to enable watching of kernel mount events: %m");
                        goto fail;
                }

                r = mnt_monitor_enable_userspace(m->mount_monitor, 1, NULL);
                if (r < 0) {
                        log_error_errno(r, "Failed to enable watching of userspace mount events: %m");
                        goto fail;
                }

                /* mnt_unref_monitor() will close the fd */
                fd = r = mnt_monitor_get_fd(m->mount_monitor);
                if (r < 0) {
                        log_error_errno(r, "Failed to acquire watch file descriptor: %m");
                        goto fail;
                }

                r = sd_event_add_io(m->event, &m->mount_event_source, fd, EPOLLIN, mount_dispatch_io, m);
                if (r < 0) {
                        log_error_errno(r, "Failed to watch mount file descriptor: %m");
                        goto fail;
                }

                r = sd_event_source_set_priority(m->mount_event_source, SD_EVENT_PRIORITY_NORMAL-10);
                if (r < 0) {
                        log_error_errno(r, "Failed to adjust mount watch priority: %m");
                        goto fail;
                }

                (void) sd_event_source_set_description(m->mount_event_source, "mount-monitor-dispatch");
        }

        r = mount_load_proc_self_mountinfo(m, false);
        if (r < 0)
                goto fail;

        return;

fail:
        mount_shutdown(m);
}

static int mount_dispatch_io(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        _cleanup_set_free_ Set *around = NULL, *gone = NULL;
        Manager *m = userdata;
        const char *what;
        Iterator i;
        Unit *u;
        int r;

        assert(m);
        assert(revents & EPOLLIN);

        if (fd == mnt_monitor_get_fd(m->mount_monitor)) {
                bool rescan = false;

                /* Drain all events and verify that the event is valid.
                 *
                 * Note that libmount also monitors /run/mount mkdir if the
                 * directory does not exist yet. The mkdir may generate event
                 * which is irrelevant for us.
                 *
                 * error: r < 0; valid: r == 0, false positive: rc == 1 */
                do {
                        r = mnt_monitor_next_change(m->mount_monitor, NULL, NULL);
                        if (r == 0)
                                rescan = true;
                        else if (r < 0)
                                return log_error_errno(r, "Failed to drain libmount events: %m");
                } while (r == 0);

                log_debug("libmount event [rescan: %s]", yes_no(rescan));
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

                if (!mount_is_mounted(mount)) {

                        /* A mount point is not around right now. It
                         * might be gone, or might never have
                         * existed. */

                        if (mount->from_proc_self_mountinfo &&
                            mount->parameters_proc_self_mountinfo.what) {

                                /* Remember that this device might just have disappeared */
                                if (set_ensure_allocated(&gone, &path_hash_ops) < 0 ||
                                    set_put(gone, mount->parameters_proc_self_mountinfo.what) < 0)
                                        log_oom(); /* we don't care too much about OOM here... */
                        }

                        mount->from_proc_self_mountinfo = false;

                        switch (mount->state) {

                        case MOUNT_MOUNTED:
                                /* This has just been unmounted by
                                 * somebody else, follow the state
                                 * change. */
                                mount->result = MOUNT_SUCCESS; /* make sure we forget any earlier umount failures */
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

                                /* This has just been mounted by somebody else, follow the state change, but let's
                                 * generate a new invocation ID for this implicitly and automatically. */
                                (void) unit_acquire_invocation_id(UNIT(mount));
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

                if (mount_is_mounted(mount) &&
                    mount->from_proc_self_mountinfo &&
                    mount->parameters_proc_self_mountinfo.what) {

                        if (set_ensure_allocated(&around, &path_hash_ops) < 0 ||
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
                device_found_node(m, what, 0, DEVICE_FOUND_MOUNT);
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
        Mount *m = MOUNT(u);

        assert(m);

        return unit_kill_common(u, who, signo, -1, MOUNT(u)->control_pid, error);
}

static int mount_control_pid(Unit *u) {
        Mount *m = MOUNT(u);

        assert(m);

        return m->control_pid;
}

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
        [MOUNT_FAILURE_CORE_DUMP] = "core-dump",
        [MOUNT_FAILURE_START_LIMIT_HIT] = "start-limit-hit",
        [MOUNT_FAILURE_PROTOCOL] = "protocol",
};

DEFINE_STRING_TABLE_LOOKUP(mount_result, MountResult);

const UnitVTable mount_vtable = {
        .object_size = sizeof(Mount),
        .exec_context_offset = offsetof(Mount, exec_context),
        .cgroup_context_offset = offsetof(Mount, cgroup_context),
        .kill_context_offset = offsetof(Mount, kill_context),
        .exec_runtime_offset = offsetof(Mount, exec_runtime),
        .dynamic_creds_offset = offsetof(Mount, dynamic_creds),

        .sections =
                "Unit\0"
                "Mount\0"
                "Install\0",
        .private_section = "Mount",

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

        .may_gc = mount_may_gc,

        .sigchld_event = mount_sigchld_event,

        .reset_failed = mount_reset_failed,

        .control_pid = mount_control_pid,

        .bus_vtable = bus_mount_vtable,
        .bus_set_property = bus_mount_set_property,
        .bus_commit_properties = bus_mount_commit_properties,

        .get_timeout = mount_get_timeout,

        .can_transient = true,

        .enumerate_perpetual = mount_enumerate_perpetual,
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
                        [JOB_TIMEOUT]    = "Timed out mounting %s.",
                },
                .finished_stop_job = {
                        [JOB_DONE]       = "Unmounted %s.",
                        [JOB_FAILED]     = "Failed unmounting %s.",
                        [JOB_TIMEOUT]    = "Timed out unmounting %s.",
                },
        },
};
