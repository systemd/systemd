/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/epoll.h>

#include "sd-messages.h"

#include "alloc-util.h"
#include "dbus-mount.h"
#include "dbus-unit.h"
#include "device.h"
#include "exit-status.h"
#include "format-util.h"
#include "fstab-util.h"
#include "libmount-util.h"
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
        [MOUNT_FAILED] = UNIT_FAILED,
        [MOUNT_CLEANING] = UNIT_MAINTENANCE,
};

static int mount_dispatch_timer(sd_event_source *source, usec_t usec, void *userdata);
static int mount_dispatch_io(sd_event_source *source, int fd, uint32_t revents, void *userdata);
static int mount_process_proc_self_mountinfo(Manager *m);

static bool MOUNT_STATE_WITH_PROCESS(MountState state) {
        return IN_SET(state,
                      MOUNT_MOUNTING,
                      MOUNT_MOUNTING_DONE,
                      MOUNT_REMOUNTING,
                      MOUNT_REMOUNTING_SIGTERM,
                      MOUNT_REMOUNTING_SIGKILL,
                      MOUNT_UNMOUNTING,
                      MOUNT_UNMOUNTING_SIGTERM,
                      MOUNT_UNMOUNTING_SIGKILL,
                      MOUNT_CLEANING);
}

static MountParameters* get_mount_parameters_fragment(Mount *m) {
        assert(m);

        if (m->from_fragment)
                return &m->parameters_fragment;

        return NULL;
}

static MountParameters* get_mount_parameters(Mount *m) {
        assert(m);

        if (m->from_proc_self_mountinfo)
                return &m->parameters_proc_self_mountinfo;

        return get_mount_parameters_fragment(m);
}

static bool mount_is_automount(const MountParameters *p) {
        assert(p);

        return fstab_test_option(p->options,
                                 "comment=systemd.automount\0"
                                 "x-systemd.automount\0");
}

static bool mount_is_network(const MountParameters *p) {
        assert(p);

        if (fstab_test_option(p->options, "_netdev\0"))
                return true;

        if (p->fstype && fstype_is_network(p->fstype))
                return true;

        return false;
}

static bool mount_is_nofail(const Mount *m) {
        assert(m);

        if (!m->from_fragment)
                return false;

        return fstab_test_yes_no_option(m->parameters_fragment.options, "nofail\0" "fail\0");
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

static bool mount_is_bound_to_device(Mount *m) {
        const MountParameters *p;

        assert(m);

        /* Determines whether to place a Requires= or BindsTo= dependency on the backing device unit. We do
         * this by checking for the x-systemd.device-bound mount option. Iff it is set we use BindsTo=,
         * otherwise Requires=. But note that we might combine the latter with StopPropagatedFrom=, see
         * below. */

        p = get_mount_parameters(m);
        if (!p)
                return false;

        return fstab_test_option(p->options, "x-systemd.device-bound\0");
}

static bool mount_propagate_stop(Mount *m) {
        assert(m);

        if (mount_is_bound_to_device(m)) /* If we are using BindsTo= the stop propagation is implicit, no need to bother */
                return false;

        return m->from_fragment; /* let's propagate stop whenever this is an explicitly configured unit,
                                  * otherwise let's not bother. */
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

        m->timer_event_source = sd_event_source_disable_unref(m->timer_event_source);
}

static int update_parameters_proc_self_mountinfo(
                Mount *m,
                const char *what,
                const char *options,
                const char *fstype) {

        MountParameters *p;
        int r, q, w;

        p = &m->parameters_proc_self_mountinfo;

        r = free_and_strdup(&p->what, what);
        if (r < 0)
                return r;

        q = free_and_strdup(&p->options, options);
        if (q < 0)
                return q;

        w = free_and_strdup(&p->fstype, fstype);
        if (w < 0)
                return w;

        return r > 0 || q > 0 || w > 0;
}

static int mount_add_mount_dependencies(Mount *m) {
        MountParameters *pm;
        Unit *other;
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
        SET_FOREACH(other, s) {

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

        /* /dev/root is a really weird thing, it's not a real device, but just a path the kernel exports for
         * the root file system specified on the kernel command line. Ignore it here. */
        if (PATH_IN_SET(p->what, "/dev/root", "/dev/nfs"))
                return 0;

        if (path_equal(m->where, "/"))
                return 0;

        /* Mount units from /proc/self/mountinfo are not bound to devices by default since they're subject to
         * races when mounts are established by other tools with different backing devices than what we
         * maintain. The user can still force this to be a BindsTo= dependency with an appropriate option (or
         * udev property) so the mount units are automatically stopped when the device disappears
         * suddenly. */
        dep = mount_is_bound_to_device(m) ? UNIT_BINDS_TO : UNIT_REQUIRES;

        /* We always use 'what' from /proc/self/mountinfo if mounted */
        mask = m->from_proc_self_mountinfo ? UNIT_DEPENDENCY_MOUNTINFO_IMPLICIT : UNIT_DEPENDENCY_FILE;

        r = unit_add_node_dependency(UNIT(m), p->what, dep, mask);
        if (r < 0)
                return r;
        if (mount_propagate_stop(m)) {
                r = unit_add_node_dependency(UNIT(m), p->what, UNIT_STOP_PROPAGATED_FROM, mask);
                if (r < 0)
                        return r;
        }

        return unit_add_blockdev_dependency(UNIT(m), p->what, mask);
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

static bool mount_is_extrinsic(Unit *u) {
        MountParameters *p;
        Mount *m = MOUNT(u);
        assert(m);

        /* Returns true for all units that are "magic" and should be excluded from the usual
         * start-up and shutdown dependencies. We call them "extrinsic" here, as they are generally
         * mounted outside of the systemd dependency logic. We shouldn't attempt to manage them
         * ourselves but it's fine if the user operates on them with us. */

        /* We only automatically manage mounts if we are in system mode */
        if (MANAGER_IS_USER(u->manager))
                return true;

        p = get_mount_parameters(m);
        if (p && fstab_is_extrinsic(m->where, p->options))
                return true;

        return false;
}

static int mount_add_default_ordering_dependencies(
                Mount *m,
                MountParameters *p,
                UnitDependencyMask mask) {

        const char *after, *before, *e;
        int r;

        assert(m);

        e = path_startswith(m->where, "/sysroot");
        if (e && in_initrd()) {
                /* All mounts under /sysroot need to happen later, at initrd-fs.target time. IOW,
                 * it's not technically part of the basic initrd filesystem itself, and so
                 * shouldn't inherit the default Before=local-fs.target dependency. */

                after = NULL;
                before = isempty(e) ? SPECIAL_INITRD_ROOT_FS_TARGET : SPECIAL_INITRD_FS_TARGET;

        } else if (mount_is_network(p)) {
                after = SPECIAL_REMOTE_FS_PRE_TARGET;
                before = SPECIAL_REMOTE_FS_TARGET;

        } else {
                after = SPECIAL_LOCAL_FS_PRE_TARGET;
                before = SPECIAL_LOCAL_FS_TARGET;
        }

        if (!mount_is_nofail(m) && !mount_is_automount(p)) {
                r = unit_add_dependency_by_name(UNIT(m), UNIT_BEFORE, before, true, mask);
                if (r < 0)
                        return r;
        }

        if (after) {
                r = unit_add_dependency_by_name(UNIT(m), UNIT_AFTER, after, true, mask);
                if (r < 0)
                        return r;
        }

        return unit_add_two_dependencies_by_name(UNIT(m), UNIT_BEFORE, UNIT_CONFLICTS,
                                                 SPECIAL_UMOUNT_TARGET, true, mask);
}

static int mount_add_default_dependencies(Mount *m) {
        UnitDependencyMask mask;
        MountParameters *p;
        int r;

        assert(m);

        if (!UNIT(m)->default_dependencies)
                return 0;

        /* We do not add any default dependencies to /, /usr or /run/initramfs/, since they are
         * guaranteed to stay mounted the whole time, since our system is on it.  Also, don't
         * bother with anything mounted below virtual file systems, it's also going to be virtual,
         * and hence not worth the effort. */
        if (mount_is_extrinsic(UNIT(m)))
                return 0;

        p = get_mount_parameters(m);
        if (!p)
                return 0;

        mask = m->from_fragment ? UNIT_DEPENDENCY_FILE : UNIT_DEPENDENCY_MOUNTINFO_DEFAULT;

        r = mount_add_default_ordering_dependencies(m, p, mask);
        if (r < 0)
                return r;

        if (mount_is_network(p)) {
                /* We order ourselves after network.target. This is primarily useful at shutdown:
                 * services that take down the network should order themselves before
                 * network.target, so that they are shut down only after this mount unit is
                 * stopped. */

                r = unit_add_dependency_by_name(UNIT(m), UNIT_AFTER, SPECIAL_NETWORK_TARGET, true, mask);
                if (r < 0)
                        return r;

                /* We pull in network-online.target, and order ourselves after it. This is useful
                 * at start-up to actively pull in tools that want to be started before we start
                 * mounting network file systems, and whose purpose it is to delay this until the
                 * network is "up". */

                r = unit_add_two_dependencies_by_name(UNIT(m), UNIT_WANTS, UNIT_AFTER, SPECIAL_NETWORK_ONLINE_TARGET, true, mask);
                if (r < 0)
                        return r;
        }

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
        assert(UNIT(m)->load_state == UNIT_LOADED);

        if (!m->from_fragment && !m->from_proc_self_mountinfo && !UNIT(m)->perpetual)
                return -ENOENT;

        r = unit_name_from_path(m->where, ".mount", &e);
        if (r < 0)
                return log_unit_error_errno(UNIT(m), r, "Failed to generate unit name from mount path: %m");

        if (!unit_has_name(UNIT(m), e))
                return log_unit_error_errno(UNIT(m), SYNTHETIC_ERRNO(ENOEXEC), "Where= setting doesn't match unit name. Refusing.");

        if (mount_point_is_api(m->where) || mount_point_ignore(m->where))
                return log_unit_error_errno(UNIT(m), SYNTHETIC_ERRNO(ENOEXEC), "Cannot create mount unit for API file system %s. Refusing.", m->where);

        p = get_mount_parameters_fragment(m);
        if (p && !p->what && !UNIT(m)->perpetual)
                return log_unit_error_errno(UNIT(m), SYNTHETIC_ERRNO(ENOEXEC),
                                            "What= setting is missing. Refusing.");

        if (m->exec_context.pam_name && m->kill_context.kill_mode != KILL_CONTROL_GROUP)
                return log_unit_error_errno(UNIT(m), SYNTHETIC_ERRNO(ENOEXEC), "Unit has PAM enabled. Kill mode must be set to control-group'. Refusing.");

        return 0;
}

static int mount_add_non_exec_dependencies(Mount *m) {
        int r;
        assert(m);

        /* Adds in all dependencies directly responsible for ordering the mount, as opposed to dependencies
         * resulting from the ExecContext and such. */

        r = mount_add_device_dependencies(m);
        if (r < 0)
                return r;

        r = mount_add_mount_dependencies(m);
        if (r < 0)
                return r;

        r = mount_add_quota_dependencies(m);
        if (r < 0)
                return r;

        r = mount_add_default_dependencies(m);
        if (r < 0)
                return r;

        return 0;
}

static int mount_add_extras(Mount *m) {
        Unit *u = UNIT(m);
        int r;

        assert(m);

        /* Note: this call might be called after we already have been loaded once (and even when it has already been
         * activated), in case data from /proc/self/mountinfo has changed. This means all code here needs to be ready
         * to run with an already set up unit. */

        if (u->fragment_path)
                m->from_fragment = true;

        if (!m->where) {
                r = unit_name_to_path(u->id, &m->where);
                if (r < 0)
                        return r;
        }

        path_simplify(m->where);

        if (!u->description) {
                r = unit_set_description(u, m->where);
                if (r < 0)
                        return r;
        }

        r = unit_patch_contexts(u);
        if (r < 0)
                return r;

        r = unit_add_exec_dependencies(u, &m->exec_context);
        if (r < 0)
                return r;

        r = unit_set_default_slice(u);
        if (r < 0)
                return r;

        r = mount_add_non_exec_dependencies(m);
        if (r < 0)
                return r;

        return 0;
}

static void mount_load_root_mount(Unit *u) {
        assert(u);

        if (!unit_has_name(u, SPECIAL_ROOT_MOUNT))
                return;

        u->perpetual = true;
        u->default_dependencies = false;

        /* The stdio/kmsg bridge socket is on /, in order to avoid a dep loop, don't use kmsg logging for -.mount */
        MOUNT(u)->exec_context.std_output = EXEC_OUTPUT_NULL;
        MOUNT(u)->exec_context.std_input = EXEC_INPUT_NULL;

        if (!u->description)
                u->description = strdup("Root Mount");
}

static int mount_load(Unit *u) {
        Mount *m = MOUNT(u);
        int r, q = 0;

        assert(u);
        assert(u->load_state == UNIT_STUB);

        mount_load_root_mount(u);

        bool fragment_optional = m->from_proc_self_mountinfo || u->perpetual;
        r = unit_load_fragment_and_dropin(u, !fragment_optional);

        /* Add in some extras. Note we do this in all cases (even if we failed to load the unit) when announced by the
         * kernel, because we need some things to be set up no matter what when the kernel establishes a mount and thus
         * we need to update the state in our unit to track it. After all, consider that we don't allow changing the
         * 'slice' field for a unit once it is active. */
        if (u->load_state == UNIT_LOADED || m->from_proc_self_mountinfo || u->perpetual)
                q = mount_add_extras(m);

        if (r < 0)
                return r;
        if (q < 0)
                return q;
        if (u->load_state != UNIT_LOADED)
                return 0;

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
                m->timer_event_source = sd_event_source_disable_unref(m->timer_event_source);
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

                r = unit_watch_pid(UNIT(m), m->control_pid, false);
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
                "%sClean Result: %s\n"
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
                "%sReadWriteOnly: %s\n"
                "%sTimeoutSec: %s\n",
                prefix, mount_state_to_string(m->state),
                prefix, mount_result_to_string(m->result),
                prefix, mount_result_to_string(m->clean_result),
                prefix, m->where,
                prefix, p ? strna(p->what) : "n/a",
                prefix, p ? strna(p->fstype) : "n/a",
                prefix, p ? strna(p->options) : "n/a",
                prefix, yes_no(m->from_proc_self_mountinfo),
                prefix, yes_no(m->from_fragment),
                prefix, yes_no(mount_is_extrinsic(u)),
                prefix, m->directory_mode,
                prefix, yes_no(m->sloppy_options),
                prefix, yes_no(m->lazy_unmount),
                prefix, yes_no(m->force_unmount),
                prefix, yes_no(m->read_write_only),
                prefix, format_timespan(buf, sizeof(buf), m->timeout_usec, USEC_PER_SEC));

        if (m->control_pid > 0)
                fprintf(f,
                        "%sControl PID: "PID_FMT"\n",
                        prefix, m->control_pid);

        exec_context_dump(&m->exec_context, f, prefix);
        kill_context_dump(&m->kill_context, f, prefix);
        cgroup_context_dump(UNIT(m), f, prefix);
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

        r = unit_watch_pid(UNIT(m), pid, true);
        if (r < 0)
                return r;

        *_pid = pid;

        return 0;
}

static void mount_enter_dead(Mount *m, MountResult f) {
        assert(m);

        if (m->result == MOUNT_SUCCESS)
                m->result = f;

        unit_log_result(UNIT(m), m->result == MOUNT_SUCCESS, mount_result_to_string(m->result));
        unit_warn_leftover_processes(UNIT(m), unit_log_leftover_process_stop);

        mount_set_state(m, m->result != MOUNT_SUCCESS ? MOUNT_FAILED : MOUNT_DEAD);

        m->exec_runtime = exec_runtime_unref(m->exec_runtime, true);

        unit_destroy_runtime_data(UNIT(m), &m->exec_context);

        unit_unref_uid_gid(UNIT(m), true);

        dynamic_creds_destroy(&m->dynamic_creds);

        /* Any dependencies based on /proc/self/mountinfo are now stale */
        unit_remove_dependencies(UNIT(m), UNIT_DEPENDENCY_MOUNTINFO_IMPLICIT);
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
                return KILL_RESTART;

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
        unit_warn_leftover_processes(UNIT(m), unit_log_leftover_process_start);

        m->control_command_id = MOUNT_EXEC_MOUNT;
        m->control_command = m->exec_command + MOUNT_EXEC_MOUNT;

        /* Create the source directory for bind-mounts if needed */
        p = get_mount_parameters_fragment(m);
        if (p && mount_is_bind(p)) {
                r = mkdir_p_label(p->what, m->directory_mode);
                /* mkdir_p_label() can return -EEXIST if the target path exists and is not a directory - which is
                 * totally OK, in case the user wants us to overmount a non-directory inode. */
                if (r < 0 && r != -EEXIST)
                        log_unit_error_errno(UNIT(m), r, "Failed to make bind mount source '%s': %m", p->what);
        }

        if (p) {
                _cleanup_free_ char *opts = NULL;

                r = fstab_filter_options(p->options, "nofail\0" "noauto\0" "auto\0", NULL, NULL, NULL, &opts);
                if (r < 0)
                        goto fail;

                r = exec_command_set(m->control_command, MOUNT_PATH, p->what, m->where, NULL);
                if (r >= 0 && m->sloppy_options)
                        r = exec_command_append(m->control_command, "-s", NULL);
                if (r >= 0 && m->read_write_only)
                        r = exec_command_append(m->control_command, "-w", NULL);
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
                if (r >= 0 && m->read_write_only)
                        r = exec_command_append(m->control_command, "-w", NULL);
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

static void mount_cycle_clear(Mount *m) {
        assert(m);

        /* Clear all state we shall forget for this new cycle */

        m->result = MOUNT_SUCCESS;
        m->reload_result = MOUNT_SUCCESS;
        exec_command_reset_status_array(m->exec_command, _MOUNT_EXEC_COMMAND_MAX);
        UNIT(m)->reset_accounting = true;
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
                   MOUNT_UNMOUNTING_SIGKILL,
                   MOUNT_CLEANING))
                return -EAGAIN;

        /* Already on it! */
        if (IN_SET(m->state, MOUNT_MOUNTING, MOUNT_MOUNTING_DONE))
                return 0;

        assert(IN_SET(m->state, MOUNT_DEAD, MOUNT_FAILED));

        r = unit_acquire_invocation_id(u);
        if (r < 0)
                return r;

        mount_cycle_clear(m);
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

        case MOUNT_CLEANING:
                /* If we are currently cleaning, then abort it, brutally. */
                mount_enter_signal(m, MOUNT_UNMOUNTING_SIGKILL, MOUNT_SUCCESS);
                return 0;

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
        (void) serialize_item_format(f, "n-retry-umount", "%u", m->n_retry_umount);

        if (m->control_pid > 0)
                (void) serialize_item_format(f, "control-pid", PID_FMT, m->control_pid);

        if (m->control_command_id >= 0)
                (void) serialize_item(f, "control-command", mount_exec_command_to_string(m->control_command_id));

        return 0;
}

static int mount_deserialize_item(Unit *u, const char *key, const char *value, FDSet *fds) {
        Mount *m = MOUNT(u);
        int r;

        assert(u);
        assert(key);
        assert(value);
        assert(fds);

        if (streq(key, "state")) {
                MountState state;

                state = mount_state_from_string(value);
                if (state < 0)
                        log_unit_debug_errno(u, state, "Failed to parse state value: %s", value);
                else
                        m->deserialized_state = state;

        } else if (streq(key, "result")) {
                MountResult f;

                f = mount_result_from_string(value);
                if (f < 0)
                        log_unit_debug_errno(u, f, "Failed to parse result value: %s", value);
                else if (f != MOUNT_SUCCESS)
                        m->result = f;

        } else if (streq(key, "reload-result")) {
                MountResult f;

                f = mount_result_from_string(value);
                if (f < 0)
                        log_unit_debug_errno(u, f, "Failed to parse reload result value: %s", value);
                else if (f != MOUNT_SUCCESS)
                        m->reload_result = f;

        } else if (streq(key, "n-retry-umount")) {

                r = safe_atou(value, &m->n_retry_umount);
                if (r < 0)
                        log_unit_debug_errno(u, r, "Failed to parse n-retry-umount value: %s", value);

        } else if (streq(key, "control-pid")) {

                r = parse_pid(value, &m->control_pid);
                if (r < 0)
                        log_unit_debug_errno(u, r, "Failed to parse control-pid value: %s", value);

        } else if (streq(key, "control-command")) {
                MountExecCommand id;

                id = mount_exec_command_from_string(value);
                if (id < 0)
                        log_unit_debug_errno(u, id, "Failed to parse exec-command value: %s", value);
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

        /* So here's the thing, we really want to know before /usr/bin/mount or /usr/bin/umount exit whether
         * they established/remove a mount. This is important when mounting, but even more so when unmounting
         * since we need to deal with nested mounts and otherwise cannot safely determine whether to repeat
         * the unmounts. In theory, the kernel fires /proc/self/mountinfo changes off before returning from
         * the mount() or umount() syscalls, and thus we should see the changes to the proc file before we
         * process the waitid() for the /usr/bin/(u)mount processes. However, this is unfortunately racy: we
         * have to waitid() for processes using P_ALL (since we need to reap unexpected children that got
         * reparented to PID 1), but when using P_ALL we might end up reaping processes that terminated just
         * instants ago, i.e. already after our last event loop iteration (i.e. after the last point we might
         * have noticed /proc/self/mountinfo events via epoll). This means event loop priorities for
         * processing SIGCHLD vs. /proc/self/mountinfo IO events are not as relevant as we want. To fix that
         * race, let's explicitly scan /proc/self/mountinfo before we start processing /usr/bin/(u)mount
         * dying. It's ugly, but it makes our ordering systematic again, and makes sure we always see
         * /proc/self/mountinfo changes before our mount/umount exits. */
        (void) mount_process_proc_self_mountinfo(u->manager);

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
                        u,
                        "Mount process",
                        mount_exec_command_to_string(m->control_command_id),
                        f == MOUNT_SUCCESS,
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

        case MOUNT_CLEANING:
                if (m->clean_result == MOUNT_SUCCESS)
                        m->clean_result = f;

                mount_enter_dead(m, MOUNT_SUCCESS);
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

        case MOUNT_CLEANING:
                log_unit_warning(UNIT(m), "Cleaning timed out. killing.");

                if (m->clean_result == MOUNT_SUCCESS)
                        m->clean_result = MOUNT_FAILURE_TIMEOUT;

                mount_enter_signal(m, MOUNT_UNMOUNTING_SIGKILL, 0);
                break;

        default:
                assert_not_reached("Timeout at wrong time.");
        }

        return 0;
}

static int mount_setup_new_unit(
                Manager *m,
                const char *name,
                const char *what,
                const char *where,
                const char *options,
                const char *fstype,
                MountProcFlags *ret_flags,
                Unit **ret) {

        _cleanup_(unit_freep) Unit *u = NULL;
        int r;

        assert(m);
        assert(name);
        assert(ret_flags);
        assert(ret);

        r = unit_new_for_name(m, sizeof(Mount), name, &u);
        if (r < 0)
                return r;

        r = free_and_strdup(&u->source_path, "/proc/self/mountinfo");
        if (r < 0)
                return r;

        r = free_and_strdup(&MOUNT(u)->where, where);
        if (r < 0)
                return r;

        r = update_parameters_proc_self_mountinfo(MOUNT(u), what, options, fstype);
        if (r < 0)
                return r;

        r = mount_add_non_exec_dependencies(MOUNT(u));
        if (r < 0)
                return r;

        /* This unit was generated because /proc/self/mountinfo reported it. Remember this, so that by the time we load
         * the unit file for it (and thus add in extra deps right after) we know what source to attributes the deps
         * to. */
        MOUNT(u)->from_proc_self_mountinfo = true;

        /* We have only allocated the stub now, let's enqueue this unit for loading now, so that everything else is
         * loaded in now. */
        unit_add_to_load_queue(u);

        *ret_flags = MOUNT_PROC_IS_MOUNTED | MOUNT_PROC_JUST_MOUNTED | MOUNT_PROC_JUST_CHANGED;
        *ret = TAKE_PTR(u);
        return 0;
}

static int mount_setup_existing_unit(
                Unit *u,
                const char *what,
                const char *where,
                const char *options,
                const char *fstype,
                MountProcFlags *ret_flags) {

        int r;

        assert(u);
        assert(ret_flags);

        if (!MOUNT(u)->where) {
                MOUNT(u)->where = strdup(where);
                if (!MOUNT(u)->where)
                        return -ENOMEM;
        }

        /* In case we have multiple mounts established on the same mount point, let's merge flags set already
         * for the current unit. Note that the flags field is reset on each iteration of reading
         * /proc/self/mountinfo, hence we know for sure anything already set here is from the current
         * iteration and thus worthy of taking into account. */
        MountProcFlags flags =
                MOUNT(u)->proc_flags | MOUNT_PROC_IS_MOUNTED;

        r = update_parameters_proc_self_mountinfo(MOUNT(u), what, options, fstype);
        if (r < 0)
                return r;
        if (r > 0)
                flags |= MOUNT_PROC_JUST_CHANGED;

        /* There are two conditions when we consider a mount point just mounted: when we haven't seen it in
         * /proc/self/mountinfo before or when MOUNT_MOUNTING is our current state. Why bother with the
         * latter? Shouldn't that be covered by the former? No, during reload it is not because we might then
         * encounter a new /proc/self/mountinfo in combination with an old mount unit state (since it stems
         * from the serialized state), and need to catch up. Since we know that the MOUNT_MOUNTING state is
         * reached when we wait for the mount to appear we hence can assume that if we are in it, we are
         * actually seeing it established for the first time. */
        if (!MOUNT(u)->from_proc_self_mountinfo || MOUNT(u)->state == MOUNT_MOUNTING)
                flags |= MOUNT_PROC_JUST_MOUNTED;

        MOUNT(u)->from_proc_self_mountinfo = true;

        if (IN_SET(u->load_state, UNIT_NOT_FOUND, UNIT_BAD_SETTING, UNIT_ERROR)) {
                /* The unit was previously not found or otherwise not loaded. Now that the unit shows up in
                 * /proc/self/mountinfo we should reconsider it this, hence set it to UNIT_LOADED. */
                u->load_state = UNIT_LOADED;
                u->load_error = 0;

                flags |= MOUNT_PROC_JUST_CHANGED;
        }

        if (FLAGS_SET(flags, MOUNT_PROC_JUST_CHANGED)) {
                /* If things changed, then make sure that all deps are regenerated. Let's
                 * first remove all automatic deps, and then add in the new ones. */

                unit_remove_dependencies(u, UNIT_DEPENDENCY_MOUNTINFO_IMPLICIT);

                r = mount_add_non_exec_dependencies(MOUNT(u));
                if (r < 0)
                        return r;
        }

        *ret_flags = flags;
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
        MountProcFlags flags;
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

        /* Mount unit names have to be (like all other unit names) short enough to fit into file names. This
         * means there's a good chance that overly long mount point paths after mangling them to look like a
         * unit name would result in unit names we don't actually consider valid. This should be OK however
         * as such long mount point paths should not happen on regular systems — and if they appear
         * nonetheless they are generally synthesized by software, and thus managed by that other
         * software. Having such long names just means you cannot use systemd to manage those specific mount
         * points, which should be an OK restriction to make. After all we don't have to be able to manage
         * all mount points in the world — as long as we don't choke on them when we encounter them. */
        r = unit_name_from_path(where, ".mount", &e);
        if (r < 0) {
                static RateLimit rate_limit = { /* Let's log about this at warning level at most once every
                                                 * 5s. Given that we generate this whenever we read the file
                                                 * otherwise we probably shouldn't flood the logs with
                                                 * this */
                        .interval = 5 * USEC_PER_SEC,
                        .burst = 1,
                };

                if (r == -ENAMETOOLONG)
                        return log_struct_errno(
                                        ratelimit_below(&rate_limit) ? LOG_WARNING : LOG_DEBUG, r,
                                        "MESSAGE_ID=" SD_MESSAGE_MOUNT_POINT_PATH_NOT_SUITABLE_STR,
                                        "MOUNT_POINT=%s", where,
                                        LOG_MESSAGE("Mount point path '%s' too long to fit into unit name, ignoring mount point.", where));

                return log_struct_errno(
                                ratelimit_below(&rate_limit) ? LOG_WARNING : LOG_DEBUG, r,
                                "MESSAGE_ID=" SD_MESSAGE_MOUNT_POINT_PATH_NOT_SUITABLE_STR,
                                "MOUNT_POINT=%s", where,
                                LOG_MESSAGE("Failed to generate valid unit name from mount point path '%s', ignoring mount point: %m", where));
        }

        u = manager_get_unit(m, e);
        if (u)
                r = mount_setup_existing_unit(u, what, where, options, fstype, &flags);
        else
                /* First time we see this mount point meaning that it's not been initiated by a mount unit but rather
                 * by the sysadmin having called mount(8) directly. */
                r = mount_setup_new_unit(m, e, what, where, options, fstype, &flags, &u);
        if (r < 0)
                return log_warning_errno(r, "Failed to set up mount unit for '%s': %m", where);

        /* If the mount changed properties or state, let's notify our clients */
        if (flags & (MOUNT_PROC_JUST_CHANGED|MOUNT_PROC_JUST_MOUNTED))
                unit_add_to_dbus_queue(u);

        if (set_flags)
                MOUNT(u)->proc_flags = flags;

        return 0;
}

static int mount_load_proc_self_mountinfo(Manager *m, bool set_flags) {
        _cleanup_(mnt_free_tablep) struct libmnt_table *table = NULL;
        _cleanup_(mnt_free_iterp) struct libmnt_iter *iter = NULL;
        int r;

        assert(m);

        r = libmount_parse(NULL, NULL, &table, &iter);
        if (r < 0)
                return log_error_errno(r, "Failed to parse /proc/self/mountinfo: %m");

        for (;;) {
                struct libmnt_fs *fs;
                const char *device, *path, *options, *fstype;

                r = mnt_table_next_fs(table, iter, &fs);
                if (r == 1)
                        break;
                if (r < 0)
                        return log_error_errno(r, "Failed to get next entry from /proc/self/mountinfo: %m");

                device = mnt_fs_get_source(fs);
                path = mnt_fs_get_target(fs);
                options = mnt_fs_get_options(fs);
                fstype = mnt_fs_get_fstype(fs);

                if (!device || !path)
                        continue;

                device_found_node(m, device, DEVICE_FOUND_MOUNT, DEVICE_FOUND_MOUNT);

                (void) mount_setup_unit(m, device, path, options, fstype, set_flags);
        }

        return 0;
}

static void mount_shutdown(Manager *m) {
        assert(m);

        m->mount_event_source = sd_event_source_disable_unref(m->mount_event_source);

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

        return UNIT(m)->perpetual || FLAGS_SET(m->proc_flags, MOUNT_PROC_IS_MOUNTED);
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

                r = sd_event_source_set_ratelimit(m->mount_event_source, 1 * USEC_PER_SEC, 5);
                if (r < 0) {
                        log_error_errno(r, "Failed to enable rate limit for mount events: %m");
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

static int drain_libmount(Manager *m) {
        bool rescan = false;
        int r;

        assert(m);

        /* Drain all events and verify that the event is valid.
         *
         * Note that libmount also monitors /run/mount mkdir if the directory does not exist yet. The mkdir
         * may generate event which is irrelevant for us.
         *
         * error: r < 0; valid: r == 0, false positive: r == 1 */
        do {
                r = mnt_monitor_next_change(m->mount_monitor, NULL, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to drain libmount events: %m");
                if (r == 0)
                        rescan = true;
        } while (r == 0);

        return rescan;
}

static int mount_process_proc_self_mountinfo(Manager *m) {
        _cleanup_set_free_free_ Set *around = NULL, *gone = NULL;
        const char *what;
        Unit *u;
        int r;

        assert(m);

        r = drain_libmount(m);
        if (r <= 0)
                return r;

        r = mount_load_proc_self_mountinfo(m, true);
        if (r < 0) {
                /* Reset flags, just in case, for later calls */
                LIST_FOREACH(units_by_type, u, m->units_by_type[UNIT_MOUNT])
                        MOUNT(u)->proc_flags = 0;

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
                                    set_put_strdup(&gone, mount->parameters_proc_self_mountinfo.what) < 0)
                                        log_oom(); /* we don't care too much about OOM here... */
                        }

                        mount->from_proc_self_mountinfo = false;
                        assert_se(update_parameters_proc_self_mountinfo(mount, NULL, NULL, NULL) >= 0);

                        switch (mount->state) {

                        case MOUNT_MOUNTED:
                                /* This has just been unmounted by somebody else, follow the state change. */
                                mount_enter_dead(mount, MOUNT_SUCCESS);
                                break;

                        case MOUNT_MOUNTING_DONE:
                                /* The mount command may add the corresponding proc mountinfo entry and
                                 * then remove it because of an internal error. E.g., fuse.sshfs seems
                                 * to do that when the connection fails. See #17617. To handle such the
                                 * case, let's once set the state back to mounting. Then, the unit can
                                 * correctly enter the failed state later in mount_sigchld(). */
                                mount_set_state(mount, MOUNT_MOUNTING);
                                break;

                        default:
                                break;
                        }

                } else if (mount->proc_flags & (MOUNT_PROC_JUST_MOUNTED|MOUNT_PROC_JUST_CHANGED)) {

                        /* A mount point was added or changed */

                        switch (mount->state) {

                        case MOUNT_DEAD:
                        case MOUNT_FAILED:

                                /* This has just been mounted by somebody else, follow the state change, but let's
                                 * generate a new invocation ID for this implicitly and automatically. */
                                (void) unit_acquire_invocation_id(u);
                                mount_cycle_clear(mount);
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
                        /* Track devices currently used */

                        if (set_ensure_allocated(&around, &path_hash_ops) < 0 ||
                            set_put_strdup(&around, mount->parameters_proc_self_mountinfo.what) < 0)
                                log_oom();
                }

                /* Reset the flags for later calls */
                mount->proc_flags = 0;
        }

        SET_FOREACH(what, gone) {
                if (set_contains(around, what))
                        continue;

                /* Let the device units know that the device is no longer mounted */
                device_found_node(m, what, 0, DEVICE_FOUND_MOUNT);
        }

        return 0;
}

static int mount_dispatch_io(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        Manager *m = userdata;

        assert(m);
        assert(revents & EPOLLIN);

        return mount_process_proc_self_mountinfo(m);
}

static void mount_reset_failed(Unit *u) {
        Mount *m = MOUNT(u);

        assert(m);

        if (m->state == MOUNT_FAILED)
                mount_set_state(m, MOUNT_DEAD);

        m->result = MOUNT_SUCCESS;
        m->reload_result = MOUNT_SUCCESS;
        m->clean_result = MOUNT_SUCCESS;
}

static int mount_kill(Unit *u, KillWho who, int signo, sd_bus_error *error) {
        Mount *m = MOUNT(u);

        assert(m);

        return unit_kill_common(u, who, signo, -1, m->control_pid, error);
}

static int mount_control_pid(Unit *u) {
        Mount *m = MOUNT(u);

        assert(m);

        return m->control_pid;
}

static int mount_clean(Unit *u, ExecCleanMask mask) {
        _cleanup_strv_free_ char **l = NULL;
        Mount *m = MOUNT(u);
        int r;

        assert(m);
        assert(mask != 0);

        if (m->state != MOUNT_DEAD)
                return -EBUSY;

        r = exec_context_get_clean_directories(&m->exec_context, u->manager->prefix, mask, &l);
        if (r < 0)
                return r;

        if (strv_isempty(l))
                return -EUNATCH;

        mount_unwatch_control_pid(m);
        m->clean_result = MOUNT_SUCCESS;
        m->control_command = NULL;
        m->control_command_id = _MOUNT_EXEC_COMMAND_INVALID;

        r = mount_arm_timer(m, usec_add(now(CLOCK_MONOTONIC), m->exec_context.timeout_clean_usec));
        if (r < 0)
                goto fail;

        r = unit_fork_and_watch_rm_rf(u, l, &m->control_pid);
        if (r < 0)
                goto fail;

        mount_set_state(m, MOUNT_CLEANING);

        return 0;

fail:
        log_unit_warning_errno(u, r, "Failed to initiate cleaning: %m");
        m->clean_result = MOUNT_FAILURE_RESOURCES;
        m->timer_event_source = sd_event_source_disable_unref(m->timer_event_source);
        return r;
}

static int mount_can_clean(Unit *u, ExecCleanMask *ret) {
        Mount *m = MOUNT(u);

        assert(m);

        return exec_context_get_clean_mask(&m->exec_context, ret);
}

static int mount_test_start_limit(Unit *u) {
        Mount *m = MOUNT(u);
        int r;

        assert(m);

        r = unit_test_start_limit(u);
        if (r < 0) {
                mount_enter_dead(m, MOUNT_FAILURE_START_LIMIT_HIT);
                return r;
        }

        return 0;
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

        .can_transient = true,
        .can_fail = true,
        .exclude_from_switch_root_serialization = true,

        .init = mount_init,
        .load = mount_load,
        .done = mount_done,

        .coldplug = mount_coldplug,

        .dump = mount_dump,

        .start = mount_start,
        .stop = mount_stop,
        .reload = mount_reload,

        .kill = mount_kill,
        .clean = mount_clean,
        .can_clean = mount_can_clean,

        .serialize = mount_serialize,
        .deserialize_item = mount_deserialize_item,

        .active_state = mount_active_state,
        .sub_state_to_string = mount_sub_state_to_string,

        .will_restart = unit_will_restart_default,

        .may_gc = mount_may_gc,
        .is_extrinsic = mount_is_extrinsic,

        .sigchld_event = mount_sigchld_event,

        .reset_failed = mount_reset_failed,

        .control_pid = mount_control_pid,

        .bus_set_property = bus_mount_set_property,
        .bus_commit_properties = bus_mount_commit_properties,

        .get_timeout = mount_get_timeout,

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

        .test_start_limit = mount_test_start_limit,
};
