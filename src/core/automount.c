/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/auto_dev-ioctl.h>
#include <linux/auto_fs4.h>
#include <sys/epoll.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "async.h"
#include "automount.h"
#include "bus-error.h"
#include "bus-util.h"
#include "dbus-automount.h"
#include "dbus-unit.h"
#include "fd-util.h"
#include "format-util.h"
#include "fstab-util.h"
#include "io-util.h"
#include "label-util.h"
#include "mkdir-label.h"
#include "mount-util.h"
#include "mount.h"
#include "mountpoint-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "serialize.h"
#include "special.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"
#include "unit-name.h"
#include "unit.h"

static const UnitActiveState state_translation_table[_AUTOMOUNT_STATE_MAX] = {
        [AUTOMOUNT_DEAD] = UNIT_INACTIVE,
        [AUTOMOUNT_WAITING] = UNIT_ACTIVE,
        [AUTOMOUNT_RUNNING] = UNIT_ACTIVE,
        [AUTOMOUNT_FAILED] = UNIT_FAILED
};

static int open_dev_autofs(Manager *m);
static int automount_dispatch_io(sd_event_source *s, int fd, uint32_t events, void *userdata);
static int automount_start_expire(Automount *a);
static void automount_stop_expire(Automount *a);
static int automount_send_ready(Automount *a, Set *tokens, int status);

static void automount_init(Unit *u) {
        Automount *a = AUTOMOUNT(u);

        assert(a);
        assert(u);
        assert(u->load_state == UNIT_STUB);

        a->pipe_fd = -EBADF;
        a->directory_mode = 0755;
        UNIT(a)->ignore_on_isolate = true;
}

static void unmount_autofs(Automount *a) {
        int r;

        assert(a);

        if (a->pipe_fd < 0)
                return;

        a->pipe_event_source = sd_event_source_disable_unref(a->pipe_event_source);
        a->pipe_fd = safe_close(a->pipe_fd);

        /* If we reload/reexecute things we keep the mount point around */
        if (!IN_SET(UNIT(a)->manager->objective, MANAGER_RELOAD, MANAGER_REEXECUTE)) {

                automount_send_ready(a, a->tokens, -EHOSTDOWN);
                automount_send_ready(a, a->expire_tokens, -EHOSTDOWN);

                if (a->where) {
                        r = repeat_unmount(a->where, MNT_DETACH|UMOUNT_NOFOLLOW);
                        if (r < 0)
                                log_unit_error_errno(UNIT(a), r, "Failed to unmount: %m");
                }
        }
}

static void automount_done(Unit *u) {
        Automount *a = AUTOMOUNT(u);

        assert(a);

        unmount_autofs(a);

        a->where = mfree(a->where);
        a->extra_options = mfree(a->extra_options);

        a->tokens = set_free(a->tokens);
        a->expire_tokens = set_free(a->expire_tokens);

        a->expire_event_source = sd_event_source_disable_unref(a->expire_event_source);
}

static int automount_add_trigger_dependencies(Automount *a) {
        Unit *x;
        int r;

        assert(a);

        r = unit_load_related_unit(UNIT(a), ".mount", &x);
        if (r < 0)
                return r;

        return unit_add_two_dependencies(UNIT(a), UNIT_BEFORE, UNIT_TRIGGERS, x, true, UNIT_DEPENDENCY_IMPLICIT);
}

static int automount_add_mount_dependencies(Automount *a) {
        _cleanup_free_ char *parent = NULL;
        int r;

        assert(a);

        r = path_extract_directory(a->where, &parent);
        if (r < 0)
                return r;

        return unit_add_mounts_for(UNIT(a), parent, UNIT_DEPENDENCY_IMPLICIT, UNIT_MOUNT_REQUIRES);
}

static int automount_add_default_dependencies(Automount *a) {
        int r;

        assert(a);

        if (!UNIT(a)->default_dependencies)
                return 0;

        if (!MANAGER_IS_SYSTEM(UNIT(a)->manager))
                return 0;

        r = unit_add_dependency_by_name(UNIT(a), UNIT_BEFORE, SPECIAL_LOCAL_FS_TARGET, true, UNIT_DEPENDENCY_DEFAULT);
        if (r < 0)
                return r;

        r = unit_add_dependency_by_name(UNIT(a), UNIT_AFTER, SPECIAL_LOCAL_FS_PRE_TARGET, true, UNIT_DEPENDENCY_DEFAULT);
        if (r < 0)
                return r;

        r = unit_add_two_dependencies_by_name(UNIT(a), UNIT_BEFORE, UNIT_CONFLICTS, SPECIAL_UMOUNT_TARGET, true, UNIT_DEPENDENCY_DEFAULT);
        if (r < 0)
                return r;

        return 0;
}

static int automount_verify(Automount *a) {
        static const char *const reserved_options[] = {
                "fd\0",
                "pgrp\0",
                "minproto\0",
                "maxproto\0",
                "direct\0",
                "indirect\0",
        };

        _cleanup_free_ char *e = NULL;
        int r;

        assert(a);
        assert(UNIT(a)->load_state == UNIT_LOADED);

        if (path_equal(a->where, "/"))
                return log_unit_error_errno(UNIT(a), SYNTHETIC_ERRNO(ENOEXEC), "Cannot have an automount unit for the root directory. Refusing.");

        r = unit_name_from_path(a->where, ".automount", &e);
        if (r < 0)
                return log_unit_error_errno(UNIT(a), r, "Failed to generate unit name from path: %m");

        if (!unit_has_name(UNIT(a), e))
                return log_unit_error_errno(UNIT(a), SYNTHETIC_ERRNO(ENOEXEC), "Where= setting doesn't match unit name. Refusing.");

        for (size_t i = 0; i < ELEMENTSOF(reserved_options); i++)
                if (fstab_test_option(a->extra_options, reserved_options[i]))
                        return log_unit_error_errno(
                                UNIT(a),
                                SYNTHETIC_ERRNO(ENOEXEC),
                                "ExtraOptions= setting may not contain reserved option %s.",
                                reserved_options[i]);

        return 0;
}

static int automount_set_where(Automount *a) {
        int r;

        assert(a);

        if (a->where)
                return 0;

        r = unit_name_to_path(UNIT(a)->id, &a->where);
        if (r < 0)
                return r;

        path_simplify(a->where);
        return 1;
}

static int automount_add_extras(Automount *a) {
        int r;

        r = automount_set_where(a);
        if (r < 0)
                return r;

        r = automount_add_trigger_dependencies(a);
        if (r < 0)
                return r;

        r = automount_add_mount_dependencies(a);
        if (r < 0)
                return r;

        return automount_add_default_dependencies(a);
}

static int automount_load(Unit *u) {
        Automount *a = AUTOMOUNT(u);
        int r;

        assert(u);
        assert(u->load_state == UNIT_STUB);

        /* Load a .automount file */
        r = unit_load_fragment_and_dropin(u, true);
        if (r < 0)
                return r;

        if (u->load_state != UNIT_LOADED)
                return 0;

        r = automount_add_extras(a);
        if (r < 0)
                return r;

        return automount_verify(a);
}

static void automount_set_state(Automount *a, AutomountState state) {
        AutomountState old_state;
        assert(a);

        if (a->state != state)
                bus_unit_send_pending_change_signal(UNIT(a), false);

        old_state = a->state;
        a->state = state;

        if (state != AUTOMOUNT_RUNNING)
                automount_stop_expire(a);

        if (!IN_SET(state, AUTOMOUNT_WAITING, AUTOMOUNT_RUNNING))
                unmount_autofs(a);

        if (state != old_state)
                log_unit_debug(UNIT(a), "Changed %s -> %s", automount_state_to_string(old_state), automount_state_to_string(state));

        unit_notify(UNIT(a), state_translation_table[old_state], state_translation_table[state], /* reload_success = */ true);
}

static int automount_coldplug(Unit *u) {
        Automount *a = AUTOMOUNT(u);
        int r;

        assert(a);
        assert(a->state == AUTOMOUNT_DEAD);

        if (a->deserialized_state == a->state)
                return 0;

        if (IN_SET(a->deserialized_state, AUTOMOUNT_WAITING, AUTOMOUNT_RUNNING)) {

                r = automount_set_where(a);
                if (r < 0)
                        return r;

                r = open_dev_autofs(u->manager);
                if (r < 0)
                        return r;

                assert(a->pipe_fd >= 0);

                r = sd_event_add_io(u->manager->event, &a->pipe_event_source, a->pipe_fd, EPOLLIN, automount_dispatch_io, u);
                if (r < 0)
                        return r;

                (void) sd_event_source_set_description(a->pipe_event_source, "automount-io");
                if (a->deserialized_state == AUTOMOUNT_RUNNING) {
                        r = automount_start_expire(a);
                        if (r < 0)
                                log_unit_warning_errno(UNIT(a), r, "Failed to start expiration timer, ignoring: %m");
                }

                automount_set_state(a, a->deserialized_state);
        }

        return 0;
}

static void automount_dump(Unit *u, FILE *f, const char *prefix) {
        Automount *a = AUTOMOUNT(u);

        assert(a);

        fprintf(f,
                "%sAutomount State: %s\n"
                "%sResult: %s\n"
                "%sWhere: %s\n"
                "%sExtraOptions: %s\n"
                "%sDirectoryMode: %04o\n"
                "%sTimeoutIdleUSec: %s\n",
                prefix, automount_state_to_string(a->state),
                prefix, automount_result_to_string(a->result),
                prefix, a->where,
                prefix, a->extra_options,
                prefix, a->directory_mode,
                prefix, FORMAT_TIMESPAN(a->timeout_idle_usec, USEC_PER_SEC));
}

static void automount_enter_dead(Automount *a, AutomountResult f) {
        assert(a);

        if (a->result == AUTOMOUNT_SUCCESS)
                a->result = f;

        unit_log_result(UNIT(a), a->result == AUTOMOUNT_SUCCESS, automount_result_to_string(a->result));
        automount_set_state(a, a->result != AUTOMOUNT_SUCCESS ? AUTOMOUNT_FAILED : AUTOMOUNT_DEAD);
}

static int open_dev_autofs(Manager *m) {
        struct autofs_dev_ioctl param;
        int r;

        assert(m);

        if (m->dev_autofs_fd >= 0)
                return m->dev_autofs_fd;

        (void) label_fix("/dev/autofs", 0);

        m->dev_autofs_fd = open("/dev/autofs", O_CLOEXEC|O_RDONLY);
        if (m->dev_autofs_fd < 0)
                return log_error_errno(errno, "Failed to open /dev/autofs: %m");

        init_autofs_dev_ioctl(&param);
        r = RET_NERRNO(ioctl(m->dev_autofs_fd, AUTOFS_DEV_IOCTL_VERSION, &param));
        if (r < 0) {
                m->dev_autofs_fd = safe_close(m->dev_autofs_fd);
                return log_error_errno(r, "Failed to issue AUTOFS_DEV_IOCTL_VERSION ioctl: %m");
        }

        log_debug("Autofs kernel version %u.%u", param.ver_major, param.ver_minor);

        return m->dev_autofs_fd;
}

static int open_ioctl_fd(int dev_autofs_fd, const char *where, dev_t devid) {
        struct autofs_dev_ioctl *param;
        size_t l;

        assert(dev_autofs_fd >= 0);
        assert(where);

        l = sizeof(struct autofs_dev_ioctl) + strlen(where) + 1;
        param = alloca_safe(l);

        init_autofs_dev_ioctl(param);
        param->size = l;
        param->ioctlfd = -EBADF;
        param->openmount.devid = devid;
        strcpy(param->path, where);

        if (ioctl(dev_autofs_fd, AUTOFS_DEV_IOCTL_OPENMOUNT, param) < 0)
                return -errno;

        if (param->ioctlfd < 0)
                return -EIO;

        (void) fd_cloexec(param->ioctlfd, true);
        return param->ioctlfd;
}

static int autofs_protocol(int dev_autofs_fd, int ioctl_fd) {
        uint32_t major, minor;
        struct autofs_dev_ioctl param;

        assert(dev_autofs_fd >= 0);
        assert(ioctl_fd >= 0);

        init_autofs_dev_ioctl(&param);
        param.ioctlfd = ioctl_fd;

        if (ioctl(dev_autofs_fd, AUTOFS_DEV_IOCTL_PROTOVER, &param) < 0)
                return -errno;

        major = param.protover.version;

        init_autofs_dev_ioctl(&param);
        param.ioctlfd = ioctl_fd;

        if (ioctl(dev_autofs_fd, AUTOFS_DEV_IOCTL_PROTOSUBVER, &param) < 0)
                return -errno;

        minor = param.protosubver.sub_version;

        log_debug("Autofs protocol version %u.%u", major, minor);
        return 0;
}

static int autofs_set_timeout(int dev_autofs_fd, int ioctl_fd, usec_t usec) {
        struct autofs_dev_ioctl param;

        assert(dev_autofs_fd >= 0);
        assert(ioctl_fd >= 0);

        init_autofs_dev_ioctl(&param);
        param.ioctlfd = ioctl_fd;

        if (usec == USEC_INFINITY)
                param.timeout.timeout = 0;
        else
                /* Convert to seconds, rounding up. */
                param.timeout.timeout = DIV_ROUND_UP(usec, USEC_PER_SEC);

        return RET_NERRNO(ioctl(dev_autofs_fd, AUTOFS_DEV_IOCTL_TIMEOUT, &param));
}

static int autofs_send_ready(int dev_autofs_fd, int ioctl_fd, uint32_t token, int status) {
        struct autofs_dev_ioctl param;

        assert(dev_autofs_fd >= 0);
        assert(ioctl_fd >= 0);

        init_autofs_dev_ioctl(&param);
        param.ioctlfd = ioctl_fd;

        if (status != 0) {
                param.fail.token = token;
                param.fail.status = status;
        } else
                param.ready.token = token;

        return RET_NERRNO(ioctl(dev_autofs_fd, status ? AUTOFS_DEV_IOCTL_FAIL : AUTOFS_DEV_IOCTL_READY, &param));
}

static int automount_send_ready(Automount *a, Set *tokens, int status) {
        _cleanup_close_ int ioctl_fd = -EBADF;
        unsigned token;
        int r;

        assert(a);
        assert(status <= 0);

        if (set_isempty(tokens))
                return 0;

        ioctl_fd = open_ioctl_fd(UNIT(a)->manager->dev_autofs_fd, a->where, a->dev_id);
        if (ioctl_fd < 0)
                return ioctl_fd;

        if (status != 0)
                log_unit_debug_errno(UNIT(a), status, "Sending failure: %m");
        else
                log_unit_debug(UNIT(a), "Sending success.");

        r = 0;

        /* Autofs thankfully does not hand out 0 as a token */
        while ((token = PTR_TO_UINT(set_steal_first(tokens)))) {
                int k;

                /* Autofs fun fact:
                 *
                 * if you pass a positive status code here, kernels
                 * prior to 4.12 will freeze! Yay! */

                k = autofs_send_ready(UNIT(a)->manager->dev_autofs_fd,
                                      ioctl_fd,
                                      token,
                                      status);
                if (k < 0)
                        r = k;
        }

        return r;
}

static void automount_trigger_notify(Unit *u, Unit *other) {
        Automount *a = AUTOMOUNT(u);
        int r;

        assert(a);
        assert(other);

        /* Filter out invocations with bogus state */
        assert(UNIT_IS_LOAD_COMPLETE(other->load_state));
        assert(other->type == UNIT_MOUNT);

        /* Don't propagate state changes from the mount if we are already down */
        if (!IN_SET(a->state, AUTOMOUNT_WAITING, AUTOMOUNT_RUNNING))
                return;

        /* Propagate start limit hit state */
        if (other->start_limit_hit) {
                automount_enter_dead(a, AUTOMOUNT_FAILURE_MOUNT_START_LIMIT_HIT);
                return;
        }

        /* Don't propagate anything if there's still a job queued */
        if (other->job)
                return;

        /* The mount is successfully established */
        if (IN_SET(MOUNT(other)->state, MOUNT_MOUNTED, MOUNT_REMOUNTING)) {
                (void) automount_send_ready(a, a->tokens, 0);

                r = automount_start_expire(a);
                if (r < 0)
                        log_unit_warning_errno(UNIT(a), r, "Failed to start expiration timer, ignoring: %m");

                automount_set_state(a, AUTOMOUNT_RUNNING);
        }

        if (IN_SET(MOUNT(other)->state,
                   MOUNT_MOUNTING, MOUNT_MOUNTING_DONE,
                   MOUNT_MOUNTED, MOUNT_REMOUNTING,
                   MOUNT_REMOUNTING_SIGTERM, MOUNT_REMOUNTING_SIGKILL,
                   MOUNT_UNMOUNTING_SIGTERM, MOUNT_UNMOUNTING_SIGKILL,
                   MOUNT_FAILED))
                (void) automount_send_ready(a, a->expire_tokens, -ENODEV);

        if (MOUNT(other)->state == MOUNT_DEAD)
                (void) automount_send_ready(a, a->expire_tokens, 0);

        /* The mount is in some unhappy state now, let's unfreeze any waiting clients */
        if (IN_SET(MOUNT(other)->state,
                   MOUNT_DEAD, MOUNT_UNMOUNTING,
                   MOUNT_REMOUNTING_SIGTERM, MOUNT_REMOUNTING_SIGKILL,
                   MOUNT_UNMOUNTING_SIGTERM, MOUNT_UNMOUNTING_SIGKILL,
                   MOUNT_FAILED)) {

                (void) automount_send_ready(a, a->tokens, -ENODEV);

                automount_set_state(a, AUTOMOUNT_WAITING);
        }
}

static void automount_enter_waiting(Automount *a) {
        _cleanup_close_pair_ int pipe_fd[2] = EBADF_PAIR;
        _cleanup_close_ int ioctl_fd = -EBADF;
        char name[STRLEN("systemd-") + DECIMAL_STR_MAX(pid_t) + 1];
        _cleanup_free_ char *options = NULL;
        bool mounted = false;
        int r, dev_autofs_fd;
        struct stat st;

        assert(a);
        assert(a->pipe_fd < 0);
        assert(a->where);

        set_clear(a->tokens);

        r = unit_fail_if_noncanonical(UNIT(a), a->where);
        if (r < 0)
                goto fail;

        (void) mkdir_p_label(a->where, a->directory_mode);

        unit_warn_if_dir_nonempty(UNIT(a), a->where);

        dev_autofs_fd = open_dev_autofs(UNIT(a)->manager);
        if (dev_autofs_fd < 0)
                goto fail;

        if (pipe2(pipe_fd, O_CLOEXEC) < 0) {
                log_unit_warning_errno(UNIT(a), errno, "Failed to allocate autofs pipe: %m");
                goto fail;
        }
        r = fd_nonblock(pipe_fd[0], true);
        if (r < 0) {
                log_unit_warning_errno(UNIT(a), r, "Failed to make read side of pipe non-blocking: %m");
                goto fail;
        }

        if (asprintf(
                    &options,
                    "fd=%i,pgrp="PID_FMT",minproto=5,maxproto=5,direct%s%s",
                    pipe_fd[1],
                    getpgrp(),
                    isempty(a->extra_options) ? "" : ",",
                    strempty(a->extra_options)) < 0) {
                log_oom();
                goto fail;
        }

        xsprintf(name, "systemd-"PID_FMT, getpid_cached());
        r = mount_nofollow_verbose(LOG_WARNING, name, a->where, "autofs", 0, options);
        if (r < 0)
                goto fail;

        mounted = true;

        pipe_fd[1] = safe_close(pipe_fd[1]);

        if (stat(a->where, &st) < 0) {
                log_unit_warning_errno(UNIT(a), errno, "Failed to stat new automount point '%s': %m", a->where);
                goto fail;
        }

        ioctl_fd = open_ioctl_fd(dev_autofs_fd, a->where, st.st_dev);
        if (ioctl_fd < 0) {
                log_unit_warning_errno(UNIT(a), ioctl_fd, "Failed to open automount ioctl fd for '%s': %m", a->where);
                goto fail;
        }

        r = autofs_protocol(dev_autofs_fd, ioctl_fd);
        if (r < 0) {
                log_unit_warning_errno(UNIT(a), r, "Failed to validate autofs protocol for '%s': %m", a->where);
                goto fail;
        }

        r = autofs_set_timeout(dev_autofs_fd, ioctl_fd, a->timeout_idle_usec);
        if (r < 0) {
                log_unit_warning_errno(UNIT(a), r, "Failed to set autofs timeout for '%s': %m", a->where);
                goto fail;
        }

        r = sd_event_add_io(UNIT(a)->manager->event, &a->pipe_event_source, pipe_fd[0], EPOLLIN, automount_dispatch_io, a);
        if (r < 0) {
                log_unit_warning_errno(UNIT(a), r, "Failed to allocate IO event source for autofs mount '%s': %m", a->where);
                goto fail;
        }

        (void) sd_event_source_set_description(a->pipe_event_source, "automount-io");

        a->pipe_fd = TAKE_FD(pipe_fd[0]);
        a->dev_id = st.st_dev;

        automount_set_state(a, AUTOMOUNT_WAITING);
        return;

fail:
        if (mounted) {
                r = repeat_unmount(a->where, MNT_DETACH|UMOUNT_NOFOLLOW);
                if (r < 0)
                        log_unit_warning_errno(UNIT(a), r, "Failed to unmount, ignoring: %m");
        }

        automount_enter_dead(a, AUTOMOUNT_FAILURE_RESOURCES);
}

static int asynchronous_expire(int dev_autofs_fd, int ioctl_fd) {
        int r;

        assert(dev_autofs_fd >= 0);
        assert(ioctl_fd >= 0);

        /* Issue AUTOFS_DEV_IOCTL_EXPIRE in subprocess, asynchronously. Note that we don't keep track of the
         * child's PID, we are PID1/autoreaper after all, hence when it dies we'll automatically clean it up
         * anyway. */

        r = safe_fork_full("(sd-expire)",
                           /* stdio_fds= */ NULL,
                           (int[]) { dev_autofs_fd, ioctl_fd },
                           /* n_except_fds= */ 2,
                           FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_REOPEN_LOG,
                           /* pid= */ NULL);
        if (r != 0)
                return r;

        /* Child */
        for (;;) {
                struct autofs_dev_ioctl param;
                init_autofs_dev_ioctl(&param);
                param.ioctlfd = ioctl_fd;

                if (ioctl(dev_autofs_fd, AUTOFS_DEV_IOCTL_EXPIRE, &param) < 0)
                        break;
        }

        if (errno != EAGAIN)
                log_warning_errno(errno, "Failed to expire automount, ignoring: %m");

        _exit(EXIT_SUCCESS);
}

static int automount_dispatch_expire(sd_event_source *source, usec_t usec, void *userdata) {
        _cleanup_close_ int ioctl_fd = -EBADF;
        Automount *a = AUTOMOUNT(userdata);
        int r;

        assert(a);
        assert(source == a->expire_event_source);

        ioctl_fd = open_ioctl_fd(UNIT(a)->manager->dev_autofs_fd, a->where, a->dev_id);
        if (ioctl_fd < 0)
                return log_unit_error_errno(UNIT(a), ioctl_fd, "Couldn't open autofs ioctl fd: %m");

        r = asynchronous_expire(UNIT(a)->manager->dev_autofs_fd, ioctl_fd);
        if (r < 0)
                return log_unit_error_errno(UNIT(a), r, "Failed to start expire job: %m");

        return automount_start_expire(a);
}

static int automount_start_expire(Automount *a) {
        usec_t timeout;
        int r;

        assert(a);

        if (a->timeout_idle_usec == 0)
                return 0;

        timeout = MAX(a->timeout_idle_usec/3, USEC_PER_SEC);

        if (a->expire_event_source) {
                r = sd_event_source_set_time_relative(a->expire_event_source, timeout);
                if (r < 0)
                        return r;

                return sd_event_source_set_enabled(a->expire_event_source, SD_EVENT_ONESHOT);
        }

        r = sd_event_add_time_relative(
                        UNIT(a)->manager->event,
                        &a->expire_event_source,
                        CLOCK_MONOTONIC, timeout, 0,
                        automount_dispatch_expire, a);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(a->expire_event_source, "automount-expire");

        return 0;
}

static void automount_stop_expire(Automount *a) {
        assert(a);

        if (!a->expire_event_source)
                return;

        (void) sd_event_source_set_enabled(a->expire_event_source, SD_EVENT_OFF);
}

static void automount_enter_running(Automount *a) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        Unit *trigger;
        struct stat st;
        int r;

        assert(a);

        /* If the user masked our unit in the meantime, fail */
        if (UNIT(a)->load_state != UNIT_LOADED) {
                log_unit_error(UNIT(a), "Suppressing automount event since unit is no longer loaded.");
                goto fail;
        }

        /* We don't take mount requests anymore if we are supposed to
         * shut down anyway */
        if (unit_stop_pending(UNIT(a))) {
                log_unit_debug(UNIT(a), "Suppressing automount request since unit stop is scheduled.");
                automount_send_ready(a, a->tokens, -EHOSTDOWN);
                automount_send_ready(a, a->expire_tokens, -EHOSTDOWN);
                return;
        }

        (void) mkdir_p_label(a->where, a->directory_mode);

        /* Before we do anything, let's see if somebody is playing games with us? */
        if (lstat(a->where, &st) < 0) {
                log_unit_warning_errno(UNIT(a), errno, "Failed to stat automount point: %m");
                goto fail;
        }

        /* The mount unit may have been explicitly started before we got the
         * autofs request. Ack it to unblock anything waiting on the mount point. */
        if (!S_ISDIR(st.st_mode) || st.st_dev != a->dev_id) {
                log_unit_info(UNIT(a), "Automount point already active?");
                automount_send_ready(a, a->tokens, 0);
                return;
        }

        trigger = UNIT_TRIGGER(UNIT(a));
        if (!trigger) {
                log_unit_error(UNIT(a), "Unit to trigger vanished.");
                goto fail;
        }

        r = manager_add_job(UNIT(a)->manager, JOB_START, trigger, JOB_REPLACE, NULL, &error, NULL);
        if (r < 0) {
                log_unit_warning(UNIT(a), "Failed to queue mount startup job: %s", bus_error_message(&error, r));
                goto fail;
        }

        automount_set_state(a, AUTOMOUNT_RUNNING);
        return;

fail:
        automount_enter_dead(a, AUTOMOUNT_FAILURE_RESOURCES);
}

static int automount_start(Unit *u) {
        Automount *a = AUTOMOUNT(u);
        int r;

        assert(a);
        assert(IN_SET(a->state, AUTOMOUNT_DEAD, AUTOMOUNT_FAILED));

        if (path_is_mount_point(a->where, NULL, 0) > 0)
                return log_unit_error_errno(u, SYNTHETIC_ERRNO(EEXIST), "Path %s is already a mount point, refusing start.", a->where);

        r = unit_test_trigger_loaded(u);
        if (r < 0)
                return r;

        r = unit_acquire_invocation_id(u);
        if (r < 0)
                return r;

        a->result = AUTOMOUNT_SUCCESS;
        automount_enter_waiting(a);
        return 1;
}

static int automount_stop(Unit *u) {
        Automount *a = AUTOMOUNT(u);

        assert(a);
        assert(IN_SET(a->state, AUTOMOUNT_WAITING, AUTOMOUNT_RUNNING));

        automount_enter_dead(a, AUTOMOUNT_SUCCESS);
        return 1;
}

static int automount_serialize(Unit *u, FILE *f, FDSet *fds) {
        Automount *a = AUTOMOUNT(u);
        void *p;
        int r;

        assert(a);
        assert(f);
        assert(fds);

        (void) serialize_item(f, "state", automount_state_to_string(a->state));
        (void) serialize_item(f, "result", automount_result_to_string(a->result));
        (void) serialize_item_format(f, "dev-id", "%lu", (unsigned long) a->dev_id);

        SET_FOREACH(p, a->tokens)
                (void) serialize_item_format(f, "token", "%u", PTR_TO_UINT(p));
        SET_FOREACH(p, a->expire_tokens)
                (void) serialize_item_format(f, "expire-token", "%u", PTR_TO_UINT(p));

        r = serialize_fd(f, fds, "pipe-fd", a->pipe_fd);
        if (r < 0)
                return r;

        return 0;
}

static int automount_deserialize_item(Unit *u, const char *key, const char *value, FDSet *fds) {
        Automount *a = AUTOMOUNT(u);
        int r;

        assert(a);
        assert(fds);

        if (streq(key, "state")) {
                AutomountState state;

                state = automount_state_from_string(value);
                if (state < 0)
                        log_unit_debug(u, "Failed to parse state value: %s", value);
                else
                        a->deserialized_state = state;
        } else if (streq(key, "result")) {
                AutomountResult f;

                f = automount_result_from_string(value);
                if (f < 0)
                        log_unit_debug(u, "Failed to parse result value: %s", value);
                else if (f != AUTOMOUNT_SUCCESS)
                        a->result = f;

        } else if (streq(key, "dev-id")) {
                unsigned long d;

                if (safe_atolu(value, &d) < 0)
                        log_unit_debug(u, "Failed to parse dev-id value: %s", value);
                else
                        a->dev_id = (dev_t) d;

        } else if (streq(key, "token")) {
                unsigned token;

                if (safe_atou(value, &token) < 0)
                        log_unit_debug(u, "Failed to parse token value: %s", value);
                else {
                        r = set_ensure_put(&a->tokens, NULL, UINT_TO_PTR(token));
                        if (r < 0)
                                log_unit_error_errno(u, r, "Failed to add token to set: %m");
                }
        } else if (streq(key, "expire-token")) {
                unsigned token;

                if (safe_atou(value, &token) < 0)
                        log_unit_debug(u, "Failed to parse token value: %s", value);
                else {
                        r = set_ensure_put(&a->expire_tokens, NULL, UINT_TO_PTR(token));
                        if (r < 0)
                                log_unit_error_errno(u, r, "Failed to add expire token to set: %m");
                }
        } else if (streq(key, "pipe-fd")) {
                safe_close(a->pipe_fd);
                a->pipe_fd = deserialize_fd(fds, value);
        } else
                log_unit_debug(u, "Unknown serialization key: %s", key);

        return 0;
}

static UnitActiveState automount_active_state(Unit *u) {
        assert(u);

        return state_translation_table[AUTOMOUNT(u)->state];
}

static const char *automount_sub_state_to_string(Unit *u) {
        assert(u);

        return automount_state_to_string(AUTOMOUNT(u)->state);
}

static bool automount_may_gc(Unit *u) {
        Unit *t;

        assert(u);

        t = UNIT_TRIGGER(u);
        if (!t)
                return true;

        return UNIT_VTABLE(t)->may_gc(t);
}

static int automount_dispatch_io(sd_event_source *s, int fd, uint32_t events, void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        union autofs_v5_packet_union packet;
        Automount *a = AUTOMOUNT(userdata);
        Unit *trigger;
        int r;

        assert(a);
        assert(fd == a->pipe_fd);

        if (events & (EPOLLHUP|EPOLLERR)) {
                log_unit_error(UNIT(a), "Got hangup/error on autofs pipe from kernel. Likely our automount point has been unmounted by someone or something else?");
                automount_enter_dead(a, AUTOMOUNT_FAILURE_UNMOUNTED);
                return 0;
        }

        if (events != EPOLLIN) {
                log_unit_error(UNIT(a), "Got invalid poll event %"PRIu32" on pipe (fd=%d)", events, fd);
                goto fail;
        }

        r = loop_read_exact(a->pipe_fd, &packet, sizeof(packet), true);
        if (r < 0) {
                log_unit_error_errno(UNIT(a), r, "Invalid read from pipe: %m");
                goto fail;
        }

        switch (packet.hdr.type) {

        case autofs_ptype_missing_direct:

                if (packet.v5_packet.pid > 0) {
                        _cleanup_free_ char *p = NULL;

                        (void) pid_get_comm(packet.v5_packet.pid, &p);
                        log_unit_info(UNIT(a), "Got automount request for %s, triggered by %"PRIu32" (%s)", a->where, packet.v5_packet.pid, strna(p));
                } else
                        log_unit_debug(UNIT(a), "Got direct mount request on %s", a->where);

                r = set_ensure_put(&a->tokens, NULL, UINT_TO_PTR(packet.v5_packet.wait_queue_token));
                if (r < 0) {
                        log_unit_error_errno(UNIT(a), r, "Failed to remember token: %m");
                        goto fail;
                }

                automount_enter_running(a);
                break;

        case autofs_ptype_expire_direct:
                log_unit_debug(UNIT(a), "Got direct umount request on %s", a->where);

                automount_stop_expire(a);

                r = set_ensure_put(&a->expire_tokens, NULL, UINT_TO_PTR(packet.v5_packet.wait_queue_token));
                if (r < 0) {
                        log_unit_error_errno(UNIT(a), r, "Failed to remember token: %m");
                        goto fail;
                }

                trigger = UNIT_TRIGGER(UNIT(a));
                if (!trigger) {
                        log_unit_error(UNIT(a), "Unit to trigger vanished.");
                        goto fail;
                }

                r = manager_add_job(UNIT(a)->manager, JOB_STOP, trigger, JOB_REPLACE, NULL, &error, NULL);
                if (r < 0) {
                        log_unit_warning(UNIT(a), "Failed to queue unmount job: %s", bus_error_message(&error, r));
                        goto fail;
                }
                break;

        default:
                log_unit_error(UNIT(a), "Received unknown automount request %i", packet.hdr.type);
                break;
        }

        return 0;

fail:
        automount_enter_dead(a, AUTOMOUNT_FAILURE_RESOURCES);
        return 0;
}

static void automount_shutdown(Manager *m) {
        assert(m);

        m->dev_autofs_fd = safe_close(m->dev_autofs_fd);
}

static void automount_reset_failed(Unit *u) {
        Automount *a = AUTOMOUNT(u);

        assert(a);

        if (a->state == AUTOMOUNT_FAILED)
                automount_set_state(a, AUTOMOUNT_DEAD);

        a->result = AUTOMOUNT_SUCCESS;
}

static bool automount_supported(void) {
        static int supported = -1;

        if (supported < 0)
                supported = access("/dev/autofs", F_OK) >= 0;

        return supported;
}

static int automount_can_start(Unit *u) {
        Automount *a = AUTOMOUNT(u);
        int r;

        assert(a);

        r = unit_test_start_limit(u);
        if (r < 0) {
                automount_enter_dead(a, AUTOMOUNT_FAILURE_START_LIMIT_HIT);
                return r;
        }

        return 1;
}

static const char* const automount_result_table[_AUTOMOUNT_RESULT_MAX] = {
        [AUTOMOUNT_SUCCESS]                       = "success",
        [AUTOMOUNT_FAILURE_RESOURCES]             = "resources",
        [AUTOMOUNT_FAILURE_START_LIMIT_HIT]       = "start-limit-hit",
        [AUTOMOUNT_FAILURE_MOUNT_START_LIMIT_HIT] = "mount-start-limit-hit",
        [AUTOMOUNT_FAILURE_UNMOUNTED]             = "unmounted",
};

DEFINE_STRING_TABLE_LOOKUP(automount_result, AutomountResult);

const UnitVTable automount_vtable = {
        .object_size = sizeof(Automount),

        .sections =
                "Unit\0"
                "Automount\0"
                "Install\0",
        .private_section = "Automount",

        .can_transient = true,
        .can_fail = true,
        .can_trigger = true,
        .exclude_from_switch_root_serialization = true,

        .init = automount_init,
        .load = automount_load,
        .done = automount_done,

        .coldplug = automount_coldplug,

        .dump = automount_dump,

        .start = automount_start,
        .stop = automount_stop,

        .serialize = automount_serialize,
        .deserialize_item = automount_deserialize_item,

        .active_state = automount_active_state,
        .sub_state_to_string = automount_sub_state_to_string,

        .may_gc = automount_may_gc,

        .trigger_notify = automount_trigger_notify,

        .reset_failed = automount_reset_failed,

        .bus_set_property = bus_automount_set_property,

        .shutdown = automount_shutdown,
        .supported = automount_supported,

        .status_message_formats = {
                .finished_start_job = {
                        [JOB_DONE]       = "Set up automount %s.",
                        [JOB_FAILED]     = "Failed to set up automount %s.",
                },
                .finished_stop_job = {
                        [JOB_DONE]       = "Unset automount %s.",
                        [JOB_FAILED]     = "Failed to unset automount %s.",
                },
        },

        .can_start = automount_can_start,
};
