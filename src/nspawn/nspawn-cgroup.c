/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mount.h>
#include <unistd.h>

#include "alloc-util.h"
#include "cgroup-setup.h"
#include "chase.h"
#include "fd-util.h"
#include "format-util.h"
#include "log.h"
#include "mount-setup.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "nspawn-cgroup.h"
#include "nsresource.h"
#include "path-util.h"
#include "pidref.h"
#include "string-util.h"
#include "strv.h"

static int chown_cgroup_path(const char *path, uid_t uid_shift) {
        _cleanup_close_ int fd = -EBADF;

        assert(path);

        fd = open(path, O_PATH|O_CLOEXEC|O_DIRECTORY);
        if (fd < 0)
                return -errno;

        FOREACH_STRING(fn,
                       ".",
                       "cgroup.controllers",
                       "cgroup.events",
                       "cgroup.procs",
                       "cgroup.stat",
                       "cgroup.subtree_control",
                       "cgroup.threads",
                       "memory.oom.group",
                       "memory.reclaim")
                if (fchownat(fd, fn, uid_shift, uid_shift, 0) < 0)
                        log_full_errno(errno == ENOENT ? LOG_DEBUG : LOG_WARNING, errno,
                                       "Failed to chown \"%s/%s\", ignoring: %m", path, fn);

        return 0;
}

int create_subcgroup(
                const PidRef *pid,
                bool keep_unit,
                uid_t uid_shift,
                int userns_fd,
                UserNamespaceMode userns_mode) {

        _cleanup_free_ char *cgroup = NULL, *payload = NULL;
        CGroupMask supported;
        int r;

        assert(pidref_is_set(pid));
        assert(pid->pid > 1);
        assert((userns_fd >= 0) == (userns_mode == USER_NAMESPACE_MANAGED));

        /* In the unified hierarchy inner nodes may only contain subgroups, but not processes. Hence, if we running in
         * the unified hierarchy and the container does the same, and we did not create a scope unit for the container
         * move us and the container into two separate subcgroups.
         *
         * Moreover, container payloads such as systemd try to manage the cgroup they run in full (i.e. including
         * its attributes), while the host systemd will only delegate cgroups for children of the cgroup created for a
         * delegation unit, instead of the cgroup itself. This means, if we'd pass on the cgroup allocated from the
         * host systemd directly to the payload, the host and payload systemd might fight for the cgroup
         * attributes. Hence, let's insert an intermediary cgroup to cover that case too. */

        r = cg_mask_supported(&supported);
        if (r < 0)
                return log_error_errno(r, "Failed to determine supported controllers: %m");

        if (keep_unit)
                r = cg_pid_get_path(0, &cgroup);
        else
                r = cg_pidref_get_path(pid, &cgroup);
        if (r < 0)
                return log_error_errno(r, "Failed to get our control group: %m");

        /* If the service manager already placed us in the supervisor cgroup, let's handle that. */
        char *e = endswith(cgroup, "/supervisor");
        if (e)
                *e = 0; /* chop off, we want the main path delegated to us */

        payload = path_join(cgroup, "payload");
        if (!payload)
                return log_oom();

        if (userns_mode != USER_NAMESPACE_MANAGED)
                r = cg_create_and_attach(payload, pid->pid);
        else
                r = cg_create(payload);
        if (r < 0)
                return log_error_errno(r, "Failed to create %s subcgroup: %m", payload);

        if (userns_mode == USER_NAMESPACE_MANAGED) {
                _cleanup_close_ int cgroup_fd = -EBADF;

                cgroup_fd = cg_path_open(payload);
                if (cgroup_fd < 0)
                        return log_error_errno(cgroup_fd, "Failed to open cgroup %s: %m", payload);

                r = cg_fd_attach(cgroup_fd, pid->pid);
                if (r < 0)
                        return log_error_errno(r, "Failed to add process " PID_FMT " to cgroup %s: %m", pid->pid, payload);

                r = nsresource_add_cgroup(
                                /* vl= */ NULL,
                                userns_fd,
                                cgroup_fd);
                if (r < 0)
                        return log_error_errno(r, "Failed to add cgroup %s to userns: %m", payload);
        } else {
                _cleanup_free_ char *fs = NULL;
                r = cg_get_path(payload, /* suffix= */ NULL, &fs);
                if (r < 0)
                        return log_error_errno(r, "Failed to get file system path for container cgroup: %m");

                r = chown_cgroup_path(fs, uid_shift);
                if (r < 0)
                        return log_error_errno(r, "Failed to chown() cgroup %s: %m", fs);
        }

        if (keep_unit) {
                _cleanup_free_ char *supervisor = NULL;
                supervisor = path_join(cgroup, "supervisor");
                if (!supervisor)
                        return log_oom();

                r = cg_create_and_attach(supervisor, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to create %s subcgroup: %m", supervisor);
        }

        /* Try to enable as many controllers as possible for the new payload. */
        (void) cg_enable(supported, supported, cgroup, NULL);
        return 0;
}

int mount_cgroups(const char *dest, bool accept_existing) {
        _cleanup_free_ char *p = NULL;
        _cleanup_close_ int fd = -EBADF;
        int r;

        r = chase("/sys/fs/cgroup", dest, CHASE_PREFIX_ROOT | CHASE_MKDIR_0755, &p, &fd);
        if (r < 0)
                return log_error_errno(r, "Failed to chase %s/sys/fs/cgroup: %m", strempty(dest));

        r = is_mount_point_at(fd, /* path= */ NULL, /* flags= */ 0);
        if (r < 0)
                return log_error_errno(r, "Failed to determine if %s is mounted already: %m", p);
        if (r > 0) {
                if (!accept_existing)
                        return log_error_errno(SYNTHETIC_ERRNO(EEXIST), "Refusing existing cgroupfs mount: %s", p);

                if (faccessat(fd, "cgroup.procs", F_OK, /* flags= */ 0) >= 0)
                        return 0;
                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to determine if mount point %s contains the unified cgroup hierarchy: %m", p);

                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s is already mounted but not a unified cgroup hierarchy. Refusing.", p);
        }

        return mount_cgroupfs(p);
}

int bind_mount_cgroup_hierarchy(void) {
        _cleanup_free_ char *own_cgroup_path = NULL;
        int r;

        /* NB: This must be called from the inner child, with /sys/fs/cgroup/ being a bind mount in mountns! */

        r = cg_pid_get_path(0, &own_cgroup_path);
        if (r < 0)
                return log_error_errno(r, "Failed to determine our own cgroup path: %m");

        /* If we are living in the top-level, then there's nothing to do... */
        if (path_equal(own_cgroup_path, "/"))
                return 0;

        const char *p = strjoina("/sys/fs/cgroup", own_cgroup_path);

        /* Make our own cgroup a (writable) bind mount */
        r = mount_nofollow_verbose(LOG_ERR, p, p, NULL, MS_BIND, NULL);
        if (r < 0)
                return r;

        /* And then remount the systemd cgroup root read-only */
        return mount_nofollow_verbose(LOG_ERR, NULL, "/sys/fs/cgroup", NULL,
                                      MS_BIND|MS_REMOUNT|MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_RDONLY, NULL);
}
