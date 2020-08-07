/* SPDX-License-Identifier: LGPL-2.1+ */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>

#include "alloc-util.h"
#include "cgroup-util.h"
#include "clone3.h"
#include "errno-util.h"
#include "fd-util.h"
#include "process-util.h"

static bool fork_into_cgroup_unsupported = false;

pid_t fork_into_cgroup_fd(int cgroup_fd) {
        pid_t pid;
        int r;

        assert(cgroup_fd >= 0);

        if (fork_into_cgroup_unsupported)
                return -ENOSYS;

        r = cg_all_unified();
        if (r < 0)
                return r;
        if (r == 0) {
                fork_into_cgroup_unsupported = true;
                return -ENOSYS;
        }

        pid = clone3(&(struct clone_args) {
                        .flags = CLONE_INTO_CGROUP,
                        .exit_signal = SIGCHLD,
                        .cgroup = cgroup_fd,
                }, sizeof(struct clone_args));
        if (pid < 0) {
                if (ERRNO_IS_NOT_SUPPORTED(errno)) {
                        fork_into_cgroup_unsupported = true;
                        return -ENOSYS;
                }

                return -errno;
        }

        if (pid == 0)
                reset_cached_pid();

        return pid;
}

pid_t fork_into_cgroup_path(const char *path) {
        _cleanup_free_ char *full = NULL;
        _cleanup_close_ int fd = -1;
        int r;

        assert(path);

        if (fork_into_cgroup_unsupported)
                return -ENOSYS;

        r = cg_all_unified();
        if (r < 0)
                return r;
        if (r == 0) {
                fork_into_cgroup_unsupported = true;
                return -ENOSYS;
        }

        r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, path, NULL, &full);
        if (r < 0)
                return r;

        fd = open(full, O_DIRECTORY|O_RDONLY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        return fork_into_cgroup_fd(fd);
}
