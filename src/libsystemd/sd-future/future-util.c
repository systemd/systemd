/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-future.h"

#include "fd-util.h"
#include "future-util.h"
#include "pidref.h"

int future_new_child_pidref(sd_event *e, PidRef *pidref, int options, sd_future **ret) {
        int r;

        assert(e);
        assert(ret);

        if (!pidref_is_set(pidref))
                return -ESRCH;

        if (pidref_is_remote(pidref))
                return -EREMOTE;

        if (pidref->fd < 0)
                return sd_future_new_child(e, pidref->pid, options, ret);

        _cleanup_close_ int copy_fd = fcntl(pidref->fd, F_DUPFD_CLOEXEC, 3);
        if (copy_fd < 0)
                return -errno;

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        r = sd_future_new_child_pidfd(e, copy_fd, options, &f);
        if (r < 0)
                return r;

        r = sd_future_set_child_pidfd_own(f, true);
        if (r < 0)
                return r;

        TAKE_FD(copy_fd);

        *ret = TAKE_PTR(f);
        return 0;
}
