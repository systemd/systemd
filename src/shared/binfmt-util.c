/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/magic.h>
#include <sys/vfs.h>

#include "binfmt-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "log.h"
#include "stat-util.h"

int binfmt_mounted_and_writable(void) {
        _cleanup_close_ int fd = -EBADF;
        int r;

        fd = RET_NERRNO(open("/proc/sys/fs/binfmt_misc", O_CLOEXEC | O_DIRECTORY | O_PATH));
        if (fd == -ENOENT)
                return false;
        if (fd < 0)
                return fd;

        r = fd_is_fs_type(fd, BINFMTFS_MAGIC);
        if (r <= 0)
                return r;

        r = access_fd(fd, W_OK);
        if (ERRNO_IS_NEG_FS_WRITE_REFUSED(r))
                return false;
        if (r < 0)
                return r;

        return true;
}

int disable_binfmt(void) {
        int r;

        /* Flush out all rules. This is important during shutdown to cover for rules using "F", since those
         * might pin a file and thus block us from unmounting stuff cleanly.
         *
         * We are a bit careful here, since binfmt_misc might still be an autofs which we don't want to
         * trigger. */

        r = binfmt_mounted_and_writable();
        if (r < 0)
                return log_warning_errno(r, "Failed to determine whether binfmt_misc is mounted: %m");
        if (r == 0) {
                log_debug("binfmt_misc is not mounted in read-write mode, not detaching entries.");
                return 0;
        }

        r = write_string_file("/proc/sys/fs/binfmt_misc/status", "-1", WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                return log_warning_errno(r, "Failed to unregister binfmt_misc entries: %m");

        log_debug("Unregistered all remaining binfmt_misc entries.");
        return 0;
}
