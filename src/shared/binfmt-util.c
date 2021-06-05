/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>

#include "binfmt-util.h"
#include "fileio.h"
#include "missing_magic.h"
#include "stat-util.h"

int disable_binfmt(void) {
        int r;

        /* Flush out all rules. This is important during shutdown to cover for rules using "F", since those
         * might pin a file and thus block us from unmounting stuff cleanly.
         *
         * We are a bit careful here, since binfmt_misc might still be an autofs which we don't want to
         * trigger. */

        r = path_is_fs_type("/proc/sys/fs/binfmt_misc", BINFMTFS_MAGIC);
        if (r == 0 || r == -ENOENT) {
                log_debug("binfmt_misc is not mounted, not detaching entries.");
                return 0;
        }
        if (r < 0)
                return log_warning_errno(r, "Failed to determine whether binfmt_misc is mounted: %m");

        r = write_string_file("/proc/sys/fs/binfmt_misc/status", "-1", WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                return log_warning_errno(r, "Failed to unregister binfmt_misc entries: %m");

        log_debug("Unregistered all remaining binfmt_misc entries.");
        return 0;
}
