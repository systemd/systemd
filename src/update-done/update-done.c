/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fileio.h"
#include "main-func.h"
#include "path-util.h"
#include "selinux-util.h"
#include "time-util.h"

static int save_timestamp(const char *dir, struct timespec *ts) {
        _cleanup_free_ char *message = NULL, *path = NULL;
        int r;

        /*
         * We store the timestamp both as mtime of the file and in the file itself,
         * to support filesystems which cannot store nanosecond-precision timestamps.
         */

        path = path_join(dir, ".updated");
        if (!path)
                return log_oom();

        if (asprintf(&message,
                     "# This file was created by systemd-update-done. The timestamp below is the\n"
                     "# modification time of /usr/ for which the most recent updates of %s have\n"
                     "# been applied. See man:systemd-update-done.service(8) for details.\n"
                     "TIMESTAMP_NSEC=" NSEC_FMT "\n",
                     dir,
                     timespec_load_nsec(ts)) < 0)
                return log_oom();

        r = write_string_file_full(AT_FDCWD, path, message, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC|WRITE_STRING_FILE_LABEL, ts, NULL);
        if (r == -EROFS)
                log_debug_errno(r, "Cannot create \"%s\", file system is read-only.", path);
        else if (r < 0)
                return log_error_errno(r, "Failed to write \"%s\": %m", path);
        return 0;
}

static int run(int argc, char *argv[]) {
        struct stat st;
        int r;

        log_setup();

        if (stat("/usr", &st) < 0)
                return log_error_errno(errno, "Failed to stat /usr: %m");

        r = mac_init();
        if (r < 0)
                return r;

        r = 0;
        RET_GATHER(r, save_timestamp("/etc/", &st.st_mtim));
        RET_GATHER(r, save_timestamp("/var/", &st.st_mtim));
        return r;
}

DEFINE_MAIN_FUNCTION(run);
