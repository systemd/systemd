/* SPDX-License-Identifier: LGPL-2.1+ */

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fileio-label.h"
#include "selinux-util.h"
#include "time-util.h"

#define MESSAGE                                                         \
        "# This file was created by systemd-update-done. Its only \n"   \
        "# purpose is to hold a timestamp of the time this directory\n" \
        "# was updated. See man:systemd-update-done.service(8).\n"

static int apply_timestamp(const char *path, struct timespec *ts) {
        _cleanup_free_ char *message = NULL;
        int r;

        /*
         * We store the timestamp both as mtime of the file and in the file itself,
         * to support filesystems which cannot store nanosecond-precision timestamps.
         */

        if (asprintf(&message,
                     MESSAGE
                     "TIMESTAMP_NSEC=" NSEC_FMT "\n",
                     timespec_load_nsec(ts)) < 0)
                return log_oom();

        r = write_string_file_atomic_label_ts(path, message, ts);
        if (r == -EROFS)
                return log_debug("Cannot create \"%s\", file system is read-only.", path);
        if (r < 0)
                return log_error_errno(r, "Failed to write \"%s\": %m", path);
        return 0;
}

int main(int argc, char *argv[]) {
        struct stat st;
        int r, q = 0;

        log_setup_service();

        if (stat("/usr", &st) < 0) {
                log_error_errno(errno, "Failed to stat /usr: %m");
                return EXIT_FAILURE;
        }

        r = mac_selinux_init();
        if (r < 0) {
                log_error_errno(r, "SELinux setup failed: %m");
                return EXIT_FAILURE;
        }

        r = apply_timestamp("/etc/.updated", &st.st_mtim);
        q = apply_timestamp("/var/.updated", &st.st_mtim);

        return r < 0 || q < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
