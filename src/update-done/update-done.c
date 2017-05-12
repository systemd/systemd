/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "alloc-util.h"
#include "fileio-label.h"
#include "selinux-util.h"
#include "util.h"

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

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        if (stat("/usr", &st) < 0) {
                log_error_errno(errno, "Failed to stat /usr: %m");
                return EXIT_FAILURE;
        }

        r = mac_selinux_init();
        if (r < 0) {
                log_error_errno(r, "SELinux setup failed: %m");
                goto finish;
        }

        r = apply_timestamp("/etc/.updated", &st.st_mtim);
        q = apply_timestamp("/var/.updated", &st.st_mtim);

finish:
        return r < 0 || q < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
