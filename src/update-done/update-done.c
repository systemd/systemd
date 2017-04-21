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
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "io-util.h"
#include "selinux-util.h"
#include "util.h"

#define MESSAGE                                                         \
        "# This file was created by systemd-update-done. Its only \n"   \
        "# purpose is to hold a timestamp of the time this directory\n" \
        "# was updated. See man:systemd-update-done.service(8).\n"

static int apply_timestamp(const char *path, struct timespec *ts) {
        struct timespec twice[2] = {
                *ts,
                *ts
        };
        _cleanup_fclose_ FILE *f = NULL;
        int fd = -1;
        int r;
        _cleanup_(unlink_and_freep) char *tmp = NULL;

        assert(path);
        assert(ts);

        /*
         * We store the timestamp both as mtime of the file and in the file itself,
         * to support filesystems which cannot store nanosecond-precision timestamps.
         * Hence, don't bother updating the file, let's just rewrite it.
         */

        r = mac_selinux_create_file_prepare(path, S_IFREG);
        if (r < 0)
                return log_error_errno(r, "Failed to set SELinux context for %s: %m", path);

        fd = open_tmpfile_linkable(path, O_WRONLY|O_CLOEXEC, &tmp);
        mac_selinux_create_file_clear();

        if (fd < 0) {
                if (errno == EROFS)
                        return log_debug("Can't create temporary timestamp file %s, file system is read-only.", tmp);

                return log_error_errno(errno, "Failed to create/open temporary timestamp file %s: %m", tmp);
        }

        f = fdopen(fd, "we");
        if (!f) {
                safe_close(fd);
                return log_error_errno(errno, "Failed to fdopen() timestamp file %s: %m", tmp);
        }

        (void) fprintf(f,
                       MESSAGE
                       "TIMESTAMP_NSEC=" NSEC_FMT "\n",
                       timespec_load_nsec(ts));

        r = fflush_and_check(f);
        if (r < 0)
                return log_error_errno(r, "Failed to write timestamp file: %m");

        if (futimens(fd, twice) < 0)
                return log_error_errno(errno, "Failed to update timestamp on %s: %m", tmp);

        /* fix permissions */
        (void) fchmod(fd, 0644);
        r = link_tmpfile(fd, tmp, path);
        if (r < 0)
                return log_error_errno(r, "Failed to move \"%s\" to \"%s\": %m", tmp, path);

        tmp = mfree(tmp);

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
