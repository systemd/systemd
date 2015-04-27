/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include "util.h"
#include "selinux-util.h"

#define MESSAGE                                                         \
        "This file was created by systemd-update-done. Its only \n"     \
        "purpose is to hold a timestamp of the time this directory\n"   \
        "was updated. See systemd-update-done.service(8).\n"

static int apply_timestamp(const char *path, struct timespec *ts) {
        struct timespec twice[2] = {
                *ts,
                *ts
        };
        struct stat st;

        assert(path);
        assert(ts);

        if (stat(path, &st) >= 0) {
                /* Is the timestamp file already newer than the OS? If
                 * so, there's nothing to do. We ignore the nanosecond
                 * component of the timestamp, since some file systems
                 * do not support any better accuracy than 1s and we
                 * have no way to identify the accuracy
                 * available. Most notably ext4 on small disks (where
                 * 128 byte inodes are used) does not support better
                 * accuracy than 1s. */
                if (st.st_mtim.tv_sec > ts->tv_sec)
                        return 0;

                /* It is older? Then let's update it */
                if (utimensat(AT_FDCWD, path, twice, AT_SYMLINK_NOFOLLOW) < 0) {

                        if (errno == EROFS)
                                return log_debug("Can't update timestamp file %s, file system is read-only.", path);

                        return log_error_errno(errno, "Failed to update timestamp on %s: %m", path);
                }

        } else if (errno == ENOENT) {
                _cleanup_close_ int fd = -1;
                int r;

                /* The timestamp file doesn't exist yet? Then let's create it. */

                r = mac_selinux_create_file_prepare(path, S_IFREG);
                if (r < 0)
                        return log_error_errno(r, "Failed to set SELinux context for %s: %m", path);

                fd = open(path, O_CREAT|O_EXCL|O_WRONLY|O_TRUNC|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW, 0644);
                mac_selinux_create_file_clear();

                if (fd < 0) {
                        if (errno == EROFS)
                                return log_debug("Can't create timestamp file %s, file system is read-only.", path);

                        return log_error_errno(errno, "Failed to create timestamp file %s: %m", path);
                }

                (void) loop_write(fd, MESSAGE, strlen(MESSAGE), false);

                if (futimens(fd, twice) < 0)
                        return log_error_errno(errno, "Failed to update timestamp on %s: %m", path);
        } else
                log_error_errno(errno, "Failed to stat() timestamp file %s: %m", path);

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

        r = mac_selinux_init(NULL);
        if (r < 0) {
                log_error_errno(r, "SELinux setup failed: %m");
                goto finish;
        }

        r = apply_timestamp("/etc/.updated", &st.st_mtim);
        q = apply_timestamp("/var/.updated", &st.st_mtim);

finish:
        return r < 0 || q < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
