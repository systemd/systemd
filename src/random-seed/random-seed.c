/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <errno.h>
#include <fcntl.h>
#include <linux/random.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "io-util.h"
#include "log.h"
#include "mkdir.h"
#include "string-util.h"
#include "util.h"

#define POOL_SIZE_MIN 512

static ssize_t get_random(int fd, struct rand_pool_info **entropy) {
        ssize_t len;
        int r;

        r = ioctl(fd, RNDGETENTCNT, &((*entropy)->entropy_count));
        if (r < 0)
                return -errno;

        len = loop_read(fd, (*entropy)->buf, (*entropy)->buf_size, false);
        if (len < 0)
                return len;
        (*entropy)->buf_size = len;

        return sizeof(struct rand_pool_info) + len;
}

static ssize_t put_random(int fd, struct rand_pool_info *entropy) {
        int r;

        r = ioctl(fd, RNDADDENTROPY, entropy);
        if (r < 0)
                return -errno;

        return 0;
}

int main(int argc, char *argv[]) {
        _cleanup_close_ int seed_fd = -1, random_fd = -1;
        _cleanup_free_ struct rand_pool_info *entropy = NULL;
        size_t buf_size = 0;
        ssize_t k;
        int r, open_rw_error;
        FILE *f;
        bool refresh_seed_file = true;

        if (argc != 2) {
                log_error("This program requires one argument.");
                return EXIT_FAILURE;
        }

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        /* Read pool size, if possible */
        f = fopen("/proc/sys/kernel/random/poolsize", "re");
        if (f) {
                if (fscanf(f, "%zu", &buf_size) > 0)
                        /* poolsize is in bits on 2.6, but we want bytes */
                        buf_size /= 8;

                fclose(f);
        }

        if (buf_size <= POOL_SIZE_MIN)
                buf_size = POOL_SIZE_MIN;

        entropy = malloc(sizeof(struct rand_pool_info) + buf_size);
        if (!entropy) {
                r = log_oom();
                goto finish;
        }
        entropy->buf_size = buf_size;
        buf_size += sizeof(struct rand_pool_info);

        r = mkdir_parents_label(RANDOM_SEED, 0755);
        if (r < 0) {
                log_error_errno(r, "Failed to create directory " RANDOM_SEED_DIR ": %m");
                goto finish;
        }

        /* When we load the seed we read it and write it to the device
         * and then immediately update the saved seed with new data,
         * to make sure the next boot gets seeded differently. */

        if (streq(argv[1], "load")) {

                seed_fd = open(RANDOM_SEED, O_RDWR|O_CLOEXEC|O_NOCTTY|O_CREAT, 0600);
                open_rw_error = -errno;
                if (seed_fd < 0) {
                        refresh_seed_file = false;

                        seed_fd = open(RANDOM_SEED, O_RDONLY|O_CLOEXEC|O_NOCTTY);
                        if (seed_fd < 0) {
                                bool missing = errno == ENOENT;

                                log_full_errno(missing ? LOG_DEBUG : LOG_ERR,
                                               open_rw_error, "Failed to open " RANDOM_SEED " for writing: %m");
                                r = log_full_errno(missing ? LOG_DEBUG : LOG_ERR,
                                                   errno, "Failed to open " RANDOM_SEED " for reading: %m");
                                if (missing)
                                        r = 0;

                                goto finish;
                        }
                }

                random_fd = open("/dev/urandom", O_RDWR|O_CLOEXEC|O_NOCTTY, 0600);
                if (random_fd < 0) {
                        random_fd = open("/dev/urandom", O_WRONLY|O_CLOEXEC|O_NOCTTY, 0600);
                        if (random_fd < 0) {
                                r = log_error_errno(errno, "Failed to open /dev/urandom: %m");
                                goto finish;
                        }
                }

                k = loop_read(seed_fd, entropy, buf_size, false);
                if (k < 0)
                        r = log_error_errno(k, "Failed to read seed from " RANDOM_SEED ": %m");
                else if (k == 0) {
                        r = 0;
                        log_debug("Seed file " RANDOM_SEED " not yet initialized, proceeding.");
                } else {
                        (void) lseek(seed_fd, 0, SEEK_SET);

                        r = put_random(random_fd, entropy);
                        if (r < 0)
                                log_error_errno(r, "Failed to write seed to /dev/urandom: %m");
                }

        } else if (streq(argv[1], "save")) {

                seed_fd = open(RANDOM_SEED, O_WRONLY|O_CLOEXEC|O_NOCTTY|O_CREAT, 0600);
                if (seed_fd < 0) {
                        r = log_error_errno(errno, "Failed to open " RANDOM_SEED ": %m");
                        goto finish;
                }

                random_fd = open("/dev/urandom", O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (random_fd < 0) {
                        r = log_error_errno(errno, "Failed to open /dev/urandom: %m");
                        goto finish;
                }

        } else {
                log_error("Unknown verb '%s'.", argv[1]);
                r = -EINVAL;
                goto finish;
        }

        if (refresh_seed_file) {

                /* This is just a safety measure. Given that we are root and
                 * most likely created the file ourselves the mode and owner
                 * should be correct anyway. */
                (void) fchmod(seed_fd, 0600);
                (void) fchown(seed_fd, 0, 0);

                k = get_random(random_fd, &entropy);
                if (k < 0) {
                        r = log_error_errno(k, "Failed to read new seed from /dev/urandom: %m");
                        goto finish;
                }
                if (k == 0) {
                        log_error("Got EOF while reading from /dev/urandom.");
                        r = -EIO;
                        goto finish;
                }

                r = loop_write(seed_fd, entropy, k, false);
                if (r < 0)
                        log_error_errno(r, "Failed to write new random seed file: %m");
        }

finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
