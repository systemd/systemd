/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>

#include "log.h"
#include "util.h"
#include "mkdir.h"

#define POOL_SIZE_MIN 512

int main(int argc, char *argv[]) {
        _cleanup_close_ int seed_fd = -1, random_fd = -1;
        _cleanup_free_ void* buf = NULL;
        size_t buf_size = 0;
        ssize_t k;
        int r;
        FILE *f;

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
                if (fscanf(f, "%zu", &buf_size) > 0) {
                        /* poolsize is in bits on 2.6, but we want bytes */
                        buf_size /= 8;
                }

                fclose(f);
        }

        if (buf_size <= POOL_SIZE_MIN)
                buf_size = POOL_SIZE_MIN;

        buf = malloc(buf_size);
        if (!buf) {
                r = log_oom();
                goto finish;
        }

        r = mkdir_parents_label(RANDOM_SEED, 0755);
        if (r < 0) {
                log_error("Failed to create directory " RANDOM_SEED_DIR ": %s", strerror(-r));
                goto finish;
        }

        /* When we load the seed we read it and write it to the device
         * and then immediately update the saved seed with new data,
         * to make sure the next boot gets seeded differently. */

        if (streq(argv[1], "load")) {

                seed_fd = open(RANDOM_SEED, O_RDWR|O_CLOEXEC|O_NOCTTY|O_CREAT, 0600);
                if (seed_fd < 0) {
                        seed_fd = open(RANDOM_SEED, O_RDONLY|O_CLOEXEC|O_NOCTTY);
                        if (seed_fd < 0) {
                                log_error("Failed to open " RANDOM_SEED ": %m");
                                r = -errno;
                                goto finish;
                        }
                }

                random_fd = open("/dev/urandom", O_RDWR|O_CLOEXEC|O_NOCTTY, 0600);
                if (random_fd < 0) {
                        random_fd = open("/dev/urandom", O_WRONLY|O_CLOEXEC|O_NOCTTY, 0600);
                        if (random_fd < 0) {
                                log_error("Failed to open /dev/urandom: %m");
                                r = -errno;
                                goto finish;
                        }
                }

                k = loop_read(seed_fd, buf, buf_size, false);
                if (k <= 0) {

                        if (r != 0)
                                log_error("Failed to read seed from " RANDOM_SEED ": %m");

                        r = k == 0 ? -EIO : (int) k;

                } else {
                        lseek(seed_fd, 0, SEEK_SET);

                        k = loop_write(random_fd, buf, (size_t) k, false);
                        if (k <= 0) {
                                log_error("Failed to write seed to /dev/urandom: %s", r < 0 ? strerror(-r) : "short write");

                                r = k == 0 ? -EIO : (int) k;
                        }
                }

        } else if (streq(argv[1], "save")) {

                seed_fd = open(RANDOM_SEED, O_WRONLY|O_CLOEXEC|O_NOCTTY|O_CREAT, 0600);
                if (seed_fd < 0) {
                        log_error("Failed to open " RANDOM_SEED ": %m");
                        r = -errno;
                        goto finish;
                }

                random_fd = open("/dev/urandom", O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (random_fd < 0) {
                        log_error("Failed to open /dev/urandom: %m");
                        r = -errno;
                        goto finish;
                }

        } else {
                log_error("Unknown verb %s.", argv[1]);
                r = -EINVAL;
                goto finish;
        }

        /* This is just a safety measure. Given that we are root and
         * most likely created the file ourselves the mode and owner
         * should be correct anyway. */
        fchmod(seed_fd, 0600);
        fchown(seed_fd, 0, 0);

        k = loop_read(random_fd, buf, buf_size, false);
        if (k <= 0) {
                log_error("Failed to read new seed from /dev/urandom: %s", r < 0 ? strerror(-r) : "EOF");
                r = k == 0 ? -EIO : (int) k;
        } else {
                r = loop_write(seed_fd, buf, (size_t) k, false);
                if (r <= 0) {
                        log_error("Failed to write new random seed file: %s", r < 0 ? strerror(-r) : "short write");
                        r = r == 0 ? -EIO : r;
                }
        }

finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
