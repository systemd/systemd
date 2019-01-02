/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "io-util.h"
#include "log.h"
#include "main-func.h"
#include "mkdir.h"
#include "string-util.h"
#include "util.h"

#define POOL_SIZE_MIN 512
#define POOL_SIZE_MAX (10*1024*1024)

static int run(int argc, char *argv[]) {
        _cleanup_close_ int seed_fd = -1, random_fd = -1;
        bool read_seed_file, write_seed_file;
        _cleanup_free_ void* buf = NULL;
        size_t buf_size = 0;
        struct stat st;
        ssize_t k;
        FILE *f;
        int r;

        log_setup_service();

        if (argc != 2)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "This program requires one argument.");

        umask(0022);

        /* Read pool size, if possible */
        f = fopen("/proc/sys/kernel/random/poolsize", "re");
        if (f) {
                if (fscanf(f, "%zu", &buf_size) > 0)
                        /* poolsize is in bits on 2.6, but we want bytes */
                        buf_size /= 8;

                fclose(f);
        }

        if (buf_size < POOL_SIZE_MIN)
                buf_size = POOL_SIZE_MIN;

        r = mkdir_parents_label(RANDOM_SEED, 0755);
        if (r < 0)
                return log_error_errno(r, "Failed to create directory " RANDOM_SEED_DIR ": %m");

        /* When we load the seed we read it and write it to the device and then immediately update the saved seed with
         * new data, to make sure the next boot gets seeded differently. */

        if (streq(argv[1], "load")) {
                int open_rw_error;

                seed_fd = open(RANDOM_SEED, O_RDWR|O_CLOEXEC|O_NOCTTY|O_CREAT, 0600);
                open_rw_error = -errno;
                if (seed_fd < 0) {
                        write_seed_file = false;

                        seed_fd = open(RANDOM_SEED, O_RDONLY|O_CLOEXEC|O_NOCTTY);
                        if (seed_fd < 0) {
                                bool missing = errno == ENOENT;

                                log_full_errno(missing ? LOG_DEBUG : LOG_ERR,
                                               open_rw_error, "Failed to open " RANDOM_SEED " for writing: %m");
                                r = log_full_errno(missing ? LOG_DEBUG : LOG_ERR,
                                                   errno, "Failed to open " RANDOM_SEED " for reading: %m");
                                return missing ? 0 : r;
                        }
                } else
                        write_seed_file = true;

                random_fd = open("/dev/urandom", O_RDWR|O_CLOEXEC|O_NOCTTY, 0600);
                if (random_fd < 0) {
                        write_seed_file = false;

                        random_fd = open("/dev/urandom", O_WRONLY|O_CLOEXEC|O_NOCTTY, 0600);
                        if (random_fd < 0)
                                return log_error_errno(errno, "Failed to open /dev/urandom: %m");
                }

                read_seed_file = true;

        } else if (streq(argv[1], "save")) {

                random_fd = open("/dev/urandom", O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (random_fd < 0)
                        return log_error_errno(errno, "Failed to open /dev/urandom: %m");

                seed_fd = open(RANDOM_SEED, O_WRONLY|O_CLOEXEC|O_NOCTTY|O_CREAT, 0600);
                if (seed_fd < 0)
                        return log_error_errno(errno, "Failed to open " RANDOM_SEED ": %m");

                read_seed_file = false;
                write_seed_file = true;

        } else
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Unknown verb '%s'.", argv[1]);

        if (fstat(seed_fd, &st) < 0)
                return log_error_errno(errno, "Failed to stat() seed file " RANDOM_SEED ": %m");

        /* If the seed file is larger than what we expect, then honour the existing size and save/restore as much as it says */
        if ((uint64_t) st.st_size > buf_size)
                buf_size = MIN(st.st_size, POOL_SIZE_MAX);

        buf = malloc(buf_size);
        if (!buf)
                return log_oom();

        if (read_seed_file) {
                sd_id128_t mid;
                int z;

                k = loop_read(seed_fd, buf, buf_size, false);
                if (k < 0)
                        r = log_error_errno(k, "Failed to read seed from " RANDOM_SEED ": %m");
                else if (k == 0) {
                        r = 0;
                        log_debug("Seed file " RANDOM_SEED " not yet initialized, proceeding.");
                } else {
                        (void) lseek(seed_fd, 0, SEEK_SET);

                        r = loop_write(random_fd, buf, (size_t) k, false);
                        if (r < 0)
                                log_error_errno(r, "Failed to write seed to /dev/urandom: %m");
                }

                /* Let's also write the machine ID into the random seed. Why? As an extra protection against "golden
                 * images" that are put together sloppily, i.e. images which are duplicated on multiple systems but
                 * where the random seed file is not properly reset. Frequently the machine ID is properly reset on
                 * those systems however (simply because it's easier to notice, if it isn't due to address clashes and
                 * so on, while random seed equivalence is generally not noticed easily), hence let's simply write the
                 * machined ID into the random pool too. */
                z = sd_id128_get_machine(&mid);
                if (z < 0)
                        log_debug_errno(z, "Failed to get machine ID, ignoring: %m");
                else {
                        z = loop_write(random_fd, &mid, sizeof(mid), false);
                        if (z < 0)
                                log_debug_errno(z, "Failed to write machine ID to /dev/urandom, ignoring: %m");
                }
        }

        if (write_seed_file) {
                /* This is just a safety measure. Given that we are root and
                 * most likely created the file ourselves the mode and owner
                 * should be correct anyway. */
                (void) fchmod(seed_fd, 0600);
                (void) fchown(seed_fd, 0, 0);

                k = loop_read(random_fd, buf, buf_size, false);
                if (k < 0)
                        return log_error_errno(k, "Failed to read new seed from /dev/urandom: %m");
                if (k == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                               "Got EOF while reading from /dev/urandom.");

                r = loop_write(seed_fd, buf, (size_t) k, false);
                if (r < 0)
                        return log_error_errno(r, "Failed to write new random seed file: %m");
        }

        return r;
}

DEFINE_MAIN_FUNCTION(run);
