/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <fcntl.h>
#include <linux/random.h>
#include <string.h>
#include <sys/ioctl.h>
#if USE_SYS_RANDOM_H
#  include <sys/random.h>
#endif
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "io-util.h"
#include "log.h"
#include "main-func.h"
#include "missing.h"
#include "mkdir.h"
#include "parse-util.h"
#include "random-util.h"
#include "string-util.h"
#include "util.h"
#include "xattr-util.h"

typedef enum CreditEntropy {
        CREDIT_ENTROPY_NO_WAY,
        CREDIT_ENTROPY_YES_PLEASE,
        CREDIT_ENTROPY_YES_FORCED,
} CreditEntropy;

static CreditEntropy may_credit(int seed_fd) {
        _cleanup_free_ char *creditable = NULL;
        const char *e;
        int r;

        assert(seed_fd >= 0);

        e = getenv("SYSTEMD_RANDOM_SEED_CREDIT");
        if (!e) {
                log_debug("$SYSTEMD_RANDOM_SEED_CREDIT is not set, not crediting entropy.");
                return CREDIT_ENTROPY_NO_WAY;
        }
        if (streq(e, "force")) {
                log_debug("$SYSTEMD_RANDOM_SEED_CREDIT is set to 'force', crediting entropy.");
                return CREDIT_ENTROPY_YES_FORCED;
        }

        r = parse_boolean(e);
        if (r <= 0) {
                if (r < 0)
                        log_warning_errno(r, "Failed to parse $SYSTEMD_RANDOM_SEED_CREDIT, not crediting entropy: %m");
                else
                        log_debug("Crediting entropy is turned off via $SYSTEMD_RANDOM_SEED_CREDIT, not crediting entropy.");

                return CREDIT_ENTROPY_NO_WAY;
        }

        /* Determine if the file is marked as creditable */
        r = fgetxattr_malloc(seed_fd, "user.random-seed-creditable", &creditable);
        if (r < 0) {
                if (IN_SET(r, -ENODATA, -ENOSYS, -EOPNOTSUPP))
                        log_debug_errno(r, "Seed file is not marked as creditable, not crediting.");
                else
                        log_warning_errno(r, "Failed to read extended attribute, ignoring: %m");

                return CREDIT_ENTROPY_NO_WAY;
        }

        r = parse_boolean(creditable);
        if (r <= 0) {
                if (r < 0)
                        log_warning_errno(r, "Failed to parse user.random-seed-creditable extended attribute, ignoring: %s", creditable);
                else
                        log_debug("Seed file is marked as not creditable, not crediting.");

                return CREDIT_ENTROPY_NO_WAY;
        }

        /* Don't credit the random seed if we are in first-boot mode, because we are supposed to start from
         * scratch. This is a safety precaution for cases where we people ship "golden" images with empty
         * /etc but populated /var that contains a random seed. */
        if (access("/run/systemd/first-boot", F_OK) < 0) {

                if (errno != ENOENT) {
                        log_warning_errno(errno, "Failed to check whether we are in first-boot mode, not crediting entropy: %m");
                        return CREDIT_ENTROPY_NO_WAY;
                }

                /* If ENOENT all is good, we are not in first-boot mode. */
        } else {
                log_debug("Not crediting entropy, since booted in first-boot mode.");
                return CREDIT_ENTROPY_NO_WAY;
        }

        return CREDIT_ENTROPY_YES_PLEASE;
}

static int run(int argc, char *argv[]) {
        _cleanup_close_ int seed_fd = -1, random_fd = -1;
        bool read_seed_file, write_seed_file, synchronous;
        _cleanup_free_ void* buf = NULL;
        size_t buf_size;
        struct stat st;
        ssize_t k;
        int r;

        log_setup_service();

        if (argc != 2)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "This program requires one argument.");

        umask(0022);

        buf_size = random_pool_size();

        r = mkdir_parents(RANDOM_SEED, 0755);
        if (r < 0)
                return log_error_errno(r, "Failed to create directory " RANDOM_SEED_DIR ": %m");

        /* When we load the seed we read it and write it to the device and then immediately update the saved seed with
         * new data, to make sure the next boot gets seeded differently. */

        if (streq(argv[1], "load")) {

                seed_fd = open(RANDOM_SEED, O_RDWR|O_CLOEXEC|O_NOCTTY|O_CREAT, 0600);
                if (seed_fd < 0) {
                        int open_rw_error = -errno;

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
                if (random_fd < 0)
                        return log_error_errno(errno, "Failed to open /dev/urandom: %m");

                read_seed_file = true;
                synchronous = true; /* make this invocation a synchronous barrier for random pool initialization */

        } else if (streq(argv[1], "save")) {

                random_fd = open("/dev/urandom", O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (random_fd < 0)
                        return log_error_errno(errno, "Failed to open /dev/urandom: %m");

                seed_fd = open(RANDOM_SEED, O_WRONLY|O_CLOEXEC|O_NOCTTY|O_CREAT, 0600);
                if (seed_fd < 0)
                        return log_error_errno(errno, "Failed to open " RANDOM_SEED ": %m");

                read_seed_file = false;
                write_seed_file = true;
                synchronous = false;
        } else
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Unknown verb '%s'.", argv[1]);

        if (fstat(seed_fd, &st) < 0)
                return log_error_errno(errno, "Failed to stat() seed file " RANDOM_SEED ": %m");

        /* If the seed file is larger than what we expect, then honour the existing size and save/restore as much as it says */
        if ((uint64_t) st.st_size > buf_size)
                buf_size = MIN(st.st_size, RANDOM_POOL_SIZE_MAX);

        buf = malloc(buf_size);
        if (!buf)
                return log_oom();

        if (read_seed_file) {
                sd_id128_t mid;

                /* First, let's write the machine ID into /dev/urandom, not crediting entropy. Why? As an
                 * extra protection against "golden images" that are put together sloppily, i.e. images which
                 * are duplicated on multiple systems but where the random seed file is not properly
                 * reset. Frequently the machine ID is properly reset on those systems however (simply
                 * because it's easier to notice, if it isn't due to address clashes and so on, while random
                 * seed equivalence is generally not noticed easily), hence let's simply write the machined
                 * ID into the random pool too. */
                r = sd_id128_get_machine(&mid);
                if (r < 0)
                        log_debug_errno(r, "Failed to get machine ID, ignoring: %m");
                else {
                        r = loop_write(random_fd, &mid, sizeof(mid), false);
                        if (r < 0)
                                log_debug_errno(r, "Failed to write machine ID to /dev/urandom, ignoring: %m");
                }

                k = loop_read(seed_fd, buf, buf_size, false);
                if (k < 0)
                        log_error_errno(k, "Failed to read seed from " RANDOM_SEED ": %m");
                else if (k == 0)
                        log_debug("Seed file " RANDOM_SEED " not yet initialized, proceeding.");
                else {
                        CreditEntropy lets_credit;

                        (void) lseek(seed_fd, 0, SEEK_SET);

                        lets_credit = may_credit(seed_fd);

                        /* Before we credit or use the entropy, let's make sure to securely drop the
                         * creditable xattr from the file, so that we never credit the same random seed
                         * again. Note that further down we'll write a new seed again, and likely mark it as
                         * credible again, hence this is just paranoia to close the short time window between
                         * the time we upload the random seed into the kernel and download the new one from
                         * it. */

                        if (fremovexattr(seed_fd, "user.random-seed-creditable") < 0) {
                                if (!IN_SET(errno, ENODATA, ENOSYS, EOPNOTSUPP))
                                        log_warning_errno(errno, "Failed to remove extended attribute, ignoring: %m");

                                /* Otherwise, there was no creditable flag set, which is OK. */
                        } else {
                                r = fsync_full(seed_fd);
                                if (r < 0) {
                                        log_warning_errno(r, "Failed to synchronize seed to disk, not crediting entropy: %m");

                                        if (lets_credit == CREDIT_ENTROPY_YES_PLEASE)
                                                lets_credit = CREDIT_ENTROPY_NO_WAY;
                                }
                        }

                        if (IN_SET(lets_credit, CREDIT_ENTROPY_YES_PLEASE, CREDIT_ENTROPY_YES_FORCED)) {
                                _cleanup_free_ struct rand_pool_info *info = NULL;

                                info = malloc(offsetof(struct rand_pool_info, buf) + k);
                                if (!info)
                                        return log_oom();

                                info->entropy_count = k * 8;
                                info->buf_size = k;
                                memcpy(info->buf, buf, k);

                                if (ioctl(random_fd, RNDADDENTROPY, info) < 0)
                                        return log_warning_errno(errno, "Failed to credit entropy, ignoring: %m");
                        } else {
                                r = loop_write(random_fd, buf, (size_t) k, false);
                                if (r < 0)
                                        log_error_errno(r, "Failed to write seed to /dev/urandom: %m");
                        }
                }
        }

        if (write_seed_file) {
                bool getrandom_worked = false;

                /* This is just a safety measure. Given that we are root and most likely created the file
                 * ourselves the mode and owner should be correct anyway. */
                r = fchmod_and_chown(seed_fd, 0600, 0, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to adjust seed file ownership and access mode.");

                /* Let's make this whole job asynchronous, i.e. let's make ourselves a barrier for
                 * proper initialization of the random pool. */
                k = getrandom(buf, buf_size, GRND_NONBLOCK);
                if (k < 0 && errno == EAGAIN && synchronous) {
                        log_notice("Kernel entropy pool is not initialized yet, waiting until it is.");
                        k = getrandom(buf, buf_size, 0); /* retry synchronously */
                }
                if (k < 0)
                        log_debug_errno(errno, "Failed to read random data with getrandom(), falling back to /dev/urandom: %m");
                else if ((size_t) k < buf_size)
                        log_debug("Short read from getrandom(), falling back to /dev/urandom: %m");
                else
                        getrandom_worked = true;

                if (!getrandom_worked) {
                        /* Retry with classic /dev/urandom */
                        k = loop_read(random_fd, buf, buf_size, false);
                        if (k < 0)
                                return log_error_errno(k, "Failed to read new seed from /dev/urandom: %m");
                        if (k == 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                                       "Got EOF while reading from /dev/urandom.");
                }

                r = loop_write(seed_fd, buf, (size_t) k, false);
                if (r < 0)
                        return log_error_errno(r, "Failed to write new random seed file: %m");

                if (ftruncate(seed_fd, k) < 0)
                        return log_error_errno(r, "Failed to truncate random seed file: %m");

                r = fsync_full(seed_fd);
                if (r < 0)
                        return log_error_errno(r, "Failed to synchronize seed file: %m");

                /* If we got this random seed data from getrandom() the data is suitable for crediting
                 * entropy later on. Let's keep that in mind by setting an extended attribute. on the file */
                if (getrandom_worked)
                        if (fsetxattr(seed_fd, "user.random-seed-creditable", "1", 1, 0) < 0)
                                log_full_errno(IN_SET(errno, ENOSYS, EOPNOTSUPP) ? LOG_DEBUG : LOG_WARNING, errno,
                                               "Failed to mark seed file as creditable, ignoring: %m");
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
