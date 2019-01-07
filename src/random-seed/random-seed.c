/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/random.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "io-util.h"
#include "log.h"
#include "main-func.h"
#include "mkdir.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "string-util.h"
#include "util.h"

static enum {
        ACTION_NONE,
        ACTION_LOAD,
        ACTION_SAVE,
} arg_action = ACTION_NONE;
static int entropy_credit;

#define POOL_SIZE_MIN 512
#define POOL_SIZE_MAX (10*1024*1024)

#define XATTR_NAME "trusted.entropy_count"

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-random-seed", "8", &link);
        if (r < 0)
                return log_oom();

        printf("systemd-random-seed [OPTIONS...] load\n"
               "systemd-random-seed save\n\n"
               "Load and save the system random seed at boot and shutdown\n\n"
               "  -h --help                       Show this help\n"
               "     --version                    Show package version\n"
               "\nSee the %s for details.\n"
               , link
        );

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_CREDIT,
        };

        static const struct option options[] = {
                { "help",               no_argument,       NULL, 'h'                    },
                { "version",            no_argument,       NULL, ARG_VERSION            },
                { "entropy-credit",     required_argument, NULL, ARG_CREDIT             },
                {},
        };

        const char *e;
        int c;

        e = getenv("SYSTEMD_ENTROPY_CREDIT");
        if (e) {
                entropy_credit = parse_permille(e);
                if (entropy_credit < 0) {
                        log_warning("Invalid value '%s' of 'SYSTEMD_ENTROPY_CREDIT'. Ignoring.", e);
                        entropy_credit = 0;
                }
        }

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_CREDIT:
                        entropy_credit = parse_permille(optarg);
                        if (entropy_credit < 0) {
                                log_warning("Ignoring invalid argument to --entropy-credit=: %s.",
                                            optarg);
                                entropy_credit = 0;
                        }
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        if (optind + 1 != argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "This program requires one argument.");

        if (streq(argv[optind], "load"))
                arg_action = ACTION_LOAD;
        else if (streq(argv[optind], "save"))
                arg_action = ACTION_SAVE;
        else
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Unknown verb '%s'.", argv[1]);

        return 1;
}

static void write_entropy_xattr(int fd, int entropy_count)
{
        char buf[32];
        int len;

        len = snprintf(buf, sizeof(buf), "%d", entropy_count);
        if (fsetxattr(fd, XATTR_NAME, buf, len+1, 0)) {
                if (errno != ENOTSUP)
                        log_warning_errno(errno, "Failed to set xattr '%s'", XATTR_NAME);
                /* If we fail for any reason, attempt to delete the xattr. We
                 * can't do much if that fails as well. */
                fremovexattr(fd, XATTR_NAME);
        }
}

static int read_entropy_xattr(int fd)
{
        char buf[32];
        int len, entropy_count;

        len = fgetxattr(fd, XATTR_NAME, buf, sizeof(buf));
        if (len < 0 || len > (int) sizeof(buf))
                return 0;
        buf[sizeof(buf) - 1] = '\0';
        if (safe_atoi(buf, &entropy_count) < 0)
                return 0;
        /* Make sure we never end up crediting the same bits twice. */
        if (fremovexattr(fd, XATTR_NAME) < 0)
                return 0;

        return entropy_count;
}

static int run(int argc, char *argv[]) {
        _cleanup_free_ struct rand_pool_info *info = NULL;
        _cleanup_close_ int seed_fd = -1, random_fd = -1;
        bool read_seed_file, write_seed_file;
        size_t buf_size = 0;
        struct stat st;
        ssize_t k;
        FILE *f;
        int r;

        log_setup_service();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

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

        if (arg_action == ACTION_LOAD) {
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

        } else if (arg_action == ACTION_SAVE) {

                random_fd = open("/dev/urandom", O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (random_fd < 0)
                        return log_error_errno(errno, "Failed to open /dev/urandom: %m");

                seed_fd = open(RANDOM_SEED, O_WRONLY|O_CLOEXEC|O_NOCTTY|O_CREAT, 0600);
                if (seed_fd < 0)
                        return log_error_errno(errno, "Failed to open " RANDOM_SEED ": %m");

                read_seed_file = false;
                write_seed_file = true;

        } else
                assert_not_reached("Unexpected action.");

        if (fstat(seed_fd, &st) < 0)
                return log_error_errno(errno, "Failed to stat() seed file " RANDOM_SEED ": %m");

        /* If the seed file is larger than what we expect, then honour the existing size and save/restore as much as it says */
        if ((uint64_t) st.st_size > buf_size)
                buf_size = MIN(st.st_size, POOL_SIZE_MAX);

        info = malloc(sizeof(*info) + buf_size);
        if (!info)
                return log_oom();

        if (read_seed_file) {
                sd_id128_t mid;
                int z;

                k = loop_read(seed_fd, info->buf, buf_size, false);
                if (k < 0)
                        r = log_error_errno(k, "Failed to read seed from " RANDOM_SEED ": %m");
                else if (k == 0) {
                        r = 0;
                        log_debug("Seed file " RANDOM_SEED " not yet initialized, proceeding.");
                } else {
                        int entropy_count;

                        (void) lseek(seed_fd, 0, SEEK_SET);
                        entropy_count = read_entropy_xattr(seed_fd);
                        entropy_count = MIN(entropy_count, 8*k);
                        entropy_count *= entropy_credit;
                        entropy_count /= 1000;

                        info->buf_size = k;
                        info->entropy_count = entropy_count;
                        r = ioctl(random_fd, RNDADDENTROPY, info);
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
                int e1, e2;

                /* This is just a safety measure. Given that we are root and
                 * most likely created the file ourselves the mode and owner
                 * should be correct anyway. */
                (void) fchmod(seed_fd, 0600);
                (void) fchown(seed_fd, 0, 0);

                if (ioctl(random_fd, RNDGETENTCNT, &e1) < 0)
                        e1 = 0;
                k = loop_read(random_fd, info->buf, buf_size, false);
                if (ioctl(random_fd, RNDGETENTCNT, &e2) < 0)
                        e2 = 0;
                if (k < 0)
                        return log_error_errno(k, "Failed to read new seed from /dev/urandom: %m");
                if (k == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                               "Got EOF while reading from /dev/urandom.");

                r = loop_write(seed_fd, info->buf, (size_t) k, false);
                if (r < 0)
                        return log_error_errno(r, "Failed to write new random seed file: %m");
                write_entropy_xattr(seed_fd, MIN(e1, e2));
        }

        return r;
}

DEFINE_MAIN_FUNCTION(run);
