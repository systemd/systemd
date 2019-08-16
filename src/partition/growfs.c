/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/btrfs.h>
#include <linux/magic.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>

#include "blockdev-util.h"
#include "crypt-util.h"
#include "device-nodes.h"
#include "dissect-image.h"
#include "escape.h"
#include "fd-util.h"
#include "format-util.h"
#include "log.h"
#include "missing.h"
#include "mountpoint-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "stat-util.h"
#include "strv.h"
#include "util.h"

static const char *arg_target = NULL;
static bool arg_dry_run = false;

static int resize_ext4(const char *path, int mountfd, int devfd, uint64_t numblocks, uint64_t blocksize) {
        assert((uint64_t) (int) blocksize == blocksize);

        if (arg_dry_run)
                return 0;

        if (ioctl(mountfd, EXT4_IOC_RESIZE_FS, &numblocks) != 0)
                return log_error_errno(errno, "Failed to resize \"%s\" to %"PRIu64" blocks (ext4): %m",
                                       path, numblocks);

        return 0;
}

static int resize_btrfs(const char *path, int mountfd, int devfd, uint64_t numblocks, uint64_t blocksize) {
        struct btrfs_ioctl_vol_args args = {};
        int r;

        assert((uint64_t) (int) blocksize == blocksize);

        /* https://bugzilla.kernel.org/show_bug.cgi?id=118111 */
        if (numblocks * blocksize < 256*1024*1024) {
                log_warning("%s: resizing of btrfs volumes smaller than 256M is not supported", path);
                return -EOPNOTSUPP;
        }

        r = snprintf(args.name, sizeof(args.name), "%"PRIu64, numblocks * blocksize);
        /* The buffer is large enough for any number to fit... */
        assert((size_t) r < sizeof(args.name));

        if (arg_dry_run)
                return 0;

        if (ioctl(mountfd, BTRFS_IOC_RESIZE, &args) != 0)
                return log_error_errno(errno, "Failed to resize \"%s\" to %"PRIu64" blocks (btrfs): %m",
                                       path, numblocks);

        return 0;
}

#if HAVE_LIBCRYPTSETUP
static int resize_crypt_luks_device(dev_t devno, const char *fstype, dev_t main_devno) {
        _cleanup_free_ char *devpath = NULL, *main_devpath = NULL;
        _cleanup_(crypt_freep) struct crypt_device *cd = NULL;
        _cleanup_close_ int main_devfd = -1;
        uint64_t size;
        int r;

        r = device_path_make_major_minor(S_IFBLK, main_devno, &main_devpath);
        if (r < 0)
                return log_error_errno(r, "Failed to format device major/minor path: %m");

        main_devfd = open(main_devpath, O_RDONLY|O_CLOEXEC);
        if (main_devfd < 0)
                return log_error_errno(errno, "Failed to open \"%s\": %m", main_devpath);

        if (ioctl(main_devfd, BLKGETSIZE64, &size) != 0)
                return log_error_errno(errno, "Failed to query size of \"%s\" (before resize): %m",
                                       main_devpath);

        log_debug("%s is %"PRIu64" bytes", main_devpath, size);
        r = device_path_make_major_minor(S_IFBLK, devno, &devpath);
        if (r < 0)
                return log_error_errno(r, "Failed to format major/minor path: %m");

        r = crypt_init(&cd, devpath);
        if (r < 0)
                return log_error_errno(r, "crypt_init(\"%s\") failed: %m", devpath);

        crypt_set_log_callback(cd, cryptsetup_log_glue, NULL);

        r = crypt_load(cd, CRYPT_LUKS, NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to load LUKS metadata for %s: %m", devpath);

        if (arg_dry_run)
                return 0;

        r = crypt_resize(cd, main_devpath, 0);
        if (r < 0)
                return log_error_errno(r, "crypt_resize() of %s failed: %m", devpath);

        if (ioctl(main_devfd, BLKGETSIZE64, &size) != 0)
                log_warning_errno(errno, "Failed to query size of \"%s\" (after resize): %m",
                                  devpath);
        else
                log_debug("%s is now %"PRIu64" bytes", main_devpath, size);

        return 1;
}
#endif

static int maybe_resize_slave_device(const char *mountpath, dev_t main_devno) {
        _cleanup_free_ char *fstype = NULL, *devpath = NULL;
        dev_t devno;
        int r;

#if HAVE_LIBCRYPTSETUP
        crypt_set_log_callback(NULL, cryptsetup_log_glue, NULL);
        if (DEBUG_LOGGING)
                crypt_set_debug_level(CRYPT_DEBUG_ALL);
#endif

        r = get_block_device_harder(mountpath, &devno);
        if (r < 0)
                return log_error_errno(r, "Failed to determine underlying block device of \"%s\": %m",
                                       mountpath);

        log_debug("Underlying device %d:%d, main dev %d:%d, %s",
                  major(devno), minor(devno),
                  major(main_devno), minor(main_devno),
                  devno == main_devno ? "same" : "different");
        if (devno == main_devno)
                return 0;

        r = device_path_make_major_minor(S_IFBLK, devno, &devpath);
        if (r < 0)
                return log_error_errno(r, "Failed to format device major/minor path: %m");

        r = probe_filesystem(devpath, &fstype);
        if (r == -EUCLEAN)
                return log_warning_errno(r, "Cannot reliably determine probe \"%s\", refusing to proceed.", devpath);
        if (r < 0)
                return log_warning_errno(r, "Failed to probe \"%s\": %m", devpath);

#if HAVE_LIBCRYPTSETUP
        if (streq_ptr(fstype, "crypto_LUKS"))
                return resize_crypt_luks_device(devno, fstype, main_devno);
#endif

        log_debug("Don't know how to resize %s of type %s, ignoring", devpath, strnull(fstype));
        return 0;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-growfs@.service", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] /path/to/mountpoint\n\n"
               "Grow filesystem or encrypted payload to device size.\n\n"
               "Options:\n"
               "  -h --help          Show this help and exit\n"
               "     --version       Print version string and exit\n"
               "  -n --dry-run       Just print what would be done\n"
               "\nSee the %s for details.\n"
               , program_invocation_short_name
               , link
        );

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
        };

        int c;

        static const struct option options[] = {
                { "help",         no_argument,       NULL, 'h'           },
                { "version" ,     no_argument,       NULL, ARG_VERSION   },
                { "dry-run",      no_argument,       NULL, 'n'           },
                {}
        };

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hn", options, NULL)) >= 0)
                switch(c) {
                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case 'n':
                        arg_dry_run = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        if (optind + 1 != argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s excepts exactly one argument (the mount point).",
                                       program_invocation_short_name);

        arg_target = argv[optind];

        return 1;
}

int main(int argc, char *argv[]) {
        _cleanup_close_ int mountfd = -1, devfd = -1;
        _cleanup_free_ char *devpath = NULL;
        uint64_t size, numblocks;
        char fb[FORMAT_BYTES_MAX];
        struct statfs sfs;
        dev_t devno;
        int blocksize;
        int r;

        log_setup_service();

        r = parse_argv(argc, argv);
        if (r < 0)
                return EXIT_FAILURE;
        if (r == 0)
                return EXIT_SUCCESS;

        r = path_is_mount_point(arg_target, NULL, 0);
        if (r < 0) {
                log_error_errno(r, "Failed to check if \"%s\" is a mount point: %m", arg_target);
                return EXIT_FAILURE;
        }
        if (r == 0) {
                log_error_errno(r, "\"%s\" is not a mount point: %m", arg_target);
                return EXIT_FAILURE;
        }

        r = get_block_device(arg_target, &devno);
        if (r < 0) {
                log_error_errno(r, "Failed to determine block device of \"%s\": %m", arg_target);
                return EXIT_FAILURE;
        }

        r = maybe_resize_slave_device(arg_target, devno);
        if (r < 0)
                return EXIT_FAILURE;

        mountfd = open(arg_target, O_RDONLY|O_CLOEXEC);
        if (mountfd < 0) {
                log_error_errno(errno, "Failed to open \"%s\": %m", arg_target);
                return EXIT_FAILURE;
        }

        r = device_path_make_major_minor(S_IFBLK, devno, &devpath);
        if (r < 0) {
                log_error_errno(r, "Failed to format device major/minor path: %m");
                return EXIT_FAILURE;
        }

        devfd = open(devpath, O_RDONLY|O_CLOEXEC);
        if (devfd < 0) {
                log_error_errno(errno, "Failed to open \"%s\": %m", devpath);
                return EXIT_FAILURE;
        }

        if (ioctl(devfd, BLKBSZGET, &blocksize) != 0) {
                log_error_errno(errno, "Failed to query block size of \"%s\": %m", devpath);
                return EXIT_FAILURE;
        }

        if (ioctl(devfd, BLKGETSIZE64, &size) != 0) {
                log_error_errno(errno, "Failed to query size of \"%s\": %m", devpath);
                return EXIT_FAILURE;
        }

        if (size % blocksize != 0)
                log_notice("Partition size %"PRIu64" is not a multiple of the blocksize %d,"
                           " ignoring %"PRIu64" bytes", size, blocksize, size % blocksize);

        numblocks = size / blocksize;

        if (fstatfs(mountfd, &sfs) < 0) {
                log_error_errno(errno, "Failed to stat file system \"%s\": %m", arg_target);
                return EXIT_FAILURE;
        }

        switch(sfs.f_type) {
        case EXT4_SUPER_MAGIC:
                r = resize_ext4(arg_target, mountfd, devfd, numblocks, blocksize);
                break;
        case BTRFS_SUPER_MAGIC:
                r = resize_btrfs(arg_target, mountfd, devfd, numblocks, blocksize);
                break;
        default:
                log_error("Don't know how to resize fs %llx on \"%s\"",
                          (long long unsigned) sfs.f_type, arg_target);
                return EXIT_FAILURE;
        }

        if (r < 0)
                return EXIT_FAILURE;

        log_info("Successfully resized \"%s\" to %s bytes (%"PRIu64" blocks of %d bytes).",
                 arg_target, format_bytes(fb, sizeof fb, size), numblocks, blocksize);
        return EXIT_SUCCESS;
}
