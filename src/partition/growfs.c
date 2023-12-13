/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/magic.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/vfs.h>
/* This needs to be included after sys/mount.h, as since [0] linux/btrfs.h
 * includes linux/fs.h causing build errors
 * See: https://github.com/systemd/systemd/issues/8507
 * [0] https://github.com/torvalds/linux/commit/a28135303a669917002f569aecebd5758263e4aa
 */
#include <linux/btrfs.h>

#include "sd-device.h"

#include "blockdev-util.h"
#include "btrfs-util.h"
#include "build.h"
#include "cryptsetup-util.h"
#include "device-nodes.h"
#include "device-util.h"
#include "devnum-util.h"
#include "dissect-image.h"
#include "escape.h"
#include "fd-util.h"
#include "format-util.h"
#include "log.h"
#include "main-func.h"
#include "mountpoint-util.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "resize-fs.h"

static const char *arg_target = NULL;
static bool arg_dry_run = false;

#if HAVE_LIBCRYPTSETUP
static int resize_crypt_luks_device(dev_t devno, const char *fstype, dev_t main_devno) {
        _cleanup_free_ char *devpath = NULL, *main_devpath = NULL;
        _cleanup_(sym_crypt_freep) struct crypt_device *cd = NULL;
        _cleanup_close_ int main_devfd = -EBADF;
        uint64_t size;
        int r;

        r = dlopen_cryptsetup();
        if (r < 0)
                return log_error_errno(r, "Cannot resize LUKS device: %m");

        main_devfd = r = device_open_from_devnum(S_IFBLK, main_devno, O_RDONLY|O_CLOEXEC, &main_devpath);
        if (r < 0)
                return log_error_errno(r, "Failed to open main block device " DEVNUM_FORMAT_STR ": %m",
                                       DEVNUM_FORMAT_VAL(main_devno));

        r = blockdev_get_device_size(main_devfd, &size);
        if (r < 0)
                return log_error_errno(r, "Failed to query size of \"%s\" (before resize): %m",
                                       main_devpath);

        log_debug("%s is %"PRIu64" bytes", main_devpath, size);

        r = devname_from_devnum(S_IFBLK, devno, &devpath);
        if (r < 0)
                return log_error_errno(r, "Failed to get devpath of " DEVNUM_FORMAT_STR ": %m",
                                       DEVNUM_FORMAT_VAL(devno));

        r = sym_crypt_init(&cd, devpath);
        if (r < 0)
                return log_error_errno(r, "crypt_init(\"%s\") failed: %m", devpath);

        cryptsetup_enable_logging(cd);

        r = sym_crypt_load(cd, CRYPT_LUKS, NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to load LUKS metadata for %s: %m", devpath);

        if (arg_dry_run)
                return 0;

        r = sym_crypt_resize(cd, main_devpath, 0);
        if (r < 0)
                return log_error_errno(r, "crypt_resize() of %s failed: %m", devpath);

        r = blockdev_get_device_size(main_devfd, &size);
        if (r < 0)
                log_warning_errno(r, "Failed to query size of \"%s\" (after resize): %m", devpath);
        else
                log_debug("%s is now %"PRIu64" bytes", main_devpath, size);

        return 1;
}
#endif

static int maybe_resize_underlying_device(
                int mountfd,
                const char *mountpath,
                dev_t main_devno) {

        _cleanup_free_ char *devpath = NULL, *fstype = NULL;
        dev_t devno;
        int r;

        assert(mountfd >= 0);
        assert(mountpath);

#if HAVE_LIBCRYPTSETUP
        cryptsetup_enable_logging(NULL);
#endif

        r = get_block_device_harder_fd(mountfd, &devno);
        if (r < 0)
                return log_error_errno(r, "Failed to determine underlying block device of \"%s\": %m",
                                       mountpath);
        if (devno == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENODEV), "File system \"%s\" not backed by block device.", arg_target);

        log_debug("Underlying device " DEVNUM_FORMAT_STR ", main dev " DEVNUM_FORMAT_STR ", %s",
                  DEVNUM_FORMAT_VAL(devno),
                  DEVNUM_FORMAT_VAL(main_devno),
                  devno == main_devno ? "same" : "different");
        if (devno == main_devno)
                return 0;

        r = devname_from_devnum(S_IFBLK, devno, &devpath);
        if (r < 0)
                return log_error_errno(r, "Failed to get devpath for block device " DEVNUM_FORMAT_STR ": %m",
                                       DEVNUM_FORMAT_VAL(devno));

        r = probe_filesystem(devpath, &fstype);
        if (r == -EUCLEAN)
                return log_warning_errno(r, "Cannot reliably determine probe \"%s\", refusing to proceed.", devpath);
        if (r < 0)
                return log_warning_errno(r, "Failed to probe \"%s\": %m", devpath);

#if HAVE_LIBCRYPTSETUP
        if (streq_ptr(fstype, "crypto_LUKS"))
                return resize_crypt_luks_device(devno, fstype, main_devno);
#endif

        log_debug("Don't know how to resize %s of type %s, ignoring.", devpath, strnull(fstype));
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
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               link);

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
                switch (c) {
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
                        assert_not_reached();
                }

        if (optind + 1 != argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s excepts exactly one argument (the mount point).",
                                       program_invocation_short_name);

        arg_target = argv[optind];

        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_close_ int mountfd = -EBADF, devfd = -EBADF;
        _cleanup_free_ char *devpath = NULL;
        uint64_t size, newsize;
        dev_t devno;
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = path_is_mount_point(arg_target, NULL, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to check if \"%s\" is a mount point: %m", arg_target);
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "\"%s\" is not a mount point: %m", arg_target);

        mountfd = open(arg_target, O_RDONLY|O_CLOEXEC|O_DIRECTORY);
        if (mountfd < 0)
                return log_error_errno(errno, "Failed to open \"%s\": %m", arg_target);

        r = get_block_device_fd(mountfd, &devno);
        if (r == -EUCLEAN)
                return btrfs_log_dev_root(LOG_ERR, r, arg_target);
        if (r < 0)
                return log_error_errno(r, "Failed to determine block device of \"%s\": %m", arg_target);
        if (devno == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENODEV), "File system \"%s\" not backed by block device.", arg_target);

        r = maybe_resize_underlying_device(mountfd, arg_target, devno);
        if (r < 0)
                log_warning_errno(r, "Unable to resize underlying device of \"%s\", proceeding anyway: %m", arg_target);

        devfd = r = device_open_from_devnum(S_IFBLK, devno, O_RDONLY|O_CLOEXEC, &devpath);
        if (r < 0)
                return log_error_errno(r, "Failed to open block device " DEVNUM_FORMAT_STR ": %m",
                                       DEVNUM_FORMAT_VAL(devno));

        r = blockdev_get_device_size(devfd, &size);
        if (r < 0)
                return log_error_errno(r, "Failed to query size of \"%s\": %m", devpath);

        log_debug("Resizing \"%s\" to %"PRIu64" bytes...", arg_target, size);

        if (arg_dry_run)
                return 0;

        r = resize_fs(mountfd, size, &newsize);
        if (r < 0)
                return log_error_errno(r, "Failed to resize \"%s\" to %"PRIu64" bytes: %m",
                                       arg_target, size);
        if (newsize == size)
                log_info("Successfully resized \"%s\" to %s bytes.",
                         arg_target,
                         FORMAT_BYTES(newsize));
        else
                log_info("Successfully resized \"%s\" to %s bytes (%"PRIu64" bytes lost due to blocksize).",
                         arg_target,
                         FORMAT_BYTES(newsize),
                         size - newsize);
        return 0;
}

DEFINE_MAIN_FUNCTION(run);
