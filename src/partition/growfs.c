/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2017 Zbigniew Jędrzejewski-Szmek

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
#include <linux/magic.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>

#include "crypt-util.h"
#include "device-nodes.h"
#include "dissect-image.h"
#include "escape.h"
#include "fd-util.h"
#include "format-util.h"
#include "log.h"
#include "missing.h"
#include "mount-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "strv.h"

static int resize_ext4(const char *path, int mountfd, int devfd, uint64_t numblocks, uint64_t blocksize) {
        assert((uint64_t) (int) blocksize == blocksize);

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

        if (ioctl(mountfd, BTRFS_IOC_RESIZE, &args) != 0)
                return log_error_errno(errno, "Failed to resize \"%s\" to %"PRIu64" blocks (btrfs): %m",
                                       path, numblocks);

        return 0;
}

static int resize_crypt_luks_device(dev_t devno, const char *fstype, dev_t main_devno) {
        char devpath[DEV_NUM_PATH_MAX], main_devpath[DEV_NUM_PATH_MAX];
        _cleanup_close_ int main_devfd = -1;
        _cleanup_(crypt_freep) struct crypt_device *cd = NULL;
        uint64_t size;
        int r;

        xsprintf_dev_num_path(main_devpath, "block", main_devno);
        main_devfd = open(main_devpath, O_RDONLY|O_CLOEXEC);
        if (main_devfd < 0)
                return log_error_errno(errno, "Failed to open \"%s\": %m", main_devpath);

        if (ioctl(main_devfd, BLKGETSIZE64, &size) != 0)
                return log_error_errno(errno, "Failed to query size of \"%s\" (before resize): %m",
                                       main_devpath);

        log_debug("%s is %"PRIu64" bytes", main_devpath, size);

        xsprintf_dev_num_path(devpath, "block", devno);
        r = crypt_init(&cd, devpath);
        if (r < 0)
                return log_error_errno(r, "crypt_init(\"%s\") failed: %m", devpath);

        crypt_set_log_callback(cd, cryptsetup_log_glue, NULL);

        r = crypt_load(cd, CRYPT_LUKS, NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to load LUKS metadata for %s: %m", devpath);

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

static int maybe_resize_slave_device(const char *mountpath, dev_t main_devno) {
        dev_t devno;
        char devpath[DEV_NUM_PATH_MAX];
        _cleanup_free_ char *fstype = NULL;
        int r;

        crypt_set_log_callback(NULL, cryptsetup_log_glue, NULL);
        crypt_set_debug_level(1);

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

        xsprintf_dev_num_path(devpath, "block", devno);
        r = probe_filesystem(devpath, &fstype);
        if (r < 0)
                return log_warning_errno(r, "Failed to probe \"%s\": %m", devpath);

        if (streq_ptr(fstype, "crypto_LUKS"))
                return resize_crypt_luks_device(devno, fstype, main_devno);

        log_debug("Don't know how to resize %s of type %s, ignoring", devpath, strnull(fstype));
        return 0;
}

int main(int argc, char *argv[]) {
        dev_t devno;
        _cleanup_close_ int mountfd = -1, devfd = -1;
        int blocksize;
        uint64_t size, numblocks;
        char devpath[DEV_NUM_PATH_MAX], fb[FORMAT_BYTES_MAX];
        struct statfs sfs;
        int r;

        if (argc != 2) {
                log_error("This program requires one argument (the mountpoint).");
                return EXIT_FAILURE;
        }

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        r = path_is_mount_point(argv[1], NULL, 0);
        if (r < 0) {
                log_error_errno(r, "Failed to check if \"%s\" is a mount point: %m", argv[1]);
                return EXIT_FAILURE;
        }
        if (r == 0) {
                log_error_errno(r, "\"%s\" is not a mount point: %m", argv[1]);
                return EXIT_FAILURE;
        }

        r = get_block_device(argv[1], &devno);
        if (r < 0) {
                log_error_errno(r, "Failed to determine block device of \"%s\": %m", argv[1]);
                return EXIT_FAILURE;
        }

        r = maybe_resize_slave_device(argv[1], devno);
        if (r < 0)
                return EXIT_FAILURE;

        mountfd = open(argv[1], O_RDONLY|O_CLOEXEC);
        if (mountfd < 0) {
                log_error_errno(errno, "Failed to open \"%s\": %m", argv[1]);
                return EXIT_FAILURE;
        }

        xsprintf_dev_num_path(devpath, "block", devno);
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
                log_error_errno(errno, "Failed to stat file system \"%s\": %m", argv[1]);
                return EXIT_FAILURE;
        }

        switch(sfs.f_type) {
        case EXT4_SUPER_MAGIC:
                r = resize_ext4(argv[1], mountfd, devfd, numblocks, blocksize);
                break;
        case BTRFS_SUPER_MAGIC:
                r = resize_btrfs(argv[1], mountfd, devfd, numblocks, blocksize);
                break;
        default:
                log_error("Don't know how to resize fs %llx on \"%s\"",
                          (long long unsigned) sfs.f_type, argv[1]);
                return EXIT_FAILURE;
        }

        if (r < 0)
                return EXIT_FAILURE;

        log_info("Successfully resized \"%s\" to %s bytes (%"PRIu64" blocks of %d bytes).",
                 argv[1], format_bytes(fb, sizeof fb, size), numblocks, blocksize);
        return EXIT_SUCCESS;
}
