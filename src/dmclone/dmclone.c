/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include <fcntl.h>
#include <getopt.h>
#include <linux/fs.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "argv-util.h"
#include "build.h"
#include "dm-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "log.h"
#include "main-func.h"
#include "pretty-print.h"
#include "string-util.h"
#include "verbs.h"

static int get_size(const char *dev_path, uint64_t *ret_size) {
        _cleanup_close_ int fd = -EBADF;
        uint64_t block_size_bytes;

        assert(dev_path);
        assert(ret_size);

        fd = open(dev_path, O_RDONLY|O_CLOEXEC);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open device '%s': %m", dev_path);

        /* Use BLKGETSIZE64 ioctl to get block size in bytes */
        if (ioctl(fd, BLKGETSIZE64, &block_size_bytes) < 0)
                return log_error_errno(errno, "Failed to get device size for '%s': %m", dev_path);

        *ret_size = block_size_bytes / 512;
        return 0;
}

static int dm_clone_task(const char *clone_name, const char *source_dev, const char *dest_dev,
                const char *metadata_dev) {

        _cleanup_(sym_dm_task_destroyp) struct dm_task *dmt = NULL;
        uint32_t cookie = 0;
        uint16_t udev_flags = 0;
        uint64_t device_size_sectors;
        char cmd[256];
        int r;

        assert(clone_name);
        assert(source_dev);
        assert(dest_dev);
        assert(metadata_dev);

        r = get_size(source_dev, &device_size_sectors);
        if (r < 0)
                return r;

        dmt = sym_dm_task_create(DM_DEVICE_CREATE);
        if (!dmt)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to create dm task.");

        if (!sym_dm_task_set_name(dmt, clone_name))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to set dm task name.");

        /* Build dm-clone target parameters:
         * Format: <metadata_dev> <dest_dev> <source_dev> <region_size> <version> <options>
         * region_size: 8 sectors (4KB regions)
         * version: 1
         * options: no_hydration (disable initial background hydration) */
        xsprintf(cmd, "%s %s %s 8 1 no_hydration", metadata_dev, dest_dev, source_dev);

        if (!sym_dm_task_add_target(dmt, 0, device_size_sectors, "clone", cmd))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to add dm target.");

        /* Set cookie for udev synchronization */
        if (!sym_dm_task_set_cookie(dmt, &cookie, udev_flags))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to set dm cookie.");

        r = sym_dm_task_run(dmt);
        if (!r) {
                /* Ensure cookie cleanup even on failure */
                if (cookie)
                        sym_dm_udev_wait(cookie);
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to run dm task.");
        }

        /* Wait for udev to finish processing the device */
        sym_dm_udev_wait(cookie);

        return 0;
}

static int dm_msg_task(const char *clone_name) {
        _cleanup_(sym_dm_task_destroyp) struct dm_task *dmt = NULL;
        int r;

        assert(clone_name);

        dmt = sym_dm_task_create(DM_DEVICE_TARGET_MSG);
        if (!dmt)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to create dm_task for message.");

        if (!sym_dm_task_set_name(dmt, clone_name))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to set device name.");

        if (!sym_dm_task_set_sector(dmt, 0))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to set sector.");

        if (!sym_dm_task_set_message(dmt, "enable_hydration"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to set message.");

        r = sym_dm_task_run(dmt);
        if (!r)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to run dm task.");

        return 0;
}

/* dm-clone device creation workflow:
 * 1. Create the dm-clone device
 * 2. Enable background hydration
 * 3. (Optional) Replace with linear mapping to finalize */
static int clone_device(const char *clone_name, const char *source_dev, const char *dest_dev,
                const char *metadata_dev) {

        char clone_dev_path[256];
        struct stat st;
        int r;

        assert(clone_name);
        assert(source_dev);
        assert(dest_dev);
        assert(metadata_dev);

        xsprintf(clone_dev_path, "/dev/mapper/%s", clone_name);
        if (stat(clone_dev_path, &st) >= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EEXIST), "Device '%s' already exists.", clone_dev_path);

        r = dm_clone_task(clone_name, source_dev, dest_dev, metadata_dev);
        if (r < 0)
                return log_error_errno(r, "Failed to create dm-clone device: %m");

        r = dm_msg_task(clone_name);
        if (r < 0)
                return log_error_errno(r, "Failed to send dm message: %m");

        return 0;
}

/* Arguments: systemd-dmclone add NAME SOURCE-DEVICE DST_DEVICE META-DEVICE [OPTIONS] */
static int verb_add(int argc, char *argv[], void *userdata) {
        int r;

        assert(argc >= 5 && argc <= 6);

        const char *name = ASSERT_PTR(argv[1]),
              *src_dev = ASSERT_PTR(argv[2]),
              *dst_dev = ASSERT_PTR(argv[3]),
              *meta_dev = ASSERT_PTR(argv[4]);

        log_debug("%s %s %s %s %s", __func__, name, src_dev, dst_dev, meta_dev);

        r = dlopen_libdevmapper();
        if (r < 0)
                return log_error_errno(r, "Failed to open libdevmapper: %m");

        r = clone_device(name, src_dev, dst_dev, meta_dev);
        if (r < 0)
                return r;

        return 0;
}

static int verb_remove(int argc, char *argv[], void *userdata) {

        return 0;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-dmclone", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s add NAME SOURCE-DEVICE DST-DEVICE META-DEVICE [OPTIONS] \n"
                        "%1$s remove VOLUME\n\n"
                        "%2$sAdd or remove a dm clone device.%3$s\n\n"
                        "  -h --help            Show this help\n"
                        "     --version         Show package version\n"
                        "\nSee the %4$s for details.\n",
                        program_invocation_short_name,
                        ansi_highlight(),
                        ansi_normal(),
                        link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
        };

        static const struct option options[] = {
                { "help",                         no_argument,       NULL, 'h'                       },
                { "version",                      no_argument,       NULL, ARG_VERSION               },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        if (argv_looks_like_help(argc, argv))
                return help();

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)
                switch (c) {

                        case 'h':
                                return help();

                        case ARG_VERSION:
                                return version();

                        case '?':
                                return -EINVAL;

                        default:
                                assert_not_reached();
                }

        return 1;
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();
        umask(0022);

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        static const Verb verbs[] = {
                { "add", 5, 6, 0, verb_add },
                { "remove", 1, 1, 0, verb_remove },
                {}
        };
        return dispatch_verb(argc, argv, verbs, NULL);
}

DEFINE_MAIN_FUNCTION(run);
