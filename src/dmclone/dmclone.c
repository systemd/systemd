/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "conf-files.h"
#include "main-func.h"
#include "errno-util.h"
#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "id128-util.h"
#include "log.h"
#include "dm-util.h"
#include <linux/fs.h>
#include <unistd.h>
#include "mkfs-util.h"
#include "argv-util.h"
#include "string-util.h"
#include "pretty-print.h"
#include "verbs.h"
#include "build.h"

static uint64_t get_size(const char *dev_path) {
        uint64_t block_size_bytes;
        uint64_t device_size_sectors;
        int fd;

        fd = open(dev_path, O_RDONLY);
        if (fd < 0) {
                log_error("Error opening device");
                return 1;
        }

        /* Use BLKGETSIZE64 ioctl to get block size in bytes */
        if (ioctl(fd, BLKGETSIZE64, &block_size_bytes) < 0) {
                log_error("Error with ioctl(BLKGETSIZE64)");
                close(fd);
                return 1;
        }
        close(fd);
        device_size_sectors = block_size_bytes / 512;
        return device_size_sectors;
}

static int dm_clone_task(const char *clone_name, const char *source_dev, const char *dest_dev,
                const char *metadata_dev, const char *options) {

        struct dm_task *dmt;
        uint32_t cookie = 0;
        uint16_t udev_flags = 0;
        uint64_t device_size_sectors;
        char cmd[256];
        int r;

        dmt = dm_task_create(DM_DEVICE_CREATE);
        if (!dmt) {
                log_error("dm task create failed\n");
                return 1;
        }

        if (!dm_task_set_name(dmt, clone_name)) {
                log_error("dm_task_set_name failed\n");
                dm_task_destroy(dmt);
                return 1;
        }

        device_size_sectors = get_size(source_dev);

        /* Build dm-clone target parameters:
         * Format: <metadata_dev> <dest_dev> <source_dev> <region_size> <version> <options>
         * region_size: 8 sectors (4KB regions)
         * version: 1
         * options: no_hydration (disable initial background hydration) */
        snprintf(cmd, sizeof(cmd), "%s %s %s 8 1 no_hydration", metadata_dev, dest_dev, source_dev);

        if (!dm_task_add_target(dmt, 0, device_size_sectors, "clone", cmd)) {
                log_error("dm_task_add_target failed\n");
                dm_task_destroy(dmt);
                return 1;
        }

        /* Set cookie for udev synchronization */
        if (!dm_task_set_cookie(dmt, &cookie, udev_flags)) {
                log_error("dm_task_set_cookie failed\n");
                dm_task_destroy(dmt);
                return 1;
        }

        r = dm_task_run(dmt);
        dm_task_destroy(dmt);

        if (!r) {
                log_error("dm_task_run failed with error code: %d\n", r);
                /* Ensure cookie cleanup even on failure */
                if (cookie)
                        dm_udev_wait(cookie);
                return 1;
        }

        /* Wait for udev to finish processing the device */
        dm_udev_wait(cookie);

        return 0;
}

static int dm_msg_task(const char *clone_name) {
        struct dm_task *dmt;
        int r;

        dmt = dm_task_create(DM_DEVICE_TARGET_MSG);
        if (!dmt) {
                log_error("Failed to create dm_task for message\n");
                return 1;
        }

        if (!dm_task_set_name(dmt,clone_name) || !dm_task_set_sector(dmt, 0) || !dm_task_set_message(dmt, "enable_hydration")) {
                log_error("Failed to set message or device name\n");
                return 1;
        }

        r = dm_task_run(dmt);
        if (!r) {
                log_error("dm_task_run failed with error code: %d\n", r);
                dm_task_destroy(dmt);
                return 1;
        }
        dm_task_destroy(dmt);
        return 0;
}

/* dm-clone device creation workflow:
 * 1. Create the dm-clone device
 * 2. Enable background hydration
 * 3. (Optional) Replace with linear mapping to finalize */
static int clone_device(const char *clone_name, const char *source_dev, const char *dest_dev,
                const char *metadata_dev, const char *options) {

        char clone_dev_path[256];
        struct stat st;

        snprintf(clone_dev_path, sizeof(clone_dev_path), "/dev/mapper/%s", clone_name);
        if (stat(clone_dev_path, &st) >= 0) {
                log_error("device %s already exists", clone_dev_path);
                return 1;
        }
        if (dm_clone_task(clone_name, source_dev, dest_dev, metadata_dev, options) != 0) {
                log_error("dm_device_create failed");
                return 1;
        }
        if (dm_msg_task(clone_name) != 0) {
                log_error("dm_device_msg failed");
                return 1;
        }
        return 0;
}

/* Arguments: systemd-dmclone add NAME SOURCE-DEVICE DST_DEVICE META-DEVICE [OPTIONS] */
static int verb_add(int argc, char *argv[], void *userdata) {
        int r;

        assert(argc >= 5 && argc <= 6);

        const char *name = ASSERT_PTR(argv[1]),
              *src_dev = ASSERT_PTR(argv[2]),
              *dst_dev = ASSERT_PTR(argv[3]),
              *meta_dev = ASSERT_PTR(argv[4]),
              *options = NULL;

        log_debug("%s %s %s %s %s opts=%s ", __func__,
                        name, src_dev, dst_dev, meta_dev, strempty(options));

        r = clone_device(name, src_dev, dst_dev, meta_dev, options);
        if (r != 0) {
                log_error("clone_device failed");
                return r;
        }
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
