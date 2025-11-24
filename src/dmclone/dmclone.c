/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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
#include <getopt.h>
#include <stdio.h>

#include <sys/ioctl.h>
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
const char *fname="/etc/dmclonetab";

static uint64_t get_size(const char *dev_path) {
        int fd, block_size;
        uint64_t device_size_sectors;

        log_info("get_size of dev_path=%s", dev_path);
        
        fd = open(dev_path, O_RDONLY);
        if (fd < 0) {
                log_error("Error opening device");
                return 1;
        }
        
        /* Use BLKGETSIZE64 ioctl to get block size in bytes */
        if (ioctl(fd, BLKGETSIZE64, &block_size) < 0) {
                log_error("Error with ioctl(BLKGETSIZE64)");
                close(fd);
                return 1;
        }
        close(fd);
        device_size_sectors = block_size / 512;
        log_info("Successfully calculated size for %s in sectors=%lu\n", dev_path, device_size_sectors);
        return device_size_sectors;
}

static int dm_clone_task(const char *clone_name, const char *source_dev, const char *dest_dev,
                const char *metadata_dev, const char *options) {

        log_info("dm_clone_task called with clone_name=%s, source_dev=%s, metadata_dev=%s, dest_dev=%s, options=%s", clone_name, source_dev, metadata_dev, dest_dev, options);

        struct dm_task *dmt;
        uint32_t cookie = 0;
        uint16_t udev_flags = 0;
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

        uint64_t device_size_sectors = get_size(source_dev);
        uint64_t device_size_sectors2 = get_size(dest_dev);
        
        /* Build dm-clone target parameters:
         * Format: <metadata_dev> <dest_dev> <source_dev> <region_size> <version> <options>
         * region_size: 8 sectors (4KB regions)
         * version: 1
         * options: no_hydration (disable initial background hydration) */
        char cmd[256];
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
        log_info("Waiting for udev to process device (cookie=%u)...", cookie);
        dm_udev_wait(cookie);
        log_info("udev processing complete");

        return 0;
}

static int dm_msg_task(const char *clone_name) {
        struct dm_task *dmt;
        int r;
        log_info("Now enabling hydration...\n");

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

static int mkfs_clone_dev(const char *clone_name, char *clone_dev_path) {

        sd_id128_t uuid;
        int r;

        r = sd_id128_randomize(&uuid);
        if (r < 0) {
                log_error("Failed to generate UUID for file system, error code=%d", r);
                return 1;
        }

        log_info("Successfully created uuid=%s for clone device: %s\n", sd_id128_is_null(uuid) ? "" : SD_ID128_TO_STRING(uuid), clone_dev_path);

        r= make_filesystem(clone_dev_path,
                        "btrfs",
                        clone_name,
                        "/",
                        uuid,
                        MKFS_DISCARD | MKFS_QUIET,
                        /* sector_size = */ 0,
                        /* compression = */ NULL,
                        /* compression_level = */ NULL,
                        /* extra_mkfs_options = */ NULL);
        if (r < 0) {
                log_error("Failed to make filesystem for %s, error code=%d", clone_name, r);
                return 1;
        }
        return 0;
}

/* dm-clone device creation workflow:
 * 1. Create the dm-clone device
 * 2. Enable background hydration
 * 3. (Optional) Replace with linear mapping to finalize */
static int clone_device(const char *clone_name, const char *source_dev, const char *dest_dev,
                const char *metadata_dev, const char *options) {

        char clone_dev_path[256];
        snprintf(clone_dev_path, sizeof(clone_dev_path), "/dev/mapper/%s", clone_name);
        
        struct stat st;
        if (stat(clone_dev_path, &st) >= 0) {
                log_error("device %s already exists", clone_dev_path);
                return 1;
        }
        if (dm_clone_task(clone_name, source_dev, dest_dev, metadata_dev, options) != 0) {
                log_error("dm_device_create failed");
                return 1;
        }
        log_info("Successfully created clone device: %s\n", clone_dev_path);
        
        /* Filesystem creation disabled - can be enabled if needed:
         * if (mkfs_clone_dev(clone_name, clone_dev_path) != 0) {
         *         log_error("mkfs_clone_dev failed");
         *         return 1;
         * } */
        
        log_info("mkfs on clone dev =  %s completed\n", clone_dev_path);
        if (dm_msg_task(clone_name) != 0) {
                log_error("dm_device_msg failed");
                return 1;
        }
        log_info("Hydration enabled for device: %s\n", clone_dev_path);
        return 0;
}

static int verb_add(int argc, char *argv[], void *userdata) {
        int r;

        /* Arguments: systemd-dmclone add NAME SOURCE-DEVICE DST_DEVICE META-DEVICE [OPTIONS] */

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
        log_info("Hello World");

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
