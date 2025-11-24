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
#include "conf-files.h" //umask
#include "main-func.h" // DEFINE_MAIN_FUNCTION
#include "errno-util.h" // RET_GATHER
#include "alloc-util.h" // _cleanup_free_
#include "fd-util.h" // _cleanup_fclose
#include "fileio.h" //  fopen_unlocked
#include "id128-util.h"
#include "log.h"
#include "dm-util.h"
#include <linux/fs.h> // For BLKSSZGET
#include <unistd.h> // close
#include "mkfs-util.h"
#include "argv-util.h" //argv_looks_like_help
#include "string-util.h" //strempty
#include "pretty-print.h" //terminal_urlify_man
#include "verbs.h"
#include "build.h" //version

static uint64_t get_size(const char *dev_path) {
        int fd, block_size;
        uint64_t device_size_sectors;

        // Open the block device for reading
        fd = open(dev_path, O_RDONLY);
        if (fd < 0) {
                log_error("Error opening device");
                return 1;
        }
        // Use the BLKGETSIZE64 ioctl command to get the block size in bytes
        // Use BLKSSZGET to get 512 - sector size of a block device.
        if (ioctl(fd, BLKGETSIZE64, &block_size) < 0) {
                log_error("Error with ioctl(BLKGETSIZE64)");
                close(fd);
                return 1;
        }
        close(fd);
        device_size_sectors = block_size / 512;
        return device_size_sectors;
}

static int dm_clone_task(const char *clone_name, const char *source_dev, const char *dest_dev,
                const char *metadata_dev, const char *options) {

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

        uint64_t device_size_sectors=get_size(source_dev);
        // Example table string for dm-clone
        // const char *table_str = "0 <device_size_sectors> clone <metadata_dev_path> <dest_dev_path> <source_dev_path> <region_size_sectors> 1 no_hydration";
        //<device_size_sectors>: Total size of the clone device in sectors.
        //<metadata_dev_path>: Path to the metadata device (e.g., /dev/sdb1).
        //<dest_dev_path>: Path to the destination device (e.g., /dev/sdc1).
        //<source_dev_path>: Path to the source device (e.g., /dev/sda1).
        //<region_size_sectors>: Size of a region in sectors (e.g., 8 for 4KB regions).
        //1: Version number.
        //no_hydration: Initially disable background hydration.
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

// https://docs.kernel.org/admin-guide/device-mapper/dm-clone.html#examples
// 1. Create the dm-clone device - ioctl for device creation
// 2. Enable background hydration - ioctl for hydration enable
// 3. Replace the table with a linear mapping to finalize the clone
static int clone_device(const char *clone_name, const char *source_dev, const char *dest_dev,
                const char *metadata_dev, const char *options) {

        char clone_dev_path[256];
        snprintf(clone_dev_path, sizeof(clone_dev_path), "/dev/mapper/%s", clone_name);
        // check if clone path already exists.
        struct stat st;
        if (stat(clone_dev_path, &st) >= 0) {
                log_error ("device %s already exists", clone_dev_path);
                return 1;
        }
        if (dm_clone_task(clone_name, source_dev, dest_dev, metadata_dev, options) != 0) {
                log_error ("dm_device_create failed");
                return 1;
        }
        if (dm_msg_task(clone_name) != 0) {
                log_error ("dm_device_msg failed");
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
              *options = NULL; // TODO add support for options

        log_debug("%s %s %s %s %s opts=%s ", __func__,
                        name, src_dev, dst_dev, meta_dev, strempty(options));

        r = clone_device(name, src_dev, dst_dev, meta_dev, options);
        if (  r != 0 ) {
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
