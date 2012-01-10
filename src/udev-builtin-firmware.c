/*
 * firmware - Kernel firmware loader
 *
 * Copyright (C) 2009 Piter Punk <piterpunk@slackware.com>
 * Copyright (C) 2009-2011 Kay Sievers <kay.sievers@vrfy.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details:*
 */

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <getopt.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/utsname.h>
#include <sys/stat.h>

#include "udev.h"

static bool set_loading(struct udev *udev, char *loadpath, const char *state)
{
        FILE *ldfile;

        ldfile = fopen(loadpath, "we");
        if (ldfile == NULL) {
                err(udev, "error: can not open '%s'\n", loadpath);
                return false;
        };
        fprintf(ldfile, "%s\n", state);
        fclose(ldfile);
        return true;
}

static bool copy_firmware(struct udev *udev, const char *source, const char *target, size_t size)
{
        char *buf;
        FILE *fsource = NULL, *ftarget = NULL;
        bool ret = false;

        buf = malloc(size);
        if (buf == NULL) {
                err(udev,"No memory available to load firmware file");
                return false;
        }

        info(udev, "writing '%s' (%zi) to '%s'\n", source, size, target);

        fsource = fopen(source, "re");
        if (fsource == NULL)
                goto exit;
        ftarget = fopen(target, "we");
        if (ftarget == NULL)
                goto exit;
        if (fread(buf, size, 1, fsource) != 1)
                goto exit;
        if (fwrite(buf, size, 1, ftarget) == 1)
                ret = true;
exit:
        if (ftarget != NULL)
                fclose(ftarget);
        if (fsource != NULL)
                fclose(fsource);
        free(buf);
        return ret;
}

static int builtin_firmware(struct udev_device *dev, int argc, char *argv[], bool test)
{
        struct udev *udev = udev_device_get_udev(dev);
        static const char *searchpath[] = { FIRMWARE_PATH };
        char fwencpath[UTIL_PATH_SIZE];
        char misspath[UTIL_PATH_SIZE];
        char loadpath[UTIL_PATH_SIZE];
        char datapath[UTIL_PATH_SIZE];
        char fwpath[UTIL_PATH_SIZE];
        const char *firmware;
        FILE *fwfile;
        struct utsname kernel;
        struct stat statbuf;
        unsigned int i;
        int rc = EXIT_SUCCESS;

        firmware = udev_device_get_property_value(dev, "FIRMWARE");
        if (firmware == NULL) {
                err(udev, "firmware parameter missing\n\n");
                rc = EXIT_FAILURE;
                goto exit;
        }

        /* lookup firmware file */
        uname(&kernel);
        for (i = 0; i < ARRAY_SIZE(searchpath); i++) {
                util_strscpyl(fwpath, sizeof(fwpath), searchpath[i], kernel.release, "/", firmware, NULL);
                dbg(udev, "trying %s\n", fwpath);
                fwfile = fopen(fwpath, "re");
                if (fwfile != NULL)
                        break;

                util_strscpyl(fwpath, sizeof(fwpath), searchpath[i], firmware, NULL);
                dbg(udev, "trying %s\n", fwpath);
                fwfile = fopen(fwpath, "re");
                if (fwfile != NULL)
                        break;
        }

        util_path_encode(firmware, fwencpath, sizeof(fwencpath));
        util_strscpyl(misspath, sizeof(misspath), udev_get_run_path(udev), "/firmware-missing/", fwencpath, NULL);
        util_strscpyl(loadpath, sizeof(loadpath), udev_device_get_syspath(dev), "/loading", NULL);

        if (fwfile == NULL) {
                int err;

                /* This link indicates the missing firmware file and the associated device */
                info(udev, "did not find firmware file '%s'\n", firmware);
                do {
                        err = util_create_path(udev, misspath);
                        if (err != 0 && err != -ENOENT)
                                break;
                        err = symlink(udev_device_get_devpath(dev), misspath);
                        if (err != 0)
                                err = -errno;
                } while (err == -ENOENT);
                rc = EXIT_FAILURE;
                set_loading(udev, loadpath, "-1");
                goto exit;
        }

        if (stat(fwpath, &statbuf) < 0 || statbuf.st_size == 0) {
                rc = EXIT_FAILURE;
                goto exit;
        }
        if (unlink(misspath) == 0)
                util_delete_path(udev, misspath);

        if (!set_loading(udev, loadpath, "1"))
                goto exit;

        util_strscpyl(datapath, sizeof(datapath), udev_device_get_syspath(dev), "/data", NULL);
        if (!copy_firmware(udev, fwpath, datapath, statbuf.st_size)) {
                err(udev, "error sending firmware '%s' to device\n", firmware);
                set_loading(udev, loadpath, "-1");
                rc = EXIT_FAILURE;
                goto exit;
        };

        set_loading(udev, loadpath, "0");
exit:
        if (fwfile)
                fclose(fwfile);
        return rc;
}

const struct udev_builtin udev_builtin_firmware = {
        .name = "firmware",
        .cmd = builtin_firmware,
        .help = "kernel firmware loader",
        .run_once = true,
};
