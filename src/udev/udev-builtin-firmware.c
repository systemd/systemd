/*
 * firmware - Kernel firmware loader
 *
 * Copyright (C) 2009 Piter Punk <piterpunk@slackware.com>
 * Copyright (C) 2009-2011 Kay Sievers <kay@vrfy.org>
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
                log_error("error: can not open '%s'", loadpath);
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
                log_error("No memory available to load firmware file");
                return false;
        }

        log_debug("writing '%s' (%zi) to '%s'", source, size, target);

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
        char loadpath[UTIL_PATH_SIZE];
        char datapath[UTIL_PATH_SIZE];
        char fwpath[UTIL_PATH_SIZE];
        const char *firmware;
        FILE *fwfile = NULL;
        struct utsname kernel;
        struct stat statbuf;
        unsigned int i;
        int rc = EXIT_SUCCESS;

        firmware = udev_device_get_property_value(dev, "FIRMWARE");
        if (firmware == NULL) {
                log_error("firmware parameter missing");
                rc = EXIT_FAILURE;
                goto exit;
        }

        /* lookup firmware file */
        uname(&kernel);
        for (i = 0; i < ELEMENTSOF(searchpath); i++) {
                strscpyl(fwpath, sizeof(fwpath), searchpath[i], kernel.release, "/", firmware, NULL);
                fwfile = fopen(fwpath, "re");
                if (fwfile != NULL)
                        break;

                strscpyl(fwpath, sizeof(fwpath), searchpath[i], firmware, NULL);
                fwfile = fopen(fwpath, "re");
                if (fwfile != NULL)
                        break;
        }

        strscpyl(loadpath, sizeof(loadpath), udev_device_get_syspath(dev), "/loading", NULL);

        if (fwfile == NULL) {
                log_debug("did not find firmware file '%s'", firmware);
                rc = EXIT_FAILURE;
                /*
                 * Do not cancel the request in the initrd, the real root might have
                 * the firmware file and the 'coldplug' run in the real root will find
                 * this pending request and fulfill or cancel it.
                 * */
                if (!in_initrd())
                        set_loading(udev, loadpath, "-1");
                goto exit;
        }

        if (stat(fwpath, &statbuf) < 0 || statbuf.st_size == 0) {
                if (!in_initrd())
                        set_loading(udev, loadpath, "-1");
                rc = EXIT_FAILURE;
                goto exit;
        }

        if (!set_loading(udev, loadpath, "1"))
                goto exit;

        strscpyl(datapath, sizeof(datapath), udev_device_get_syspath(dev), "/data", NULL);
        if (!copy_firmware(udev, fwpath, datapath, statbuf.st_size)) {
                log_error("error sending firmware '%s' to device", firmware);
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
