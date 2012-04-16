/*
 * usb-db, pci-db - lookup vendor/product database
 *
 * Copyright (C) 2009 Lennart Poettering <lennart@poettering.net>
 * Copyright (C) 2011 Kay Sievers <kay.sievers@vrfy.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <ctype.h>
#include <stdlib.h>

#include "udev.h"

static int get_id_attr(
        struct udev_device *parent,
        const char *name,
        uint16_t *value) {

        const char *t;
        unsigned u;

        if (!(t = udev_device_get_sysattr_value(parent, name))) {
                fprintf(stderr, "%s lacks %s.\n", udev_device_get_syspath(parent), name);
                return -1;
        }

        if (startswith(t, "0x"))
                t += 2;

        if (sscanf(t, "%04x", &u) != 1 || u > 0xFFFFU) {
                fprintf(stderr, "Failed to parse %s on %s.\n", name, udev_device_get_syspath(parent));
                return -1;
        }

        *value = (uint16_t) u;
        return 0;
}

static int get_vid_pid(
        struct udev_device *parent,
        const char *vendor_attr,
        const char *product_attr,
        uint16_t *vid,
        uint16_t *pid) {

        if (get_id_attr(parent, vendor_attr, vid) < 0)
                return -1;
        else if (*vid <= 0) {
                fprintf(stderr, "Invalid vendor id.\n");
                return -1;
        }

        if (get_id_attr(parent, product_attr, pid) < 0)
                return -1;

        return 0;
}

static void rstrip(char *n) {
        size_t i;

        for (i = strlen(n); i > 0 && isspace(n[i-1]); i--)
                n[i-1] = 0;
}

#define HEXCHARS "0123456789abcdefABCDEF"
#define WHITESPACE " \t\n\r"
static int lookup_vid_pid(const char *database,
                          uint16_t vid, uint16_t pid,
                          char **vendor, char **product)
{

        FILE *f;
        int ret = -1;
        int found_vendor = 0;
        char *line = NULL;

        *vendor = *product = NULL;

        if (!(f = fopen(database, "rme"))) {
                fprintf(stderr, "Failed to open database file '%s': %s\n", database, strerror(errno));
                return -1;
        }

        for (;;) {
                size_t n;

                if (getline(&line, &n, f) < 0)
                        break;

                rstrip(line);

                if (line[0] == '#' || line[0] == 0)
                        continue;

                if (strspn(line, HEXCHARS) == 4) {
                        unsigned u;

                        if (found_vendor)
                                break;

                        if (sscanf(line, "%04x", &u) == 1 && u == vid) {
                                char *t;

                                t = line+4;
                                t += strspn(t, WHITESPACE);

                                if (!(*vendor = strdup(t))) {
                                        fprintf(stderr, "Out of memory.\n");
                                        goto finish;
                                }

                                found_vendor = 1;
                        }

                        continue;
                }

                if (found_vendor && line[0] == '\t' && strspn(line+1, HEXCHARS) == 4) {
                        unsigned u;

                        if (sscanf(line+1, "%04x", &u) == 1 && u == pid) {
                                char *t;

                                t = line+5;
                                t += strspn(t, WHITESPACE);

                                if (!(*product = strdup(t))) {
                                        fprintf(stderr, "Out of memory.\n");
                                        goto finish;
                                }

                                break;
                        }
                }
        }

        ret = 0;

finish:
        free(line);
        fclose(f);

        if (ret < 0) {
                free(*product);
                free(*vendor);

                *product = *vendor = NULL;
        }

        return ret;
}

static struct udev_device *find_device(struct udev_device *dev, const char *subsys, const char *devtype)
{
        const char *str;

        str = udev_device_get_subsystem(dev);
        if (str == NULL)
                goto try_parent;
        if (strcmp(str, subsys) != 0)
                goto try_parent;

        if (devtype != NULL) {
                str = udev_device_get_devtype(dev);
                if (str == NULL)
                        goto try_parent;
                if (strcmp(str, devtype) != 0)
                        goto try_parent;
        }
        return dev;
try_parent:
        return udev_device_get_parent_with_subsystem_devtype(dev, subsys, devtype);
}


static int builtin_db(struct udev_device *dev, bool test,
                      const char *database,
                      const char *vendor_attr, const char *product_attr,
                      const char *subsys, const char *devtype)
{
        struct udev_device *parent;
        uint16_t vid = 0, pid = 0;
        char *vendor = NULL, *product = NULL;

        parent = find_device(dev, subsys, devtype);
        if (!parent) {
                fprintf(stderr, "Failed to find device.\n");
                goto finish;
        }

        if (get_vid_pid(parent, vendor_attr, product_attr, &vid, &pid) < 0)
                goto finish;

        if (lookup_vid_pid(database, vid, pid, &vendor, &product) < 0)
                goto finish;

        if (vendor)
                udev_builtin_add_property(dev, test, "ID_VENDOR_FROM_DATABASE", vendor);
        if (product)
                udev_builtin_add_property(dev, test, "ID_MODEL_FROM_DATABASE", product);

finish:
        free(vendor);
        free(product);
        return 0;
}

static int builtin_usb_db(struct udev_device *dev, int argc, char *argv[], bool test)
{
        return builtin_db(dev, test, USB_DATABASE, "idVendor", "idProduct", "usb", "usb_device");
}

static int builtin_pci_db(struct udev_device *dev, int argc, char *argv[], bool test)
{
        return builtin_db(dev, test, PCI_DATABASE, "vendor", "device", "pci", NULL);
}

const struct udev_builtin udev_builtin_usb_db = {
        .name = "usb-db",
        .cmd = builtin_usb_db,
        .help = "USB vendor/product database",
        .run_once = true,
};

const struct udev_builtin udev_builtin_pci_db = {
        .name = "pci-db",
        .cmd = builtin_pci_db,
        .help = "PCI vendor/product database",
        .run_once = true,
};
