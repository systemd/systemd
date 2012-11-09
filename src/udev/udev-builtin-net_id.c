/***
  This file is part of systemd.

  Copyright 2012 Kay Sievers <kay@vrfy.org>

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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "udev.h"

/* IEEE Organizationally Unique Identifier */
static int lookup_OUI(struct udev_device *dev, bool test) {
        const char *addr;
        unsigned int a1, a2, a3;
        char oui[16];

        addr = udev_device_get_sysattr_value(dev, "address");
        if (!addr)
                return -ENOENT;

        if (sscanf(addr, "%x:%x:%x:", &a1, &a2, &a3) != 3)
                return -EINVAL;

        snprintf(oui, sizeof(oui), "OUI:%X%X%X", a1, a2, a3);
        return udev_builtin_hwdb_lookup(dev, oui, test);
}

static int builtin_net_id(struct udev_device *dev, int argc, char *argv[], bool test) {
        lookup_OUI(dev, test);
        return EXIT_SUCCESS;
}

const struct udev_builtin udev_builtin_net_id = {
        .name = "net_id",
        .cmd = builtin_net_id,
        .help = "network device properties",
};
