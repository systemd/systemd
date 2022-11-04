/* SPDX-License-Identifier: GPL-2.0-or-later */

#define UDEV_VARLINK_ADDRESS "/run/udev/io.systemd.udev"

typedef struct Manager Manager;

int udev_open_varlink(Manager *m);
