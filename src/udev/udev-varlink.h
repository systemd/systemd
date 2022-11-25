/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "varlink.h"

#define UDEV_VARLINK_ADDRESS "/run/udev/io.systemd.udev"

typedef struct Manager Manager;

int udev_open_varlink(Manager *m, int fd);

int udev_varlink_connect(Varlink **ret_link);
int udev_varlink_call(Varlink *link, const char *method, JsonVariant *parameters, JsonVariant **ret_parameters);
