/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include "varlink.h"

#define UDEV_VARLINK_ADDRESS "/run/udev/io.systemd.udev"

int udev_varlink_connect(Varlink **ret);
int udev_varlink_call(Varlink *link, const char *method, JsonVariant *parameters, JsonVariant **ret_parameters);
