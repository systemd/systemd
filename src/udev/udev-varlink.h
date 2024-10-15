/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include "sd-varlink.h"

#define UDEV_VARLINK_ADDRESS "/run/udev/io.systemd.udev"

int udev_varlink_connect(sd_varlink **ret);
int udev_varlink_call(sd_varlink *link, const char *method, sd_json_variant *parameters, sd_json_variant **ret_parameters);
