/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-bus.h"

typedef struct Link Link;

int wpa_supplicant_get_interface(Link *link);
int on_wpa_supplicant_properties_changed(sd_bus_message *message, void *userdata, sd_bus_error *ret_error);
